//! Input injection on the host through XTEST.

use super::keymap::{self, X_KEYCODE_OFFSET};
use super::x11::{BUTTON_PRESS, BUTTON_RELEASE, Conn, Ext, KEY_PRESS, KEY_RELEASE, MOTION_NOTIFY, Target};
use crate::log;
use crate::proto::*;
use crate::screen::Area;
use crate::util::Result;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// X button numbers for `BTN_LEFT..=BTN_X2`.
const BUTTONS: [u8; 5] = [1, 3, 2, 8, 9];
const WHEEL_STEP: i32 = 120;
/// Bounds the clicks one wheel message can produce.
const MAX_WHEEL_CLICKS: i32 = 20;

struct Xtest {
    conn: Conn,
    ext: Ext,
}

/// Synthesises the remote user's keyboard and mouse on the X display.
#[derive(Default)]
pub struct Injector {
    area: Area,
    /// Display to inject into; `None` means this process's `$DISPLAY`.
    target: Option<Target>,
    x: Option<Xtest>,
    retry_at: Option<Instant>,
    /// X keycodes and buttons the remote user holds down.
    keys: HashSet<u8>,
    buttons: HashSet<u8>,
    /// Partial wheel rotation per axis (vertical, horizontal), in 1/120 notches.
    wheel: [i32; 2],
}

impl Injector {
    /// An injector for a specific display (tests, virtual displays).
    #[cfg(test)]
    pub fn on(target: Target) -> Injector {
        let mut inj = Injector::default();
        inj.target = Some(target);
        inj
    }

    pub fn set_area(&mut self, a: Area) {
        self.area = a;
    }

    /// The XTEST connection, opened on first use and re-opened (at most once a second) after
    /// the server went away.
    fn xtest(&mut self) -> Option<&mut Xtest> {
        if self.x.is_none() && self.retry_at.is_none_or(|t| Instant::now() >= t) {
            let opened = (|| -> Result<Xtest> {
                let target = match &self.target {
                    Some(t) => t.clone(),
                    None => Target::from_env()?,
                };
                let mut conn = Conn::connect(&target)?;
                let ext = conn.xtest()?.ok_or("the X server lacks the XTEST extension")?;
                Ok(Xtest { conn, ext })
            })();
            match opened {
                Ok(x) => {
                    self.x = Some(x);
                    self.retry_at = None;
                }
                Err(e) => {
                    if self.retry_at.is_none() {
                        log!("input injection unavailable: {e}");
                    }
                    self.retry_at = Some(Instant::now() + Duration::from_secs(1));
                }
            }
        }
        self.x.as_mut()
    }

    fn fake(&mut self, kind: u8, detail: u8, x: i16, y: i16) {
        let Some(xt) = self.xtest() else { return };
        if let Err(e) = xt.conn.fake_input(xt.ext, kind, detail, x, y) {
            log!("input injection failed: {e}");
            self.x = None;
            // The server is gone, and with it every key we held.
            self.keys.clear();
            self.buttons.clear();
        }
    }

    fn click(&mut self, button: u8) {
        self.fake(BUTTON_PRESS, button, 0, 0);
        self.fake(BUTTON_RELEASE, button, 0, 0);
    }

    fn wheel(&mut self, delta: i16, horizontal: bool) {
        let axis = horizontal as usize;
        self.wheel[axis] += delta as i32;
        let clicks = (self.wheel[axis] / WHEEL_STEP).clamp(-MAX_WHEEL_CLICKS, MAX_WHEEL_CLICKS);
        // Keep only a partial notch; rotation beyond the per-message bound is dropped.
        self.wheel[axis] = (self.wheel[axis] - clicks * WHEEL_STEP).clamp(1 - WHEEL_STEP, WHEEL_STEP - 1);
        // Windows: positive is away from the user (up) or to the right.
        let button = match (horizontal, clicks > 0) {
            (false, true) => 4,
            (false, false) => 5,
            (true, false) => 6,
            (true, true) => 7,
        };
        for _ in 0..clicks.abs() {
            self.click(button);
        }
    }

    fn keycode(&self, vk: u16, scan: u16, flags: u8) -> Option<u8> {
        let code = keymap::to_evdev(vk, scan, flags & KEY_EXTENDED != 0)? + X_KEYCODE_OFFSET;
        let setup = &self.x.as_ref()?.conn.setup;
        (code >= setup.min_keycode as u16 && code <= setup.max_keycode as u16).then_some(code as u8)
    }

    pub fn handle(&mut self, m: &ClientMsg) {
        match *m {
            ClientMsg::MouseMove { x, y } => {
                let a = self.area;
                if a.width <= 0 || a.height <= 0 {
                    return;
                }
                let px = (a.left + (x as i32).min(a.width - 1)).clamp(i16::MIN as i32, i16::MAX as i32);
                let py = (a.top + (y as i32).min(a.height - 1)).clamp(i16::MIN as i32, i16::MAX as i32);
                self.fake(MOTION_NOTIFY, 0, px as i16, py as i16);
            }
            ClientMsg::MouseButton { button, down } => {
                let Some(&b) = BUTTONS.get(button as usize) else { return };
                let changed = if down { self.buttons.insert(b) } else { self.buttons.remove(&b) };
                if changed {
                    self.fake(if down { BUTTON_PRESS } else { BUTTON_RELEASE }, b, 0, 0);
                }
            }
            ClientMsg::Wheel { delta, horizontal } => self.wheel(delta, horizontal),
            ClientMsg::Key { vk, scan, flags } => {
                if self.xtest().is_none() {
                    return;
                }
                let Some(code) = self.keycode(vk, scan, flags) else { return };
                if flags & KEY_UP != 0 {
                    if self.keys.remove(&code) {
                        self.fake(KEY_RELEASE, code, 0, 0);
                    }
                } else {
                    // Auto-repeat arrives as repeated presses, as from a local keyboard.
                    self.keys.insert(code);
                    self.fake(KEY_PRESS, code, 0, 0);
                }
            }
            ClientMsg::ReleaseAll => self.release_all(),
            _ => {}
        }
    }

    /// Releases every key and button the remote user still holds down.
    pub fn release_all(&mut self) {
        self.wheel = [0, 0];
        let keys: Vec<u8> = self.keys.drain().collect();
        let buttons: Vec<u8> = self.buttons.drain().collect();
        if self.x.is_none() {
            return;
        }
        for k in keys {
            self.fake(KEY_RELEASE, k, 0, 0);
        }
        for b in buttons {
            self.fake(BUTTON_RELEASE, b, 0, 0);
        }
        if let Some(xt) = &mut self.x {
            let _ = xt.conn.sync();
        }
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        self.release_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::x11::{self, Event};
    use crate::platform::linux::xvfb::VirtualDisplay;

    #[test]
    fn wheel_steps_accumulate() {
        // No display: the clicks go nowhere, but the bookkeeping must hold.
        let mut inj = Injector::on(Target { display: ":79".into(), xauthority: None });
        inj.retry_at = Some(Instant::now() + Duration::from_secs(60));
        inj.wheel(60, false);
        assert_eq!(inj.wheel, [60, 0]);
        inj.wheel(60, false);
        assert_eq!(inj.wheel, [0, 0]);
        inj.wheel(-200, true);
        assert_eq!(inj.wheel, [0, -80]);
        inj.wheel(i16::MAX, false);
        assert!(inj.wheel[0].abs() < WHEEL_STEP);
    }

    /// Creates a window covering the display that receives keyboard and pointer events.
    fn test_window(c: &mut Conn, w: u16, h: u16) -> u32 {
        let mask =
            x11::KEY_PRESS_MASK | x11::KEY_RELEASE_MASK | x11::BUTTON_PRESS_MASK | x11::BUTTON_RELEASE_MASK | x11::STRUCTURE_NOTIFY_MASK;
        let root = c.root();
        let win = c.create_window(root, 0, 0, w, h, 1, x11::CW_EVENT_MASK, &[mask]).unwrap();
        c.map_window(win).unwrap();
        loop {
            if let Some(Event::Map { window }) = c.wait_event(Duration::from_secs(5)).unwrap() {
                if window == win {
                    break;
                }
            }
        }
        c.set_input_focus(win).unwrap();
        c.sync().unwrap();
        win
    }

    fn next_input(c: &mut Conn) -> Event {
        loop {
            let e = c.wait_event(Duration::from_secs(5)).unwrap().expect("no event");
            if matches!(e, Event::Key { .. } | Event::Button { .. }) {
                return e;
            }
        }
    }

    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn injects_keys_buttons_and_motion() {
        let vd = VirtualDisplay::spawn(Some(72), 400, 300, None).unwrap();
        let mut c = Conn::connect(&vd.target()).unwrap();
        let root = c.root();
        let _win = test_window(&mut c, 400, 300);

        // The server must use evdev keycodes: 'a' at 38, Home at 110, Hangul at 130.
        let (per, syms) = c.keyboard_mapping(8, 248).unwrap();
        let sym = |code: usize| syms[(code - 8) * per];
        assert_eq!((sym(38), sym(110), sym(119 + 8)), (0x61, 0xff50, 0xff13));

        let mut inj = Injector::on(vd.target());
        inj.set_area(crate::screen::Area { left: 100, top: 50, width: 200, height: 100 });
        inj.handle(&ClientMsg::MouseMove { x: 10, y: 20 });
        inj.handle(&ClientMsg::MouseMove { x: 5000, y: 5000 });
        if let Some(xt) = &mut inj.x {
            xt.conn.sync().unwrap();
        }
        let p = c.query_pointer(root).unwrap();
        assert_eq!((p.root_x, p.root_y), (299, 149), "clamped to the area");
        inj.handle(&ClientMsg::MouseMove { x: 10, y: 20 });
        if let Some(xt) = &mut inj.x {
            xt.conn.sync().unwrap();
        }
        let p = c.query_pointer(root).unwrap();
        assert_eq!((p.root_x, p.root_y), (110, 70));

        // 'A' by scancode, Pause by virtual key, Left (extended).
        inj.handle(&ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: 0 });
        assert!(matches!(next_input(&mut c), Event::Key { press: true, keycode: 38, .. }));
        inj.handle(&ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: KEY_UP });
        assert!(matches!(next_input(&mut c), Event::Key { press: false, keycode: 38, .. }));
        inj.handle(&ClientMsg::Key { vk: keymap::VK_PAUSE, scan: 0x45, flags: 0 });
        assert!(matches!(next_input(&mut c), Event::Key { press: true, keycode: 127, .. }));
        inj.handle(&ClientMsg::Key { vk: 0x25, scan: 0x4b, flags: KEY_EXTENDED });
        assert!(matches!(next_input(&mut c), Event::Key { press: true, keycode: 113, .. }));

        // Buttons and wheel.
        inj.handle(&ClientMsg::MouseButton { button: BTN_RIGHT, down: true });
        assert!(matches!(next_input(&mut c), Event::Button { press: true, button: 3, x: 110, y: 70 }));
        inj.handle(&ClientMsg::MouseButton { button: BTN_RIGHT, down: false });
        assert!(matches!(next_input(&mut c), Event::Button { press: false, button: 3, .. }));
        inj.handle(&ClientMsg::Wheel { delta: -120, horizontal: false });
        assert!(matches!(next_input(&mut c), Event::Button { press: true, button: 5, .. }));
        assert!(matches!(next_input(&mut c), Event::Button { press: false, button: 5, .. }));
        inj.handle(&ClientMsg::Wheel { delta: 120, horizontal: true });
        assert!(matches!(next_input(&mut c), Event::Button { press: true, button: 7, .. }));
        assert!(matches!(next_input(&mut c), Event::Button { press: false, button: 7, .. }));

        // Held keys and buttons are released by release_all (Pause and Left still down).
        inj.handle(&ClientMsg::MouseButton { button: BTN_LEFT, down: true });
        assert!(matches!(next_input(&mut c), Event::Button { press: true, button: 1, .. }));
        inj.handle(&ClientMsg::ReleaseAll);
        let mut released = Vec::new();
        for _ in 0..3 {
            match next_input(&mut c) {
                Event::Key { press: false, keycode, .. } => released.push(keycode as u32),
                Event::Button { press: false, button, .. } => released.push(1000 + button as u32),
                e => panic!("unexpected {e:?}"),
            }
        }
        released.sort();
        assert_eq!(released, [113, 127, 1001]);
        drop(inj);
        assert!(c.wait_event(Duration::from_millis(200)).unwrap().is_none_or(|e| !matches!(e, Event::Key { .. })));
    }
}
