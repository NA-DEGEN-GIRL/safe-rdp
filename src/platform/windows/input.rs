//! Input injection on the host via SendInput.

use super::capture::virtual_screen;
use crate::screen::Area;
use crate::proto::*;
use std::collections::{HashSet, VecDeque};
use std::sync::{Mutex, PoisonError};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{XBUTTON1, XBUTTON2};

/// Tags kept for events the privacy hooks have not seen yet; the oldest make room.
const MAX_PENDING: usize = 4096;

/// Tags of the events we injected that no privacy hook has passed yet, oldest first. Tags are
/// recorded only while privacy mode is on ("armed"): an event sent while it is off reaches
/// other programs' hooks and windows with its tag unused, so that tag must never open the
/// privacy hooks later.
struct Pending {
    armed: bool,
    tags: VecDeque<usize>,
}

impl Pending {
    const fn new() -> Pending {
        Pending { armed: false, tags: VecDeque::new() }
    }

    fn arm(&mut self, on: bool) {
        self.armed = on;
        self.tags.clear();
    }

    fn add(&mut self, tag: usize) {
        if !self.armed {
            return;
        }
        if self.tags.len() >= MAX_PENDING {
            self.tags.pop_front();
        }
        self.tags.push_back(tag);
    }

    /// Removes `tag`; false if it is not (or no longer) there. The newest come first: with the
    /// hooks running, the event they are looking at was sent moments ago.
    fn take(&mut self, tag: usize) -> bool {
        match self.tags.iter().rposition(|&t| t == tag) {
            Some(i) => {
                self.tags.remove(i);
                true
            }
            None => false,
        }
    }
}

static PENDING: Mutex<Pending> = Mutex::new(Pending::new());

/// Called by privacy mode once its hooks are in place (`true`) and after they are gone
/// (`false`). Either way every tag issued so far stops counting.
pub fn arm(on: bool) {
    PENDING.lock().unwrap_or_else(PoisonError::into_inner).arm(on);
}

/// A fresh random marker for the `dwExtraInfo` of one event we inject, recorded (while privacy
/// mode is on) for the privacy hooks, which let an injected event through only with a tag they
/// have not seen before.
pub fn new_tag() -> usize {
    let mut b = [0u8; size_of::<usize>()];
    if crate::crypto::random(&mut b).is_err() {
        // CNG does not fail in practice; std's hash keys come from the OS generator too.
        use std::hash::{BuildHasher, RandomState};
        b = (RandomState::new().hash_one(std::process::id()) as usize).to_ne_bytes();
    }
    // Never 0 (what other programs send) nor the pen/touch signature 0xFF5157xx.
    let tag = (usize::from_ne_bytes(b) & !0x8000_0000) | 1;
    PENDING.lock().unwrap_or_else(PoisonError::into_inner).add(tag);
    tag
}

/// Called by the privacy hooks: whether `tag` is that of an event we injected, which it then
/// stops being. Each tag lets one event through.
pub fn take_tag(tag: usize) -> bool {
    PENDING.lock().unwrap_or_else(PoisonError::into_inner).take(tag)
}

/// Tests that use the process-wide tags hold this, with privacy mode's arming simulated.
#[cfg(test)]
pub fn armed_for_test() -> impl Drop {
    static LOCK: Mutex<()> = Mutex::new(());
    struct Armed(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
    impl Drop for Armed {
        fn drop(&mut self) {
            arm(false);
        }
    }
    let guard = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    arm(true);
    Armed(guard)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct HeldKey {
    vk: u16,
    scan: u16,
    extended: bool,
}

#[derive(Default)]
pub struct Injector {
    area: Area,
    keys: HashSet<HeldKey>,
    buttons: [bool; 5],
}

fn send(inputs: &[INPUT]) {
    unsafe { SendInput(inputs.len() as u32, inputs.as_ptr(), size_of::<INPUT>() as i32) };
}

fn mouse(dx: i32, dy: i32, data: i32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT { dx, dy, mouseData: data as u32, dwFlags: flags, time: 0, dwExtraInfo: new_tag() },
        },
    }
}

/// Keys whose scancodes are ambiguous or layout-specific are injected by virtual-key code.
fn inject_by_vk(vk: u16, scan: u16) -> bool {
    scan == 0 || matches!(vk, VK_PAUSE | VK_HANGUL | VK_HANJA | VK_IME_ON | VK_IME_OFF)
}

fn key(k: HeldKey, up: bool) -> INPUT {
    let mut flags = if up { KEYEVENTF_KEYUP } else { 0 };
    if k.extended {
        flags |= KEYEVENTF_EXTENDEDKEY;
    }
    let vk = if inject_by_vk(k.vk, k.scan) {
        k.vk
    } else {
        flags |= KEYEVENTF_SCANCODE;
        0
    };
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT { wVk: vk, wScan: k.scan, dwFlags: flags, time: 0, dwExtraInfo: new_tag() },
        },
    }
}

const BUTTON_FLAGS: [(MOUSE_EVENT_FLAGS, MOUSE_EVENT_FLAGS, i32); 5] = [
    (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, 0),
    (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, 0),
    (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, 0),
    (MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, XBUTTON1 as i32),
    (MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, XBUTTON2 as i32),
];

impl Injector {
    pub fn set_area(&mut self, a: Area) {
        self.area = a;
    }

    pub fn handle(&mut self, m: &ClientMsg) {
        match *m {
            ClientMsg::MouseMove { x, y } => {
                let a = self.area;
                let v = virtual_screen();
                if a.width <= 0 || v.width <= 0 || v.height <= 0 {
                    return;
                }
                let px = (a.left + (x as i32).min(a.width - 1)) - v.left;
                let py = (a.top + (y as i32).min(a.height - 1)) - v.top;
                // Round up so that Windows' (n * size) >> 16 maps back to exactly this pixel.
                let nx = ((px as i64 * 65536 + v.width as i64 - 1) / v.width as i64) as i32;
                let ny = ((py as i64 * 65536 + v.height as i64 - 1) / v.height as i64) as i32;
                send(&[mouse(nx, ny, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK)]);
            }
            ClientMsg::MouseButton { button, down } => {
                let Some(&(df, uf, data)) = BUTTON_FLAGS.get(button as usize) else { return };
                self.buttons[button as usize] = down;
                send(&[mouse(0, 0, data, if down { df } else { uf })]);
            }
            ClientMsg::Wheel { delta, horizontal } => {
                send(&[mouse(0, 0, delta as i32, if horizontal { MOUSEEVENTF_HWHEEL } else { MOUSEEVENTF_WHEEL })]);
            }
            ClientMsg::Key { vk, scan, flags } => {
                let k = HeldKey { vk, scan, extended: flags & KEY_EXTENDED != 0 };
                let up = flags & KEY_UP != 0;
                if up {
                    self.keys.remove(&k);
                } else {
                    self.keys.insert(k);
                }
                send(&[key(k, up)]);
            }
            ClientMsg::ReleaseAll => self.release_all(),
            _ => {}
        }
    }

    /// Releases every key and button the remote user still holds down.
    pub fn release_all(&mut self) {
        let mut inputs: Vec<INPUT> = self.keys.drain().map(|k| key(k, true)).collect();
        for (i, held) in self.buttons.iter_mut().enumerate() {
            if std::mem::take(held) {
                let (_, uf, data) = BUTTON_FLAGS[i];
                inputs.push(mouse(0, 0, data, uf));
            }
        }
        if !inputs.is_empty() {
            send(&inputs);
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
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetCursorPos, SetCursorPos};

    #[test]
    fn every_event_gets_a_fresh_tag_that_passes_once() {
        let _armed = armed_for_test();
        let a = |up| key(HeldKey { vk: 0x41, scan: 0x1e, extended: false }, up);
        let inputs = [a(false), mouse(0, 0, 0, MOUSEEVENTF_MOVE), a(true), mouse(0, 0, 0, MOUSEEVENTF_MOVE)];
        let extra = |i: INPUT| unsafe { if i.r#type == INPUT_KEYBOARD { i.Anonymous.ki.dwExtraInfo } else { i.Anonymous.mi.dwExtraInfo } };
        let tags = inputs.map(extra);
        for (i, &t) in tags.iter().enumerate() {
            assert!(!tags[..i].contains(&t), "tag reused: {tags:x?}");
            assert_ne!(t, 0);
            assert_ne!(t, 0x5344_5250, "the old fixed tag");
            assert_ne!(t & 0xFFFF_FF00, 0xFF51_5700);
        }
        // In any order, but each only once; anything else never.
        for &t in tags.iter().rev() {
            assert!(take_tag(t));
            assert!(!take_tag(t), "a tag passed twice");
        }
        assert!(!take_tag(0));
        assert!(!take_tag(new_tag() ^ 0x5a5a));
    }

    #[test]
    fn tags_count_only_while_privacy_mode_is_on() {
        let mut p = Pending::new();
        p.add(7); // sent while privacy mode was off: others may have seen it
        p.arm(true);
        assert!(!p.take(7), "a tag from before privacy mode passed");
        p.add(8);
        p.add(9);
        assert!(p.take(8));
        p.arm(false);
        assert!(!p.take(9), "a tag survived the end of privacy mode");
        p.add(10);
        p.arm(true);
        assert!(!p.take(10));
    }

    #[test]
    fn pending_tags_are_bounded_and_the_oldest_go() {
        let mut p = Pending::new();
        p.arm(true);
        for t in 1..=MAX_PENDING + 10 {
            p.add(t);
        }
        assert_eq!(p.tags.len(), MAX_PENDING);
        assert!(!p.take(10) && p.take(11) && p.take(MAX_PENDING + 10) && p.take(MAX_PENDING));
        assert!(!p.take(11));
        assert_eq!(p.tags.len(), MAX_PENDING - 3);
    }

    #[test]
    #[ignore = "moves the real mouse cursor; run with --ignored"]
    fn absolute_moves_land_on_exact_pixels() {
        unsafe {
            windows_sys::Win32::UI::HiDpi::SetProcessDpiAwarenessContext(windows_sys::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
        };
        let mut orig = POINT { x: 0, y: 0 };
        unsafe { GetCursorPos(&mut orig) };
        let area = crate::platform::capture::resolve(crate::screen::MonitorSel::Primary).unwrap();
        let mut inj = Injector::default();
        inj.set_area(area);
        let mut seen = Vec::new();
        for (x, y) in [(0, 0), (1, 1), (123, 457), (area.width - 1, area.height - 1), (area.width / 2 + 1, area.height / 3)] {
            inj.handle(&ClientMsg::MouseMove { x: x as u16, y: y as u16 });
            std::thread::sleep(std::time::Duration::from_millis(40));
            let mut p = POINT { x: 0, y: 0 };
            unsafe { GetCursorPos(&mut p) };
            seen.push(((area.left + x, area.top + y), (p.x, p.y)));
        }
        unsafe { SetCursorPos(orig.x, orig.y) };
        for (want, got) in seen {
            assert_eq!(want, got);
        }
    }
}