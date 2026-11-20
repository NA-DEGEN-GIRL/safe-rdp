//! Input injection on the host via SendInput.

use crate::capture::{Area, virtual_screen};
use crate::proto::*;
use std::collections::HashSet;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{XBUTTON1, XBUTTON2};

/// Marker in `dwExtraInfo` so injected events can be recognised.
pub const INJECT_TAG: usize = 0x5344_5250; // "SRDP"

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
            mi: MOUSEINPUT { dx, dy, mouseData: data as u32, dwFlags: flags, time: 0, dwExtraInfo: INJECT_TAG },
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
            ki: KEYBDINPUT { wVk: vk, wScan: k.scan, dwFlags: flags, time: 0, dwExtraInfo: INJECT_TAG },
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
    #[ignore = "moves the real mouse cursor; run with --ignored"]
    fn absolute_moves_land_on_exact_pixels() {
        unsafe {
            windows_sys::Win32::UI::HiDpi::SetProcessDpiAwarenessContext(windows_sys::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
        };
        let mut orig = POINT { x: 0, y: 0 };
        unsafe { GetCursorPos(&mut orig) };
        let area = crate::capture::resolve(crate::capture::MonitorSel::Primary).unwrap();
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