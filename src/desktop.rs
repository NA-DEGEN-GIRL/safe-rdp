//! Following the input desktop (Default <-> Winlogon/secure desktop).
//!
//! When the host runs as SYSTEM (service mode) this lets capture and input reach the lock
//! screen, the sign-in screen and UAC prompts. As a normal user the secure desktop cannot be
//! opened and the thread simply stays where it is.

use crate::util::from_wide;
use windows_sys::Win32::Foundation::GENERIC_WRITE;
use windows_sys::Win32::System::StationsAndDesktops::*;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

fn desktop_name(h: HDESK) -> String {
    let mut buf = [0u16; 128];
    let mut needed = 0u32;
    let ok = unsafe { GetUserObjectInformationW(h, UOI_NAME, buf.as_mut_ptr().cast(), (buf.len() * 2) as u32, &mut needed) };
    if ok == 0 { String::new() } else { from_wide(&buf) }
}

pub struct DesktopFollower {
    handle: HDESK,
    name: String,
}

impl DesktopFollower {
    pub fn new() -> DesktopFollower {
        let name = desktop_name(unsafe { GetThreadDesktop(GetCurrentThreadId()) });
        DesktopFollower { handle: std::ptr::null_mut(), name }
    }

    /// Moves the calling thread to the current input desktop if it changed; true if it moved.
    /// The thread must not own windows or hooks.
    pub fn sync(&mut self) -> bool {
        unsafe {
            let access = DESKTOP_CREATEMENU
                | DESKTOP_CREATEWINDOW
                | DESKTOP_ENUMERATE
                | DESKTOP_HOOKCONTROL
                | DESKTOP_WRITEOBJECTS
                | DESKTOP_READOBJECTS
                | DESKTOP_SWITCHDESKTOP
                | GENERIC_WRITE;
            let h = OpenInputDesktop(0, 0, access);
            if h.is_null() {
                return false;
            }
            let name = desktop_name(h);
            if name == self.name || SetThreadDesktop(h) == 0 {
                CloseDesktop(h);
                return false;
            }
            if !self.handle.is_null() {
                CloseDesktop(self.handle);
            }
            crate::log!("switched to desktop '{name}'");
            self.handle = h;
            self.name = name;
            true
        }
    }
}
