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

/// Keeps the calling thread on the input desktop. Must be dropped on the thread that created
/// it, which it then returns to its original desktop.
pub struct DesktopFollower {
    /// The desktop we opened and moved the thread to; null until the first switch.
    handle: HDESK,
    /// The thread's desktop when we started; not ours to close.
    orig: HDESK,
}

impl DesktopFollower {
    pub fn new() -> DesktopFollower {
        let orig = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
        DesktopFollower { handle: std::ptr::null_mut(), orig }
    }

    /// Moves the calling thread to the current input desktop if it is elsewhere; true if it
    /// moved. The thread must not own windows or hooks. Another follower on the same thread
    /// (the input injector has one) may have moved it since our last switch, so this looks at
    /// where the thread is rather than where we put it.
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
            if name == desktop_name(GetThreadDesktop(GetCurrentThreadId())) || SetThreadDesktop(h) == 0 {
                CloseDesktop(h);
                return false;
            }
            if !self.handle.is_null() {
                CloseDesktop(self.handle);
            }
            crate::log!("switched to desktop '{name}'");
            self.handle = h;
            true
        }
    }

    /// Returns the thread to its original desktop and closes ours (a thread's current desktop
    /// cannot be closed); true if there was one and it was closed.
    fn release(&mut self) -> bool {
        if self.handle.is_null() {
            return false;
        }
        let h = std::mem::replace(&mut self.handle, std::ptr::null_mut());
        unsafe {
            SetThreadDesktop(self.orig);
            CloseDesktop(h) != 0
        }
    }
}

impl Drop for DesktopFollower {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::wide;

    #[test]
    fn dropping_returns_the_thread_and_closes_the_desktop() {
        // A thread of its own, which owns no windows or hooks and so may change desktops.
        std::thread::spawn(|| unsafe {
            let mut f = DesktopFollower::new();
            assert!(!f.release(), "nothing to close before any switch");
            let orig = GetThreadDesktop(GetCurrentThreadId());
            let name = desktop_name(orig);
            // Stands in for a switch: the same desktop through a handle of our own.
            let h = OpenDesktopW(wide(&name).as_ptr(), 0, 0, DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS | DESKTOP_CREATEWINDOW);
            assert!(!h.is_null(), "OpenDesktopW({name}) failed");
            assert!(SetThreadDesktop(h) != 0);
            assert_eq!(GetThreadDesktop(GetCurrentThreadId()), h);
            f.handle = h;
            assert!(f.release(), "the desktop handle was not closed");
            assert!(f.handle.is_null());
            assert_eq!(GetThreadDesktop(GetCurrentThreadId()), orig);
            drop(f);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn sync_goes_by_where_the_thread_is_not_where_it_was_left() {
        std::thread::spawn(|| unsafe {
            let orig = GetThreadDesktop(GetCurrentThreadId());
            let input = OpenInputDesktop(0, 0, DESKTOP_READOBJECTS);
            if input.is_null() {
                return; // the lock screen: nothing to follow
            }
            let input_name = desktop_name(input);
            CloseDesktop(input);
            if desktop_name(orig) != input_name {
                return;
            }
            let mut f = DesktopFollower::new();
            assert!(!f.sync(), "moved although already on the input desktop");
            // Another follower takes the thread elsewhere: to a desktop of its own that is
            // never shown.
            let name = wide(&format!("safe-rdp-test-{}", std::process::id()));
            let access = DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS;
            let other = CreateDesktopW(name.as_ptr(), std::ptr::null(), std::ptr::null(), 0, access, std::ptr::null());
            assert!(!other.is_null(), "CreateDesktopW failed");
            assert!(SetThreadDesktop(other) != 0);
            assert!(f.sync(), "the thread was left off the input desktop");
            assert_eq!(desktop_name(GetThreadDesktop(GetCurrentThreadId())), input_name);
            assert!(!f.sync());
            drop(f);
            assert_eq!(GetThreadDesktop(GetCurrentThreadId()), orig);
            assert!(CloseDesktop(other) != 0);
        })
        .join()
        .unwrap();
    }
}
