//! The `crate::platform` items the shared modules use, on Android. (Built for the desktop too,
//! where only what the crate's unit tests need does anything.)

/// Bionic and the kernel share Linux's layouts and constants for what this uses.
#[cfg(target_os = "android")]
#[path = "../../../../src/platform/linux/mem.rs"]
pub mod mem;

#[cfg(target_os = "android")]
pub mod audio;
#[cfg(target_os = "android")]
#[path = "../../../../src/platform/jitter.rs"]
mod jitter;

#[cfg(all(target_os = "android", not(all(target_pointer_width = "64", any(target_arch = "x86_64", target_arch = "aarch64")))))]
compile_error!("the safe-rdp app's system interface was checked for 64-bit arm64-v8a and x86_64 only");

#[cfg(target_os = "android")]
mod libc {
    use std::ffi::{c_char, c_int, c_long};

    /// `struct tm` (bionic, 64-bit).
    #[repr(C)]
    pub struct Tm {
        pub tm_sec: c_int,
        pub tm_min: c_int,
        pub tm_hour: c_int,
        pub tm_mday: c_int,
        pub tm_mon: c_int,
        pub tm_year: c_int,
        pub tm_wday: c_int,
        pub tm_yday: c_int,
        pub tm_isdst: c_int,
        pub tm_gmtoff: c_long,
        pub tm_zone: *const c_char,
    }

    unsafe extern "C" {
        pub fn time(t: *mut i64) -> i64;
        pub fn localtime_r(t: *const i64, out: *mut Tm) -> *mut Tm;
    }
}

/// Log lines kept for the app's log screen; never written to the system log, which other apps
/// with the right permission and anyone with adb can read.
static LOG: std::sync::Mutex<std::collections::VecDeque<String>> = std::sync::Mutex::new(std::collections::VecDeque::new());
const LOG_LINES: usize = 300;

pub fn log(line: &str) {
    let mut l = LOG.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if l.len() == LOG_LINES {
        l.pop_front();
    }
    l.push_back(line.trim_end().to_string());
}

/// The kept log lines, oldest first.
pub fn log_text() -> String {
    let l = LOG.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    l.iter().map(|s| format!("{s}\n")).collect()
}

/// `[year, month, day, hour, minute, second]` in local time, for log lines.
#[cfg(target_os = "android")]
pub fn local_time() -> [u32; 6] {
    let t = unsafe { libc::time(std::ptr::null_mut()) };
    let mut tm: libc::Tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return [1970, 1, 1, 0, 0, 0];
    }
    [tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec].map(|v| v.max(0) as u32)
}

#[cfg(not(target_os = "android"))]
pub fn local_time() -> [u32; 6] {
    [1970, 1, 1, 0, 0, 0]
}
