//! Linux platform layer (X11).

pub mod audio;
pub mod capture;
pub mod clipboard;
pub mod desktop;
pub mod input;
pub mod keystore;
pub mod mem;
pub mod privacy;
pub mod viewer;

mod libc {
    use std::ffi::{c_char, c_int, c_long};

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
        pub fn prctl(option: c_int, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> c_int;
        pub fn tcgetattr(fd: c_int, t: *mut Termios) -> c_int;
        pub fn tcsetattr(fd: c_int, action: c_int, t: *const Termios) -> c_int;
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Termios {
        pub c_iflag: u32,
        pub c_oflag: u32,
        pub c_cflag: u32,
        pub c_lflag: u32,
        pub c_line: u8,
        pub c_cc: [u8; 32],
        pub c_ispeed: u32,
        pub c_ospeed: u32,
    }

    pub const ECHO: u32 = 0o10;
    pub const TCSANOW: c_int = 0;

    pub const PR_SET_DUMPABLE: c_int = 4;
}

/// Per-process hardening: no core dumps and no ptrace attach by other same-user processes,
/// so screen contents and keys cannot be scraped from this process's memory that way.
pub fn init_process() {
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
}

/// Local wall-clock time: [year, month, day, hour, minute, second].
pub fn local_time() -> [u16; 6] {
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::Tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return [0; 6];
        }
        [
            (tm.tm_year + 1900) as u16,
            (tm.tm_mon + 1) as u16,
            tm.tm_mday as u16,
            tm.tm_hour as u16,
            tm.tm_min as u16,
            tm.tm_sec as u16,
        ]
    }
}

/// Ctrl+Alt+Del has no meaning on an X11 host.
pub fn request_sas() -> bool {
    false
}

/// Reads one line from stdin without echoing it when stdin is a terminal.
pub fn read_secret(prompt: &str) -> crate::util::Result<String> {
    eprint!("{prompt}");
    let mut line = String::new();
    unsafe {
        let mut t: libc::Termios = std::mem::zeroed();
        let tty = libc::tcgetattr(0, &mut t) == 0;
        if tty {
            let mut quiet = t;
            quiet.c_lflag &= !libc::ECHO;
            libc::tcsetattr(0, libc::TCSANOW, &quiet);
        }
        let r = std::io::stdin().read_line(&mut line);
        if tty {
            libc::tcsetattr(0, libc::TCSANOW, &t);
            eprintln!();
        }
        r?;
    }
    Ok(line)
}
/// This machine's name as shown to viewers.
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_string()).unwrap_or_default()
}
