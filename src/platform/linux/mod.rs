//! Linux platform layer (X11).

pub mod audio;
pub mod capture;
pub mod clipboard;
pub mod desktop;
pub mod input;
mod keymap;
pub mod keystore;
pub mod mem;
pub mod privacy;
pub mod viewer;
mod x11;
pub mod xvfb;

use std::ffi::c_ulong;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

// Constants and structure layouts of the C library and the kernel are written out by hand in
// this module and the ones above, in the Linux parts of net.rs and files.rs, and in
// crypto/openssl.rs. They were checked against the kernel's uapi headers and glibc's and musl's
// for these architectures only; others differ (open flags on arm and powerpc, SOL_SOCKET and
// MAP_ANONYMOUS on mips, the size of time_t and off_t on 32-bit ones), so check them before
// adding one here.
#[cfg(not(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")
)))]
compile_error!("safe-rdp's Linux system interface was checked for 64-bit x86_64, aarch64 and riscv64 only");

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
        /// Takes four `unsigned long` arguments after `option`.
        pub fn prctl(option: c_int, ...) -> c_int;
        pub fn tcgetattr(fd: c_int, t: *mut Termios) -> c_int;
        pub fn tcsetattr(fd: c_int, action: c_int, t: *const Termios) -> c_int;
        pub fn signal(sig: c_int, handler: extern "C" fn(c_int)) -> usize;
        pub fn _exit(code: c_int) -> !;
    }

    pub const SIGHUP: c_int = 1;
    pub const SIGINT: c_int = 2;
    pub const SIGTERM: c_int = 15;

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
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong) };
}

static STOP_FLAG: AtomicPtr<AtomicBool> = AtomicPtr::new(std::ptr::null_mut());
static SIGNALS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_signal(_sig: std::ffi::c_int) {
    let flag = STOP_FLAG.load(Ordering::SeqCst);
    // A second signal while shutting down means "now". Counted separately: `stop` may also
    // have been set for other reasons (the session ended), which is not a first signal.
    if flag.is_null() || SIGNALS.fetch_add(1, Ordering::SeqCst) > 0 {
        unsafe { libc::_exit(130) };
    }
    unsafe { (*flag).store(true, Ordering::SeqCst) };
}

/// SIGINT, SIGTERM and SIGHUP set `stop` instead of killing the process, so it can shut down
/// cleanly (release held keys, stop a virtual display). A second signal exits at once.
pub fn stop_on_signals(stop: &'static AtomicBool) {
    STOP_FLAG.store(stop as *const AtomicBool as *mut AtomicBool, Ordering::SeqCst);
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        unsafe { libc::signal(sig, on_signal) };
    }
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
