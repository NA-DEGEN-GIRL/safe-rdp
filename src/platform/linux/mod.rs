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
        /// Handlers as addresses (`sighandler_t`): what comes back may be `SIG_IGN` or `SIG_ERR`,
        /// which are not functions.
        pub fn signal(sig: c_int, handler: usize) -> usize;
        pub fn _exit(code: c_int) -> !;
        pub fn write(fd: c_int, buf: *const std::ffi::c_void, n: usize) -> isize;
    }

    pub const SIGHUP: c_int = 1;
    pub const SIGINT: c_int = 2;
    pub const SIGQUIT: c_int = 3;
    pub const SIGTERM: c_int = 15;
    pub const SIG_IGN: usize = 1;
    pub const SIG_ERR: usize = usize::MAX;

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
    pub const ISIG: u32 = 0o1;
    pub const ICANON: u32 = 0o2;
    /// Indexes into `Termios::c_cc`.
    pub const VTIME: usize = 5;
    pub const VMIN: usize = 6;
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
        unsafe { libc::signal(sig, on_signal as *const () as usize) };
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

/// The terminal settings `read_secret` switched echo off from, while it waits.
static ECHO_TERMIOS: AtomicPtr<libc::Termios> = AtomicPtr::new(std::ptr::null_mut());
/// Set while `wait_key` waits under `key qr`: a signal ending the process clears the screen too.
static CLEAR_ON_SIGNAL: AtomicBool = AtomicBool::new(false);
/// Clear the screen and the scrollback, cursor home.
const CLEAR_SCREEN: &[u8] = b"\x1b[2J\x1b[3J\x1b[H";

/// A signal that ends the process while `read_secret` or `wait_key` waits (Ctrl+C, Ctrl+\, a
/// terminal closed or a kill): the terminal settings go back first, or the shell's terminal
/// would stay without echo; for `wait_key` the screen is cleared. Only async-signal-safe calls.
extern "C" fn restore_echo(sig: std::ffi::c_int) {
    let t = ECHO_TERMIOS.load(Ordering::SeqCst);
    if !t.is_null() {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, t) };
    }
    if CLEAR_ON_SIGNAL.load(Ordering::SeqCst) {
        unsafe { libc::write(1, CLEAR_SCREEN.as_ptr().cast(), CLEAR_SCREEN.len()) };
    }
    unsafe { libc::_exit(128 + sig) };
}

/// Echo switched off on the terminal while `read_secret` waits (or, `raw`, the terminal made to
/// hand over single keys, Ctrl+C included, while `wait_key` waits); dropping it (also when
/// reading panics) puts the terminal settings and the signal handlers back.
struct EchoOff {
    /// Where `restore_echo` finds them, for as long as its handlers are in place.
    saved: Box<libc::Termios>,
    handlers: Vec<(std::ffi::c_int, usize)>,
    raw: bool,
}

impl EchoOff {
    /// None when stdin is not a terminal.
    fn new() -> Option<EchoOff> {
        Self::with(false)
    }

    fn with(raw: bool) -> Option<EchoOff> {
        unsafe {
            let mut t: libc::Termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) != 0 {
                return None;
            }
            let saved = Box::new(t);
            ECHO_TERMIOS.store((&raw const *saved).cast_mut(), Ordering::SeqCst);
            let mut handlers = Vec::new();
            for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP] {
                match libc::signal(sig, restore_echo as *const () as usize) {
                    libc::SIG_ERR => {}
                    // Left ignored if it was (nohup).
                    libc::SIG_IGN => _ = libc::signal(sig, libc::SIG_IGN),
                    old => handlers.push((sig, old)),
                }
            }
            let mut quiet = t;
            quiet.c_lflag &= !libc::ECHO;
            if raw {
                quiet.c_lflag &= !(libc::ICANON | libc::ISIG);
                quiet.c_cc[libc::VMIN] = 1;
                quiet.c_cc[libc::VTIME] = 0;
                CLEAR_ON_SIGNAL.store(true, Ordering::SeqCst);
            }
            libc::tcsetattr(0, libc::TCSANOW, &quiet);
            Some(EchoOff { saved, handlers, raw })
        }
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &*self.saved);
            for &(sig, old) in &self.handlers {
                libc::signal(sig, old);
            }
        }
        ECHO_TERMIOS.store(std::ptr::null_mut(), Ordering::SeqCst);
        CLEAR_ON_SIGNAL.store(false, Ordering::SeqCst);
        if !self.raw {
            eprintln!();
        }
    }
}

/// Waits for one key on the terminal (stdin), Ctrl+C included: it arrives as a key, not as the
/// signal, so that the caller still runs what follows (`key qr` clears the screen).
pub fn wait_key() -> crate::util::Result<()> {
    use std::io::Read;
    // A signal meanwhile (the terminal closed, a kill) restores the terminal and clears the
    // screen before the process ends (`restore_echo`).
    let raw = EchoOff::with(true);
    let mut b = [0u8; 1];
    let r = std::io::stdin().read(&mut b);
    drop(raw);
    r?;
    Ok(())
}

/// Reads one line from stdin without echoing it when stdin is a terminal.
pub fn read_secret(prompt: &str) -> crate::util::Result<String> {
    eprint!("{prompt}");
    // Room for a key line, so that it is not copied while growing; wiped if reading fails.
    let mut line = String::with_capacity(256);
    let echo_off = EchoOff::new();
    let r = std::io::stdin().read_line(&mut line);
    drop(echo_off);
    if let Err(e) = r {
        // Also what a failed read left beyond the length (invalid UTF-8 is cut off again).
        drop(crate::util::SecureVec(line.into_bytes()));
        return Err(e.into());
    }
    Ok(line)
}
/// This machine's name as shown to viewers.
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_string()).unwrap_or_default()
}
