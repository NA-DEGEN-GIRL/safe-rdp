//! Windows platform layer.

pub mod audio;
pub mod capture;
pub mod clipboard;
pub mod desktop;
mod dxgi;
pub mod input;
pub mod keystore;
pub mod launcher;
pub mod mem;
pub mod privacy;
pub mod service;
pub mod toolbar;
pub mod viewer;

/// Per-process setup before any window or capture: work in physical pixels.
pub fn init_process() {
    use windows_sys::Win32::UI::HiDpi::{DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext};
    unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
}

/// Local wall-clock time: [year, month, day, hour, minute, second].
pub fn local_time() -> [u16; 6] {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    let mut t = unsafe { std::mem::zeroed() };
    unsafe { GetLocalTime(&mut t) };
    [t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond]
}

/// Asks the service to generate Ctrl+Alt+Del (only works when running as its agent).
pub fn request_sas() -> bool {
    service::request_sas()
}

static STOP_FLAG: std::sync::OnceLock<&'static std::sync::atomic::AtomicBool> = std::sync::OnceLock::new();
static CONSOLE_EVENTS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

unsafe extern "system" fn on_console_event(event: u32) -> i32 {
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    let Some(stop) = STOP_FLAG.get() else { return 0 };
    // A second Ctrl+C while shutting down falls through to the default handler (exit now).
    // Counted separately: `stop` may also have been set for another reason.
    if CONSOLE_EVENTS.fetch_add(1, Ordering::SeqCst) > 0 {
        return 0;
    }
    stop.store(true, Ordering::SeqCst);
    if event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT {
        // Console closed / logoff / shutdown: the process ends when this returns, so give
        // the host a moment to release held keys and end the session.
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    1
}

/// Ctrl+C / Ctrl+Break / closing the console set `stop` instead of killing the process, so
/// it can shut down cleanly (release held keys, end privacy mode). A second Ctrl+C exits.
pub fn stop_on_signals(stop: &'static std::sync::atomic::AtomicBool) {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    if STOP_FLAG.set(stop).is_ok() {
        unsafe { SetConsoleCtrlHandler(Some(on_console_event), 1) };
    }
}

/// The console mode `read_secret` switched echo off from.
static ECHO_MODE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Ctrl+C or a closed console while `read_secret` waits: echo goes back on before the next
/// handler (the default one) ends the process, or the console would stay without it.
unsafe extern "system" fn restore_echo(_event: u32) -> i32 {
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode};
    unsafe { SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), ECHO_MODE.load(std::sync::atomic::Ordering::SeqCst)) };
    0
}

/// Lets the console interpret ANSI colour and erase sequences (older consoles do not by default).
pub fn enable_terminal_colors() {
    use windows_sys::Win32::System::Console::*;
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0;
        if GetConsoleMode(h, &mut mode) != 0 {
            SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

/// Waits for one key on the console (stdin), Ctrl+C included: it arrives as a key, not as the
/// console's interrupt, so that the caller still runs what follows (`key qr` clears the screen).
pub fn wait_key() -> crate::util::Result<()> {
    use std::io::Read;
    use windows_sys::Win32::System::Console::*;
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0;
        let console = GetConsoleMode(h, &mut mode) != 0;
        if console {
            SetConsoleMode(h, mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT));
        }
        let mut b = [0u8; 1];
        let r = std::io::stdin().read(&mut b);
        if console {
            SetConsoleMode(h, mode);
        }
        r?;
    }
    Ok(())
}

/// Reads one line from stdin without echoing it when stdin is a console.
pub fn read_secret(prompt: &str) -> crate::util::Result<String> {
    use windows_sys::Win32::System::Console::*;
    eprint!("{prompt}");
    // Room for a key line, so that it is not copied while growing; wiped if reading fails.
    let mut line = String::with_capacity(256);
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0;
        let console = GetConsoleMode(h, &mut mode) != 0;
        if console {
            ECHO_MODE.store(mode, std::sync::atomic::Ordering::SeqCst);
            SetConsoleCtrlHandler(Some(restore_echo), 1);
            SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
        }
        let r = std::io::stdin().read_line(&mut line);
        if console {
            SetConsoleMode(h, mode);
            SetConsoleCtrlHandler(Some(restore_echo), 0);
            eprintln!();
        }
        if let Err(e) = r {
            // Also what a failed read left beyond the length (invalid UTF-8 is cut off again).
            drop(crate::util::SecureVec(line.into_bytes()));
            return Err(e.into());
        }
    }
    Ok(line)
}
/// This machine's name as shown to viewers.
pub fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}
