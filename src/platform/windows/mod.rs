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

unsafe extern "system" fn on_console_event(event: u32) -> i32 {
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    let Some(stop) = STOP_FLAG.get() else { return 0 };
    // A second Ctrl+C while shutting down falls through to the default handler (exit now).
    if stop.swap(true, Ordering::SeqCst) {
        return 0;
    }
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

/// Reads one line from stdin without echoing it when stdin is a console.
pub fn read_secret(prompt: &str) -> crate::util::Result<String> {
    use windows_sys::Win32::System::Console::*;
    eprint!("{prompt}");
    let mut line = String::new();
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0;
        let console = GetConsoleMode(h, &mut mode) != 0;
        if console {
            SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
        }
        let r = std::io::stdin().read_line(&mut line);
        if console {
            SetConsoleMode(h, mode);
            eprintln!();
        }
        r?;
    }
    Ok(line)
}
/// This machine's name as shown to viewers.
pub fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}
