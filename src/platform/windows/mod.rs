//! Windows platform layer.

pub mod capture;
pub mod clipboard;
pub mod desktop;
mod dxgi;
pub mod input;
pub mod keystore;
pub mod mem;
pub mod service;
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