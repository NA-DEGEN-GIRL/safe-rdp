//! Optional text-only clipboard bridge.
//!
//! Runs a message-only window on its own thread that reports local clipboard changes and
//! applies remote ones. Text written from the remote side is flagged so Windows keeps it out
//! of clipboard history (Win+V) and cloud clipboard sync.

use crate::proto::MAX_CLIPBOARD;
use crate::util::{Error, Result, wide};
use std::ptr::{null, null_mut};
use std::sync::mpsc;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::DataExchange::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const WM_APP_SET: u32 = WM_APP + 1;

struct State {
    on_change: Box<dyn Fn(String) + Send>,
    rx: mpsc::Receiver<String>,
    ignore_seq: u32,
}

pub struct Clipboard {
    hwnd: usize,
    tx: mpsc::Sender<String>,
}

impl Clipboard {
    /// Starts watching the clipboard; `on_change` runs on the bridge thread.
    pub fn spawn(on_change: impl Fn(String) + Send + 'static) -> Result<Clipboard> {
        let (tx, rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<usize>>();
        std::thread::Builder::new().name("clipboard".into()).spawn(move || {
            let state = Box::new(State { on_change: Box::new(on_change), rx, ignore_seq: 0 });
            match create_window(state) {
                Ok(hwnd) => {
                    let _ = ready_tx.send(Ok(hwnd as usize));
                    pump();
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                }
            }
        })?;
        let hwnd = ready_rx.recv().map_err(|_| Error::msg("clipboard thread died"))??;
        Ok(Clipboard { hwnd, tx })
    }

    /// Replaces the local clipboard text (asynchronously, on the bridge thread).
    pub fn set(&self, text: String) {
        if self.tx.send(text).is_ok() {
            unsafe { PostMessageW(self.hwnd as HWND, WM_APP_SET, 0, 0) };
        }
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        unsafe { PostMessageW(self.hwnd as HWND, WM_CLOSE, 0, 0) };
    }
}

fn pump() {
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            DispatchMessageW(&msg);
        }
    }
}

fn create_window(state: Box<State>) -> Result<HWND> {
    unsafe {
        let class = wide("SafeRdpClipboard");
        let hinst = GetModuleHandleW(null());
        let wc = WNDCLASSW { lpfnWndProc: Some(wnd_proc), hInstance: hinst, lpszClassName: class.as_ptr(), ..std::mem::zeroed() };
        RegisterClassW(&wc); // may already exist; CreateWindow reports real failures
        let hwnd = CreateWindowExW(0, class.as_ptr(), class.as_ptr(), 0, 0, 0, 0, 0, HWND_MESSAGE, null_mut(), hinst, null());
        if hwnd.is_null() {
            return Err(Error::last_os("CreateWindowExW(clipboard)"));
        }
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(state) as isize);
        if AddClipboardFormatListener(hwnd) == 0 {
            DestroyWindow(hwnd);
            return Err(Error::last_os("AddClipboardFormatListener"));
        }
        Ok(hwnd)
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        let state = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut State;
        match msg {
            WM_CLIPBOARDUPDATE if !state.is_null() => {
                let s = &mut *state;
                if GetClipboardSequenceNumber() != s.ignore_seq {
                    if let Some(t) = read_text(hwnd) {
                        (s.on_change)(t);
                    }
                }
                0
            }
            WM_APP_SET if !state.is_null() => {
                let s = &mut *state;
                // Only the newest pending value matters.
                if let Some(t) = s.rx.try_iter().last() {
                    if write_text(hwnd, &t) {
                        s.ignore_seq = GetClipboardSequenceNumber();
                    }
                }
                0
            }
            WM_DESTROY => {
                RemoveClipboardFormatListener(hwnd);
                if !state.is_null() {
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    drop(Box::from_raw(state));
                }
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

fn open(hwnd: HWND) -> bool {
    // Another process may hold the clipboard briefly.
    for _ in 0..10 {
        if unsafe { OpenClipboard(hwnd) } != 0 {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(15));
    }
    false
}

pub fn read_text(hwnd: HWND) -> Option<String> {
    unsafe {
        if IsClipboardFormatAvailable(CF_UNICODETEXT as u32) == 0 || !open(hwnd) {
            return None;
        }
        let mut out = None;
        let h = GetClipboardData(CF_UNICODETEXT as u32);
        if !h.is_null() {
            let p = GlobalLock(h) as *const u16;
            if !p.is_null() {
                let max = GlobalSize(h) / 2;
                let len = (0..max).take_while(|&i| *p.add(i) != 0).count();
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
                GlobalUnlock(h);
                if s.len() <= MAX_CLIPBOARD {
                    out = Some(s);
                }
            }
        }
        CloseClipboard();
        out
    }
}

unsafe fn global_copy(bytes: &[u8]) -> HGLOBAL {
    unsafe {
        let h = GlobalAlloc(GMEM_MOVEABLE, bytes.len());
        if h.is_null() {
            return h;
        }
        let p = GlobalLock(h) as *mut u8;
        if p.is_null() {
            GlobalFree(h);
            return null_mut();
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        GlobalUnlock(h);
        h
    }
}

pub fn write_text(hwnd: HWND, text: &str) -> bool {
    let utf16: Vec<u8> = text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
    unsafe {
        if !open(hwnd) {
            return false;
        }
        EmptyClipboard();
        let mut ok = false;
        let h = global_copy(&utf16);
        if !h.is_null() {
            if SetClipboardData(CF_UNICODETEXT as u32, h).is_null() {
                GlobalFree(h);
            } else {
                ok = true;
            }
        }
        // Keep remote text out of clipboard history and cloud sync.
        for name in ["CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"] {
            let fmt = RegisterClipboardFormatW(wide(name).as_ptr());
            let h = global_copy(&0u32.to_le_bytes());
            if fmt != 0 && !h.is_null() && SetClipboardData(fmt, h).is_null() {
                GlobalFree(h);
            }
        }
        CloseClipboard();
        ok
    }
}

/// Regular files currently copied in Explorer (CF_HDROP); placeholder until implemented.
pub fn copied_files() -> Vec<std::path::PathBuf> {
    Vec::new()
}
