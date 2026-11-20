//! Optional text-only clipboard bridge, and the files copied in Explorer for `FilePull`.
//!
//! Runs a message-only window on its own thread that reports local clipboard changes and
//! applies remote ones. Text written from the remote side is flagged so Windows keeps it out
//! of clipboard history (Win+V) and cloud clipboard sync.

use crate::proto::MAX_CLIPBOARD;
use crate::util::{Error, Result, wide};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};
use std::sync::mpsc;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::{
    GetTokenInformation, ImpersonateLoggedOnUser, IsWellKnownSid, RevertToSelf, TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
};
use windows_sys::Win32::System::DataExchange::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Ole::{CF_HDROP, CF_UNICODETEXT};
use windows_sys::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{DragQueryFileW, HDROP};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

// In windows-sys behind the Win32_Storage_FileSystem feature, which nothing else needs.
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetDriveTypeW(root: *const u16) -> u32;
}

const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const DRIVE_CDROM: u32 = 5;
const DRIVE_RAMDISK: u32 = 6;

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

/// Upper bound on the files taken from one clipboard file list.
const MAX_COPIED_FILES: u32 = 1000;

/// Regular files on local drives currently copied in Explorer (CF_HDROP), as canonical paths
/// without duplicates, checked as the `FileUser` who will open them. Network, device and
/// relative paths, directories and missing files are left out.
pub fn copied_files() -> Vec<PathBuf> {
    let names = unsafe {
        if IsClipboardFormatAvailable(CF_HDROP as u32) == 0 || !open(null_mut()) {
            return Vec::new();
        }
        // The list is owned by the clipboard: read it while it is open, never DragFinish it.
        let h = GetClipboardData(CF_HDROP as u32);
        let names = if h.is_null() { Vec::new() } else { drop_list(h) };
        CloseClipboard();
        names
    };
    FileUser::get().and_then(|u| u.act(|| regular_files(names))).unwrap_or_default()
}

/// The identity copied files are checked and opened with. A host running as SYSTEM (the
/// service's agent) acts as the user signed in on its console session, so a viewer can pull no
/// file that user could not open; any other host already is that user.
pub struct FileUser {
    /// The console user's token, or null for the host's own identity.
    token: HANDLE,
}

impl FileUser {
    /// Fails when the host runs as SYSTEM and nobody is signed in on its session.
    pub fn get() -> Result<FileUser> {
        if !running_as_system() {
            return Ok(FileUser { token: null_mut() });
        }
        unsafe {
            let (console, mut own) = (WTSGetActiveConsoleSessionId(), u32::MAX);
            if ProcessIdToSessionId(GetCurrentProcessId(), &mut own) == 0 || own != console {
                return Err(Error::msg("the host is not running in the console session"));
            }
            let mut token = null_mut();
            if WTSQueryUserToken(console, &mut token) == 0 {
                return Err(Error::msg("nobody is signed in on the host"));
            }
            Ok(FileUser { token })
        }
    }

    /// Runs `f` on this thread as the user.
    pub fn act<T>(&self, f: impl FnOnce() -> T) -> Result<T> {
        if self.token.is_null() {
            return Ok(f());
        }
        if unsafe { ImpersonateLoggedOnUser(self.token) } == 0 {
            return Err(Error::last_os("ImpersonateLoggedOnUser"));
        }
        let _revert = Revert;
        Ok(f())
    }
}

impl Drop for FileUser {
    fn drop(&mut self) {
        if !self.token.is_null() {
            unsafe { CloseHandle(self.token) };
        }
    }
}

/// Ends the thread's impersonation, also when the impersonated code panics.
struct Revert;

impl Drop for Revert {
    fn drop(&mut self) {
        unsafe { RevertToSelf() };
    }
}

/// Whether this process runs as LocalSystem (S-1-5-18). If that cannot be told it is assumed,
/// so files are never read with more rights than the signed-in user has.
fn running_as_system() -> bool {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return true;
        }
        // TOKEN_USER and the SID it points to (at most 68 bytes); u64s keep it aligned.
        let mut buf = [0u64; 16];
        let mut len = 0;
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), size_of_val(&buf) as u32, &mut len);
        CloseHandle(token);
        ok == 0 || IsWellKnownSid((*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid, WinLocalSystemSid) != 0
    }
}

/// The paths in a CF_HDROP block.
unsafe fn drop_list(h: HDROP) -> Vec<PathBuf> {
    let count = unsafe { DragQueryFileW(h, u32::MAX, null_mut(), 0) }.min(MAX_COPIED_FILES);
    let mut out = Vec::new();
    for i in 0..count {
        // Length in characters without the terminating NUL; long paths go up to 32767.
        let len = unsafe { DragQueryFileW(h, i, null_mut(), 0) } as usize;
        if len == 0 || len > 32767 {
            continue;
        }
        let mut buf = vec![0u16; len + 1];
        let n = unsafe { DragQueryFileW(h, i, buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n == 0 || n > len {
            continue;
        }
        out.push(PathBuf::from(OsString::from_wide(&buf[..n])));
    }
    out
}

fn regular_files(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for p in paths {
        // Checked before anything opens it: canonicalize alone already reaches a network path.
        if !drive_letter(&p, false).is_some_and(local_drive) {
            continue;
        }
        let Ok(c) = std::fs::canonicalize(&p) else { continue };
        // A link may lead elsewhere.
        if !drive_letter(&c, true).is_some_and(local_drive) {
            continue;
        }
        if std::fs::metadata(&c).is_ok_and(|m| m.is_file()) && !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// The drive letter of an `X:\...` path, or with `verbatim` of a `\\?\X:\...` one (as
/// `canonicalize` returns them). Every other form is refused: UNC (`\\server\share`,
/// `\\?\UNC\...`), device (`\\.\...`) and object-manager (`\\?\GLOBALROOT\...`) paths reach
/// the network or devices as soon as they are opened, and relative ones depend on the
/// current directory.
fn drive_letter(p: &Path, verbatim: bool) -> Option<u8> {
    let mut c = p.components();
    match (c.next(), c.next()) {
        (Some(Component::Prefix(pre)), Some(Component::RootDir)) => match pre.kind() {
            Prefix::Disk(d) if !verbatim => Some(d),
            Prefix::VerbatimDisk(d) if verbatim => Some(d),
            _ => None,
        },
        _ => None,
    }
}

/// Whether drive `d` is a local volume, not a network share (mapped drives included).
fn local_drive(d: u8) -> bool {
    let root = [d as u16, b':' as u16, b'\\' as u16, 0];
    matches!(unsafe { GetDriveTypeW(root.as_ptr()) }, DRIVE_REMOVABLE | DRIVE_FIXED | DRIVE_CDROM | DRIVE_RAMDISK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::DROPFILES;

    /// A CF_HDROP block as Explorer puts it on the clipboard (DROPFILES + double-NUL list).
    fn hdrop(paths: &[PathBuf]) -> HGLOBAL {
        let mut list: Vec<u16> = Vec::new();
        for p in paths {
            list.extend(p.as_os_str().encode_wide());
            list.push(0);
        }
        list.push(0);
        let header = size_of::<DROPFILES>();
        let df = DROPFILES { pFiles: header as u32, fWide: 1, ..Default::default() };
        let mut bytes = vec![0u8; header];
        unsafe { std::ptr::write_unaligned(bytes.as_mut_ptr() as *mut DROPFILES, df) };
        bytes.extend(list.iter().flat_map(|c| c.to_le_bytes()));
        let h = unsafe { global_copy(&bytes) };
        assert!(!h.is_null());
        h
    }

    #[test]
    fn drop_list_keeps_regular_files_only() {
        let mut r = [0u8; 8];
        crate::crypto::random(&mut r).unwrap();
        let dir = std::env::temp_dir().join(format!("srdp-hdrop-{}", crate::util::hex_encode(&r)));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        std::fs::write(dir.join("파일 b.bin"), b"b").unwrap();
        let listed = [
            dir.join("a.txt"),
            dir.join("sub"),
            dir.join("missing.txt"),
            dir.join("sub").join("..").join("a.txt"),
            PathBuf::from("a.txt"),
            dir.join("파일 b.bin"),
        ];
        let h = hdrop(&listed);
        let names = unsafe { drop_list(h) };
        unsafe { GlobalFree(h) };
        assert_eq!(names, listed);
        let a = std::fs::canonicalize(dir.join("a.txt")).unwrap();
        let files = regular_files(names);
        let expect = [a, std::fs::canonicalize(dir.join("파일 b.bin")).unwrap()];
        assert_eq!(files, expect);
        // A local file named only by verbatim, object-manager and device paths, all of which
        // canonicalize to it: refused before anything opens them.
        std::fs::write(dir.join("c.txt"), b"c").unwrap();
        let c = std::fs::canonicalize(dir.join("c.txt")).unwrap();
        let plain = dir.join("c.txt").display().to_string();
        let raw = [c.clone(), format!(r"\\?\GLOBALROOT\??\{plain}").into(), format!(r"\\.\{plain}").into()];
        for p in &raw {
            assert_eq!(std::fs::canonicalize(p).unwrap(), c, "{}", p.display());
        }
        assert_eq!(regular_files(raw.to_vec()), Vec::<PathBuf>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_drive_letter_paths_are_opened() {
        for p in [r"C:\Users\x\a.txt", r"c:\a", r"D:\", r"C:\dir\..\..\b.txt"] {
            assert!(drive_letter(Path::new(p), false).is_some(), "{p}");
        }
        for p in [
            r"\\server\share\a.txt",
            r"//server/share/a.txt",
            r"\\?\UNC\server\share\a.txt",
            r"\\?\C:\a.txt",
            r"\\?\GLOBALROOT\Device\Mup\server\share\a.txt",
            r"\\.\pipe\x",
            r"\\.\C:\a.txt",
            r"\??\UNC\server\share\a.txt",
            r"\a.txt",
            r"C:a.txt",
            r"a.txt",
            "",
        ] {
            assert_eq!(drive_letter(Path::new(p), false), None, "{p}");
        }
        // Canonical paths are verbatim; only a drive letter may follow.
        assert_eq!(drive_letter(Path::new(r"\\?\C:\a.txt"), true), Some(b'C'));
        for p in [r"C:\a.txt", r"\\?\UNC\server\share\a.txt", r"\\?\Volume{0}\a.txt", r"\\?\GLOBALROOT\Device\x"] {
            assert_eq!(drive_letter(Path::new(p), true), None, "{p}");
        }
        let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert!(drive_letter(&temp, true).is_some_and(local_drive));
    }

    #[test]
    fn a_user_host_reads_files_as_itself() {
        // Tests never run as SYSTEM: no impersonation, and `act` runs on this thread.
        assert!(!running_as_system());
        let user = FileUser::get().unwrap();
        assert!(user.token.is_null());
        let here = std::thread::current().id();
        assert_eq!(user.act(|| std::thread::current().id()).unwrap(), here);
    }

    #[test]
    fn reading_the_clipboard_does_not_fail() {
        // Read-only: whatever is copied right now, every entry must be an existing regular file.
        for p in copied_files() {
            assert!(p.is_absolute() && p.is_file());
        }
    }
}
