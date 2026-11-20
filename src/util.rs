//! Small shared helpers: error type, logging, wide strings, secret wiping.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{Ordering, compiler_fence};
use std::sync::{Mutex, OnceLock, PoisonError};

#[derive(Debug)]
pub struct Error(String);

impl Error {
    pub fn msg(s: impl Into<String>) -> Self {
        Error(s.into())
    }

    /// Error carrying the calling thread's last Win32 error code.
    pub fn last_os(what: &str) -> Self {
        Error(format!("{what} failed: {}", std::io::Error::last_os_error()))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[macro_export]
macro_rules! bail {
    ($($t:tt)*) => { return Err($crate::util::Error::msg(format!($($t)*))) };
}

#[macro_export]
macro_rules! log {
    ($($t:tt)*) => { $crate::util::log_line(&format!($($t)*)) };
}

#[cfg_attr(not(windows), allow(dead_code))] // the service and the Windows UI
/// Size at which the log file is moved to `<name>.old` and started afresh.
const LOG_LIMIT: u64 = 4 << 20;

static LOG_FILE: OnceLock<Mutex<LogFile>> = OnceLock::new();

#[cfg_attr(not(windows), allow(dead_code))] // the service and the Windows UI
/// Mirror log lines into `path` (append). Logs never contain key material or screen data.
/// The file stays bounded however long the process runs: past 4 MiB it becomes `<name>.old`
/// (replacing the previous one) and a new one is started.
pub fn set_log_file(path: &Path) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let log = LogFile::open(path, LOG_LIMIT)?;
    let _ = LOG_FILE.set(Mutex::new(log));
    Ok(())
}

pub fn log_line(msg: &str) {
    let [y, mo, d, h, mi, s] = crate::platform::local_time();
    let line = format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} {msg}\n");
    let _ = std::io::stderr().write_all(line.as_bytes());
    if let Some(f) = LOG_FILE.get() {
        f.lock().unwrap_or_else(PoisonError::into_inner).write(line.as_bytes());
    }
}

/// A log file of bounded size. Writing never fails the caller: a line that cannot be written
/// is dropped (it still went to stderr).
struct LogFile {
    path: PathBuf,
    limit: u64,
    file: Option<File>,
    /// Bytes in the file (as of opening it) plus those written since.
    len: u64,
}

impl LogFile {
    #[cfg_attr(not(windows), allow(dead_code))] // the service and the Windows UI
    fn open(path: &Path, limit: u64) -> std::io::Result<LogFile> {
        let mut log = LogFile { path: path.to_path_buf(), limit, file: None, len: 0 };
        if std::fs::metadata(path).is_ok_and(|m| m.len() >= limit) {
            log.rotate();
        }
        log.attach()?;
        Ok(log)
    }

    /// Opens the file for appending (another process may append too) and notes its length.
    fn attach(&mut self) -> std::io::Result<()> {
        let f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        self.len = f.metadata()?.len();
        self.file = Some(f);
        Ok(())
    }

    /// Moves the file to `<name>.old`; where that is impossible (the old copy is held open
    /// elsewhere), empties it instead. The next write starts a new file.
    fn rotate(&mut self) {
        self.file = None;
        let mut old = self.path.clone().into_os_string();
        old.push(".old");
        if std::fs::rename(&self.path, &old).is_err() {
            let _ = OpenOptions::new().write(true).truncate(true).open(&self.path);
        }
    }

    fn write(&mut self, line: &[u8]) {
        if self.file.is_some() && self.len > 0 && self.len + line.len() as u64 > self.limit {
            self.rotate();
        }
        if self.file.is_none() && self.attach().is_err() {
            return;
        }
        if let Some(f) = &mut self.file {
            if f.write_all(line).is_ok() {
                self.len += line.len() as u64;
            }
        }
    }
}

/// NUL-terminated UTF-16 string for Win32 APIs.
#[cfg_attr(not(windows), allow(dead_code))] // the service and the Windows UI
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg_attr(not(windows), allow(dead_code))] // the service and the Windows UI
pub fn from_wide(s: &[u16]) -> String {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end])
}

/// Overwrite memory in a way the optimizer may not elide.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Fixed-size secret that is wiped when dropped.
pub struct Secret<const N: usize>(pub [u8; N]);

impl<const N: usize> Secret<N> {
    pub fn zero() -> Self {
        Secret([0u8; N])
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Heap buffer that is wiped when dropped (used for frame buffers and plaintext records).
#[derive(Default)]
pub struct SecureVec(pub Vec<u8>);

impl Drop for SecureVec {
    fn drop(&mut self) {
        // Wipe the whole allocation, including spare capacity, through a raw pointer.
        let p = self.0.as_mut_ptr();
        for i in 0..self.0.capacity() {
            unsafe { std::ptr::write_volatile(p.add(i), 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

pub fn hex_encode(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if s.len() % 2 != 0 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.chunks(2).map(|p| Some(nib(p[0])? << 4 | nib(p[1])?)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let v = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex_encode(&v), "0001abff");
        assert_eq!(hex_decode("0001ABff").unwrap(), v);
        assert!(hex_decode("0g").is_none());
        assert!(hex_decode("abc").is_none());
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let mut r = [0u8; 8];
        crate::crypto::random(&mut r).unwrap();
        let d = std::env::temp_dir().join(format!("srdp-log-{tag}-{}", hex_encode(&r)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn read(p: &Path) -> String {
        String::from_utf8(std::fs::read(p).unwrap()).unwrap()
    }

    #[test]
    fn log_file_stays_bounded() {
        let dir = tmpdir("rotate");
        let (path, old) = (dir.join("host.log"), dir.join("host.log.old"));
        let mut log = LogFile::open(&path, 100).unwrap();
        for i in 0..40 {
            log.write(format!("line {i:02}\n").as_bytes());
        }
        // 8 bytes a line: 12 fit; the newest are in the file, the 12 before them in `.old`.
        let (cur, prev) = (read(&path), read(&old));
        assert!(cur.len() <= 100 && prev.len() <= 100);
        assert!(cur.ends_with("line 39\n") && cur.starts_with("line 36\n"), "{cur}");
        assert!(prev.ends_with("line 35\n") && prev.starts_with("line 24\n"), "{prev}");
        drop(log);

        // An existing log is appended to while below the limit, moved aside when above it.
        let log = LogFile::open(&path, 100).unwrap();
        assert_eq!(log.len, cur.len() as u64);
        drop(log);
        std::fs::write(&path, [b'x'; 150]).unwrap();
        let mut log = LogFile::open(&path, 100).unwrap();
        log.write(b"fresh\n");
        assert_eq!(read(&path), "fresh\n");
        assert_eq!(std::fs::metadata(&old).unwrap().len(), 150);
        // A line longer than the limit is still written, once.
        log.write(&[b'y'; 120]);
        log.write(b"next\n");
        assert_eq!(read(&path), "next\n");
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn log_file_is_emptied_when_the_old_copy_is_locked() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tmpdir("locked");
        let (path, old) = (dir.join("host.log"), dir.join("host.log.old"));
        std::fs::write(&old, b"kept").unwrap();
        // Held open without FILE_SHARE_DELETE: it cannot be replaced.
        let hold = OpenOptions::new().read(true).share_mode(1).open(&old).unwrap();
        let mut log = LogFile::open(&path, 50).unwrap();
        for i in 0..20 {
            log.write(format!("line {i:02}\n").as_bytes());
        }
        assert!(read(&path).len() <= 50);
        assert!(read(&path).ends_with("line 19\n"));
        drop(hold);
        assert_eq!(read(&old), "kept");
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
