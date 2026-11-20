//! Small shared helpers: error type, logging, wide strings, secret wiping.

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{Ordering, compiler_fence};
use std::sync::{Mutex, OnceLock};

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

static LOG_FILE: OnceLock<Mutex<File>> = OnceLock::new();

/// Mirror log lines into `path` (append). Logs never contain key material or screen data.
pub fn set_log_file(path: &std::path::Path) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Keep the log bounded: start over once it grows past 4 MiB.
    let truncate = std::fs::metadata(path).map(|m| m.len() > 4 << 20).unwrap_or(false);
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(!truncate)
        .write(true)
        .truncate(truncate)
        .open(path)?;
    let _ = LOG_FILE.set(Mutex::new(f));
    Ok(())
}

pub fn log_line(msg: &str) {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    let mut t = unsafe { std::mem::zeroed() };
    unsafe { GetLocalTime(&mut t) };
    let line = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {msg}\n",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
    );
    let _ = std::io::stderr().write_all(line.as_bytes());
    if let Some(f) = LOG_FILE.get() {
        if let Ok(mut f) = f.lock() {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// NUL-terminated UTF-16 string for Win32 APIs.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

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
}
