//! File transfer, both directions (viewer → host uploads, host → viewer "pull" of the
//! files on the host's clipboard).
//!
//! Receiving side guarantees:
//! * names are a single plain path component (`proto::valid_file_name`), never a path;
//! * data goes to a hidden `.part` file created exclusively, and only becomes visible after
//!   the size and SHA-256 match; anything incomplete is deleted;
//! * existing files are never overwritten (`name (1).ext`, `name (2).ext`, ...);
//! * received files are marked as coming from another machine (Windows: Mark of the Web),
//!   so SmartScreen / Office Protected View treat them as untrusted.

use crate::bail;
use crate::crypto::Sha256;
use crate::proto::{MAX_FILE_SIZE, valid_file_name};
use crate::util::Result;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Chunk size used when sending (well below `proto::MAX_FILE_CHUNK`, so frames interleave).
pub const SEND_CHUNK: usize = 256 * 1024;

/// `Downloads/safe-rdp` in the current user's profile; created on demand.
pub fn transfer_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("USERPROFILE").map(PathBuf::from).ok_or("%USERPROFILE% is not set")?.join("Downloads");
    #[cfg(not(windows))]
    let base = match std::env::var_os("XDG_DOWNLOAD_DIR").filter(|v| !v.is_empty()) {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(std::env::var_os("HOME").ok_or("$HOME is not set")?).join("Downloads"),
    };
    let dir = base.join("safe-rdp");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// First of `name`, `stem (1).ext`, `stem (2).ext`, ... that does not exist in `dir`.
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (1..).map(|n| dir.join(format!("{stem} ({n}){ext}"))).find(|p| !p.exists()).unwrap()
}

/// A file being received.
pub struct Incoming {
    pub id: u32,
    pub name: String,
    pub size: u64,
    received: u64,
    dir: PathBuf,
    part: PathBuf,
    file: Option<File>,
    hash: Sha256,
}

impl Incoming {
    pub fn begin(dir: &Path, id: u32, size: u64, name: &str) -> Result<Incoming> {
        if !valid_file_name(name) {
            bail!("invalid file name");
        }
        if size > MAX_FILE_SIZE {
            bail!("file too large");
        }
        let part = dir.join(format!(".{name}.{id}.part"));
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&part)?;
        Ok(Incoming { id, name: name.to_string(), size, received: 0, dir: dir.to_path_buf(), part, file: Some(file), hash: Sha256::new() })
    }

    pub fn received(&self) -> u64 {
        self.received
    }

    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        if self.received + data.len() as u64 > self.size {
            bail!("{}: more data than announced", self.name);
        }
        self.file.as_mut().unwrap().write_all(data)?;
        self.hash.update(data);
        self.received += data.len() as u64;
        Ok(())
    }

    /// Verifies size and checksum, then moves the file into place. Returns the final path.
    pub fn finish(mut self, sha256: &[u8; 32]) -> Result<PathBuf> {
        if self.received != self.size {
            bail!("{}: received {} of {} bytes", self.name, self.received, self.size);
        }
        let mut file = self.file.take().unwrap();
        file.flush()?;
        file.sync_all()?;
        drop(file);
        let hash = std::mem::replace(&mut self.hash, Sha256::new()).finish();
        if !crate::crypto::ct_eq(&hash, sha256) {
            bail!("{}: checksum mismatch", self.name);
        }
        let dest = unique_path(&self.dir, &self.name);
        std::fs::rename(&self.part, &dest)?;
        mark_from_other_machine(&dest);
        Ok(dest)
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        // Not finished (or finish failed): remove the partial file.
        self.file.take();
        let _ = std::fs::remove_file(&self.part);
    }
}

/// Windows: attach a Zone.Identifier stream (Internet zone), like a browser download.
#[cfg(windows)]
fn mark_from_other_machine(path: &Path) {
    let mut ads = path.as_os_str().to_owned();
    ads.push(":Zone.Identifier");
    let _ = std::fs::write(PathBuf::from(ads), b"[ZoneTransfer]\r\nZoneId=3\r\n");
}

#[cfg(not(windows))]
fn mark_from_other_machine(_path: &Path) {}

/// A file being sent.
pub struct Outgoing {
    pub id: u32,
    pub name: String,
    pub size: u64,
    file: File,
    sent: u64,
    hash: Sha256,
}

impl Outgoing {
    pub fn open(path: &Path, id: u32) -> Result<Outgoing> {
        let meta = std::fs::metadata(path)?;
        if !meta.is_file() {
            bail!("{} is not a regular file", path.display());
        }
        if meta.len() > MAX_FILE_SIZE {
            bail!("{} is too large", path.display());
        }
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if !valid_file_name(&name) {
            bail!("unsupported file name: {}", path.display());
        }
        Ok(Outgoing { id, name, size: meta.len(), file: File::open(path)?, sent: 0, hash: Sha256::new() })
    }

    pub fn sent(&self) -> u64 {
        self.sent
    }

    /// Reads the next chunk into `buf`; returns false at end of file.
    pub fn next_chunk(&mut self, buf: &mut Vec<u8>) -> Result<bool> {
        buf.resize(SEND_CHUNK, 0);
        let n = self.file.read(buf)?;
        buf.truncate(n);
        if n == 0 {
            if self.sent != self.size {
                bail!("{} changed while it was being sent", self.name);
            }
            return Ok(false);
        }
        self.sent += n as u64;
        if self.sent > self.size {
            bail!("{} grew while it was being sent", self.name);
        }
        self.hash.update(buf);
        Ok(true)
    }

    pub fn finish(self) -> [u8; 32] {
        self.hash.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let mut r = [0u8; 8];
        crate::crypto::random(&mut r).unwrap();
        let d = std::env::temp_dir().join(format!("srdp-test-{tag}-{}", crate::util::hex_encode(&r)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn roundtrip_and_no_overwrite() {
        let src_dir = tmpdir("src");
        let dst_dir = tmpdir("dst");
        let src = src_dir.join("report.txt");
        let content: Vec<u8> = (0..700_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &content).unwrap();
        std::fs::write(dst_dir.join("report.txt"), b"existing").unwrap();

        let mut out = Outgoing::open(&src, 1).unwrap();
        let mut inc = Incoming::begin(&dst_dir, out.id, out.size, &out.name).unwrap();
        let mut buf = Vec::new();
        while out.next_chunk(&mut buf).unwrap() {
            inc.write(&buf).unwrap();
        }
        let path = inc.finish(&out.finish()).unwrap();
        assert_eq!(path.file_name().unwrap(), "report (1).txt");
        assert_eq!(std::fs::read(&path).unwrap(), content);
        assert_eq!(std::fs::read(dst_dir.join("report.txt")).unwrap(), b"existing");
        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&dst_dir);
    }

    #[test]
    fn rejects_bad_names_overflow_and_checksum() {
        let dir = tmpdir("bad");
        assert!(Incoming::begin(&dir, 1, 1, "../x").is_err());
        assert!(Incoming::begin(&dir, 1, 1, "a\\b").is_err());
        let mut inc = Incoming::begin(&dir, 2, 3, "x.bin").unwrap();
        assert!(inc.write(b"abcd").is_err());
        inc.write(b"abc").unwrap();
        assert!(inc.finish(&[0u8; 32]).is_err());
        // The partial file is gone and nothing was published.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let inc = Incoming::begin(&dir, 3, 10, "short.bin").unwrap();
        drop(inc);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
