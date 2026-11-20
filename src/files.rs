//! File transfer, both directions (viewer → host uploads, host → viewer "pull" of the
//! files on the host's clipboard).
//!
//! Receiving side guarantees:
//! * names are a single plain path component (`proto::valid_file_name`), never a path;
//! * data goes to a hidden, randomly named `.srdp-*.part` file created exclusively, and only
//!   becomes visible after the size and SHA-256 match; anything incomplete is deleted (parts
//!   left behind by a crash or kill are removed after a day);
//! * existing files are never overwritten (`name (1).ext`, `name (2).ext`, ...);
//! * received files are marked as coming from another machine (Windows: Mark of the Web, written
//!   before the file gets its final name), so SmartScreen / Office Protected View treat them as
//!   untrusted; a file that cannot be marked is not published.

use crate::bail;
use crate::crypto::Sha256;
use crate::proto::{MAX_FILE_NAME, MAX_FILE_SIZE, valid_file_name};
use crate::util::Result;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Chunk size used when sending (well below `proto::MAX_FILE_CHUNK`, so frames interleave).
pub const SEND_CHUNK: usize = 256 * 1024;
/// Partial files are `.srdp-<16 hex digits>.part`, independent of the peer's name and id.
const PART_PREFIX: &str = ".srdp-";
const PART_SUFFIX: &str = ".part";
/// A partial file nothing wrote to for this long was left behind by a crash or a kill.
const STALE_PART: Duration = Duration::from_secs(24 * 3600);

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

/// First of `name`, `stem (1).ext`, `stem (2).ext`, ... that does not exist in `dir`; the stem
/// is shortened where needed to keep the name within `MAX_FILE_NAME` bytes.
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 && name.len() - i <= 32 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (1..)
        .map(|n| {
            let suffix = format!(" ({n}){ext}");
            let keep = stem.floor_char_boundary(MAX_FILE_NAME.saturating_sub(suffix.len()));
            dir.join(format!("{}{suffix}", &stem[..keep]))
        })
        .find(|p| !p.exists())
        .unwrap()
}

/// Deletes partial files in `dir` that no transfer has written to for `STALE_PART`.
fn remove_stale_parts(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let name = e.file_name();
        if !name.to_str().is_some_and(|n| n.starts_with(PART_PREFIX) && n.ends_with(PART_SUFFIX)) {
            continue;
        }
        // `DirEntry::metadata` does not follow symlinks: only regular files are removed.
        let age = e.metadata().ok().filter(|m| m.is_file()).and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok());
        if age.is_some_and(|a| a > STALE_PART) {
            let _ = std::fs::remove_file(e.path());
        }
    }
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
        // Checked up front: with a random part name such a name would only fail at the final rename.
        if cfg!(windows) && name.contains(['<', '>', '"', '|', '?', '*']) {
            bail!("{name}: not a valid file name on Windows");
        }
        if size > MAX_FILE_SIZE {
            bail!("file too large");
        }
        remove_stale_parts(dir);
        let mut r = [0u8; 8];
        crate::crypto::random(&mut r)?;
        let part = dir.join(format!("{PART_PREFIX}{}{PART_SUFFIX}", crate::util::hex_encode(&r)));
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
        // Marked while it still has the part's name: the stream moves with the data on rename,
        // whatever name the file ends up with.
        mark_from_other_machine(&self.part).map_err(|e| format!("{}: cannot mark it as coming from another computer: {e}", self.name))?;
        let dest = unique_path(&self.dir, &self.name);
        std::fs::rename(&self.part, &dest)?;
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
fn mark_from_other_machine(path: &Path) -> std::io::Result<()> {
    std::fs::write(zone_identifier(path), ZONE_INTERNET)
}

#[cfg(windows)]
const ZONE_INTERNET: &[u8] = b"[ZoneTransfer]\r\nZoneId=3\r\n";

#[cfg(windows)]
fn zone_identifier(path: &Path) -> PathBuf {
    let mut ads = path.as_os_str().to_owned();
    ads.push(":Zone.Identifier");
    PathBuf::from(ads)
}

#[cfg(not(windows))]
fn mark_from_other_machine(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

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
        // The Mark of the Web travelled with the data, and nothing else was left behind.
        #[cfg(windows)]
        assert_eq!(std::fs::read(zone_identifier(&path)).unwrap(), ZONE_INTERNET);
        assert_eq!(names(&dst_dir), ["report (1).txt", "report.txt"]);
        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&dst_dir);
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    fn receive(dir: &Path, id: u32, name: &str, data: &[u8]) -> PathBuf {
        let mut inc = Incoming::begin(dir, id, data.len() as u64, name).unwrap();
        inc.write(data).unwrap();
        inc.finish(&crate::crypto::sha256(&[data])).unwrap()
    }

    #[test]
    fn parts_are_private_to_each_transfer() {
        let dir = tmpdir("parts");
        // The same name and id twice at once (ids restart in every session): no collision.
        let mut a = Incoming::begin(&dir, 1, 1, "same.bin").unwrap();
        let mut b = Incoming::begin(&dir, 1, 1, "same.bin").unwrap();
        let parts = names(&dir);
        assert_eq!(parts.len(), 2);
        assert!(parts.iter().all(|n| n.starts_with(PART_PREFIX) && n.ends_with(PART_SUFFIX) && n.len() == 6 + 16 + 5), "{parts:?}");
        a.write(b"a").unwrap();
        b.write(b"b").unwrap();
        a.finish(&crate::crypto::sha256(&[b"a"])).unwrap();
        b.finish(&crate::crypto::sha256(&[b"b"])).unwrap();
        assert_eq!(names(&dir), ["same (1).bin", "same.bin"]);

        // Parts abandoned by a crash go once they are a day old; nothing else is touched.
        let old = std::time::SystemTime::now() - 2 * STALE_PART;
        for n in [".srdp-00112233445566ff.part", "keep.part", ".srdp-notes.txt"] {
            std::fs::File::create(dir.join(n)).unwrap().set_modified(old).unwrap();
        }
        std::fs::write(dir.join(".srdp-ffeeddccbbaa0099.part"), b"in use").unwrap();
        let c = Incoming::begin(&dir, 2, 1, "c.bin").unwrap();
        let left = names(&dir);
        assert!(!left.contains(&".srdp-00112233445566ff.part".to_string()), "{left:?}");
        for n in [".srdp-ffeeddccbbaa0099.part", "keep.part", ".srdp-notes.txt"] {
            assert!(left.contains(&n.to_string()), "{n} removed");
        }
        drop(c);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn long_names_still_get_unique_names() {
        let dir = tmpdir("long");
        let name = format!("{}.txt", "가".repeat(83)); // 253 bytes
        assert_eq!(receive(&dir, 1, &name, b"1").file_name().unwrap().to_str().unwrap(), name);
        let second = receive(&dir, 1, &name, b"2");
        let second = second.file_name().unwrap().to_str().unwrap();
        assert!(second.len() <= MAX_FILE_NAME && second.ends_with(" (1).txt") && second.starts_with("가가"), "{second}");
        // An overlong "extension" is not kept whole.
        let odd = format!("a.{}", "x".repeat(250));
        receive(&dir, 2, &odd, b"1");
        let p = receive(&dir, 2, &odd, b"2");
        let n = p.file_name().unwrap().to_str().unwrap();
        assert!(n.len() <= MAX_FILE_NAME && n.ends_with(" (1)"), "{n}");
        assert_eq!(names(&dir).len(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_bad_names_overflow_and_checksum() {
        let dir = tmpdir("bad");
        assert!(Incoming::begin(&dir, 1, 1, "../x").is_err());
        assert!(Incoming::begin(&dir, 1, 1, "a\\b").is_err());
        // Names Windows would save under another name (losing the Mark of the Web) or as a device.
        for bad in ["setup.exe.", "doc.docm ", "NUL.txt", "com1", "x\u{202E}gpj.exe"] {
            assert!(Incoming::begin(&dir, 1, 1, bad).is_err(), "{bad:?}");
        }
        assert_eq!(Incoming::begin(&dir, 1, 1, "what?.txt").is_err(), cfg!(windows));
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
