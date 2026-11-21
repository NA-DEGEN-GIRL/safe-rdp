//! File transfer, both directions (viewer → host uploads, host → viewer "pull" of the
//! files on the host's clipboard).
//!
//! Receiving side guarantees:
//! * names are a single plain path component (`proto::valid_file_name`), never a path;
//! * data goes to a hidden, randomly named `.srdp-*.part` file created exclusively (on Windows
//!   nobody else can write, delete or rename it while the transfer holds it; elsewhere a
//!   same-user program could still alter it, which only a length check catches), and only
//!   becomes visible after the size and SHA-256 match and the part still holds that many bytes;
//!   anything incomplete is
//!   deleted (parts left behind by a crash or kill are removed after a day);
//! * existing files are never overwritten (`name (1).ext`, `name (2).ext`, ...);
//! * received files are marked as coming from another machine (Windows: Mark of the Web, written
//!   when the part is created), so SmartScreen / Office Protected View treat them as untrusted;
//!   a transfer whose file cannot be marked is refused;
//! * nothing is saved into the folder the running program was started from, where Windows looks
//!   for its DLLs (and the programs it runs) first;
//! * a file is accepted only if its volume keeps a reserve of free space (`Reserve`: a small one,
//!   a larger one for the service's own folder) once it and every other transfer still arriving
//!   are complete; a transfer that would eat into the reserve after all (something else filled
//!   the disk) is stopped.

use crate::bail;
use crate::crypto::Sha256;
use crate::proto::{MAX_FILE_NAME, MAX_FILE_SIZE, valid_file_name};
use crate::util::Result;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Chunk size used when sending (well below `proto::MAX_FILE_CHUNK`, so frames interleave).
pub const SEND_CHUNK: usize = 256 * 1024;
/// Partial files are `.srdp-<16 hex digits>.part`, independent of the peer's name and id.
const PART_PREFIX: &str = ".srdp-";
const PART_SUFFIX: &str = ".part";
/// A partial file nothing wrote to for this long was left behind by a crash or a kill.
const STALE_PART: Duration = Duration::from_secs(24 * 3600);
/// Free space a received file never takes from its volume (`Reserve`): 1% of it, within these
/// bounds...
const MIN_RESERVE: u64 = 256 << 20;
const MAX_RESERVE: u64 = 2 << 30;
/// ...or 5% of it, within these, for the service's own folder.
const MIN_SERVICE_RESERVE: u64 = 1 << 30;
const MAX_SERVICE_RESERVE: u64 = 16 << 30;
/// How often (in bytes received) a transfer looks at the free space again.
const SPACE_RECHECK: u64 = 64 << 20;

/// Bytes the transfers of this process have announced but not yet written: each one is
/// admitted only if the volume can take it on top of these.
static PROMISED: AtomicU64 = AtomicU64::new(0);

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
        // Not `DirEntry::metadata`: on Windows that is the directory entry, which shows a part still
        // being written with the time it was created. Symlinks are not followed: only regular files go.
        let meta = std::fs::symlink_metadata(e.path());
        let age = meta.ok().filter(|m| m.is_file()).and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok());
        if age.is_some_and(|a| a > STALE_PART) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Whether `dir` is the folder the running program was started from. Windows looks there first
/// for the DLLs a program loads and for the programs it starts, so a received `dxgi.dll` or
/// `netsh.exe` saved there would run with the program's rights. A folder that cannot be resolved
/// counts as another one: `dir` then does not exist, and the program's own folder resolves for
/// every account that could save anything into it.
fn is_program_dir(dir: &Path) -> bool {
    let Some(exe_dir) = std::env::current_exe().ok().and_then(|e| e.parent().and_then(|d| std::fs::canonicalize(d).ok())) else {
        return false;
    };
    std::fs::canonicalize(dir).is_ok_and(|d| d == exe_dir)
}

/// The refusal for a folder `is_program_dir` found, saying what to do about it. Its reader may
/// sit at the other computer (a refused upload), hence "the program receiving this file".
fn program_dir_refusal(dir: &Path) -> String {
    let exe = std::env::current_exe().ok().and_then(|e| e.file_name().map(|n| n.to_string_lossy().into_owned()));
    let exe = exe.unwrap_or_else(|| "safe-rdp".into());
    format!(
        "the {exe} receiving this file runs from {}, where received files are saved, and nothing is saved next to a running program: move {exe} to another folder (the Desktop, for example), start it there and try again",
        dir.display()
    )
}

/// Free space a received file must leave on its volume.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reserve {
    /// 1% of the volume, 256 MiB to 2 GiB: no transfer runs a disk full, and a small file still
    /// fits on a nearly full one while gigabytes are free.
    Ordinary,
    /// 5% of the volume, 1 to 16 GiB: the service's own folder, on the system volume, which a
    /// viewer can fill even at the sign-in screen and only an administrator can empty.
    ServiceFolder,
}

impl Reserve {
    /// Bytes to leave free on a volume of `total` bytes.
    fn of(self, total: u64) -> u64 {
        match self {
            Reserve::Ordinary => (total / 100).clamp(MIN_RESERVE, MAX_RESERVE),
            Reserve::ServiceFolder => (total / 20).clamp(MIN_SERVICE_RESERVE, MAX_SERVICE_RESERVE),
        }
    }
}

/// Whether `need` more bytes fit on a volume with `space` = (free, total) bytes and still leave
/// `keep`; otherwise the bytes `keep` asks for. A volume that reports no size cannot be judged.
fn room(space: Option<(u64, u64)>, need: u64, keep: Reserve) -> std::result::Result<(), u64> {
    match space {
        Some((free, total)) if total > 0 && free.saturating_sub(need) < keep.of(total) => Err(keep.of(total)),
        _ => Ok(()),
    }
}

/// `bytes` for a message: whole MiB below 1 GiB, GiB to one decimal from there.
fn amount(bytes: u64) -> String {
    if bytes < 1 << 30 {
        format!("{} MiB", bytes >> 20)
    } else {
        format!("{:.1} GiB", bytes as f64 / (1u64 << 30) as f64)
    }
}

/// Free and total bytes of the volume that holds the open file `f`, by its handle: whatever its
/// path leads to by now, this is where the data goes.
#[cfg(windows)]
fn space(f: &File) -> Option<(u64, u64)> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    /// FILE_FS_FULL_SIZE_INFORMATION (ntifs.h).
    #[repr(C)]
    #[derive(Default)]
    struct FullSize {
        total_units: i64,
        caller_free_units: i64,
        actual_free_units: i64,
        sectors_per_unit: u32,
        bytes_per_sector: u32,
    }
    #[link(name = "ntdll", kind = "raw-dylib")]
    unsafe extern "system" {
        fn NtQueryVolumeInformationFile(file: HANDLE, io: *mut IO_STATUS_BLOCK, info: *mut c_void, len: u32, class: i32) -> i32;
    }
    /// FS_INFORMATION_CLASS FileFsFullSizeInformation.
    const FILE_FS_FULL_SIZE_INFORMATION: i32 = 7;
    let mut info = FullSize::default();
    let mut io: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let (h, len) = (f.as_raw_handle() as HANDLE, size_of::<FullSize>() as u32);
    let status = unsafe { NtQueryVolumeInformationFile(h, &mut io, &mut info as *mut FullSize as *mut c_void, len, FILE_FS_FULL_SIZE_INFORMATION) };
    if status < 0 {
        return None;
    }
    let unit = info.sectors_per_unit as u64 * info.bytes_per_sector as u64;
    // What a disk quota leaves this account, if less than what is left on the volume.
    let free = info.caller_free_units.min(info.actual_free_units).max(0) as u64;
    Some((free.saturating_mul(unit), (info.total_units.max(0) as u64).saturating_mul(unit)))
}

#[cfg(not(windows))]
fn space(f: &File) -> Option<(u64, u64)> {
    use std::ffi::{c_int, c_ulong};
    use std::os::fd::AsRawFd;
    /// The start of `struct statvfs` (glibc and musl); the rest is never read but must fit.
    #[repr(C)]
    struct StatVfs {
        bsize: c_ulong,
        frsize: c_ulong,
        blocks: c_ulong,
        bfree: c_ulong,
        bavail: c_ulong,
        rest: [c_ulong; 16],
    }
    unsafe extern "C" {
        fn fstatvfs(fd: c_int, buf: *mut StatVfs) -> c_int;
    }
    let mut st: StatVfs = unsafe { std::mem::zeroed() };
    if unsafe { fstatvfs(f.as_raw_fd(), &mut st) } != 0 {
        return None;
    }
    let unit = (if st.frsize != 0 { st.frsize } else { st.bsize }) as u64;
    // `bavail`, not `bfree`: the blocks kept for root are no use to us.
    Some(((st.bavail as u64).saturating_mul(unit), (st.blocks as u64).saturating_mul(unit)))
}

/// Bytes in the regular files directly inside `dir`, and its number of entries of any kind
/// (links are counted, never followed).
pub fn dir_usage(dir: &Path) -> Result<(u64, usize)> {
    let (mut bytes, mut entries) = (0u64, 0usize);
    for e in std::fs::read_dir(dir)? {
        entries += 1;
        // Not `DirEntry::metadata`: on Windows that shows a part being written at its old length.
        let meta = std::fs::symlink_metadata(e?.path());
        bytes = bytes.saturating_add(meta.ok().filter(|m| m.is_file()).map_or(0, |m| m.len()));
    }
    Ok((bytes, entries))
}

/// A file being received.
pub struct Incoming {
    pub id: u32,
    pub name: String,
    pub size: u64,
    received: u64,
    /// Bytes announced but not received yet, counted in `PROMISED` until they arrive.
    promised: u64,
    /// `received` at which the free space is looked at again.
    next_check: u64,
    /// Free space the volume keeps while this file arrives.
    reserve: Reserve,
    dir: PathBuf,
    part: PathBuf,
    file: Option<File>,
    hash: Sha256,
}

impl Incoming {
    /// Starts receiving `name` into `dir`, leaving the volume the `Ordinary` reserve.
    pub fn begin(dir: &Path, id: u32, size: u64, name: &str) -> Result<Incoming> {
        Incoming::begin_keeping(dir, id, size, name, Reserve::Ordinary)
    }

    /// `begin`, leaving the volume `reserve` instead.
    pub fn begin_keeping(dir: &Path, id: u32, size: u64, name: &str, reserve: Reserve) -> Result<Incoming> {
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
        if is_program_dir(dir) {
            bail!("{}", program_dir_refusal(dir));
        }
        remove_stale_parts(dir);
        let mut r = [0u8; 8];
        crate::crypto::random(&mut r)?;
        let part = dir.join(format!("{PART_PREFIX}{}{PART_SUFFIX}", crate::util::hex_encode(&r)));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Foundation::GENERIC_WRITE;
            use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_SHARE_READ};
            // Nobody else may write, truncate, delete or rename the part while it is being
            // written (the Zone.Identifier stream is shared separately). DELETE: an abandoned
            // part is removed through this handle, not by its path.
            options.access_mode(GENERIC_WRITE | DELETE).share_mode(FILE_SHARE_READ);
        }
        let file = options.open(&part)?;
        let hash = Sha256::new();
        // Counted before the check, so transfers starting at the same time see each other
        // (`inc` gives the bytes back when it is dropped).
        let need = PROMISED.fetch_add(size, Ordering::SeqCst).saturating_add(size);
        let inc = Incoming {
            id,
            name: name.to_string(),
            size,
            received: 0,
            promised: size,
            next_check: SPACE_RECHECK,
            reserve,
            dir: dir.to_path_buf(),
            part,
            file: Some(file),
            hash,
        };
        // On the volume the part is on, whatever `dir` leads to.
        if let Err(keep) = room(space(inc.file.as_ref().unwrap()), need, reserve) {
            bail!("not enough disk space for {name} ({size} bytes): at least {} has to stay free", amount(keep));
        }
        // Marked before any data arrives (dropping `inc` on failure removes the part): the stream
        // moves with the data on rename, whatever name the file ends up with.
        mark_from_other_machine(&inc.part).map_err(|e| format!("{name}: cannot mark it as coming from another computer: {e}"))?;
        Ok(inc)
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
        self.promised -= data.len() as u64;
        PROMISED.fetch_sub(data.len() as u64, Ordering::SeqCst);
        if self.received >= self.next_check {
            self.next_check = self.received.saturating_add(SPACE_RECHECK);
            // Something else may have filled the disk since this transfer was admitted.
            if let Err(keep) = room(space(self.file.as_ref().unwrap()), PROMISED.load(Ordering::SeqCst), self.reserve) {
                bail!("{}: stopped, the disk is nearly full (at least {} has to stay free)", self.name, amount(keep));
            }
        }
        Ok(())
    }

    /// Verifies size and checksum, and that the part on disk still holds all of it, then moves
    /// the file into place. Returns the final path.
    pub fn finish(mut self, sha256: &[u8; 32]) -> Result<PathBuf> {
        if self.received != self.size {
            bail!("{}: received {} of {} bytes", self.name, self.received, self.size);
        }
        // Checked while the part is still open, so a mismatch removes it through its handle.
        let hash = std::mem::replace(&mut self.hash, Sha256::new()).finish();
        if !crate::crypto::ct_eq(&hash, sha256) {
            bail!("{}: checksum mismatch", self.name);
        }
        let mut file = self.file.take().unwrap();
        file.flush()?;
        file.sync_all()?;
        drop(file);
        // The checksum covers the bytes as they arrived, not the file: one that was cut short or
        // removed (and the rename then fails) since is not published.
        let meta = std::fs::symlink_metadata(&self.part)?;
        if !meta.is_file() || meta.len() != self.size {
            bail!("{}: the partial file was changed by another program", self.name);
        }
        let dest = unique_path(&self.dir, &self.name);
        std::fs::rename(&self.part, &dest)?;
        Ok(dest)
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        PROMISED.fetch_sub(self.promised, Ordering::SeqCst);
        // Not finished (or finish failed): remove the partial file.
        let file = self.file.take();
        // Still open (Windows): removed through its handle as it closes, never by its path, which
        // may lead elsewhere by now (a host running as SYSTEM drops uploads to a folder a user
        // controls). A part that cannot be removed even so is swept once it is a day old.
        #[cfg(windows)]
        if let Some(f) = &file {
            delete_on_close(f);
            return;
        }
        drop(file);
        let _ = std::fs::remove_file(&self.part);
    }
}

/// Marks the open file `f` for deletion once its last handle is closed.
#[cfg(windows)]
fn delete_on_close(f: &File) {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle};
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    let len = size_of::<FILE_DISPOSITION_INFO>() as u32;
    unsafe { SetFileInformationByHandle(f.as_raw_handle() as HANDLE, FileDispositionInfo, &info as *const _ as *const c_void, len) };
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

    #[cfg_attr(not(windows), allow(dead_code))] // used by the Windows UI
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
    fn the_sweep_goes_by_the_file_not_its_directory_entry() {
        let dir = tmpdir("sweep");
        // Created long ago, written just now through a handle that is still open: on Windows its
        // directory entry still shows the old time (and the old length) until the handle closes.
        let part = dir.join(".srdp-0123456789abcdef.part");
        std::fs::File::create(&part).unwrap().set_modified(std::time::SystemTime::now() - 2 * STALE_PART).unwrap();
        let mut f = std::fs::OpenOptions::new().write(true).open(&part).unwrap();
        f.write_all(&[1; 200_000]).unwrap();
        remove_stale_parts(&dir);
        assert!(part.exists());
        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_part_changed_behind_the_transfer_is_never_published() {
        let dir = tmpdir("changed");
        let data = [7u8; 4096];
        let sum = crate::crypto::sha256(&[&data]);
        // Marked from the start, so finishing never has to create anything on disk.
        let mut inc = Incoming::begin(&dir, 1, 4096, "big.iso").unwrap();
        #[cfg(windows)]
        assert_eq!(std::fs::read(zone_identifier(&inc.part)).unwrap(), ZONE_INTERNET);
        inc.write(&data).unwrap();
        // Another program writing to the part: Windows refuses it outright; elsewhere a part cut
        // short is caught by the length check (what arrived still matches the checksum).
        let writer = std::fs::OpenOptions::new().write(true).open(&inc.part);
        if cfg!(windows) {
            assert!(writer.is_err(), "another program could write to the part");
            drop(inc);
        } else {
            writer.unwrap().set_len(0).unwrap();
            assert!(inc.finish(&sum).is_err());
        }
        assert!(names(&dir).is_empty());

        // Removed: Windows refuses while the transfer holds the part; elsewhere finishing fails.
        let mut inc = Incoming::begin(&dir, 2, 4096, "big.iso").unwrap();
        inc.write(&data).unwrap();
        assert_eq!(std::fs::remove_file(&inc.part).is_err(), cfg!(windows));
        match inc.finish(&sum) {
            Ok(path) => {
                assert!(cfg!(windows));
                assert_eq!(std::fs::read(path).unwrap(), data);
            }
            Err(_) => assert!(names(&dir).is_empty()),
        }
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

    #[cfg(windows)]
    fn junction(link: &Path, target: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    fn refused(dir: &Path, name: &str) -> String {
        match Incoming::begin(dir, 1, 1, name) {
            Ok(_) => panic!("{name} would have been saved in {}", dir.display()),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn nothing_is_saved_next_to_the_program() {
        let exe_dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
        let parts = |d: &Path| names(d).into_iter().filter(|n| n.starts_with(PART_PREFIX)).count();
        let before = parts(&exe_dir);
        // The refusal names the program and its folder, and says what to do, on either computer.
        let exe = std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().into_owned();
        let e = refused(&exe_dir, "dxgi.dll");
        let what = format!("the {exe} receiving this file runs from {}", exe_dir.display());
        assert!(e.starts_with(&what) && e.contains(&format!("move {exe} to another folder")), "{e}");
        // However the folder is spelled.
        let other = exe_dir.join("..").join(exe_dir.file_name().unwrap()).join(".");
        assert!(refused(&other, "netsh.exe").contains("next to a running program"));
        assert_eq!(parts(&exe_dir), before, "a partial file was created");
        // Or reached through a link.
        #[cfg(windows)]
        {
            let t = tmpdir("exe-link");
            if junction(&t.join("j"), &exe_dir) {
                assert!(refused(&t.join("j"), "wtsapi32.dll").contains("next to a running program"));
                std::fs::remove_dir(t.join("j")).unwrap();
            }
            let _ = std::fs::remove_dir_all(&t);
        }
        // Any other folder is fine.
        let dir = tmpdir("not-exe");
        assert_eq!(receive(&dir, 1, "dxgi.dll", b"x").file_name().unwrap(), "dxgi.dll");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn received_files_leave_a_reserve() {
        const G: u64 = 1 << 30;
        const M: u64 = 1 << 20;
        let (any, service) = (Reserve::Ordinary, Reserve::ServiceFolder);
        assert_eq!(any.of(0), 256 * M);
        assert_eq!(any.of(16 * G), 256 * M);
        assert_eq!(any.of(100 * G), G);
        assert_eq!(any.of(238 * G), 2 * G);
        assert_eq!(any.of(100_000 * G), 2 * G);
        assert_eq!(service.of(0), G);
        assert_eq!(service.of(4 * G), G);
        assert_eq!(service.of(100 * G), 5 * G);
        assert_eq!(service.of(100_000 * G), 16 * G);
        // 100 GiB volume with 10 GiB free: 9 GiB fit, one byte more does not; in the service's
        // own folder 5 GiB do.
        assert_eq!(room(Some((10 * G, 100 * G)), 9 * G, any), Ok(()));
        assert_eq!(room(Some((10 * G, 100 * G)), 9 * G + 1, any), Err(G));
        assert_eq!(room(Some((10 * G, 100 * G)), 5 * G, service), Ok(()));
        assert_eq!(room(Some((10 * G, 100 * G)), 5 * G + 1, service), Err(5 * G));
        // A small file still fits on a nearly full disk while gigabytes are free: a 238 GiB laptop
        // disk with 9 GiB left, a 119 GiB tablet with 5, a 20 GiB server with 900 MiB.
        assert_eq!(room(Some((9 * G, 238 * G)), 20 << 10, any), Ok(()));
        assert_eq!(room(Some((5 * G, 119 * G)), 50 << 10, any), Ok(()));
        assert_eq!(room(Some((900 * M, 20 * G)), M, any), Ok(()));
        // Already below the reserve: not even an empty file.
        assert_eq!(room(Some((G / 2, 100 * G)), 0, any), Err(G));
        assert_eq!(room(Some((4 * G, 100 * G)), 0, service), Err(5 * G));
        assert_eq!(room(Some((G, 100 * G)), u64::MAX, any), Err(G));
        // A volume that reports nothing cannot be judged.
        assert_eq!(room(None, u64::MAX, service), Ok(()));
        assert_eq!(room(Some((0, 0)), u64::MAX, service), Ok(()));
        assert_eq!(amount(5 * G + G / 2), "5.5 GiB");
        assert_eq!(amount(2 * G), "2.0 GiB");
        assert_eq!(amount(256 * M), "256 MiB");
    }

    #[test]
    fn each_transfer_keeps_its_reserve() {
        let dir = tmpdir("reserve");
        let inc = Incoming::begin(&dir, 1, 10, "x.bin").unwrap();
        assert_eq!(inc.reserve, Reserve::Ordinary);
        let (free, total) = space(inc.file.as_ref().unwrap()).unwrap();
        drop(inc);
        // The service's folder keeps its larger reserve, at the start and as data arrives.
        match Incoming::begin_keeping(&dir, 2, 10, "y.bin", Reserve::ServiceFolder) {
            Ok(inc) => assert_eq!(inc.reserve, Reserve::ServiceFolder),
            Err(e) => assert!(e.to_string().contains(&amount(Reserve::ServiceFolder.of(total))), "{e}"),
        }
        // More than is free never fits (where the largest file allowed is more than that).
        if free < MAX_FILE_SIZE {
            for keep in [Reserve::Ordinary, Reserve::ServiceFolder] {
                match Incoming::begin_keeping(&dir, 3, free + 1, "big.bin", keep) {
                    Ok(_) => panic!("{} bytes fit where {free} are free", free + 1),
                    Err(e) => assert!(e.to_string().contains("has to stay free"), "{e}"),
                }
            }
        }
        assert!(names(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn free_space_is_read_from_the_open_part() {
        let dir = tmpdir("space");
        let inc = Incoming::begin(&dir, 1, 10, "x.bin").unwrap();
        let (free, total) = space(inc.file.as_ref().unwrap()).expect("the volume reports no size");
        assert!(total > 0 && free <= total, "{free} free of {total}");
        drop(inc);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn announced_bytes_are_counted_until_they_arrive() {
        let dir = tmpdir("promised");
        let mut inc = Incoming::begin(&dir, 1, 3 * SPACE_RECHECK, "big.bin").unwrap();
        assert_eq!(inc.promised, 3 * SPACE_RECHECK);
        // Other tests transfer at the same time: this one's bytes are there, at least.
        assert!(PROMISED.load(Ordering::SeqCst) >= inc.promised);
        let chunk = vec![0u8; 1 << 20];
        for _ in 0..(SPACE_RECHECK >> 20) + 1 {
            inc.write(&chunk).unwrap();
        }
        // Past the first recheck, which found room.
        assert_eq!(inc.promised, 2 * SPACE_RECHECK - (1 << 20));
        assert_eq!(inc.next_check, 2 * SPACE_RECHECK);
        drop(inc);
        assert!(names(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn an_abandoned_part_is_removed_through_its_handle() {
        let dir = tmpdir("handle");
        let mut inc = Incoming::begin(&dir, 1, 10, "x.bin").unwrap();
        inc.write(b"12345").unwrap();
        let part = inc.part.clone();
        // A file of the part's name where the part's path now leads must survive: only the
        // file the transfer created goes. The part itself cannot be moved aside while it is
        // held, so the transfer is pointed at a stand-in instead.
        let elsewhere = tmpdir("handle-elsewhere");
        let stand_in = elsewhere.join(part.file_name().unwrap());
        std::fs::write(&stand_in, b"keep").unwrap();
        inc.part = stand_in.clone();
        drop(inc);
        assert_eq!(std::fs::read(&stand_in).unwrap(), b"keep");
        assert!(std::fs::symlink_metadata(&part).is_err(), "the part was left behind");
        assert!(names(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn folder_usage_counts_without_following_links() {
        let dir = tmpdir("usage");
        assert_eq!(dir_usage(&dir).unwrap(), (0, 0));
        std::fs::write(dir.join("a"), [0u8; 100]).unwrap();
        std::fs::write(dir.join("b"), [0u8; 23]).unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("c"), [0u8; 1000]).unwrap();
        // A part still being written counts with what it holds so far.
        let mut inc = Incoming::begin(&dir, 1, 10, "d.bin").unwrap();
        inc.write(b"1234567").unwrap();
        assert_eq!(dir_usage(&dir).unwrap(), (130, 4));
        #[cfg(windows)]
        if junction(&dir.join("j"), &dir.join("sub")) {
            assert_eq!(dir_usage(&dir).unwrap(), (130, 5));
        }
        drop(inc);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
