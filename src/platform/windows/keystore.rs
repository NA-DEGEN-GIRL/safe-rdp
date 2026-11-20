//! Key storage on Windows.
//!
//! * Per-user storage: `%APPDATA%\safe-rdp\key.dpapi`, encrypted with DPAPI to the current
//!   Windows account.
//! * Service storage: `%ProgramData%\safe-rdp\service.key`, DPAPI with machine scope (which any
//!   local account can undo, so the ACL is what protects it) inside a directory owned by
//!   Administrators whose ACL only admits SYSTEM and Administrators. Ordinary users may create
//!   directories in `%ProgramData%`, so the installer refuses a directory somebody else created
//!   and removes everything inside that SYSTEM or Administrators did not create; the service
//!   and its agent check the directory again before they write logs there or read the key.

use crate::bail;
use crate::util::{Error, Result, Secret, SecureVec, wide};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{FileTypeExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GENERIC_WRITE, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::Cryptography::*;
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorOwner, IsWellKnownSid, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SetFileSecurityW, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle, READ_CONTROL,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

const ENTROPY: &[u8] = b"safe-rdp/1 psk";
/// Owner Administrators; SYSTEM and Administrators only, not inherited from the parent.
const ADMIN_ONLY_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// The same for a file.
const KEY_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
const KEY_FILE: &str = "service.key";
/// What the service and its agent keep in the service directory.
const SERVICE_FILES: [&str; 4] = [KEY_FILE, "service.log", "host.log", "incoming"];
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
}

fn dpapi_protect(data: &[u8], machine: bool) -> Result<Vec<u8>> {
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
    let flags = CRYPTPROTECT_UI_FORBIDDEN | if machine { CRYPTPROTECT_LOCAL_MACHINE } else { 0 };
    let desc = wide("safe-rdp key");
    unsafe {
        if CryptProtectData(&blob(data), desc.as_ptr(), &blob(ENTROPY), null(), null(), flags, &mut out) == 0 {
            return Err(Error::last_os("CryptProtectData"));
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as HLOCAL);
        Ok(v)
    }
}

fn dpapi_unprotect(data: &[u8]) -> Result<SecureVec> {
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
    unsafe {
        if CryptUnprotectData(&blob(data), null_mut(), &blob(ENTROPY), null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out) == 0 {
            return Err(Error::last_os("CryptUnprotectData"));
        }
        let plain = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
        let v = SecureVec(plain.to_vec());
        crate::util::wipe(plain);
        LocalFree(out.pbData as HLOCAL);
        Ok(v)
    }
}

fn unwrap_key(plain: SecureVec) -> Result<Secret<32>> {
    if plain.0.len() != 32 {
        bail!("stored key is corrupt");
    }
    let mut k = Secret::<32>::zero();
    k.0.copy_from_slice(&plain.0);
    Ok(k)
}

fn env_dir(var: &str) -> Result<PathBuf> {
    std::env::var_os(var).map(PathBuf::from).ok_or_else(|| Error::msg(format!("%{var}% is not set")))
}

pub fn user_key_path() -> Result<PathBuf> {
    Ok(env_dir("APPDATA")?.join("safe-rdp").join("key.dpapi"))
}

pub fn save_user_key(k: &Secret<32>) -> Result<PathBuf> {
    let path = user_key_path()?;
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, dpapi_protect(&k.0, false)?)?;
    Ok(path)
}

pub fn load_user_key() -> Result<Secret<32>> {
    let path = user_key_path()?;
    let data = std::fs::read(&path).map_err(|_| {
        Error::msg(format!("no key stored at {} (run `safe-rdp keygen` or `safe-rdp key import`)", path.display()))
    })?;
    unwrap_key(dpapi_unprotect(&data)?)
}

pub fn forget_user_key() -> Result<bool> {
    let path = user_key_path()?;
    if !path.exists() {
        return Ok(false);
    }
    // Overwrite before deleting (best effort; the file only ever held a DPAPI blob).
    let len = std::fs::metadata(&path)?.len() as usize;
    std::fs::write(&path, vec![0u8; len])?;
    std::fs::remove_file(&path)?;
    Ok(true)
}

pub fn service_dir() -> PathBuf {
    std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData")).join("safe-rdp")
}

pub fn service_key_path() -> PathBuf {
    service_dir().join(KEY_FILE)
}

fn wide_path(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// A security descriptor allocated by Windows, freed on drop.
struct Sd(PSECURITY_DESCRIPTOR);

impl Sd {
    fn parse(sddl: &str) -> Result<Sd> {
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let w = wide(sddl);
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(w.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) } == 0 {
            return Err(Error::last_os("ConvertStringSecurityDescriptorToSecurityDescriptorW"));
        }
        Ok(Sd(sd))
    }

    fn dacl(&self) -> *mut ACL {
        let (mut present, mut defaulted, mut dacl) = (0, 0, null_mut());
        unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) };
        dacl
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: self.0, bInheritHandle: 0 }
    }
}

impl Drop for Sd {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0 as HLOCAL) };
    }
}

/// Applies the SYSTEM+Administrators-only DACL to a file or directory.
pub fn restrict_to_admins(path: &Path) -> Result<()> {
    let sd = Sd::parse(ADMIN_ONLY_SDDL)?;
    let p = wide_path(path);
    if unsafe { SetFileSecurityW(p.as_ptr(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd.0) } == 0 {
        return Err(Error::last_os(&format!("setting permissions on {}", path.display())));
    }
    Ok(())
}

fn is_admin_sid(sid: PSID) -> bool {
    !sid.is_null() && unsafe { IsWellKnownSid(sid, WinLocalSystemSid) != 0 || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 }
}

/// Who may use an object, as far as the service cares.
#[derive(Debug, PartialEq)]
struct Access {
    /// Owned by SYSTEM or Administrators (an owner can always rewrite the ACL).
    admin_owner: bool,
    /// Every ACE allows access to SYSTEM or Administrators, and nothing else is there.
    admin_aces: bool,
    /// The ACL does not inherit from the parent.
    protected: bool,
}

fn access(sd: PSECURITY_DESCRIPTOR) -> Access {
    unsafe {
        let (mut owner, mut defaulted): (PSID, _) = (null_mut(), 0);
        GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted);
        let (mut present, mut dacl): (_, *mut ACL) = (0, null_mut());
        GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted);
        let (mut control, mut revision) = (0u16, 0u32);
        GetSecurityDescriptorControl(sd, &mut control, &mut revision);
        // No DACL at all means full access for everybody.
        let admin_aces = present != 0
            && !dacl.is_null()
            && (0..(*dacl).AceCount as u32).all(|i| {
                let mut ace: *mut c_void = null_mut();
                if GetAce(dacl, i, &mut ace) == 0 {
                    return false;
                }
                let ace = &*(ace as *const ACCESS_ALLOWED_ACE);
                ace.Header.AceType as u32 == ACCESS_ALLOWED_ACE_TYPE && is_admin_sid(&ace.SidStart as *const u32 as PSID)
            });
        Access { admin_owner: is_admin_sid(owner), admin_aces, protected: control & SE_DACL_PROTECTED != 0 }
    }
}

/// What matters about a file or directory before the service trusts it.
struct Facts {
    dir: bool,
    /// A symbolic link, junction or other reparse point.
    reparse: bool,
    /// Hard links to the same file.
    links: u32,
    access: Access,
}

impl Facts {
    /// Created by SYSTEM or an administrator, and not a way to reach some other file.
    fn ours(&self) -> bool {
        self.access.admin_owner && !self.reparse && (self.dir || self.links <= 1)
    }
}

/// Opens `path` itself, never the target of a link, to read its attributes and security.
fn open_entry(path: &Path, share: u32) -> std::io::Result<File> {
    OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(share)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Owner and DACL of an open file (needs READ_CONTROL).
fn file_access(f: &File) -> Result<Access> {
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    let what = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let h = f.as_raw_handle() as HANDLE;
    let r = unsafe { GetSecurityInfo(h, SE_FILE_OBJECT, what, null_mut(), null_mut(), null_mut(), null_mut(), &mut sd) };
    if r != 0 {
        bail!("GetSecurityInfo failed: {}", std::io::Error::from_raw_os_error(r as i32));
    }
    let sd = Sd(sd);
    Ok(access(sd.0))
}

fn facts(f: &File) -> Result<Facts> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(f.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(Error::last_os("GetFileInformationByHandle"));
    }
    Ok(Facts {
        dir: info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        reparse: info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        links: info.nNumberOfLinks,
        access: file_access(f)?,
    })
}

fn entry_facts(path: &Path) -> Result<Facts> {
    let f = open_entry(path, SHARE_ALL).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    facts(&f)
}

/// Checks that `dir` is a plain directory owned by SYSTEM or Administrators that admits only them.
fn check_dir(dir: &Path) -> Result<()> {
    let fx = entry_facts(dir)?;
    if !fx.dir || fx.reparse {
        bail!("{} is not a plain directory", dir.display());
    }
    if !fx.access.admin_owner {
        bail!("{} is not owned by SYSTEM or Administrators", dir.display());
    }
    if !fx.access.protected || !fx.access.admin_aces {
        bail!("{} admits accounts other than SYSTEM and Administrators", dir.display());
    }
    Ok(())
}

/// Checks the files the service keeps in `dir`, where present.
fn check_entries(dir: &Path) -> Result<()> {
    for name in SERVICE_FILES {
        let path = dir.join(name);
        let fx = match open_entry(&path, SHARE_ALL) {
            Ok(f) => facts(&f)?,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => bail!("cannot open {}: {e}", path.display()),
        };
        if !fx.ours() {
            bail!("{} was not created by SYSTEM or an administrator, or is a link", path.display());
        }
        if !fx.access.admin_aces {
            bail!("{} admits accounts other than SYSTEM and Administrators", path.display());
        }
    }
    Ok(())
}

/// Verifies, without creating or changing anything, that the service directory and the files
/// the service keeps there belong to SYSTEM or Administrators and are closed to everybody
/// else. The service and its agent call this before they write logs there or read the key.
pub fn check_service_dir() -> Result<PathBuf> {
    let dir = service_dir();
    check_dir(&dir)
        .and_then(|()| check_entries(&dir))
        .map_err(|e| format!("{e}; run `safe-rdp service install` again from an elevated terminal"))?;
    Ok(dir)
}

/// Removes a file, directory tree or link (never what a link points to).
fn remove_entry(path: &Path) -> std::io::Result<()> {
    let ft = std::fs::symlink_metadata(path)?.file_type();
    if ft.is_symlink_dir() {
        std::fs::remove_dir(path)
    } else if ft.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// Removes everything below `dir` that SYSTEM or Administrators did not create, and every link.
fn purge_foreign(dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        match entry_facts(&path) {
            Ok(fx) if fx.ours() => {
                if fx.dir {
                    purge_foreign(&path)?;
                }
            }
            _ => remove_entry(&path).map_err(|e| {
                format!("cannot remove {} (not created by an administrator): {e}; remove it by hand and try again", path.display())
            })?,
        }
    }
    Ok(())
}

/// Creates `dir` owned by Administrators with the admin-only ACL, or takes over an existing
/// directory that SYSTEM or Administrators own: the ACL is applied to it and to everything
/// inside, then whatever SYSTEM or Administrators did not create is removed. A directory owned
/// by anybody else is refused, since its owner could change its ACL again at any time.
fn secure_dir(dir: &Path) -> Result<()> {
    let sd = Sd::parse(ADMIN_ONLY_SDDL)?;
    let w = wide_path(dir);
    let sa = sd.attributes();
    if unsafe { CreateDirectoryW(w.as_ptr(), &sa) } == 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            bail!("cannot create {}: {e}", dir.display());
        }
    }
    // Held without FILE_SHARE_DELETE: while it is open the directory cannot be swapped for a link.
    let pin = open_entry(dir, FILE_SHARE_READ | FILE_SHARE_WRITE).map_err(|e| format!("cannot open {}: {e}", dir.display()))?;
    let fx = facts(&pin)?;
    if !fx.dir || fx.reparse {
        bail!("{} is not a plain directory; remove it and try again", dir.display());
    }
    if !fx.access.admin_owner {
        bail!(
            "{} was not created by an administrator, so someone else may control it; delete it with everything inside and try again",
            dir.display()
        );
    }
    // Setting the ACL by name also re-applies inheritance to everything inside.
    let what = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let r = unsafe { SetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, what, null_mut(), null_mut(), sd.dacl(), null()) };
    if r != 0 {
        bail!("cannot set permissions on {}: {}", dir.display(), std::io::Error::from_raw_os_error(r as i32));
    }
    purge_foreign(dir)?;
    drop(pin);
    Ok(())
}

/// Creates `path`, which must not exist yet, with security descriptor `sddl` and contents `data`.
fn write_new(path: &Path, data: &[u8], sddl: &str) -> Result<()> {
    let sd = Sd::parse(sddl)?;
    let sa = sd.attributes();
    let h = unsafe { CreateFileW(wide_path(path).as_ptr(), GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, null_mut()) };
    if h == INVALID_HANDLE_VALUE {
        return Err(Error::last_os(&format!("creating {}", path.display())));
    }
    let mut f = unsafe { File::from_raw_handle(h) };
    if let Err(e) = f.write_all(data).and_then(|()| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(e.into());
    }
    Ok(())
}

/// Stores the key for the service (requires an elevated caller).
pub fn save_service_key(k: &Secret<32>) -> Result<PathBuf> {
    let dir = service_dir();
    secure_dir(&dir)?;
    let path = dir.join(KEY_FILE);
    // Never write into an existing file: someone may hold it open.
    match std::fs::remove_file(&path) {
        Err(e) if e.kind() != ErrorKind::NotFound => bail!("cannot replace {}: {e}", path.display()),
        _ => {}
    }
    write_new(&path, &dpapi_protect(&k.0, true)?, KEY_SDDL)?;
    Ok(path)
}

pub fn load_service_key() -> Result<Secret<32>> {
    let path = service_key_path();
    let data = std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    unwrap_key(dpapi_unprotect(&data)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_roundtrip() {
        let k = crate::keys::generate().unwrap();
        let blob = dpapi_protect(&k.0, false).unwrap();
        assert!(!blob.windows(32).any(|w| w == k.0));
        assert_eq!(unwrap_key(dpapi_unprotect(&blob).unwrap()).unwrap().0, k.0);
    }

    /// A fresh directory under %TEMP%, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let mut r = [0u8; 8];
            crate::crypto::random(&mut r).unwrap();
            let p = std::env::temp_dir().join(format!("safe-rdp-test-{tag}-{:016x}", u64::from_ne_bytes(r)));
            std::fs::create_dir(&p).unwrap();
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sddl_access(sddl: &str) -> Access {
        access(Sd::parse(sddl).unwrap().0)
    }

    #[test]
    fn only_system_and_administrators_count() {
        let all = Access { admin_owner: true, admin_aces: true, protected: true };
        assert_eq!(sddl_access(ADMIN_ONLY_SDDL), all);
        assert_eq!(sddl_access(KEY_SDDL), all);
        assert_eq!(sddl_access("O:SYD:P(A;OICI;FA;;;SY)"), all);
        // An empty DACL admits nobody.
        assert_eq!(sddl_access("O:SYD:P"), all);
        // Owned by Users, or by anybody but SYSTEM and Administrators.
        assert!(!sddl_access("O:BUD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").admin_owner);
        assert!(!sddl_access("O:WDD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").admin_owner);
        // Inherits from the parent.
        assert!(!sddl_access("O:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").protected);
        // Grants something to somebody else, even only "create files" or "read attributes".
        assert!(!sddl_access("O:BAD:P(A;OICI;FA;;;SY)(A;CI;0x2;;;BU)").admin_aces);
        assert!(!sddl_access("O:BAD:P(A;;FA;;;BA)(A;;0x80;;;AU)").admin_aces);
        assert!(!sddl_access("O:BAD:P(A;;FA;;;BA)(A;;FA;;;CO)").admin_aces);
        // Deny entries are never ours either; a missing DACL admits everybody.
        assert!(!sddl_access("O:BAD:P(D;;FA;;;BU)(A;;FA;;;BA)").admin_aces);
        assert!(!sddl_access("O:BAD:NO_ACCESS_CONTROL").admin_aces);
    }

    fn running_elevated(t: &TempDir) -> bool {
        entry_facts(&t.0).unwrap().access.admin_owner
    }

    #[test]
    fn directories_of_ordinary_users_are_refused() {
        let t = TempDir::new("owner");
        if running_elevated(&t) {
            eprintln!("elevated: new directories belong to Administrators; skipped");
            return;
        }
        let e = check_dir(&t.0).unwrap_err().to_string();
        assert!(e.contains("not owned by SYSTEM or Administrators"), "{e}");
        let e = secure_dir(&t.0).unwrap_err().to_string();
        assert!(e.contains("not created by an administrator"), "{e}");
        // Refused before anything changed.
        std::fs::write(t.0.join("x"), b"x").unwrap();
        assert!(!entry_facts(&t.0).unwrap().access.protected);
        // A file or a link where the directory should be is no directory.
        let file = t.0.join("x");
        assert!(check_dir(&file).unwrap_err().to_string().contains("not a plain directory"));
        assert!(check_dir(&t.0.join("missing")).is_err());
    }

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

    #[test]
    fn foreign_entries_and_links_are_purged_without_following_links() {
        let t = TempDir::new("purge");
        let elevated = running_elevated(&t);
        let root = t.0.join("root");
        let outside = t.0.join("outside");
        std::fs::create_dir_all(root.join("incoming").join("deeper")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep.txt"), b"keep").unwrap();
        std::fs::write(root.join("host.log"), b"log").unwrap();
        std::fs::write(root.join("incoming").join("deeper").join("f"), b"f").unwrap();
        // A second name for a file elsewhere.
        std::fs::hard_link(outside.join("keep.txt"), root.join("service.log")).unwrap();
        let have_junction = junction(&root.join("incoming").join("j"), &outside);

        purge_foreign(&root).unwrap();

        assert!(outside.join("keep.txt").exists(), "a link was followed");
        assert_eq!(std::fs::read(outside.join("keep.txt")).unwrap(), b"keep");
        assert!(std::fs::symlink_metadata(root.join("service.log")).is_err(), "hard link kept");
        if have_junction {
            assert!(std::fs::symlink_metadata(root.join("incoming").join("j")).is_err(), "junction kept");
        }
        let left: Vec<_> = std::fs::read_dir(&root).unwrap().map(|e| e.unwrap().file_name()).collect();
        if elevated {
            assert!(root.join("host.log").exists() && root.join("incoming").join("deeper").join("f").exists());
        } else {
            assert!(left.is_empty(), "left behind: {left:?}");
        }
    }

    #[test]
    fn service_files_of_ordinary_users_are_rejected() {
        let t = TempDir::new("entries");
        check_entries(&t.0).unwrap();
        if running_elevated(&t) {
            return;
        }
        std::fs::write(t.0.join("host.log"), b"").unwrap();
        let e = check_entries(&t.0).unwrap_err().to_string();
        assert!(e.contains("host.log"), "{e}");
    }

    #[test]
    fn key_files_are_created_fresh_with_their_own_acl() {
        let t = TempDir::new("key");
        let path = t.0.join("service.key");
        // Admin-only would lock this (non-elevated) test out of its own file; the owner part of
        // KEY_SDDL needs elevation anyway. What matters is that the given DACL is used as is.
        let sddl = "D:P(A;;FA;;;WD)";
        // An existing file, for instance one someone planted and holds open, is never reused.
        std::fs::write(&path, b"planted").unwrap();
        assert!(write_new(&path, b"secret", sddl).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"planted");
        std::fs::remove_file(&path).unwrap();
        write_new(&path, b"secret", sddl).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
        let a = entry_facts(&path).unwrap().access;
        assert!(a.protected && !a.admin_aces, "{a:?}");
    }
}
