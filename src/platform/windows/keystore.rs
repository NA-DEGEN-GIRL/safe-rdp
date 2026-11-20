//! Key storage on Windows.
//!
//! * Per-user storage: `%APPDATA%\safe-rdp\key.dpapi`, encrypted with DPAPI to the current
//!   Windows account.
//! * Service storage: `%ProgramData%\safe-rdp\service.key`, DPAPI (machine scope) inside a
//!   directory whose ACL only admits SYSTEM and Administrators.

use crate::bail;
use crate::util::{Error, Result, Secret, SecureVec, wide};
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::Cryptography::*;
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetFileSecurityW};

const ENTROPY: &[u8] = b"safe-rdp/1 psk";
/// SYSTEM and Administrators only, not inherited from the parent.
const ADMIN_ONLY_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

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
    service_dir().join("service.key")
}

/// Applies the SYSTEM+Administrators-only DACL to a file or directory.
pub fn restrict_to_admins(path: &std::path::Path) -> Result<()> {
    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let sddl = wide(ADMIN_ONLY_SDDL);
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) == 0 {
            return Err(Error::last_os("ConvertStringSecurityDescriptorToSecurityDescriptorW"));
        }
        let p = wide(&path.to_string_lossy());
        let ok = SetFileSecurityW(p.as_ptr(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
        LocalFree(sd as HLOCAL);
        if ok == 0 {
            return Err(Error::last_os(&format!("setting permissions on {}", path.display())));
        }
    }
    Ok(())
}

/// Stores the key for the service (requires an elevated caller).
pub fn save_service_key(k: &Secret<32>) -> Result<PathBuf> {
    let dir = service_dir();
    std::fs::create_dir_all(&dir)?;
    // Lock the directory down first so the key file never exists with looser permissions.
    restrict_to_admins(&dir)?;
    let path = service_key_path();
    std::fs::write(&path, dpapi_protect(&k.0, true)?)?;
    restrict_to_admins(&path)?;
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
}
