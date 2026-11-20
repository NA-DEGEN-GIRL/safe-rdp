//! Windows backend: CNG (bcrypt.dll) pseudo-handles, Windows 10+.

use super::{NONCE_LEN, PUBKEY_LEN, TAG_LEN};
use crate::bail;
use crate::util::{Result, Secret};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::Security::Cryptography::*;

fn check(st: NTSTATUS, what: &str) -> Result<()> {
    if st < 0 {
        bail!("{what} failed (NTSTATUS {:#010x})", st as u32);
    }
    Ok(())
}

pub fn random(buf: &mut [u8]) -> Result<()> {
    let st = unsafe {
        BCryptGenRandom(null_mut(), buf.as_mut_ptr(), buf.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    };
    check(st, "BCryptGenRandom")
}

fn hash_parts(alg: BCRYPT_ALG_HANDLE, key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        let mut h: BCRYPT_HASH_HANDLE = null_mut();
        let kp = if key.is_empty() { null() } else { key.as_ptr() };
        let st = BCryptCreateHash(alg, &mut h, null_mut(), 0, kp, key.len() as u32, 0);
        assert!(st >= 0, "BCryptCreateHash failed: {st:#x}");
        for p in parts {
            let st = BCryptHashData(h, p.as_ptr(), p.len() as u32, 0);
            assert!(st >= 0, "BCryptHashData failed: {st:#x}");
        }
        let st = BCryptFinishHash(h, out.as_mut_ptr(), 32, 0);
        assert!(st >= 0, "BCryptFinishHash failed: {st:#x}");
        BCryptDestroyHash(h);
    }
    out
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    hash_parts(BCRYPT_SHA256_ALG_HANDLE, &[], parts)
}

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    hash_parts(BCRYPT_HMAC_SHA256_ALG_HANDLE, key, parts)
}

/// Ephemeral ECDH P-256 key pair.
pub struct EcdhKey(BCRYPT_KEY_HANDLE);

impl EcdhKey {
    pub fn generate() -> Result<Self> {
        let mut h: BCRYPT_KEY_HANDLE = null_mut();
        unsafe {
            check(BCryptGenerateKeyPair(BCRYPT_ECDH_P256_ALG_HANDLE, &mut h, 256, 0), "BCryptGenerateKeyPair")?;
            let key = EcdhKey(h);
            check(BCryptFinalizeKeyPair(h, 0), "BCryptFinalizeKeyPair")?;
            Ok(key)
        }
    }

    /// Imports a known key pair (private scalar `d`, public point `q`); used by known-answer tests.
    #[cfg(test)]
    pub fn from_private(d: &[u8; 32], q: &[u8; PUBKEY_LEN]) -> Result<Self> {
        let mut blob = Vec::with_capacity(8 + PUBKEY_LEN + 32);
        blob.extend_from_slice(&BCRYPT_ECDH_PRIVATE_P256_MAGIC.to_le_bytes());
        blob.extend_from_slice(&32u32.to_le_bytes());
        blob.extend_from_slice(q);
        blob.extend_from_slice(d);
        let mut h: BCRYPT_KEY_HANDLE = null_mut();
        unsafe {
            check(
                BCryptImportKeyPair(BCRYPT_ECDH_P256_ALG_HANDLE, null_mut(), BCRYPT_ECCPRIVATE_BLOB, &mut h, blob.as_ptr(), blob.len() as u32, 0),
                "importing private key",
            )?;
        }
        Ok(EcdhKey(h))
    }

    /// Uncompressed public point, X || Y (big-endian coordinates).
    pub fn public_bytes(&self) -> Result<[u8; PUBKEY_LEN]> {
        let mut blob = [0u8; 8 + PUBKEY_LEN];
        let mut n = 0u32;
        unsafe {
            check(
                BCryptExportKey(self.0, null_mut(), BCRYPT_ECCPUBLIC_BLOB, blob.as_mut_ptr(), blob.len() as u32, &mut n, 0),
                "BCryptExportKey",
            )?;
        }
        let magic = u32::from_le_bytes(blob[0..4].try_into().unwrap());
        let cb = u32::from_le_bytes(blob[4..8].try_into().unwrap());
        if n as usize != blob.len() || magic != BCRYPT_ECDH_PUBLIC_P256_MAGIC || cb != 32 {
            bail!("unexpected ECC public blob");
        }
        let mut out = [0u8; PUBKEY_LEN];
        out.copy_from_slice(&blob[8..]);
        Ok(out)
    }

    /// ECDH shared secret with `peer`: the X coordinate, big-endian (SEC 1 / OpenSSL order).
    /// CNG validates that the peer point is on the curve.
    pub fn agree(&self, peer: &[u8; PUBKEY_LEN]) -> Result<Secret<32>> {
        let mut blob = [0u8; 8 + PUBKEY_LEN];
        blob[0..4].copy_from_slice(&BCRYPT_ECDH_PUBLIC_P256_MAGIC.to_le_bytes());
        blob[4..8].copy_from_slice(&32u32.to_le_bytes());
        blob[8..].copy_from_slice(peer);
        let mut out = Secret::<32>::zero();
        unsafe {
            let mut pk: BCRYPT_KEY_HANDLE = null_mut();
            check(
                BCryptImportKeyPair(BCRYPT_ECDH_P256_ALG_HANDLE, null_mut(), BCRYPT_ECCPUBLIC_BLOB, &mut pk, blob.as_ptr(), blob.len() as u32, 0),
                "importing peer public key",
            )?;
            let mut sec: BCRYPT_SECRET_HANDLE = null_mut();
            let st = BCryptSecretAgreement(self.0, pk, &mut sec, 0);
            BCryptDestroyKey(pk);
            check(st, "BCryptSecretAgreement")?;
            let mut n = 0u32;
            // "TRUNCATE" = the raw secret, which CNG returns little-endian.
            let st = BCryptDeriveKey(sec, BCRYPT_KDF_RAW_SECRET, null(), out.0.as_mut_ptr(), 32, &mut n, 0);
            BCryptDestroySecret(sec);
            check(st, "BCryptDeriveKey")?;
            if n != 32 {
                bail!("unexpected ECDH secret length {n}");
            }
        }
        out.0.reverse();
        if out.0.iter().all(|&b| b == 0) {
            bail!("degenerate ECDH secret");
        }
        Ok(out)
    }
}

impl Drop for EcdhKey {
    fn drop(&mut self) {
        unsafe { BCryptDestroyKey(self.0) };
    }
}

/// AES-256-GCM key.
pub struct Aead(BCRYPT_KEY_HANDLE);

// CNG key handles may be used from any thread; each Aead is only ever used by one thread at a time.
unsafe impl Send for Aead {}

impl Aead {
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        let mut h: BCRYPT_KEY_HANDLE = null_mut();
        unsafe {
            check(
                BCryptGenerateSymmetricKey(BCRYPT_AES_GCM_ALG_HANDLE, &mut h, null_mut(), 0, key.as_ptr(), 32, 0),
                "BCryptGenerateSymmetricKey",
            )?;
        }
        Ok(Aead(h))
    }

    fn info(nonce: &[u8; NONCE_LEN], aad: &[u8], tag: *mut u8) -> BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            pbNonce: nonce.as_ptr() as *mut u8,
            cbNonce: NONCE_LEN as u32,
            pbAuthData: if aad.is_empty() { null_mut() } else { aad.as_ptr() as *mut u8 },
            cbAuthData: aad.len() as u32,
            pbTag: tag,
            cbTag: TAG_LEN as u32,
            pbMacContext: null_mut(),
            cbMacContext: 0,
            cbAAD: 0,
            cbData: 0,
            dwFlags: 0,
        }
    }

    /// Encrypts `data` in place and returns the authentication tag.
    pub fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        let mut tag = [0u8; TAG_LEN];
        let info = Self::info(nonce, aad, tag.as_mut_ptr());
        let mut n = 0u32;
        let p = data.as_mut_ptr();
        let st = unsafe {
            BCryptEncrypt(self.0, p, data.len() as u32, &info as *const _ as *const _, null_mut(), 0, p, data.len() as u32, &mut n, 0)
        };
        check(st, "AES-GCM encrypt")?;
        Ok(tag)
    }

    /// Decrypts `data` in place; fails (and wipes `data`) if the tag does not verify.
    pub fn open(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<()> {
        let info = Self::info(nonce, aad, tag.as_ptr() as *mut u8);
        let mut n = 0u32;
        let p = data.as_mut_ptr();
        let st = unsafe {
            BCryptDecrypt(self.0, p, data.len() as u32, &info as *const _ as *const _, null_mut(), 0, p, data.len() as u32, &mut n, 0)
        };
        if st < 0 {
            crate::util::wipe(data);
            bail!("record authentication failed");
        }
        Ok(())
    }
}

impl Drop for Aead {
    fn drop(&mut self) {
        unsafe { BCryptDestroyKey(self.0) };
    }
}
