//! Cryptographic primitives backed by Windows CNG (bcrypt.dll).
//!
//! No third-party crypto code: SHA-256, HMAC, ECDH P-256, AES-256-GCM and the RNG are all
//! the operating system's FIPS-validated implementations. Only HKDF (a few HMAC calls)
//! is composed here.

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

/// RFC 5869 HKDF-Extract.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Secret<32> {
    Secret(hmac_sha256(salt, &[ikm]))
}

/// RFC 5869 HKDF-Expand; `info` is the concatenation of `info_parts`.
pub fn hkdf_expand(prk: &[u8], info_parts: &[&[u8]], out: &mut [u8]) {
    assert!(out.len() <= 255 * 32);
    let mut t = Secret::<32>::zero();
    let mut t_len = 0;
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let ctr = [(i + 1) as u8];
        let mut parts: Vec<&[u8]> = Vec::with_capacity(info_parts.len() + 2);
        parts.push(&t.0[..t_len]);
        parts.extend_from_slice(info_parts);
        parts.push(&ctr);
        t.0 = hmac_sha256(prk, &parts);
        t_len = 32;
        chunk.copy_from_slice(&t.0[..chunk.len()]);
    }
}

/// Constant-time equality.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    unsafe { std::ptr::read_volatile(&d) == 0 }
}

pub const PUBKEY_LEN: usize = 64;

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

    /// Raw ECDH shared secret with `peer`. CNG validates that the point is on the curve.
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
            // "TRUNCATE" = raw secret (little-endian X coordinate); both ends use the same form.
            let st = BCryptDeriveKey(sec, BCRYPT_KDF_RAW_SECRET, null(), out.0.as_mut_ptr(), 32, &mut n, 0);
            BCryptDestroySecret(sec);
            check(st, "BCryptDeriveKey")?;
            if n != 32 {
                bail!("unexpected ECDH secret length {n}");
            }
        }
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

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

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

    /// Decrypts `data` in place; fails (and leaves garbage in `data`) if the tag does not verify.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex_decode, hex_encode};

    #[test]
    fn sha256_abc() {
        assert_eq!(
            hex_encode(&sha256(&[b"a", b"bc"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_rfc4231_case2() {
        assert_eq!(
            hex_encode(&hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"])),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = [0x0bu8; 22];
        let salt = hex_decode("000102030405060708090a0b0c").unwrap();
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(hex_encode(&prk.0), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let mut okm = [0u8; 42];
        hkdf_expand(&prk.0, &[&info[..4], &info[4..]], &mut okm);
        assert_eq!(
            hex_encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn aes_gcm_nist_case14() {
        let aead = Aead::new(&[0u8; 32]).unwrap();
        let mut data = [0u8; 16];
        let tag = aead.seal(&[0u8; 12], &[], &mut data).unwrap();
        assert_eq!(hex_encode(&data), "cea7403d4d606b6e074ec5d3baf39d18");
        assert_eq!(hex_encode(&tag), "d0d1c8a799996bf0265b98b5d48ab919");
        aead.open(&[0u8; 12], &[], &mut data, &tag).unwrap();
        assert_eq!(data, [0u8; 16]);
    }

    #[test]
    fn aes_gcm_rejects_tamper() {
        let aead = Aead::new(&[7u8; 32]).unwrap();
        let nonce = [1u8; 12];
        let mut data = *b"hello world, this is a test";
        let tag = aead.seal(&nonce, b"aad", &mut data).unwrap();
        let mut bad = data;
        bad[3] ^= 1;
        assert!(aead.open(&nonce, b"aad", &mut bad, &tag).is_err());
        let mut d2 = data;
        assert!(aead.open(&nonce, b"aaX", &mut d2, &tag).is_err());
        aead.open(&nonce, b"aad", &mut data, &tag).unwrap();
        assert_eq!(&data, b"hello world, this is a test");
    }

    #[test]
    fn ecdh_agrees() {
        let a = EcdhKey::generate().unwrap();
        let b = EcdhKey::generate().unwrap();
        let sa = a.agree(&b.public_bytes().unwrap()).unwrap();
        let sb = b.agree(&a.public_bytes().unwrap()).unwrap();
        assert_eq!(sa.0, sb.0);
        // Points not on the curve must be rejected.
        let mut bogus = b.public_bytes().unwrap();
        bogus[63] ^= 1;
        assert!(a.agree(&bogus).is_err());
        assert!(a.agree(&[0u8; 64]).is_err());
    }
}
