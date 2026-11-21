//! Pre-shared key format (portable). Storage is per platform (`platform::keystore`).
//!
//! The key is 32 random bytes, written as `srdp1-` + 64 hex digits. It is never derived
//! from a password, so the handshake cannot be attacked offline with a dictionary.

use crate::bail;
use crate::util::{Result, Secret, hex_decode, hex_encode, wipe};

pub const KEY_PREFIX: &str = "srdp1-";
/// What the fingerprint is an HMAC of. The handshake only ever feeds HMAC under the key a
/// 32-byte ECDH secret, which this can never be.
#[cfg_attr(not(windows), allow(dead_code))] // compared with the service's key
const FINGERPRINT_LABEL: &[u8] = b"safe-rdp/1 key fingerprint";

pub fn generate() -> Result<Secret<32>> {
    let mut k = Secret::<32>::zero();
    crate::crypto::random(&mut k.0)?;
    Ok(k)
}

pub fn format_key(k: &Secret<32>) -> String {
    format!("{KEY_PREFIX}{}", hex_encode(&k.0))
}

pub fn parse_key(s: &str) -> Result<Secret<32>> {
    let s = s.trim();
    let Some(hex) = s.strip_prefix(KEY_PREFIX) else {
        bail!("not a safe-rdp key (expected '{KEY_PREFIX}...'; create one with `safe-rdp keygen`)");
    };
    let mut bytes = hex_decode(hex).ok_or("key is not valid hex")?;
    if bytes.len() != 32 {
        wipe(&mut bytes);
        bail!("key must be 32 bytes");
    }
    let mut k = Secret::<32>::zero();
    k.0.copy_from_slice(&bytes);
    wipe(&mut bytes);
    Ok(k)
}

/// A non-secret name for a key, to tell whether two places hold the same one: the first 8
/// bytes of HMAC-SHA256(key, label) as 16 lowercase hex digits. Nothing about the key can be
/// learnt from it.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn fingerprint(k: &Secret<32>) -> String {
    hex_encode(&crate::crypto::hmac_sha256(&k.0, &[FINGERPRINT_LABEL])[..8])
}

/// Whether `s` is written the way `fingerprint` writes one.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn is_fingerprint(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Reads a key from a text file containing `srdp1-...`.
pub fn load_key_file(path: &str) -> Result<Secret<32>> {
    let mut text = std::fs::read_to_string(path).map_err(|e| format!("cannot read key file {path}: {e}"))?;
    let k = parse_key(&text);
    unsafe { wipe(text.as_bytes_mut()) };
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_text_roundtrip() {
        let k = generate().unwrap();
        let s = format_key(&k);
        assert!(s.starts_with(KEY_PREFIX) && s.len() == KEY_PREFIX.len() + 64);
        assert_eq!(parse_key(&format!("  {s}\r\n")).unwrap().0, k.0);
        assert!(parse_key("hunter2").is_err());
        assert!(parse_key("srdp1-abcd").is_err());
    }

    #[test]
    fn fingerprints_name_keys_without_revealing_them() {
        let mut k = Secret::<32>::zero();
        for (i, b) in k.0.iter_mut().enumerate() {
            *b = i as u8;
        }
        // Fixed for good: the service records it and later versions compare with it.
        assert_eq!(fingerprint(&k), "891d3768f5c4f960");
        let other = generate().unwrap();
        let fp = fingerprint(&other);
        assert!(is_fingerprint(&fp), "{fp}");
        assert_eq!(fp, fingerprint(&other));
        assert_ne!(fp, fingerprint(&k));
        for bad in ["", "891d3768f5c4f96", "891d3768f5c4f9600", "891D3768F5C4F960", "891d3768f5c4f96g", "891d3768 5c4f960"] {
            assert!(!is_fingerprint(bad), "{bad}");
        }
    }
}
