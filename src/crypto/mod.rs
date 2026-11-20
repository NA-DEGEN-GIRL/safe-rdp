//! Cryptographic primitives.
//!
//! Every primitive comes from the operating system's vetted implementation: Windows CNG
//! (bcrypt.dll, FIPS-validated) or the system OpenSSL libcrypto on Linux (loaded at run time).
//! Only HKDF, a few HMAC calls, is composed here. Both backends expose the same API:
//!
//! * `random`, `sha256`, `hmac_sha256`, `Sha256` (incremental)
//! * `EcdhKey` (P-256; `agree` returns the big-endian X coordinate, as in SEC 1)
//! * `Aead` (AES-256-GCM, 96-bit nonce, 128-bit tag, in-place)

use crate::util::Secret;

#[cfg(windows)]
mod cng;
#[cfg(windows)]
pub use cng::*;

#[cfg(target_os = "linux")]
mod openssl;
#[cfg(target_os = "linux")]
pub use openssl::*;

/// Uncompressed P-256 public point without the 0x04 prefix: X || Y, big-endian.
pub const PUBKEY_LEN: usize = 64;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex_decode, hex_encode};

    fn h<const N: usize>(s: &str) -> [u8; N] {
        hex_decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn sha256_abc() {
        assert_eq!(
            hex_encode(&sha256(&[b"a", b"bc"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_encode(&sha256(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
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
    fn aes_gcm_with_aad_nist_case16() {
        // GCM spec test case 16 (AES-256, 60-byte plaintext, 20-byte AAD), 96-bit IV.
        let key: [u8; 32] = h("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let iv: [u8; 12] = h("cafebabefacedbaddecaf888");
        let aad = hex_decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let mut data = hex_decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        )
        .unwrap();
        let aead = Aead::new(&key).unwrap();
        let tag = aead.seal(&iv, &aad, &mut data).unwrap();
        assert_eq!(
            hex_encode(&data),
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        );
        assert_eq!(hex_encode(&tag), "76fc6ece0f4e1768cddf8853bb2d551b");
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
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        let mut d3 = data;
        assert!(aead.open(&nonce, b"aad", &mut d3, &bad_tag).is_err());
        aead.open(&nonce, b"aad", &mut data, &tag).unwrap();
        assert_eq!(&data, b"hello world, this is a test");
    }

    #[test]
    fn ecdh_agrees_and_validates() {
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

    /// NIST CAVS "KAS ECC CDH primitive" P-256, COUNT = 0. Pins the shared-secret byte order
    /// so the Windows and Linux backends interoperate.
    #[test]
    fn ecdh_nist_cavs_p256() {
        let peer: [u8; 64] = h(concat!(
            "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
            "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac"
        ));
        let d: [u8; 32] = h("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
        let q: [u8; 64] = h(concat!(
            "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230",
            "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141"
        ));
        let k = EcdhKey::from_private(&d, &q).unwrap();
        assert_eq!(k.public_bytes().unwrap(), q);
        assert_eq!(hex_encode(&k.agree(&peer).unwrap().0), "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b");
    }

    #[test]
    fn sha256_streaming_matches_one_shot() {
        let mut s = Sha256::new();
        s.update(b"a");
        s.update(b"");
        s.update(b"bc");
        assert_eq!(s.finish(), sha256(&[b"abc"]));
    }

    #[test]
    fn random_is_not_constant() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        random(&mut a).unwrap();
        random(&mut b).unwrap();
        assert_ne!(a, b);
    }
}
