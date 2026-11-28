//! Cryptographic primitives.
//!
//! Every primitive comes from the operating system's vetted implementation: Windows CNG
//! (bcrypt.dll, FIPS-validated), the system OpenSSL libcrypto on Linux (loaded at run time), or
//! on Android the platform's Java crypto provider (Conscrypt, BoringSSL inside), reached through
//! JNI since the NDK offers no crypto library. Only HKDF, a few HMAC calls, is composed here.
//! The backends expose the same API:
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

/// Built only into the Android app (`android/native`), whose JNI layer it calls.
#[cfg(target_os = "android")]
mod jca;
#[cfg(target_os = "android")]
pub use jca::*;

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

    // NIST CAVS "KAS ECC CDH primitive" P-256 IUT key pairs, COUNT = 0 and 1.
    const D0: &str = "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534";
    const Q0: &str = concat!(
        "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230",
        "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141"
    );
    const D1: &str = "38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5";
    const Q1: &str = concat!(
        "119f2f047902782ab0c9e27a54aff5eb9b964829ca99c06b02ddba95b0a3f6d0",
        "8f52b726664cac366fc98ac7a012b2682cbd962e5acb544671d41b9445704d1d"
    );

    #[test]
    fn ecdh_nist_cavs_p256_count1() {
        let peer: [u8; 64] = h(concat!(
            "809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae",
            "b29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3"
        ));
        let k = EcdhKey::from_private(&h(D1), &h(Q1)).unwrap();
        assert_eq!(hex_encode(&k.agree(&peer).unwrap().0), "057d636096cb80b67a8c038c890e887d1adfa4195e9b3ce241c8a778c59cda67");
    }

    /// Cross-platform pinning: CNG (Windows) and OpenSSL (Linux) must both produce exactly these
    /// bytes, which were also checked against a third implementation (pyca/cryptography). If this
    /// fails on one OS only, Windows and Linux builds would not interoperate.
    #[test]
    fn cross_backend_pinning() {
        let a = EcdhKey::from_private(&h(D0), &h(Q0)).unwrap();
        let b = EcdhKey::from_private(&h(D1), &h(Q1)).unwrap();
        assert_eq!(a.public_bytes().unwrap(), h::<64>(Q0));
        assert_eq!(b.public_bytes().unwrap(), h::<64>(Q1));
        let ab = a.agree(&h(Q1)).unwrap();
        let ba = b.agree(&h(Q0)).unwrap();
        assert_eq!(hex_encode(&ab.0), "69854de86f85d63854b189cd4f7a556c668977ed93277edc449e9f7655b28175");
        assert_eq!(ab.0, ba.0);

        // A record framed as channel.rs does: nonce = 0u32 | seq:u64le (seq 42), AAD = len:u32le.
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let mut nonce = [0u8; NONCE_LEN];
        nonce[4] = 42;
        let plain = *b"safe-rdp/2 cross-backend pinning vector";
        let aad = ((plain.len() + TAG_LEN) as u32).to_le_bytes();
        let aead = Aead::new(&key).unwrap();
        let mut data = plain;
        let tag = aead.seal(&nonce, &aad, &mut data).unwrap();
        assert_eq!(hex_encode(&data), "59eca9aabf236b025d0406b4e3d5f6c4babf8e3c3855d064bdbc8d57ad1f35f16e96554af07e17");
        assert_eq!(hex_encode(&tag), "a4116f6a538d7c68e5dcef81119623c9");
        aead.open(&nonce, &aad, &mut data, &tag).unwrap();
        assert_eq!(data, plain);
    }

    /// A shared secret whose first byte is zero (made with OpenSSL): every backend must keep it,
    /// all 32 bytes, or one handshake in 256 fails between them.
    #[test]
    fn ecdh_keeps_a_leading_zero() {
        let k = EcdhKey::from_private(&h(LEADING_ZERO_D), &h(LEADING_ZERO_Q)).unwrap();
        assert_eq!(hex_encode(&k.agree(&h(LEADING_ZERO_PEER)).unwrap().0), LEADING_ZERO_SECRET);
    }

    const LEADING_ZERO_D: &str = "4c1878c43baf7d586d7fdd9e05d6bc25d9d808e179f02fb2b0595ca324b8fe5f";
    const LEADING_ZERO_Q: &str = concat!(
        "5de4347ae98154a6cc25f4e5df12b92956c5a678f656731780107beb1e2b9288",
        "8e145f52939c8c8f03c7b0699fbe417f1f619e46194e8656b92fa2766f50c84e"
    );
    const LEADING_ZERO_PEER: &str = concat!(
        "1c3b316b2a830b95c33db030f5b822c0b84cc4f5e8e64bed07a4c3e0be9e86aa",
        "b74fab021fcef445bfc46fdc27cc6a44a58d72a30bbb0805b9418c67a7f44296"
    );
    const LEADING_ZERO_SECRET: &str = "00048c61f1b2a4063a21c0ec1bac79cd87518cc7fbbb7ff025deb48c7bd26045";

    #[test]
    fn ecdh_rejects_non_canonical_points() {
        let a = EcdhKey::generate().unwrap();
        // (0, y) is on P-256 and must be accepted; the same point with x written as p must not.
        let y = "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4";
        let zero_x: [u8; 64] = h(&format!("{:064x}{y}", 0));
        assert!(a.agree(&zero_x).is_ok());
        let x_is_p: [u8; 64] = h(&format!("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff{y}"));
        assert!(a.agree(&x_is_p).is_err());
        assert!(a.agree(&[0xff; 64]).is_err());
    }

    #[test]
    fn hmac_empty_key_and_message() {
        assert_eq!(
            hex_encode(&hmac_sha256(&[], &[])),
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
        assert_eq!(hmac_sha256(&[], &[b"", b""]), hmac_sha256(&[], &[]));
    }

    #[test]
    fn aes_gcm_nist_case13_empty_plaintext() {
        let aead = Aead::new(&[0u8; 32]).unwrap();
        let tag = aead.seal(&[0u8; 12], &[], &mut []).unwrap();
        assert_eq!(hex_encode(&tag), "530f8afbc74536b9a963b4f1c4cb738b");
        aead.open(&[0u8; 12], &[], &mut [], &tag).unwrap();
        let mut bad = tag;
        bad[15] ^= 1;
        assert!(aead.open(&[0u8; 12], &[], &mut [], &bad).is_err());
    }

    #[test]
    fn aead_is_reusable_after_failed_open() {
        let aead = Aead::new(&[9u8; 32]).unwrap();
        for seq in 0..3u8 {
            let nonce = [seq; NONCE_LEN];
            let mut data = [seq; 50];
            let tag = aead.seal(&nonce, b"hdr", &mut data).unwrap();
            let mut bad = data;
            bad[0] ^= 1;
            assert!(aead.open(&nonce, b"hdr", &mut bad, &tag).is_err());
            assert_eq!(bad, [0u8; 50], "failed open must wipe the buffer");
            aead.open(&nonce, b"hdr", &mut data, &tag).unwrap();
            assert_eq!(data, [seq; 50]);
        }
    }

    #[test]
    fn sha256_million_a_streamed() {
        let mut s = Sha256::new();
        for _ in 0..1000 {
            s.update(&[b'a'; 1000]);
        }
        assert_eq!(hex_encode(&s.finish()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    /// Live interoperability check of the whole channel (ECDH, HKDF, AES-GCM records) between two
    /// builds, typically a Linux (OpenSSL) host and a Windows (CNG) viewer. Without SRDP_INTEROP
    /// both halves run here over loopback. Across machines, with the port forwarded over SSH:
    ///
    /// ```text
    /// linux$ SRDP_INTEROP=serve:127.0.0.1:0 cargo test interop -- --ignored --nocapture  # prints PORT
    /// win$   ssh -N -L 127.0.0.1:47100:127.0.0.1:PORT linux-host
    /// win$   SRDP_INTEROP=connect:127.0.0.1:47100 cargo test interop -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "cross-machine check, see the doc comment"]
    fn interop_channel() {
        match std::env::var("SRDP_INTEROP") {
            Ok(v) if v.starts_with("serve:") => interop::serve(std::net::TcpListener::bind(&v[6..]).unwrap()),
            Ok(v) if v.starts_with("connect:") => interop::connect(&v[8..]),
            Ok(v) => panic!("SRDP_INTEROP must be serve:ADDR or connect:ADDR, not {v:?}"),
            Err(_) => {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let addr = l.local_addr().unwrap().to_string();
                let host = std::thread::spawn(move || interop::serve(l));
                interop::connect(&addr);
                host.join().unwrap();
            }
        }
    }

    mod interop {
        use crate::channel::{RecordReader, RecordWriter, client_handshake, server_handshake};
        use crate::crypto::sha256;
        use std::net::{TcpListener, TcpStream};
        use std::time::{Duration, Instant};

        const PSK: [u8; 32] = [0x5a; 32];
        const BACKEND: &str = if cfg!(windows) {
            "CNG"
        } else if cfg!(target_os = "android") {
            "JCA"
        } else {
            "OpenSSL"
        };
        const PAYLOAD_LEN: usize = 100_000;
        const TIMEOUT: Duration = Duration::from_secs(30);

        fn payload() -> Vec<u8> {
            let mut p: Vec<u8> = (0..PAYLOAD_LEN as u32).map(|i| (i * 31 % 251) as u8).collect();
            p.extend_from_slice(BACKEND.as_bytes());
            p
        }

        /// Host half: accepts one viewer and answers its record with the record's SHA-256 and our backend.
        pub fn serve(l: TcpListener) {
            eprintln!("interop: {BACKEND} host listening on {}", l.local_addr().unwrap());
            l.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(300);
            let mut s = loop {
                match l.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(50))
                    }
                    Err(e) => panic!("no viewer connected: {e}"),
                }
            };
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(TIMEOUT)).unwrap();
            let keys = server_handshake(&mut s, &PSK).unwrap();
            let mut r = RecordReader::new(s.try_clone().unwrap(), keys.recv);
            let mut w = RecordWriter::new(s, keys.send);
            let msg = r.recv().unwrap().to_vec();
            let mut reply = sha256(&[&msg]).to_vec();
            reply.extend_from_slice(BACKEND.as_bytes());
            w.send(&reply).unwrap();
            let peer = String::from_utf8_lossy(msg.get(PAYLOAD_LEN..).unwrap_or_default());
            eprintln!("interop: OK, {BACKEND} host served a {peer} viewer");
        }

        /// Viewer half: handshakes, sends a large record and checks the host's digest of it.
        pub fn connect(addr: &str) {
            let mut s = TcpStream::connect(addr).unwrap();
            s.set_read_timeout(Some(TIMEOUT)).unwrap();
            let keys = client_handshake(&mut s, &PSK).unwrap();
            let mut w = RecordWriter::new(s.try_clone().unwrap(), keys.send);
            let mut r = RecordReader::new(s, keys.recv);
            let msg = payload();
            w.send(&msg).unwrap();
            let reply = r.recv().unwrap();
            assert!(reply.len() > 32);
            assert_eq!(reply[..32], sha256(&[&msg]));
            eprintln!("interop: OK, {BACKEND} viewer <-> {} host", String::from_utf8_lossy(&reply[32..]));
        }
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
