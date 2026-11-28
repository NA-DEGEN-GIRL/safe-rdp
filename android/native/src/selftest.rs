//! Checks run on the device (`Native.selfTest`): the crypto backend against the vectors that pin
//! the desktop backends (crypto/mod.rs tests), so that the app interoperates with Windows and
//! Linux hosts, then a whole handshake and record stream over loopback.

use crate::channel::{RecordReader, RecordWriter, client_handshake, server_handshake};
use crate::crypto::{Aead, EcdhKey, NONCE_LEN, Sha256, TAG_LEN, hkdf_expand, hkdf_extract, hmac_sha256, random, sha256};
use crate::util::{Result, hex_decode, hex_encode};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

fn h<const N: usize>(s: &str) -> [u8; N] {
    hex_decode(s).unwrap().try_into().unwrap()
}

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

fn check(ok: bool, what: &str) -> Result<()> {
    if !ok {
        crate::bail!("{what}");
    }
    Ok(())
}

fn digests() -> Result<()> {
    check(hex_encode(&sha256(&[b"a", b"bc"])) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256 abc")?;
    check(hex_encode(&sha256(&[])) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256 empty")?;
    let mut s = Sha256::new();
    for _ in 0..1000 {
        s.update(&[b'a'; 1000]);
    }
    check(hex_encode(&s.finish()) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "sha256 million a")?;
    check(
        hex_encode(&hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"])) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "hmac rfc4231 case 2",
    )?;
    check(hex_encode(&hmac_sha256(&[], &[])) == "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad", "hmac empty key")?;
    let prk = hkdf_extract(&hex_decode("000102030405060708090a0b0c").unwrap(), &[0x0b; 22]);
    check(hex_encode(&prk.0) == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "hkdf extract")?;
    let info = hex_decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let mut okm = [0u8; 42];
    hkdf_expand(&prk.0, &[&info[..4], &info[4..]], &mut okm);
    check(
        hex_encode(&okm) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        "hkdf expand",
    )?;
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    random(&mut a)?;
    random(&mut b)?;
    check(a != b && a != [0; 32], "random")
}

fn gcm() -> Result<()> {
    let aead = Aead::new(&[0u8; 32])?;
    let mut data = [0u8; 16];
    let tag = aead.seal(&[0u8; 12], &[], &mut data)?;
    check(hex_encode(&data) == "cea7403d4d606b6e074ec5d3baf39d18" && hex_encode(&tag) == "d0d1c8a799996bf0265b98b5d48ab919", "gcm case 14")?;
    aead.open(&[0u8; 12], &[], &mut data, &tag)?;
    check(data == [0u8; 16], "gcm case 14 open")?;

    let aead = Aead::new(&[0u8; 32])?;
    let tag = aead.seal(&[1u8; 12], &[], &mut [])?;
    aead.open(&[1u8; 12], &[], &mut [], &tag)?;
    let tag = Aead::new(&[0u8; 32])?.seal(&[0u8; 12], &[], &mut [])?;
    check(hex_encode(&tag) == "530f8afbc74536b9a963b4f1c4cb738b", "gcm case 13 (empty)")?;

    let key: [u8; 32] = h("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let iv: [u8; 12] = h("cafebabefacedbaddecaf888");
    let aad = hex_decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
    let mut data = hex_decode(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    )
    .unwrap();
    let tag = Aead::new(&key)?.seal(&iv, &aad, &mut data)?;
    check(
        hex_encode(&data)
            == "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
            && hex_encode(&tag) == "76fc6ece0f4e1768cddf8853bb2d551b",
        "gcm case 16",
    )?;

    let aead = Aead::new(&[9u8; 32])?;
    for seq in 0..3u8 {
        let nonce = [seq; NONCE_LEN];
        let mut data = [seq; 50];
        let tag = aead.seal(&nonce, b"hdr", &mut data)?;
        let mut bad = data;
        bad[0] ^= 1;
        check(aead.open(&nonce, b"hdr", &mut bad, &tag).is_err(), "gcm rejects tampering")?;
        check(bad == [0u8; 50], "gcm wipes a failed open")?;
        let mut bad_tag = tag;
        bad_tag[15] ^= 1;
        let mut d = data;
        check(aead.open(&nonce, b"hdr", &mut d, &bad_tag).is_err(), "gcm rejects a bad tag")?;
        check(aead.open(&nonce, b"hdX", &mut data.clone(), &tag).is_err(), "gcm rejects other aad")?;
        aead.open(&nonce, b"hdr", &mut data, &tag)?;
        check(data == [seq; 50], "gcm usable after a failed open")?;
    }
    Ok(())
}

fn ecdh() -> Result<()> {
    let peer: [u8; 64] = h(concat!(
        "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
        "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac"
    ));
    let k = EcdhKey::from_private(&h(D0), &h(Q0))?;
    check(k.public_bytes()? == h::<64>(Q0), "ecdh public key")?;
    check(hex_encode(&k.agree(&peer)?.0) == "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b", "ecdh cavs 0")?;

    // crypto/mod.rs `cross_backend_pinning`: the bytes CNG and OpenSSL produce.
    let a = EcdhKey::from_private(&h(D0), &h(Q0))?;
    let b = EcdhKey::from_private(&h(D1), &h(Q1))?;
    let ab = a.agree(&h(Q1))?;
    check(hex_encode(&ab.0) == "69854de86f85d63854b189cd4f7a556c668977ed93277edc449e9f7655b28175", "pinned ecdh")?;
    check(ab.0 == b.agree(&h(Q0))?.0, "pinned ecdh, both ways")?;
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4] = 42;
    let plain = *b"safe-rdp/2 cross-backend pinning vector";
    let aad = ((plain.len() + TAG_LEN) as u32).to_le_bytes();
    let mut data = plain;
    let tag = Aead::new(&key)?.seal(&nonce, &aad, &mut data)?;
    check(
        hex_encode(&data) == "59eca9aabf236b025d0406b4e3d5f6c4babf8e3c3855d064bdbc8d57ad1f35f16e96554af07e17"
            && hex_encode(&tag) == "a4116f6a538d7c68e5dcef81119623c9",
        "pinned record",
    )?;

    // crypto/mod.rs `ecdh_keeps_a_leading_zero` (made with OpenSSL).
    let z = EcdhKey::from_private(
        &h("4c1878c43baf7d586d7fdd9e05d6bc25d9d808e179f02fb2b0595ca324b8fe5f"),
        &h(concat!(
            "5de4347ae98154a6cc25f4e5df12b92956c5a678f656731780107beb1e2b9288",
            "8e145f52939c8c8f03c7b0699fbe417f1f619e46194e8656b92fa2766f50c84e"
        )),
    )?;
    let peer = h(concat!(
        "1c3b316b2a830b95c33db030f5b822c0b84cc4f5e8e64bed07a4c3e0be9e86aa",
        "b74fab021fcef445bfc46fdc27cc6a44a58d72a30bbb0805b9418c67a7f44296"
    ));
    check(
        hex_encode(&z.agree(&peer)?.0) == "00048c61f1b2a4063a21c0ec1bac79cd87518cc7fbbb7ff025deb48c7bd26045",
        "ecdh keeps a leading zero byte",
    )?;

    let x = EcdhKey::generate()?;
    let y = EcdhKey::generate()?;
    check(x.agree(&y.public_bytes()?)?.0 == y.agree(&x.public_bytes()?)?.0, "ecdh agreement")?;
    let mut bogus = y.public_bytes()?;
    bogus[63] ^= 1;
    check(x.agree(&bogus).is_err(), "ecdh rejects a point off the curve")?;
    check(x.agree(&[0u8; 64]).is_err(), "ecdh rejects (0, 0)")?;
    let yy = "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4";
    check(x.agree(&h(&format!("{:064x}{yy}", 0))).is_ok(), "ecdh accepts (0, y)")?;
    check(
        x.agree(&h(&format!("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff{yy}"))).is_err(),
        "ecdh rejects x = p",
    )?;
    check(x.agree(&[0xff; 64]).is_err(), "ecdh rejects all ones")
}

/// A handshake and records both ways over loopback; returns the record throughput.
fn channel() -> Result<String> {
    const PSK: [u8; 32] = [0x5a; 32];
    const MIB: usize = 1 << 20;
    let l = TcpListener::bind("127.0.0.1:0")?;
    let addr = l.local_addr()?;
    let host = std::thread::spawn(move || -> Result<()> {
        let (mut s, _) = l.accept()?;
        let keys = server_handshake(&mut s, &PSK)?;
        let mut r = RecordReader::new(s.try_clone()?, keys.recv);
        let mut w = RecordWriter::new(s, keys.send);
        loop {
            let m = r.recv()?.to_vec();
            if m == b"end" {
                return w.send(b"bye");
            }
            w.send(&sha256(&[&m]))?;
        }
    });
    let mut s = TcpStream::connect(addr)?;
    let keys = client_handshake(&mut s, &PSK)?;
    let mut w = RecordWriter::new(s.try_clone()?, keys.send);
    let mut r = RecordReader::new(s, keys.recv);
    let msg: Vec<u8> = (0..4 * MIB).map(|i| (i * 31 % 251) as u8).collect();
    let started = Instant::now();
    let rounds = 16;
    for _ in 0..rounds {
        w.send(&msg)?;
        check(r.recv()? == sha256(&[&msg]), "record round trip")?;
    }
    let secs = started.elapsed().as_secs_f64();
    w.send(b"end")?;
    check(r.recv()? == b"bye", "orderly end")?;
    host.join().map_err(|_| "loopback host panicked")??;
    // Each 4 MiB went through a seal and an open (and a SHA-256 on the host side).
    Ok(format!("{:.0} MiB/s sealed+opened+hashed", (rounds * 4) as f64 / secs))
}

/// Runs everything; one line per group, "ok" or the first failure.
pub fn run() -> String {
    let mut out = String::new();
    let mut line = |name: &str, r: Result<String>| {
        out.push_str(&match r {
            Ok(note) if note.is_empty() => format!("ok    {name}\n"),
            Ok(note) => format!("ok    {name}: {note}\n"),
            Err(e) => format!("FAIL  {name}: {e}\n"),
        });
    };
    line("digests, hmac, hkdf, random", digests().map(|()| String::new()));
    line("aes-256-gcm", gcm().map(|()| String::new()));
    line("p-256 ecdh", ecdh().map(|()| String::new()));
    line("handshake and records", channel());
    out
}
