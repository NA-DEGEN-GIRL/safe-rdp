//! Authenticated key exchange and encrypted record layer.
//!
//! Handshake (both sides hold the same 256-bit pre-shared key `psk`):
//!
//! ```text
//! C -> S  ClientHello = "SRDP" | ver | nonce_c[32] | ecdh_pub_c[64]
//! S -> C  ServerHello = "SRDP" | ver | nonce_s[32] | ecdh_pub_s[64] | server_confirm[32]
//! C -> S  client_confirm[32]
//!
//! th   = SHA-256(label | ClientHello | ServerHello-without-confirm)
//! prk  = HKDF-Extract(salt = psk, ikm = ECDH(eph_c, eph_s))
//! okm  = HKDF-Expand(prk, "keys" | th, 128)
//!      = key_c2s | key_s2c | server_confirm | client_confirm
//! ```
//!
//! Ephemeral ECDH gives forward secrecy; mixing in the PSK authenticates both ends.
//! The server proves itself first, so a client never reveals anything to a fake server.
//!
//! Records: `len:u32le | AES-256-GCM(ciphertext) | tag[16]`, nonce = 0u32 | seq:u64le,
//! AAD = the length prefix. Each direction has its own key and counter.

use crate::bail;
use crate::crypto::{self, Aead, EcdhKey, NONCE_LEN, PUBKEY_LEN, TAG_LEN};
use crate::util::{Error, Result, Secret, SecureVec, wipe};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub const MAGIC: &[u8; 4] = b"SRDP";
pub const VERSION: u8 = 2;
const HELLO_LEN: usize = 4 + 1 + 32 + PUBKEY_LEN;
const TRANSCRIPT_LABEL: &[u8] = b"safe-rdp/2 transcript";
const KEYS_LABEL: &[u8] = b"safe-rdp/2 keys";
/// Upper bound on a single record; bounds memory a peer can make us allocate.
pub const MAX_RECORD: usize = 32 << 20;
/// Error text for an orderly or abrupt close by the peer; callers treat it as a normal end.
pub const CLOSED: &str = "connection closed by peer";

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    use ErrorKind::*;
    r.read_exact(buf).map_err(|e| match e.kind() {
        UnexpectedEof | ConnectionReset | ConnectionAborted => Error::msg(CLOSED),
        TimedOut | WouldBlock => Error::msg("connection timed out"),
        _ => e.into(),
    })
}

/// A socket with an absolute deadline: each read and write gets only the time that is left.
/// The socket's own timeouts restart with every byte, so a peer trickling its handshake or
/// first record could otherwise hold the other end (a host's pending slot, a viewer's
/// connection attempt) for many minutes.
pub struct Deadline<'a> {
    pub s: &'a TcpStream,
    pub until: Instant,
}

impl Deadline<'_> {
    fn left(&self) -> std::io::Result<Duration> {
        match self.until.checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => Ok(d),
            _ => Err(ErrorKind::TimedOut.into()),
        }
    }
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.s.set_read_timeout(Some(self.left()?))?;
        let mut s = self.s;
        s.read(buf)
    }
}

impl Write for Deadline<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.s.set_write_timeout(Some(self.left()?))?;
        let mut s = self.s;
        s.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct SessionKeys {
    pub send: Aead,
    pub recv: Aead,
}

struct Derived {
    c2s: Secret<32>,
    s2c: Secret<32>,
    server_confirm: Secret<32>,
    client_confirm: Secret<32>,
}

fn hello(nonce: &[u8; 32], pubkey: &[u8; PUBKEY_LEN]) -> [u8; HELLO_LEN] {
    let mut h = [0u8; HELLO_LEN];
    h[0..4].copy_from_slice(MAGIC);
    h[4] = VERSION;
    h[5..37].copy_from_slice(nonce);
    h[37..].copy_from_slice(pubkey);
    h
}

fn parse_hello(h: &[u8; HELLO_LEN]) -> Result<[u8; PUBKEY_LEN]> {
    if &h[0..4] != MAGIC {
        bail!("peer is not a safe-rdp endpoint");
    }
    if h[4] != VERSION {
        bail!("protocol version mismatch (peer {}, ours {VERSION})", h[4]);
    }
    let mut pk = [0u8; PUBKEY_LEN];
    pk.copy_from_slice(&h[37..]);
    Ok(pk)
}

fn derive(psk: &[u8; 32], eph: &EcdhKey, peer_pub: &[u8; PUBKEY_LEN], ch: &[u8], sh: &[u8]) -> Result<Derived> {
    let shared = eph.agree(peer_pub)?;
    let th = crypto::sha256(&[TRANSCRIPT_LABEL, ch, sh]);
    let prk = crypto::hkdf_extract(psk, &shared.0);
    let mut okm = Secret::<128>::zero();
    crypto::hkdf_expand(&prk.0, &[KEYS_LABEL, &th], &mut okm.0);
    let take = |i: usize| {
        let mut s = Secret::<32>::zero();
        s.0.copy_from_slice(&okm.0[i * 32..i * 32 + 32]);
        s
    };
    Ok(Derived { c2s: take(0), s2c: take(1), server_confirm: take(2), client_confirm: take(3) })
}

pub fn client_handshake<S: Read + Write>(s: &mut S, psk: &[u8; 32]) -> Result<SessionKeys> {
    let eph = EcdhKey::generate()?;
    let mut nonce = [0u8; 32];
    crypto::random(&mut nonce)?;
    let ch = hello(&nonce, &eph.public_bytes()?);
    s.write_all(&ch)?;
    s.flush()?;

    let mut sh = [0u8; HELLO_LEN];
    let mut confirm = [0u8; 32];
    read_full(s, &mut sh)?;
    read_full(s, &mut confirm)?;
    let peer = parse_hello(&sh)?;
    let d = derive(psk, &eph, &peer, &ch, &sh)?;
    if !crypto::ct_eq(&confirm, &d.server_confirm.0) {
        bail!("host failed authentication (wrong key, or someone is impersonating the host)");
    }
    s.write_all(&d.client_confirm.0)?;
    s.flush()?;
    Ok(SessionKeys { send: Aead::new(&d.c2s.0)?, recv: Aead::new(&d.s2c.0)? })
}

pub fn server_handshake<S: Read + Write>(s: &mut S, psk: &[u8; 32]) -> Result<SessionKeys> {
    let mut ch = [0u8; HELLO_LEN];
    read_full(s, &mut ch)?;
    let peer = parse_hello(&ch)?;

    let eph = EcdhKey::generate()?;
    let mut nonce = [0u8; 32];
    crypto::random(&mut nonce)?;
    let sh = hello(&nonce, &eph.public_bytes()?);
    let d = derive(psk, &eph, &peer, &ch, &sh)?;
    let mut msg = [0u8; HELLO_LEN + 32];
    msg[..HELLO_LEN].copy_from_slice(&sh);
    msg[HELLO_LEN..].copy_from_slice(&d.server_confirm.0);
    s.write_all(&msg)?;
    s.flush()?;

    let mut confirm = [0u8; 32];
    read_full(s, &mut confirm).map_err(|e| match e.to_string().as_str() {
        CLOSED => Error::msg("viewer hung up during the handshake (it probably has a different key)"),
        _ => e,
    })?;
    if !crypto::ct_eq(&confirm, &d.client_confirm.0) {
        bail!("client failed authentication");
    }
    Ok(SessionKeys { send: Aead::new(&d.s2c.0)?, recv: Aead::new(&d.c2s.0)? })
}

fn nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&seq.to_le_bytes());
    n
}

pub struct RecordWriter<W: Write> {
    w: W,
    aead: Aead,
    seq: u64,
    buf: Vec<u8>,
    /// A write failed: the peer may have part of a record, and nothing after it would authenticate.
    failed: bool,
}

impl<W: Write> RecordWriter<W> {
    pub fn new(w: W, aead: Aead) -> Self {
        RecordWriter { w, aead, seq: 0, buf: Vec::new(), failed: false }
    }

    /// The same record stream, written through `w` from here on (see `RecordReader::with_reader`).
    pub fn with_writer<S: Write>(self, w: S) -> RecordWriter<S> {
        RecordWriter { w, aead: self.aead, seq: self.seq, buf: self.buf, failed: self.failed }
    }

    /// Encrypts and sends one record. Once a write has failed every later send fails at once:
    /// what follows a record cut off would only make the peer fail authentication, as tampering.
    pub fn send(&mut self, msg: &[u8]) -> Result<()> {
        let total = msg.len() + TAG_LEN;
        if self.failed {
            bail!("an earlier send on this connection failed");
        }
        if msg.is_empty() || total > MAX_RECORD {
            bail!("record size {} out of range", msg.len());
        }
        if self.seq == u64::MAX {
            bail!("record counter exhausted");
        }
        let len = (total as u32).to_le_bytes();
        self.buf.clear();
        self.buf.extend_from_slice(&len);
        self.buf.extend_from_slice(msg);
        let tag = self.aead.seal(&nonce(self.seq), &len, &mut self.buf[4..])?;
        self.seq += 1;
        self.buf.extend_from_slice(&tag);
        // The sequence number stays used either way: a nonce is never sealed with twice.
        self.failed = true;
        self.w.write_all(&self.buf)?;
        self.w.flush()?;
        self.failed = false;
        // Large frame buffers would otherwise linger; keep a modest allocation around.
        if self.buf.capacity() > 4 << 20 {
            self.buf = Vec::new();
        }
        Ok(())
    }
}

pub struct RecordReader<R: Read> {
    r: R,
    aead: Aead,
    seq: u64,
    buf: SecureVec,
}

impl<R: Read> RecordReader<R> {
    pub fn new(r: R, aead: Aead) -> Self {
        RecordReader { r, aead, seq: 0, buf: SecureVec::default() }
    }

    /// The same record stream, read through `r` from here on (the same connection, read
    /// differently: say once a deadline for the first records no longer applies).
    pub fn with_reader<S: Read>(self, r: S) -> RecordReader<S> {
        RecordReader { r, aead: self.aead, seq: self.seq, buf: self.buf }
    }

    /// Reads, authenticates and decrypts the next record. The returned slice is valid
    /// until the next call.
    pub fn recv(&mut self) -> Result<&[u8]> {
        self.recv_max(MAX_RECORD - TAG_LEN)
    }

    /// `recv` of a message of at most `max` bytes: a longer record is refused as soon as its
    /// length arrives, before anything is allocated or read for it.
    pub fn recv_max(&mut self, max: usize) -> Result<&[u8]> {
        let mut len = [0u8; 4];
        read_full(&mut self.r, &mut len)?;
        let total = u32::from_le_bytes(len) as usize;
        if total <= TAG_LEN || total > MAX_RECORD || total - TAG_LEN > max {
            bail!("invalid record length {total}");
        }
        if self.seq == u64::MAX {
            bail!("record counter exhausted");
        }
        // Wipe the previous plaintext before reusing the buffer.
        wipe(&mut self.buf.0);
        self.buf.0.resize(total, 0);
        read_full(&mut self.r, &mut self.buf.0)?;
        let body_len = total - TAG_LEN;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&self.buf.0[body_len..]);
        self.aead.open(&nonce(self.seq), &len, &mut self.buf.0[..body_len], &tag)?;
        self.seq += 1;
        Ok(&self.buf.0[..body_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn pair(psk_c: [u8; 32], psk_s: [u8; 32]) -> (Result<SessionKeys>, Result<SessionKeys>, TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let r = server_handshake(&mut s, &psk_s);
            (r, s)
        });
        let mut c = TcpStream::connect(addr).unwrap();
        let rc = client_handshake(&mut c, &psk_c);
        if rc.is_err() {
            let _ = c.shutdown(std::net::Shutdown::Both);
        }
        let (rs, s) = t.join().unwrap();
        (rc, rs, c, s)
    }

    #[test]
    fn handshake_and_records() {
        let (rc, rs, c, s) = pair([9u8; 32], [9u8; 32]);
        let kc = rc.unwrap();
        let ks = rs.unwrap();
        let mut cw = RecordWriter::new(c.try_clone().unwrap(), kc.send);
        let mut cr = RecordReader::new(c, kc.recv);
        let mut sw = RecordWriter::new(s.try_clone().unwrap(), ks.send);
        let mut sr = RecordReader::new(s, ks.recv);
        for i in 0..5u8 {
            cw.send(&[i; 100]).unwrap();
            assert_eq!(sr.recv().unwrap(), &[i; 100]);
            sw.send(&vec![i; 70000]).unwrap();
            assert_eq!(cr.recv().unwrap(), &vec![i; 70000][..]);
        }
    }

    #[test]
    fn wrong_key_rejected() {
        let (rc, rs, _c, _s) = pair([1u8; 32], [2u8; 32]);
        assert!(rc.is_err());
        assert!(rs.is_err());
    }

    #[test]
    fn tampered_record_rejected() {
        let (rc, rs, c, s) = pair([5u8; 32], [5u8; 32]);
        let kc = rc.unwrap();
        let ks = rs.unwrap();
        // Encrypt into a buffer, flip a bit, then feed it to the reader.
        let mut wire = Vec::new();
        let mut w = RecordWriter::new(&mut wire, kc.send);
        w.send(b"move mouse").unwrap();
        w.send(b"second").unwrap();
        drop(w);
        wire[6] ^= 0x40;
        let mut r = RecordReader::new(&wire[..], ks.recv);
        assert!(r.recv().is_err());
        drop((c, s));
    }

    #[test]
    fn replayed_record_rejected() {
        let (rc, rs, _c, _s) = pair([5u8; 32], [5u8; 32]);
        let (kc, ks) = (rc.unwrap(), rs.unwrap());
        let mut wire = Vec::new();
        let mut w = RecordWriter::new(&mut wire, kc.send);
        w.send(b"click").unwrap();
        drop(w);
        let twice = [wire.clone(), wire].concat();
        let mut r = RecordReader::new(&twice[..], ks.recv);
        assert_eq!(r.recv().unwrap(), b"click");
        assert!(r.recv().is_err());
    }

    #[test]
    fn records_longer_than_the_caller_takes_are_refused_unread() {
        let key = [8u8; 32];
        let mut wire = Vec::new();
        let mut w = RecordWriter::new(&mut wire, Aead::new(&key).unwrap());
        w.send(b"hello").unwrap();
        w.send(&[7; 64]).unwrap();
        w.send(&[7; 65]).unwrap();
        drop(w);
        let mut r = RecordReader::new(&wire[..], Aead::new(&key).unwrap());
        assert_eq!(r.recv_max(5).unwrap(), b"hello");
        assert_eq!(r.recv_max(64).unwrap(), &[7; 64]);
        let e = r.recv_max(64).unwrap_err().to_string();
        assert_eq!(e, format!("invalid record length {}", 65 + TAG_LEN));
        // Only the length of a record as large as any may be has come: refused at once, with
        // nothing allocated for it (`recv` would allocate the 32 MiB and wait for them).
        let announced = (MAX_RECORD as u32).to_le_bytes();
        let mut r = RecordReader::new(&announced[..], Aead::new(&key).unwrap());
        assert!(r.recv_max(64).unwrap_err().to_string().starts_with("invalid record length"));
        assert_eq!(r.buf.0.capacity(), 0);
        // The rest of a stream goes on where the first reader left off.
        let mut r = RecordReader::new(&wire[..], Aead::new(&key).unwrap());
        assert_eq!(r.recv().unwrap(), b"hello");
        let mut r = r.with_reader(&wire[4 + 5 + TAG_LEN..]);
        assert_eq!(r.recv().unwrap(), &[7; 64]);
    }

    /// Takes `room` bytes, then fails every write (a connection that timed out or broke).
    struct Breaks {
        wire: Vec<u8>,
        room: usize,
    }

    impl Write for Breaks {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.room);
            if n == 0 {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            self.room -= n;
            self.wire.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn nothing_is_sent_after_a_record_cut_off() {
        let key = [3u8; 32];
        let mut w = RecordWriter::new(Breaks { wire: Vec::new(), room: 4 + 5 + TAG_LEN + 10 }, Aead::new(&key).unwrap());
        w.send(b"first").unwrap();
        assert!(w.send(&[1; 64]).is_err());
        // The connection works again (a timeout that passed), but the peer has part of a record.
        w.w.room = usize::MAX;
        assert!(w.send(b"later").unwrap_err().to_string().contains("earlier send"));
        let mut r = RecordReader::new(&w.w.wire[..], Aead::new(&key).unwrap());
        assert_eq!(r.recv().unwrap(), b"first");
        assert_eq!(w.w.wire.len(), 4 + 5 + TAG_LEN + 10);
        // A stream moved to another writer keeps going where it was.
        let mut wire = Vec::new();
        let mut w = RecordWriter::new(&mut wire, Aead::new(&key).unwrap());
        w.send(b"one").unwrap();
        let mut more = Vec::new();
        w.with_writer(&mut more).send(b"two").unwrap();
        let both = [wire, more].concat();
        let mut r = RecordReader::new(&both[..], Aead::new(&key).unwrap());
        assert_eq!((r.recv().unwrap().to_vec(), r.recv().unwrap().to_vec()), (b"one".to_vec(), b"two".to_vec()));
    }
}
