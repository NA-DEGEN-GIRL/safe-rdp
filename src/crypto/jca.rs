//! Android backend: the platform's Java crypto provider (Conscrypt, BoringSSL inside, updated
//! with the system), reached through the app's JNI layer (`crate::jni`, android/native) and the
//! static methods of its `Crypto` class.
//!
//! Data goes to Java as direct `ByteBuffer`s over this process's memory, which Conscrypt hashes,
//! MACs and seals in place: record plaintext does not pass through the Java heap. Key bytes do
//! (`SecretKeySpec` copies them; the arrays handed over are zeroed afterwards, those copies only
//! when the collector reuses their memory), as does the ECDH secret: both are the session's own,
//! made fresh for every connection. The pre-shared key never does (it is a Keystore key, see the
//! app's `KeyVault`).

use super::{NONCE_LEN, PUBKEY_LEN, TAG_LEN};
use crate::bail;
use crate::jni::{Env, Global, Local, env, obj, up};
use crate::util::{Result, Secret, wipe};
use std::sync::Mutex;

/// A direct buffer over `data`, which Java only reads.
fn reading(env: Env, data: &[u8]) -> Result<Local> {
    env.direct(data.as_ptr().cast_mut(), data.len())
}

/// Copies `byte[]` `a` (a secret made by Java) into `out` and zeroes the array.
fn take(env: Env, a: &Local, out: &mut [u8]) -> Result<()> {
    let r = env.read_bytes(a.obj, out);
    env.zero(a.obj);
    r
}

pub fn random(buf: &mut [u8]) -> Result<()> {
    let env = env()?;
    let a = env.byte_array(&vec![0; buf.len()])?;
    env.call_void(up()?.random, &[obj(a.obj)])?;
    take(env, &a, buf)
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finish()
}

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let r = (|| -> Result<[u8; 32]> {
        let (env, up) = (env()?, up()?);
        let k = env.byte_array(key)?;
        let mac = env.call_object(up.hmac, &[obj(k.obj)]);
        env.zero(k.obj);
        let mac = mac?;
        for p in parts {
            let b = reading(env, p)?;
            env.call_void(up.hmac_update, &[obj(mac.obj), obj(b.obj)])?;
        }
        let mut out = [0u8; 32];
        take(env, &env.call_object(up.hmac_finish, &[obj(mac.obj)])?, &mut out)?;
        Ok(out)
    })();
    r.unwrap_or_else(|e| panic!("HMAC-SHA256 failed: {e}"))
}

/// Incremental SHA-256 (a `java.security.MessageDigest`).
pub struct Sha256(Global);

impl Sha256 {
    pub fn new() -> Self {
        let r = (|| -> Result<Global> {
            let env = env()?;
            env.global(&env.call_object(up()?.digest, &[])?)
        })();
        Sha256(r.unwrap_or_else(|e| panic!("SHA-256 unavailable: {e}")))
    }

    pub fn update(&mut self, data: &[u8]) {
        let r = (|| -> Result<()> {
            let env = env()?;
            let b = reading(env, data)?;
            env.call_void(up()?.digest_update, &[obj(self.0.obj()), obj(b.obj)])
        })();
        r.unwrap_or_else(|e| panic!("SHA-256 failed: {e}"))
    }

    pub fn finish(self) -> [u8; 32] {
        let r = (|| -> Result<[u8; 32]> {
            let env = env()?;
            let mut out = [0u8; 32];
            env.read_bytes(env.call_object(up()?.digest_finish, &[obj(self.0.obj())])?.obj, &mut out)?;
            Ok(out)
        })();
        r.unwrap_or_else(|e| panic!("SHA-256 failed: {e}"))
    }
}

/// An ephemeral P-256 key pair (a `java.security.KeyPair`; the private key stays in Conscrypt).
pub struct EcdhKey(Global);

impl EcdhKey {
    pub fn generate() -> Result<Self> {
        let env = env()?;
        Ok(EcdhKey(env.global(&env.call_object(up()?.ecdh_generate, &[])?)?))
    }

    /// A known key pair (test vectors).
    #[allow(dead_code)]
    pub fn from_private(d: &[u8; 32], q: &[u8; PUBKEY_LEN]) -> Result<Self> {
        let env = env()?;
        let (da, qa) = (env.byte_array(d)?, env.byte_array(q)?);
        let k = env.call_object(up()?.ecdh_from_private, &[obj(da.obj), obj(qa.obj)]);
        env.zero(da.obj);
        Ok(EcdhKey(env.global(&k?)?))
    }

    pub fn public_bytes(&self) -> Result<[u8; PUBKEY_LEN]> {
        let env = env()?;
        let mut out = [0u8; PUBKEY_LEN];
        env.read_bytes(env.call_object(up()?.ecdh_public, &[obj(self.0.obj())])?.obj, &mut out)?;
        Ok(out)
    }

    /// The shared secret's X coordinate; fails for a point not on the curve (Conscrypt checks).
    pub fn agree(&self, peer: &[u8; PUBKEY_LEN]) -> Result<Secret<32>> {
        let env = env()?;
        let p = env.byte_array(peer)?;
        let s = env.call_object(up()?.ecdh_agree, &[obj(self.0.obj()), obj(p.obj)])?;
        let mut out = Secret::<32>::zero();
        take(env, &s, &mut out.0)?;
        // As the CNG and OpenSSL backends do.
        if out.0.iter().all(|&b| b == 0) {
            bail!("degenerate ECDH secret");
        }
        Ok(out)
    }
}

/// The scratch buffer size kept between records (a full frame's records are 4 MiB).
const SCRATCH_KEEP: usize = 4 << 20;

/// AES-256-GCM under one key (a `javax.crypto.Cipher`, initialised anew for every nonce).
pub struct Aead {
    cipher: Global,
    /// Where a sealed record is written (ciphertext, then tag) and an opened one read from;
    /// wiped when the key goes.
    scratch: Mutex<Vec<u8>>,
}

impl Aead {
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        let env = env()?;
        let k = env.byte_array(key)?;
        let c = env.call_object(up()?.aead, &[obj(k.obj)]);
        env.zero(k.obj);
        Ok(Aead { cipher: env.global(&c?)?, scratch: Mutex::new(Vec::new()) })
    }

    fn scratch(&self, len: usize) -> std::sync::MutexGuard<'_, Vec<u8>> {
        let mut s = self.scratch.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // A large record's buffer is not kept for the small ones after it.
        if s.capacity() > SCRATCH_KEEP && len <= SCRATCH_KEEP {
            wipe(&mut s);
            *s = Vec::new();
        }
        s.resize(len, 0);
        s
    }

    /// Encrypts `data` in place and returns the authentication tag.
    pub fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        let (env, up) = (env()?, up()?);
        let n = data.len();
        let mut out = self.scratch(n + TAG_LEN);
        let (nonce, aad) = (env.byte_array(nonce)?, env.byte_array(aad)?);
        let input = env.direct(data.as_mut_ptr(), n)?;
        let output = env.direct(out.as_mut_ptr(), n + TAG_LEN)?;
        env.call_void(up.aead_seal, &[obj(self.cipher.obj()), obj(nonce.obj), obj(aad.obj), obj(input.obj), obj(output.obj)])?;
        data.copy_from_slice(&out[..n]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&out[n..]);
        Ok(tag)
    }

    /// Decrypts `data` in place; fails (and wipes `data`) if the tag does not verify.
    pub fn open(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<()> {
        let (env, up) = (env()?, up()?);
        let n = data.len();
        let mut sealed = self.scratch(n + TAG_LEN);
        sealed[..n].copy_from_slice(data);
        sealed[n..].copy_from_slice(tag);
        let (nonce, aad) = (env.byte_array(nonce)?, env.byte_array(aad)?);
        let input = env.direct(sealed.as_mut_ptr(), n + TAG_LEN)?;
        let output = env.direct(data.as_mut_ptr(), n)?;
        let args = [obj(self.cipher.obj()), obj(nonce.obj), obj(aad.obj), obj(input.obj), obj(output.obj)];
        match env.call_bool(up.aead_open, &args) {
            Ok(true) => Ok(()),
            Ok(false) => {
                wipe(data);
                bail!("record authentication failed");
            }
            Err(e) => {
                wipe(data);
                bail!("AES-GCM decryption failed: {e}");
            }
        }
    }
}

impl Drop for Aead {
    fn drop(&mut self) {
        wipe(self.scratch.get_mut().unwrap_or_else(std::sync::PoisonError::into_inner));
    }
}
