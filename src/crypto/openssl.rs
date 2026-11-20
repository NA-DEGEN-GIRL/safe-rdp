//! Linux backend: the system OpenSSL libcrypto, loaded at run time (placeholder).

use super::{NONCE_LEN, PUBKEY_LEN, TAG_LEN};
use crate::bail;
use crate::util::{Result, Secret};

pub fn random(_buf: &mut [u8]) -> Result<()> {
    bail!("libcrypto backend not implemented yet")
}

pub fn sha256(_parts: &[&[u8]]) -> [u8; 32] {
    unimplemented!("libcrypto backend not implemented yet")
}

pub fn hmac_sha256(_key: &[u8], _parts: &[&[u8]]) -> [u8; 32] {
    unimplemented!("libcrypto backend not implemented yet")
}

pub struct Sha256;

impl Sha256 {
    pub fn new() -> Self {
        unimplemented!("libcrypto backend not implemented yet")
    }

    pub fn update(&mut self, _data: &[u8]) {}

    pub fn finish(self) -> [u8; 32] {
        unimplemented!("libcrypto backend not implemented yet")
    }
}

pub struct EcdhKey;

impl EcdhKey {
    pub fn generate() -> Result<Self> {
        bail!("libcrypto backend not implemented yet")
    }

    #[cfg(test)]
    pub fn from_private(_d: &[u8; 32], _q: &[u8; PUBKEY_LEN]) -> Result<Self> {
        bail!("libcrypto backend not implemented yet")
    }

    pub fn public_bytes(&self) -> Result<[u8; PUBKEY_LEN]> {
        bail!("libcrypto backend not implemented yet")
    }

    pub fn agree(&self, _peer: &[u8; PUBKEY_LEN]) -> Result<Secret<32>> {
        bail!("libcrypto backend not implemented yet")
    }
}

pub struct Aead;

impl Aead {
    pub fn new(_key: &[u8; 32]) -> Result<Self> {
        bail!("libcrypto backend not implemented yet")
    }

    pub fn seal(&self, _nonce: &[u8; NONCE_LEN], _aad: &[u8], _data: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        bail!("libcrypto backend not implemented yet")
    }

    pub fn open(&self, _nonce: &[u8; NONCE_LEN], _aad: &[u8], _data: &mut [u8], _tag: &[u8; TAG_LEN]) -> Result<()> {
        bail!("libcrypto backend not implemented yet")
    }
}
