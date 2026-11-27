//! safe-rdp viewer for Android, the native part: the session (connection, decoding, drawing,
//! input, sound) runs here, on the same code as the desktop viewers; the Java side hosts the
//! views and the platform services Rust cannot reach (Keystore, crypto provider, clipboard).
//!
//! The shared modules are compiled from the desktop program's sources (`#[path]`), unchanged, as
//! parts of this crate, so they find each other under the same `crate::` paths.

#![cfg_attr(not(target_os = "android"), allow(dead_code))]

#[path = "../../../src/util.rs"]
#[allow(dead_code)] // the desktop's log file and Win32 helpers
mod util;

#[cfg(target_os = "android")]
#[path = "../../../src/channel.rs"]
mod channel;
#[cfg(target_os = "android")]
#[path = "../../../src/codec/mod.rs"]
#[allow(dead_code)] // the encoder is the host's
mod codec;
#[cfg(target_os = "android")]
#[path = "../../../src/crypto/mod.rs"]
mod crypto;

/// The unit tests of the shared modules built into this crate on the desktop (util's) only need
/// names for temporary files from it.
#[cfg(all(test, not(target_os = "android")))]
mod crypto {
    pub fn random(buf: &mut [u8]) -> crate::util::Result<()> {
        use std::hash::{BuildHasher, RandomState};
        for (i, b) in buf.iter_mut().enumerate() {
            *b = RandomState::new().hash_one(i) as u8;
        }
        Ok(())
    }
}
#[cfg(target_os = "android")]
#[path = "../../../src/keys.rs"]
#[allow(dead_code)]
mod keys;
#[cfg(target_os = "android")]
#[path = "../../../src/net.rs"]
#[allow(dead_code)] // listening is the host's
mod net;
#[path = "../../../src/proto.rs"]
#[allow(dead_code)]
mod proto;
#[cfg(target_os = "android")]
#[path = "../../../src/viewer.rs"]
mod viewer;

#[path = "../../../src/platform/linux/keymap.rs"]
#[allow(dead_code)] // the X11 parts
mod keymap;

#[path = "../../../src/qr.rs"]
#[allow(dead_code)] // the desktop's encoder
mod qr;
mod touch;
mod view;

#[cfg(target_os = "android")]
#[path = "../../../src/audio.rs"]
#[allow(dead_code)] // the host's encoder
mod audio;
mod cursor;
#[cfg(target_os = "android")]
mod gl;
#[cfg(target_os = "android")]
mod render;
#[cfg(target_os = "android")]
mod session;

#[cfg(target_os = "android")]
mod jni;
#[cfg(target_os = "android")]
mod natives;
mod platform;
#[cfg(target_os = "android")]
mod selftest;

/// What `net` asks of the Tailscale CLI, which an app cannot run: nothing is known.
#[cfg(target_os = "android")]
#[allow(dead_code)]
mod tailscale {
    pub struct Status;

    impl Status {
        pub fn is_own_address(&self, _ip: std::net::IpAddr) -> bool {
            false
        }
    }

    pub fn status() -> Result<Status, String> {
        Err("the Tailscale CLI is not available to apps".into())
    }
}
