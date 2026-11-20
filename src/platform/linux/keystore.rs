//! Key storage on Linux: `$XDG_CONFIG_HOME/safe-rdp/key` (default `~/.config/safe-rdp/key`),
//! directory 0700 and file 0600, like an SSH private key.

use crate::keys::format_key;
use crate::util::{Error, Result, Secret, wipe};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

pub fn user_key_path() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(std::env::var_os("HOME").ok_or("$HOME is not set")?).join(".config"),
    };
    Ok(base.join("safe-rdp").join("key"))
}

pub fn save_user_key(k: &Secret<32>) -> Result<PathBuf> {
    let path = user_key_path()?;
    let dir = path.parent().unwrap();
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let tmp = dir.join(".key.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    let mut text = format_key(k);
    let r = f.write_all(text.as_bytes()).and_then(|_| f.sync_all());
    unsafe { wipe(text.as_bytes_mut()) };
    r?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

pub fn load_user_key() -> Result<Secret<32>> {
    let path = user_key_path()?;
    let meta = std::fs::metadata(&path).map_err(|_| {
        Error::msg(format!("no key stored at {} (run `safe-rdp keygen` or `safe-rdp key import`)", path.display()))
    })?;
    if meta.mode() & 0o077 != 0 {
        crate::bail!("{} is readable by other users; run `chmod 600` on it", path.display());
    }
    crate::keys::load_key_file(&path.to_string_lossy())
}

pub fn forget_user_key() -> Result<bool> {
    let path = user_key_path()?;
    if !path.exists() {
        return Ok(false);
    }
    let len = std::fs::metadata(&path)?.len() as usize;
    std::fs::write(&path, vec![0u8; len])?;
    std::fs::remove_file(&path)?;
    Ok(true)
}
