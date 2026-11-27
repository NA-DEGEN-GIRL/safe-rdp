//! Key storage on Linux: `$XDG_CONFIG_HOME/safe-rdp/key` (default `~/.config/safe-rdp/key`),
//! directory 0700 and file 0600, like an SSH private key.

use super::xvfb::O_NOFOLLOW;
use crate::keys::format_key;
use crate::util::{Error, Result, Secret, SecureVec, wipe};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

unsafe extern "C" {
    fn geteuid() -> u32;
}

pub fn user_key_path() -> Result<PathBuf> {
    key_path(std::env::var_os("XDG_CONFIG_HOME"), std::env::var_os("HOME"))
}

/// The XDG base directory spec has a relative `XDG_CONFIG_HOME` ignored.
fn key_path(config_home: Option<OsString>, home: Option<OsString>) -> Result<PathBuf> {
    let base = match config_home.map(PathBuf::from).filter(|d| d.is_absolute()) {
        Some(d) => d,
        None => PathBuf::from(home.filter(|h| !h.is_empty()).ok_or("$HOME is not set")?).join(".config"),
    };
    Ok(base.join("safe-rdp").join("key"))
}

pub fn save_user_key(k: &Secret<32>) -> Result<PathBuf> {
    let path = user_key_path()?;
    save_key(&path, k)?;
    Ok(path)
}

fn save_key(path: &Path, k: &Secret<32>) -> Result<()> {
    let dir = path.parent().unwrap();
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    // One made before (by hand, say) must not let anyone else replace the key.
    let m = std::fs::metadata(dir)?;
    if !m.is_dir() || m.uid() != unsafe { geteuid() } || m.mode() & 0o022 != 0 {
        crate::bail!("{} must be a directory of this user that nobody else can write to; run `chmod 700` on it", dir.display());
    }
    let tmp = dir.join(".key.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    let mut text = format_key(k);
    let r = f.write_all(text.as_bytes()).and_then(|_| f.sync_all()).and_then(|_| std::fs::rename(&tmp, path));
    unsafe { wipe(text.as_bytes_mut()) };
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(r?)
}

pub fn load_user_key() -> Result<Secret<32>> {
    load_key(&user_key_path()?)
}

/// Reads the key through the descriptor checked: the file itself (not a link), owned by this
/// user (or root) and private.
fn load_key(path: &Path) -> Result<Secret<32>> {
    let f = match OpenOptions::new().read(true).custom_flags(O_NOFOLLOW).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            crate::bail!("no key stored at {} (run `safe-rdp keygen` or `safe-rdp key import`)", path.display())
        }
        Err(e) => crate::bail!("cannot read key file {}: {e}", path.display()),
    };
    let meta = f.metadata()?;
    if !meta.is_file() {
        crate::bail!("{} is not a regular file", path.display());
    }
    if meta.uid() != unsafe { geteuid() } && meta.uid() != 0 {
        crate::bail!("{} belongs to another user", path.display());
    }
    if meta.mode() & 0o077 != 0 {
        crate::bail!("{} is readable by other users; run `chmod 600` on it", path.display());
    }
    // A key line is short; room for it up front, so the text is never moved (and copied).
    let mut text = String::with_capacity(4096);
    let r = (&f).take(4095).read_to_string(&mut text);
    let k = r.map_err(|e| Error::msg(format!("cannot read key file {}: {e}", path.display()))).and_then(|_| crate::keys::parse_key(&text));
    // All of it: text that was not UTF-8 is cut off again, but stays in the buffer.
    drop(SecureVec(text.into_bytes()));
    k
}

pub fn forget_user_key() -> Result<bool> {
    forget_key(&user_key_path()?)
}

/// Overwrites the key file in place (its own blocks, not a new copy) and deletes it. Anything
/// else of the name, a link say, is only deleted: never what it leads to.
fn forget_key(path: &Path) -> Result<bool> {
    let m = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    if m.is_file() {
        let f = OpenOptions::new().write(true).custom_flags(O_NOFOLLOW).open(path)?;
        let zeros = [0u8; 4096];
        let len = f.metadata()?.len();
        let mut at = 0;
        while at < len {
            let n = (len - at).min(zeros.len() as u64);
            f.write_all_at(&zeros[..n as usize], at)?;
            at += n;
        }
        f.sync_all()?;
    }
    std::fs::remove_file(path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("safe-rdp-keystore-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        dir
    }

    fn key(b: u8) -> Secret<32> {
        let mut k = Secret::<32>::zero();
        k.0 = [b; 32];
        k
    }

    #[test]
    fn config_home_must_be_absolute() {
        let at = |c: Option<&str>, h: Option<&str>| key_path(c.map(Into::into), h.map(Into::into));
        assert_eq!(at(Some("/cfg"), Some("/home/u")).unwrap(), Path::new("/cfg/safe-rdp/key"));
        for relative in ["", "cfg", "./cfg"] {
            assert_eq!(at(Some(relative), Some("/home/u")).unwrap(), Path::new("/home/u/.config/safe-rdp/key"), "{relative:?}");
        }
        assert_eq!(at(None, Some("/home/u")).unwrap(), Path::new("/home/u/.config/safe-rdp/key"));
        assert!(at(None, None).is_err() && at(Some("cfg"), Some("")).is_err());
    }

    #[test]
    fn keys_are_saved_privately_and_loaded_back() {
        let dir = temp_dir("save");
        let path = dir.join("safe-rdp").join("key");
        save_key(&path, &key(1)).unwrap();
        assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(load_key(&path).unwrap().0, [1; 32]);
        save_key(&path, &key(2)).unwrap();
        assert_eq!(load_key(&path).unwrap().0, [2; 32]);
        assert!(!path.with_file_name(".key.tmp").exists());

        // A directory others can write to is refused, and nothing is left behind.
        let open = dir.join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(save_key(&open.join("key"), &key(3)).is_err());
        assert_eq!(std::fs::read_dir(&open).unwrap().count(), 0);
        // A failed save removes its temporary file: the key's name taken by a directory.
        let blocked = dir.join("blocked");
        std::fs::create_dir_all(blocked.join("key").join("inside")).unwrap();
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(save_key(&blocked.join("key"), &key(4)).is_err());
        assert!(!blocked.join(".key.tmp").exists(), "temporary file left behind");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_a_private_key_file_itself_is_loaded() {
        let dir = temp_dir("load");
        let path = dir.join("key");
        assert!(load_key(&path).err().unwrap().to_string().contains("no key stored"));
        save_key(&path, &key(5)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_key(&path).err().unwrap().to_string().contains("chmod 600"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_key(&link).is_err(), "followed a link");
        assert!(load_key(&dir).is_err(), "read a directory");
        assert_eq!(load_key(&path).unwrap().0, [5; 32]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn forgetting_overwrites_the_key_itself_and_never_follows_links() {
        let dir = temp_dir("forget");
        let path = dir.join("key");
        assert!(!forget_key(&path).unwrap());
        save_key(&path, &key(6)).unwrap();
        // A second name for the same file shows what happened to its contents.
        let other = dir.join("hard");
        std::fs::hard_link(&path, &other).unwrap();
        let len = std::fs::metadata(&path).unwrap().len() as usize;
        assert!(forget_key(&path).unwrap());
        assert!(!path.exists());
        assert_eq!(std::fs::read(&other).unwrap(), vec![0u8; len], "not overwritten in place");

        // A link in the key's place is deleted; what it leads to is left alone.
        let target = dir.join("target");
        std::fs::write(&target, b"keep me").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(forget_key(&path).unwrap());
        assert!(std::fs::symlink_metadata(&path).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep me");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
