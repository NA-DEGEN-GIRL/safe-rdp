//! X11 clipboard bridge (not supported yet).

use crate::bail;
use crate::util::Result;

pub struct Clipboard;

impl Clipboard {
    pub fn spawn(_on_change: impl Fn(String) + Send + 'static) -> Result<Clipboard> {
        bail!("clipboard sharing is not supported on Linux yet")
    }

    pub fn set(&self, _text: String) {}
}

/// Files currently copied on this machine (none: X11 file clipboards are not supported).
pub fn copied_files() -> Vec<std::path::PathBuf> {
    Vec::new()
}
