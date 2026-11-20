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
