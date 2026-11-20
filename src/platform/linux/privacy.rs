//! Privacy mode: blank the host's physical screen and block its local keyboard/mouse while
//! a viewer is connected (placeholder until implemented).

use crate::bail;
use crate::util::Result;

pub struct Privacy;

impl Privacy {
    /// Whether this host can provide privacy mode at all.
    pub fn available() -> bool {
        false
    }

    /// Turns privacy mode on; dropping the returned value turns it off again.
    pub fn enable() -> Result<Privacy> {
        bail!("privacy mode is not available on this host")
    }
}
