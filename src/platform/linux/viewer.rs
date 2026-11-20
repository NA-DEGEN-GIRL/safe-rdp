//! X11 viewer (placeholder until the X11 backend lands).

use crate::bail;
use crate::util::{Result, Secret};
use crate::viewer::ViewerOptions;

pub fn run(_target: &str, _opts: ViewerOptions, _psk: Secret<32>) -> Result<()> {
    bail!("the Linux viewer is not implemented yet")
}
