//! Operating-system layer. Each platform module provides the same items:
//!
//! * `capture::{Capturer, CursorTracker, monitors, resolve}` — screen source
//! * `input::Injector` — synthesises keyboard/mouse events on the host
//! * `desktop::DesktopFollower` — follows the input desktop (no-op where meaningless)
//! * `clipboard::Clipboard` — text clipboard bridge
//! * `mem::{LockedBuf, lock_pages}` — RAM-pinned, wiped pixel buffers
//! * `keystore` — per-user key storage
//! * `viewer::run` — the interactive viewer window
//! * `init_process`, `local_time`, `request_sas`

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;
