//! X11 screen capture (placeholder until the X11 backend lands).

use crate::bail;
use crate::proto::Cursor;
pub use crate::screen::{Area, MonitorSel};
use crate::util::Result;

pub fn monitors() -> Vec<Area> {
    Vec::new()
}

pub fn resolve(_sel: MonitorSel) -> Option<Area> {
    None
}

pub struct Capturer;

impl Capturer {
    pub fn open(_sel: MonitorSel, _area: Area) -> Result<Capturer> {
        bail!("X11 capture is not implemented yet")
    }

    pub fn try_upgrade(&mut self, _sel: MonitorSel) -> bool {
        false
    }

    pub fn backend(&self) -> &'static str {
        "X11"
    }

    pub fn area(&self) -> Area {
        Area::default()
    }

    pub fn waits_for_changes(&self) -> bool {
        false
    }

    pub fn next_frame(&mut self, _timeout_ms: u32) -> Result<bool> {
        bail!("X11 capture is not implemented yet")
    }

    pub fn pixels(&self) -> &[u8] {
        &[]
    }
}

pub struct CursorTracker;

impl CursorTracker {
    pub fn new() -> CursorTracker {
        CursorTracker
    }

    pub fn current(&self) -> Cursor {
        Cursor::Arrow
    }
}
