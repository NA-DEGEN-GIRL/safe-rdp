//! Screen geometry shared by every platform.

/// A rectangle of the virtual desktop, in physical pixels.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Area {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}

/// Which part of the host's desktop to share.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MonitorSel {
    Primary,
    /// Zero-based, primary first, then left to right.
    Index(usize),
    /// The whole virtual desktop.
    All,
}
