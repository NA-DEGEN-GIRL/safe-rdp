//! There is no secure-desktop switching on X11; this exists to keep the host loop portable.

pub struct DesktopFollower;

impl DesktopFollower {
    pub fn new() -> DesktopFollower {
        DesktopFollower
    }

    pub fn sync(&mut self) -> bool {
        false
    }
}
