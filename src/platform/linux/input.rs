//! X11 input injection (placeholder until the XTEST backend lands).

use crate::proto::ClientMsg;
use crate::screen::Area;

#[derive(Default)]
pub struct Injector;

impl Injector {
    pub fn set_area(&mut self, _a: Area) {}

    pub fn handle(&mut self, _m: &ClientMsg) {}

    pub fn release_all(&mut self) {}
}
