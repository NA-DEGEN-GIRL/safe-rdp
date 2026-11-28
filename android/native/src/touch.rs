//! Touch gestures to mouse input. Two ways to work the remote pointer:
//!
//! * Trackpad (default): the phone is a touchpad. One finger moves the pointer from where it is,
//!   a tap clicks, a long press holds the left button down until the finger lifts (to drag).
//!   The view scrolls along when the pointer nears an edge.
//! * Direct: the pointer goes where the finger touches. A tap clicks there, dragging drags with
//!   the left button, a long press right-clicks.
//!
//! In both, two fingers scroll (dragged) or zoom the view (pinched; moving them pans), a
//! two-finger tap right-clicks and a three-finger tap middle-clicks.
//!
//! Times are milliseconds, positions surface pixels; `View` maps them to the remote screen.

use crate::view::View;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode {
    Trackpad,
    Direct,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Action {
    /// Pointer to this remote pixel.
    Move(u16, u16),
    Button(u8, bool),
    Wheel { delta: i16, horizontal: bool },
    /// A long press took effect: the phone should buzz.
    Haptic,
}

pub const BTN_LEFT: u8 = 0;
pub const BTN_RIGHT: u8 = 1;
pub const BTN_MIDDLE: u8 = 2;

/// A press shorter than this, without moving, is a tap.
const TAP_MS: u64 = 300;
/// A press held this long without moving is a long press.
pub const LONG_MS: u64 = 500;
/// Movement (dp) a finger may make and still be tapping.
const SLOP_DP: f32 = 8.0;
/// A pinch is told from a two-finger drag by the distance between the fingers changing this much.
const PINCH_RATIO: f32 = 0.15;
/// Two fingers moving this far (dp) scroll by one wheel notch.
const DP_PER_NOTCH: f32 = 40.0;
const WHEEL_NOTCH: f32 = 120.0;
/// The view keeps the trackpad pointer this far (dp) inside its edges.
const FOLLOW_MARGIN_DP: f32 = 48.0;

#[derive(Clone, Copy, Debug)]
struct Finger {
    id: i32,
    x: f32,
    y: f32,
    start: (f32, f32),
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Two {
    Undecided,
    Scroll,
    Pinch,
}

#[derive(Clone, Copy, Debug)]
enum Gesture {
    None,
    One { start: u64, moved: bool, held: bool, long: bool },
    Multi { start: u64, kind: Two, moved: bool, most: usize, centre: (f32, f32), dist: f32 },
    /// Some fingers lifted from a multi-finger gesture: the rest do nothing until all are up.
    Spent,
}

pub struct Touch {
    pub mode: Mode,
    /// Surface pixels per dp.
    density: f32,
    fingers: Vec<Finger>,
    gesture: Gesture,
    /// The remote pointer, in remote pixels.
    pointer: (f32, f32),
    /// Wheel movement not sent yet (a fraction of a unit).
    wheel: (f32, f32),
    last_move: u64,
}

impl Touch {
    pub fn new(mode: Mode, density: f32) -> Touch {
        Touch { mode, density: density.max(0.5), fingers: Vec::new(), gesture: Gesture::None, pointer: (0.0, 0.0), wheel: (0.0, 0.0), last_move: 0 }
    }

    pub fn pointer(&self) -> (f32, f32) {
        self.pointer
    }

    /// Puts the pointer somewhere (a mouse moved it, or the screen changed).
    pub fn set_pointer(&mut self, view: &View, rx: f32, ry: f32) {
        self.pointer = (rx.clamp(0.0, view.rw - 1.0), ry.clamp(0.0, view.rh - 1.0));
    }

    fn slop(&self) -> f32 {
        SLOP_DP * self.density
    }

    fn move_action(&self) -> Action {
        Action::Move(self.pointer.0.round() as u16, self.pointer.1.round() as u16)
    }

    fn click(&self, out: &mut Vec<Action>, button: u8) {
        out.push(Action::Button(button, true));
        out.push(Action::Button(button, false));
    }

    /// Centre of the first two fingers and their distance.
    fn pair(&self) -> ((f32, f32), f32) {
        let (a, b) = (self.fingers[0], self.fingers[1]);
        (((a.x + b.x) / 2.0, (a.y + b.y) / 2.0), (a.x - b.x).hypot(a.y - b.y).max(1.0))
    }

    pub fn down(&mut self, view: &mut View, id: i32, x: f32, y: f32, t: u64) -> Vec<Action> {
        let mut out = Vec::new();
        self.fingers.retain(|f| f.id != id);
        self.fingers.push(Finger { id, x, y, start: (x, y) });
        match (self.fingers.len(), self.gesture) {
            (1, _) => {
                self.gesture = Gesture::One { start: t, moved: false, held: false, long: false };
                self.last_move = t;
                if self.mode == Mode::Direct {
                    let (rx, ry) = view.to_remote(x, y);
                    self.set_pointer(view, rx, ry);
                    out.push(self.move_action());
                }
            }
            (2, Gesture::One { held, start, .. }) => {
                if held {
                    out.push(Action::Button(BTN_LEFT, false));
                }
                for f in &mut self.fingers {
                    f.start = (f.x, f.y);
                }
                let (centre, dist) = self.pair();
                self.gesture = Gesture::Multi { start, kind: Two::Undecided, moved: false, most: 2, centre, dist };
                self.wheel = (0.0, 0.0);
            }
            (n, Gesture::Multi { start, kind, moved, most, .. }) => {
                // Measured afresh: the pair `pair` takes may now include the new finger.
                let (centre, dist) = self.pair();
                self.gesture = Gesture::Multi { start, kind, moved, most: most.max(n), centre, dist };
            }
            (2, Gesture::Spent) => {
                // A finger put back after a pinch or scroll: pinch (or scroll) again, no tap.
                for f in &mut self.fingers {
                    f.start = (f.x, f.y);
                }
                let (centre, dist) = self.pair();
                self.gesture = Gesture::Multi { start: t, kind: Two::Undecided, moved: true, most: 2, centre, dist };
            }
            _ => {}
        }
        out
    }

    pub fn moved(&mut self, view: &mut View, id: i32, x: f32, y: f32, t: u64) -> Vec<Action> {
        let mut out = Vec::new();
        let slop = self.slop();
        let Some(i) = self.fingers.iter().position(|f| f.id == id) else { return out };
        let f = self.fingers[i];
        let (dx, dy) = (x - f.x, y - f.y);
        self.fingers[i].x = x;
        self.fingers[i].y = y;
        let far = (x - f.start.0).hypot(y - f.start.1) > slop;
        match self.gesture {
            Gesture::One { start, moved, held, long } => {
                let moved = moved || far;
                self.gesture = Gesture::One { start, moved, held, long };
                if !moved {
                    return out;
                }
                match self.mode {
                    Mode::Trackpad => {
                        let s = view.scale();
                        // A little acceleration: quick flicks go further.
                        let dt = t.saturating_sub(self.last_move).max(1) as f32;
                        let speed = (dx.hypot(dy) / self.density) / dt; // dp per ms
                        let gain = 1.0 + (speed * 0.5).min(1.5);
                        self.set_pointer(view, self.pointer.0 + dx * gain / s, self.pointer.1 + dy * gain / s);
                        view.follow(self.pointer.0, self.pointer.1, FOLLOW_MARGIN_DP * self.density);
                        out.push(self.move_action());
                    }
                    Mode::Direct if long => {}
                    Mode::Direct => {
                        if !held {
                            out.push(Action::Button(BTN_LEFT, true));
                            self.gesture = Gesture::One { start, moved, held: true, long };
                        }
                        let (rx, ry) = view.to_remote(x, y);
                        self.set_pointer(view, rx, ry);
                        // Zoomed in, dragging to an edge scrolls the view on.
                        view.follow(rx, ry, FOLLOW_MARGIN_DP * self.density);
                        out.push(self.move_action());
                    }
                }
                self.last_move = t;
            }
            Gesture::Multi { start, mut kind, moved, most, centre, dist } => {
                let moved = moved || far;
                if self.fingers.len() < 2 {
                    return out;
                }
                let (c, d) = self.pair();
                if kind == Two::Undecided && most == 2 {
                    let first = (self.fingers[0], self.fingers[1]);
                    let start_dist = (first.0.start.0 - first.1.start.0).hypot(first.0.start.1 - first.1.start.1).max(1.0);
                    let start_centre = ((first.0.start.0 + first.1.start.0) / 2.0, (first.0.start.1 + first.1.start.1) / 2.0);
                    if (d / start_dist - 1.0).abs() > PINCH_RATIO {
                        kind = Two::Pinch;
                    } else if (c.0 - start_centre.0).hypot(c.1 - start_centre.1) > slop {
                        kind = Two::Scroll;
                    }
                }
                match kind {
                    Two::Pinch => {
                        view.zoom_at(c.0, c.1, d / dist);
                        view.pan(c.0 - centre.0, c.1 - centre.1);
                    }
                    Two::Scroll => {
                        let per_px = WHEEL_NOTCH / (DP_PER_NOTCH * self.density);
                        // Natural scrolling: the content follows the fingers.
                        self.wheel.0 -= (c.0 - centre.0) * per_px;
                        self.wheel.1 += (c.1 - centre.1) * per_px;
                        for (acc, horizontal) in [(&mut self.wheel.1, false), (&mut self.wheel.0, true)] {
                            let whole = acc.trunc();
                            if whole != 0.0 {
                                *acc -= whole;
                                out.push(Action::Wheel { delta: whole.clamp(-30_000.0, 30_000.0) as i16, horizontal });
                            }
                        }
                    }
                    Two::Undecided => {}
                }
                self.gesture = Gesture::Multi { start, kind, moved, most, centre: c, dist: d };
            }
            Gesture::None | Gesture::Spent => {}
        }
        out
    }

    pub fn up(&mut self, view: &mut View, id: i32, t: u64) -> Vec<Action> {
        let mut out = Vec::new();
        let Some(i) = self.fingers.iter().position(|f| f.id == id) else { return out };
        let f = self.fingers.remove(i);
        let left = self.fingers.len();
        match self.gesture {
            Gesture::One { start, moved, held, long } => {
                if held {
                    out.push(Action::Button(BTN_LEFT, false));
                } else if !moved && !long && t.saturating_sub(start) < TAP_MS {
                    self.click(&mut out, BTN_LEFT);
                }
                self.gesture = Gesture::None;
            }
            Gesture::Multi { start, kind, moved, most, .. } => {
                if left == 0 {
                    let tap = !moved && kind == Two::Undecided && t.saturating_sub(start) < TAP_MS + 100;
                    if tap {
                        if self.mode == Mode::Direct {
                            let (rx, ry) = view.to_remote(f.x, f.y);
                            self.set_pointer(view, rx, ry);
                            out.push(self.move_action());
                        }
                        self.click(&mut out, if most >= 3 { BTN_MIDDLE } else { BTN_RIGHT });
                    }
                    self.gesture = Gesture::None;
                } else if left == 1 {
                    // The last finger left down does nothing: lifting one of two after a pinch
                    // must not move the pointer.
                    self.gesture = if kind == Two::Undecided && !moved {
                        Gesture::Multi { start, kind, moved, most, centre: (0.0, 0.0), dist: 1.0 }
                    } else {
                        Gesture::Spent
                    };
                } else {
                    // Two or more left: measure the pair they now make, or the next move jumps.
                    let (centre, dist) = self.pair();
                    self.gesture = Gesture::Multi { start, kind, moved, most, centre, dist };
                }
            }
            Gesture::Spent if left == 0 => self.gesture = Gesture::None,
            _ => {}
        }
        out
    }

    /// Time passing with fingers down: a long press takes effect.
    pub fn tick(&mut self, t: u64) -> Vec<Action> {
        let mut out = Vec::new();
        if let Gesture::One { start, moved: false, held, long: false } = self.gesture
            && t.saturating_sub(start) >= LONG_MS
        {
            out.push(Action::Haptic);
            match self.mode {
                Mode::Trackpad => {
                    out.push(Action::Button(BTN_LEFT, true));
                    self.gesture = Gesture::One { start, moved: false, held: true, long: true };
                }
                Mode::Direct => {
                    self.click(&mut out, BTN_RIGHT);
                    self.gesture = Gesture::One { start, moved: false, held, long: true };
                }
            }
        }
        out
    }

    /// The system took the touch stream away: lets go of a held button.
    pub fn cancel(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        if let Gesture::One { held: true, .. } = self.gesture {
            out.push(Action::Button(BTN_LEFT, false));
        }
        self.fingers.clear();
        self.gesture = Gesture::None;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Action::*;

    fn setup(mode: Mode) -> (Touch, View) {
        // 1:1 scale, density 1 (slop 8 px).
        let v = View::new(1000.0, 500.0, 1000.0, 500.0);
        let mut t = Touch::new(mode, 1.0);
        t.set_pointer(&v, 100.0, 100.0);
        (t, v)
    }

    #[test]
    fn trackpad_tap_clicks_where_the_pointer_is() {
        let (mut t, mut v) = setup(Mode::Trackpad);
        assert_eq!(t.down(&mut v, 0, 500.0, 300.0, 0), []);
        assert_eq!(t.moved(&mut v, 0, 503.0, 302.0, 50), [], "jitter within the slop is not a move");
        assert_eq!(t.up(&mut v, 0, 100), [Button(BTN_LEFT, true), Button(BTN_LEFT, false)]);
        assert_eq!(t.pointer(), (100.0, 100.0));
        // Too long a press without a long press firing (no tick) is no tap either.
        t.down(&mut v, 1, 500.0, 300.0, 1000);
        assert_eq!(t.up(&mut v, 1, 1400), []);
    }

    #[test]
    fn trackpad_moves_relatively() {
        let (mut t, mut v) = setup(Mode::Trackpad);
        t.down(&mut v, 0, 500.0, 300.0, 0);
        let a = t.moved(&mut v, 0, 520.0, 300.0, 1000); // slow: no acceleration to speak of
        assert_eq!(a.len(), 1);
        let Move(x, y) = a[0] else { panic!("{a:?}") };
        assert!((120..=121).contains(&x) && y == 100, "{x},{y}");
        assert_eq!(t.up(&mut v, 0, 1100), [], "a move is not a tap");
    }

    #[test]
    fn trackpad_long_press_drags() {
        let (mut t, mut v) = setup(Mode::Trackpad);
        t.down(&mut v, 0, 500.0, 300.0, 0);
        assert_eq!(t.tick(200), []);
        assert_eq!(t.tick(LONG_MS), [Haptic, Button(BTN_LEFT, true)]);
        assert_eq!(t.tick(LONG_MS + 100), [], "once");
        let a = t.moved(&mut v, 0, 540.0, 300.0, 2000);
        assert!(matches!(a[..], [Move(..)]));
        assert_eq!(t.up(&mut v, 0, 2100), [Button(BTN_LEFT, false)]);
    }

    #[test]
    fn direct_taps_and_drags_where_the_finger_is() {
        let (mut t, mut v) = setup(Mode::Direct);
        assert_eq!(t.down(&mut v, 0, 300.0, 200.0, 0), [Move(300, 200)]);
        assert_eq!(t.up(&mut v, 0, 80), [Button(BTN_LEFT, true), Button(BTN_LEFT, false)]);
        t.down(&mut v, 0, 300.0, 200.0, 1000);
        assert_eq!(t.moved(&mut v, 0, 330.0, 200.0, 1050), [Button(BTN_LEFT, true), Move(330, 200)]);
        assert_eq!(t.moved(&mut v, 0, 340.0, 210.0, 1060), [Move(340, 210)]);
        assert_eq!(t.up(&mut v, 0, 1100), [Button(BTN_LEFT, false)]);
    }

    #[test]
    fn direct_long_press_right_clicks() {
        let (mut t, mut v) = setup(Mode::Direct);
        t.down(&mut v, 0, 300.0, 200.0, 0);
        assert_eq!(t.tick(LONG_MS), [Haptic, Button(BTN_RIGHT, true), Button(BTN_RIGHT, false)]);
        assert_eq!(t.moved(&mut v, 0, 360.0, 200.0, 700), [], "no drag after the right click");
        assert_eq!(t.up(&mut v, 0, 800), []);
    }

    #[test]
    fn two_fingers_tap_scroll_and_pinch() {
        let (mut t, mut v) = setup(Mode::Trackpad);
        t.down(&mut v, 0, 400.0, 200.0, 0);
        t.down(&mut v, 1, 500.0, 200.0, 20);
        t.up(&mut v, 0, 120);
        assert_eq!(t.up(&mut v, 1, 140), [Button(BTN_RIGHT, true), Button(BTN_RIGHT, false)]);

        // Both fingers up by 80 px: natural scrolling, content up = wheel down (negative).
        t.down(&mut v, 0, 400.0, 300.0, 1000);
        t.down(&mut v, 1, 500.0, 300.0, 1000);
        let mut wheel = 0i32;
        for step in 1..=8 {
            let y = 300.0 - 10.0 * step as f32;
            for a in t.moved(&mut v, 0, 400.0, y, 1000 + step).into_iter().chain(t.moved(&mut v, 1, 500.0, y, 1000 + step)) {
                if let Wheel { delta, horizontal: false } = a {
                    wheel += delta as i32;
                }
            }
        }
        // 80 px at 120 units per 40 px, less what was within the slop before scrolling began.
        assert!((-240..=-200).contains(&wheel), "{wheel}");
        assert_eq!(t.up(&mut v, 0, 1100), []);
        assert_eq!(t.up(&mut v, 1, 1100), [], "a scroll is not a tap");

        // Spreading the fingers zooms the view, and moves nothing on the remote side.
        let zoom = v.zoom();
        t.down(&mut v, 0, 400.0, 250.0, 2000);
        t.down(&mut v, 1, 500.0, 250.0, 2000);
        let mut acts = t.moved(&mut v, 0, 350.0, 250.0, 2010);
        acts.extend(t.moved(&mut v, 1, 550.0, 250.0, 2010));
        assert!(acts.is_empty(), "{acts:?}");
        assert!(v.zoom() > zoom * 1.5, "{}", v.zoom());
        assert_eq!(t.up(&mut v, 0, 2100), []);
        assert_eq!(t.moved(&mut v, 1, 600.0, 300.0, 2110), [], "the finger left after a pinch does nothing");
        assert_eq!(t.up(&mut v, 1, 2120), []);
    }

    #[test]
    fn three_finger_tap_middle_clicks_and_cancel_releases() {
        let (mut t, mut v) = setup(Mode::Trackpad);
        for i in 0..3 {
            t.down(&mut v, i, 300.0 + 50.0 * i as f32, 200.0, 0);
        }
        t.up(&mut v, 0, 100);
        t.up(&mut v, 1, 100);
        assert_eq!(t.up(&mut v, 2, 110), [Button(BTN_MIDDLE, true), Button(BTN_MIDDLE, false)]);

        t.down(&mut v, 0, 300.0, 200.0, 1000);
        t.tick(1000 + LONG_MS);
        assert_eq!(t.cancel(), [Button(BTN_LEFT, false)]);
        assert_eq!(t.up(&mut v, 0, 2000), []);
    }

    #[test]
    fn lifting_one_of_three_fingers_does_not_jump() {
        let (mut t, mut v) = setup(Mode::Trackpad);
        t.down(&mut v, 0, 100.0, 250.0, 0);
        t.down(&mut v, 1, 900.0, 250.0, 0);
        t.moved(&mut v, 1, 1100.0, 250.0, 10); // a pinch
        t.down(&mut v, 2, 500.0, 250.0, 20);
        // The first finger goes: the pair is now fingers 1 and 2, 600 px apart instead of 1000.
        t.up(&mut v, 0, 50);
        let zoom = v.zoom();
        let a = t.moved(&mut v, 1, 1102.0, 250.0, 60);
        assert!(a.is_empty(), "{a:?}");
        assert!((v.zoom() - zoom).abs() < 0.05, "zoom jumped from {zoom} to {}", v.zoom());
    }

    #[test]
    fn pinching_again_after_lifting_a_finger() {
        let (mut t, mut v) = setup(Mode::Trackpad);
        t.down(&mut v, 0, 400.0, 250.0, 0);
        t.down(&mut v, 1, 500.0, 250.0, 0);
        t.moved(&mut v, 0, 350.0, 250.0, 10);
        t.moved(&mut v, 1, 550.0, 250.0, 10);
        t.up(&mut v, 1, 100);
        let zoom = v.zoom();
        assert_eq!(t.down(&mut v, 1, 650.0, 250.0, 200), []);
        t.moved(&mut v, 1, 800.0, 250.0, 210);
        assert!(v.zoom() > zoom, "the second pinch zoomed: {} -> {}", zoom, v.zoom());
        t.up(&mut v, 0, 300);
        assert_eq!(t.up(&mut v, 1, 300), [], "no right click after a pinch");
    }

    #[test]
    fn second_finger_ends_a_drag() {
        let (mut t, mut v) = setup(Mode::Direct);
        t.down(&mut v, 0, 300.0, 200.0, 0);
        t.moved(&mut v, 0, 340.0, 200.0, 50);
        assert_eq!(t.down(&mut v, 1, 500.0, 200.0, 60), [Button(BTN_LEFT, false)]);
    }
}
