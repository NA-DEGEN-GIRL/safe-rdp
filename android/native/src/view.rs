//! Where the remote screen is drawn on the phone's: fitted to the surface, then zoomed in around
//! a point and moved about. Coordinates are surface pixels and remote pixels; the remote screen
//! is drawn at `scale()` surface pixels per remote pixel.

/// How far in one can zoom: this many surface pixels per remote pixel at most (but always at
/// least twice the fitted size).
const MAX_PIXEL_SCALE: f32 = 4.0;

#[derive(Clone, Debug, PartialEq)]
pub struct View {
    /// Surface size.
    pub sw: f32,
    pub sh: f32,
    /// Remote screen size.
    pub rw: f32,
    pub rh: f32,
    /// 1 = the whole remote screen fits.
    zoom: f32,
    /// The remote point shown at the centre of the surface.
    cx: f32,
    cy: f32,
}

impl View {
    pub fn new(sw: f32, sh: f32, rw: f32, rh: f32) -> View {
        let mut v = View { sw: sw.max(1.0), sh: sh.max(1.0), rw: rw.max(1.0), rh: rh.max(1.0), zoom: 1.0, cx: 0.0, cy: 0.0 };
        v.reset();
        v
    }

    /// Back to the whole screen, fitted.
    pub fn reset(&mut self) {
        self.zoom = 1.0;
        (self.cx, self.cy) = (self.rw / 2.0, self.rh / 2.0);
    }

    #[cfg(test)]
    pub fn zoom(&self) -> f32 {
        self.zoom
    }

    fn fit(&self) -> f32 {
        (self.sw / self.rw).min(self.sh / self.rh)
    }

    fn max_zoom(&self) -> f32 {
        (MAX_PIXEL_SCALE / self.fit()).max(2.0)
    }

    /// Surface pixels per remote pixel.
    pub fn scale(&self) -> f32 {
        self.fit() * self.zoom
    }

    /// A new surface size; the same remote point stays in the middle.
    pub fn set_surface(&mut self, sw: f32, sh: f32) {
        (self.sw, self.sh) = (sw.max(1.0), sh.max(1.0));
        self.clamp();
    }

    /// A new remote size (another monitor, another scale): shows all of it again.
    pub fn set_remote(&mut self, rw: f32, rh: f32) {
        if (rw, rh) != (self.rw, self.rh) {
            (self.rw, self.rh) = (rw.max(1.0), rh.max(1.0));
            self.reset();
        }
    }

    /// The remote screen's rectangle on the surface: left, top, width, height.
    pub fn rect(&self) -> (f32, f32, f32, f32) {
        let s = self.scale();
        (self.sw / 2.0 - self.cx * s, self.sh / 2.0 - self.cy * s, self.rw * s, self.rh * s)
    }

    /// The remote point under surface point (`x`, `y`), not limited to the screen.
    fn remote_unclamped(&self, x: f32, y: f32) -> (f32, f32) {
        let (l, t, _, _) = self.rect();
        let s = self.scale();
        ((x - l) / s, (y - t) / s)
    }

    /// The remote pixel under surface point (`x`, `y`), the nearest one if outside the screen.
    pub fn to_remote(&self, x: f32, y: f32) -> (f32, f32) {
        let (rx, ry) = self.remote_unclamped(x, y);
        (rx.clamp(0.0, self.rw - 1.0), ry.clamp(0.0, self.rh - 1.0))
    }

    pub fn to_surface(&self, rx: f32, ry: f32) -> (f32, f32) {
        let (l, t, _, _) = self.rect();
        let s = self.scale();
        (l + rx * s, t + ry * s)
    }

    /// Keeps the screen on the surface: centred along an axis where it fits, else edge to edge.
    fn clamp(&mut self) {
        self.zoom = self.zoom.clamp(1.0, self.max_zoom());
        let s = self.scale();
        let axis = |c: f32, half_visible: f32, len: f32| {
            if len <= 2.0 * half_visible { len / 2.0 } else { c.clamp(half_visible, len - half_visible) }
        };
        self.cx = axis(self.cx, self.sw / 2.0 / s, self.rw);
        self.cy = axis(self.cy, self.sh / 2.0 / s, self.rh);
    }

    /// Zooms by `factor` around surface point (`fx`, `fy`), which keeps showing the same remote point.
    pub fn zoom_at(&mut self, fx: f32, fy: f32, factor: f32) {
        if !factor.is_finite() || factor <= 0.0 {
            return;
        }
        let (rx, ry) = self.remote_unclamped(fx, fy);
        self.zoom = (self.zoom * factor).clamp(1.0, self.max_zoom());
        let s = self.scale();
        self.cx = rx - (fx - self.sw / 2.0) / s;
        self.cy = ry - (fy - self.sh / 2.0) / s;
        self.clamp();
    }

    /// Moves the picture by (`dx`, `dy`) surface pixels, as a finger drags it.
    pub fn pan(&mut self, dx: f32, dy: f32) {
        let s = self.scale();
        self.cx -= dx / s;
        self.cy -= dy / s;
        self.clamp();
    }

    /// Scrolls the picture as little as needed to show remote point (`rx`, `ry`) at least
    /// `margin` surface pixels inside the surface's edges.
    pub fn follow(&mut self, rx: f32, ry: f32, margin: f32) {
        let (x, y) = self.to_surface(rx, ry);
        let m = margin.min(self.sw / 2.0).min(self.sh / 2.0);
        let dx = if x < m { m - x } else if x > self.sw - m { self.sw - m - x } else { 0.0 };
        let dy = if y < m { m - y } else if y > self.sh - m { self.sh - m - y } else { 0.0 };
        if dx != 0.0 || dy != 0.0 {
            self.pan(dx, dy);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: (f32, f32), b: (f32, f32)) -> bool {
        (a.0 - b.0).abs() < 0.01 && (a.1 - b.1).abs() < 0.01
    }

    #[test]
    fn fits_and_letterboxes() {
        // A 16:9 screen on a 2400x1080 landscape phone: full height, bars left and right.
        let v = View::new(2400.0, 1080.0, 1920.0, 1080.0);
        assert_eq!(v.scale(), 1.0);
        assert_eq!(v.rect(), (240.0, 0.0, 1920.0, 1080.0));
        assert!(close(v.to_remote(240.0, 0.0), (0.0, 0.0)));
        assert!(close(v.to_remote(0.0, 2000.0), (0.0, 1079.0)), "outside points clamp to the screen");
        assert!(close(v.to_surface(960.0, 540.0), (1200.0, 540.0)));
    }

    #[test]
    fn zoom_keeps_the_focus_still_and_stays_in_bounds() {
        let mut v = View::new(1000.0, 1000.0, 1000.0, 1000.0);
        let focus = (700.0, 600.0);
        let before = v.to_remote(focus.0, focus.1);
        v.zoom_at(focus.0, focus.1, 2.0);
        assert_eq!(v.zoom(), 2.0);
        assert!(close(v.to_remote(focus.0, focus.1), before));

        // Where the screen fits along an axis it stays centred there, focus or not.
        let mut v = View::new(1000.0, 1000.0, 2000.0, 1000.0);
        assert_eq!(v.scale(), 0.5);
        v.zoom_at(700.0, 600.0, 1.5);
        assert!(close(v.to_surface(1000.0, 500.0), (v.to_surface(1000.0, 500.0).0, 500.0)));
        // Zooming out past the fit snaps back to the whole screen, centred.
        v.zoom_at(10.0, 10.0, 0.1);
        assert_eq!(v.zoom(), 1.0);
        assert_eq!(v.rect(), (0.0, 250.0, 1000.0, 500.0));
        // Never beyond 4 surface pixels per remote pixel.
        v.zoom_at(500.0, 500.0, 1000.0);
        assert!((v.scale() - 4.0).abs() < 1e-4);
    }

    #[test]
    fn panning_stops_at_the_edges() {
        let mut v = View::new(1000.0, 500.0, 1000.0, 500.0);
        v.zoom_at(0.0, 0.0, 2.0);
        assert!(close(v.to_remote(0.0, 0.0), (0.0, 0.0)));
        v.pan(500.0, 500.0); // dragging right/down shows more of the left/top: none left
        assert!(close(v.to_remote(0.0, 0.0), (0.0, 0.0)));
        v.pan(-10_000.0, -10_000.0);
        assert!(close(v.to_remote(999.0, 499.0), (999.0, 499.0)));
        let (l, t, w, h) = v.rect();
        assert!((l + w - 1000.0).abs() < 0.01 && (t + h - 500.0).abs() < 0.01, "right and bottom edges meet the surface's");
    }

    #[test]
    fn follow_scrolls_just_enough() {
        let mut v = View::new(1000.0, 1000.0, 1000.0, 1000.0);
        v.zoom_at(500.0, 500.0, 4.0);
        let r = (900.0, 500.0);
        v.follow(r.0, r.1, 50.0);
        let (x, y) = v.to_surface(r.0, r.1);
        assert!((x - 950.0).abs() < 0.01 && (y - 500.0).abs() < 0.01, "({x}, {y})");
        // Already visible: nothing moves.
        let before = v.clone();
        v.follow(880.0, 480.0, 50.0);
        assert_eq!(v, before);
    }

    #[test]
    fn surface_and_remote_changes() {
        let mut v = View::new(1080.0, 2400.0, 1920.0, 1080.0);
        v.zoom_at(540.0, 1200.0, 3.0);
        v.set_surface(2400.0, 1080.0); // rotated
        let (l, t, w, h) = v.rect();
        assert!(l <= 0.0 && t <= 0.0 && l + w >= 2400.0 && t + h >= 1080.0, "still covers the surface where it can");
        v.set_remote(1280.0, 720.0);
        assert_eq!(v.zoom(), 1.0);
        assert!(close(v.to_surface(640.0, 360.0), (1200.0, 540.0)));
    }
}
