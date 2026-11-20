//! X11 screen capture and cursor-shape tracking.
//!
//! Frames come from MIT-SHM (`ShmGetImage` into a shared segment) when the server is local,
//! otherwise from `GetImage` over the socket. The cursor shape is followed through XFIXES
//! cursor-change events and the names cursor themes give their cursors.

use super::mem::LockedBuf;
use super::x11::{Conn, Ext, ShmSegment, Target};
use crate::log;
use crate::proto::Cursor;
pub use crate::screen::{Area, MonitorSel};
use crate::util::Result;
use std::sync::Mutex;

/// Connection for monitor queries from `monitors()` / `resolve()` (re-opened after errors).
static QUERY: Mutex<Option<Conn>> = Mutex::new(None);

fn with_query<T>(f: impl Fn(&mut Conn) -> Result<T>) -> Result<T> {
    static LAST_ERROR: Mutex<String> = Mutex::new(String::new());
    let mut conn = QUERY.lock().unwrap_or_else(|e| e.into_inner());
    let mut attempt = || -> Result<T> {
        if conn.is_none() {
            *conn = Some(Conn::connect(&Target::from_env()?)?);
        }
        let r = f(conn.as_mut().unwrap());
        if r.is_err() {
            *conn = None;
        }
        r
    };
    let r = attempt().or_else(|_| attempt());
    if let Err(e) = &r {
        let mut last = LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner());
        if *last != e.to_string() {
            log!("X display unavailable: {e}");
            *last = e.to_string();
        }
    }
    r
}

fn root_area(c: &mut Conn) -> Result<Area> {
    let root = c.root();
    let g = c.get_geometry(root)?;
    Ok(Area { left: 0, top: 0, width: g.width as i32, height: g.height as i32 })
}

/// Monitors on `c`, primary first, then left-to-right; the whole root window if the server
/// knows no monitors.
pub fn monitors_on(c: &mut Conn) -> Result<Vec<Area>> {
    let mut list = c.monitors()?;
    list.retain(|m| m.width > 0 && m.height > 0);
    list.sort_by_key(|m| (!m.primary, m.x, m.y));
    if list.is_empty() {
        return Ok(vec![root_area(c)?]);
    }
    Ok(list.iter().map(|m| Area { left: m.x as i32, top: m.y as i32, width: m.width as i32, height: m.height as i32 }).collect())
}

/// The area `sel` covers on `c`, clipped to the root window.
pub fn resolve_on(c: &mut Conn, sel: MonitorSel) -> Result<Option<Area>> {
    let root = root_area(c)?;
    let a = match sel {
        MonitorSel::All => root,
        MonitorSel::Primary => match monitors_on(c)?.first() {
            Some(&a) => a,
            None => return Ok(None),
        },
        MonitorSel::Index(i) => match monitors_on(c)?.get(i) {
            Some(&a) => a,
            None => return Ok(None),
        },
    };
    Ok(clip(a, root))
}

/// `a` clipped to `root`, if anything usable (and within the wire's 16-bit sizes) remains.
fn clip(a: Area, root: Area) -> Option<Area> {
    let (l, t) = (a.left.max(0), a.top.max(0));
    let r = (a.left + a.width).min(root.width);
    let b = (a.top + a.height).min(root.height);
    let c = Area { left: l, top: t, width: r - l, height: b - t };
    (c.width > 0 && c.height > 0 && c.width <= 0xffff && c.height <= 0xffff && l <= i16::MAX as i32 && t <= i16::MAX as i32).then_some(c)
}

/// Monitors with the primary first, then left-to-right.
pub fn monitors() -> Vec<Area> {
    with_query(monitors_on).unwrap_or_default()
}

pub fn resolve(sel: MonitorSel) -> Option<Area> {
    with_query(|c| resolve_on(c, sel)).ok().flatten()
}

/// Screen source for one area of the root window.
pub struct Capturer {
    conn: Conn,
    area: Area,
    shm: Option<(Ext, ShmSegment)>,
    /// Server-format image, when it must be converted and does not come through SHM.
    raw: LockedBuf,
    /// BGRA output; empty when the SHM segment already holds BGRX pixels.
    out: LockedBuf,
}

impl Capturer {
    /// Opens a source for `area` (already resolved from `sel`) on this process's display.
    pub fn open(_sel: MonitorSel, area: Area) -> Result<Capturer> {
        Capturer::open_on(&Target::from_env()?, area)
    }

    pub fn open_on(target: &Target, area: Area) -> Result<Capturer> {
        if area.width <= 0 || area.height <= 0 || area.width > 0xffff || area.height > 0xffff {
            crate::bail!("invalid capture area {}x{}", area.width, area.height);
        }
        let mut conn = Conn::connect(target)?;
        let fmt = conn.setup.format;
        let (w, h) = (area.width as usize, area.height as usize);
        let image_len = fmt.row_bytes(w) * h;
        let shm = match conn.shm() {
            Ok(Some(ext)) => match ShmSegment::new(&mut conn, ext, image_len) {
                Ok(seg) => Some((ext, seg)),
                Err(e) => {
                    log!("MIT-SHM unavailable ({e}); capturing over the X socket");
                    None
                }
            },
            _ => None,
        };
        let mut c = Capturer { conn, area, shm, raw: LockedBuf::new(0), out: LockedBuf::new(0) };
        c.allocate();
        if let Err(e) = c.grab() {
            if c.shm.is_none() {
                return Err(e);
            }
            log!("MIT-SHM capture failed ({e}); capturing over the X socket");
            c.drop_shm();
            c.grab()?;
        }
        Ok(c)
    }

    fn allocate(&mut self) {
        let fmt = self.conn.setup.format;
        let (w, h) = (self.area.width as usize, self.area.height as usize);
        let direct_shm = self.shm.is_some() && fmt.is_bgrx();
        self.out = LockedBuf::new(if direct_shm { 0 } else { w * h * 4 });
        self.raw = LockedBuf::new(if self.shm.is_none() && !fmt.is_bgrx() { fmt.row_bytes(w) * h } else { 0 });
    }

    fn drop_shm(&mut self) {
        if let Some((ext, seg)) = self.shm.take() {
            seg.detach(&mut self.conn, ext);
        }
        self.allocate();
    }

    fn grab(&mut self) -> Result<()> {
        let a = self.area;
        let (x, y, w, h) = (a.left as i16, a.top as i16, a.width as u16, a.height as u16);
        let root = self.conn.root();
        let fmt = self.conn.setup.format;
        match &mut self.shm {
            Some((ext, seg)) => {
                self.conn.shm_get_image(*ext, root, x, y, w, h, seg.seg)?;
                if !fmt.is_bgrx() {
                    fmt.to_bgra(seg.as_slice(), w as usize, h as usize, self.out.as_mut_slice());
                }
            }
            None if fmt.is_bgrx() => self.conn.get_image(root, x, y, w, h, self.out.as_mut_slice())?,
            None => {
                self.conn.get_image(root, x, y, w, h, self.raw.as_mut_slice())?;
                fmt.to_bgra(self.raw.as_slice(), w as usize, h as usize, self.out.as_mut_slice());
            }
        }
        Ok(())
    }

    /// X11 has nothing better to switch to.
    pub fn try_upgrade(&mut self, _sel: MonitorSel) -> bool {
        false
    }

    pub fn backend(&self) -> &'static str {
        if self.shm.is_some() { "X11-SHM" } else { "X11" }
    }

    pub fn area(&self) -> Area {
        self.area
    }

    /// X11 capture is polled.
    pub fn waits_for_changes(&self) -> bool {
        false
    }

    /// Grabs the screen into `pixels()`; always reports a (possibly unchanged) frame.
    pub fn next_frame(&mut self, _timeout_ms: u32) -> Result<bool> {
        self.grab()?;
        Ok(true)
    }

    /// The most recent image: BGRA, top-down, `width*height*4` bytes.
    pub fn pixels(&self) -> &[u8] {
        match &self.shm {
            Some((_, seg)) if self.out.len() == 0 => {
                &seg.as_slice()[..self.area.width as usize * self.area.height as usize * 4]
            }
            _ => self.out.as_slice(),
        }
    }
}

impl Drop for Capturer {
    fn drop(&mut self) {
        if let Some((ext, seg)) = &self.shm {
            seg.detach(&mut self.conn, *ext);
        }
    }
}

/// Maps a cursor theme name (legacy X cursor-font names and CSS names) to a standard shape.
pub fn cursor_from_name(name: &str) -> Cursor {
    match name {
        "xterm" | "text" | "ibeam" | "vertical-text" => Cursor::IBeam,
        "watch" | "wait" | "clock" => Cursor::Wait,
        "left_ptr_watch" | "progress" | "half-busy" => Cursor::AppStarting,
        "crosshair" | "cross" | "tcross" | "cross_reverse" | "diamond_cross" | "cell" | "plus" => Cursor::Cross,
        "center_ptr" | "sb_up_arrow" | "up-arrow" | "up_arrow" => Cursor::UpArrow,
        "bottom_right_corner" | "top_left_corner" | "nwse-resize" | "nw-resize" | "se-resize" | "size_fdiag" => Cursor::SizeNwse,
        "bottom_left_corner" | "top_right_corner" | "nesw-resize" | "ne-resize" | "sw-resize" | "size_bdiag" => Cursor::SizeNesw,
        "sb_h_double_arrow" | "h_double_arrow" | "ew-resize" | "col-resize" | "left_side" | "right_side" | "e-resize" | "w-resize"
        | "size_hor" | "split_h" => Cursor::SizeWe,
        "sb_v_double_arrow" | "v_double_arrow" | "ns-resize" | "row-resize" | "top_side" | "bottom_side" | "n-resize" | "s-resize"
        | "size_ver" | "split_v" => Cursor::SizeNs,
        "fleur" | "move" | "all-scroll" | "size_all" | "grabbing" | "dnd-move" => Cursor::SizeAll,
        "not-allowed" | "crossed_circle" | "no-drop" | "forbidden" | "circle" | "dnd-none" => Cursor::No,
        "hand1" | "hand2" | "hand" | "pointer" | "pointing_hand" | "grab" | "openhand" => Cursor::Hand,
        "question_arrow" | "help" | "whats_this" | "left_ptr_help" | "dnd-ask" => Cursor::Help,
        _ => Cursor::Arrow,
    }
}

struct CursorState {
    conn: Conn,
    xfixes: Ext,
    current: Cursor,
    names: Vec<(u32, Cursor)>,
}

impl CursorState {
    fn open(target: &Target) -> Result<CursorState> {
        let mut conn = Conn::connect(target)?;
        let xfixes = conn.xfixes()?.ok_or("the X server lacks XFIXES")?;
        conn.select_cursor_input(xfixes)?;
        let name = conn.cursor_name(xfixes)?;
        let mut s = CursorState { conn, xfixes, current: Cursor::Arrow, names: Vec::new() };
        s.current = s.shape(name)?;
        Ok(s)
    }

    fn shape(&mut self, atom: u32) -> Result<Cursor> {
        if atom == 0 {
            return Ok(Cursor::Arrow);
        }
        if let Some(&(_, c)) = self.names.iter().find(|(a, _)| *a == atom) {
            return Ok(c);
        }
        let c = cursor_from_name(&self.conn.atom_name(atom)?);
        if self.names.len() < 256 {
            self.names.push((atom, c));
        }
        Ok(c)
    }

    /// Applies cursor-change events received so far.
    fn update(&mut self) -> Result<Cursor> {
        self.conn.read_pending()?;
        let notify = self.xfixes.first_event + 1; // XFixesCursorNotify
        while let Some(ev) = self.conn.poll_event()? {
            if let super::x11::Event::Other(raw) = ev {
                if raw[0] & 0x7f == notify {
                    let name = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
                    self.current = self.shape(name)?;
                }
            }
        }
        Ok(self.current)
    }
}

/// Follows the shape of the X cursor (falls back to the arrow without XFIXES).
pub struct CursorTracker {
    state: Mutex<Option<CursorState>>,
}

impl CursorTracker {
    pub fn new() -> CursorTracker {
        CursorTracker::open(Target::from_env().ok())
    }

    #[cfg(test)]
    pub fn new_on(target: &Target) -> CursorTracker {
        CursorTracker::open(Some(target.clone()))
    }

    fn open(target: Option<Target>) -> CursorTracker {
        let state = target.and_then(|t| match CursorState::open(&t) {
            Ok(s) => Some(s),
            Err(e) => {
                log!("cursor shape tracking unavailable: {e}");
                None
            }
        });
        CursorTracker { state: Mutex::new(state) }
    }

    pub fn current(&self) -> Cursor {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match state.as_mut().map(CursorState::update) {
            Some(Ok(c)) => c,
            Some(Err(_)) => {
                *state = None;
                Cursor::Arrow
            }
            None => Cursor::Arrow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::input::Injector;
    use crate::platform::linux::x11::{self, Req};
    use crate::platform::linux::xvfb::VirtualDisplay;
    use std::time::{Duration, Instant};

    fn xsetroot(vd: &VirtualDisplay, color: &str) {
        let st = std::process::Command::new("xsetroot")
            .args(["-solid", color])
            .env("DISPLAY", vd.display_name())
            .env("XAUTHORITY", vd.xauthority())
            .status()
            .unwrap();
        assert!(st.success());
    }

    fn assert_solid(c: &Capturer, bgr: [u8; 3]) {
        let px = c.pixels();
        assert_eq!(px.len(), c.area().width as usize * c.area().height as usize * 4);
        assert!(px.chunks_exact(4).all(|p| p[..3] == bgr), "first pixel {:?}", &px[..4]);
    }

    #[test]
    #[ignore = "needs Xvfb and xsetroot; run on the Linux test host with --ignored"]
    fn captures_root_window() {
        let vd = VirtualDisplay::spawn(Some(73), 320, 200, None).unwrap();
        let t = vd.target();
        let mut q = Conn::connect(&t).unwrap();
        assert_eq!(monitors_on(&mut q).unwrap(), vec![Area { left: 0, top: 0, width: 320, height: 200 }]);
        assert_eq!(resolve_on(&mut q, MonitorSel::All).unwrap(), Some(Area { left: 0, top: 0, width: 320, height: 200 }));
        assert_eq!(resolve_on(&mut q, MonitorSel::Index(1)).unwrap(), None);

        xsetroot(&vd, "#3366cc");
        let area = Area { left: 10, top: 20, width: 100, height: 50 };
        let mut c = Capturer::open_on(&t, area).unwrap();
        assert_eq!(c.backend(), "X11-SHM");
        assert_solid(&c, [0xcc, 0x66, 0x33]);

        xsetroot(&vd, "#10ff20");
        assert!(c.next_frame(0).unwrap());
        assert_solid(&c, [0x20, 0xff, 0x10]);

        // The same through GetImage over the socket.
        c.drop_shm();
        assert_eq!(c.backend(), "X11");
        xsetroot(&vd, "#806040");
        c.next_frame(0).unwrap();
        assert_solid(&c, [0x40, 0x60, 0x80]);

        // An area off the screen fails cleanly.
        assert!(Capturer::open_on(&t, Area { left: 300, top: 0, width: 100, height: 10 }).is_err());
    }

    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn tracks_named_cursors() {
        let vd = VirtualDisplay::spawn(Some(74), 200, 200, None).unwrap();
        let t = vd.target();
        let tracker = CursorTracker::new_on(&t);
        assert_eq!(tracker.current(), Cursor::Arrow);

        // A window whose cursor is the cursor-font I-beam, named the way Xcursor names it.
        let mut c = Conn::connect(&t).unwrap();
        let xfixes = c.xfixes().unwrap().unwrap();
        let font = c.open_font("cursor").unwrap();
        let cursor = c.create_glyph_cursor(font, 152).unwrap();
        c.send(Req::new(xfixes.opcode, 23).u32(cursor).u16(5).pad(2).bytes(b"xterm")).unwrap();
        let root = c.root();
        let win = c.create_window(root, 100, 0, 100, 200, 1, x11::CW_CURSOR, &[cursor]).unwrap();
        c.map_window(win).unwrap();
        c.sync().unwrap();

        let mut inj = Injector::on(t.clone());
        inj.set_area(Area { left: 0, top: 0, width: 200, height: 200 });
        let wait_for = |want: Cursor| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while tracker.current() != want {
                assert!(Instant::now() < deadline, "cursor never became {want:?}");
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        inj.handle(&crate::proto::ClientMsg::MouseMove { x: 150, y: 100 });
        wait_for(Cursor::IBeam);
        inj.handle(&crate::proto::ClientMsg::MouseMove { x: 20, y: 100 });
        wait_for(Cursor::Arrow);
    }

    #[test]
    #[ignore = "needs Xvfb; prints capture timings"]
    fn capture_speed_full_hd() {
        let vd = VirtualDisplay::spawn(Some(75), 1920, 1080, None).unwrap();
        let area = Area { left: 0, top: 0, width: 1920, height: 1080 };
        let mut c = Capturer::open_on(&vd.target(), area).unwrap();
        for shm in [true, false] {
            if !shm {
                c.drop_shm();
            }
            let t0 = Instant::now();
            for _ in 0..20 {
                c.next_frame(0).unwrap();
            }
            eprintln!("{}: {:.1} ms per 1920x1080 frame", c.backend(), t0.elapsed().as_secs_f64() * 1000.0 / 20.0);
        }
    }

    #[test]
    fn clips_to_root() {
        let root = Area { left: 0, top: 0, width: 1920, height: 1080 };
        assert_eq!(clip(root, root), Some(root));
        let half = Area { left: 960, top: -10, width: 1920, height: 1080 };
        assert_eq!(clip(half, root), Some(Area { left: 960, top: 0, width: 960, height: 1070 }));
        assert_eq!(clip(Area { left: 1920, top: 0, width: 10, height: 10 }, root), None);
        let huge = Area { left: 0, top: 0, width: 70000, height: 10 };
        assert_eq!(clip(huge, Area { left: 0, top: 0, width: 70000, height: 10 }), None);
    }

    #[test]
    fn cursor_names() {
        assert_eq!(cursor_from_name("xterm"), Cursor::IBeam);
        assert_eq!(cursor_from_name("text"), Cursor::IBeam);
        assert_eq!(cursor_from_name("left_ptr"), Cursor::Arrow);
        assert_eq!(cursor_from_name("default"), Cursor::Arrow);
        assert_eq!(cursor_from_name("hand2"), Cursor::Hand);
        assert_eq!(cursor_from_name("pointer"), Cursor::Hand);
        assert_eq!(cursor_from_name("progress"), Cursor::AppStarting);
        assert_eq!(cursor_from_name("watch"), Cursor::Wait);
        assert_eq!(cursor_from_name("sb_h_double_arrow"), Cursor::SizeWe);
        assert_eq!(cursor_from_name("ns-resize"), Cursor::SizeNs);
        assert_eq!(cursor_from_name("nwse-resize"), Cursor::SizeNwse);
        assert_eq!(cursor_from_name("top_right_corner"), Cursor::SizeNesw);
        assert_eq!(cursor_from_name("not-allowed"), Cursor::No);
        assert_eq!(cursor_from_name("fleur"), Cursor::SizeAll);
        assert_eq!(cursor_from_name("question_arrow"), Cursor::Help);
        assert_eq!(cursor_from_name("crosshair"), Cursor::Cross);
        assert_eq!(cursor_from_name("something-odd"), Cursor::Arrow);
    }
}
