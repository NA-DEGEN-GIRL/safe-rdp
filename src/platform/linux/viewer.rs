//! Viewer: an X11 window that shows the remote screen, scaled to fit and letterboxed, and
//! forwards keyboard and mouse.
//!
//! Hotkeys (handled locally, never forwarded):
//!   Ctrl+Alt+Enter  toggle full screen (the keyboard is grabbed while full screen and focused)
//!   Ctrl+Alt+End    send Ctrl+Alt+Del to the host (service mode only)

use super::clipboard::Clipboard;
use super::keymap::{
    self, KEY_END, KEY_ENTER, KEY_KPENTER, KEY_LEFTALT, KEY_LEFTCTRL, KEY_LEFTMETA, KEY_RIGHTALT, KEY_RIGHTCTRL, KEY_RIGHTMETA, X_KEYCODE_OFFSET,
};
use super::mem::LockedBuf;
use super::x11::{self, Conn, Event, Ext, ShmSegment, Target, Wake, Waker};
use crate::audio::AudioReceiver;
use crate::channel::{self, RecordReader};
use crate::codec::{self, Rect};
use crate::log;
use crate::proto::*;
use crate::util::{Result, Secret};
use crate::viewer::{FrameLock, Next, OutQueue, ResizePacer, TileDecoder, ViewerOptions};
use std::collections::HashSet;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const XK_HANGUL: u32 = 0xff31;
const XK_HANGUL_HANJA: u32 = 0xff34;
/// FocusIn/FocusOut modes: a focus change made while the keyboard was free, or while it was
/// grabbed (the other two modes are a grab or ungrab itself).
const NOTIFY_NORMAL: u8 = 0;
const NOTIFY_WHILE_GRABBED: u8 = 3;
/// Largest remote screen accepted (two 8K screens side by side), bounding what a host can make
/// the viewer allocate.
const MAX_PIXELS: usize = 2 * 7680 * 4320;

fn check_size(w: usize, h: usize) -> Result<()> {
    if w * h > MAX_PIXELS {
        crate::bail!("remote screen {w}x{h} is too large");
    }
    Ok(())
}

/// Whether a FocusOut means keys now go to another window: the focus moved away from this
/// window, or from the pointer-root focus it was getting keys through. Grabs and ungrabs
/// (our own included) move no focus.
fn focus_moved_away(detail: u8, mode: u8) -> bool {
    detail != x11::NOTIFY_INFERIOR && moves_focus(mode)
}

/// Whether a focus event of `mode` reports the focus moving (FocusIn: keys now come to this
/// window). Those of a grab or ungrab do not: another client grabbing the keyboard on the root
/// sends a FocusIn (detail Pointer) to the window under the pointer, which has no focus.
fn moves_focus(mode: u8) -> bool {
    matches!(mode, NOTIFY_NORMAL | NOTIFY_WHILE_GRABBED)
}

/// Whether a FocusIn gives this window the keyboard: the focus moved here. Under a window
/// manager not a focus moved to the root (or PointerRoot) while the pointer is over this
/// window (detail Pointer), as in GTK: keys come here only until the pointer leaves, which
/// nothing tells this window, so a full-screen grab taken then would keep what is typed into
/// the window focused next. Without a window manager that is how keys come at all.
fn gains_focus(detail: u8, mode: u8, has_wm: bool) -> bool {
    moves_focus(mode) && !(has_wm && detail == x11::NOTIFY_POINTER)
}

/// Whether after a FocusOut the keys held now are released elsewhere: the focus moved away, or
/// another client grabbed the keyboard. A grab's FocusOut with detail Pointer is left out: our
/// own grab sends one under a pointer-root focus, while the keys still come here.
fn keys_released_elsewhere(detail: u8, mode: u8) -> bool {
    focus_moved_away(detail, mode)
        || (detail != x11::NOTIFY_INFERIOR && detail != x11::NOTIFY_POINTER && mode != x11::NOTIFY_UNGRAB)
}

/// Whether a window manager runs, as EWMH tells: the root's _NET_SUPPORTING_WM_CHECK names a
/// window whose own _NET_SUPPORTING_WM_CHECK names itself. One that crashed leaves the root's
/// property behind, naming a window that is gone.
fn wm_running(conn: &mut Conn) -> Result<bool> {
    let check = conn.atom("_NET_SUPPORTING_WM_CHECK")?;
    let root = conn.root();
    let named = |p: &x11::Property| <[u8; 4]>::try_from(&p.value[..]).ok().map(u32::from_le_bytes);
    let Some(child) = named(&conn.get_property(root, check, x11::ATOM_WINDOW, 4, false)?) else { return Ok(false) };
    Ok(conn.try_get_property(child, check, x11::ATOM_WINDOW, 4, false)?.is_ok_and(|p| named(&p) == Some(child)))
}

/// Cursor-font glyphs for the mirrored shapes (`None`: inherit the desktop's themed arrow).
fn cursor_glyph(c: Cursor) -> Option<u16> {
    Some(match c {
        Cursor::Hidden | Cursor::Arrow => return None,
        Cursor::IBeam => 152,                    // xterm
        Cursor::Wait | Cursor::AppStarting => 150, // watch
        Cursor::Cross => 34,                     // crosshair
        Cursor::UpArrow => 114,                  // sb_up_arrow
        Cursor::SizeNwse => 14,                  // bottom_right_corner
        Cursor::SizeNesw => 12,                  // bottom_left_corner
        Cursor::SizeWe => 108,                   // sb_h_double_arrow
        Cursor::SizeNs => 116,                   // sb_v_double_arrow
        Cursor::SizeAll => 52,                   // fleur
        Cursor::No => 0,                         // X_cursor
        Cursor::Hand => 60,                      // hand2
        Cursor::Help => 92,                      // question_arrow
    })
}

/// The remote screen as last decoded.
struct Framebuffer {
    w: usize,
    h: usize,
    px: LockedBuf,
    dirty: Option<Rect>,
    /// The remote size changed: everything must be rescaled.
    resized: bool,
    resizes: ResizePacer,
}

/// State shared between the network thread and the window thread.
struct Shared {
    fb: FrameLock<Framebuffer>,
    cursor: AtomicU8,
    cursor_changed: AtomicBool,
    closed: Mutex<Option<String>>,
    waker: Waker,
}

impl Shared {
    fn new(w: usize, h: usize, waker: Waker) -> Shared {
        let fb = Framebuffer { w, h, px: LockedBuf::new(w * h * 4), dirty: None, resized: true, resizes: ResizePacer::new(Instant::now()) };
        Shared {
            fb: FrameLock::new(fb),
            cursor: AtomicU8::new(Cursor::Arrow as u8),
            cursor_changed: AtomicBool::new(false),
            closed: Mutex::new(None),
            waker,
        }
    }

    fn close(&self, reason: String) {
        let mut c = self.closed.lock().unwrap();
        if c.is_none() {
            *c = Some(reason);
        }
        drop(c);
        self.waker.wake();
    }

    /// The framebuffer, locked on the window thread / on the network thread (`FrameLock`).
    fn ui_fb(&self) -> MutexGuard<'_, Framebuffer> {
        self.fb.ui().unwrap()
    }

    fn reader_fb(&self) -> MutexGuard<'_, Framebuffer> {
        self.fb.reader().unwrap()
    }
}

fn union(a: Option<Rect>, b: Rect) -> Rect {
    match a {
        None => b,
        Some(d) => {
            let (x0, y0) = (d.x.min(b.x), d.y.min(b.y));
            let (x1, y1) = ((d.x + d.w).max(b.x + b.w), (d.y + d.h).max(b.y + b.h));
            Rect { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }
        }
    }
}

/// Plays the host's sound (when it was asked for). Problems are reported once and never end
/// the session.
#[derive(Default)]
struct Sound {
    rx: AudioReceiver,
    warned: bool,
}

impl Sound {
    fn play(&mut self, rate: u32, channels: u8, codec: u8, data: &[u8]) {
        if let Err(e) = self.rx.play(rate, channels, codec, data) {
            if !std::mem::replace(&mut self.warned, true) {
                log!("cannot play the host's sound: {e}");
            }
        }
    }
}

/// Applies one message from the host; returns the acknowledgement to send, if any.
fn on_server_msg(
    shared: &Shared,
    dec: &mut TileDecoder,
    msg: ServerMsg,
    clip: Option<&Clipboard>,
    sound: Option<&mut Sound>,
) -> Result<Option<ClientMsg>> {
    match msg {
        ServerMsg::Tiles(p) => {
            let hdr = codec::parse_header(p)?;
            let size = (hdr.width, hdr.height);
            // A new size gets its buffer allocated and locked, and the old one wiped, outside
            // the lock `present` takes; under it only the buffers are swapped. Declared before
            // `fb`, so even an early return drops them after the lock is released.
            let (mut fresh, mut old) = (None, None);
            let mut fb = loop {
                let mut fb = shared.reader_fb();
                if (fb.w, fb.h) == size || fresh.is_some() {
                    break fb;
                }
                check_size(hdr.width, hdr.height)?;
                let wait = fb.resizes.wait(Instant::now());
                drop(fb);
                std::thread::sleep(wait);
                // This thread's own copy of the screen goes first, so that two screens' worth is
                // held at most: the old framebuffer and the new one, then the new one and a new copy.
                dec.forget();
                fresh = Some(LockedBuf::new(hdr.width * hdr.height * 4));
            };
            if (fb.w, fb.h) != size
                && let Some(px) = fresh.take()
            {
                log!("remote screen is now {}x{}", hdr.width, hdr.height);
                old = Some(std::mem::replace(&mut fb.px, px));
                (fb.w, fb.h) = size;
                fb.resized = true;
            }
            drop(fb);
            // A replaced (or unneeded) buffer is wiped with the lock released, and before this
            // thread makes its own copy of the screen at the new size.
            drop((old, fresh));
            // Decoded without the lock (`TileDecoder`): only copying the rects drawn takes it, a
            // band at a time, so `present` waits for one band at most.
            if let Some(b) = dec.decode(p, hdr.width, hdr.height)? {
                let mut at = (0, 0);
                loop {
                    let mut fb = shared.reader_fb();
                    if dec.copy(fb.px.as_mut_slice(), &mut at) {
                        fb.dirty = Some(union(fb.dirty, b));
                        break;
                    }
                }
            }
            if hdr.last {
                shared.waker.wake();
                return Ok(Some(ClientMsg::Ack(hdr.frame)));
            }
        }
        ServerMsg::Cursor(c) => {
            shared.cursor.store(c as u8, Ordering::SeqCst);
            shared.cursor_changed.store(true, Ordering::SeqCst);
            shared.waker.wake();
        }
        ServerMsg::Clipboard(t) => {
            if let Some(c) = clip {
                c.set(t);
            }
        }
        ServerMsg::Notice(t) => log!("host: {}", printable(&t)),
        ServerMsg::Audio { rate, channels, codec, data, .. } => {
            if let Some(s) = sound {
                s.play(rate, channels, codec, data);
            }
        }
        ServerMsg::State { key, value: STATE_UNAVAILABLE } => match key {
            SET_AUDIO => log!("the host does not share its sound"),
            SET_PRIVACY => log!("the host does not offer privacy mode"),
            _ => {}
        },
        _ => {}
    }
    Ok(None)
}

fn net_loop(
    reader: &mut RecordReader<TcpStream>,
    shared: &Shared,
    out: &OutQueue,
    clip: Option<&Clipboard>,
    mut sound: Option<Sound>,
) -> Result<()> {
    let mut dec = TileDecoder::new()?;
    loop {
        let rec = reader.recv()?;
        if let Some(reply) = on_server_msg(shared, &mut dec, ServerMsg::decode(rec)?, clip, sound.as_mut())? {
            let _ = out.send(reply);
        }
    }
}

/// Source span `[a, b)` that destination index `i` covers when `s` pixels are scaled to `d`.
fn span(i: usize, s: usize, d: usize) -> (usize, usize) {
    let a = (i * s / d).min(s - 1);
    let b = ((i + 1) * s / d).clamp(a + 1, s);
    (a, b)
}

/// Scales the destination rows/columns `[x0, x1) x [y0, y1)` of `src` (`sw*sh` BGRA) into `dst`
/// (`dw*dh` BGRA): box-filtered when shrinking, nearest neighbour when enlarging.
#[allow(clippy::too_many_arguments)]
fn scale_region(src: &[u8], sw: usize, sh: usize, dst: &mut [u8], dw: usize, dh: usize, (x0, y0, x1, y1): (usize, usize, usize, usize)) {
    if sw == 0 || sh == 0 || dw == 0 || dh == 0 || x0 >= x1 || y0 >= y1 || x1 > dw || y1 > dh {
        return;
    }
    if (sw, sh) == (dw, dh) {
        for y in y0..y1 {
            dst[(y * dw + x0) * 4..(y * dw + x1) * 4].copy_from_slice(&src[(y * sw + x0) * 4..(y * sw + x1) * 4]);
        }
        return;
    }
    let cols: Vec<(usize, usize)> = (x0..x1).map(|x| span(x, sw, dw)).collect();
    for y in y0..y1 {
        let (sy0, sy1) = span(y, sh, dh);
        let out = &mut dst[(y * dw + x0) * 4..(y * dw + x1) * 4];
        for (o, &(sx0, sx1)) in out.chunks_exact_mut(4).zip(&cols) {
            if sy1 - sy0 == 1 && sx1 - sx0 == 1 {
                let p = (sy0 * sw + sx0) * 4;
                o.copy_from_slice(&[src[p], src[p + 1], src[p + 2], 255]);
                continue;
            }
            let mut acc = [0u32; 3];
            for sy in sy0..sy1 {
                for px in src[(sy * sw + sx0) * 4..(sy * sw + sx1) * 4].chunks_exact(4) {
                    acc[0] += px[0] as u32;
                    acc[1] += px[1] as u32;
                    acc[2] += px[2] as u32;
                }
            }
            let n = ((sy1 - sy0) * (sx1 - sx0)) as u32;
            o.copy_from_slice(&[((acc[0] + n / 2) / n) as u8, ((acc[1] + n / 2) / n) as u8, ((acc[2] + n / 2) / n) as u8, 255]);
        }
    }
}

/// Letterboxed position `(x, y, w, h)` of an `fw*fh` image inside a `cw*ch` window.
fn dest_rect(cw: usize, ch: usize, fw: usize, fh: usize) -> (usize, usize, usize, usize) {
    if cw == 0 || ch == 0 || fw == 0 || fh == 0 {
        return (0, 0, 0, 0);
    }
    let (dw, dh) = if cw * fh <= ch * fw { (cw, (cw * fh / fw).max(1)) } else { ((ch * fw / fh).max(1), ch) };
    ((cw - dw) / 2, (ch - dh) / 2, dw, dh)
}

/// Window-relative point to remote screen coordinates.
fn to_remote(px: i32, py: i32, dest: (usize, usize, usize, usize), fw: usize, fh: usize) -> (u16, u16) {
    let (dx, dy, dw, dh) = (dest.0 as i64, dest.1 as i64, dest.2.max(1) as i64, dest.3.max(1) as i64);
    let (fw, fh) = (fw.max(1) as i64, fh.max(1) as i64);
    let rx = ((px as i64 - dx) * fw / dw).clamp(0, fw - 1);
    let ry = ((py as i64 - dy) * fh / dh).clamp(0, fh - 1);
    (rx.min(u16::MAX as i64) as u16, ry.min(u16::MAX as i64) as u16)
}

/// Where the scaled image lives: an MIT-SHM segment the server reads directly, or our memory
/// uploaded with PutImage.
enum Canvas {
    Shm(ShmSegment),
    Mem(LockedBuf),
}

impl Canvas {
    fn pixels(&mut self) -> &mut [u8] {
        match self {
            Canvas::Shm(s) => s.as_mut_slice(),
            Canvas::Mem(m) => m.as_mut_slice(),
        }
    }
}

struct Atoms {
    wm_protocols: u32,
    wm_delete: u32,
    net_wm_state: u32,
    fullscreen: u32,
}

/// The window and everything needed to draw into it.
struct View {
    conn: Conn,
    win: u32,
    gc: u32,
    atoms: Atoms,
    /// Window size.
    size: (usize, usize),
    /// Remote size the canvas was scaled from, and the letterboxed destination.
    remote: (usize, usize),
    dest: (usize, usize, usize, usize),
    shm: Option<Ext>,
    canvas: Option<Canvas>,
    /// A ShmPutImage may still be reading the canvas.
    put_pending: bool,
    strip: LockedBuf,
    font: Option<u32>,
    cursors: Vec<(Cursor, u32)>,
    has_wm: bool,
    fullscreen: bool,
    saved_geometry: Option<(i16, i16, u16, u16)>,
    want_grab: bool,
    /// The window has the input focus as far as FocusIn/FocusOut tell. A window manager
    /// focuses it after mapping it; without one keys follow the pointer and no FocusIn may
    /// ever come, so it starts out true. Under a window manager a focus that reaches it only
    /// through the pointer does not count (`gains_focus`). The keyboard is grabbed only while
    /// this holds: a grab kept after the focus moved would send what is typed into another
    /// local window to the remote.
    focused: bool,
}

impl View {
    fn create(mut conn: Conn, title: &str, rw: usize, rh: usize, fullscreen: bool) -> Result<View> {
        let root = conn.root();
        let screen = conn.get_geometry(root)?;
        let (sw, sh) = (screen.width as f64, screen.height as f64);
        let scale = (sw * 0.9 / rw as f64).min(sh * 0.9 / rh as f64).min(1.0);
        let cw = ((rw as f64 * scale) as u16).max(160);
        let ch = ((rh as f64 * scale) as u16).max(120);
        let (x, y) = (((sw as i32 - cw as i32) / 2).max(0) as i16, ((sh as i32 - ch as i32) / 2).max(0) as i16);
        let mask = x11::KEY_PRESS_MASK
            | x11::KEY_RELEASE_MASK
            | x11::BUTTON_PRESS_MASK
            | x11::BUTTON_RELEASE_MASK
            | x11::POINTER_MOTION_MASK
            | x11::EXPOSURE_MASK
            | x11::STRUCTURE_NOTIFY_MASK
            | x11::FOCUS_CHANGE_MASK;
        let black = conn.setup.black;
        let win = conn.create_window(root, x, y, cw, ch, 1, x11::CW_BACK_PIXEL | x11::CW_EVENT_MASK, &[black, mask])?;
        let atoms = Atoms {
            wm_protocols: conn.atom("WM_PROTOCOLS")?,
            wm_delete: conn.atom("WM_DELETE_WINDOW")?,
            net_wm_state: conn.atom("_NET_WM_STATE")?,
            fullscreen: conn.atom("_NET_WM_STATE_FULLSCREEN")?,
        };
        let utf8 = conn.atom("UTF8_STRING")?;
        let net_wm_name = conn.atom("_NET_WM_NAME")?;
        let latin1: Vec<u8> = title.chars().map(|c| if (c as u32) < 256 { c as u8 } else { b'?' }).collect();
        conn.change_property(win, x11::ATOM_WM_NAME, x11::ATOM_STRING, 8, &latin1)?;
        conn.change_property(win, net_wm_name, utf8, 8, title.as_bytes())?;
        conn.change_property(win, x11::ATOM_WM_CLASS, x11::ATOM_STRING, 8, b"safe-rdp\0safe-rdp\0")?;
        conn.change_property(win, atoms.wm_protocols, x11::ATOM_ATOM, 32, &atoms.wm_delete.to_le_bytes())?;
        let has_wm = wm_running(&mut conn)?;
        let gc = conn.create_gc(win, black)?;
        let shm = if conn.setup.format.is_bgrx() { conn.shm().unwrap_or(None) } else { None };
        let mut v = View {
            conn,
            win,
            gc,
            atoms,
            size: (cw as usize, ch as usize),
            remote: (0, 0),
            dest: (0, 0, 0, 0),
            shm,
            canvas: None,
            put_pending: false,
            strip: LockedBuf::new(0),
            font: None,
            cursors: Vec::new(),
            has_wm,
            fullscreen: false,
            saved_geometry: None,
            want_grab: false,
            focused: !has_wm,
        };
        if fullscreen {
            if has_wm {
                // Ask the window manager to map us full screen right away.
                let state = v.atoms.net_wm_state;
                let fs = v.atoms.fullscreen.to_le_bytes();
                v.conn.change_property(win, state, x11::ATOM_ATOM, 32, &fs)?;
                v.fullscreen = true;
                v.want_grab = true;
            } else {
                v.toggle_fullscreen()?;
            }
        }
        v.conn.map_window(win)?;
        Ok(v)
    }

    /// Recomputes the destination rectangle and (re)allocates the canvas when the window or
    /// remote size changed. Returns true if everything must be redrawn.
    fn layout(&mut self, fw: usize, fh: usize) -> Result<bool> {
        let dest = dest_rect(self.size.0, self.size.1, fw, fh);
        if dest == self.dest && (fw, fh) == self.remote && self.canvas.is_some() {
            return Ok(false);
        }
        let resized = (dest.2, dest.3) != (self.dest.2, self.dest.3) || self.canvas.is_none();
        self.dest = dest;
        self.remote = (fw, fh);
        if resized {
            self.wait_put()?;
            let len = dest.2 * dest.3 * 4;
            if let Some(Canvas::Shm(old)) = self.canvas.take() {
                if let Some(ext) = self.shm {
                    old.detach(&mut self.conn, ext);
                }
            }
            self.canvas = Some(match self.shm.map(|ext| ShmSegment::new(&mut self.conn, ext, len.max(4))) {
                Some(Ok(seg)) => Canvas::Shm(seg),
                Some(Err(e)) => {
                    log!("MIT-SHM unavailable ({e}); drawing over the X socket");
                    self.shm = None;
                    Canvas::Mem(LockedBuf::new(len))
                }
                None => Canvas::Mem(LockedBuf::new(len)),
            });
        }
        Ok(true)
    }

    /// Waits until the server has finished reading the SHM canvas.
    fn wait_put(&mut self) -> Result<()> {
        if std::mem::take(&mut self.put_pending) {
            self.conn.sync()?;
        }
        Ok(())
    }

    fn clear_borders(&mut self) -> Result<()> {
        let (cw, ch) = self.size;
        let (x, y, w, h) = self.dest;
        let w16 = |v: usize| v.min(u16::MAX as usize) as u16;
        let rects = [(0, 0, cw, y), (0, y + h, cw, ch.saturating_sub(y + h)), (0, y, x, h), (x + w, y, cw.saturating_sub(x + w), h)];
        for (rx, ry, rw, rh) in rects {
            self.conn.clear_area(self.win, rx as i16, ry as i16, w16(rw), w16(rh))?;
        }
        Ok(())
    }

    /// Rescales the canvas region `r` (canvas coordinates) from the framebuffer.
    fn rescale(&mut self, fb: &Framebuffer, r: (usize, usize, usize, usize)) -> Result<()> {
        self.wait_put()?;
        let (dw, dh) = (self.dest.2, self.dest.3);
        if let Some(c) = &mut self.canvas {
            if fb.px.len() == fb.w * fb.h * 4 {
                scale_region(fb.px.as_slice(), fb.w, fb.h, c.pixels(), dw, dh, r);
            }
        }
        Ok(())
    }

    /// Sends the canvas region `r` (canvas coordinates) to the window.
    fn put(&mut self, (x0, y0, x1, y1): (usize, usize, usize, usize)) -> Result<()> {
        let (dx, dy, dw, dh) = self.dest;
        let (x1, y1) = (x1.min(dw), y1.min(dh));
        if x0 >= x1 || y0 >= y1 {
            return Ok(());
        }
        let (w, h) = (x1 - x0, y1 - y0);
        let (win, gc) = (self.win, self.gc);
        match &mut self.canvas {
            Some(Canvas::Shm(seg)) => {
                let ext = self.shm.ok_or("no MIT-SHM")?;
                let total = (dw as u16, dh as u16);
                let src = (x0 as u16, y0 as u16, w as u16, h as u16);
                self.conn.shm_put_image(ext, win, gc, total, src, ((dx + x0) as i16, (dy + y0) as i16), seg.seg)?;
                self.put_pending = true;
            }
            Some(Canvas::Mem(px)) => {
                let fmt = self.conn.setup.format;
                let stride = fmt.row_bytes(w);
                // Strips that fit one request and stay below 1 MiB.
                let fit = self.conn.max_request_bytes().saturating_sub(32).min(1 << 20) / stride.max(1);
                let rows = fit.clamp(1, h);
                if self.strip.len() < rows * stride {
                    self.strip = LockedBuf::new(rows * stride);
                }
                let mut row = y0;
                while row < y1 {
                    let n = rows.min(y1 - row);
                    let strip = self.strip.as_mut_slice();
                    for i in 0..n {
                        let src = &px.as_slice()[((row + i) * dw + x0) * 4..((row + i) * dw + x1) * 4];
                        let out = &mut strip[i * stride..(i + 1) * stride];
                        if fmt.is_bgrx() {
                            out[..w * 4].copy_from_slice(src);
                        } else {
                            fmt.from_bgra_row(src, out);
                        }
                    }
                    let data = &self.strip.as_slice()[..n * stride];
                    self.conn.put_image(win, gc, w as u16, n as u16, (dx + x0) as i16, (dy + row) as i16, data)?;
                    row += n;
                }
            }
            None => {}
        }
        Ok(())
    }

    /// Brings the window up to date with the framebuffer.
    fn present(&mut self, shared: &Shared) -> Result<()> {
        let mut fb = shared.ui_fb();
        let resized = std::mem::take(&mut fb.resized);
        let full = self.layout(fb.w, fb.h)? || resized;
        let dirty = fb.dirty.take();
        let (_, _, dw, dh) = self.dest;
        let region = if full {
            Some((0, 0, dw, dh))
        } else {
            dirty.map(|r| {
                // Canvas pixels whose source spans touch the dirty rectangle, plus one for rounding.
                let x0 = (r.x * dw / fb.w).saturating_sub(1);
                let y0 = (r.y * dh / fb.h).saturating_sub(1);
                let x1 = ((r.x + r.w) * dw).div_ceil(fb.w) + 1;
                let y1 = ((r.y + r.h) * dh).div_ceil(fb.h) + 1;
                (x0, y0, x1.min(dw), y1.min(dh))
            })
        };
        let Some(region) = region else { return Ok(()) };
        self.rescale(&fb, region)?;
        drop(fb);
        if full {
            self.clear_borders()?;
        }
        self.put(region)
    }

    /// Redraws a window area from the canvas (after Expose).
    fn expose(&mut self, (x0, y0, x1, y1): (usize, usize, usize, usize)) -> Result<()> {
        self.clear_borders()?;
        let (dx, dy, _, _) = self.dest;
        self.put((x0.saturating_sub(dx), y0.saturating_sub(dy), x1.saturating_sub(dx), y1.saturating_sub(dy)))
    }

    fn set_cursor(&mut self, c: Cursor) -> Result<()> {
        let id = match self.cursors.iter().find(|(k, _)| *k == c) {
            Some(&(_, id)) => id,
            None => {
                let id = match (c, cursor_glyph(c)) {
                    (Cursor::Hidden, _) => self.conn.create_blank_cursor(self.win)?,
                    (_, None) => x11::NONE,
                    (_, Some(glyph)) => {
                        let font = match self.font {
                            Some(f) => f,
                            None => *self.font.insert(self.conn.open_font("cursor")?),
                        };
                        self.conn.create_glyph_cursor(font, glyph)?
                    }
                };
                self.cursors.push((c, id));
                id
            }
        };
        self.conn.change_window_attributes(self.win, x11::CW_CURSOR, &[id])
    }

    fn toggle_fullscreen(&mut self) -> Result<()> {
        let on = !self.fullscreen;
        let win = self.win;
        if self.has_wm {
            let mut ev = [0u8; 32];
            ev[0] = 33; // ClientMessage
            ev[1] = 32;
            ev[4..8].copy_from_slice(&win.to_le_bytes());
            ev[8..12].copy_from_slice(&self.atoms.net_wm_state.to_le_bytes());
            for (i, v) in [on as u32, self.atoms.fullscreen, 0, 1, 0].iter().enumerate() {
                ev[12 + 4 * i..16 + 4 * i].copy_from_slice(&v.to_le_bytes());
            }
            let root = self.conn.root();
            self.conn.send_event(root, x11::SUBSTRUCTURE_REDIRECT_MASK | x11::SUBSTRUCTURE_NOTIFY_MASK, &ev)?;
        } else if on {
            // No window manager: cover the screen ourselves.
            let g = self.conn.get_geometry(win)?;
            self.saved_geometry = Some((g.x, g.y, g.width, g.height));
            let root = self.conn.get_geometry(self.conn.root())?;
            let mask = x11::CONFIG_X | x11::CONFIG_Y | x11::CONFIG_WIDTH | x11::CONFIG_HEIGHT | x11::CONFIG_STACK_MODE;
            self.conn.configure_window(win, mask, &[0, 0, root.width as u32, root.height as u32, 0])?;
        } else if let Some((x, y, w, h)) = self.saved_geometry.take() {
            let mask = x11::CONFIG_X | x11::CONFIG_Y | x11::CONFIG_WIDTH | x11::CONFIG_HEIGHT;
            self.conn.configure_window(win, mask, &[x as i32 as u32, y as i32 as u32, w as u32, h as u32])?;
        }
        self.fullscreen = on;
        self.want_grab = on;
        if on { self.try_grab() } else { self.conn.ungrab_keyboard() }
    }

    /// Grabs the keyboard while full screen (retried until the window is viewable and has the
    /// focus).
    fn try_grab(&mut self) -> Result<()> {
        if self.want_grab && self.focused && self.conn.grab_keyboard(self.win)? {
            self.want_grab = false;
        }
        Ok(())
    }

    /// The focus went to another window (one on another monitor, a dialog): the keyboard goes
    /// with it, also in full screen, until the focus is back.
    fn focus_lost(&mut self) -> Result<()> {
        self.focused = false;
        if self.fullscreen {
            self.want_grab = true;
            self.conn.ungrab_keyboard()?;
        }
        Ok(())
    }

    fn focus_gained(&mut self) -> Result<()> {
        self.focused = true;
        self.try_grab()
    }
}

/// Keyboard, mouse and window-event handling on top of the view.
struct Ui {
    view: View,
    out: Arc<OutQueue>,
    view_only: bool,
    sas: bool,
    /// Local Ctrl/Alt keys held (evdev codes).
    mods: HashSet<u16>,
    /// Hotkey keys whose release must not reach the host either.
    swallowed: HashSet<u16>,
    /// X keycodes whose keysym is Hangul / Hangul_Hanja on this keyboard layout.
    korean: Vec<(u8, u16)>,
    buttons: u16,
    last_move: Option<(u16, u16)>,
    expose: Option<(usize, usize, usize, usize)>,
    closed: Option<String>,
}

impl Ui {
    fn new(view: View, out: Arc<OutQueue>, view_only: bool, sas: bool) -> Result<Ui> {
        let mut ui = Ui {
            view,
            out,
            view_only,
            sas,
            mods: HashSet::new(),
            swallowed: HashSet::new(),
            korean: Vec::new(),
            buttons: 0,
            last_move: None,
            expose: None,
            closed: None,
        };
        if !ui.view.conn.detectable_autorepeat().unwrap_or(false) {
            log!("warning: key auto-repeat will reach the host as separate presses");
        }
        ui.load_keymap()?;
        Ok(ui)
    }

    fn send(&self, m: ClientMsg) {
        let _ = self.out.send(m);
    }

    /// Finds the keys the local layout uses for Hangul and Hanja (often Right Alt / Right Ctrl).
    fn load_keymap(&mut self) -> Result<()> {
        let (min, max) = (self.view.conn.setup.min_keycode, self.view.conn.setup.max_keycode);
        let count = (max.saturating_sub(min) as u16 + 1).min(255) as u8;
        let (per, syms) = self.view.conn.keyboard_mapping(min, count)?;
        self.korean.clear();
        for (i, row) in syms.chunks(per.max(1)).enumerate() {
            let vk = match row.iter().take(2).find(|&&s| s == XK_HANGUL || s == XK_HANGUL_HANJA) {
                Some(&XK_HANGUL) => keymap::VK_HANGUL,
                Some(_) => keymap::VK_HANJA,
                None => continue,
            };
            self.korean.push((min.saturating_add(i as u8), vk));
        }
        Ok(())
    }

    /// Whether a key now was typed for another window: in full screen after the focus moved,
    /// the grab still catches keys until the server has let the keyboard go. They are never
    /// forwarded; the full-screen hotkey still works.
    fn typed_elsewhere(&self) -> bool {
        self.view.fullscreen && !self.view.focused
    }

    fn release_all(&mut self) {
        self.mods.clear();
        self.swallowed.clear();
        self.buttons = 0;
        if !self.view_only {
            self.send(ClientMsg::ReleaseAll);
        }
    }

    fn on_key(&mut self, press: bool, keycode: u8) -> Result<()> {
        let Some(evdev) = (keycode as u16).checked_sub(X_KEYCODE_OFFSET) else { return Ok(()) };
        if matches!(evdev, KEY_LEFTCTRL | KEY_RIGHTCTRL | KEY_LEFTALT | KEY_RIGHTALT | KEY_LEFTMETA | KEY_RIGHTMETA) {
            if press {
                self.mods.insert(evdev);
            } else {
                self.mods.remove(&evdev);
            }
        }
        let ctrl = self.mods.contains(&KEY_LEFTCTRL) || self.mods.contains(&KEY_RIGHTCTRL);
        let alt = self.mods.contains(&KEY_LEFTALT) || self.mods.contains(&KEY_RIGHTALT);
        let win = self.mods.contains(&KEY_LEFTMETA) || self.mods.contains(&KEY_RIGHTMETA);
        if !press && self.swallowed.remove(&evdev) {
            return Ok(());
        }
        if press && self.swallowed.contains(&evdev) {
            // An auto-repeat of a key held back (a hotkey's Enter or End held on after Ctrl or
            // Alt was let go, say): its release is held back too.
            return Ok(());
        }
        if press && ctrl && alt && matches!(evdev, KEY_ENTER | KEY_KPENTER | KEY_END) {
            self.swallowed.insert(evdev);
            if evdev == KEY_END {
                if self.typed_elsewhere() {
                    // Meant for another window, like the keys below.
                } else if self.sas && !self.view_only {
                    self.send(ClientMsg::Sas);
                } else {
                    log!("Ctrl+Alt+Del forwarding is not enabled on the host");
                }
            } else {
                self.view.toggle_fullscreen()?;
            }
            return Ok(());
        }
        if self.view_only {
            return Ok(());
        }
        if self.typed_elsewhere() {
            // Its release is held back too, if it comes before the focus is back.
            if press {
                self.swallowed.insert(evdev);
            }
            return Ok(());
        }
        if press && win && !self.view.fullscreen {
            // In a window the Super key and what is typed while it is held stay local, as the
            // Windows viewer keeps Win and Win+key there.
            self.swallowed.insert(evdev);
            return Ok(());
        }
        let wire = match self.korean.iter().find(|(k, _)| *k == keycode) {
            Some(&(_, vk)) => Some((vk, 0, false)),
            None => keymap::from_evdev(evdev),
        };
        let Some((vk, scan, extended)) = wire else { return Ok(()) };
        let mut flags = if press { 0 } else { KEY_UP };
        if extended {
            flags |= KEY_EXTENDED;
        }
        self.send(ClientMsg::Key { vk, scan, flags });
        Ok(())
    }

    fn remote_point(&self, x: i16, y: i16) -> (u16, u16) {
        let (fw, fh) = self.view.remote;
        to_remote(x as i32, y as i32, self.view.dest, fw, fh)
    }

    fn on_button(&mut self, press: bool, button: u8, x: i16, y: i16) {
        if self.view_only {
            return;
        }
        let wheel = match button {
            4 => Some((120, false)),
            5 => Some((-120, false)),
            6 => Some((-120, true)),
            7 => Some((120, true)),
            _ => None,
        };
        if let Some((delta, horizontal)) = wheel {
            if press {
                self.send(ClientMsg::Wheel { delta, horizontal });
            }
            return;
        }
        let b = match button {
            1 => BTN_LEFT,
            2 => BTN_MIDDLE,
            3 => BTN_RIGHT,
            8 => BTN_X1,
            9 => BTN_X2,
            _ => return,
        };
        let (rx, ry) = self.remote_point(x, y);
        self.send(ClientMsg::MouseMove { x: rx, y: ry });
        self.last_move = Some((rx, ry));
        let bit = 1u16 << b;
        let held = self.buttons & bit != 0;
        if press == held {
            return;
        }
        self.buttons ^= bit;
        self.send(ClientMsg::MouseButton { button: b, down: press });
    }

    fn on_event(&mut self, ev: Event, next: Option<&Event>) -> Result<()> {
        match ev {
            Event::Key { press: false, keycode, time, .. }
                if matches!(next, Some(Event::Key { press: true, keycode: k, time: t, .. }) if *k == keycode && *t == time) =>
            {
                // Auto-repeat without XKB: drop the synthetic release, keep the press.
            }
            Event::Key { press, keycode, .. } => self.on_key(press, keycode)?,
            Event::Button { press, button, x, y } => self.on_button(press, button, x, y),
            Event::Motion { x, y } => {
                if !self.view_only && !matches!(next, Some(Event::Motion { .. })) {
                    let p = self.remote_point(x, y);
                    if self.last_move != Some(p) {
                        self.last_move = Some(p);
                        self.send(ClientMsg::MouseMove { x: p.0, y: p.1 });
                    }
                }
            }
            Event::Focus { focus_in: false, detail, mode } => {
                if keys_released_elsewhere(detail, mode) {
                    self.release_all();
                }
                if focus_moved_away(detail, mode) {
                    self.view.focus_lost()?;
                }
            }
            Event::Focus { focus_in: true, detail, mode } => {
                if gains_focus(detail, mode, self.view.has_wm) {
                    if !self.view.focused {
                        // Keys seen while the focus was elsewhere were released there.
                        self.mods.clear();
                        self.swallowed.clear();
                    }
                    self.view.focus_gained()?;
                } else {
                    // A grab or ungrab, or a focus that only follows the pointer, which bring
                    // no focus: only retry a grab that failed while another client held the
                    // keyboard.
                    self.view.try_grab()?;
                }
            }
            Event::Expose { x, y, width, height, count } => {
                let r = (x as usize, y as usize, x as usize + width as usize, y as usize + height as usize);
                self.expose = Some(match self.expose {
                    None => r,
                    Some(e) => (e.0.min(r.0), e.1.min(r.1), e.2.max(r.2), e.3.max(r.3)),
                });
                if count == 0 {
                    if let Some(r) = self.expose.take() {
                        self.view.expose(r)?;
                    }
                }
            }
            Event::Configure { window, width, height } if window == self.view.win => {
                self.view.size = (width as usize, height as usize);
                self.view.try_grab()?;
            }
            Event::Map { window } if window == self.view.win => self.view.try_grab()?,
            Event::ClientMessage { kind, format: 32, data, .. } if kind == self.view.atoms.wm_protocols => {
                if u32::from_le_bytes(data[..4].try_into().unwrap()) == self.view.atoms.wm_delete {
                    self.closed = Some("closed".into());
                }
            }
            Event::Mapping { request: 1, .. } => self.load_keymap()?,
            _ => {}
        }
        Ok(())
    }

    /// Handles every event received so far.
    fn pump(&mut self) -> Result<()> {
        let mut batch = Vec::new();
        while let Some(e) = self.view.conn.poll_event()? {
            batch.push(e);
        }
        for i in 0..batch.len() {
            self.on_event(batch[i], batch.get(i + 1))?;
        }
        Ok(())
    }

    /// Applies frames and cursor changes from the network thread.
    fn sync_remote(&mut self, shared: &Shared) -> Result<()> {
        self.view.present(shared)?;
        if shared.cursor_changed.swap(false, Ordering::SeqCst) {
            self.view.set_cursor(Cursor::from_u8(shared.cursor.load(Ordering::SeqCst)))?;
        }
        Ok(())
    }

    /// Runs until the window is closed or the connection ends.
    fn run(&mut self, shared: &Shared, wake: &Wake) -> Result<()> {
        loop {
            self.pump()?;
            if self.closed.is_none() && self.out.stalled() {
                self.closed = Some(crate::viewer::STALLED.into());
            }
            if self.closed.is_some() || shared.closed.lock().unwrap().is_some() {
                return Ok(());
            }
            self.sync_remote(shared)?;
            if self.view.conn.has_buffered_event() {
                continue;
            }
            let ready = x11::wait_readable(&[self.view.conn.fd(), wake.fd()], -1)?;
            if ready[1] {
                wake.drain();
            }
            if ready[0] {
                self.view.conn.read_input()?;
            }
        }
    }
}

/// What to tell the user about local screen capture. Windows keeps the viewer window out of
/// screenshots and recordings unless `--allow-capture` is given; X11 has no such protection,
/// so the user who relies on that default is the one to warn.
fn capture_warning(allow_capture: bool) -> Option<&'static str> {
    (!allow_capture).then_some(
        "warning: X11 cannot keep the viewer window out of screen capture: screenshot, recording and \
         screen-sharing programs on this display can see the remote screen",
    )
}

/// Window title from the host's (untrusted) name.
fn title(host_name: &str, target: &str) -> String {
    let name: String = printable(host_name).chars().take(64).collect();
    if name.is_empty() || name == target { format!("safe-rdp - {target}") } else { format!("safe-rdp - {name} ({target})") }
}

pub fn run(target: &str, opts: ViewerOptions, psk: Secret<32>) -> Result<()> {
    // Fail before contacting the host if there is no display.
    let conn = Conn::connect(&Target::from_env()?)?;
    let crate::viewer::Connection { stream, mut reader, mut writer, width: w, height: h, flags, host_name, .. } =
        crate::viewer::connect(target, &opts, &psk)?;
    drop(psk);
    check_size(w, h)?;
    let view_only = opts.view_only || flags & F_VIEW_ONLY != 0;
    if let Some(warning) = capture_warning(opts.allow_capture) {
        log!("{warning}");
    }

    let wake = Wake::new()?;
    let shared = Shared::new(w, h, wake.waker()?);
    // Shared with the Windows viewer: acks keep only the newest, and a host that stops reading
    // ends the session instead of making the queue grow without end.
    let out = Arc::new(OutQueue::default());
    let r = std::thread::scope(|s| -> Result<()> {
        let shared = &shared;
        let queue = &*out;
        s.spawn(move || {
            let r = (|| -> Result<()> {
                loop {
                    let m = match queue.next(Duration::from_secs(5)) {
                        Next::Msg(m) => m,
                        Next::Idle => ClientMsg::Ping(0),
                        Next::Closed => return Ok(()),
                    };
                    let mut b = Vec::with_capacity(16);
                    m.encode(&mut b);
                    writer.send(&b)?;
                }
            })();
            if let Err(e) = r {
                shared.close(format!("connection lost: {e}"));
            }
        });

        let clip = if opts.clipboard && flags & F_CLIPBOARD != 0 {
            let out = out.clone();
            match Clipboard::spawn(move |t| {
                let _ = out.send(ClientMsg::Clipboard(t));
            }) {
                Ok(c) => Some(c),
                Err(e) => {
                    log!("clipboard sharing unavailable: {e}");
                    None
                }
            }
        } else {
            if opts.clipboard {
                log!("host has clipboard sharing disabled");
            }
            None
        };
        // Played on the network thread; the player stops when the connection ends.
        let sound = opts.audio.then(Sound::default);
        s.spawn(move || {
            // A panic (a framebuffer that cannot be allocated, say) ends the session with a
            // reason, rather than leaving the window on the last frame.
            let net = std::panic::AssertUnwindSafe(|| net_loop(&mut reader, shared, queue, clip.as_ref(), sound));
            let r = std::panic::catch_unwind(net);
            shared.close(match r {
                Err(_) => "the viewer failed while handling the host's data (out of memory?)".into(),
                Ok(Err(e)) if e.to_string() != channel::CLOSED => format!("connection lost: {e}"),
                Ok(_) => "the host closed the connection".into(),
            });
        });

        let ui = View::create(conn, &title(&host_name, target), w, h, opts.fullscreen)
            .and_then(|view| Ui::new(view, out.clone(), view_only, flags & F_SAS != 0));
        let r = ui.and_then(|mut ui| {
            let r = ui.run(shared, &wake);
            if let Some(reason) = ui.closed.take() {
                shared.close(reason);
            }
            let _ = ui.view.conn.destroy_window(ui.view.win);
            let _ = ui.view.conn.sync();
            r
        });
        if let Err(e) = &r {
            shared.close(format!("display error: {e}"));
        }
        // Unblock the network threads: the reader sees the socket close, the writer its queue.
        let _ = stream.shutdown(Shutdown::Both);
        out.close();
        r
    });
    // Wipe the remote screen contents before returning.
    shared.ui_fb().px = LockedBuf::new(0);
    r?;
    match shared.closed.lock().unwrap().take() {
        Some(reason) if reason != "closed" => Err(reason.into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::input::Injector;
    use crate::platform::linux::xvfb::VirtualDisplay;
    use crate::screen::Area;
    use std::time::Instant;

    /// The FocusIn/FocusOut mode of a grab itself.
    const NOTIFY_GRAB: u8 = 1;

    #[test]
    fn scaling() {
        // Identity copies the region only.
        let src: Vec<u8> = (0..4 * 4 * 4).map(|i| i as u8).collect();
        let mut dst = vec![0u8; 64];
        scale_region(&src, 4, 4, &mut dst, 4, 4, (1, 1, 3, 3));
        assert_eq!(dst[(4 + 1) * 4..(4 + 3) * 4], src[(4 + 1) * 4..(4 + 3) * 4]);
        assert_eq!(dst[..16], [0; 16]);

        // 2x shrink averages 2x2 blocks.
        let mut src = vec![0u8; 4 * 2 * 4];
        for (i, px) in src.chunks_exact_mut(4).enumerate() {
            let v = if i % 4 < 2 { [0, 100, 200, 0] } else { [10, 20, 30, 0] };
            px.copy_from_slice(&v);
        }
        src[0] = 4; // one sample differs: (4+0+0+0)/4 = 1
        let mut dst = vec![0u8; 2 * 4];
        scale_region(&src, 4, 2, &mut dst, 2, 1, (0, 0, 2, 1));
        assert_eq!(dst, [1, 100, 200, 255, 10, 20, 30, 255]);

        // Enlarging repeats pixels.
        let src = [1, 2, 3, 0, 4, 5, 6, 0];
        let mut dst = vec![0u8; 4 * 4];
        scale_region(&src, 2, 1, &mut dst, 4, 1, (0, 0, 4, 1));
        assert_eq!(dst, [1, 2, 3, 255, 1, 2, 3, 255, 4, 5, 6, 255, 4, 5, 6, 255]);

        assert!(check_size(7680, 4320).is_ok());
        assert!(check_size(65535, 65535).is_err());

        // Out-of-range regions are ignored rather than panicking.
        scale_region(&src, 2, 1, &mut dst, 4, 1, (0, 0, 5, 1));
        scale_region(&src, 2, 1, &mut dst, 4, 1, (3, 0, 2, 1));
        for (i, s, d) in [(0, 3, 7), (6, 3, 7), (0, 1920, 1), (99, 100, 100)] {
            let (a, b) = span(i, s, d);
            assert!(a < b && b <= s);
        }
    }

    #[test]
    fn letterbox_and_mapping() {
        assert_eq!(dest_rect(800, 600, 1600, 1200), (0, 0, 800, 600));
        assert_eq!(dest_rect(1000, 600, 1600, 1200), (100, 0, 800, 600));
        assert_eq!(dest_rect(800, 800, 1600, 1200), (0, 100, 800, 600));
        assert_eq!(dest_rect(0, 600, 1600, 1200), (0, 0, 0, 0));
        let d = dest_rect(1000, 600, 1600, 1200);
        assert_eq!(to_remote(100, 0, d, 1600, 1200), (0, 0));
        assert_eq!(to_remote(899, 599, d, 1600, 1200), (1598, 1198));
        assert_eq!(to_remote(-50, 9000, d, 1600, 1200), (0, 1199));
        assert_eq!(to_remote(500, 300, (0, 0, 0, 0), 0, 0), (0, 0));
    }

    #[test]
    fn titles_are_sanitised() {
        assert_eq!(title("desk", "desk"), "safe-rdp - desk");
        assert_eq!(title("", "100.64.0.1"), "safe-rdp - 100.64.0.1");
        assert_eq!(title("pc\n\u{1b}[31m", "pc.tail"), "safe-rdp - pc??[31m (pc.tail)");
        assert_eq!(title("a\u{202E}gpj.exe\u{200B}", "t"), "safe-rdp - a?gpj.exe? (t)");
        assert_eq!(title(&"x".repeat(100), "t"), format!("safe-rdp - {} (t)", "x".repeat(64)));
    }

    #[test]
    fn focus_changes_that_move_the_keyboard() {
        const GRAB: u8 = 1;
        const ANCESTOR: u8 = 0;
        const NONLINEAR: u8 = 3;
        // Another window (or the window manager's frame) took the focus, also while we held the
        // keyboard, or the pointer-root focus we had keys through went elsewhere.
        for detail in [ANCESTOR, NONLINEAR, x11::NOTIFY_POINTER] {
            assert!(focus_moved_away(detail, NOTIFY_NORMAL), "{detail}");
            assert!(focus_moved_away(detail, NOTIFY_WHILE_GRABBED), "{detail}");
            // Grabs and ungrabs, ours included, move no focus: letting go on those would only
            // grab again at once.
            assert!(!focus_moved_away(detail, GRAB), "{detail}");
            assert!(!focus_moved_away(detail, x11::NOTIFY_UNGRAB), "{detail}");
        }
        // Focus moving into a child window stays with us.
        assert!(!focus_moved_away(x11::NOTIFY_INFERIOR, NOTIFY_NORMAL));
        // FocusIn: only a focus change gives us the keys, not another client grabbing the
        // keyboard on the root (detail Pointer, to the window under the pointer) or letting go.
        assert!(moves_focus(NOTIFY_NORMAL) && moves_focus(NOTIFY_WHILE_GRABBED));
        assert!(!moves_focus(GRAB) && !moves_focus(x11::NOTIFY_UNGRAB));
        // Under a window manager the focus must move to us, not to the root with the pointer
        // over us (detail Pointer): nothing would tell us once the pointer leaves. Without one
        // keys follow the pointer.
        for mode in [NOTIFY_NORMAL, NOTIFY_WHILE_GRABBED] {
            for has_wm in [false, true] {
                assert!(gains_focus(ANCESTOR, mode, has_wm) && gains_focus(NONLINEAR, mode, has_wm), "{mode} {has_wm}");
            }
            assert!(gains_focus(x11::NOTIFY_POINTER, mode, false), "{mode}");
            assert!(!gains_focus(x11::NOTIFY_POINTER, mode, true), "{mode}");
        }
        for detail in [ANCESTOR, NONLINEAR, x11::NOTIFY_POINTER] {
            for has_wm in [false, true] {
                assert!(!gains_focus(detail, GRAB, has_wm) && !gains_focus(detail, x11::NOTIFY_UNGRAB, has_wm), "{detail} {has_wm}");
            }
        }
    }

    #[test]
    fn focus_changes_that_release_held_keys() {
        const ANCESTOR: u8 = 0;
        const NONLINEAR: u8 = 3;
        for detail in [ANCESTOR, NONLINEAR, x11::NOTIFY_POINTER] {
            // Whenever the focus moves away (the keyboard then goes with it), the pointer-root
            // focus included.
            for mode in [NOTIFY_NORMAL, NOTIFY_WHILE_GRABBED] {
                assert!(keys_released_elsewhere(detail, mode), "{detail} {mode}");
                assert_eq!(keys_released_elsewhere(detail, mode), focus_moved_away(detail, mode));
            }
            // An ungrab, ours included, brings the keys back if anything.
            assert!(!keys_released_elsewhere(detail, x11::NOTIFY_UNGRAB), "{detail}");
        }
        // Another client grabbed the keyboard; with detail Pointer it can be our own grab.
        assert!(keys_released_elsewhere(ANCESTOR, NOTIFY_GRAB) && keys_released_elsewhere(NONLINEAR, NOTIFY_GRAB));
        assert!(!keys_released_elsewhere(x11::NOTIFY_POINTER, NOTIFY_GRAB));
        // Focus moving into a child window stays with us.
        for mode in [NOTIFY_NORMAL, NOTIFY_GRAB, x11::NOTIFY_UNGRAB, NOTIFY_WHILE_GRABBED] {
            assert!(!keys_released_elsewhere(x11::NOTIFY_INFERIOR, mode), "{mode}");
        }
    }

    #[test]
    fn capture_warning_goes_to_those_relying_on_the_default() {
        assert!(capture_warning(false).is_some_and(|w| w.contains("X11") && w.contains("screen capture")));
        assert_eq!(capture_warning(true), None);
    }

    #[test]
    fn sound_problems_never_end_the_session() {
        let wake = Wake::new().unwrap();
        let shared = Shared::new(8, 8, wake.waker().unwrap());
        let mut dec = TileDecoder::new().unwrap();
        let mut sound = Sound::default();
        // Undecodable audio is reported once and skipped; no player is started for it.
        for (seq, codec) in [(1, 99), (2, 99), (3, AUDIO_IMA_ADPCM)] {
            let data: &[u8] = if codec == 99 { &[1, 2, 3, 4] } else { &[0xff; 3] };
            let msg = ServerMsg::Audio { seq, rate: 48000, channels: 2, codec, data };
            assert_eq!(on_server_msg(&shared, &mut dec, msg, None, Some(&mut sound)).unwrap(), None);
        }
        assert!(sound.warned);
        // Audio nobody asked for is ignored.
        let msg = ServerMsg::Audio { seq: 4, rate: 1, channels: 9, codec: 0, data: &[] };
        assert_eq!(on_server_msg(&shared, &mut dec, msg, None, None).unwrap(), None);
        for key in [SET_AUDIO, SET_PRIVACY] {
            let msg = ServerMsg::State { key, value: STATE_UNAVAILABLE };
            assert_eq!(on_server_msg(&shared, &mut dec, msg, None, None).unwrap(), None);
        }
    }

    #[test]
    fn size_changes_swap_the_buffer() {
        let wake = Wake::new().unwrap();
        let shared = Shared::new(8, 8, wake.waker().unwrap());
        let mut dec = TileDecoder::new().unwrap();
        let mut tiles = |id: u32, w: usize, h: usize| {
            let msg = codec::pack(id, w, h, &[]).remove(0);
            on_server_msg(&shared, &mut dec, ServerMsg::decode(&msg).unwrap(), None, None)
        };
        shared.ui_fb().resized = false;
        assert_eq!(tiles(1, 8, 8).unwrap(), Some(ClientMsg::Ack(1)));
        assert!(!shared.ui_fb().resized);
        assert_eq!(tiles(2, 16, 4).unwrap(), Some(ClientMsg::Ack(2)));
        let fb = shared.ui_fb();
        assert_eq!((fb.w, fb.h, fb.px.len(), fb.resized), (16, 4, 16 * 4 * 4, true));
        drop(fb);
        assert!(tiles(3, 8193, 8192).is_err());
        assert_eq!(shared.ui_fb().w, 16);
    }

    /// Encodes `frame` the way a host does and feeds it to the viewer's message handler.
    fn deliver(shared: &Shared, codec: &mut (codec::Encoder, TileDecoder), frame: &[u8], w: usize, h: usize, id: u32) {
        let rects = codec.0.encode(frame, w, h);
        let msgs = codec::pack(id, w, h, &rects);
        for (i, m) in msgs.iter().enumerate() {
            let ack = on_server_msg(shared, &mut codec.1, ServerMsg::decode(m).unwrap(), None, None).unwrap();
            assert_eq!(ack, (i + 1 == msgs.len()).then_some(ClientMsg::Ack(id)));
        }
    }

    fn window_pixel(view: &mut View, x: i16, y: i16) -> [u8; 3] {
        let mut px = [0u8; 4];
        view.conn.get_image(view.win, x, y, 1, 1, &mut px).unwrap();
        [px[0], px[1], px[2]]
    }

    fn drain_messages(out: &OutQueue) -> Vec<ClientMsg> {
        std::iter::from_fn(|| match out.next(Duration::ZERO) {
            Next::Msg(m) => Some(m),
            _ => None,
        })
        .collect()
    }

    /// Pumps X events until `done` holds (or fails after a few seconds).
    fn pump_until(ui: &mut Ui, mut done: impl FnMut(&mut Ui) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done(ui) {
            assert!(Instant::now() < deadline, "timed out");
            ui.view.conn.read_pending().unwrap();
            ui.pump().unwrap();
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Host capture -> encoder -> decoder -> viewer window, on one display: a gnome-terminal
    /// session on the left is captured and shown 1:1 by a viewer window on the right, which
    /// must then hold exactly the captured pixels. Set SRDP_SCREENSHOT=path to also dump the
    /// whole display as raw BGRA (preceded by width and height as little-endian u32).
    #[test]
    #[ignore = "needs Xvfb, dbus-run-session and gnome-terminal"]
    fn host_to_viewer_pipeline() {
        use crate::platform::linux::capture::Capturer;
        use crate::platform::linux::xvfb::DEFAULT_SESSION;
        let vd = VirtualDisplay::spawn(Some(79), 1600, 600, Some(DEFAULT_SESSION)).unwrap();
        let t = vd.target();
        let st = std::process::Command::new("xsetroot")
            .args(["-solid", "#204060"])
            .env("DISPLAY", vd.display_name())
            .env("XAUTHORITY", vd.xauthority())
            .status()
            .unwrap();
        assert!(st.success());
        let area = Area { left: 0, top: 0, width: 720, height: 480 };
        let mut cap = Capturer::open_on(&t, area).unwrap();
        // Wait until the terminal has drawn something other than the background.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            cap.next_frame(0).unwrap();
            let busy = cap.pixels().chunks_exact(4).filter(|p| p[..3] != [0x60, 0x40, 0x20]).count();
            if busy > 10_000 {
                break;
            }
            assert!(Instant::now() < deadline, "the session never drew");
            std::thread::sleep(Duration::from_millis(200));
        }
        std::thread::sleep(Duration::from_millis(500)); // let it settle
        cap.next_frame(0).unwrap();

        let (w, h) = (area.width as usize, area.height as usize);
        let wake = Wake::new().unwrap();
        let shared = Shared::new(w, h, wake.waker().unwrap());
        let view = View::create(Conn::connect(&t).unwrap(), "safe-rdp - pipeline", w, h, false).unwrap();
        let mut ui = Ui::new(view, Arc::default(), false, false).unwrap();
        let win = ui.view.win;
        ui.view.conn.configure_window(win, x11::CONFIG_X | x11::CONFIG_Y, &[800, 60]).unwrap();
        ui.view.conn.sync().unwrap();
        assert_eq!(ui.view.size, (w, h), "1:1 window expected");

        let mut codec = (codec::Encoder::new().unwrap(), TileDecoder::new().unwrap());
        deliver(&shared, &mut codec, cap.pixels(), w, h, 1);
        pump_until(&mut ui, |ui| ui.view.conn.get_geometry(ui.view.win).is_ok_and(|g| (g.x, g.y) == (800, 60)));
        ui.sync_remote(&shared).unwrap();
        ui.view.conn.sync().unwrap();

        let mut shown = vec![0u8; w * h * 4];
        ui.view.conn.get_image(win, 0, 0, w as u16, h as u16, &mut shown).unwrap();
        let src = cap.pixels();
        let diff = shown.chunks_exact(4).zip(src.chunks_exact(4)).filter(|(a, b)| a[..3] != b[..3]).count();
        assert_eq!(diff, 0, "viewer differs from the captured screen in {diff} pixels");

        if let Ok(path) = std::env::var("SRDP_SCREENSHOT") {
            let mut whole = Capturer::open_on(&t, Area { left: 0, top: 0, width: 1600, height: 600 }).unwrap();
            whole.next_frame(0).unwrap();
            let mut out = Vec::new();
            out.extend_from_slice(&1600u32.to_le_bytes());
            out.extend_from_slice(&600u32.to_le_bytes());
            out.extend_from_slice(whole.pixels());
            std::fs::write(path, out).unwrap();
        }
    }

    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn renders_frames_and_forwards_input() {
        let vd = VirtualDisplay::spawn(Some(76), 400, 300, None).unwrap();
        let t = vd.target();
        // A 640x480 remote screen: left half red, right half blue, white 2x2 dot at (320, 240).
        let (rw, rh) = (640, 480);
        let mut frame = vec![0u8; rw * rh * 4];
        for (i, px) in frame.chunks_exact_mut(4).enumerate() {
            px.copy_from_slice(if i % rw < rw / 2 { &[0, 0, 255, 255] } else { &[255, 0, 0, 255] });
        }

        let wake = Wake::new().unwrap();
        let shared = Shared::new(rw, rh, wake.waker().unwrap());
        let view = View::create(Conn::connect(&t).unwrap(), "safe-rdp - test", rw, rh, false).unwrap();
        let rx = Arc::new(OutQueue::default());
        let mut ui = Ui::new(view, rx.clone(), false, false).unwrap();
        // 90% of 400x300 keeps the aspect ratio: 360x270, so the image fills the window.
        assert_eq!(ui.view.size, (360, 270));
        ui.view.conn.sync().unwrap();

        let mut codec = (codec::Encoder::new().unwrap(), TileDecoder::new().unwrap());
        deliver(&shared, &mut codec, &frame, rw, rh, 1);
        ui.sync_remote(&shared).unwrap();
        ui.view.conn.sync().unwrap();
        assert_eq!(ui.view.dest, (0, 0, 360, 270));
        assert_eq!(window_pixel(&mut ui.view, 10, 10), [0, 0, 255]);
        assert_eq!(window_pixel(&mut ui.view, 350, 260), [255, 0, 0]);

        // A partial update (green band) is decoded as a dirty region and drawn.
        for y in 100..140 {
            for x in 0..rw {
                frame[(y * rw + x) * 4..(y * rw + x) * 4 + 4].copy_from_slice(&[0, 255, 0, 255]);
            }
        }
        deliver(&shared, &mut codec, &frame, rw, rh, 2);
        let dirty = shared.ui_fb().dirty.unwrap();
        assert!(dirty.y <= 100 && dirty.y + dirty.h >= 140 && dirty.h < rh, "{dirty:?}");
        ui.sync_remote(&shared).unwrap();
        ui.view.conn.sync().unwrap();
        assert_eq!(window_pixel(&mut ui.view, 10, 120 * 270 / 480), [0, 255, 0]);
        assert_eq!(window_pixel(&mut ui.view, 350, 120 * 270 / 480), [0, 255, 0]);
        assert_eq!(window_pixel(&mut ui.view, 10, 10), [0, 0, 255]);

        // Resizing letterboxes: 200x270 shows the image as 200x150 at y=60.
        let mask = x11::CONFIG_WIDTH | x11::CONFIG_HEIGHT;
        ui.view.conn.configure_window(ui.view.win, mask, &[200, 270]).unwrap();
        pump_until(&mut ui, |ui| ui.view.size == (200, 270));
        ui.sync_remote(&shared).unwrap();
        ui.view.conn.sync().unwrap();
        assert_eq!(ui.view.dest, (0, 60, 200, 150));
        assert_eq!(window_pixel(&mut ui.view, 100, 30), [0, 0, 0], "letterbox border");
        assert_eq!(window_pixel(&mut ui.view, 10, 65), [0, 0, 255]);
        assert_eq!(window_pixel(&mut ui.view, 190, 200), [255, 0, 0]);

        // The same through PutImage over the socket.
        ui.view.shm = None;
        ui.view.canvas = None;
        ui.view.conn.clear_area(ui.view.win, 0, 0, 200, 270).unwrap();
        ui.sync_remote(&shared).unwrap();
        ui.view.conn.sync().unwrap();
        assert_eq!(window_pixel(&mut ui.view, 10, 65), [0, 0, 255]);
        assert_eq!(window_pixel(&mut ui.view, 190, 200), [255, 0, 0]);

        // Input: focus the viewer and type / click through XTEST.
        let root_pos = ui.view.conn.get_geometry(ui.view.win).unwrap();
        ui.view.conn.set_input_focus(ui.view.win).unwrap();
        ui.view.conn.sync().unwrap();
        drain_messages(&rx);
        let mut inj = Injector::on(t.clone());
        inj.set_area(Area { left: 0, top: 0, width: 400, height: 300 });
        inj.handle(&ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: 0 });
        inj.handle(&ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: KEY_UP });
        inj.handle(&ClientMsg::Key { vk: 0x2e, scan: 0x53, flags: KEY_EXTENDED });
        inj.handle(&ClientMsg::Key { vk: 0x2e, scan: 0x53, flags: KEY_EXTENDED | KEY_UP });
        // Window (100, 135) is the middle of the image: remote (320, 240).
        inj.handle(&ClientMsg::MouseMove { x: root_pos.x as u16 + 100, y: root_pos.y as u16 + 135 });
        inj.handle(&ClientMsg::MouseButton { button: BTN_LEFT, down: true });
        inj.handle(&ClientMsg::MouseButton { button: BTN_LEFT, down: false });
        inj.handle(&ClientMsg::Wheel { delta: 120, horizontal: false });
        let mut got = Vec::new();
        pump_until(&mut ui, |_| {
            got.extend(drain_messages(&rx));
            got.iter().filter(|m| matches!(m, ClientMsg::Wheel { .. })).count() == 1
        });
        let keys: Vec<_> = got.iter().filter(|m| matches!(m, ClientMsg::Key { .. })).collect();
        assert_eq!(
            keys,
            [
                &ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: 0 },
                &ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: KEY_UP },
                &ClientMsg::Key { vk: 0x2e, scan: 0x53, flags: KEY_EXTENDED },
                &ClientMsg::Key { vk: 0x2e, scan: 0x53, flags: KEY_EXTENDED | KEY_UP },
            ]
        );
        assert!(got.contains(&ClientMsg::MouseMove { x: 320, y: 240 }), "{got:?}");
        assert!(got.contains(&ClientMsg::MouseButton { button: BTN_LEFT, down: true }));
        assert!(got.contains(&ClientMsg::MouseButton { button: BTN_LEFT, down: false }));
        assert!(got.contains(&ClientMsg::Wheel { delta: 120, horizontal: false }));

        // Ctrl+Alt+Enter: full screen (no window manager: the viewer covers the screen itself),
        // and neither Enter press nor release reaches the host.
        drain_messages(&rx);
        let (ctrl, alt, enter) = ((0xa2, 0x1d), (0xa4, 0x38), (0x0d, 0x1c));
        for ((vk, scan), flags) in [(ctrl, 0), (alt, 0), (enter, 0), (enter, KEY_UP), (alt, KEY_UP), (ctrl, KEY_UP)] {
            inj.handle(&ClientMsg::Key { vk, scan, flags });
        }
        pump_until(&mut ui, |ui| ui.view.size == (400, 300));
        assert!(ui.view.fullscreen);
        let got = drain_messages(&rx);
        assert!(!got.iter().any(|m| matches!(m, ClientMsg::Key { scan: 0x1c, .. })), "{got:?}");
        assert_eq!(got.iter().filter(|m| matches!(m, ClientMsg::Key { .. })).count(), 4);

        // WM_DELETE_WINDOW closes the viewer.
        let mut ev = [0u8; 32];
        ev[0] = 33;
        ev[1] = 32;
        ev[4..8].copy_from_slice(&ui.view.win.to_le_bytes());
        ev[8..12].copy_from_slice(&ui.view.atoms.wm_protocols.to_le_bytes());
        ev[12..16].copy_from_slice(&ui.view.atoms.wm_delete.to_le_bytes());
        let win = ui.view.win;
        ui.view.conn.send_event(win, 0, &ev).unwrap();
        pump_until(&mut ui, |ui| ui.closed.is_some());
    }

    /// In full screen the keyboard is grabbed only while the viewer has the focus: once another
    /// local window takes it, typing goes there and nothing reaches the host, and the grab
    /// comes back with the focus.
    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn full_screen_lets_the_keyboard_go_with_the_focus() {
        let vd = VirtualDisplay::spawn(Some(83), 400, 300, None).unwrap();
        let t = vd.target();
        let view = View::create(Conn::connect(&t).unwrap(), "safe-rdp - focus", 640, 480, false).unwrap();
        let rx = Arc::new(OutQueue::default());
        let mut ui = Ui::new(view, rx.clone(), false, false).unwrap();
        // Another local program with a window of its own.
        let mut other = Conn::connect(&t).unwrap();
        let root = other.root();
        let win = other.create_window(root, 0, 0, 50, 50, 1, x11::CW_EVENT_MASK, &[x11::KEY_PRESS_MASK]).unwrap();
        other.map_window(win).unwrap();
        other.sync().unwrap();
        // Nobody else can grab the keyboard while the viewer holds it.
        let viewer_holds_keyboard = |other: &mut Conn| {
            let free = other.grab_keyboard(win).unwrap();
            if free {
                other.ungrab_keyboard().unwrap();
                other.sync().unwrap();
            }
            !free
        };

        ui.view.conn.set_input_focus(ui.view.win).unwrap();
        ui.view.conn.sync().unwrap();
        ui.pump().unwrap();
        assert!(ui.view.focused);
        ui.view.toggle_fullscreen().unwrap();
        pump_until(&mut ui, |ui| ui.view.size == (400, 300) && !ui.view.want_grab);
        assert!(viewer_holds_keyboard(&mut other));

        // The other program takes the focus: the grab goes, and typing reaches it, not the host.
        other.set_input_focus(win).unwrap();
        other.sync().unwrap();
        pump_until(&mut ui, |ui| !ui.view.focused);
        ui.view.conn.sync().unwrap();
        assert!(!viewer_holds_keyboard(&mut other));
        drain_messages(&rx);
        let mut inj = Injector::on(t.clone());
        inj.handle(&ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: 0 });
        inj.handle(&ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: KEY_UP });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(other.wait_event(Duration::from_millis(100)).unwrap(), Some(Event::Key { press: true, .. })) {
            assert!(Instant::now() < deadline, "the other window got no key");
        }
        std::thread::sleep(Duration::from_millis(200));
        ui.view.conn.read_pending().unwrap();
        ui.pump().unwrap();
        let got = drain_messages(&rx);
        assert!(!got.iter().any(|m| matches!(m, ClientMsg::Key { .. })), "{got:?}");
        // A press still caught before the server let the keyboard go is dropped; its release
        // goes to the other window.
        let key_a = (30 + X_KEYCODE_OFFSET) as u8;
        ui.on_event(Event::Key { press: true, keycode: key_a, time: 0, state: 0 }, None).unwrap();
        assert!(drain_messages(&rx).is_empty());

        // A third program grabs the keyboard on the root and lets go, as a global shortcut does,
        // while the pointer rests over the viewer (which covers the screen). The viewer is told
        // (FocusIn, detail Pointer) but has no focus: it must not take the keyboard, though by
        // the time it looks nobody holds it.
        inj.set_area(Area { left: 0, top: 0, width: 400, height: 300 });
        inj.handle(&ClientMsg::MouseMove { x: 200, y: 150 });
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            // QueryPointer: the top-level window under the pointer.
            let seq = other.send(x11::Req::new(38, 0).u32(root)).unwrap();
            let r = other.reply(seq).unwrap();
            if u32::from_le_bytes(r[12..16].try_into().unwrap()) == ui.view.win {
                break;
            }
            assert!(Instant::now() < deadline, "the pointer is not over the viewer");
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut third = Conn::connect(&t).unwrap();
        assert!(third.grab_keyboard(root).unwrap());
        third.ungrab_keyboard().unwrap();
        third.sync().unwrap();
        ui.view.conn.sync().unwrap();
        let mut seen = Vec::new();
        while let Some(e) = ui.view.conn.poll_event().unwrap() {
            seen.push(e);
        }
        let told = Event::Focus { focus_in: true, detail: x11::NOTIFY_POINTER, mode: NOTIFY_GRAB };
        assert!(seen.contains(&told), "{seen:?}");
        for e in seen {
            ui.on_event(e, None).unwrap();
        }
        assert!(!ui.view.focused);
        // As a later Configure or Map of the window does.
        ui.view.try_grab().unwrap();
        assert!(!viewer_holds_keyboard(&mut other));

        // The focus comes back while the third program holds the keyboard: the grab follows
        // once it lets go.
        assert!(third.grab_keyboard(root).unwrap());
        ui.view.conn.set_input_focus(ui.view.win).unwrap();
        ui.view.conn.sync().unwrap();
        pump_until(&mut ui, |ui| ui.view.focused);
        assert!(ui.view.want_grab, "grabbed while another program held the keyboard");
        third.ungrab_keyboard().unwrap();
        third.sync().unwrap();
        pump_until(&mut ui, |ui| !ui.view.want_grab);
        assert!(viewer_holds_keyboard(&mut other));

        // The press dropped earlier does not hold back the next release of that key.
        drain_messages(&rx);
        inj.handle(&ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: 0 });
        inj.handle(&ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: KEY_UP });
        let mut keys = Vec::new();
        pump_until(&mut ui, |_| {
            keys.extend(drain_messages(&rx).into_iter().filter(|m| matches!(m, ClientMsg::Key { .. })));
            keys.len() >= 2
        });
        assert_eq!(keys, [ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: 0 }, ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: KEY_UP }]);
    }

    /// Without a window manager keys follow the pointer (pointer-root focus). When another
    /// program takes the focus from there, the full-screen viewer lets the keyboard go and the
    /// host lets go of the keys it holds.
    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn full_screen_lets_go_of_the_pointer_root_focus() {
        let vd = VirtualDisplay::spawn(Some(91), 400, 300, None).unwrap();
        let t = vd.target();
        let view = View::create(Conn::connect(&t).unwrap(), "safe-rdp - pointer root", 640, 480, false).unwrap();
        let rx = Arc::new(OutQueue::default());
        let mut ui = Ui::new(view, rx.clone(), false, false).unwrap();
        let mut other = Conn::connect(&t).unwrap();
        let root = other.root();
        let win = other.create_window(root, 0, 0, 50, 50, 1, x11::CW_EVENT_MASK, &[x11::KEY_PRESS_MASK]).unwrap();
        other.map_window(win).unwrap();
        other.sync().unwrap();
        assert!(ui.view.focused, "no window manager: keys follow the pointer");
        ui.view.toggle_fullscreen().unwrap();
        pump_until(&mut ui, |ui| ui.view.size == (400, 300) && !ui.view.want_grab);

        // Ctrl held down over the viewer reaches the host. Our own grab (FocusOut, detail
        // Pointer) released nothing.
        let mut inj = Injector::on(t.clone());
        inj.set_area(Area { left: 0, top: 0, width: 400, height: 300 });
        inj.handle(&ClientMsg::MouseMove { x: 200, y: 150 });
        inj.handle(&ClientMsg::Key { vk: 0xa2, scan: 0x1d, flags: 0 });
        let mut got = Vec::new();
        pump_until(&mut ui, |_| {
            got.extend(drain_messages(&rx));
            got.iter().any(|m| matches!(m, ClientMsg::Key { .. }))
        });
        assert!(!got.contains(&ClientMsg::ReleaseAll), "{got:?}");
        assert!(ui.mods.contains(&KEY_LEFTCTRL));

        // Another program takes the focus: the grab goes, and so does the key on the host.
        other.set_input_focus(win).unwrap();
        other.sync().unwrap();
        pump_until(&mut ui, |ui| !ui.view.focused);
        ui.view.conn.sync().unwrap();
        let got = drain_messages(&rx);
        assert!(got.contains(&ClientMsg::ReleaseAll), "{got:?}");
        assert!(ui.mods.is_empty());
        let free = other.grab_keyboard(win).unwrap();
        assert!(free, "the viewer kept the keyboard");
        other.ungrab_keyboard().unwrap();
        inj.handle(&ClientMsg::Key { vk: 0xa2, scan: 0x1d, flags: KEY_UP });
    }

    /// Waits until the pointer is over `win`, a top-level window.
    fn wait_pointer_over(conn: &mut Conn, win: u32) {
        let root = conn.root();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            // QueryPointer: the top-level window under the pointer.
            let seq = conn.send(x11::Req::new(38, 0).u32(root)).unwrap();
            let r = conn.reply(seq).unwrap();
            if u32::from_le_bytes(r[12..16].try_into().unwrap()) == win {
                return;
            }
            assert!(Instant::now() < deadline, "the pointer is not over window {win:#x}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Under a window manager that focuses the root when nothing else is left to focus, the
    /// full-screen viewer under the pointer is told (FocusIn, detail Pointer) but nothing when
    /// the pointer leaves: it must not take the keyboard for that, or what is typed into the
    /// window focused next would reach the host. The test plays the window manager.
    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn full_screen_ignores_pointer_focus_under_a_window_manager() {
        let vd = VirtualDisplay::spawn(Some(93), 400, 300, None).unwrap();
        let t = vd.target();
        // Announced the EWMH way, so the viewer knows there is a window manager.
        let mut wm = Conn::connect(&t).unwrap();
        let root = wm.root();
        let check = wm.create_window(root, 0, 0, 1, 1, 1, 0, &[]).unwrap();
        let supporting = wm.atom("_NET_SUPPORTING_WM_CHECK").unwrap();
        for w in [root, check] {
            wm.change_property(w, supporting, x11::ATOM_WINDOW, 32, &check.to_le_bytes()).unwrap();
        }
        wm.sync().unwrap();
        let view = View::create(Conn::connect(&t).unwrap(), "safe-rdp - pointer focus", 640, 480, true).unwrap();
        assert!(view.has_wm && view.fullscreen && !view.focused);
        let rx = Arc::new(OutQueue::default());
        let mut ui = Ui::new(view, rx.clone(), false, false).unwrap();
        ui.view.conn.sync().unwrap();
        let viewer = ui.view.win;
        // Another local program (a terminal, a password prompt) with a window of its own.
        let mut other = Conn::connect(&t).unwrap();
        let win = other.create_window(root, 0, 0, 50, 50, 1, x11::CW_EVENT_MASK, &[x11::KEY_PRESS_MASK]).unwrap();
        other.map_window(win).unwrap();
        other.sync().unwrap();
        let viewer_holds_keyboard = |other: &mut Conn| {
            let free = other.grab_keyboard(win).unwrap();
            if free {
                other.ungrab_keyboard().unwrap();
                other.sync().unwrap();
            }
            !free
        };

        // The window manager shows the viewer full screen on top and focuses it: it takes the
        // keyboard.
        let mask = x11::CONFIG_X | x11::CONFIG_Y | x11::CONFIG_WIDTH | x11::CONFIG_HEIGHT | x11::CONFIG_STACK_MODE;
        wm.configure_window(viewer, mask, &[0, 0, 400, 300, 0]).unwrap();
        wm.set_input_focus(viewer).unwrap();
        wm.sync().unwrap();
        pump_until(&mut ui, |ui| ui.view.size == (400, 300) && ui.view.focused && !ui.view.want_grab);
        assert!(viewer_holds_keyboard(&mut other));

        // A dialog takes the focus: the viewer lets the keyboard go.
        other.set_input_focus(win).unwrap();
        other.sync().unwrap();
        pump_until(&mut ui, |ui| !ui.view.focused);
        ui.view.conn.sync().unwrap();
        assert!(!viewer_holds_keyboard(&mut other));

        // The dialog is answered while the pointer rests over the viewer, and the window manager,
        // with nothing else to focus, focuses the root: keys now follow the pointer.
        let mut inj = Injector::on(t.clone());
        inj.set_area(Area { left: 0, top: 0, width: 400, height: 300 });
        inj.handle(&ClientMsg::MouseMove { x: 200, y: 150 });
        wait_pointer_over(&mut other, viewer);
        wm.set_input_focus(root).unwrap();
        wm.sync().unwrap();
        ui.view.conn.sync().unwrap();
        let mut seen = Vec::new();
        while let Some(e) = ui.view.conn.poll_event().unwrap() {
            seen.push(e);
        }
        let told = Event::Focus { focus_in: true, detail: x11::NOTIFY_POINTER, mode: NOTIFY_NORMAL };
        assert!(seen.contains(&told), "{seen:?}");
        for e in seen {
            ui.on_event(e, None).unwrap();
        }
        assert!(!ui.view.focused);
        assert!(!viewer_holds_keyboard(&mut other));

        // The pointer moves on to the other program's window (on another monitor, say), which
        // is then focused. The viewer is told nothing, and holds no keyboard: typing goes to
        // that window, and nothing reaches the host.
        wm.configure_window(win, x11::CONFIG_STACK_MODE, &[0]).unwrap();
        wm.sync().unwrap();
        inj.handle(&ClientMsg::MouseMove { x: 25, y: 25 });
        wait_pointer_over(&mut other, win);
        other.set_input_focus(win).unwrap();
        other.sync().unwrap();
        ui.view.conn.sync().unwrap();
        ui.pump().unwrap();
        assert!(!ui.view.focused);
        assert!(!viewer_holds_keyboard(&mut other));
        drain_messages(&rx);
        inj.handle(&ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: 0 });
        inj.handle(&ClientMsg::Key { vk: 0x41, scan: 0x1e, flags: KEY_UP });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(other.wait_event(Duration::from_millis(100)).unwrap(), Some(Event::Key { press: true, .. })) {
            assert!(Instant::now() < deadline, "the other window got no key");
        }
        std::thread::sleep(Duration::from_millis(200));
        ui.view.conn.read_pending().unwrap();
        ui.pump().unwrap();
        let got = drain_messages(&rx);
        assert!(!got.iter().any(|m| matches!(m, ClientMsg::Key { .. })), "{got:?}");

        // Focused by the window manager again, the viewer takes the keyboard back.
        wm.set_input_focus(viewer).unwrap();
        wm.sync().unwrap();
        pump_until(&mut ui, |ui| ui.view.focused && !ui.view.want_grab);
        assert!(viewer_holds_keyboard(&mut other));
    }

    /// A window manager counts only while its check window is there and names itself: one that
    /// crashed leaves the root's property behind, and the viewer must then go full screen (and
    /// take the keys) by itself.
    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn a_window_manager_that_is_gone_does_not_count() {
        let vd = VirtualDisplay::spawn(Some(96), 400, 300, None).unwrap();
        let t = vd.target();
        let mut wm = Conn::connect(&t).unwrap();
        let root = wm.root();
        let supporting = wm.atom("_NET_SUPPORTING_WM_CHECK").unwrap();
        let check = wm.create_window(root, 0, 0, 1, 1, 1, 0, &[]).unwrap();
        wm.change_property(root, supporting, x11::ATOM_WINDOW, 32, &check.to_le_bytes()).unwrap();
        wm.sync().unwrap();
        let mut c = Conn::connect(&t).unwrap();
        assert!(!wm_running(&mut c).unwrap(), "the check window does not name itself");
        wm.change_property(check, supporting, x11::ATOM_WINDOW, 32, &check.to_le_bytes()).unwrap();
        wm.sync().unwrap();
        assert!(wm_running(&mut c).unwrap());
        drop(wm);
        let deadline = Instant::now() + Duration::from_secs(5);
        while wm_running(&mut c).unwrap() {
            assert!(Instant::now() < deadline, "the check window outlived its client");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(c.get_property(root, supporting, x11::ATOM_WINDOW, 4, false).unwrap().value, check.to_le_bytes());
        let view = View::create(c, "safe-rdp - no wm", 640, 480, true).unwrap();
        assert!(!view.has_wm && view.fullscreen && view.focused);
    }

    /// Keys typed into the viewer: in a window Super and what is typed with it stay local; the
    /// auto-repeats of a hotkey's Enter go nowhere, also once Ctrl and Alt are up, and do not
    /// toggle full screen again.
    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn super_in_a_window_and_hotkey_repeats_stay_local() {
        let vd = VirtualDisplay::spawn(Some(97), 400, 300, None).unwrap();
        let view = View::create(Conn::connect(&vd.target()).unwrap(), "safe-rdp - keys", 640, 480, false).unwrap();
        let rx = Arc::new(OutQueue::default());
        let mut ui = Ui::new(view, rx.clone(), false, false).unwrap();
        let key = |evdev: u16| (evdev + X_KEYCODE_OFFSET) as u8;
        let (ctrl, alt, enter, e, a) = (key(KEY_LEFTCTRL), key(KEY_LEFTALT), key(KEY_ENTER), key(18), key(30));
        let type_keys = |ui: &mut Ui, keys: &[(bool, u8)]| {
            for &(press, k) in keys {
                ui.on_key(press, k).unwrap();
            }
            drain_messages(&rx)
                .into_iter()
                .filter_map(|m| match m {
                    ClientMsg::Key { vk, flags, .. } => Some((flags & KEY_UP == 0, vk)),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

        // Super+E (and its repeats) stays local in a window; A after it goes to the host.
        let win = key(KEY_LEFTMETA);
        let sent = type_keys(&mut ui, &[(true, win), (true, win), (true, e), (true, e), (false, e), (false, win), (true, a), (false, a)]);
        assert_eq!(sent, [(true, 0x41), (false, 0x41)]);

        // Ctrl+Alt+Enter held, Ctrl and Alt let go first: the repeats of Enter go nowhere, and
        // full screen is toggled once.
        let sent = type_keys(&mut ui, &[(true, ctrl), (true, alt), (true, enter), (true, enter), (false, ctrl), (false, alt)]);
        assert_eq!(sent, [(true, 0xa2), (true, 0xa4), (false, 0xa2), (false, 0xa4)]);
        assert!(ui.view.fullscreen);
        let sent = type_keys(&mut ui, &[(true, enter), (true, enter), (false, enter), (true, enter), (false, enter)]);
        assert_eq!(sent, [(true, 0x0d), (false, 0x0d)], "Enter is a key again once let go");

        // In full screen Super goes to the host.
        let sent = type_keys(&mut ui, &[(true, win), (true, e), (false, e), (false, win)]);
        assert_eq!(sent, [(true, 0x5b), (true, 0x45), (false, 0x45), (false, 0x5b)]);
    }
}
