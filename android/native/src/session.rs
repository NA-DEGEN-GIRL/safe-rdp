//! One viewer session: connecting (and reconnecting), the host's messages, the input the user
//! makes, and what the Java side is told (`Event`s, which its event thread takes with `next_event`).
//!
//! Threads: the control thread connects and then reads the host's messages (decoding into the
//! framebuffer, as the Linux viewer's network thread does); a writer thread per connection sends
//! the `OutQueue`; the render thread draws (render.rs). Input comes from Java's UI thread.

use crate::audio::AudioReceiver;
use crate::channel::{self, Psk};
use crate::codec;
use crate::keymap;
use crate::log;
use crate::platform::mem::LockedBuf;
use crate::proto::*;
use crate::render::{Renderer, Screen, union};
use crate::touch::{Action, Mode, Touch};
use crate::util::{Error, Result};
use crate::viewer::{self, Connection, EndKind, Next, OutQueue, RateMeter, TileDecoder, ViewerOptions};
use std::collections::VecDeque;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Largest remote screen this viewer takes as it is (two 4K screens' worth); a larger one is
/// asked to scale itself down. Phones have the memory for a few copies of that, not of 64 Mpx.
const MAX_PIXELS: usize = 2 * 3840 * 2160;

/// Session states, as `Event::Status` reports them.
pub const CONNECTING: u8 = 0;
pub const CONNECTED: u8 = 1;
pub const RECONNECTING: u8 = 2;
pub const ENDED: u8 = 3;

/// Commands (`Session::command`).
pub const CMD_SAS: i32 = 1;
pub const CMD_REFRESH: i32 = 2;
pub const CMD_RELEASE_ALL: i32 = 3;
pub const CMD_PAUSE: i32 = 4;
pub const CMD_RESUME: i32 = 5;
pub const CMD_RESET_VIEW: i32 = 6;
pub const CMD_TRACKPAD: i32 = 7;
pub const CMD_DIRECT: i32 = 8;

/// What Java is told, encoded as `[kind, fields...]` (little-endian) for `Native.nextEvent`.
pub enum Event {
    Status(u8, String),
    Hello { flags: u32, width: u16, height: u16, monitor: u8, monitors: u8, name: String },
    Cursor(Cursor),
    Clipboard(String),
    Notice(String),
    State(u8, u32),
    Stats(String),
    Haptic,
}

impl Event {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Event::Status(s, text) => {
                b.extend([1, *s]);
                b.extend(text.as_bytes());
            }
            Event::Hello { flags, width, height, monitor, monitors, name } => {
                b.push(2);
                b.extend(flags.to_le_bytes());
                b.extend(width.to_le_bytes());
                b.extend(height.to_le_bytes());
                b.extend([*monitor, *monitors]);
                b.extend(name.as_bytes());
            }
            Event::Cursor(c) => b.extend([3, *c as u8]),
            Event::Clipboard(t) => {
                b.push(4);
                b.extend(t.as_bytes());
            }
            Event::Notice(t) => {
                b.push(5);
                b.extend(t.as_bytes());
            }
            Event::State(k, v) => {
                b.extend([6, *k]);
                b.extend(v.to_le_bytes());
            }
            Event::Stats(t) => {
                b.push(7);
                b.extend(t.as_bytes());
            }
            Event::Haptic => b.push(8),
        }
        b
    }
}

/// The pre-shared key, however it is held.
pub type Key = Box<dyn Psk + Send + Sync>;

/// Events that may wait in the queue at most: Java takes them as they come, so this many only
/// pile up if the host floods (the kinds it can repeat are merged first, `emit`).
const MAX_EVENTS: usize = 256;

struct Input {
    touch: Touch,
    /// Mouse buttons held (Android's MotionEvent button bits).
    buttons: i32,
    /// Wheel movement from a mouse or touchpad not sent yet (fractions of a unit).
    wheel: (f32, f32),
}

impl Input {
    /// Forgets held buttons, half-made gestures and partial wheel steps (what the host was told
    /// is released separately, by `ClientMsg::ReleaseAll` or a new connection).
    fn reset(&mut self) {
        self.touch.cancel();
        self.buttons = 0;
        self.wheel = (0.0, 0.0);
    }
}

/// How a connection's reading ended: a link problem is classified as the desktop viewers do; a
/// message that cannot be decoded is the host's fault, and reconnecting would not help.
type ReadEnd = (EndKind, Error);

fn fatal(e: Error) -> ReadEnd {
    (EndKind::Fatal, e)
}

pub struct Session {
    target: String,
    key: Key,
    opts: Mutex<ViewerOptions>,
    /// View only by the user's choice; `is_view_only` adds the host's.
    view_only: bool,
    pub screen: Arc<Screen>,
    pub renderer: Arc<Renderer>,
    out: Mutex<Option<Arc<OutQueue>>>,
    stream: Mutex<Option<TcpStream>>,
    // Lock order: `input`, then `screen.view`, then `screen.pointer`.
    input: Mutex<Input>,
    events: Mutex<VecDeque<Event>>,
    events_cv: Condvar,
    /// Set once by `close`; the control thread sleeps on `events_cv` between reconnect attempts.
    stopped: AtomicBool,
    ended: AtomicBool,
    /// The host's capability flags of the current connection.
    flags: AtomicU32,
    /// Off the screen: frames are not acknowledged (so the host stops sending them), sound is not
    /// played and the host's clipboard text waits in `held_clipboard`.
    paused: AtomicBool,
    /// The newest frame not acknowledged while paused (`u64::MAX`: none).
    unacked: AtomicU64,
    held_clipboard: Mutex<Option<String>>,
    last_notice: Mutex<Option<Instant>>,
}

impl Session {
    pub fn start(target: String, key: Key, opts: ViewerOptions, mode: Mode, density: f32) -> Result<Arc<Session>> {
        let density = if density.is_finite() { density.clamp(0.5, 8.0) } else { 1.0 };
        let screen = Arc::new(Screen::new(density));
        let renderer = Renderer::new();
        renderer.start(screen.clone())?;
        let s = Arc::new(Session {
            target,
            key,
            view_only: opts.view_only,
            opts: Mutex::new(opts),
            screen,
            renderer,
            out: Mutex::new(None),
            stream: Mutex::new(None),
            input: Mutex::new(Input { touch: Touch::new(mode, density), buttons: 0, wheel: (0.0, 0.0) }),
            events: Mutex::new(VecDeque::new()),
            events_cv: Condvar::new(),
            stopped: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            flags: AtomicU32::new(0),
            paused: AtomicBool::new(false),
            unacked: AtomicU64::new(u64::MAX),
            held_clipboard: Mutex::new(None),
            last_notice: Mutex::new(None),
        });
        let me = s.clone();
        let spawned = std::thread::Builder::new().name("session".into()).spawn(move || {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| me.control()));
            if r.is_err() {
                me.end("the viewer failed while handling the host's data (out of memory?)".into());
            }
            // A tiles message decoding when the session was closed may have drawn after the
            // first wipe.
            me.screen.wipe();
        });
        if let Err(e) = spawned {
            s.renderer.stop();
            return Err(e.into());
        }
        Ok(s)
    }

    /// View only, by the user's choice or the host's (`F_VIEW_ONLY`).
    fn is_view_only(&self) -> bool {
        self.view_only || self.flags.load(Ordering::SeqCst) & F_VIEW_ONLY != 0
    }

    /// Queues an event for Java. Of the kinds a host can send over and over only the newest
    /// waits, so a flood neither grows the queue nor stacks dialogs.
    fn emit(&self, e: Event) {
        let mut q = lock(&self.events);
        let same = |old: &Event| match (old, &e) {
            (Event::Clipboard(_), Event::Clipboard(_))
            | (Event::Notice(_), Event::Notice(_))
            | (Event::Cursor(_), Event::Cursor(_))
            | (Event::Stats(_), Event::Stats(_))
            | (Event::Haptic, Event::Haptic) => true,
            (Event::State(a, _), Event::State(b, _)) => a == b,
            _ => false,
        };
        if let Some(i) = q.iter().position(same) {
            q[i] = e;
        } else if q.len() < MAX_EVENTS || matches!(e, Event::Status(..) | Event::Hello { .. }) {
            q.push_back(e);
        }
        drop(q);
        self.events_cv.notify_all();
    }

    /// The next event for Java, waiting for one; `None` once the session ended and all were taken.
    pub fn next_event(&self) -> Option<Event> {
        let mut q = lock(&self.events);
        loop {
            if let Some(e) = q.pop_front() {
                return Some(e);
            }
            if self.ended.load(Ordering::SeqCst) {
                return None;
            }
            q = self.events_cv.wait(q).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// The session is over (with `reason`); everything it showed is wiped.
    fn end(&self, reason: String) {
        {
            // Under the queue's lock: `next_event` sees the end only with its event queued.
            let mut q = lock(&self.events);
            if self.ended.load(Ordering::SeqCst) {
                return;
            }
            q.push_back(Event::Status(ENDED, reason.clone()));
            self.ended.store(true, Ordering::SeqCst);
        }
        self.events_cv.notify_all();
        if !reason.is_empty() {
            log!("session ended: {reason}");
        }
        self.renderer.stop();
        self.screen.wipe();
        lock(&self.held_clipboard).take();
    }

    /// Ends the session at the user's request (again: nothing more happens).
    pub fn close(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(out) = lock(&self.out).as_ref()
            && !self.is_view_only()
            && out.send(ClientMsg::ReleaseAll)
        {
            // Let the release go out before the socket closes; the writer is quick.
            std::thread::sleep(Duration::from_millis(30));
        }
        if let Some(s) = lock(&self.stream).as_ref() {
            let _ = s.shutdown(Shutdown::Both);
        }
        if let Some(out) = lock(&self.out).as_ref() {
            out.close();
        }
        self.events_cv.notify_all();
        self.end(String::new());
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Waits `d` unless the session is closed first; false if it was.
    fn sleep(&self, d: Duration) -> bool {
        let until = Instant::now() + d;
        let mut q = lock(&self.events);
        while !self.stopped() {
            let now = Instant::now();
            if now >= until {
                return true;
            }
            q = self.events_cv.wait_timeout(q, until - now).unwrap_or_else(PoisonError::into_inner).0;
        }
        false
    }

    fn send(&self, m: ClientMsg) {
        if let Some(out) = lock(&self.out).as_ref() {
            out.send(m);
        }
    }

    fn connect(&self, reconnect: bool, instance_in_hello: bool) -> Result<Connection> {
        let opts = {
            let mut o = lock(&self.opts);
            o.reconnect = reconnect;
            o.instance_in_hello = instance_in_hello;
            ViewerOptions { ..*o }
        };
        viewer::connect(&self.target, &opts, &*self.key)
    }

    /// Connects, then runs connections and reconnects until the session ends.
    fn control(&self) {
        self.emit(Event::Status(CONNECTING, self.target.clone()));
        let mut conn = match self.connect(false, false) {
            Ok(c) => c,
            Err(e) => return self.end(e.to_string()),
        };
        let mut reconnected = false;
        loop {
            let announced = conn.flags & F_INSTANCE != 0;
            let started = Instant::now();
            let (kind, reason) = self.run(conn);
            if self.stopped() {
                return self.end(String::new());
            }
            let since_notice = lock(&self.last_notice).map(|t| t.elapsed());
            if !viewer::should_reconnect(kind, started.elapsed(), reconnected, since_notice) {
                return self.end(reason);
            }
            log!("connection lost: {reason}");
            self.emit(Event::Status(RECONNECTING, reason.clone()));
            let since = Instant::now();
            let (mut attempt, mut unanswered) = (0, false);
            conn = loop {
                if !self.sleep(viewer::reconnect_delay(attempt)) {
                    return self.end(String::new());
                }
                let named = announced && !unanswered;
                match self.connect(true, named) {
                    Ok(c) => break c,
                    Err(e) => {
                        let text = e.to_string();
                        log!("reconnect failed: {text}");
                        attempt += 1;
                        unanswered |= text == viewer::HELLO_UNANSWERED;
                        // Turned away without the instance: the host knows instances after all,
                        // and the live session may be ours. Named, the next try can take it back.
                        let name_again = announced && !named && text.starts_with(viewer::REFUSED);
                        if name_again {
                            unanswered = false;
                        }
                        if !(name_again || viewer::retryable(&e)) || since.elapsed() >= viewer::RECONNECT_FOR {
                            return self.end(text);
                        }
                        self.emit(Event::Status(RECONNECTING, text));
                    }
                }
            };
            reconnected = true;
        }
    }

    /// One connection, until it ends: how and why.
    fn run(&self, conn: Connection) -> (EndKind, String) {
        let Connection { stream, mut reader, mut writer, width, height, flags, host_name, monitors, monitor, .. } = conn;
        if self.stopped() {
            let _ = stream.shutdown(Shutdown::Both);
            return (EndKind::Closed, String::new());
        }
        self.flags.store(flags, Ordering::SeqCst);
        self.unacked.store(u64::MAX, Ordering::SeqCst);
        let out = Arc::new(OutQueue::default());
        *lock(&self.stream) = Some(stream);
        *lock(&self.out) = Some(out.clone());
        // `close` may have run between the check above and the stream being kept here.
        if self.stopped()
            && let Some(s) = lock(&self.stream).as_ref()
        {
            let _ = s.shutdown(Shutdown::Both);
        }
        {
            let mut input = lock(&self.input);
            input.reset();
            let mut v = lock(&self.screen.view);
            v.set_remote(width as f32, height as f32);
            let (px, py) = input.touch.pointer();
            let at = if (px, py) == (0.0, 0.0) { (width as f32 / 2.0, height as f32 / 2.0) } else { (px, py) };
            input.touch.set_pointer(&v, at.0, at.1);
            lock(&self.screen.pointer).at = input.touch.pointer();
        }
        self.emit(Event::Hello { flags, width: width as u16, height: height as u16, monitor, monitors: monitors.len() as u8, name: host_name });
        self.emit(Event::Status(CONNECTED, String::new()));
        let mut max_tex = self.fit_screen(width, height);

        // Pings carry the time they were sent, since `epoch`; the host echoes it.
        let epoch = Instant::now();
        let writer_thread = {
            let out = out.clone();
            std::thread::Builder::new().name("send".into()).spawn(move || -> Result<()> {
                loop {
                    let m = match out.next(Duration::from_secs(2)) {
                        Next::Msg(m) => m,
                        Next::Idle => ClientMsg::Ping(epoch.elapsed().as_micros() as u64),
                        Next::Closed => return Ok(()),
                    };
                    let mut b = Vec::with_capacity(16);
                    m.encode(&mut b);
                    if let Err(e) = writer.send(&b) {
                        out.close();
                        return Err(e);
                    }
                }
            })
        };
        let r = match writer_thread {
            Ok(_) => self.read(&mut reader, &out, (width, height), epoch, &mut max_tex),
            Err(e) => Err(fatal(e.into())),
        };
        out.close();
        if let Some(s) = lock(&self.stream).take() {
            let _ = s.shutdown(Shutdown::Both);
        }
        *lock(&self.out) = None;
        let stalled = out.stalled();
        match r {
            Ok(()) => (EndKind::Closed, "the host closed the connection".into()),
            Err((EndKind::Fatal, e)) => (EndKind::Fatal, e.to_string()),
            Err(_) if stalled => (EndKind::Network, viewer::STALLED.into()),
            Err((kind, e)) => {
                let reason = if kind == EndKind::Closed { "the host closed the connection".into() } else { e.to_string() };
                (kind, reason)
            }
        }
    }

    /// Asks the host for a smaller picture if this one (`w`x`h`, as sent at the current scale) is
    /// more than the phone takes; returns the texture size limit it went by (0: not known yet).
    fn fit_screen(&self, w: usize, h: usize) -> usize {
        let max_tex = self.screen.max_texture.load(Ordering::SeqCst).max(0) as usize;
        let current = lock(&self.opts).downscale.clamp(1, 4) as usize;
        // The host's full size, as far as this picture tells it.
        let (fw, fh) = (w * current, h * current);
        let fits = |n: usize| (fw / n) * (fh / n) <= MAX_PIXELS && (max_tex == 0 || (fw / n <= max_tex && fh / n <= max_tex));
        if fits(current) {
            return max_tex;
        }
        let n = (current + 1..=4).find(|&n| fits(n)).unwrap_or(4);
        if n > current {
            log!("the remote screen ({w}x{h}) is too large for this phone; asking for 1/{n}");
            lock(&self.opts).downscale = n as u8;
            self.send(ClientMsg::Set { key: SET_DOWNSCALE, value: n as u32 });
        }
        max_tex
    }

    /// Reads the host's messages until the connection ends.
    fn read(
        &self,
        reader: &mut channel::RecordReader<TcpStream>,
        out: &OutQueue,
        mut size: (usize, usize),
        epoch: Instant,
        max_tex: &mut usize,
    ) -> std::result::Result<(), ReadEnd> {
        let mut dec = TileDecoder::new().map_err(fatal)?;
        let mut sound = lock(&self.opts).audio.then(AudioReceiver::default);
        let mut sound_warned = false;
        let (mut frames, mut bytes) = (0u64, 0u64);
        let mut meter = RateMeter::new(Instant::now());
        let mut rtt_ms = None;
        loop {
            let rec = reader.recv().map_err(|e| (viewer::classify_link_error(&e), e))?;
            bytes += rec.len() as u64 + 20;
            match ServerMsg::decode(rec).map_err(fatal)? {
                ServerMsg::Tiles(p) => {
                    let hdr = codec::parse_header(p).map_err(fatal)?;
                    // The renderer learns the GPU's texture limit only once it has a surface.
                    let known = self.screen.max_texture.load(Ordering::SeqCst).max(0) as usize;
                    if (hdr.width, hdr.height) != size || known != *max_tex {
                        if (hdr.width, hdr.height) != size {
                            size = (hdr.width, hdr.height);
                            let mut input = lock(&self.input);
                            let v = {
                                let mut v = lock(&self.screen.view);
                                v.set_remote(hdr.width as f32, hdr.height as f32);
                                v.clone()
                            };
                            let (px, py) = input.touch.pointer();
                            input.touch.set_pointer(&v, px, py);
                        }
                        *max_tex = self.fit_screen(hdr.width, hdr.height);
                    }
                    if hdr.width * hdr.height <= MAX_PIXELS {
                        self.tiles(&mut dec, p, hdr.width, hdr.height).map_err(fatal)?;
                    }
                    if hdr.last {
                        frames += 1;
                        self.renderer.redraw();
                        if self.paused.load(Ordering::SeqCst) {
                            self.unacked.store(hdr.frame as u64, Ordering::SeqCst);
                        } else {
                            out.send(ClientMsg::Ack(hdr.frame));
                        }
                    }
                }
                ServerMsg::Cursor(c) => {
                    lock(&self.screen.pointer).shape = c;
                    self.renderer.redraw();
                    self.emit(Event::Cursor(c));
                }
                ServerMsg::Clipboard(t) => {
                    if lock(&self.opts).clipboard {
                        // Out of sight it waits: it must not replace what the user copies
                        // in another app meanwhile.
                        if self.paused.load(Ordering::SeqCst) {
                            *lock(&self.held_clipboard) = Some(t);
                        } else {
                            self.emit(Event::Clipboard(t));
                        }
                    }
                }
                ServerMsg::Notice(t) => {
                    *lock(&self.last_notice) = Some(Instant::now());
                    self.emit(Event::Notice(printable(&t)));
                }
                ServerMsg::Audio { rate, channels, codec, data, .. } => {
                    if let Some(s) = sound.as_mut() {
                        if self.paused.load(Ordering::SeqCst) {
                            s.stop();
                        } else if let Err(e) = s.play(rate, channels, codec, data)
                            && !std::mem::replace(&mut sound_warned, true)
                        {
                            log!("cannot play the host's sound: {e}");
                        }
                    }
                }
                ServerMsg::State { key, value } => {
                    let wanted = lock(&self.opts).audio;
                    match (key, value) {
                        (SET_AUDIO, 1) if !wanted => {
                            // Sound the user did not ask for is refused.
                            out.send(ClientMsg::Set { key: SET_AUDIO, value: 0 });
                            continue;
                        }
                        (SET_AUDIO, _) => sound = (value == 1).then(AudioReceiver::default),
                        (SET_PRIVACY, STATE_UNAVAILABLE) => lock(&self.opts).privacy = false,
                        _ => {}
                    }
                    if (key, value) == (SET_AUDIO, STATE_UNAVAILABLE) {
                        lock(&self.opts).audio = false;
                    }
                    self.emit(Event::State(key, value));
                }
                ServerMsg::Pong(t) => rtt_ms = Some((epoch.elapsed().as_micros() as u64).saturating_sub(t) / 1000),
                _ => {}
            }
            if let Some((fps, mbps)) = meter.update(Instant::now(), frames, bytes) {
                self.emit(Event::Stats(viewer::stats_text(rtt_ms, fps, mbps)));
            }
        }
    }

    /// Decodes a tiles message into the framebuffer (as the Linux viewer does: a new size gets its
    /// buffer outside the lock the renderer takes, and the rects drawn are copied in bands).
    fn tiles(&self, dec: &mut TileDecoder, p: &[u8], w: usize, h: usize) -> Result<()> {
        let (mut fresh, mut old) = (None, None);
        let mut fb = loop {
            let mut fb = self.screen.fb.reader().unwrap_or_else(PoisonError::into_inner);
            if (fb.w, fb.h) == (w, h) || fresh.is_some() {
                break fb;
            }
            let wait = fb.resizes.wait(Instant::now());
            drop(fb);
            std::thread::sleep(wait);
            dec.forget();
            fresh = Some(LockedBuf::new(w * h * 4));
        };
        if (fb.w, fb.h) != (w, h)
            && let Some(px) = fresh.take()
        {
            old = Some(std::mem::replace(&mut fb.px, px));
            (fb.w, fb.h) = (w, h);
            fb.dirty = Some(codec::Rect { x: 0, y: 0, w, h });
        }
        drop(fb);
        drop((old, fresh));
        if let Some(b) = dec.decode(p, w, h)? {
            let mut at = (0, 0);
            loop {
                let mut fb = self.screen.fb.reader().unwrap_or_else(PoisonError::into_inner);
                if dec.copy(fb.px.as_mut_slice(), &mut at) {
                    fb.dirty = Some(union(fb.dirty, b));
                    break;
                }
            }
        }
        Ok(())
    }

    fn act(&self, actions: Vec<Action>) {
        let view_only = self.is_view_only();
        for a in actions {
            match a {
                Action::Move(x, y) => {
                    lock(&self.screen.pointer).at = (x as f32, y as f32);
                    if !view_only {
                        self.send(ClientMsg::MouseMove { x, y });
                    }
                }
                Action::Button(button, down) if !view_only => self.send(ClientMsg::MouseButton { button, down }),
                Action::Wheel { delta, horizontal } if !view_only => self.send(ClientMsg::Wheel { delta, horizontal }),
                Action::Haptic => self.emit(Event::Haptic),
                _ => {}
            }
        }
        self.renderer.redraw();
    }

    /// A touch: `kind` 0 down, 1 move, 2 up, 3 cancel.
    pub fn touch(&self, kind: i32, id: i32, x: f32, y: f32, t: u64) {
        if !(x.is_finite() && y.is_finite()) {
            return;
        }
        let actions = {
            let mut input = lock(&self.input);
            let mut view = lock(&self.screen.view);
            lock(&self.screen.pointer).drawn = true;
            match kind {
                0 => input.touch.down(&mut view, id, x, y, t),
                1 => input.touch.moved(&mut view, id, x, y, t),
                2 => input.touch.up(&mut view, id, t),
                _ => input.touch.cancel(),
            }
        };
        self.act(actions);
    }

    pub fn tick(&self, t: u64) {
        let actions = lock(&self.input).touch.tick(t);
        self.act(actions);
    }

    /// A mouse (or touchpad): `kind` 0 moved, 1 buttons changed, 2 scrolled. `buttons` are
    /// MotionEvent's button bits; scrolling is in notches.
    pub fn mouse(&self, kind: i32, x: f32, y: f32, buttons: i32, v: f32, h: f32) {
        if !(x.is_finite() && y.is_finite()) {
            return;
        }
        let mut actions = Vec::new();
        {
            let mut input = lock(&self.input);
            let view = lock(&self.screen.view);
            let (rx, ry) = view.to_remote(x, y);
            input.touch.set_pointer(&view, rx, ry);
            drop(view);
            lock(&self.screen.pointer).drawn = false;
            actions.push(Action::Move(rx.round() as u16, ry.round() as u16));
            if kind == 1 {
                // BUTTON_PRIMARY, SECONDARY, TERTIARY, BACK, FORWARD.
                const MAP: [(i32, u8); 5] = [(1, BTN_LEFT), (2, BTN_RIGHT), (4, BTN_MIDDLE), (8, BTN_X1), (16, BTN_X2)];
                for (bit, b) in MAP {
                    if (buttons ^ input.buttons) & bit != 0 {
                        actions.push(Action::Button(b, buttons & bit != 0));
                    }
                }
                input.buttons = buttons;
            }
            if kind == 2 && v.is_finite() && h.is_finite() {
                let wheel = &mut input.wheel;
                wheel.0 += h * 120.0;
                wheel.1 += v * 120.0;
                for (acc, horizontal) in [(&mut wheel.1, false), (&mut wheel.0, true)] {
                    let whole = acc.trunc();
                    if whole != 0.0 {
                        *acc -= whole;
                        actions.push(Action::Wheel { delta: whole.clamp(-30_000.0, 30_000.0) as i16, horizontal });
                    }
                }
            }
        }
        self.act(actions);
    }

    /// A key (Linux evdev code, as `KeyEvent.getScanCode()` gives and the app's keyboard sends).
    pub fn key(&self, evdev: i32, down: bool) {
        if self.is_view_only() {
            return;
        }
        let Some((vk, scan, ext)) = u16::try_from(evdev).ok().and_then(keymap::from_evdev) else { return };
        let flags = if ext { KEY_EXTENDED } else { 0 } | if down { 0 } else { KEY_UP };
        self.send(ClientMsg::Key { vk, scan, flags });
    }

    /// A setting (`SET_*`); kept for reconnects too.
    pub fn set(&self, key: u8, value: u32) {
        if key == SET_PRIVACY && self.is_view_only() {
            return;
        }
        let value = {
            let mut o = lock(&self.opts);
            match key {
                SET_QUALITY if value <= QUALITY_LOW => {
                    o.quality = value as u8;
                    value
                }
                SET_DOWNSCALE => {
                    o.downscale = value.clamp(1, 4) as u8;
                    o.downscale as u32
                }
                SET_MONITOR if value <= MONITOR_ALL as u32 => {
                    o.monitor = value as u8;
                    value
                }
                SET_AUDIO => {
                    o.audio = value == 1;
                    o.audio as u32
                }
                SET_PRIVACY => {
                    o.privacy = value == 1;
                    o.privacy as u32
                }
                _ => return,
            }
        };
        self.send(ClientMsg::Set { key, value });
    }

    pub fn command(&self, cmd: i32) {
        let view_only = self.is_view_only();
        match cmd {
            CMD_SAS if !view_only => self.send(ClientMsg::Sas),
            CMD_REFRESH => self.send(ClientMsg::Refresh),
            CMD_RELEASE_ALL => {
                lock(&self.input).reset();
                if !view_only {
                    self.send(ClientMsg::ReleaseAll);
                }
            }
            CMD_PAUSE => {
                self.paused.store(true, Ordering::SeqCst);
                lock(&self.input).reset();
                if !view_only {
                    self.send(ClientMsg::ReleaseAll);
                }
            }
            CMD_RESUME => {
                self.paused.store(false, Ordering::SeqCst);
                let f = self.unacked.swap(u64::MAX, Ordering::SeqCst);
                if f != u64::MAX {
                    self.send(ClientMsg::Ack(f as u32));
                }
                self.send(ClientMsg::Refresh);
                if let Some(t) = lock(&self.held_clipboard).take() {
                    self.emit(Event::Clipboard(t));
                }
                self.renderer.redraw();
            }
            CMD_RESET_VIEW => {
                lock(&self.screen.view).reset();
                self.renderer.redraw();
            }
            CMD_TRACKPAD | CMD_DIRECT => {
                let mut input = lock(&self.input);
                input.reset();
                input.touch.mode = if cmd == CMD_TRACKPAD { Mode::Trackpad } else { Mode::Direct };
                drop(input);
                if !view_only {
                    self.send(ClientMsg::ReleaseAll);
                }
                self.renderer.redraw();
            }
            _ => {}
        }
    }

    pub fn clipboard(&self, text: String) {
        if lock(&self.opts).clipboard && !self.is_view_only() && self.flags.load(Ordering::SeqCst) & F_CLIPBOARD != 0 && text.len() <= MAX_CLIPBOARD {
            self.send(ClientMsg::Clipboard(text));
        }
    }

    pub fn surface_size(&self, w: i32, h: i32) {
        if w <= 0 || h <= 0 {
            return;
        }
        lock(&self.screen.view).set_surface(w as f32, h as f32);
        self.renderer.redraw();
    }
}
