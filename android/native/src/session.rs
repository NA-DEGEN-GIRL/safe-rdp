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

struct Input {
    touch: Touch,
    /// Mouse buttons held (Android's MotionEvent button bits).
    buttons: i32,
    /// Wheel movement from a mouse or touchpad not sent yet (fractions of a unit).
    wheel: (f32, f32),
}

pub struct Session {
    target: String,
    key: Key,
    opts: Mutex<ViewerOptions>,
    view_only: bool,
    pub screen: Arc<Screen>,
    pub renderer: Arc<Renderer>,
    out: Mutex<Option<Arc<OutQueue>>>,
    stream: Mutex<Option<TcpStream>>,
    input: Mutex<Input>,
    events: Mutex<VecDeque<Event>>,
    events_cv: Condvar,
    /// Set once by `close`; the control thread sleeps on `events_cv` between reconnect attempts.
    stopped: AtomicBool,
    ended: AtomicBool,
    /// The host's capability flags of the current connection.
    flags: AtomicU32,
    /// Off the screen: frames are not acknowledged, so the host stops sending them.
    paused: AtomicBool,
    /// The newest frame not acknowledged while paused (`u64::MAX`: none).
    unacked: AtomicU64,
    last_notice: Mutex<Option<Instant>>,
}

impl Session {
    pub fn start(target: String, key: Key, opts: ViewerOptions, mode: Mode, density: f32) -> Result<Arc<Session>> {
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
            last_notice: Mutex::new(None),
        });
        let me = s.clone();
        std::thread::Builder::new().name("session".into()).spawn(move || {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| me.control()));
            if r.is_err() {
                me.end("the viewer failed while handling the host's data (out of memory?)".into());
            }
        })?;
        Ok(s)
    }

    fn emit(&self, e: Event) {
        lock(&self.events).push_back(e);
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
    }

    /// Ends the session at the user's request.
    pub fn close(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(out) = lock(&self.out).as_ref() {
            out.send(ClientMsg::ReleaseAll);
        }
        // Let the release go out before the socket closes; the writer is quick.
        std::thread::sleep(Duration::from_millis(30));
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
        self.flags.store(flags, Ordering::SeqCst);
        let out = Arc::new(OutQueue::default());
        *lock(&self.stream) = stream.try_clone().ok();
        *lock(&self.out) = Some(out.clone());
        if self.stopped() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        {
            let mut v = lock(&self.screen.view);
            v.set_remote(width as f32, height as f32);
            let mut input = lock(&self.input);
            let (cx, cy) = (width as f32 / 2.0, height as f32 / 2.0);
            if input.touch.pointer() == (0.0, 0.0) {
                input.touch.set_pointer(&v, cx, cy);
                lock(&self.screen.pointer).at = (cx, cy);
            }
        }
        self.emit(Event::Hello { flags, width: width as u16, height: height as u16, monitor, monitors: monitors.len() as u8, name: host_name });
        self.emit(Event::Status(CONNECTED, String::new()));
        self.fit_screen(width, height);

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
            Ok(_) => self.read(&mut reader, &out, (width, height), epoch),
            Err(e) => Err(Error::from(e)),
        };
        out.close();
        let _ = stream.shutdown(Shutdown::Both);
        *lock(&self.out) = None;
        *lock(&self.stream) = None;
        let stalled = out.stalled();
        match r {
            Ok(()) => (EndKind::Closed, "the host closed the connection".into()),
            Err(_) if stalled => (EndKind::Network, viewer::STALLED.into()),
            Err(e) => {
                let kind = viewer::classify_link_error(&e);
                let reason = if kind == EndKind::Closed { "the host closed the connection".into() } else { e.to_string() };
                (kind, reason)
            }
        }
    }

    /// Asks the host for a smaller picture if this one is more than the phone takes.
    fn fit_screen(&self, w: usize, h: usize) {
        let max_tex = self.screen.max_texture.load(Ordering::SeqCst).max(0) as usize;
        let fits = |n: usize| (w / n) * (h / n) <= MAX_PIXELS && (max_tex == 0 || (w / n <= max_tex && h / n <= max_tex));
        if fits(1) {
            return;
        }
        let current = lock(&self.opts).downscale.max(1) as usize;
        if let Some(n) = (current + 1..=4).find(|&n| fits(n * current) || n == 4) {
            log!("the remote screen ({w}x{h}) is too large for this phone; asking for 1/{n}");
            lock(&self.opts).downscale = n as u8;
            self.send(ClientMsg::Set { key: SET_DOWNSCALE, value: n as u32 });
        }
    }

    /// Reads the host's messages until the connection ends.
    fn read(&self, reader: &mut channel::RecordReader<TcpStream>, out: &OutQueue, mut size: (usize, usize), epoch: Instant) -> Result<()> {
        let mut dec = TileDecoder::new()?;
        let mut sound = lock(&self.opts).audio.then(AudioReceiver::default);
        let mut sound_warned = false;
        let (mut frames, mut bytes) = (0u64, 0u64);
        let mut meter = RateMeter::new(Instant::now());
        let mut rtt_ms = None;
        loop {
            let rec = reader.recv()?;
            bytes += rec.len() as u64 + 20;
            match ServerMsg::decode(rec)? {
                ServerMsg::Tiles(p) => {
                    let hdr = codec::parse_header(p)?;
                    if (hdr.width, hdr.height) != size {
                        size = (hdr.width, hdr.height);
                        lock(&self.screen.view).set_remote(hdr.width as f32, hdr.height as f32);
                        self.fit_screen(hdr.width, hdr.height);
                    }
                    if hdr.width * hdr.height <= MAX_PIXELS {
                        self.tiles(&mut dec, p, hdr.width, hdr.height)?;
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
                        self.emit(Event::Clipboard(t));
                    }
                }
                ServerMsg::Notice(t) => {
                    *lock(&self.last_notice) = Some(Instant::now());
                    self.emit(Event::Notice(printable(&t)));
                }
                ServerMsg::Audio { rate, channels, codec, data, .. } => {
                    if let Some(s) = sound.as_mut()
                        && !self.paused.load(Ordering::SeqCst)
                        && let Err(e) = s.play(rate, channels, codec, data)
                        && !std::mem::replace(&mut sound_warned, true)
                    {
                        log!("cannot play the host's sound: {e}");
                    }
                }
                ServerMsg::State { key, value } => {
                    if key == SET_AUDIO {
                        sound = (value == 1).then(AudioReceiver::default);
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
        for a in actions {
            match a {
                Action::Move(x, y) => {
                    lock(&self.screen.pointer).at = (x as f32, y as f32);
                    if !self.view_only {
                        self.send(ClientMsg::MouseMove { x, y });
                    }
                }
                Action::Button(button, down) if !self.view_only => self.send(ClientMsg::MouseButton { button, down }),
                Action::Wheel { delta, horizontal } if !self.view_only => self.send(ClientMsg::Wheel { delta, horizontal }),
                Action::Haptic => self.emit(Event::Haptic),
                _ => {}
            }
        }
        self.renderer.redraw();
    }

    /// A touch: `kind` 0 down, 1 move, 2 up, 3 cancel.
    pub fn touch(&self, kind: i32, id: i32, x: f32, y: f32, t: u64) {
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

    /// A mouse (or touchpad, or stylus used as one): `kind` 0 moved, 1 buttons changed, 2 scrolled.
    /// `buttons` are MotionEvent's button bits; scrolling is in notches.
    pub fn mouse(&self, kind: i32, x: f32, y: f32, buttons: i32, v: f32, h: f32) {
        let mut actions = Vec::new();
        {
            let mut input = lock(&self.input);
            let view = lock(&self.screen.view);
            let (rx, ry) = view.to_remote(x, y);
            input.touch.set_pointer(&view, rx, ry);
            drop(view);
            {
                let mut p = lock(&self.screen.pointer);
                p.drawn = false;
            }
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
            if kind == 2 {
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
        if self.view_only {
            return;
        }
        let Some((vk, scan, ext)) = u16::try_from(evdev).ok().and_then(keymap::from_evdev) else { return };
        let flags = if ext { KEY_EXTENDED } else { 0 } | if down { 0 } else { KEY_UP };
        self.send(ClientMsg::Key { vk, scan, flags });
    }

    /// A setting (`SET_*`); kept for reconnects too.
    pub fn set(&self, key: u8, value: u32) {
        {
            let mut o = lock(&self.opts);
            match key {
                SET_QUALITY => o.quality = value as u8,
                SET_DOWNSCALE => o.downscale = value.clamp(1, 4) as u8,
                SET_MONITOR => o.monitor = value as u8,
                SET_AUDIO => o.audio = value == 1,
                SET_PRIVACY => o.privacy = value == 1,
                _ => return,
            }
        }
        if self.view_only && key == SET_PRIVACY {
            return;
        }
        self.send(ClientMsg::Set { key, value });
    }

    pub fn command(&self, cmd: i32) {
        match cmd {
            CMD_SAS if !self.view_only => self.send(ClientMsg::Sas),
            CMD_REFRESH => self.send(ClientMsg::Refresh),
            CMD_RELEASE_ALL if !self.view_only => self.send(ClientMsg::ReleaseAll),
            CMD_PAUSE => {
                self.paused.store(true, Ordering::SeqCst);
                if !self.view_only {
                    self.send(ClientMsg::ReleaseAll);
                }
                let cancel = lock(&self.input).touch.cancel();
                self.act(cancel);
            }
            CMD_RESUME => {
                self.paused.store(false, Ordering::SeqCst);
                let f = self.unacked.swap(u64::MAX, Ordering::SeqCst);
                if f != u64::MAX {
                    self.send(ClientMsg::Ack(f as u32));
                }
                self.send(ClientMsg::Refresh);
                self.renderer.redraw();
            }
            CMD_RESET_VIEW => {
                lock(&self.screen.view).reset();
                self.renderer.redraw();
            }
            CMD_TRACKPAD | CMD_DIRECT => {
                lock(&self.input).touch.mode = if cmd == CMD_TRACKPAD { Mode::Trackpad } else { Mode::Direct };
                self.renderer.redraw();
            }
            _ => {}
        }
    }

    pub fn clipboard(&self, text: String) {
        if lock(&self.opts).clipboard && !self.view_only && self.flags.load(Ordering::SeqCst) & F_CLIPBOARD != 0 && text.len() <= MAX_CLIPBOARD {
            self.send(ClientMsg::Clipboard(text));
        }
    }

    pub fn surface_size(&self, w: i32, h: i32) {
        lock(&self.screen.view).set_surface(w as f32, h as f32);
        self.renderer.redraw();
    }
}
