//! Viewer: a Win32 window that renders the remote screen and forwards keyboard and mouse,
//! with a connection bar (monitor, quality, scale, Ctrl+Alt+Del, clipboard, files, sound,
//! privacy screen), toasts for events, and automatic reconnects when the link drops.
//!
//! Hotkeys (handled locally, never forwarded):
//!   Ctrl+Alt+Enter  toggle full screen
//!   Ctrl+Alt+End    send Ctrl+Alt+Del to the host (service mode only)
//!
//! Threads: the UI thread owns the window, the chrome and `Ui` (thread-local). Each session
//! has a writer thread draining its `OutQueue`, a reader thread (frames, clipboard, audio,
//! downloads) and, while files are being sent, an uploader. Session threads reach the UI
//! through `App::events` + `WM_APP_EVENT`. A reconnect replaces the whole `Session`;
//! anything still arriving from an old one is recognised by its generation number.

use super::audio::AudioPlayer;
use super::capture::CURSOR_IDS;
use super::clipboard::Clipboard;
use super::mem::LockedBuf;
use super::toolbar::{self, Bar, BarModel, Feature, Overlay, ToastAction, Toasts, Tone, Txt, tr, trf};
use crate::channel::{RecordReader, RecordWriter};
use crate::codec::{self, Decoder, Rect};
use crate::files;
use crate::proto::*;
use crate::util::{Error, Result, Secret, wide};
use crate::viewer::{self as core, Connection, EndKind, Next, OutQueue, ViewerOptions};
use crate::{bail, log};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::net::{Shutdown, TcpStream};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::Dialogs::*;
use windows_sys::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
use windows_sys::Win32::UI::Shell::{DragAcceptFiles, DragFinish, DragQueryFileW, HDROP};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::audio::AdpcmDecoder;

const WM_APP_FRAME: u32 = WM_APP + 1;
const WM_APP_CURSOR: u32 = WM_APP + 2;
const WM_APP_EVENT: u32 = WM_APP + 3;
const WM_APP_FULLSCREEN: u32 = WM_APP + 4;
/// Re-sync the chrome with the window (size, DPI, full screen). Posted, so it never runs
/// inside another handler.
const WM_APP_LAYOUT: u32 = WM_APP + 5;

const T_TICK: usize = 1;
const T_RECONNECT: usize = 2;
const TICK_MS: u32 = 250;

const MOD_CTRL: u8 = 1;
const MOD_ALT: u8 = 2;
const MOD_WIN: u8 = 4;

const PING_EVERY: Duration = Duration::from_secs(2);
/// Silence after which the bar warns that the host is not responding.
const QUIET_WARN_MS: u64 = 6000;
/// Files from the host are accepted only after asking for them: the first must start
/// within this time of the click, each next one within this time of progress on the files
/// accepted for that click. So a host cannot push files nobody asked for.
const PULL_WINDOW_MS: u64 = 30_000;
/// Most files, and longest time, one click on "Get copied files" accepts new files for.
const PULL_MAX_FILES: u32 = 1000;
const PULL_MAX_MS: u64 = 60 * 60 * 1000;
const MAX_DOWNLOADS: usize = 8;
/// Events waiting for the UI thread beyond which host-driven ones (notices, settings,
/// toasts) are dropped; notices and settings are merged into a queued one first.
const MAX_EVENTS: usize = 64;
/// Events handled per `WM_APP_EVENT`, so the message loop keeps running during a flood.
const EVENTS_PER_WAKE: usize = 16;
/// At most one toast per this time for messages from the host (the latest is shown).
const NOTICE_GAP: Duration = Duration::from_secs(1);
const MAX_HOST_NAME: usize = 64;
const MAX_HOST_TEXT: usize = 4096;
/// Largest remote screen accepted (keeps a hostile size from exhausting memory).
const MAX_PIXELS: usize = 64 << 20;
/// Most files queued from one selection or drop.
const MAX_BATCH: usize = 1000;
/// How long the floating bar stays after being revealed.
const BAR_HOLD_MS: u32 = 2000;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Framebuffer {
    w: usize,
    h: usize,
    px: LockedBuf,
    dirty: Option<Rect>,
}

struct Saved {
    style: isize,
    placement: WINDOWPLACEMENT,
}

// SAFETY: WINDOWPLACEMENT inside `Saved` is plain data.
unsafe impl Send for Saved {}

/// Process-wide viewer state shared by the UI thread, the keyboard hook and session threads.
struct App {
    hwnd: AtomicUsize,
    fb: Mutex<Framebuffer>,
    fb_w: AtomicU32,
    fb_h: AtomicU32,
    /// Height of the docked bar above the remote image (0 in full screen).
    top: AtomicI32,
    cursor: AtomicU8,
    hook_active: AtomicBool,
    mods: AtomicU8,
    swallowed: Mutex<HashSet<u16>>,
    /// Keys held down and whether their press went to the local desktop (see `stays_local`).
    routes: Mutex<HashMap<u16, bool>>,
    fullscreen: Mutex<Option<Saved>>,
    /// A popup menu is open: keys belong to it, not to the host.
    local_keys: AtomicBool,
    buttons: AtomicU8,
    last_move: AtomicU32,
    /// The live session; `None` while reconnecting.
    session: Mutex<Option<Arc<Session>>>,
    events: Mutex<VecDeque<Event>>,
}

static APP: OnceLock<App> = OnceLock::new();

/// True once the viewer window exists (later errors are reported in the window).
fn window_shown() -> bool {
    APP.get().is_some_and(|a| a.hwnd.load(Ordering::SeqCst) != 0)
}

impl App {
    fn hwnd(&self) -> HWND {
        self.hwnd.load(Ordering::SeqCst) as HWND
    }

    fn session(&self) -> Option<Arc<Session>> {
        lock(&self.session).clone()
    }

    /// The live session, if it accepts input.
    fn input(&self) -> Option<Arc<Session>> {
        self.session().filter(|s| !s.view_only)
    }

    fn is_fullscreen(&self) -> bool {
        lock(&self.fullscreen).is_some()
    }

    /// Queues an event for the UI thread.
    fn post(&self, ev: Event) {
        if enqueue(&mut lock(&self.events), ev) {
            unsafe { PostMessageW(self.hwnd(), WM_APP_EVENT, 0, 0) };
        }
    }
}

/// Adds `ev` to the UI queue, keeping it bounded however fast the host sends: a notice
/// replaces a queued notice and a setting's state a queued state of the same setting, and
/// host-driven events are dropped once `MAX_EVENTS` wait. True if a new entry was added.
fn enqueue(q: &mut VecDeque<Event>, ev: Event) -> bool {
    let same = |e: &Event| match (e, &ev) {
        (Event::Notice { generation: a, .. }, Event::Notice { generation: b, .. }) => a == b,
        (Event::State { generation: a, key: k, .. }, Event::State { generation: b, key: l, .. }) => a == b && k == l,
        _ => false,
    };
    if let Some(i) = q.iter().position(same) {
        q[i] = ev;
        return false;
    }
    if q.len() >= MAX_EVENTS && matches!(ev, Event::Notice { .. } | Event::State { .. } | Event::Toast { .. }) {
        return false;
    }
    q.push_back(ev);
    true
}

enum Event {
    Ended { generation: u64, kind: EndKind, reason: String, lifetime: Duration, since_notice: Option<Duration> },
    Attempt { id: u64, result: Result<Connection> },
    Toast { generation: u64, tone: Tone, title: String, text: String, action: Option<ToastAction> },
    Notice { generation: u64, text: String },
    State { generation: u64, key: u8, value: u32 },
    SoundFailed { generation: u64, reason: String },
}

#[derive(Clone, Default)]
struct Progress {
    name: String,
    done: u64,
    total: u64,
}

#[derive(Default)]
struct Transfers {
    queue: VecDeque<PathBuf>,
    uploading: bool,
    next_id: u32,
    /// Sent files waiting for the host's `FileResult`.
    sent: HashMap<u32, String>,
    up: Option<Progress>,
    batch_done: usize,
    batch_total: usize,
    down: Option<Progress>,
}

/// One authenticated connection and the threads serving it.
struct Session {
    generation: u64,
    out: OutQueue,
    sock: TcpStream,
    flags: u32,
    view_only: bool,
    start: Instant,
    /// Established by an automatic reconnect.
    reconnected: bool,
    ended: AtomicBool,
    frames: AtomicU64,
    rx_bytes: AtomicU64,
    last_rx_ms: AtomicU64,
    rtt_ms: AtomicU64,
    last_notice_ms: AtomicU64,
    /// Play incoming audio.
    sound: AtomicBool,
    pull: Mutex<Pull>,
    clipboard: Mutex<Option<Clipboard>>,
    xfer: Mutex<Transfers>,
}

const UNSET: u64 = u64::MAX;

impl Session {
    fn ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn send(&self, m: ClientMsg) {
        self.out.send(m);
    }

    fn is_ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }

    /// Reports the end of the session once (the first of reader and writer wins).
    fn end(&self, kind: EndKind, reason: String) {
        if self.ended.swap(true, Ordering::SeqCst) {
            return;
        }
        let notice = self.last_notice_ms.load(Ordering::SeqCst);
        let now = self.ms();
        let since_notice = (notice != UNSET).then(|| Duration::from_millis(now.saturating_sub(notice)));
        let lifetime = self.start.elapsed();
        APP.get().unwrap().post(Event::Ended { generation: self.generation, kind, reason, lifetime, since_notice });
    }

    /// Stops every thread of this session (the reader notices the closed socket).
    fn shutdown(&self) {
        self.ended.store(true, Ordering::SeqCst);
        self.out.close();
        let _ = self.sock.shutdown(Shutdown::Both);
        lock(&self.clipboard).take();
    }

    fn toast(&self, tone: Tone, title: String, text: String, action: Option<ToastAction>) {
        APP.get().unwrap().post(Event::Toast { generation: self.generation, tone, title, text, action });
    }

    fn files_allowed(&self) -> bool {
        self.flags & F_FILES != 0
    }
}

/// Which files from the host the user asked for. A click on "Get copied files" lets the
/// first file start within `PULL_WINDOW_MS`; after that only progress on files accepted for
/// that click keeps the window open (a new file alone never does), for at most
/// `PULL_MAX_FILES` files and never later than `PULL_MAX_MS` after the click.
#[derive(Default)]
struct Pull {
    /// Number of the latest click (0: never asked).
    request: u32,
    /// New files are accepted while `now < until`; 0 means nothing was requested.
    until: u64,
    /// The click's absolute limit for new files.
    deadline: u64,
    files_left: u32,
}

impl Pull {
    /// The user asked for the host's copied files at session time `now` (ms).
    fn request(&mut self, now: u64) {
        self.request = self.request.wrapping_add(1).max(1);
        self.until = now + PULL_WINDOW_MS;
        self.deadline = now + PULL_MAX_MS;
        self.files_left = PULL_MAX_FILES;
    }

    /// The host starts a file: the request it is accepted for, or `None` if nobody asked.
    fn begin(&mut self, now: u64) -> Option<u32> {
        if self.until == 0 || now >= self.until || now >= self.deadline || self.files_left == 0 {
            return None;
        }
        self.files_left -= 1;
        Some(self.request)
    }

    /// Data or the end of a file accepted for `request` arrived: the next file may follow.
    fn progress(&mut self, request: u32, now: u64) {
        if request == self.request && self.until != 0 {
            self.until = self.until.max((now + PULL_WINDOW_MS).min(self.deadline));
        }
    }
}

/// Settings the user chose; they survive reconnects and seed the next hello.
struct Prefs {
    quality: u8,
    downscale: u8,
    monitor: u8,
    audio: bool,
    privacy: bool,
    clipboard: bool,
}

struct Reconnect {
    since: Instant,
    attempt: u32,
    /// When the next attempt starts; `None` while one is running.
    due: Option<Instant>,
    in_flight: Option<u64>,
    /// Why the session ended, and the error of the latest failed attempt.
    cause: String,
    last_error: Option<String>,
}

/// UI-thread state. Lives in `UI`; handlers borrow it briefly and never across calls that
/// run a modal loop (menus, dialogs, message boxes).
struct Ui {
    hwnd: HWND,
    target: String,
    opts: ViewerOptions,
    psk: Arc<Secret<32>>,
    prefs: Prefs,
    host: String,
    monitors: Vec<MonitorInfo>,
    flags: u32,
    view_only: bool,
    /// `SET_*` keys the host reported unavailable.
    unavailable: [bool; 8],
    /// `SET_*` keys changed by the user and not yet confirmed.
    pending: [bool; 8],
    sound_local_failed: bool,
    bar: Bar,
    toasts: Toasts,
    overlay: Overlay,
    floating: bool,
    meter: core::RateMeter,
    fps: f64,
    mbps: f64,
    generation: u64,
    reconnect: Option<Reconnect>,
    next_attempt: u64,
    last_notice: Option<String>,
    /// `last_notice` still needs a toast, and when the latest such toast appeared.
    notice_waiting: bool,
    notice_shown: Option<Instant>,
    /// Set once the window is going away; later events are ignored.
    closing: bool,
    exit_error: Option<String>,
}

thread_local! {
    static UI: RefCell<Option<Ui>> = const { RefCell::new(None) };
}

/// Runs `f` on the UI state unless it is already borrowed further up the stack.
fn with_ui<R>(f: impl FnOnce(&mut Ui) -> R) -> Option<R> {
    UI.with(|cell| match cell.try_borrow_mut() {
        Ok(mut g) => g.as_mut().map(f),
        Err(_) => None,
    })
}

/// Follow-up work that must run outside the `Ui` borrow.
enum After {
    Nothing,
    Quit(Option<String>),
    ChooseFiles,
    ToggleFullscreen,
}

/// Runs the viewer. When started from a shortcut or Explorer the console exists only for us:
/// hide it, and report errors that happen before the window appears in a message box.
pub fn run(target: &str, opts: ViewerOptions, psk: Secret<32>) -> Result<()> {
    use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
    let own_console = unsafe {
        let mut pids = [0u32; 4];
        GetConsoleProcessList(pids.as_mut_ptr(), 4) == 1
    };
    if own_console {
        unsafe { FreeConsole() };
    }
    let r = run_window(target, opts, psk);
    if let (true, false, Err(e)) = (own_console, window_shown(), &r) {
        let (text, title) = (wide(&e.to_string()), wide("safe-rdp"));
        unsafe { MessageBoxW(null_mut(), text.as_ptr(), title.as_ptr(), MB_ICONERROR | MB_OK) };
    }
    r
}

fn run_window(target: &str, opts: ViewerOptions, psk: Secret<32>) -> Result<()> {
    let conn = core::connect(target, &opts, &psk)?;
    let (w, h) = (conn.width, conn.height);
    if w * h > MAX_PIXELS {
        bail!("the host's screen ({w}x{h}) is too large");
    }
    let app = App {
        hwnd: AtomicUsize::new(0),
        fb: Mutex::new(Framebuffer { w, h, px: LockedBuf::new(w * h * 4), dirty: None }),
        fb_w: AtomicU32::new(w as u32),
        fb_h: AtomicU32::new(h as u32),
        top: AtomicI32::new(0),
        cursor: AtomicU8::new(Cursor::Arrow as u8),
        hook_active: AtomicBool::new(false),
        mods: AtomicU8::new(0),
        swallowed: Mutex::new(HashSet::new()),
        routes: Mutex::new(HashMap::new()),
        fullscreen: Mutex::new(None),
        local_keys: AtomicBool::new(false),
        buttons: AtomicU8::new(0),
        last_move: AtomicU32::new(u32::MAX),
        session: Mutex::new(None),
        events: Mutex::new(VecDeque::new()),
    };
    if APP.set(app).is_err() {
        bail!("viewer already running in this process");
    }
    let app = APP.get().unwrap();

    let hwnd = create_window(target, &opts)?;
    app.hwnd.store(hwnd as usize, Ordering::SeqCst);
    let bar = Bar::create(hwnd)?;
    app.top.store(bar.docked_height(), Ordering::SeqCst);
    fit_window(hwnd, w, h, bar.docked_height());

    let prefs = Prefs {
        quality: opts.quality,
        downscale: opts.downscale.clamp(1, 4),
        monitor: opts.monitor,
        audio: opts.audio,
        privacy: opts.privacy,
        clipboard: opts.clipboard,
    };
    if opts.clipboard && conn.flags & F_CLIPBOARD == 0 {
        log!("host has clipboard sharing disabled");
    }
    let ui = Ui {
        hwnd,
        target: target.to_string(),
        psk: Arc::new(psk),
        prefs,
        host: String::new(),
        monitors: Vec::new(),
        flags: 0,
        view_only: opts.view_only,
        unavailable: [false; 8],
        pending: [false; 8],
        sound_local_failed: false,
        bar,
        toasts: Toasts::new(hwnd),
        overlay: Overlay::new(hwnd),
        floating: false,
        meter: core::RateMeter::new(Instant::now()),
        fps: 0.0,
        mbps: 0.0,
        generation: 0,
        reconnect: None,
        next_attempt: 0,
        last_notice: None,
        notice_waiting: false,
        notice_shown: None,
        closing: false,
        exit_error: None,
        opts,
    };
    let fullscreen = ui.opts.fullscreen;
    UI.with(|cell| *cell.borrow_mut() = Some(ui));
    with_ui(|ui| {
        ui.install(conn, false);
        ui.refresh_bar();
    });

    unsafe {
        DragAcceptFiles(hwnd, 1);
        ShowWindow(hwnd, SW_SHOW);
        SetTimer(hwnd, T_TICK, TICK_MS, None);
    }
    let hook = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(ll_keyboard), GetModuleHandleW(null()), 0) };
    if hook.is_null() {
        log!("warning: keyboard hook unavailable; system shortcuts stay local");
    } else {
        app.hook_active.store(true, Ordering::SeqCst);
    }
    if fullscreen {
        toggle_fullscreen(hwnd);
    }

    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if !hook.is_null() {
            UnhookWindowsHookEx(hook);
        }
    }
    let ui = UI.with(|cell| cell.borrow_mut().take());
    if let Some(s) = lock(&app.session).take() {
        s.shutdown();
    }
    // Pending reconnect results hold live connections: close them.
    lock(&app.events).clear();
    // Wipe the remote screen contents before exiting.
    lock(&app.fb).px = LockedBuf::new(0);
    match ui.and_then(|u| u.exit_error) {
        Some(e) => Err(e.into()),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------------------
// Session threads

fn writer_loop(s: &Session, mut w: RecordWriter<TcpStream>) {
    let mut buf = Vec::with_capacity(64);
    let mut last_ping: Option<Instant> = None;
    let r = (|| -> Result<()> {
        loop {
            if last_ping.is_none_or(|t| t.elapsed() >= PING_EVERY) {
                s.send(ClientMsg::Ping(s.ms()));
                last_ping = Some(Instant::now());
            }
            match s.out.next(Duration::from_millis(500)) {
                Next::Closed => return Ok(()),
                Next::Idle => {}
                Next::Msg(m) => {
                    buf.clear();
                    m.encode(&mut buf);
                    let r = w.send(&buf);
                    // Keystrokes, clipboard text and file data: do not leave plaintext around.
                    crate::util::wipe(&mut buf);
                    r?;
                }
            }
        }
    })();
    if let Err(e) = r {
        s.end(core::classify_link_error(&e), e.to_string());
    }
}

fn reader_loop(s: &Session, mut reader: RecordReader<TcpStream>) {
    let mut audio = AudioSink::default();
    let mut downloads = Downloads::default();
    let r = read_session(s, &mut reader, &mut audio, &mut downloads);
    if let Err((kind, e)) = r {
        s.end(kind, e.to_string());
    }
}

type Ending = (EndKind, Error);

fn read_session(
    s: &Session,
    reader: &mut RecordReader<TcpStream>,
    audio: &mut AudioSink,
    downloads: &mut Downloads,
) -> std::result::Result<(), Ending> {
    let app = APP.get().unwrap();
    let fatal = |e: Error| (EndKind::Fatal, e);
    let mut dec = Decoder::new().map_err(fatal)?;
    loop {
        let rec = reader.recv().map_err(|e| (core::classify_link_error(&e), e))?;
        if s.is_ended() {
            return Ok(());
        }
        s.rx_bytes.fetch_add(rec.len() as u64 + 20, Ordering::Relaxed);
        s.last_rx_ms.store(s.ms(), Ordering::Relaxed);
        let msg = ServerMsg::decode(rec).map_err(|e| fatal(format!("protocol error: {e}").into()))?;
        match msg {
            ServerMsg::Tiles(p) => {
                if apply_tiles(app, s, &mut dec, p).map_err(|e| fatal(format!("bad screen update: {e}").into()))? {
                    s.frames.fetch_add(1, Ordering::Relaxed);
                }
            }
            ServerMsg::Cursor(c) => {
                app.cursor.store(c as u8, Ordering::SeqCst);
                unsafe { PostMessageW(app.hwnd(), WM_APP_CURSOR, 0, 0) };
            }
            ServerMsg::Clipboard(t) => {
                if let Some(c) = lock(&s.clipboard).as_ref() {
                    c.set(t);
                }
            }
            ServerMsg::Pong(t) => {
                let now = s.ms();
                if t <= now {
                    s.rtt_ms.store(now - t, Ordering::Relaxed);
                }
            }
            ServerMsg::Notice(text) => {
                let text = toolbar::clean_text(&text, true, MAX_HOST_TEXT);
                log!("host: {}", text.replace('\n', " "));
                s.last_notice_ms.store(s.ms(), Ordering::SeqCst);
                app.post(Event::Notice { generation: s.generation, text });
            }
            ServerMsg::Audio { rate, channels, codec, data, .. } => audio.play(s, rate, channels, codec, data),
            ServerMsg::FileBegin { id, size, name } => downloads.begin(s, id, size, &name),
            ServerMsg::FileData { id, data } => downloads.data(s, id, data),
            ServerMsg::FileEnd { id, sha256 } => downloads.end(s, id, &sha256),
            ServerMsg::FileResult { id, ok, message } => file_result(s, id, ok, message),
            ServerMsg::State { key, value } => app.post(Event::State { generation: s.generation, key, value }),
            ServerMsg::Ping | ServerMsg::Hello { .. } => {}
        }
    }
}

/// Applies one tiles message of session `s`; returns true when it completed a frame.
fn apply_tiles(app: &App, s: &Session, dec: &mut Decoder, p: &[u8]) -> Result<bool> {
    let hdr = codec::parse_header(p)?;
    let mut fb = lock(&app.fb);
    if (hdr.width, hdr.height) != (fb.w, fb.h) {
        if hdr.width * hdr.height > MAX_PIXELS {
            bail!("remote screen {}x{} is too large", hdr.width, hdr.height);
        }
        log!("remote screen is now {}x{}", hdr.width, hdr.height);
        fb.px = LockedBuf::new(hdr.width * hdr.height * 4);
        fb.w = hdr.width;
        fb.h = hdr.height;
        fb.dirty = Some(Rect { x: 0, y: 0, w: fb.w, h: fb.h });
        app.fb_w.store(fb.w as u32, Ordering::SeqCst);
        app.fb_h.store(fb.h as u32, Ordering::SeqCst);
    }
    let (fw, fh) = (fb.w, fb.h);
    if let Some(b) = dec.apply(p, fb.px.as_mut_slice(), fw, fh)? {
        fb.dirty = Some(match fb.dirty {
            None => b,
            Some(d) => {
                let (x0, y0) = (d.x.min(b.x), d.y.min(b.y));
                let (x1, y1) = ((d.x + d.w).max(b.x + b.w), (d.y + d.h).max(b.y + b.h));
                Rect { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }
            }
        });
    }
    drop(fb);
    if hdr.last {
        // Acked on this session's own queue: never on a newer session after a reconnect.
        s.send(ClientMsg::Ack(hdr.frame));
        unsafe { PostMessageW(app.hwnd(), WM_APP_FRAME, 0, 0) };
    }
    Ok(hdr.last)
}

/// Decodes and plays the host's audio while sound is on.
#[derive(Default)]
struct AudioSink {
    player: Option<(AudioPlayer, u32, u8)>,
    adpcm: Option<AdpcmDecoder>,
    pcm: Vec<i16>,
    failed: bool,
    warned: bool,
}

impl AudioSink {
    fn play(&mut self, s: &Session, rate: u32, channels: u8, codec: u8, data: &[u8]) {
        if !s.sound.load(Ordering::Relaxed) {
            self.player = None;
            return;
        }
        if self.failed || !core::audio_format_ok(rate, channels) {
            return;
        }
        let decoded = match codec {
            AUDIO_PCM16 => core::pcm16_le(data, &mut self.pcm),
            AUDIO_IMA_ADPCM => {
                self.pcm.clear();
                self.adpcm.get_or_insert_with(AdpcmDecoder::new).decode(data, channels, &mut self.pcm)
            }
            other => Err(format!("unknown audio codec {other}").into()),
        };
        if let Err(e) = decoded {
            if !std::mem::replace(&mut self.warned, true) {
                log!("cannot decode the host's audio: {e}");
            }
            return;
        }
        if self.player.as_ref().is_none_or(|(_, r, c)| (*r, *c) != (rate, channels)) {
            self.player = None;
            match AudioPlayer::new(rate, channels) {
                Ok(p) => self.player = Some((p, rate, channels)),
                Err(e) => {
                    self.failed = true;
                    APP.get().unwrap().post(Event::SoundFailed { generation: s.generation, reason: e.to_string() });
                    return;
                }
            }
        }
        if let Some((p, ..)) = self.player.as_mut() {
            p.push(&self.pcm);
        }
    }
}

/// Files the host sends after `FilePull`. Partial files are deleted when dropped.
#[derive(Default)]
struct Downloads {
    /// Transfers in progress and the `Pull` request each was accepted for.
    active: HashMap<u32, (files::Incoming, u32)>,
}

impl Downloads {
    fn begin(&mut self, s: &Session, id: u32, size: u64, name: &str) {
        if !s.files_allowed() || self.active.contains_key(&id) || self.active.len() >= MAX_DOWNLOADS {
            log!("ignored a file from the host: not allowed, or too many transfers at once");
            return;
        }
        let Some(request) = lock(&s.pull).begin(s.ms()) else {
            log!("ignored a file the host sent without being asked");
            return;
        };
        // Saved and shown under a name without bidi tricks (`a\u{202e}fdp.exe`).
        let name = toolbar::clean_text(name, false, MAX_FILE_NAME);
        match files::transfer_dir().and_then(|dir| files::Incoming::begin(&dir, id, size, &name)) {
            Ok(inc) => {
                self.active.insert(id, (inc, request));
                self.progress(s);
            }
            Err(e) => s.toast(Tone::Error, trf(Txt::ReceiveFailed, &[&name]), e.to_string(), None),
        }
    }

    fn data(&mut self, s: &Session, id: u32, data: &[u8]) {
        let Some((inc, request)) = self.active.get_mut(&id) else { return };
        lock(&s.pull).progress(*request, s.ms());
        if let Err(e) = inc.write(data) {
            let name = inc.name.clone();
            self.active.remove(&id);
            s.toast(Tone::Error, trf(Txt::ReceiveFailed, &[&name]), e.to_string(), None);
        }
        self.progress(s);
    }

    fn end(&mut self, s: &Session, id: u32, sha256: &[u8; 32]) {
        let Some((inc, request)) = self.active.remove(&id) else { return };
        lock(&s.pull).progress(request, s.ms());
        let name = inc.name.clone();
        match inc.finish(sha256) {
            Ok(path) => {
                log!("received {}", path.display());
                let folder = path.parent().map(Path::to_path_buf);
                s.toast(
                    Tone::Success,
                    trf(Txt::Received, &[&name]),
                    trf(Txt::SavedTo, &[&path.display()]),
                    folder.map(ToastAction::OpenFolder),
                );
            }
            Err(e) => s.toast(Tone::Error, trf(Txt::ReceiveFailed, &[&name]), e.to_string(), None),
        }
        self.progress(s);
    }

    /// Publishes the progress of one active download for the bar.
    fn progress(&self, s: &Session) {
        let p = self.active.values().next().map(|(i, _)| Progress { name: i.name.clone(), done: i.received(), total: i.size });
        lock(&s.xfer).down = p;
    }
}

fn file_result(s: &Session, id: u32, ok: bool, message: String) {
    let Some(name) = lock(&s.xfer).sent.remove(&id) else {
        log!("file result for an unknown transfer {id}");
        return;
    };
    let message = toolbar::clean_text(&message, false, MAX_HOST_TEXT);
    if ok {
        log!("sent {name}");
        s.toast(Tone::Success, trf(Txt::Sent, &[&name]), trf(Txt::SavedOnHost, &[&message]), None);
    } else {
        log!("host rejected {name}: {message}");
        s.toast(Tone::Error, trf(Txt::SendFailed, &[&name]), message, None);
    }
}

/// Queues files for upload, starting the uploader thread if needed.
fn queue_upload(s: &Arc<Session>, paths: Vec<PathBuf>) {
    let mut x = lock(&s.xfer);
    x.batch_total += paths.len();
    x.queue.extend(paths);
    if !x.uploading {
        x.uploading = true;
        let s = s.clone();
        let spawned = std::thread::Builder::new().name("upload".into()).spawn(move || uploader(&s));
        if spawned.is_err() {
            x.uploading = false;
            x.queue.clear();
        }
    }
}

fn uploader(s: &Session) {
    loop {
        let (path, id) = {
            let mut x = lock(&s.xfer);
            let Some(path) = x.queue.pop_front() else {
                x.uploading = false;
                x.up = None;
                x.batch_done = 0;
                x.batch_total = 0;
                return;
            };
            x.next_id = x.next_id.wrapping_add(1).max(1);
            (path, x.next_id)
        };
        let shown = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.display().to_string());
        match send_file(s, &path, id) {
            Ok(true) => {}
            Ok(false) => {
                let mut x = lock(&s.xfer);
                x.queue.clear();
                x.uploading = false;
                x.up = None;
                drop(x);
                s.toast(Tone::Warning, trf(Txt::SendFailed, &[&shown]), tr(Txt::Interrupted).to_string(), None);
                return;
            }
            Err(e) => s.toast(Tone::Error, trf(Txt::SendFailed, &[&shown]), e.to_string(), None),
        }
        lock(&s.xfer).batch_done += 1;
    }
}

/// Sends one file in bulk messages. Ok(false): the session ended meanwhile.
fn send_file(s: &Session, path: &Path, id: u32) -> Result<bool> {
    let mut f = files::Outgoing::open(path, id)?;
    let (name, size) = (f.name.clone(), f.size);
    lock(&s.xfer).up = Some(Progress { name: name.clone(), done: 0, total: size });
    if !s.out.send_bulk(ClientMsg::FileBegin { id, size, name: name.clone() }) {
        return Ok(false);
    }
    // Registered before the data goes out, so a fast FileResult finds it.
    {
        let mut x = lock(&s.xfer);
        if x.sent.len() >= 1024 {
            x.sent.clear();
        }
        x.sent.insert(id, name);
    }
    let mut buf = Vec::new();
    let r = (|| -> Result<bool> {
        while f.next_chunk(&mut buf)? {
            for part in buf.chunks(core::FILE_MSG_CHUNK) {
                if !s.out.send_bulk(ClientMsg::FileData { id, data: part.to_vec() }) {
                    return Ok(false);
                }
            }
            if let Some(p) = lock(&s.xfer).up.as_mut() {
                p.done = f.sent();
            }
        }
        Ok(true)
    })();
    crate::util::wipe(&mut buf);
    match r {
        Ok(true) => Ok(s.out.send_bulk(ClientMsg::FileEnd { id, sha256: f.finish() })),
        Ok(false) => Ok(false),
        Err(e) => {
            // Make the host discard what it has (the checksum cannot match), quietly.
            lock(&s.xfer).sent.remove(&id);
            s.out.send_bulk(ClientMsg::FileEnd { id, sha256: [0; 32] });
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------------------
// UI state and events

impl Ui {
    /// Makes `conn` the live session and starts its threads.
    fn install(&mut self, conn: Connection, reconnected: bool) {
        let Connection { host_name, monitors, monitor, stream, reader, writer, flags, .. } = conn;
        self.generation += 1;
        let view_only = self.opts.view_only || flags & F_VIEW_ONLY != 0;
        let session = Arc::new(Session {
            generation: self.generation,
            out: OutQueue::default(),
            sock: stream,
            flags,
            view_only,
            start: Instant::now(),
            reconnected,
            ended: AtomicBool::new(false),
            frames: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            last_rx_ms: AtomicU64::new(0),
            rtt_ms: AtomicU64::new(UNSET),
            last_notice_ms: AtomicU64::new(UNSET),
            sound: AtomicBool::new(self.prefs.audio && flags & F_AUDIO != 0),
            pull: Mutex::new(Pull::default()),
            clipboard: Mutex::new(None),
            xfer: Mutex::new(Transfers::default()),
        });
        // Shown in the title, the bar, toasts and message boxes: no bidi tricks, bounded.
        let host_name = toolbar::clean_text(&host_name, false, MAX_HOST_NAME);
        self.host = if host_name.is_empty() { self.target.clone() } else { host_name };
        self.monitors = monitors;
        self.prefs.monitor = monitor;
        self.flags = flags;
        self.view_only = view_only;
        self.unavailable = [false; 8];
        self.pending = [false; 8];
        self.sound_local_failed = false;
        self.last_notice = None;
        self.notice_waiting = false;
        self.meter = core::RateMeter::new(Instant::now());
        (self.fps, self.mbps) = (0.0, 0.0);
        if self.prefs.clipboard && flags & F_CLIPBOARD != 0 {
            start_clipboard(&session);
        }
        let s = session.clone();
        let w = std::thread::Builder::new().name("send".into()).spawn(move || writer_loop(&s, writer));
        let s = session.clone();
        let r = std::thread::Builder::new().name("receive".into()).spawn(move || reader_loop(&s, reader));
        if w.is_err() || r.is_err() {
            session.end(EndKind::Network, "cannot start the session threads".into());
        }
        *lock(&APP.get().unwrap().session) = Some(session);
        let title = wide(&if self.host == self.target {
            format!("{} - safe-rdp", self.host)
        } else {
            format!("{} ({}) - safe-rdp", self.host, self.target)
        });
        unsafe { SetWindowTextW(self.hwnd, title.as_ptr()) };
    }

    /// Stops the live session, if any.
    fn drop_session(&mut self) {
        let app = APP.get().unwrap();
        if let Some(s) = lock(&app.session).take() {
            s.shutdown();
        }
        // `routes` stays: it follows keys held down here, whatever the session.
        app.mods.store(0, Ordering::SeqCst);
        lock(&app.swallowed).clear();
    }

    fn hello_options(&self) -> ViewerOptions {
        ViewerOptions {
            fullscreen: false,
            clipboard: self.prefs.clipboard,
            view_only: self.opts.view_only,
            allow_capture: self.opts.allow_capture,
            downscale: self.prefs.downscale,
            quality: self.prefs.quality,
            monitor: self.prefs.monitor,
            audio: self.prefs.audio,
            privacy: self.prefs.privacy,
        }
    }

    fn handle(&mut self, ev: Event) -> After {
        if self.closing {
            return After::Nothing;
        }
        match ev {
            Event::Ended { generation, kind, reason, lifetime, since_notice } => {
                self.on_ended(generation, kind, reason, lifetime, since_notice)
            }
            Event::Attempt { id, result } => self.on_attempt(id, result),
            Event::Toast { generation, tone, title, text, action } => {
                if generation == self.generation {
                    self.toasts.show(tone, &title, &text, action);
                }
                After::Nothing
            }
            Event::Notice { generation, text } => {
                if generation == self.generation {
                    self.last_notice = Some(text);
                    self.notice_waiting = true;
                    self.show_notice();
                }
                After::Nothing
            }
            Event::State { generation, key, value } => {
                if generation == self.generation {
                    self.on_state(key, value);
                }
                After::Nothing
            }
            Event::SoundFailed { generation, reason } => {
                if generation == self.generation {
                    log!("sound playback unavailable: {reason}");
                    self.sound_local_failed = true;
                    self.prefs.audio = false;
                    if let Some(s) = APP.get().unwrap().session() {
                        s.sound.store(false, Ordering::Relaxed);
                        s.send(ClientMsg::Set { key: SET_AUDIO, value: 0 });
                    }
                    self.toasts.show(Tone::Warning, tr(Txt::SoundUnavailable), &reason, None);
                }
                After::Nothing
            }
        }
    }

    /// Shows the latest message from the host, at most one toast per `NOTICE_GAP`; one that
    /// arrives sooner waits for `tick` (and is replaced by any later one).
    fn show_notice(&mut self) {
        if !self.notice_waiting || self.notice_shown.is_some_and(|t| t.elapsed() < NOTICE_GAP) {
            return;
        }
        self.notice_waiting = false;
        if let Some(text) = &self.last_notice {
            self.toasts.show(Tone::Info, tr(Txt::HostMessage), text, None);
            self.notice_shown = Some(Instant::now());
        }
    }

    fn on_ended(&mut self, generation: u64, kind: EndKind, reason: String, lifetime: Duration, since_notice: Option<Duration>) -> After {
        if generation != self.generation || self.reconnect.is_some() {
            return After::Nothing;
        }
        let reconnected = APP.get().unwrap().session().is_some_and(|s| s.reconnected);
        self.drop_session();
        log!("connection to {} lost: {reason}", self.host);
        let reason = reason_text(kind, &reason);
        if !core::should_reconnect(kind, lifetime, reconnected, since_notice) {
            let message = match (kind, &self.last_notice) {
                (EndKind::Closed, Some(n)) if since_notice.is_some_and(|d| d < core::NOTICE_GRACE) => {
                    trf(Txt::SessionEnded, &[&self.host, n])
                }
                (EndKind::Closed, _) if reconnected => trf(Txt::KickedAgain, &[&self.host]),
                _ => trf(Txt::SessionEnded, &[&self.host, &reason]),
            };
            return After::Quit(Some(message));
        }
        dim_framebuffer();
        let now = Instant::now();
        let delay = core::reconnect_delay(0);
        self.reconnect =
            Some(Reconnect { since: now, attempt: 0, due: Some(now + delay), in_flight: None, cause: reason, last_error: None });
        unsafe { SetTimer(self.hwnd, T_RECONNECT, delay.as_millis() as u32, None) };
        self.bar.set_keep_visible(true);
        self.refresh_overlay();
        self.refresh_bar();
        After::Nothing
    }

    fn launch_attempt(&mut self) {
        unsafe { KillTimer(self.hwnd, T_RECONNECT) };
        let (target, psk, opts) = (self.target.clone(), self.psk.clone(), self.hello_options());
        let id = self.next_attempt + 1;
        let Some(rc) = self.reconnect.as_mut() else { return };
        if rc.in_flight.is_some() {
            return;
        }
        self.next_attempt = id;
        rc.in_flight = Some(id);
        rc.due = None;
        let spawned = std::thread::Builder::new().name("reconnect".into()).spawn(move || {
            let result = core::connect(&target, &opts, &psk);
            APP.get().unwrap().post(Event::Attempt { id, result });
        });
        if spawned.is_err() {
            rc.in_flight = None;
            rc.due = Some(Instant::now() + Duration::from_secs(1));
            unsafe { SetTimer(self.hwnd, T_RECONNECT, 1000, None) };
        }
        self.refresh_overlay();
    }

    fn on_attempt(&mut self, id: u64, result: Result<Connection>) -> After {
        let Some(rc) = self.reconnect.as_mut() else { return After::Nothing };
        if rc.in_flight != Some(id) {
            return After::Nothing;
        }
        rc.in_flight = None;
        match result {
            Ok(conn) => {
                self.reconnect = None;
                self.install(conn, true);
                self.overlay.hide();
                self.bar.set_keep_visible(false);
                self.toasts.show(Tone::Success, &trf(Txt::Reconnected, &[&self.host]), "", None);
                self.refresh_bar();
                After::Nothing
            }
            Err(e) => {
                log!("reconnect failed: {e}");
                rc.attempt += 1;
                rc.last_error = Some(short_error(&e.to_string()));
                if !core::retryable(&e) || rc.since.elapsed() >= core::RECONNECT_FOR {
                    return After::Quit(Some(trf(Txt::GaveUp, &[&self.host, &e])));
                }
                let delay = core::reconnect_delay(rc.attempt);
                rc.due = Some(Instant::now() + delay);
                unsafe { SetTimer(self.hwnd, T_RECONNECT, delay.as_millis() as u32, None) };
                self.refresh_overlay();
                After::Nothing
            }
        }
    }

    fn refresh_overlay(&mut self) {
        let Some(rc) = &self.reconnect else { return };
        let cause = match &rc.last_error {
            Some(e) => trf(Txt::AttemptFailed, &[&rc.attempt, e]),
            None => trf(Txt::LostBecause, &[&rc.cause]),
        };
        let next = match rc.due {
            Some(due) => trf(Txt::NextAttempt, &[&due.saturating_duration_since(Instant::now()).as_secs_f64().ceil()]),
            None => tr(Txt::Trying).to_string(),
        };
        let text = format!(
            "{cause}
{next}"
        );
        self.overlay.show(&trf(Txt::Reconnecting, &[&self.host]), &text);
    }

    fn on_state(&mut self, key: u8, value: u32) {
        let k = key as usize;
        if k >= self.unavailable.len() {
            return;
        }
        let requested = std::mem::replace(&mut self.pending[k], false);
        if value == STATE_UNAVAILABLE {
            self.unavailable[k] = true;
            let label = match key {
                SET_QUALITY => tr(Txt::Quality),
                SET_DOWNSCALE => tr(Txt::Scale),
                SET_MONITOR => tr(Txt::Monitor),
                SET_AUDIO => tr(Txt::Sound),
                SET_PRIVACY => tr(Txt::Privacy),
                _ => return,
            };
            match key {
                SET_AUDIO => self.set_sound(false, false),
                SET_PRIVACY => self.prefs.privacy = false,
                _ => {}
            }
            if requested {
                self.toasts.show(Tone::Warning, &trf(Txt::SettingRefused, &[&label]), "", None);
            }
        } else {
            self.unavailable[k] = false;
            match key {
                SET_QUALITY if value <= QUALITY_LOW => self.prefs.quality = value as u8,
                SET_DOWNSCALE if (1..=4).contains(&value) => self.prefs.downscale = value as u8,
                SET_MONITOR if value == MONITOR_ALL as u32 || (value as usize) < self.monitors.len() => self.prefs.monitor = value as u8,
                SET_AUDIO | SET_PRIVACY => {
                    let user_on = if key == SET_AUDIO { self.prefs.audio } else { self.prefs.privacy };
                    let (on, refuse) = feature_from_host(user_on, value);
                    if key == SET_AUDIO {
                        self.set_sound(on, false);
                    } else {
                        self.prefs.privacy = on;
                    }
                    if refuse && let Some(s) = APP.get().unwrap().session() {
                        s.send(ClientMsg::Set { key, value: 0 });
                    }
                }
                _ => {}
            }
        }
        self.refresh_bar();
    }

    /// Changes a host setting (optimistically; `ServerMsg::State` confirms or corrects it).
    fn request(&mut self, key: u8, value: u32) {
        if let Some(s) = APP.get().unwrap().session() {
            s.send(ClientMsg::Set { key, value });
            self.pending[key as usize] = true;
        }
    }

    fn set_sound(&mut self, on: bool, tell_host: bool) {
        self.prefs.audio = on;
        if let Some(s) = APP.get().unwrap().session() {
            s.sound.store(on && s.flags & F_AUDIO != 0, Ordering::Relaxed);
        }
        if tell_host {
            self.request(SET_AUDIO, on as u32);
        }
    }

    fn on_command(&mut self, cmd: u16) -> After {
        let session = APP.get().unwrap().session();
        let needs_session = !matches!(cmd, toolbar::CMD_FULLSCREEN | toolbar::CMD_DISCONNECT);
        if needs_session && session.is_none() {
            self.toasts.show(Tone::Warning, tr(Txt::NotConnected), "", None);
            return After::Nothing;
        }
        match cmd {
            toolbar::CMD_FULLSCREEN => return After::ToggleFullscreen,
            toolbar::CMD_DISCONNECT => return After::Quit(None),
            toolbar::CMD_SAS => {
                if let Some(s) = session.filter(|s| s.flags & F_SAS != 0 && !s.view_only) {
                    s.send(ClientMsg::Sas);
                }
            }
            toolbar::CMD_CLIPBOARD => {
                self.prefs.clipboard = !self.prefs.clipboard;
                if let Some(s) = session {
                    if self.prefs.clipboard && s.flags & F_CLIPBOARD != 0 {
                        start_clipboard(&s);
                    } else {
                        lock(&s.clipboard).take();
                    }
                }
            }
            toolbar::CMD_SEND_FILES => return After::ChooseFiles,
            toolbar::CMD_GET_FILES => {
                if let Some(s) = session.filter(|s| s.files_allowed()) {
                    lock(&s.pull).request(s.ms());
                    s.send(ClientMsg::FilePull);
                    self.toasts.show(Tone::Info, tr(Txt::RequestedFiles), tr(Txt::RequestedFilesHint), None);
                }
            }
            toolbar::CMD_SOUND => {
                let on = !self.prefs.audio;
                self.set_sound(on, true);
            }
            toolbar::CMD_PRIVACY => {
                self.prefs.privacy = !self.prefs.privacy;
                self.request(SET_PRIVACY, self.prefs.privacy as u32);
            }
            c if (toolbar::CMD_QUALITY..=toolbar::CMD_QUALITY + QUALITY_LOW as u16).contains(&c) => {
                self.prefs.quality = (c - toolbar::CMD_QUALITY) as u8;
                self.request(SET_QUALITY, self.prefs.quality as u32);
            }
            c if (toolbar::CMD_SCALE + 1..=toolbar::CMD_SCALE + 4).contains(&c) => {
                self.prefs.downscale = (c - toolbar::CMD_SCALE) as u8;
                self.request(SET_DOWNSCALE, self.prefs.downscale as u32);
            }
            c if (toolbar::CMD_MONITOR..=toolbar::CMD_MONITOR + MONITOR_ALL as u16).contains(&c) => {
                let m = (c - toolbar::CMD_MONITOR) as u8;
                if m == MONITOR_ALL || (m as usize) < self.monitors.len() {
                    self.prefs.monitor = m;
                    self.request(SET_MONITOR, m as u32);
                }
            }
            _ => {}
        }
        self.refresh_bar();
        After::Nothing
    }

    /// Queues files picked in the dialog or dropped on the window.
    fn send_files(&mut self, paths: Vec<PathBuf>) {
        let Some(s) = APP.get().unwrap().session() else {
            self.toasts.show(Tone::Warning, tr(Txt::NotConnected), "", None);
            return;
        };
        if !s.files_allowed() {
            self.toasts.show(Tone::Warning, &trf(Txt::SettingRefused, &[&tr(Txt::SendFiles)]), "", None);
            return;
        }
        let (dirs, files): (Vec<PathBuf>, Vec<PathBuf>) = paths.into_iter().take(MAX_BATCH).partition(|p| p.is_dir());
        if !dirs.is_empty() {
            let names: Vec<String> = dirs
                .iter()
                .take(3)
                .map(|d| d.file_name().map_or_else(|| d.display().to_string(), |n| n.to_string_lossy().into_owned()))
                .collect();
            self.toasts.show(Tone::Warning, tr(Txt::FoldersNotSupported), &names.join(", "), None);
        }
        if !files.is_empty() {
            log!("sending {} file(s)", files.len());
            queue_upload(&s, files);
        }
        self.refresh_bar();
    }

    /// Periodic work: statistics, the reconnect countdown, the bar.
    fn tick(&mut self) {
        if let Some(s) = APP.get().unwrap().session() {
            let (frames, bytes) = (s.frames.load(Ordering::Relaxed), s.rx_bytes.load(Ordering::Relaxed));
            if let Some((fps, mbps)) = self.meter.update(Instant::now(), frames, bytes) {
                (self.fps, self.mbps) = (fps, mbps);
            }
        }
        if self.reconnect.is_some() {
            self.refresh_overlay();
        }
        self.show_notice();
        self.refresh_bar();
    }

    fn feature(&self, flag: u32, key: Option<u8>, on: bool) -> Feature {
        if self.flags & flag == 0 {
            Feature::Hidden
        } else if key.is_some_and(|k| self.unavailable[k as usize]) {
            Feature::Unavailable
        } else if on {
            Feature::On
        } else {
            Feature::Off
        }
    }

    fn setting(&self, key: u8) -> Feature {
        if self.unavailable[key as usize] { Feature::Unavailable } else { Feature::Off }
    }

    fn refresh_bar(&mut self) {
        let session = APP.get().unwrap().session();
        let mut m = BarModel {
            host: self.host.clone(),
            connected: session.is_some(),
            monitors: self.monitors.clone(),
            monitor: self.prefs.monitor,
            monitor_menu: if self.monitors.len() >= 2 { self.setting(SET_MONITOR) } else { Feature::Hidden },
            quality: self.prefs.quality,
            quality_menu: self.setting(SET_QUALITY),
            downscale: self.prefs.downscale,
            scale_menu: self.setting(SET_DOWNSCALE),
            sas: if self.view_only { Feature::Hidden } else { self.feature(F_SAS, None, false) },
            clipboard: self.feature(F_CLIPBOARD, None, self.prefs.clipboard),
            send_files: self.feature(F_FILES, None, false),
            get_files: self.feature(F_FILES, None, false),
            sound: if self.flags & F_AUDIO != 0 && self.sound_local_failed {
                Feature::NoLocal
            } else {
                self.feature(F_AUDIO, Some(SET_AUDIO), self.prefs.audio)
            },
            privacy: self.feature(F_PRIVACY, Some(SET_PRIVACY), self.prefs.privacy),
            fullscreen: self.floating,
            ..BarModel::default()
        };
        match &session {
            None => {
                m.status = tr(Txt::ReconnectingShort).to_string();
                m.status_short = "…".to_string();
                m.warn = true;
            }
            Some(s) => {
                let x = lock(&s.xfer);
                if let Some(p) = &x.up {
                    let (pct, n) = (core::percent(p.done, p.total), (x.batch_done + 1).min(x.batch_total.max(1)));
                    m.status = trf(Txt::Uploading, &[&p.name, &pct, &n, &x.batch_total.max(1)]);
                    m.status_short = format!("↑ {pct}%");
                    m.progress = Some(pct as f32 / 100.0);
                } else if let Some(p) = &x.down {
                    let pct = core::percent(p.done, p.total);
                    m.status = trf(Txt::Downloading, &[&p.name, &pct]);
                    m.status_short = format!("↓ {pct}%");
                    m.progress = Some(pct as f32 / 100.0);
                } else {
                    let quiet = s.ms().saturating_sub(s.last_rx_ms.load(Ordering::Relaxed));
                    if quiet >= QUIET_WARN_MS {
                        m.status = trf(Txt::NotResponding, &[&(quiet / 1000)]);
                        m.status_short = format!("{} s", quiet / 1000);
                        m.warn = true;
                    } else {
                        let rtt = s.rtt_ms.load(Ordering::Relaxed);
                        let rtt = (rtt != UNSET).then_some(rtt);
                        m.status = core::stats_text(rtt, self.fps, self.mbps);
                        m.status_short = rtt.map_or_else(|| "– ms".to_string(), |r| format!("{} ms", r.min(9999)));
                    }
                }
            }
        }
        self.bar.set_model(&m);
    }

    /// Brings the chrome in line with the window: docked or floating bar, positions.
    fn sync_chrome(&mut self) {
        let app = APP.get().unwrap();
        let floating = app.is_fullscreen();
        if floating != self.floating {
            self.floating = floating;
            self.bar.set_floating(floating);
            self.refresh_bar();
            if floating {
                self.bar.reveal(3000);
            }
            if self.reconnect.is_some() {
                self.bar.set_keep_visible(true);
            }
        }
        self.bar.relayout();
        let top = self.bar.docked_height();
        if app.top.swap(top, Ordering::SeqCst) != top {
            unsafe { InvalidateRect(self.hwnd, null(), 0) };
        }
        self.toasts.relayout();
        self.overlay.relayout();
    }
}

/// What the host's `State { SET_AUDIO | SET_PRIVACY, value }` does while the user has the
/// feature `user_on`: it stays the user's choice (sound plays here only if asked for), so
/// the host may confirm or end it but never start it. Returns whether the feature is on and
/// whether to tell the host to turn it off again.
fn feature_from_host(user_on: bool, value: u32) -> (bool, bool) {
    let host_on = value != 0;
    (user_on && host_on, host_on && !user_on)
}

/// A connect error without the "cannot connect to <address>: " prefix the overlay already implies.
fn short_error(e: &str) -> String {
    match e.strip_prefix("cannot connect to ").and_then(|r| r.split_once(": ")) {
        Some((_, why)) => why.to_string(),
        None => e.to_string(),
    }
}

/// User-facing wording for why a session ended.
fn reason_text(kind: EndKind, raw: &str) -> String {
    match kind {
        EndKind::Closed => tr(Txt::HostClosed).to_string(),
        EndKind::Network if raw == "connection timed out" => tr(Txt::NoAnswer).to_string(),
        _ => raw.to_string(),
    }
}

fn start_clipboard(s: &Arc<Session>) {
    let mut slot = lock(&s.clipboard);
    if slot.is_some() {
        return;
    }
    let weak = Arc::downgrade(s);
    match Clipboard::spawn(move |t| {
        if let Some(s) = weak.upgrade() {
            s.send(ClientMsg::Clipboard(t));
        }
    }) {
        Ok(c) => *slot = Some(c),
        Err(e) => log!("clipboard sharing unavailable: {e}"),
    }
}

/// Darkens the last frame (shown while reconnecting).
fn dim_framebuffer() {
    let app = APP.get().unwrap();
    dim(lock(&app.fb).px.as_mut_slice());
    unsafe { InvalidateRect(app.hwnd(), null(), 0) };
}

fn dim(px: &mut [u8]) {
    for p in px.chunks_exact_mut(4) {
        for c in &mut p[..3] {
            *c = (*c as u16 * 3 / 8) as u8;
        }
    }
}

/// Handles a batch of queued events; the rest get another `WM_APP_EVENT`, so the message
/// loop (and with it the keyboard hook) keeps running in between.
fn dispatch_events(hwnd: HWND) {
    let app = APP.get().unwrap();
    for _ in 0..EVENTS_PER_WAKE {
        let Some(ev) = lock(&app.events).pop_front() else { return };
        let after = with_ui(|ui| ui.handle(ev)).unwrap_or(After::Nothing);
        follow_up(hwnd, after);
    }
    if !lock(&app.events).is_empty() {
        unsafe { PostMessageW(hwnd, WM_APP_EVENT, 0, 0) };
    }
}

fn follow_up(hwnd: HWND, after: After) {
    match after {
        After::Nothing => {}
        After::ToggleFullscreen => toggle_fullscreen(hwnd),
        After::ChooseFiles => {
            let host = with_ui(|ui| ui.host.clone()).unwrap_or_default();
            match choose_files(hwnd, &host) {
                Ok(paths) if !paths.is_empty() => {
                    with_ui(|ui| ui.send_files(paths));
                }
                Ok(_) => {}
                Err(e) => {
                    with_ui(|ui| ui.toasts.show(Tone::Warning, &e.to_string(), "", None));
                }
            }
        }
        After::Quit(message) => quit(hwnd, message),
    }
}

/// Ends the viewer: stops the session, shows `message` (if any) and closes the window.
fn quit(hwnd: HWND, message: Option<String>) {
    let first = with_ui(|ui| {
        if ui.closing {
            return false;
        }
        ui.closing = true;
        ui.exit_error = message.clone();
        ui.reconnect = None;
        ui.drop_session();
        unsafe {
            KillTimer(hwnd, T_TICK);
            KillTimer(hwnd, T_RECONNECT);
        }
        true
    })
    .unwrap_or(true);
    if !first {
        return;
    }
    if let Some(m) = &message {
        log!("{}", m.replace("\n\n", " "));
        let (text, title) = (wide(m), wide("safe-rdp"));
        unsafe { MessageBoxW(hwnd, text.as_ptr(), title.as_ptr(), MB_ICONWARNING | MB_OK) };
    }
    unsafe { DestroyWindow(hwnd) };
}

// ---------------------------------------------------------------------------------------
// Files from the local side

/// Multi-select "Open" dialog. An empty list means cancelled.
fn choose_files(owner: HWND, host: &str) -> Result<Vec<PathBuf>> {
    let mut buf = vec![0u16; 1 << 16];
    let filter: Vec<u16> = format!("{}\0*.*\0\0", tr(Txt::AllFiles)).encode_utf16().collect();
    let title = wide(&trf(Txt::ChooseFiles, &[&host]));
    unsafe {
        let mut ofn: OPENFILENAMEW = std::mem::zeroed();
        ofn.lStructSize = size_of::<OPENFILENAMEW>() as u32;
        ofn.hwndOwner = owner;
        ofn.lpstrFilter = filter.as_ptr();
        ofn.nFilterIndex = 1;
        ofn.lpstrFile = buf.as_mut_ptr();
        ofn.nMaxFile = buf.len() as u32;
        ofn.lpstrTitle = title.as_ptr();
        ofn.Flags = OFN_ALLOWMULTISELECT | OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;
        if GetOpenFileNameW(&mut ofn) == 0 {
            return match CommDlgExtendedError() {
                0 => Ok(Vec::new()),
                FNERR_BUFFERTOOSMALL => Err(tr(Txt::TooManyFiles).into()),
                code => Err(format!("file dialog failed ({code:#x})").into()),
            };
        }
    }
    Ok(parse_multi_select(&buf))
}

/// Parses an `OFN_ALLOWMULTISELECT | OFN_EXPLORER` result: one full path, or a directory
/// followed by file names, each NUL-terminated, the list ending with an empty string.
fn parse_multi_select(buf: &[u16]) -> Vec<PathBuf> {
    let mut parts = buf.split(|&c| c == 0).take_while(|p| !p.is_empty()).map(OsString::from_wide);
    let Some(first) = parts.next() else { return Vec::new() };
    let rest: Vec<OsString> = parts.collect();
    if rest.is_empty() {
        vec![PathBuf::from(first)]
    } else {
        let dir = PathBuf::from(first);
        rest.into_iter().map(|n| dir.join(n)).collect()
    }
}

fn dropped_files(hdrop: HDROP) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    unsafe {
        let n = DragQueryFileW(hdrop, u32::MAX, null_mut(), 0);
        for i in 0..n.min(MAX_BATCH as u32) {
            let len = DragQueryFileW(hdrop, i, null_mut(), 0);
            if len == 0 {
                continue;
            }
            let mut b = vec![0u16; len as usize + 1];
            let got = DragQueryFileW(hdrop, i, b.as_mut_ptr(), b.len() as u32) as usize;
            paths.push(PathBuf::from(OsString::from_wide(&b[..got.min(len as usize)])));
        }
        DragFinish(hdrop);
    }
    paths
}

// ---------------------------------------------------------------------------------------
// Window

fn create_window(target: &str, opts: &ViewerOptions) -> Result<HWND> {
    unsafe {
        let hinst = GetModuleHandleW(null());
        let class = wide("SafeRdpViewer");
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinst,
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: GetStockObject(BLACK_BRUSH),
            lpszClassName: class.as_ptr(),
            ..std::mem::zeroed()
        };
        if RegisterClassExW(&wc) == 0 {
            return Err(Error::last_os("RegisterClassExW"));
        }
        let title = wide(&format!("safe-rdp - {target}"));
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            800,
            600,
            null_mut(),
            null_mut(),
            hinst,
            null(),
        );
        if hwnd.is_null() {
            return Err(Error::last_os("CreateWindowExW"));
        }
        if !opts.allow_capture && SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) == 0 {
            SetWindowDisplayAffinity(hwnd, WDA_MONITOR);
        }
        Ok(hwnd)
    }
}

fn dpi_of(hwnd: HWND) -> u32 {
    match unsafe { GetDpiForWindow(hwnd) } {
        0 => 96,
        d => d,
    }
}

/// Fits a `w`x`h` remote screen plus a `top` bar into the work area of the window's
/// monitor, keeping the aspect ratio, and centres the window.
fn fit_window(hwnd: HWND, w: usize, h: usize, top: i32) {
    unsafe {
        let mon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTOPRIMARY);
        let mut mi: MONITORINFO = std::mem::zeroed();
        mi.cbSize = size_of::<MONITORINFO>() as u32;
        GetMonitorInfoW(mon, &mut mi);
        let work = mi.rcWork;
        let style = GetWindowLongPtrW(hwnd, GWL_STYLE) as u32;
        let mut frame = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        AdjustWindowRectExForDpi(&mut frame, style, 0, 0, dpi_of(hwnd));
        let (fw, fh) = (frame.right - frame.left, frame.bottom - frame.top + top);
        let max_w = ((work.right - work.left) - fw).max(320) as f64;
        let max_h = ((work.bottom - work.top) - fh).max(240) as f64;
        let scale = (max_w / w.max(1) as f64).min(max_h / h.max(1) as f64).min(1.0);
        let (cw, ch) = ((w as f64 * scale) as i32 + fw, (h as f64 * scale) as i32 + fh);
        SetWindowPos(
            hwnd,
            null_mut(),
            work.left + ((work.right - work.left) - cw).max(0) / 2,
            work.top + ((work.bottom - work.top) - ch).max(0) / 2,
            cw,
            ch,
            SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }
}

/// Letterboxed destination rectangle of a `fw`x`fh` image inside a `cw`x`ch` area.
fn dest_rect(cw: i32, ch: i32, fw: i32, fh: i32) -> RECT {
    if cw <= 0 || ch <= 0 || fw <= 0 || fh <= 0 {
        return RECT { left: 0, top: 0, right: 0, bottom: 0 };
    }
    let (dw, dh) = if cw as i64 * fh as i64 <= ch as i64 * fw as i64 {
        (cw, (cw as i64 * fh as i64 / fw as i64) as i32)
    } else {
        ((ch as i64 * fw as i64 / fh as i64) as i32, ch)
    };
    let (x, y) = ((cw - dw) / 2, (ch - dh) / 2);
    RECT { left: x, top: y, right: x + dw, bottom: y + dh }
}

/// Where the remote image goes in the client area: below the docked bar, letterboxed.
fn image_rect(hwnd: HWND, fw: i32, fh: i32) -> RECT {
    let (cw, ch) = client_size(hwnd);
    let top = APP.get().unwrap().top.load(Ordering::SeqCst).clamp(0, ch.max(0));
    let mut d = dest_rect(cw, ch - top, fw, fh);
    d.top += top;
    d.bottom += top;
    d
}

/// Maps a client point to remote coordinates through destination rectangle `d`.
fn map_to_remote(d: &RECT, fw: i64, fh: i64, x: i32, y: i32) -> (u16, u16) {
    let (dw, dh) = ((d.right - d.left).max(1) as i64, (d.bottom - d.top).max(1) as i64);
    let rx = ((x - d.left) as i64 * fw / dw).clamp(0, (fw - 1).max(0));
    let ry = ((y - d.top) as i64 * fh / dh).clamp(0, (fh - 1).max(0));
    (rx.min(u16::MAX as i64) as u16, ry.min(u16::MAX as i64) as u16)
}

fn client_size(hwnd: HWND) -> (i32, i32) {
    let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    unsafe { GetClientRect(hwnd, &mut r) };
    (r.right - r.left, r.bottom - r.top)
}

fn paint(hwnd: HWND) {
    let app = APP.get().unwrap();
    unsafe {
        let mut ps: PAINTSTRUCT = std::mem::zeroed();
        let hdc = BeginPaint(hwnd, &mut ps);
        let (cw, ch) = client_size(hwnd);
        let top = app.top.load(Ordering::SeqCst).clamp(0, ch.max(0));
        let fb = lock(&app.fb);
        let (fw, fh) = (fb.w as i32, fb.h as i32);
        let d = image_rect(hwnd, fw, fh);
        let black = GetStockObject(BLACK_BRUSH);
        for r in [
            RECT { left: 0, top, right: cw, bottom: d.top },
            RECT { left: 0, top: d.bottom, right: cw, bottom: ch },
            RECT { left: 0, top: d.top, right: d.left, bottom: d.bottom },
            RECT { left: d.right, top: d.top, right: cw, bottom: d.bottom },
        ] {
            if r.right > r.left && r.bottom > r.top {
                FillRect(hdc, &r, black);
            }
        }
        if fb.px.len() == (fw as usize) * (fh as usize) * 4 && fw > 0 {
            let mut bmi: BITMAPINFO = std::mem::zeroed();
            bmi.bmiHeader = BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: fw,
                biHeight: -fh,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                ..std::mem::zeroed()
            };
            let bits = fb.px.as_slice().as_ptr().cast();
            let (dw, dh) = (d.right - d.left, d.bottom - d.top);
            if dw == fw && dh == fh {
                SetDIBitsToDevice(hdc, d.left, d.top, fw as u32, fh as u32, 0, 0, 0, fh as u32, bits, &bmi, DIB_RGB_COLORS);
            } else {
                SetStretchBltMode(hdc, HALFTONE);
                SetBrushOrgEx(hdc, 0, 0, null_mut());
                StretchDIBits(hdc, d.left, d.top, dw, dh, 0, 0, fw, fh, bits, &bmi, DIB_RGB_COLORS, SRCCOPY);
            }
        }
        drop(fb);
        EndPaint(hwnd, &ps);
    }
}

/// Invalidates the window region covering the remote pixels that changed.
fn invalidate_dirty(hwnd: HWND) {
    let app = APP.get().unwrap();
    let (dirty, fw, fh) = {
        let mut fb = lock(&app.fb);
        (fb.dirty.take(), fb.w as i64, fb.h as i64)
    };
    let Some(r) = dirty else { return };
    if fw <= 0 || fh <= 0 {
        return;
    }
    let d = image_rect(hwnd, fw as i32, fh as i32);
    let (dw, dh) = ((d.right - d.left) as i64, (d.bottom - d.top) as i64);
    if dw <= 0 || dh <= 0 {
        return;
    }
    // Two pixels of slack for the halftone filter.
    let wr = RECT {
        left: d.left + (r.x as i64 * dw / fw) as i32 - 2,
        top: d.top + (r.y as i64 * dh / fh) as i32 - 2,
        right: d.left + (((r.x + r.w) as i64 * dw + fw - 1) / fw) as i32 + 2,
        bottom: d.top + (((r.y + r.h) as i64 * dh + fh - 1) / fh) as i32 + 2,
    };
    unsafe { InvalidateRect(hwnd, &wr, 0) };
}

/// Maps a client-area point to remote screen coordinates.
fn to_remote(hwnd: HWND, x: i32, y: i32) -> (u16, u16) {
    let app = APP.get().unwrap();
    let (fw, fh) = (app.fb_w.load(Ordering::SeqCst) as i64, app.fb_h.load(Ordering::SeqCst) as i64);
    let d = image_rect(hwnd, fw as i32, fh as i32);
    map_to_remote(&d, fw, fh, x, y)
}

fn cursor_handle(c: u8) -> HCURSOR {
    let c = Cursor::from_u8(c);
    if c == Cursor::Hidden {
        return null_mut();
    }
    let id = CURSOR_IDS.iter().find(|(_, s)| *s == c).map(|(id, _)| *id).unwrap_or(IDC_ARROW);
    unsafe { LoadCursorW(null_mut(), id) }
}

fn cursor_inside(hwnd: HWND) -> bool {
    unsafe {
        let mut p = POINT { x: 0, y: 0 };
        GetCursorPos(&mut p);
        WindowFromPoint(p) == hwnd && {
            ScreenToClient(hwnd, &mut p);
            let (cw, ch) = client_size(hwnd);
            p.x >= 0 && p.y >= 0 && p.x < cw && p.y < ch
        }
    }
}

fn toggle_fullscreen(hwnd: HWND) {
    let app = APP.get().unwrap();
    {
        let mut fs = lock(&app.fullscreen);
        unsafe {
            if let Some(saved) = fs.take() {
                drop(fs);
                SetWindowLongPtrW(hwnd, GWL_STYLE, saved.style);
                SetWindowPlacement(hwnd, &saved.placement);
                SetWindowPos(hwnd, null_mut(), 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
            } else {
                let style = GetWindowLongPtrW(hwnd, GWL_STYLE);
                let mut placement: WINDOWPLACEMENT = std::mem::zeroed();
                placement.length = size_of::<WINDOWPLACEMENT>() as u32;
                GetWindowPlacement(hwnd, &mut placement);
                let mut mi: MONITORINFO = std::mem::zeroed();
                mi.cbSize = size_of::<MONITORINFO>() as u32;
                GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mut mi);
                let r = mi.rcMonitor;
                *fs = Some(Saved { style, placement });
                drop(fs);
                SetWindowLongPtrW(hwnd, GWL_STYLE, style & !(WS_OVERLAPPEDWINDOW as isize));
                SetWindowPos(hwnd, HWND_TOP, r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
            }
        }
    }
    unsafe { PostMessageW(hwnd, WM_APP_LAYOUT, 0, 0) };
}

// ---------------------------------------------------------------------------------------
// Input

fn release_all(app: &App) {
    app.mods.store(0, Ordering::SeqCst);
    lock(&app.swallowed).clear();
    lock(&app.routes).clear();
    if app.buttons.swap(0, Ordering::SeqCst) != 0 {
        unsafe { ReleaseCapture() };
    }
    if let Some(s) = app.input() {
        s.send(ClientMsg::ReleaseAll);
    }
}

/// Handles a physical key event while the viewer is in the foreground. Returns true if the
/// event was consumed (forwarded or used as a hotkey) and must not reach the local system.
fn on_key(app: &App, vk: u16, scan: u16, extended: bool, up: bool) -> bool {
    if app.local_keys.load(Ordering::SeqCst) {
        return false;
    }
    let bit = match vk {
        VK_CONTROL | VK_LCONTROL | VK_RCONTROL => MOD_CTRL,
        VK_MENU | VK_LMENU | VK_RMENU => MOD_ALT,
        VK_LWIN | VK_RWIN => MOD_WIN,
        _ => 0,
    };
    if bit != 0 {
        if up {
            app.mods.fetch_and(!bit, Ordering::SeqCst);
        } else {
            app.mods.fetch_or(bit, Ordering::SeqCst);
        }
    }
    let mods = app.mods.load(Ordering::SeqCst);
    let ctrl_alt = mods & (MOD_CTRL | MOD_ALT) == (MOD_CTRL | MOD_ALT);
    if up && lock(&app.swallowed).remove(&vk) {
        return true;
    }
    let session = app.session();
    if !up && ctrl_alt && (vk == VK_RETURN || vk == VK_END) {
        lock(&app.swallowed).insert(vk);
        if vk == VK_RETURN {
            unsafe { PostMessageW(app.hwnd(), WM_APP_FULLSCREEN, 0, 0) };
        } else if let Some(s) = session.as_ref().filter(|s| s.flags & F_SAS != 0 && !s.view_only) {
            s.send(ClientMsg::Sas);
        } else if let Some(s) = session.as_ref().filter(|s| !s.view_only) {
            s.toast(Tone::Info, tr(Txt::SasDisabled).to_string(), String::new(), None);
        }
        return true;
    }
    // Decided before the session check, so `routes` follows every press and release.
    let local = stays_local(app.is_fullscreen(), mods, vk, up, &mut lock(&app.routes));
    let Some(s) = session.filter(|s| !s.view_only) else { return false };
    if local {
        return false;
    }
    let mut flags = if up { KEY_UP } else { 0 };
    if extended {
        flags |= KEY_EXTENDED;
    }
    s.send(ClientMsg::Key { vk, scan, flags });
    true
}

/// Whether a key event goes to the local desktop instead of the host. In a window the
/// Windows key with everything pressed while it is held (Win+D, Win+E, ...) and Alt+Tab /
/// Alt+Esc / Ctrl+Esc stay local (like mstsc's default); in full screen everything goes to
/// the host. Auto-repeats and the release of a key follow its first press (`routes`); a
/// release whose press was not seen here (it went to another window or a menu) stays local.
fn stays_local(fullscreen: bool, mods: u8, vk: u16, up: bool, routes: &mut HashMap<u16, bool>) -> bool {
    if up {
        return routes.remove(&vk).unwrap_or(true);
    }
    if let Some(&local) = routes.get(&vk) {
        return local;
    }
    let local = !fullscreen
        && (matches!(vk, VK_LWIN | VK_RWIN)
            || mods & MOD_WIN != 0
            || (mods & MOD_ALT != 0 && matches!(vk, VK_TAB | VK_ESCAPE))
            || (mods & MOD_CTRL != 0 && vk == VK_ESCAPE));
    routes.insert(vk, local);
    local
}

unsafe extern "system" fn ll_keyboard(code: i32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        if code == HC_ACTION as i32 {
            if let Some(app) = APP.get() {
                let hwnd = app.hwnd();
                if !hwnd.is_null() && GetForegroundWindow() == hwnd {
                    let k = &*(lp as *const KBDLLHOOKSTRUCT);
                    let up = k.flags & LLKHF_UP != 0;
                    if on_key(app, k.vkCode as u16, k.scanCode as u16, k.flags & LLKHF_EXTENDED != 0, up) {
                        return 1;
                    }
                }
            }
        }
        CallNextHookEx(null_mut(), code, wp, lp)
    }
}

fn point(lp: LPARAM) -> (i32, i32) {
    ((lp & 0xffff) as i16 as i32, ((lp >> 16) & 0xffff) as i16 as i32)
}

fn mouse_button(app: &App, hwnd: HWND, lp: LPARAM, button: u8, down: bool) {
    let Some(s) = app.input() else { return };
    let (x, y) = point(lp);
    let (x, y) = to_remote(hwnd, x, y);
    s.send(ClientMsg::MouseMove { x, y });
    s.send(ClientMsg::MouseButton { button, down });
    let bit = 1u8 << button;
    unsafe {
        if down {
            if app.buttons.fetch_or(bit, Ordering::SeqCst) == 0 {
                SetCapture(hwnd);
            }
        } else if app.buttons.fetch_and(!bit, Ordering::SeqCst) & !bit == 0 {
            ReleaseCapture();
        }
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let Some(app) = APP.get() else { return unsafe { DefWindowProcW(hwnd, msg, wp, lp) } };
    unsafe {
        match msg {
            WM_PAINT => {
                paint(hwnd);
                0
            }
            WM_ERASEBKGND => 1,
            WM_APP_FRAME => {
                invalidate_dirty(hwnd);
                0
            }
            WM_SIZE => {
                InvalidateRect(hwnd, null(), 0);
                PostMessageW(hwnd, WM_APP_LAYOUT, 0, 0);
                0
            }
            WM_APP_LAYOUT => {
                with_ui(|ui| ui.sync_chrome());
                0
            }
            toolbar::WM_CHROME => {
                with_ui(|ui| ui.toasts.relayout());
                0
            }
            WM_APP_FULLSCREEN => {
                toggle_fullscreen(hwnd);
                0
            }
            WM_APP_EVENT => {
                dispatch_events(hwnd);
                0
            }
            WM_COMMAND => {
                let after = with_ui(|ui| ui.on_command((wp & 0xffff) as u16)).unwrap_or(After::Nothing);
                follow_up(hwnd, after);
                0
            }
            WM_TIMER => {
                match wp {
                    T_TICK => {
                        with_ui(|ui| ui.tick());
                        // In case a WM_APP_EVENT could not be posted (full message queue).
                        dispatch_events(hwnd);
                    }
                    T_RECONNECT => {
                        with_ui(|ui| ui.launch_attempt());
                    }
                    _ => {}
                }
                0
            }
            WM_DROPFILES => {
                let paths = dropped_files(wp as HDROP);
                if !paths.is_empty() {
                    with_ui(|ui| ui.send_files(paths));
                }
                0
            }
            WM_APP_CURSOR => {
                if cursor_inside(hwnd) {
                    SetCursor(cursor_handle(app.cursor.load(Ordering::SeqCst)));
                }
                0
            }
            // Only for the remote image itself; the chrome windows keep their arrow.
            WM_SETCURSOR if wp as HWND == hwnd && (lp & 0xffff) as u32 == HTCLIENT => {
                SetCursor(cursor_handle(app.cursor.load(Ordering::SeqCst)));
                1
            }
            WM_CLOSE => {
                quit(hwnd, None);
                0
            }
            WM_ACTIVATE => {
                if (wp & 0xffff) as u32 == WA_INACTIVE {
                    release_all(app);
                }
                0
            }
            WM_ENTERMENULOOP => {
                app.local_keys.store(true, Ordering::SeqCst);
                release_all(app);
                0
            }
            WM_EXITMENULOOP => {
                app.local_keys.store(false, Ordering::SeqCst);
                0
            }
            WM_MOUSEMOVE => {
                let (cx, cy) = point(lp);
                if cy <= 2 && app.is_fullscreen() {
                    with_ui(|ui| {
                        if ui.bar.in_reveal_zone(cx, cy) {
                            ui.bar.reveal(BAR_HOLD_MS);
                        }
                    });
                }
                if let Some(s) = app.input() {
                    let (x, y) = to_remote(hwnd, cx, cy);
                    let packed = (x as u32) << 16 | y as u32;
                    if app.last_move.swap(packed, Ordering::SeqCst) != packed {
                        s.send(ClientMsg::MouseMove { x, y });
                    }
                }
                0
            }
            WM_LBUTTONDOWN | WM_LBUTTONDBLCLK => {
                mouse_button(app, hwnd, lp, BTN_LEFT, true);
                0
            }
            WM_LBUTTONUP => {
                mouse_button(app, hwnd, lp, BTN_LEFT, false);
                0
            }
            WM_RBUTTONDOWN | WM_RBUTTONDBLCLK => {
                mouse_button(app, hwnd, lp, BTN_RIGHT, true);
                0
            }
            WM_RBUTTONUP => {
                mouse_button(app, hwnd, lp, BTN_RIGHT, false);
                0
            }
            WM_MBUTTONDOWN | WM_MBUTTONDBLCLK => {
                mouse_button(app, hwnd, lp, BTN_MIDDLE, true);
                0
            }
            WM_MBUTTONUP => {
                mouse_button(app, hwnd, lp, BTN_MIDDLE, false);
                0
            }
            WM_XBUTTONDOWN | WM_XBUTTONDBLCLK | WM_XBUTTONUP => {
                let b = if ((wp >> 16) & 0xffff) as u16 == XBUTTON1 { BTN_X1 } else { BTN_X2 };
                mouse_button(app, hwnd, lp, b, msg != WM_XBUTTONUP);
                1
            }
            WM_MOUSEWHEEL | WM_MOUSEHWHEEL => {
                if let Some(s) = app.input() {
                    let delta = ((wp >> 16) & 0xffff) as u16 as i16;
                    s.send(ClientMsg::Wheel { delta, horizontal: msg == WM_MOUSEHWHEEL });
                }
                0
            }
            WM_CAPTURECHANGED => {
                // Capture taken away mid-drag: let go of the buttons on the host as well.
                let held = app.buttons.swap(0, Ordering::SeqCst);
                if let (true, Some(s)) = (held != 0, app.input()) {
                    for b in 0..5u8 {
                        if held & (1 << b) != 0 {
                            s.send(ClientMsg::MouseButton { button: b, down: false });
                        }
                    }
                }
                0
            }
            WM_KEYDOWN | WM_KEYUP | WM_SYSKEYDOWN | WM_SYSKEYUP => {
                // Only reached when the low-level hook is unavailable or passed the key on.
                if !app.hook_active.load(Ordering::SeqCst) {
                    let scan = ((lp >> 16) & 0xff) as u16;
                    let extended = (lp >> 24) & 1 != 0;
                    let up = msg == WM_KEYUP || msg == WM_SYSKEYUP;
                    if on_key(app, wp as u16, scan, extended, up) {
                        return 0;
                    }
                }
                DefWindowProcW(hwnd, msg, wp, lp)
            }
            WM_SYSCHAR | WM_SYSCOMMAND if msg == WM_SYSCHAR || (wp & 0xfff0) as u32 == SC_KEYMENU => 0,
            WM_DPICHANGED => {
                let r = &*(lp as *const RECT);
                SetWindowPos(hwnd, null_mut(), r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER | SWP_NOACTIVATE);
                PostMessageW(hwnd, WM_APP_LAYOUT, 0, 0);
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letterbox_and_pointer_mapping() {
        // 16:9 image in a 4:3 area: bars above and below.
        let d = dest_rect(800, 600, 1920, 1080);
        assert_eq!((d.left, d.top, d.right, d.bottom), (0, 75, 800, 525));
        assert_eq!(map_to_remote(&d, 1920, 1080, 0, 75), (0, 0));
        assert_eq!(map_to_remote(&d, 1920, 1080, 799, 524), (1917, 1077));
        // Outside the image clamps to the edge.
        assert_eq!(map_to_remote(&d, 1920, 1080, -50, 1000), (0, 1079));
        let tall = dest_rect(1000, 500, 1000, 1000);
        assert_eq!((tall.left, tall.right), (250, 750));
        assert_eq!(dest_rect(0, 600, 1920, 1080).right, 0);
        // A degenerate rectangle never divides by zero.
        let zero = RECT { left: 5, top: 5, right: 5, bottom: 5 };
        assert_eq!(map_to_remote(&zero, 100, 100, 50, 50), (99, 99));
    }

    #[test]
    fn open_dialog_results() {
        let w = |s: &str| -> Vec<u16> { s.encode_utf16().collect() };
        let single = w("C:\\data\\report.pdf\0\0");
        assert_eq!(parse_multi_select(&single), [PathBuf::from("C:\\data\\report.pdf")]);
        let multi = w("C:\\data\0a.txt\0보고서.hwp\0\0garbage");
        assert_eq!(parse_multi_select(&multi), [PathBuf::from("C:\\data\\a.txt"), PathBuf::from("C:\\data\\보고서.hwp")]);
        assert!(parse_multi_select(&w("\0\0")).is_empty());
        assert!(parse_multi_select(&[]).is_empty());
    }

    #[test]
    fn dimming_keeps_alpha_and_darkens() {
        let mut px = [255, 128, 8, 255, 0, 0, 0, 255];
        dim(&mut px);
        assert_eq!(px, [95, 48, 3, 255, 0, 0, 0, 255]);
    }

    #[test]
    fn end_reasons_are_worded_for_people() {
        assert_eq!(reason_text(EndKind::Closed, crate::channel::CLOSED), tr(Txt::HostClosed));
        assert_eq!(reason_text(EndKind::Network, "connection timed out"), tr(Txt::NoAnswer));
        assert_eq!(reason_text(EndKind::Network, "os error 10054"), "os error 10054");
        assert_eq!(short_error("cannot connect to 127.0.0.1:47300: refused (os error 10061)"), "refused (os error 10061)");
        assert_eq!(short_error("cannot resolve x: no such host"), "cannot resolve x: no such host");
    }

    #[test]
    fn files_arrive_only_when_asked() {
        let mut p = Pull::default();
        // Nothing requested: refused even in the session's first millisecond.
        assert_eq!(p.begin(0), None);
        assert_eq!(p.begin(5), None);
        p.progress(0, 5);
        assert_eq!(p.begin(6), None);
        p.request(1000);
        let r = p.begin(1000 + PULL_WINDOW_MS - 1).expect("first file within the window");
        // A new file alone never keeps the window open...
        assert_eq!(p.begin(1000 + PULL_WINDOW_MS), None);
        // ...progress on a file accepted for the click does.
        p.progress(r, 40_000);
        assert!(p.begin(40_000 + PULL_WINDOW_MS - 1).is_some());
        assert_eq!(p.begin(40_000 + PULL_WINDOW_MS), None);
        // Files of an earlier click do not extend a new click's window.
        p.request(100_000);
        p.progress(r, 125_000);
        assert_eq!(p.begin(100_000 + PULL_WINDOW_MS), None);
    }

    #[test]
    fn one_click_accepts_a_bounded_pull() {
        let mut p = Pull::default();
        p.request(0);
        for i in 0..PULL_MAX_FILES as u64 {
            assert!(p.begin(i).is_some(), "file {i}");
        }
        assert_eq!(p.begin(PULL_MAX_FILES as u64), None);
        // Busy transfers keep the window open, but never past the click's ceiling.
        let mut p = Pull::default();
        p.request(0);
        let r = p.begin(0).unwrap();
        p.progress(r, PULL_MAX_MS - 10);
        assert!(p.begin(PULL_MAX_MS - 1).is_some());
        p.progress(r, PULL_MAX_MS + 5);
        assert_eq!(p.begin(PULL_MAX_MS), None);
        assert_eq!(p.begin(PULL_MAX_MS + 6), None);
        // A new click starts a new budget.
        p.request(PULL_MAX_MS + 10);
        assert!(p.begin(PULL_MAX_MS + 11).is_some());
    }

    #[test]
    fn host_events_cannot_flood_the_ui() {
        let mut q = VecDeque::new();
        let notice = |g: u64, t: &str| Event::Notice { generation: g, text: t.into() };
        let state = |key: u8, value: u32| Event::State { generation: 1, key, value };
        assert!(enqueue(&mut q, notice(1, "a")));
        assert!(!enqueue(&mut q, notice(1, "b")), "merged into the queued notice");
        assert!(enqueue(&mut q, notice(2, "c")));
        assert!(enqueue(&mut q, state(SET_AUDIO, 1)));
        assert!(!enqueue(&mut q, state(SET_AUDIO, 0)));
        assert!(enqueue(&mut q, state(SET_PRIVACY, 1)));
        assert_eq!(q.len(), 4);
        assert!(matches!(&q[0], Event::Notice { text, .. } if text == "b"));
        assert!(matches!(q[2], Event::State { key: SET_AUDIO, value: 0, .. }));
        let toast = |i: usize| Event::Toast { generation: 1, tone: Tone::Info, title: i.to_string(), text: String::new(), action: None };
        for i in 0..1000 {
            enqueue(&mut q, toast(i));
        }
        assert_eq!(q.len(), MAX_EVENTS);
        assert!(!enqueue(&mut q, notice(3, "late")));
        assert!(!enqueue(&mut q, state(SET_QUALITY, 1)));
        // The end of a session is never dropped.
        let ended =
            Event::Ended { generation: 1, kind: EndKind::Closed, reason: String::new(), lifetime: Duration::ZERO, since_notice: None };
        assert!(enqueue(&mut q, ended));
        assert_eq!(q.len(), MAX_EVENTS + 1);
    }

    #[test]
    fn host_cannot_turn_sound_on() {
        // Unasked: stays off, and the host is told to stop.
        assert_eq!(feature_from_host(false, 1), (false, true));
        assert_eq!(feature_from_host(false, 7), (false, true));
        // Confirmed, or ended by the host.
        assert_eq!(feature_from_host(true, 1), (true, false));
        assert_eq!(feature_from_host(true, 0), (false, false));
        assert_eq!(feature_from_host(false, 0), (false, false));
    }

    #[test]
    fn windows_key_chords_stay_local_in_a_window() {
        let (mut r, win, d, e) = (HashMap::new(), MOD_WIN, b'D' as u16, b'E' as u16);
        // Win+D: every event stays local, so the host gets no 'd' and Start does not open.
        assert!(stays_local(false, win, VK_LWIN, false, &mut r));
        assert!(stays_local(false, win, d, false, &mut r));
        assert!(stays_local(false, win, d, true, &mut r));
        assert!(stays_local(false, 0, VK_LWIN, true, &mut r));
        assert!(r.is_empty());
        // Shift pressed before Win keeps going to the host, auto-repeats and release included.
        assert!(!stays_local(false, 0, VK_LSHIFT, false, &mut r));
        assert!(stays_local(false, win, VK_LWIN, false, &mut r));
        assert!(!stays_local(false, win, VK_LSHIFT, false, &mut r));
        assert!(!stays_local(false, win, VK_LSHIFT, true, &mut r));
        // A key pressed during the chord is released locally, even after Win went up.
        assert!(stays_local(false, win, e, false, &mut r));
        assert!(stays_local(false, 0, VK_LWIN, true, &mut r));
        assert!(stays_local(false, 0, e, true, &mut r));
        assert!(!stays_local(false, 0, e, false, &mut r));
        assert!(!stays_local(false, 0, e, true, &mut r));
        // Alt+Tab stays local (Alt itself goes to the host).
        assert!(!stays_local(false, MOD_ALT, VK_LMENU, false, &mut r));
        assert!(stays_local(false, MOD_ALT, VK_TAB, false, &mut r));
        assert!(!stays_local(false, 0, VK_LMENU, true, &mut r));
        assert!(stays_local(false, 0, VK_TAB, true, &mut r));
        // Full screen: everything goes to the host.
        assert!(!stays_local(true, win, VK_LWIN, false, &mut r));
        assert!(!stays_local(true, win, d, false, &mut r));
        assert!(!stays_local(true, win, d, true, &mut r));
        assert!(!stays_local(true, 0, VK_LWIN, true, &mut r));
        assert!(r.is_empty());
        // Pressed before the viewer had the focus: the release is not swallowed either.
        assert!(stays_local(true, 0, VK_RETURN, true, &mut r));
    }

    fn env_num(name: &str) -> Option<u64> {
        std::env::var(name).ok()?.parse().ok()
    }

    /// Manual harness: a scripted host that offers every feature (settings are confirmed,
    /// privacy is reported unavailable, "Get copied files" delivers a small text file,
    /// uploads are acknowledged), for trying the viewer UI without a real v2 host:
    ///
    /// `SRDP_FAKE_KEY_FILE=key.txt cargo test --release fake_host -- --ignored --nocapture`
    /// then `safe-rdp connect 127.0.0.1:47422 --key-file key.txt --view-only`.
    /// `SRDP_FAKE_DROP_AFTER=<s>` drops the first session after that many seconds and stays
    /// unreachable for `SRDP_FAKE_DOWN` seconds (default 6), to show the reconnect overlay.
    #[test]
    #[ignore = "manual: serves a scripted fake host until killed"]
    fn fake_host() {
        let port = env_num("SRDP_FAKE_PORT").unwrap_or(47422) as u16;
        let key = crate::keys::load_key_file(&std::env::var("SRDP_FAKE_KEY_FILE").expect("SRDP_FAKE_KEY_FILE")).unwrap();
        let mut drop_after = env_num("SRDP_FAKE_DROP_AFTER").map(Duration::from_secs);
        loop {
            let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
            let (sock, peer) = listener.accept().unwrap();
            drop(listener);
            eprintln!("fake host: session from {peer}");
            let dropped = serve_fake(sock, &key, drop_after.take());
            eprintln!("fake host: session ended");
            if dropped {
                std::thread::sleep(Duration::from_secs(env_num("SRDP_FAKE_DOWN").unwrap_or(6)));
            }
        }
    }

    /// Serves one fake session; returns true if it was dropped on purpose.
    fn serve_fake(sock: TcpStream, key: &Secret<32>, drop_after: Option<Duration>) -> bool {
        use crate::channel;
        let Ok(keys) = channel::server_handshake(&mut &sock, &key.0) else { return false };
        let mut reader = RecordReader::new(sock.try_clone().unwrap(), keys.recv);
        let writer = Arc::new(Mutex::new(RecordWriter::new(sock.try_clone().unwrap(), keys.send)));
        let send = {
            let writer = writer.clone();
            move |m: &ServerMsg| {
                let mut b = Vec::new();
                m.encode(&mut b);
                lock(&writer).send(&b).is_ok()
            }
        };
        if reader.recv().is_err() {
            return false;
        }
        let (w, h) = (800usize, 450usize);
        let monitors =
            vec![MonitorInfo { left: 0, top: 0, width: 2560, height: 1440 }, MonitorInfo { left: 2560, top: 0, width: 1920, height: 1080 }];
        let flags = F_CLIPBOARD | F_SAS | F_AUDIO | F_FILES | F_PRIVACY;
        send(&ServerMsg::Hello { width: w as u16, height: h as u16, flags, monitor: 0, monitors, name: "fake-host".into() });

        let stop = Arc::new(AtomicBool::new(false));
        let audio = Arc::new(AtomicBool::new(false));
        let input = {
            let (stop, audio, send) = (stop.clone(), audio.clone(), send.clone());
            std::thread::spawn(move || {
                let mut uploads: HashMap<u32, (String, u64)> = HashMap::new();
                while let Ok(rec) = reader.recv() {
                    let Ok(m) = ClientMsg::decode(rec) else { break };
                    match m {
                        ClientMsg::Ping(t) => {
                            send(&ServerMsg::Pong(t));
                        }
                        ClientMsg::Set { key, value } => {
                            eprintln!("fake host: set {key} = {value}");
                            if key == SET_AUDIO {
                                audio.store(value != 0, Ordering::SeqCst);
                            }
                            let value = if key == SET_PRIVACY { STATE_UNAVAILABLE } else { value };
                            send(&ServerMsg::State { key, value });
                        }
                        ClientMsg::FilePull => {
                            let data = b"Hello from the fake host.\r\n".repeat(40);
                            let sha256 = crate::crypto::sha256(&[&data]);
                            send(&ServerMsg::FileBegin { id: 7, size: data.len() as u64, name: "notes from host.txt".into() });
                            send(&ServerMsg::FileData { id: 7, data: &data });
                            send(&ServerMsg::FileEnd { id: 7, sha256 });
                        }
                        ClientMsg::FileBegin { id, name, .. } => {
                            uploads.insert(id, (name, 0));
                        }
                        ClientMsg::FileData { id, data } => {
                            if let Some(u) = uploads.get_mut(&id) {
                                u.1 += data.len() as u64;
                            }
                            // SRDP_FAKE_SLOW=<ms per chunk> emulates a slow link.
                            if let Some(ms) = env_num("SRDP_FAKE_SLOW") {
                                std::thread::sleep(Duration::from_millis(ms));
                            }
                        }
                        ClientMsg::FileEnd { id, .. } => {
                            if let Some((name, n)) = uploads.remove(&id) {
                                eprintln!("fake host: received {name} ({n} bytes)");
                                send(&ServerMsg::FileResult {
                                    id,
                                    ok: true,
                                    message: format!("C:\\Users\\host\\Downloads\\safe-rdp\\{name}"),
                                });
                            }
                        }
                        _ => {}
                    }
                }
                stop.store(true, Ordering::SeqCst);
            })
        };

        let mut enc = codec::Encoder::new().unwrap();
        let mut img = vec![0u8; w * h * 4];
        let start = Instant::now();
        let mut noticed = false;
        let mut frame = 0u32;
        let mut dropped = false;
        while !stop.load(Ordering::SeqCst) {
            let t = start.elapsed().as_millis() as usize;
            for y in 0..h {
                for x in 0..w {
                    let i = (y * w + x) * 4;
                    let lit = (x + t / 8) % w < 120 && (200..260).contains(&y);
                    img[i..i + 4].copy_from_slice(&if lit {
                        [250, 250, 250, 255]
                    } else {
                        [(x * 255 / w) as u8, 90, (y * 255 / h) as u8, 255]
                    });
                }
            }
            frame = frame.wrapping_add(1);
            for msg in codec::pack(frame, w, h, &enc.encode(&img, w, h)) {
                if lock(&writer).send(&msg).is_err() {
                    stop.store(true, Ordering::SeqCst);
                }
            }
            if audio.load(Ordering::SeqCst) {
                send(&ServerMsg::Audio { seq: frame, rate: 48000, channels: 2, codec: AUDIO_PCM16, data: &[0u8; 7680] });
            }
            if !noticed && start.elapsed() > Duration::from_millis(1500) {
                noticed = true;
                send(&ServerMsg::Notice("Fake host: everything is set up.".into()));
            }
            if drop_after.is_some_and(|d| start.elapsed() > d) {
                dropped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(80));
        }
        let _ = sock.shutdown(Shutdown::Both);
        let _ = input.join();
        dropped
    }
}
