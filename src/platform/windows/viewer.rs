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
use crate::codec::{self, Rect};
use crate::files;
use crate::proto::*;
use crate::util::{Error, Result, Secret, wide};
use crate::viewer::{self as core, Connection, EndKind, Next, OutQueue, ViewerOptions};
use crate::{bail, log};
use std::cell::{Cell, RefCell};
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
use windows_sys::Win32::System::RemoteDesktop::{NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification, WTSUnRegisterSessionNotification};
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
/// A frame waits for its turn to be painted (`show_frame`).
const T_FRAME: usize = 3;
/// What was painted unsmoothed while it moved is to be smoothed (`Scaling::Rough`).
const T_REFINE: usize = 4;
const TICK_MS: u32 = 250;

const MOD_CTRL: u8 = 1;
const MOD_ALT: u8 = 2;
const MOD_WIN: u8 = 4;

const PING_EVERY: Duration = Duration::from_secs(2);
/// Silence after which the bar warns that the host is not responding.
const QUIET_WARN_MS: u64 = 6000;
/// Files from the host are accepted only after asking for them: the first must start
/// within this time of the click, each next one within this time of progress on the files
/// accepted so far. So a host cannot push files nobody asked for.
const PULL_WINDOW_MS: u64 = 30_000;
/// Most files one click on "Get copied files" accepts (the host sends at most this many).
const PULL_MAX_FILES: u32 = 1000;
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
/// How long the viewer waits at exit for the session reader to end, wiping its copy of the screen.
const READER_EXIT_WAIT: Duration = Duration::from_secs(1);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Framebuffer {
    w: usize,
    h: usize,
    px: LockedBuf,
    dirty: Option<Rect>,
    resizes: core::ResizePacer,
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
    fb: core::FrameLock<Framebuffer>,
    fb_w: AtomicU32,
    fb_h: AtomicU32,
    /// Height of the docked bar above the remote image (0 in full screen).
    top: AtomicI32,
    cursor: AtomicU8,
    /// A WM_APP_FRAME / WM_APP_CURSOR / WM_APP_EVENT is waiting (see `post_once`).
    frame_posted: AtomicBool,
    cursor_posted: AtomicBool,
    events_posted: AtomicBool,
    hook_active: AtomicBool,
    mods: AtomicU8,
    swallowed: Mutex<HashSet<u16>>,
    /// Keys held down and whether their press went to the local desktop (see `stays_local`).
    routes: Mutex<HashMap<u16, bool>>,
    /// The Left Ctrl held down (`routes`) was pressed through a window message, which cannot
    /// always tell it from AltGr's (`left_ctrl_scan`).
    left_ctrl_unsure: AtomicBool,
    /// Modifiers held down on the host that a chord staying local pressed here as well
    /// (see `share_modifiers`): their repeats and release go to both.
    shared: Mutex<HashSet<u16>>,
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
        post_event(&self.events, &self.events_posted, self.hwnd(), ev);
    }

    /// The framebuffer, locked on the UI thread / on a session's reader (`core::FrameLock`).
    fn ui_fb(&self) -> MutexGuard<'_, Framebuffer> {
        self.fb.ui().unwrap_or_else(PoisonError::into_inner)
    }

    fn reader_fb(&self) -> MutexGuard<'_, Framebuffer> {
        self.fb.reader().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Posts `msg` unless one is still waiting (`pending`, which its handler clears before doing
/// the work). Wakeups the host triggers go through here, so however fast it sends, at most
/// one of each kind waits: the queue never fills up (posts would then fail, including the
/// viewer's own), and the message loop lets input go between them (`next_message`).
fn post_once(hwnd: HWND, pending: &AtomicBool, msg: u32) {
    if !pending.swap(true, Ordering::SeqCst) && unsafe { PostMessageW(hwnd, msg, 0, 0) } == 0 {
        pending.store(false, Ordering::SeqCst);
    }
}

/// Queues `ev` for the UI thread and wakes it. One WM_APP_EVENT handles many events, so a
/// wakeup is posted only while none waits (`post_once`; `dispatch_events` clears `posted`
/// before taking the first event): a host whose events outpace the UI thread cannot fill the
/// posted queue, which would refuse the viewer's own posts and hold back its timers.
fn post_event(events: &Mutex<VecDeque<Event>>, posted: &AtomicBool, hwnd: HWND, ev: Event) {
    enqueue(&mut lock(events), ev);
    post_once(hwnd, posted, WM_APP_EVENT);
}

/// Takes up to `EVENTS_PER_WAKE` events off the UI queue for `handle`; if more remain, another
/// WM_APP_EVENT follows (through `post_once`, so still at most one waits).
fn drain_events(events: &Mutex<VecDeque<Event>>, posted: &AtomicBool, hwnd: HWND, mut handle: impl FnMut(Event)) {
    for _ in 0..EVENTS_PER_WAKE {
        let Some(ev) = lock(events).pop_front() else { return };
        handle(ev);
    }
    if !lock(events).is_empty() {
        post_once(hwnd, posted, WM_APP_EVENT);
    }
}

/// Adds `ev` to the UI queue, keeping it bounded however fast the host sends: a notice
/// replaces a queued notice and a setting's state a queued state of the same setting, and
/// host-driven events are dropped once `MAX_EVENTS` wait. True if a new entry was added.
fn enqueue(q: &mut VecDeque<Event>, mut ev: Event) -> bool {
    let same = |e: &Event| match (e, &ev) {
        (Event::Notice { generation: a, .. }, Event::Notice { generation: b, .. }) => a == b,
        (Event::State { generation: a, key: k, .. }, Event::State { generation: b, key: l, .. }) => a == b && k == l,
        _ => false,
    };
    if let Some(i) = q.iter().position(same) {
        // The merged state still answers every `Set` the replaced ones answered.
        if let (Event::State { states: before, .. }, Event::State { states, .. }) = (&q[i], &mut ev) {
            *states = states.saturating_add(*before);
        }
        q[i] = ev;
        return false;
    }
    // States of real settings are never dropped (each answers a `Set` that is being counted);
    // they merge per setting above, so they cannot pile up.
    let droppable = match ev {
        Event::Notice { .. } | Event::Toast { .. } => true,
        Event::State { key, .. } => key as usize >= 8,
        _ => false,
    };
    if q.len() >= MAX_EVENTS && droppable {
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
    /// The latest of `states` host `State`s for `key` (more than one once merged in the queue).
    State { generation: u64, key: u8, value: u32, states: u32 },
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
        if !self.out.send(m) && self.out.stalled() {
            self.end(EndKind::Network, core::STALLED.into());
        }
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
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::System::IO::CancelIoEx;
        self.ended.store(true, Ordering::SeqCst);
        self.out.close();
        let _ = self.sock.shutdown(Shutdown::Both);
        // Windows does not wake a recv blocked in another thread on shutdown (`host.rs` has the
        // same): cancelling the socket's I/O lets the reader end now and wipe its copy of the
        // screen, rather than with the process (unwiped) or the host's next record.
        unsafe { CancelIoEx(self.sock.as_raw_socket() as HANDLE, null()) };
        lock(&self.clipboard).take();
    }

    fn toast(&self, tone: Tone, title: String, text: String, action: Option<ToastAction>) {
        APP.get().unwrap().post(Event::Toast { generation: self.generation, tone, title, text, action });
    }

    /// Not in a view-only session (the viewer's or the host's), which changes nothing on the host.
    fn files_allowed(&self) -> bool {
        self.flags & F_FILES != 0 && !self.view_only
    }
}

/// Which files from the host the user asked for. A click on "Get copied files" lets the
/// first file start within `PULL_WINDOW_MS`; after that only progress on files already
/// accepted keeps the window open (a new file alone never does), for at most
/// `PULL_MAX_FILES` files per click. The host sends one batch at a time, so a second click
/// during a long batch must not cut the first one off.
#[derive(Default)]
struct Pull {
    /// Number of the latest click (0: never asked).
    request: u32,
    /// New files are accepted while `now < until`; 0 means nothing was requested.
    until: u64,
    files_left: u32,
    /// The click for which the user was last told that files came too late.
    warned: u32,
}

impl Pull {
    /// The user asked for the host's copied files at session time `now` (ms).
    fn request(&mut self, now: u64) {
        self.request = self.request.wrapping_add(1).max(1);
        self.until = self.until.max(now + PULL_WINDOW_MS);
        self.files_left = PULL_MAX_FILES;
    }

    /// The host starts a file: the request it is accepted for, or `None` if nobody asked.
    fn begin(&mut self, now: u64) -> Option<u32> {
        if self.until == 0 || now >= self.until || self.files_left == 0 {
            return None;
        }
        self.files_left -= 1;
        Some(self.request)
    }

    /// Data or the end of an accepted file arrived: the next file may follow.
    fn progress(&mut self, now: u64) {
        if self.until != 0 {
            self.until = self.until.max(now + PULL_WINDOW_MS);
        }
    }

    /// A file was refused: whether to tell the user (once per click, and only when they did
    /// ask at some point, i.e. it came too late rather than unasked).
    fn tell_refused(&mut self) -> bool {
        if self.request == 0 || self.warned == self.request {
            return false;
        }
        self.warned = self.request;
        true
    }
}

/// The `Set`s sent for one `SET_*` key that the host has not answered yet (it answers each
/// with a `State`, in order), and the value the latest asked for.
#[derive(Clone, Copy, Default)]
struct Asked {
    due: u32,
    value: u32,
    /// The latest ask was no click but the hello's wish, or the viewer turning off again what
    /// the host turned on by itself (`Ui::on_state`, as often as the host likes): its answer
    /// shows no toast and waits for the tick, like the host's own changes.
    quiet: bool,
}

/// What a `State` from the host is, next to the `Set`s sent for its key.
#[derive(Debug, PartialEq)]
enum Reply {
    /// The answer to an earlier `Set` than the latest: outdated, ignored.
    Stale,
    /// The answer to the latest `Set`, which asked for this value.
    Latest(u32),
    /// Nothing was asked: the host changed the setting by itself.
    Unasked,
}

impl Asked {
    fn sent(&mut self, value: u32) {
        self.due = self.due.saturating_add(1);
        self.value = value;
        self.quiet = false;
    }

    /// The hello asked for `value`; the host answers that with one `State` as well.
    fn wished(&mut self, value: u32) {
        self.sent(value);
        self.quiet = true;
    }

    /// `states` `State`s arrived for the key; what the latest of them is.
    fn reply(&mut self, states: u32) -> Reply {
        let due = self.due;
        self.due = due.saturating_sub(states);
        match due.cmp(&states) {
            std::cmp::Ordering::Greater => Reply::Stale,
            std::cmp::Ordering::Equal => Reply::Latest(self.value),
            std::cmp::Ordering::Less => Reply::Unasked,
        }
    }

    /// `reply`, and whether the latest `State` answers a click (not a `quiet` ask): only that
    /// shows a refusal toast and the bar at once.
    fn answer(&mut self, states: u32) -> (Reply, bool) {
        let quiet = self.quiet;
        let reply = self.reply(states);
        let clicked = matches!(reply, Reply::Latest(_)) && !quiet;
        (reply, clicked)
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
    /// An attempt whose hello carried the instance was closed unanswered (`HELLO_UNANSWERED`):
    /// an older host may be answering now, so the next ones leave it out.
    instance_unanswered: bool,
}

impl Reconnect {
    /// Whether the next hello carries the instance, to a host that `announced` it (`F_INSTANCE`).
    fn names(&self, announced: bool) -> bool {
        announced && !self.instance_unanswered
    }

    /// Counts a failed attempt (`e`) on a host that `announced` the instance; whether to try again.
    fn failed(&mut self, e: &Error, announced: bool) -> bool {
        let named = self.names(announced);
        let text = e.to_string();
        self.attempt += 1;
        self.last_error = Some(short_error(&text));
        self.instance_unanswered |= text == core::HELLO_UNANSWERED;
        // A hello left without the instance after one went unanswered was turned away. Only a
        // host that knows instances does that, and it takes them in the hello: the link, not the
        // host, failed before the answer (a reset reads as a close), and the session live there
        // may be this viewer's own. The next attempt names it; turned away then, it stops.
        let name_again = announced && !named && text.starts_with(core::REFUSED);
        if name_again {
            self.instance_unanswered = false;
        }
        (name_again || core::retryable(e)) && self.since.elapsed() < core::RECONNECT_FOR
    }
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
    /// `SET_*` keys changed here and not yet confirmed.
    asked: [Asked; 8],
    sound_local_failed: bool,
    bar: Bar,
    toasts: Toasts,
    overlay: Overlay,
    floating: bool,
    meter: core::RateMeter,
    fps: f64,
    mbps: f64,
    generation: u64,
    /// The latest session's reader thread.
    reader: Option<std::thread::JoinHandle<()>>,
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

fn run_window(target: &str, mut opts: ViewerOptions, psk: Secret<32>) -> Result<()> {
    // Names this window's connections to the host, so that its automatic reconnects take back
    // only the session it lost, never one another viewer has started since. The first hello is
    // the five-byte one every host takes; `connect` names the session only to a host that
    // announced `F_INSTANCE`.
    opts.instance = core::new_instance()?;
    let conn = core::connect(target, &opts, &psk)?;
    let (w, h) = (conn.width, conn.height);
    if w * h > MAX_PIXELS {
        bail!("the host's screen ({w}x{h}) is too large");
    }
    let app = App {
        hwnd: AtomicUsize::new(0),
        fb: core::FrameLock::new(Framebuffer {
            w,
            h,
            px: LockedBuf::new(w * h * 4),
            dirty: None,
            resizes: core::ResizePacer::new(Instant::now()),
        }),
        fb_w: AtomicU32::new(w as u32),
        fb_h: AtomicU32::new(h as u32),
        top: AtomicI32::new(0),
        cursor: AtomicU8::new(Cursor::Arrow as u8),
        frame_posted: AtomicBool::new(false),
        cursor_posted: AtomicBool::new(false),
        events_posted: AtomicBool::new(false),
        hook_active: AtomicBool::new(false),
        mods: AtomicU8::new(0),
        swallowed: Mutex::new(HashSet::new()),
        routes: Mutex::new(HashMap::new()),
        left_ctrl_unsure: AtomicBool::new(false),
        shared: Mutex::new(HashSet::new()),
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
        asked: [Asked::default(); 8],
        sound_local_failed: false,
        bar,
        toasts: Toasts::new(hwnd),
        overlay: Overlay::new(hwnd),
        floating: false,
        meter: core::RateMeter::new(Instant::now()),
        fps: 0.0,
        mbps: 0.0,
        generation: 0,
        reader: None,
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
        // Locking and unlocking (Win+L, Ctrl+Alt+Del) hide key releases from the hook.
        WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
        ShowWindow(hwnd, SW_SHOW);
        SetTimer(hwnd, T_TICK, TICK_MS, None);
    }
    if !hook_keyboard(app) {
        log!("warning: keyboard hook unavailable; system shortcuts stay local");
    }
    if fullscreen {
        toggle_fullscreen(hwnd);
    }

    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        let mut after_host = false;
        while next_message(&mut msg, after_host) {
            after_host = host_triggered(&msg, hwnd);
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    unhook_keyboard(app);
    let mut ui = UI.with(|cell| cell.borrow_mut().take());
    if let Some(s) = lock(&app.session).take() {
        s.shutdown();
    }
    // The reader wipes its own copy of the screen as it ends; exiting first would free it unwiped.
    if let Some(r) = ui.as_mut().and_then(|u| u.reader.take()) {
        let deadline = Instant::now() + READER_EXIT_WAIT;
        while !r.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    // Pending reconnect results hold live connections: close them.
    lock(&app.events).clear();
    // Wipe the remote screen contents before exiting.
    app.ui_fb().px = LockedBuf::new(0);
    match ui.and_then(|u| u.exit_error) {
        Some(e) => Err(e.into()),
        None => Ok(()),
    }
}

/// Messages posted for the host: frames, cursor shapes and events.
fn host_triggered(msg: &MSG, hwnd: HWND) -> bool {
    msg.hwnd == hwnd && matches!(msg.message, WM_APP_FRAME | WM_APP_CURSOR | WM_APP_EVENT)
}

/// The next message for the loop in `run_window`; false at WM_QUIT. GetMessage returns
/// posted messages before input, timers and paint. At most one of each kind the host triggers
/// waits (`post_once`), but a host that sends fast enough posts the next one while this thread
/// handles the last, so one would always be waiting: input, the tick and repaints would never
/// get a turn. After such a message, waiting input, then a due timer, then a repaint go first.
unsafe fn next_message(msg: &mut MSG, after_host: bool) -> bool {
    unsafe {
        if after_host
            && (PeekMessageW(msg, null_mut(), 0, 0, PM_REMOVE | PM_QS_INPUT) != 0
                || PeekMessageW(msg, null_mut(), WM_TIMER, WM_TIMER, PM_REMOVE) != 0
                || PeekMessageW(msg, null_mut(), 0, 0, PM_REMOVE | PM_QS_PAINT) != 0)
        {
            return msg.message != WM_QUIT;
        }
        GetMessageW(msg, null_mut(), 0, 0) > 0
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

/// Ends the session if its reader panics (a framebuffer that cannot be allocated, say), rather
/// than leaving the window on the last frame with no error and no reconnect.
struct EndOnPanic<'a>(&'a Session);

impl Drop for EndOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.end(EndKind::Fatal, "the viewer failed while handling the host's data (out of memory?)".into());
        }
    }
}

fn reader_loop(s: &Session, mut reader: RecordReader<TcpStream>) {
    let _end = EndOnPanic(s);
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
    let mut dec = core::TileDecoder::new().map_err(fatal)?;
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
                // Only a new shape needs a wakeup; WM_SETCURSOR shows the latest on every move.
                if app.cursor.swap(c as u8, Ordering::SeqCst) != c as u8 {
                    post_once(app.hwnd(), &app.cursor_posted, WM_APP_CURSOR);
                }
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
                let text = host_text(&text, true);
                log!("host: {}", host_line(&text));
                s.last_notice_ms.store(s.ms(), Ordering::SeqCst);
                app.post(Event::Notice { generation: s.generation, text });
            }
            ServerMsg::Audio { rate, channels, codec, data, .. } => audio.play(s, rate, channels, codec, data),
            ServerMsg::FileBegin { id, size, name } => downloads.begin(s, id, size, &name),
            ServerMsg::FileData { id, data } => downloads.data(s, id, data),
            ServerMsg::FileEnd { id, sha256 } => downloads.end(s, id, &sha256),
            ServerMsg::FileResult { id, ok, message } => file_result(s, id, ok, message),
            ServerMsg::State { key, value } => app.post(Event::State { generation: s.generation, key, value, states: 1 }),
            ServerMsg::Ping | ServerMsg::Hello { .. } => {}
        }
    }
}

/// Applies one tiles message of session `s`; returns true when it completed a frame.
fn apply_tiles(app: &App, s: &Session, dec: &mut core::TileDecoder, p: &[u8]) -> Result<bool> {
    let hdr = codec::parse_header(p)?;
    let size = (hdr.width, hdr.height);
    // A new size gets its buffer allocated and page-locked, and the old one wiped (up to
    // 256 MiB each), outside the lock: under it only the buffers are swapped, so the UI thread
    // never waits for either. Declared before `fb`, so even an early return drops them after
    // the lock is released.
    let (mut fresh, mut old) = (None, None);
    let mut fb = loop {
        let mut fb = app.reader_fb();
        // Ended while it waited (paced, or allocating): the framebuffer may be a newer
        // session's already, which an older message must not resize or draw on.
        if s.is_ended() {
            return Ok(false);
        }
        if (fb.w, fb.h) == size || fresh.is_some() {
            break fb;
        }
        if hdr.width * hdr.height > MAX_PIXELS {
            bail!("remote screen {}x{} is too large", hdr.width, hdr.height);
        }
        let wait = fb.resizes.wait(Instant::now());
        drop(fb);
        std::thread::sleep(wait);
        // This reader's own copy of the screen goes first, so that two screens' worth is
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
        fb.dirty = Some(Rect { x: 0, y: 0, w: fb.w, h: fb.h });
        app.fb_w.store(fb.w as u32, Ordering::SeqCst);
        app.fb_h.store(fb.h as u32, Ordering::SeqCst);
    }
    drop(fb);
    // A replaced (or unneeded) buffer is wiped with the lock released, and before this reader
    // makes its own copy of the screen at the new size.
    drop((old, fresh));
    // Decoded without the lock (`core::TileDecoder`): only copying the rects drawn takes it,
    // a band at a time, so the UI thread waits for one band at most.
    if let Some(b) = dec.decode(p, hdr.width, hdr.height)? {
        let mut at = (0, 0);
        loop {
            let mut fb = app.reader_fb();
            if s.is_ended() {
                return Ok(false);
            }
            // Resized again meanwhile (by an older session's reader): this message is outdated.
            if (fb.w, fb.h) != size {
                break;
            }
            if dec.copy(fb.px.as_mut_slice(), &mut at) {
                fb.dirty = Some(match fb.dirty {
                    None => b,
                    Some(d) => {
                        let (x0, y0) = (d.x.min(b.x), d.y.min(b.y));
                        let (x1, y1) = ((d.x + d.w).max(b.x + b.w), (d.y + d.h).max(b.y + b.h));
                        Rect { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }
                    }
                });
                break;
            }
        }
    }
    if hdr.last {
        // Acked on this session's own queue: never on a newer session after a reconnect.
        s.send(ClientMsg::Ack(hdr.frame));
        post_once(app.hwnd(), &app.frame_posted, WM_APP_FRAME);
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
        let accepted = lock(&s.pull).begin(s.ms());
        let Some(request) = accepted else {
            log!("ignored a file the host sent without being asked");
            if lock(&s.pull).tell_refused() {
                s.toast(Tone::Warning, tr(Txt::PullExpired).to_string(), tr(Txt::PullExpiredHint).to_string(), None);
            }
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
        let Some((inc, _)) = self.active.get_mut(&id) else { return };
        lock(&s.pull).progress(s.ms());
        if let Err(e) = inc.write(data) {
            let name = inc.name.clone();
            self.active.remove(&id);
            s.toast(Tone::Error, trf(Txt::ReceiveFailed, &[&name]), e.to_string(), None);
        }
        self.progress(s);
    }

    fn end(&mut self, s: &Session, id: u32, sha256: &[u8; 32]) {
        let Some((inc, _)) = self.active.remove(&id) else { return };
        lock(&s.pull).progress(s.ms());
        let name = inc.name.clone();
        match inc.finish(sha256) {
            Ok(path) => {
                log!("received {}", printable(&path.display().to_string()));
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
    let message = host_text(&message, false);
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
        // The hello left the quality to a host that will not say which it uses (an earlier
        // version): such a host uses Balanced, unless it was started with `--quality`.
        if flags & F_QUALITY_STATE == 0 && self.opts.quality as u32 > QUALITY_LOW {
            self.prefs.quality = QUALITY_BALANCED as u8;
        }
        self.flags = flags;
        self.view_only = view_only;
        self.unavailable = [false; 8];
        self.asked = [Asked::default(); 8];
        // The host answers the hello's sound and privacy wishes with a `State` each; count them,
        // or a click before they arrive would be matched with the wrong answer.
        if self.prefs.audio {
            self.asked[SET_AUDIO as usize].wished(1);
        }
        if self.prefs.privacy {
            self.asked[SET_PRIVACY as usize].wished(1);
        }
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
        // An earlier session's reader was stopped with its session and ends by itself.
        self.reader = r.ok();
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
        // Dropped mid-drag: a capture kept would take the clicks meant for the bar.
        if app.buttons.swap(0, Ordering::SeqCst) != 0 {
            unsafe { ReleaseCapture() };
        }
    }

    /// The hello of an automatic reconnect.
    fn hello_options(&self) -> ViewerOptions {
        let announced = self.flags & F_INSTANCE != 0;
        ViewerOptions {
            fullscreen: false,
            clipboard: self.prefs.clipboard,
            view_only: self.opts.view_only,
            allow_capture: self.opts.allow_capture,
            downscale: self.prefs.downscale,
            // What the user picked, else still the host's choice (`prefs` shows the one in effect).
            quality: self.opts.quality,
            monitor: self.prefs.monitor,
            audio: self.prefs.audio,
            privacy: self.prefs.privacy,
            instance: self.opts.instance,
            reconnect: true,
            // Only a host that announced it takes the instance in the hello: an older one rejects
            // that hello after replacing its viewer. Without it, an older host takes the hello as
            // any other, and a newer one lets it in only while nobody is connected.
            instance_in_hello: self.reconnect.as_ref().map_or(announced, |rc| rc.names(announced)),
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
            Event::State { generation, key, value, states } => {
                if generation == self.generation {
                    self.on_state(key, value, states);
                }
                After::Nothing
            }
            Event::SoundFailed { generation, reason } => {
                if generation == self.generation {
                    log!("sound playback unavailable: {reason}");
                    self.sound_local_failed = true;
                    self.set_sound(false, true);
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
                // One line: the message also ends up in the log as the viewer's last error.
                (EndKind::Closed, Some(n)) if since_notice.is_some_and(|d| d < core::NOTICE_GRACE) => {
                    trf(Txt::SessionEnded, &[&self.host, &host_line(n)])
                }
                (EndKind::Closed, _) if reconnected => trf(Txt::KickedAgain, &[&self.host]),
                _ => trf(Txt::SessionEnded, &[&self.host, &reason]),
            };
            return After::Quit(Some(message));
        }
        dim_framebuffer();
        let now = Instant::now();
        let delay = core::reconnect_delay(0);
        self.reconnect = Some(Reconnect {
            since: now,
            attempt: 0,
            due: Some(now + delay),
            in_flight: None,
            cause: reason,
            last_error: None,
            instance_unanswered: false,
        });
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
                if !rc.failed(&e, self.flags & F_INSTANCE != 0) {
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

    fn on_state(&mut self, key: u8, value: u32, states: u32) {
        let k = key as usize;
        if k >= self.unavailable.len() {
            return;
        }
        // While later `Set`s are unanswered, the latest of them decides. Clicked for, rather
        // than wished in the hello, refused here or changed by the host: `requested`.
        let (reply, requested) = self.asked[k].answer(states);
        if reply == Reply::Stale {
            return;
        }
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
                    let current = if key == SET_AUDIO { self.prefs.audio } else { self.prefs.privacy };
                    let (on, refuse) = feature_state(current, &reply, value);
                    if key == SET_AUDIO {
                        self.set_sound(on, false);
                    } else {
                        self.prefs.privacy = on;
                    }
                    if refuse {
                        // No click: its answer (unavailable, say) must not buy the host a toast
                        // and a relayout of the bar for every two `State`s it sends.
                        self.request(key, 0);
                        self.asked[k].quiet = true;
                    }
                }
                _ => {}
            }
        }
        // An answer to a click shows at once. What the host changes by itself, as often as it
        // likes, shows with the next tick's refresh: a relayout of the bar per `State` would let
        // a host keep this thread busy.
        if requested {
            self.refresh_bar();
        }
    }

    /// Changes a host setting (optimistically; `ServerMsg::State` confirms or corrects it).
    fn request(&mut self, key: u8, value: u32) {
        if let Some(s) = APP.get().unwrap().session() {
            s.send(ClientMsg::Set { key, value });
            self.asked[key as usize].sent(value);
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
            toolbar::CMD_PRIVACY if !self.view_only => {
                self.prefs.privacy = !self.prefs.privacy;
                self.request(SET_PRIVACY, self.prefs.privacy as u32);
            }
            c if (toolbar::CMD_QUALITY..=toolbar::CMD_QUALITY + QUALITY_LOW as u16).contains(&c) => {
                self.prefs.quality = (c - toolbar::CMD_QUALITY) as u8;
                self.opts.quality = self.prefs.quality;
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
            send_files: if self.view_only { Feature::Hidden } else { self.feature(F_FILES, None, false) },
            get_files: if self.view_only { Feature::Hidden } else { self.feature(F_FILES, None, false) },
            sound: if self.flags & F_AUDIO != 0 && self.sound_local_failed {
                Feature::NoLocal
            } else {
                self.feature(F_AUDIO, Some(SET_AUDIO), self.prefs.audio)
            },
            privacy: if self.view_only { Feature::Hidden } else { self.feature(F_PRIVACY, Some(SET_PRIVACY), self.prefs.privacy) },
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

/// `feature_from_host` for a feature that is `current`ly on or off: the answer to the latest
/// `Set` is held to what that `Set` asked for, an unasked `State` to the current choice, and an
/// outdated answer changes nothing.
fn feature_state(current: bool, reply: &Reply, value: u32) -> (bool, bool) {
    match *reply {
        Reply::Stale => (current, false),
        Reply::Latest(asked) => feature_from_host(asked != 0, value),
        Reply::Unasked => feature_from_host(current, value),
    }
}

/// Text from the host made safe to show: `clean_text`, then `proto::printable` on each line, so
/// nothing deceptive is left (line separators, invisible characters, ...).
fn host_text(s: &str, multiline: bool) -> String {
    let s = toolbar::clean_text(s, multiline, MAX_HOST_TEXT);
    s.split('\n').map(printable).collect::<Vec<_>>().join("\n")
}

/// Text from the host on one line, for the log and one-line messages.
fn host_line(s: &str) -> String {
    printable(&s.replace('\n', " "))
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
    // A view-only session still gets the host's clipboard, but changes nothing there.
    match Clipboard::spawn(move |t| {
        if let Some(s) = weak.upgrade().filter(|s| !s.view_only) {
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
    dim(app.ui_fb().px.as_mut_slice());
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
    // Cleared before the first event is taken, so an event queued meanwhile gets a wakeup of
    // its own; also from the tick, so a wakeup that went astray cannot leave events waiting.
    app.events_posted.store(false, Ordering::SeqCst);
    drain_events(&app.events, &app.events_posted, hwnd, |ev| {
        let after = with_ui(|ui| ui.handle(ev)).unwrap_or(After::Nothing);
        follow_up(hwnd, after);
    });
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
        // Shared icons from the resource build.rs embeds (null in test builds: the default icon).
        let icon = |metric| {
            let size = GetSystemMetrics(metric);
            LoadImageW(hinst, super::launcher::ICON_ID as usize as *const u16, IMAGE_ICON, size, size, LR_SHARED) as HICON
        };
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinst,
            hIcon: icon(SM_CXICON),
            hIconSm: icon(SM_CXSMICON),
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

/// Frames are repainted at most this often (a host sends at most 120 a second).
const FRAME_GAP: Duration = Duration::from_millis(8);
/// Smooth (HALFTONE) scaling takes 5-10 ns per source pixel painted, or 13-20 ns per window
/// pixel when enlarging. Measured into an offscreen DC on a 6-core desktop CPU: 45-85 ms for a
/// whole 4K frame shrunk into a window, 120-140 ms for 1440p enlarged to 4K, 130-175 ms for 5K
/// shown on 4K or 5K, 260-300 ms for 8192x8192 shown on 4K. One paint smooths at most this many
/// (window pixels, times the source pixels behind each when shrinking): a whole frame of the
/// common 4K-class and 5K screens (3840x2400, 4096x2160, 5120x2160, 5120x2880) in a window, or
/// of any screen enlarged to fill a 4K or 5K one, so that such an update shows one frame. A
/// larger one (`Scaling`) is scaled by dropping pixels while the picture moves (COLORONCOLOR:
/// 10-30 ms for 8192x8192 on 4K) and smoothed once it stands still, in bands of this many with
/// input and the keyboard hook getting their turn in between: whatever its screen size, a host
/// never makes one paint take longer than a 5K screen does (under 0.2 s on that CPU, little
/// more than 1440p enlarged to 4K; a hook Windows drops for waiting too long is put back:
/// `KeyHook`).
const PAINT_PIXELS: i64 = 15 << 20;
/// What was painted unsmoothed while it moved (`Scaling::Rough`) is smoothed once no such
/// update came for this long (ms).
const REFINE_MS: u32 = 150;
/// A remote screen shown at less than a quarter of its width and height (a thumbnail) is
/// scaled by dropping pixels (COLORONCOLOR, a few ms at any size) instead of smoothed, so an
/// enormous screen announced by a host does not make every frame cost a smoothing of all of it.
const SMOOTH_MAX_SHRINK: i64 = 16;

/// Paces repaints for new frames (`show_frame`). UI thread only.
#[derive(Clone, Copy)]
struct Pace {
    /// When the latest paint started.
    painted: Option<Instant>,
    /// Part of a still picture is still to be smoothed (`Scaling::Band`).
    banding: bool,
    /// A frame arrived while banding: shown after the last band.
    waiting: bool,
    /// `T_FRAME` is set.
    timer: bool,
    /// Window area of the frames shown since the latest paint (`invalidate_dirty`).
    fresh: Option<RECT>,
    /// Window area painted unsmoothed (`Scaling::Rough`), to be smoothed at `T_REFINE`.
    rough: Option<RECT>,
}

thread_local! {
    static PACE: Cell<Pace> =
        const { Cell::new(Pace { painted: None, banding: false, waiting: false, timer: false, fresh: None, rough: None }) };
}

/// How long a new frame waits to be painted after a paint that started at `painted`.
fn frame_wait(now: Instant, painted: Option<Instant>) -> Duration {
    painted.map_or(Duration::ZERO, |t| (t + FRAME_GAP).saturating_duration_since(now))
}

/// Whether an image of `src` pixels shown on `dst` window pixels is smoothed.
fn smooth(src: i64, dst: i64) -> bool {
    src <= SMOOTH_MAX_SHRINK * dst
}

/// Splits a smoothed paint of `update` (window coordinates) into the band to paint now and the
/// rest, when the part of it inside `image` (showing `src` pixels on `dst`) is more than
/// `PAINT_PIXELS` of work; `None` if it all fits.
fn paint_band(update: &RECT, image: &RECT, src: i64, dst: i64) -> Option<(RECT, RECT)> {
    let (left, right) = (update.left.max(image.left), update.right.min(image.right));
    let (top, bottom) = (update.top.max(image.top), update.bottom.min(image.bottom));
    if left >= right || top >= bottom || dst <= 0 {
        return None;
    }
    let row = (right - left) as i64 * src.max(dst) / dst;
    let rows = (PAINT_PIXELS / row.max(1)).max(1);
    if rows >= (bottom - top) as i64 {
        return None;
    }
    let split = top + rows as i32;
    Some((RECT { left, top, right, bottom: split }, RECT { left, top: split, right, bottom }))
}

/// How `paint` scales an update.
enum Scaling {
    /// Smoothed (HALFTONE), in one pass.
    Smooth,
    /// Dropping pixels (COLORONCOLOR): a thumbnail (`smooth`).
    Fast,
    /// Dropping pixels for now, in one pass: new frames that changed more than one paint
    /// smooths. In bands they would show parts of different frames, as the session's reader
    /// keeps copying in newer ones meanwhile. Smoothed once the picture stands still.
    Rough,
    /// Smoothed, the first rect now and the second in the next WM_PAINT: more than one paint
    /// smooths, of a picture that stands still (new frames wait for the last band).
    Band(RECT, RECT),
}

/// How an update (window coordinates) of `image` (showing `src` remote pixels on `dst`) is
/// painted, `fresh` being the area of it new frames changed.
fn scaling(update: &RECT, fresh: Option<&RECT>, image: &RECT, src: i64, dst: i64) -> Scaling {
    if !smooth(src, dst) {
        return Scaling::Fast;
    }
    match paint_band(update, image, src, dst) {
        None => Scaling::Smooth,
        Some(_) if fresh.is_some_and(|f| paint_band(f, image, src, dst).is_some()) => Scaling::Rough,
        Some((band, rest)) => Scaling::Band(band, rest),
    }
}

/// The smallest rect holding `a` (if any) and `b`.
fn union_rect(a: Option<RECT>, b: RECT) -> RECT {
    a.map_or(b, |a| RECT { left: a.left.min(b.left), top: a.top.min(b.top), right: a.right.max(b.right), bottom: a.bottom.max(b.bottom) })
}

/// Shows the frames decoded since the last call: invalidates what they changed, at most once
/// per `FRAME_GAP`, and not while a still picture is being smoothed in bands (or the next
/// frame's invalidation would restart it at the top every time, and the bottom would never be
/// painted); then after its last band. A frame that changed more than one paint smooths does
/// not wait: it is painted at once, unsmoothed, along with the bands left (`Scaling::Rough`).
fn show_frame(hwnd: HWND) {
    let mut p = PACE.get();
    let now = Instant::now();
    // (Bands follow each other at once; one that never came, say for a minimized window,
    // holds frames back for a second at most.)
    if p.banding && p.painted.is_some_and(|t| now.saturating_duration_since(t) < Duration::from_secs(1)) {
        if large_frame_waiting(hwnd) {
            PACE.set(Pace { banding: false, waiting: false, ..p });
            invalidate_dirty(hwnd);
            return;
        }
        p.waiting = true;
    } else if !p.timer {
        let wait = frame_wait(now, p.painted);
        // Windows rounds the delay up to its timer resolution.
        p.timer = !wait.is_zero() && unsafe { SetTimer(hwnd, T_FRAME, wait.as_millis().max(1) as u32, None) } != 0;
        if !p.timer {
            PACE.set(Pace { banding: false, waiting: false, ..p });
            invalidate_dirty(hwnd);
            return;
        }
    }
    PACE.set(p);
}

fn paint(hwnd: HWND) {
    let app = APP.get().unwrap();
    let started = Instant::now();
    let fresh = PACE.get().fresh;
    let (mut rest, mut rough) = (None, None);
    unsafe {
        let mut ps: PAINTSTRUCT = std::mem::zeroed();
        let hdc = BeginPaint(hwnd, &mut ps);
        let (cw, ch) = client_size(hwnd);
        let top = app.top.load(Ordering::SeqCst).clamp(0, ch.max(0));
        let fb = app.ui_fb();
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
                let (src, dst) = (fw as i64 * fh as i64, dw as i64 * dh as i64);
                let how = scaling(&ps.rcPaint, fresh.as_ref(), &d, src, dst);
                if matches!(how, Scaling::Fast | Scaling::Rough) {
                    SetStretchBltMode(hdc, COLORONCOLOR);
                } else {
                    SetStretchBltMode(hdc, HALFTONE);
                    SetBrushOrgEx(hdc, 0, 0, null_mut());
                }
                match how {
                    // Smoothing costs what the clip region covers: paint one band of a large update.
                    Scaling::Band(band, more) => {
                        IntersectClipRect(hdc, band.left, band.top, band.right, band.bottom);
                        rest = Some(more);
                    }
                    Scaling::Rough => rough = Some(ps.rcPaint),
                    Scaling::Smooth | Scaling::Fast => {}
                }
                StretchDIBits(hdc, d.left, d.top, dw, dh, 0, 0, fw, fh, bits, &bmi, DIB_RGB_COLORS, SRCCOPY);
            }
        }
        drop(fb);
        EndPaint(hwnd, &ps);
        if let Some(r) = &rest {
            InvalidateRect(hwnd, r, 0);
        }
        if rough.is_some() {
            // (Again at every such update: it comes once the picture stands still.)
            SetTimer(hwnd, T_REFINE, REFINE_MS, None);
        }
    }
    let mut p = PACE.get();
    p.painted = Some(started);
    p.fresh = None;
    p.banding = rest.is_some();
    if let Some(r) = rough {
        p.rough = Some(union_rect(p.rough, r));
    }
    let show = !p.banding && std::mem::take(&mut p.waiting);
    PACE.set(p);
    if show {
        show_frame(hwnd);
    }
}

/// At `T_REFINE`: smooths what was painted unsmoothed while it moved (`Scaling::Rough`).
fn refine(hwnd: HWND) {
    unsafe { KillTimer(hwnd, T_REFINE) };
    let p = PACE.get();
    if let Some(r) = p.rough {
        PACE.set(Pace { rough: None, ..p });
        unsafe { InvalidateRect(hwnd, &r, 0) };
    }
}

/// The window area showing remote pixels `r` of a `fw`x`fh` screen shown in `d`, with two
/// pixels of slack for the halftone filter.
fn window_area(d: &RECT, r: &Rect, fw: i64, fh: i64) -> RECT {
    let (dw, dh) = ((d.right - d.left) as i64, (d.bottom - d.top) as i64);
    RECT {
        left: d.left + (r.x as i64 * dw / fw) as i32 - 2,
        top: d.top + (r.y as i64 * dh / fh) as i32 - 2,
        right: d.left + (((r.x + r.w) as i64 * dw + fw - 1) / fw) as i32 + 2,
        bottom: d.top + (((r.y + r.h) as i64 * dh + fh - 1) / fh) as i32 + 2,
    }
}

/// The window area showing the remote pixels changed since they were last shown
/// (`Framebuffer::dirty`, taken if `take`), with the image rect and its remote and window
/// pixel counts.
fn dirty_area(hwnd: HWND, take: bool) -> Option<(RECT, RECT, i64, i64)> {
    let app = APP.get().unwrap();
    let (dirty, fw, fh) = {
        let mut fb = app.ui_fb();
        (if take { fb.dirty.take() } else { fb.dirty }, fb.w as i64, fb.h as i64)
    };
    let r = dirty?;
    if fw <= 0 || fh <= 0 {
        return None;
    }
    let d = image_rect(hwnd, fw as i32, fh as i32);
    let (dw, dh) = ((d.right - d.left) as i64, (d.bottom - d.top) as i64);
    if dw <= 0 || dh <= 0 {
        return None;
    }
    Some((window_area(&d, &r, fw, fh), d, fw * fh, dw * dh))
}

/// Invalidates the window region covering the remote pixels that changed.
fn invalidate_dirty(hwnd: HWND) {
    let Some((wr, ..)) = dirty_area(hwnd, true) else { return };
    unsafe { InvalidateRect(hwnd, &wr, 0) };
    let p = PACE.get();
    PACE.set(Pace { fresh: Some(union_rect(p.fresh, wr)), ..p });
}

/// Whether the frames waiting to be shown changed more than one paint smooths (`Scaling::Rough`).
fn large_frame_waiting(hwnd: HWND) -> bool {
    dirty_area(hwnd, false).is_some_and(|(wr, d, src, dst)| smooth(src, dst) && paint_band(&wr, &d, src, dst).is_some())
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

/// An unassigned virtual key, pressed on the host while a modifier is down there that is used
/// for a chord staying local or that is let go of because the focus left, so that its release
/// does not count as a press of that modifier alone: Alt alone opens the menu bar of the
/// focused program, Win alone the Start menu. AutoHotkey masks with the same key. A Linux host
/// has no such key and ignores it.
const VK_MASK: u16 = 0xe8;
/// kbd.h `SCANCODE_SIMULATED`: Windows sets it on keys it makes up itself, such as the Left
/// Ctrl it adds to Right Alt on layouts with AltGr (scancode 0x21D).
const SCANCODE_SIMULATED: u16 = 0x200;
/// That Left Ctrl's scancode, under which it is tracked (`routes`).
const ALTGR_CTRL: u16 = 0x1d | SCANCODE_SIMULATED;
/// `dwExtraInfo` of the keys the viewer presses on the local system itself (`press_locally`);
/// the hook lets them through. Another program sending it only keeps its keys on this PC.
const LOCAL_TAG: usize = 0x5352_4450;
/// Key events the hook remembers, so the window can tell which messages it handled already.
const HOOK_SEEN: usize = 32;

/// Unicode text typed in the viewer: 1 once some was kept from the host, 2 once that is logged.
static UNICODE_TEXT: AtomicU8 = AtomicU8::new(0);

fn release_all(app: &App) {
    app.mods.store(0, Ordering::SeqCst);
    lock(&app.swallowed).clear();
    lock(&app.shared).clear();
    let routes = std::mem::take(&mut *lock(&app.routes));
    if app.buttons.swap(0, Ordering::SeqCst) != 0 {
        unsafe { ReleaseCapture() };
    }
    if let Some(s) = app.input() {
        if modifier_on_host(&routes) {
            mask(&s);
        }
        s.send(ClientMsg::ReleaseAll);
    }
}

/// Whether a modifier is held down on the host (`routes`).
fn modifier_on_host(routes: &HashMap<u16, bool>) -> bool {
    routes.iter().any(|(&vk, &local)| !local && is_modifier(vk))
}

/// Presses and releases `VK_MASK` on the host.
fn mask(s: &Session) {
    for flags in [0, KEY_UP] {
        s.send(ClientMsg::Key { vk: VK_MASK, scan: 0, flags });
    }
}

/// Handles a physical key event while the viewer is in the foreground. Returns true if the
/// event was consumed (forwarded or used as a hotkey) and must not reach the local system.
/// `hooked`: it comes from the low-level hook, before the system acted on it.
fn on_key(app: &App, vk: u16, scan: u16, extended: bool, up: bool, hooked: bool) -> bool {
    if app.local_keys.load(Ordering::SeqCst) {
        return false;
    }
    if vk == VK_PACKET {
        // Text a program types as Unicode characters (auto-type, emoji panel): the scancode
        // field holds a character, not a key position, and the host can only press keys. It
        // stays here rather than pressing unrelated keys there.
        let _ = UNICODE_TEXT.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
        return false;
    }
    // Not a key of the keyboard (AltGr's Left Ctrl): the host's own layout decides what AltGr
    // does, and as Ctrl here it would turn AltGr+Enter and AltGr+End into the hotkeys.
    let unsure = app.left_ctrl_unsure.load(Ordering::SeqCst);
    let scan = if vk == VK_LCONTROL { left_ctrl_scan(&lock(&app.routes), scan, hooked, unsure) } else { scan };
    let simulated = is_simulated(vk, scan);
    let bit = if simulated { 0 } else { mod_bit(vk) };
    if bit != 0 {
        if up {
            app.mods.fetch_and(!bit, Ordering::SeqCst);
        } else {
            app.mods.fetch_or(bit, Ordering::SeqCst);
        }
    }
    // Win always reaches the local system in a window, so it is read from there: the release of
    // Win+L happens on the lock screen, where this hook never sees it.
    let win = unsafe { GetAsyncKeyState(VK_LWIN as i32) < 0 || GetAsyncKeyState(VK_RWIN as i32) < 0 };
    let mods = app.mods.load(Ordering::SeqCst) | if win { MOD_WIN } else { 0 };
    if simulated {
        // Never sent. It reaches the local system where its Right Alt does (the same rules
        // apply to both), tracked under its scancode so that it cannot take over the route
        // of a real Left Ctrl held down.
        let to_host = app.input().is_some();
        return !stays_local(app.is_fullscreen(), mods, scan, up, to_host, &mut lock(&app.routes));
    }
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
    // Decided with the session check, so `routes` records where every press really went.
    let session = session.filter(|s| !s.view_only);
    let to_host = session.is_some();
    let (local, moved) = {
        let mut routes = lock(&app.routes);
        let first = !up && !routes.contains_key(&vk);
        if first && vk == VK_LCONTROL {
            app.left_ctrl_unsure.store(!hooked, Ordering::SeqCst);
        }
        let local = stays_local(app.is_fullscreen(), mods, vk, up, to_host, &mut routes);
        // A chord that stays local needs the modifiers pressed before it, which went to the
        // host (the Alt of Alt+Tab, the Ctrl of Ctrl+Win+Right): they are pressed here too.
        // Only from the hook; a window message comes after the system acted on the key.
        let moved = if hooked && to_host && local && first { share_modifiers(&routes, &mut lock(&app.shared)) } else { Vec::new() };
        (local, moved)
    };
    if !moved.is_empty() {
        if let Some(s) = &session {
            // They stay down there too; their release must not count as a press of its own.
            mask(s);
        }
        if press_locally(&moved, vk, scan, extended) {
            return true;
        }
        let mut shared = lock(&app.shared);
        for m in &moved {
            shared.remove(m);
        }
        return false;
    }
    let shared = if up { lock(&app.shared).remove(&vk) } else { lock(&app.shared).contains(&vk) };
    let Some(s) = session.filter(|_| !local) else { return false };
    let mut flags = if up { KEY_UP } else { 0 };
    if extended {
        flags |= KEY_EXTENDED;
    }
    s.send(ClientMsg::Key { vk, scan, flags });
    // A shared modifier goes on to the local system as well.
    !shared
}

/// A key event Windows made up itself rather than one from the keyboard. (A Unicode
/// character in the scancode field of VK_PACKET is no such mark.)
fn is_simulated(vk: u16, scan: u16) -> bool {
    vk != VK_PACKET && scan & SCANCODE_SIMULATED != 0
}

/// Keys that only modify others, and so do something of their own when pressed alone.
fn is_modifier(vk: u16) -> bool {
    matches!(
        vk,
        VK_SHIFT | VK_LSHIFT | VK_RSHIFT | VK_CONTROL | VK_LCONTROL | VK_RCONTROL | VK_MENU | VK_LMENU | VK_RMENU | VK_LWIN | VK_RWIN
    )
}

/// The modifiers held down on the host (`routes`) that are not shared yet, for a chord that
/// stays local: they become shared, to be pressed on the local system as well.
fn share_modifiers(routes: &HashMap<u16, bool>, shared: &mut HashSet<u16>) -> Vec<u16> {
    let mut moved: Vec<u16> =
        routes.iter().filter(|&(&vk, &local)| !local && is_modifier(vk) && !shared.contains(&vk)).map(|(&vk, _)| vk).collect();
    moved.sort_unstable();
    shared.extend(&moved);
    moved
}

/// Presses `mods` and then the key on the local system in place of the key's own event (which
/// the hook swallows), so that the system sees the whole chord. Their releases are passed on
/// as they come. False if Windows did not take them.
fn press_locally(mods: &[u16], vk: u16, scan: u16, extended: bool) -> bool {
    let inputs = chord_inputs(mods, vk, scan, extended);
    unsafe { SendInput(inputs.len() as u32, inputs.as_ptr(), size_of::<INPUT>() as i32) as usize == inputs.len() }
}

/// The key presses of `press_locally`, tagged for the hook.
fn chord_inputs(mods: &[u16], vk: u16, scan: u16, extended: bool) -> Vec<INPUT> {
    let key = |vk: u16, (scan, extended): (u16, bool)| INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: if extended { KEYEVENTF_EXTENDEDKEY } else { 0 },
                time: 0,
                dwExtraInfo: LOCAL_TAG,
            },
        },
    };
    mods.iter().map(|&m| key(m, modifier_scan(m))).chain([key(vk, (scan, extended))]).collect()
}

/// The key position (set-1 scancode, extended) of a modifier, for pressing it here.
fn modifier_scan(vk: u16) -> (u16, bool) {
    match vk {
        VK_SHIFT | VK_LSHIFT => (0x2a, false),
        VK_RSHIFT => (0x36, false),
        VK_CONTROL | VK_LCONTROL => (0x1d, false),
        VK_RCONTROL => (0x1d, true),
        VK_MENU | VK_LMENU => (0x38, false),
        VK_RMENU => (0x38, true),
        VK_LWIN => (0x5b, true),
        VK_RWIN => (0x5c, true),
        _ => (0, false),
    }
}

/// The left or right virtual key the hook reports for a modifier, from the either-side one of a
/// window message, so that a key pressed with the hook and released without it (or the other
/// way round) is the same key in `routes`.
fn sided_vk(vk: u16, scan: u16, extended: bool) -> u16 {
    match vk {
        VK_SHIFT if scan == 0x36 => VK_RSHIFT,
        VK_SHIFT => VK_LSHIFT,
        VK_CONTROL if extended => VK_RCONTROL,
        VK_CONTROL => VK_LCONTROL,
        VK_MENU if extended => VK_RMENU,
        VK_MENU => VK_LMENU,
        _ => vk,
    }
}

/// Whether a Ctrl key message (`msg`, `wp`, `lp`, stamped `time`) is the Left Ctrl Windows
/// makes up for AltGr. The message has no room for its scancode's mark (`SCANCODE_SIMULATED`)
/// that the hook sees, but Windows posts it right before the Right Alt it goes with, for the
/// press and for the release, with the same time: it is told by the message after it (`next`),
/// as browsers do.
fn altgr_ctrl(msg: u32, wp: WPARAM, lp: LPARAM, time: u32, next: &MSG) -> bool {
    let up = |m: u32| matches!(m, WM_KEYUP | WM_SYSKEYUP);
    let extended = |lp: LPARAM| (lp >> 24) & 1 != 0;
    wp as u16 == VK_CONTROL
        && !extended(lp)
        && matches!(next.message, WM_KEYDOWN | WM_KEYUP | WM_SYSKEYDOWN | WM_SYSKEYUP)
        && up(next.message) == up(msg)
        && next.wParam as u16 == VK_MENU
        && extended(next.lParam)
        && next.time == time
}

/// `altgr_ctrl` with the next key message in the queue, which stays there.
fn altgr_ctrl_queued(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM, time: u32) -> bool {
    if wp as u16 != VK_CONTROL {
        return false;
    }
    let mut next = MSG::default();
    // Input only: a character an earlier key left in the queue (posted, so it comes before
    // input) is not the message after this one.
    let queued = unsafe { PeekMessageW(&mut next, hwnd, WM_KEYFIRST, WM_KEYLAST, PM_NOREMOVE | PM_QS_INPUT) != 0 };
    queued && altgr_ctrl(msg, wp, lp, time, &next)
}

/// The scancode a Left Ctrl event (`hooked`: seen by the hook) is handled under, `ALTGR_CTRL`
/// for AltGr's. The hook always tells the two apart; a window message cannot always
/// (`altgr_ctrl`: the Right Alt may not be queued yet), and then takes AltGr's for a real one.
/// Where a window message may have mixed them up, an event whose own key is not held goes
/// where the other one's went, so that a press, its auto-repeats (Windows repeats AltGr's Left
/// Ctrl with its Right Alt, each told apart or not) and its release share one route: AltGr's
/// joins a Left Ctrl pressed through a window message (`unsure`), which went to the host and
/// set Ctrl here, and is repeated and released as one; a Left Ctrl from a window message joins
/// AltGr's. Otherwise each keeps its own route, so a real Left Ctrl held through AltGr stays
/// down on the host. (A real Left Ctrl pressed through a window message and AltGr's then count
/// as one key: rare, and nothing is left held either way.)
fn left_ctrl_scan(routes: &HashMap<u16, bool>, scan: u16, hooked: bool, unsure: bool) -> u16 {
    let held = |key: u16| routes.contains_key(&key);
    if is_simulated(VK_LCONTROL, scan) {
        if unsure && !held(scan) && held(VK_LCONTROL) { modifier_scan(VK_LCONTROL).0 } else { scan }
    } else if !hooked && !held(VK_LCONTROL) && held(ALTGR_CTRL) {
        ALTGR_CTRL
    } else {
        scan
    }
}

/// Whether a key event goes to the local desktop instead of the host. In a window the
/// Windows key with everything pressed while it is held (Win+D, Win+E, ...) and Alt+Tab /
/// Alt+Esc / Ctrl+Esc stay local (like mstsc's default); in full screen everything goes to
/// the host; without a session that takes input (`to_host` false) everything stays local.
/// Auto-repeats and the release of a key follow its first press (`routes`); a release whose
/// press was not seen here (it went to another window or a menu) stays local.
fn stays_local(fullscreen: bool, mods: u8, vk: u16, up: bool, to_host: bool, routes: &mut HashMap<u16, bool>) -> bool {
    if up {
        return routes.remove(&vk).unwrap_or(true);
    }
    if let Some(&local) = routes.get(&vk) {
        return local;
    }
    let local = !to_host
        || (!fullscreen
            && (matches!(vk, VK_LWIN | VK_RWIN)
                || mods & MOD_WIN != 0
                || (mods & MOD_ALT != 0 && matches!(vk, VK_TAB | VK_ESCAPE))
                || (mods & MOD_CTRL != 0 && vk == VK_ESCAPE)));
    routes.insert(vk, local);
    local
}

/// The modifier `on_key` tracks for `vk`. Not Win: that is read from the system.
fn mod_bit(vk: u16) -> u8 {
    match vk {
        VK_CONTROL | VK_LCONTROL | VK_RCONTROL => MOD_CTRL,
        VK_MENU | VK_LMENU | VK_RMENU => MOD_ALT,
        _ => 0,
    }
}

/// The low-level keyboard hook. It belongs to the UI thread, which also runs its callback.
struct KeyHook {
    handle: HHOOK,
    /// A key message reached the window without passing the hook: Windows dropped it (it does
    /// so silently once the hook misses its time limit, for instance while this thread paints a
    /// very large frame), or it could not be installed.
    missed: bool,
    /// Times of the latest key events the hook saw (`KBDLLHOOKSTRUCT::time`, which is what
    /// `GetMessageTime` reports for the message of an event it passed on).
    seen: VecDeque<u32>,
}

impl KeyHook {
    const fn new() -> KeyHook {
        KeyHook { handle: null_mut(), missed: false, seen: VecDeque::new() }
    }

    fn saw(&mut self, time: u32) {
        if self.seen.len() == HOOK_SEEN {
            self.seen.pop_front();
        }
        self.seen.push_back(time);
    }

    /// Whether the hook handled the key message stamped `time` already (it passed the key on);
    /// if not, it is gone.
    fn handled(&mut self, time: u32) -> bool {
        let seen = self.seen.contains(&time);
        self.missed |= !seen;
        seen
    }

    /// At a timer tick: true when the hook is to be installed afresh, which is only after it
    /// missed a key. Not while it works: a fresh hook goes ahead of those other programs
    /// installed since (a key remapper, a screen reader), and a key held across the switch
    /// would meet a different hook for its press and for its release.
    fn due(&mut self) -> bool {
        std::mem::take(&mut self.missed)
    }
}

thread_local! {
    static KEY_HOOK: RefCell<KeyHook> = const { RefCell::new(KeyHook::new()) };
}

/// Runs `f` on the hook state unless it is already borrowed further up the stack.
fn with_hook<R>(f: impl FnOnce(&mut KeyHook) -> R) -> Option<R> {
    KEY_HOOK.try_with(|cell| cell.try_borrow_mut().ok().map(|mut h| f(&mut h))).ok().flatten()
}

/// Installs the keyboard hook, or a fresh one in place of the current one: the new hook is in
/// place before the old one goes. On failure the current one (if any) stays.
fn hook_keyboard(app: &App) -> bool {
    let new = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(ll_keyboard), GetModuleHandleW(null()), 0) };
    if new.is_null() {
        return false;
    }
    let Some(old) = with_hook(|h| {
        h.missed = false;
        std::mem::replace(&mut h.handle, new)
    }) else {
        unsafe { UnhookWindowsHookEx(new) };
        return false;
    };
    if !old.is_null() {
        unsafe { UnhookWindowsHookEx(old) };
    }
    app.hook_active.store(true, Ordering::SeqCst);
    true
}

fn unhook_keyboard(app: &App) {
    app.hook_active.store(false, Ordering::SeqCst);
    if let Some(h) = with_hook(|h| std::mem::replace(&mut h.handle, null_mut())).filter(|h| !h.is_null()) {
        unsafe { UnhookWindowsHookEx(h) };
    }
}

/// From the timer: installs the hook afresh once it missed a key (`KeyHook::due`).
fn rehook(app: &App) {
    if with_hook(KeyHook::due) == Some(true) {
        hook_keyboard(app);
    }
    if UNICODE_TEXT.compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
        log!("note: text typed as Unicode characters (auto-type, emoji panel) is not sent to the host");
    }
}

unsafe extern "system" fn ll_keyboard(code: i32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        if code == HC_ACTION as i32 {
            let k = &*(lp as *const KBDLLHOOKSTRUCT);
            with_hook(|h| h.saw(k.time));
            // The viewer's own presses of a chord that stays local (`press_locally`).
            let ours = k.flags & LLKHF_INJECTED != 0 && k.dwExtraInfo == LOCAL_TAG;
            if let (false, Some(app)) = (ours, APP.get()) {
                let hwnd = app.hwnd();
                if !hwnd.is_null() && GetForegroundWindow() == hwnd {
                    let (vk, up) = (k.vkCode as u16, k.flags & LLKHF_UP != 0);
                    // The release of a key held down on this PC goes on to it as well, whatever
                    // went to the host: its press reached the system past the hook (Windows had
                    // dropped it, or the key went down before the viewer had the focus), and
                    // swallowed, it would leave the key down here. Its message is then known as
                    // passed on (`KeyHook::handled`), so the host still gets it once. (In the
                    // hook, the key's state is still the one before this event.)
                    if on_key(app, vk, k.scanCode as u16, k.flags & LLKHF_EXTENDED != 0, up, true)
                        && !(up && GetAsyncKeyState(vk as i32) < 0)
                    {
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
    let bit = 1u8 << button;
    // The last button let go of ends the capture whether or not a session takes input (one may
    // have ended mid-drag).
    if !down && app.buttons.fetch_and(!bit, Ordering::SeqCst) & !bit == 0 {
        unsafe { ReleaseCapture() };
    }
    let Some(s) = app.input() else { return };
    let (x, y) = point(lp);
    let (x, y) = to_remote(hwnd, x, y);
    s.send(ClientMsg::MouseMove { x, y });
    s.send(ClientMsg::MouseButton { button, down });
    if down && app.buttons.fetch_or(bit, Ordering::SeqCst) == 0 {
        unsafe { SetCapture(hwnd) };
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
                app.frame_posted.store(false, Ordering::SeqCst);
                show_frame(hwnd);
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
                        rehook(app);
                    }
                    T_RECONNECT => {
                        with_ui(|ui| ui.launch_attempt());
                    }
                    T_FRAME => {
                        KillTimer(hwnd, T_FRAME);
                        PACE.set(Pace { timer: false, ..PACE.get() });
                        show_frame(hwnd);
                    }
                    T_REFINE => refine(hwnd),
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
                app.cursor_posted.store(false, Ordering::SeqCst);
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
            WM_WTSSESSION_CHANGE => {
                if matches!(wp as u32, WTS_SESSION_LOCK | WTS_SESSION_UNLOCK) {
                    release_all(app);
                }
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
                // Handled here unless the low-level hook saw the key first and passed it on:
                // every key while there is no hook (it could not be installed, or Windows
                // dropped it), with system shortcuts staying local. Such a key has the hook
                // installed afresh at the next tick.
                let time = GetMessageTime() as u32;
                let seen = with_hook(|h| h.handled(time)).unwrap_or(false) && app.hook_active.load(Ordering::SeqCst);
                if !seen && GetForegroundWindow() == hwnd {
                    let mut scan = ((lp >> 16) & 0xff) as u16;
                    let extended = (lp >> 24) & 1 != 0;
                    let up = msg == WM_KEYUP || msg == WM_SYSKEYUP;
                    // Named as the hook names it, so that it is no Ctrl here or on the host.
                    if altgr_ctrl_queued(hwnd, msg, wp, lp, time) {
                        scan |= SCANCODE_SIMULATED;
                    }
                    if on_key(app, sided_vk(wp as u16, scan, extended), scan, extended, up, false) {
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
                WTSUnRegisterSessionNotification(hwnd);
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

    /// A session over a loopback connection, with no threads; the other end is returned too.
    fn loopback_session(flags: u32, view_only: bool) -> (Session, TcpStream) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let sock = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let peer = l.accept().unwrap().0;
        let s = Session {
            generation: 1,
            out: OutQueue::default(),
            sock,
            flags,
            view_only,
            start: Instant::now(),
            reconnected: false,
            ended: AtomicBool::new(false),
            frames: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            last_rx_ms: AtomicU64::new(0),
            rtt_ms: AtomicU64::new(UNSET),
            last_notice_ms: AtomicU64::new(UNSET),
            sound: AtomicBool::new(false),
            pull: Mutex::new(Pull::default()),
            clipboard: Mutex::new(None),
            xfer: Mutex::new(Transfers::default()),
        };
        (s, peer)
    }

    #[test]
    fn shutdown_wakes_a_reader_blocked_on_a_silent_host() {
        use std::io::Read;
        // The host stays connected and silent: only the shutdown can end the read.
        let (s, _host) = loopback_session(0, false);
        let mut sock = s.sock.try_clone().unwrap();
        let reader = std::thread::spawn(move || sock.read(&mut [0u8; 16]));
        std::thread::sleep(Duration::from_millis(200));
        assert!(!reader.is_finished(), "nothing was sent, so the read blocks");
        s.shutdown();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !reader.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(reader.is_finished(), "the reader is still blocked after the shutdown");
        assert!(s.is_ended());
    }

    #[test]
    fn view_only_sessions_transfer_no_files() {
        assert!(loopback_session(F_FILES, false).0.files_allowed());
        assert!(!loopback_session(F_FILES, true).0.files_allowed());
        assert!(!loopback_session(0, false).0.files_allowed());
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
    fn a_refused_fallback_names_its_own_session() {
        let series = |since| Reconnect {
            since,
            attempt: 0,
            due: None,
            in_flight: None,
            cause: String::new(),
            last_error: None,
            instance_unanswered: false,
        };
        let refused = || Error::msg(format!("{}another viewer is using this host", core::REFUSED));
        let unanswered = Error::msg(core::HELLO_UNANSWERED);
        let mut rc = series(Instant::now());
        assert!(rc.names(true));
        // The link breaks between the hello and the answer: the next hello leaves the instance
        // out, and the host, which still holds this viewer's session, turns that one away.
        assert!(rc.failed(&unanswered, true) && !rc.names(true));
        assert!(rc.failed(&refused(), true), "gave up on its own session");
        assert!(rc.names(true) && rc.attempt == 2);
        // Turned away with the instance, too: another viewer's session. Stop.
        assert!(!rc.failed(&refused(), true));
        // A host that never announced instances, or a refusal of a hello that named the
        // session: final at once.
        assert!(!series(Instant::now()).failed(&refused(), false));
        let mut rc = series(Instant::now());
        rc.instance_unanswered = true;
        assert!(!rc.failed(&refused(), false));
        // And never beyond RECONNECT_FOR.
        if let Some(long_ago) = Instant::now().checked_sub(core::RECONNECT_FOR) {
            let mut rc = series(long_ago);
            rc.instance_unanswered = true;
            assert!(!rc.failed(&refused(), true));
        }
    }

    #[test]
    fn files_arrive_only_when_asked() {
        let mut p = Pull::default();
        // Nothing requested: refused even in the session's first millisecond, and no toast
        // (nobody asked, so nothing was missed).
        assert_eq!(p.begin(0), None);
        assert_eq!(p.begin(5), None);
        p.progress(5);
        assert_eq!(p.begin(6), None);
        assert!(!p.tell_refused());
        p.request(1000);
        p.begin(1000 + PULL_WINDOW_MS - 1).expect("first file within the window");
        // A new file alone never keeps the window open...
        assert_eq!(p.begin(1000 + PULL_WINDOW_MS), None);
        // ...progress on an accepted file does.
        p.progress(40_000);
        assert!(p.begin(40_000 + PULL_WINDOW_MS - 1).is_some());
        assert_eq!(p.begin(40_000 + PULL_WINDOW_MS), None);
        // Too late after a request: told once per click.
        assert!(p.tell_refused() && !p.tell_refused());
        p.request(100_000);
        assert!(p.tell_refused());
    }

    #[test]
    fn a_second_click_does_not_cut_off_the_first_batch() {
        // The host sends one batch at a time and answers a second click with a notice only.
        let mut p = Pull::default();
        p.request(0);
        assert!(p.begin(10).is_some()); // a large file A
        p.request(20_000); // clicked again while A is still arriving
        for t in (20_000..200_000).step_by(10_000) {
            p.progress(t); // A's data keeps coming
        }
        assert!(p.begin(200_001).is_some(), "B, the next file of the first batch, was refused");
        // Long pulls keep going as long as data flows, with no overall time limit.
        for t in (200_000..10_000_000).step_by(20_000) {
            p.progress(t);
        }
        assert!(p.begin(10_000_001).is_some());
    }

    #[test]
    fn one_click_accepts_a_bounded_pull() {
        let mut p = Pull::default();
        p.request(0);
        for i in 0..PULL_MAX_FILES as u64 {
            assert!(p.begin(i).is_some(), "file {i}");
            p.progress(i);
        }
        assert_eq!(p.begin(PULL_MAX_FILES as u64), None);
        // A new click starts a new budget.
        p.request(2000);
        assert!(p.begin(2001).is_some());
        // Without progress the window closes again.
        assert_eq!(p.begin(2000 + PULL_WINDOW_MS + 5_000), None);
    }

    #[test]
    fn host_events_cannot_flood_the_ui() {
        let mut q = VecDeque::new();
        let notice = |g: u64, t: &str| Event::Notice { generation: g, text: t.into() };
        let state = |key: u8, value: u32| Event::State { generation: 1, key, value, states: 1 };
        assert!(enqueue(&mut q, notice(1, "a")));
        assert!(!enqueue(&mut q, notice(1, "b")), "merged into the queued notice");
        assert!(enqueue(&mut q, notice(2, "c")));
        assert!(enqueue(&mut q, state(SET_AUDIO, 1)));
        assert!(!enqueue(&mut q, state(SET_AUDIO, 0)));
        assert!(enqueue(&mut q, state(SET_PRIVACY, 1)));
        assert_eq!(q.len(), 4);
        assert!(matches!(&q[0], Event::Notice { text, .. } if text == "b"));
        // The merged state still counts as both answers.
        assert!(matches!(q[2], Event::State { key: SET_AUDIO, value: 0, states: 2, .. }));
        let toast = |i: usize| Event::Toast { generation: 1, tone: Tone::Info, title: i.to_string(), text: String::new(), action: None };
        for i in 0..1000 {
            enqueue(&mut q, toast(i));
        }
        assert_eq!(q.len(), MAX_EVENTS);
        assert!(!enqueue(&mut q, notice(3, "late")));
        assert!(!enqueue(&mut q, state(9, 1)), "a state of no real setting is dropped");
        // An answer to a counted `Set` is never dropped, and still merges.
        assert!(enqueue(&mut q, state(SET_QUALITY, 1)));
        assert!(!enqueue(&mut q, state(SET_QUALITY, 2)));
        // The end of a session is never dropped.
        let ended =
            Event::Ended { generation: 1, kind: EndKind::Closed, reason: String::new(), lifetime: Duration::ZERO, since_notice: None };
        assert!(enqueue(&mut q, ended));
        assert_eq!(q.len(), MAX_EVENTS + 2);
    }

    /// Posted to a null window, messages go to this test thread's own queue (no window).
    #[test]
    fn host_wakeups_wait_once_and_let_timers_in() {
        let take = |kind: u32| {
            let mut msg: MSG = unsafe { std::mem::zeroed() };
            let mut n = 0;
            while unsafe { PeekMessageW(&mut msg, null_mut(), kind, kind, PM_REMOVE) } != 0 {
                n += 1;
            }
            n
        };
        take(WM_APP_FRAME); // creates the queue
        let pending = AtomicBool::new(false);
        for _ in 0..10_000 {
            post_once(null_mut(), &pending, WM_APP_FRAME);
        }
        assert_eq!(take(WM_APP_FRAME), 1);
        // Until the handler clears the flag, nothing more is posted; then the next one is.
        post_once(null_mut(), &pending, WM_APP_FRAME);
        assert_eq!(take(WM_APP_FRAME), 0);
        pending.store(false, Ordering::SeqCst);
        post_once(null_mut(), &pending, WM_APP_FRAME);
        post_once(null_mut(), &pending, WM_APP_FRAME);
        assert_eq!(take(WM_APP_FRAME), 1);

        // A due timer and two posted wakeups: GetMessage alone returns the posts first; right
        // after a host-triggered message, the timer goes first.
        let timer = unsafe { SetTimer(null_mut(), 0, 10, None) };
        assert_ne!(timer, 0);
        std::thread::sleep(Duration::from_millis(100));
        for _ in 0..2 {
            unsafe { PostMessageW(null_mut(), WM_APP_FRAME, 0, 0) };
        }
        let mut msg: MSG = unsafe { std::mem::zeroed() };
        assert!(unsafe { next_message(&mut msg, false) });
        assert_eq!(msg.message, WM_APP_FRAME);
        assert!(host_triggered(&msg, null_mut()) && !host_triggered(&msg, std::ptr::dangling_mut()));
        assert!(unsafe { next_message(&mut msg, true) });
        assert_eq!(msg.message, WM_TIMER);
        assert!(!host_triggered(&msg, null_mut()));
        assert!(unsafe { next_message(&mut msg, false) });
        assert_eq!(msg.message, WM_APP_FRAME);
        unsafe { KillTimer(null_mut(), timer) };
        take(WM_TIMER);
    }

    /// Removes every queued `kind` message of this thread; how many there were.
    fn take_all(hwnd: HWND, kind: u32) -> usize {
        let mut msg: MSG = unsafe { std::mem::zeroed() };
        let mut n = 0;
        while unsafe { PeekMessageW(&mut msg, hwnd, kind, kind, PM_REMOVE) } != 0 {
            n += 1;
        }
        n
    }

    #[test]
    fn a_state_flood_leaves_one_wakeup_waiting() {
        // A message-only window (never shown) owned by this thread stands in for the viewer's.
        let hwnd = unsafe {
            let class = wide("SafeRdpTestEvents");
            let hinst = GetModuleHandleW(null());
            let wc = WNDCLASSW { lpfnWndProc: Some(DefWindowProcW), hInstance: hinst, lpszClassName: class.as_ptr(), ..std::mem::zeroed() };
            RegisterClassW(&wc);
            CreateWindowExW(0, class.as_ptr(), null(), 0, 0, 0, 0, 0, HWND_MESSAGE, null_mut(), hinst, null())
        };
        assert!(!hwnd.is_null());
        let events = Arc::new(Mutex::new(VecDeque::new()));
        let posted = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        // The reader: every `State` of two settings, flipping between two values, as fast as it can.
        let reader = {
            let (events, posted, stop, target) = (events.clone(), posted.clone(), stop.clone(), hwnd as usize);
            std::thread::spawn(move || {
                let mut sent = 0u64;
                while !stop.load(Ordering::SeqCst) {
                    for (key, value) in [(SET_QUALITY, 0), (SET_DOWNSCALE, 1), (SET_QUALITY, 1), (SET_DOWNSCALE, 2)] {
                        post_event(&events, &posted, target as HWND, Event::State { generation: 1, key, value, states: 1 });
                        sent += 1;
                    }
                }
                sent
            })
        };
        // The UI thread handles each event far more slowly than the reader sends them.
        let (mut wakeups, mut handled, mut most_waiting) = (0, 0u64, 0);
        let until = Instant::now() + Duration::from_millis(400);
        while Instant::now() < until {
            let waiting = take_all(hwnd, WM_APP_EVENT);
            most_waiting = most_waiting.max(waiting);
            if waiting > 0 {
                wakeups += 1;
                posted.store(false, Ordering::SeqCst);
                drain_events(&events, &posted, hwnd, |_| {
                    handled += 1;
                    let t = Instant::now();
                    while t.elapsed() < Duration::from_micros(200) {}
                });
            }
        }
        stop.store(true, Ordering::SeqCst);
        let sent = reader.join().unwrap();
        assert!(most_waiting <= 1, "{most_waiting} wakeups waited at once");
        assert!(wakeups > 10 && handled < sent, "{wakeups} wakeups, {handled} of {sent} states handled");
        // The viewer's own posts still get in.
        assert_ne!(unsafe { PostMessageW(hwnd, WM_APP_FULLSCREEN, 0, 0) }, 0);
        assert_eq!(take_all(hwnd, WM_APP_FULLSCREEN), 1);
        take_all(hwnd, WM_APP_EVENT);
        unsafe { DestroyWindow(hwnd) };
    }

    #[test]
    fn repaints_are_paced_and_banded() {
        let t0 = Instant::now();
        assert_eq!(frame_wait(t0, None), Duration::ZERO);
        assert_eq!(frame_wait(t0 + Duration::from_millis(3), Some(t0)), FRAME_GAP - Duration::from_millis(3));
        assert_eq!(frame_wait(t0 + FRAME_GAP * 2, Some(t0)), Duration::ZERO);
        // Smoothed down to a quarter of the width and height; a thumbnail drops pixels instead.
        assert!(smooth(3840 * 2160, 1920 * 1080) && smooth(7680 * 4320, 1920 * 1080));
        assert!(!smooth(8192 * 8192, 1920 * 1080) && !smooth(7680 * 4320, 1280 * 720));
        assert!(smooth(1280 * 720, 2560 * 1440));
        let rect = |left, top, right, bottom| RECT { left, top, right, bottom };
        let image = rect(0, 40, 1920, 1120);
        let (k4, k8, p1080) = (3840 * 2160, 7680 * 4320, 1920 * 1080);
        // A small update is painted whole, and so is a whole 4K frame in a 1080p window (four
        // source pixels behind each window pixel), or a whole 1440p one enlarged to 4K (enlarging
        // costs per window pixel).
        assert!(paint_band(&rect(10, 50, 200, 300), &image, k4, p1080).is_none());
        let all = rect(0, 0, 1920, 1200);
        assert!(paint_band(&all, &image, k4, p1080).is_none());
        let screen = rect(0, 0, 3840, 2160);
        assert!(paint_band(&screen, &screen, 2560 * 1440, k4).is_none());
        // 8K in a 1080p window: bands of `PAINT_PIXELS` of work.
        let (band, rest) = paint_band(&all, &image, k8, p1080).unwrap();
        let rows = PAINT_PIXELS / (1920 * 16);
        assert_eq!((band.left, band.top, band.right, band.bottom), (0, 40, 1920, 40 + rows as i32));
        assert_eq!((rest.left, rest.top, rest.right, rest.bottom), (0, 40 + rows as i32, 1920, 1120));
        // Band after band makes its way down to the bottom.
        let (mut update, mut bands) = (all, 0);
        while let Some((_, rest)) = paint_band(&update, &image, k8, p1080) {
            (update, bands) = (rest, bands + 1);
        }
        assert_eq!(bands + 1, 1080usize.div_ceil(rows as usize), "one paint per band");
        // A band is at least one row; nothing outside the image.
        let narrow = rect(0, 0, 4, 4);
        let (band, _) = paint_band(&narrow, &narrow, 8192 * 8192, 16).unwrap();
        assert_eq!(band.bottom - band.top, 1);
        assert!(paint_band(&rect(0, 0, 1920, 40), &image, k8, p1080).is_none());
    }

    #[test]
    fn moving_pictures_are_never_painted_in_bands() {
        let rect = |left, top, right, bottom| RECT { left, top, right, bottom };
        let kind = |s: Scaling| match s {
            Scaling::Smooth => "smooth",
            Scaling::Fast => "fast",
            Scaling::Rough => "rough",
            Scaling::Band(..) => "band",
        };
        let (image, all, small) = (rect(0, 40, 1920, 1120), rect(0, 0, 1920, 1200), rect(100, 100, 300, 200));
        let (k4, k8, p1080) = (3840 * 2160, 7680 * 4320, 1920 * 1080);
        // A 4K host in a 1080p window: every update smoothed whole, frames or not.
        assert_eq!(kind(scaling(&all, Some(&all), &image, k4, p1080)), "smooth");
        assert_eq!(kind(scaling(&all, None, &image, k4, p1080)), "smooth");
        // An 8K one: frames changing that much drop pixels, in one pass, until the picture stands
        // still; then it is smoothed in bands, as is a still picture shown afresh (a resize).
        assert_eq!(kind(scaling(&all, Some(&all), &image, k8, p1080)), "rough");
        assert_eq!(kind(scaling(&all, None, &image, k8, p1080)), "band");
        // A small change goes along with the bands of a larger update (later ones wait for them)
        // and is smoothed whole on its own.
        assert_eq!(kind(scaling(&all, Some(&small), &image, k8, p1080)), "band");
        assert_eq!(kind(scaling(&small, Some(&small), &image, k8, p1080)), "smooth");
        // A thumbnail always drops pixels.
        assert_eq!(kind(scaling(&all, Some(&all), &image, 8192 * 8192, p1080)), "fast");
        assert_eq!(kind(scaling(&small, None, &image, 8192 * 8192, p1080)), "fast");
        // What was painted unsmoothed adds up until it is smoothed.
        let r = union_rect(Some(rect(10, 20, 30, 40)), rect(0, 30, 20, 50));
        assert_eq!((r.left, r.top, r.right, r.bottom), (0, 20, 30, 50));
        let r = union_rect(None, small);
        assert_eq!((r.left, r.top, r.right, r.bottom), (100, 100, 300, 200));
        // The window area of a change, with slack for the halftone filter.
        let a = window_area(&image, &Rect { x: 0, y: 0, w: 3840, h: 2160 }, 3840, 2160);
        assert_eq!((a.left, a.top, a.right, a.bottom), (-2, 38, 1922, 1122));
        let a = window_area(&image, &Rect { x: 1, y: 1, w: 2, h: 2 }, 3840, 2160);
        assert_eq!((a.left, a.top, a.right, a.bottom), (-2, 38, 4, 44));
    }

    #[test]
    fn common_4k_and_5k_screens_move_smoothed() {
        // Whole frames of them, shrunk into a window or enlarged to fill a 4K or 5K one.
        let screens = [(3840, 2160), (3840, 2400), (4096, 2160), (5120, 2160), (5120, 2880), (2560, 1600), (1920, 1200), (2560, 1440)];
        let windows = [(1920, 1097), (2560, 1377), (2880, 1800), (3840, 2120), (3840, 2160), (3840, 2400), (5120, 2880)];
        for (fw, fh) in screens {
            for (cw, ch) in windows {
                let image = dest_rect(cw, ch, fw, fh);
                let dst = (image.right - image.left) as i64 * (image.bottom - image.top) as i64;
                let all = RECT { left: 0, top: 0, right: cw, bottom: ch };
                let how = scaling(&all, Some(&all), &image, fw as i64 * fh as i64, dst);
                assert!(matches!(how, Scaling::Smooth), "{fw}x{fh} in {cw}x{ch}");
            }
        }
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

    /// Clicks on a feature toggle, then the host's answers (`states` per event); returns
    /// whether the feature ends up on and how often the host was told to turn it off again.
    fn settle(on: bool, clicks: usize, answers: &[(u32, u32)]) -> (bool, usize, u32) {
        let (mut on, mut asked, mut refused) = (on, Asked::default(), 0);
        for _ in 0..clicks {
            on = !on;
            asked.sent(on as u32);
        }
        for &(value, states) in answers {
            let refuse;
            (on, refuse) = feature_state(on, &asked.reply(states), value);
            if refuse {
                refused += 1;
                asked.sent(0);
            }
        }
        (on, refused, asked.due)
    }

    #[test]
    fn hello_wishes_count_as_asked() {
        // Sound wished in the hello; off and on clicked before the host's answer to the hello.
        let (mut asked, mut on, mut refused) = (Asked::default(), true, 0);
        asked.wished(1);
        for v in [0, 1] {
            on = v == 1;
            asked.sent(v);
        }
        for value in [1, 0, 1] {
            let refuse;
            (on, refuse) = feature_state(on, &asked.reply(1), value);
            refused += refuse as u32;
        }
        assert_eq!((on, refused, asked.due), (true, 0, 0));
        // An answer to the hello alone is not one the user clicked for.
        let mut a = Asked::default();
        a.wished(1);
        assert!(a.quiet);
        assert_eq!(a.answer(1), (Reply::Latest(1), false));
        a.wished(1);
        a.sent(0);
        assert!(!a.quiet);
        assert_eq!(a.answer(2), (Reply::Latest(0), true));
    }

    #[test]
    fn the_viewers_own_refusals_are_no_clicks() {
        // The host turns sound on by itself, then reports it unavailable, again and again. Each
        // time the viewer turns it off again (as `on_state` does), and the host's answer to that
        // is no answer to a click: no refusal toast, and no relayout of the bar.
        let (mut a, mut on) = (Asked::default(), false);
        for _ in 0..3 {
            let (reply, clicked) = a.answer(1);
            assert!(!clicked);
            let refuse;
            (on, refuse) = feature_state(on, &reply, 1);
            assert!(!on && refuse);
            a.sent(0);
            a.quiet = true;
            assert_eq!(a.answer(1), (Reply::Latest(0), false));
        }
        assert_eq!(a.due, 0);
        // A click while that refusal is unanswered is one again; its answer comes last.
        a.sent(0);
        a.quiet = true;
        a.sent(1);
        assert_eq!(a.answer(1), (Reply::Stale, false));
        assert_eq!(a.answer(1), (Reply::Latest(1), true));
    }

    #[test]
    fn quick_clicks_end_as_the_last_click() {
        // On, then off and on again within one round trip: the outdated "off" changes nothing.
        assert_eq!(settle(true, 2, &[(0, 1), (1, 1)]), (true, 0, 0));
        // The same answers merged in the queue.
        assert_eq!(settle(true, 2, &[(1, 2)]), (true, 0, 0));
        // Off, then on, then off: the host's "on" for the middle click does not turn it on.
        assert_eq!(settle(true, 3, &[(0, 1), (1, 1), (0, 1)]), (false, 0, 0));
        assert_eq!(settle(false, 2, &[(1, 1), (0, 1)]), (false, 0, 0));
        // The host keeps it on although the latest click asked for off: told again.
        assert_eq!(settle(true, 1, &[(1, 1)]), (false, 1, 1));
        // Refused, or turned on by the host unasked.
        assert_eq!(settle(false, 1, &[(0, 1)]), (false, 0, 0));
        assert_eq!(settle(false, 0, &[(1, 1)]), (false, 1, 1));
        assert_eq!(settle(true, 0, &[(0, 1), (1, 1)]), (false, 1, 1));
        // More answers than questions: the extra ones are the host's own, held to the choice.
        assert_eq!(settle(true, 1, &[(1, 3)]), (false, 1, 1));
        assert_eq!(settle(false, 1, &[(1, 3)]), (true, 0, 0));
    }

    #[test]
    fn answers_are_matched_to_the_latest_request() {
        let mut a = Asked::default();
        assert_eq!(a.reply(1), Reply::Unasked);
        a.sent(2);
        a.sent(0);
        assert_eq!(a.reply(1), Reply::Stale);
        assert_eq!(a.reply(1), Reply::Latest(0));
        assert_eq!(a.reply(1), Reply::Unasked);
        a.sent(1);
        a.sent(3);
        a.sent(2);
        assert_eq!(a.reply(2), Reply::Stale);
        assert_eq!(a.reply(1), Reply::Latest(2));
        assert_eq!(a.due, 0);
    }

    #[test]
    fn windows_key_chords_stay_local_in_a_window() {
        let (mut r, win, d, e) = (HashMap::new(), MOD_WIN, b'D' as u16, b'E' as u16);
        // Win+D: every event stays local, so the host gets no 'd' and Start does not open.
        assert!(stays_local(false, win, VK_LWIN, false, true, &mut r));
        assert!(stays_local(false, win, d, false, true, &mut r));
        assert!(stays_local(false, win, d, true, true, &mut r));
        assert!(stays_local(false, 0, VK_LWIN, true, true, &mut r));
        assert!(r.is_empty());
        // Shift pressed before Win keeps going to the host, auto-repeats and release included.
        assert!(!stays_local(false, 0, VK_LSHIFT, false, true, &mut r));
        assert!(stays_local(false, win, VK_LWIN, false, true, &mut r));
        assert!(!stays_local(false, win, VK_LSHIFT, false, true, &mut r));
        assert!(!stays_local(false, win, VK_LSHIFT, true, true, &mut r));
        // A key pressed during the chord is released locally, even after Win went up.
        assert!(stays_local(false, win, e, false, true, &mut r));
        assert!(stays_local(false, 0, VK_LWIN, true, true, &mut r));
        assert!(stays_local(false, 0, e, true, true, &mut r));
        assert!(!stays_local(false, 0, e, false, true, &mut r));
        assert!(!stays_local(false, 0, e, true, true, &mut r));
        // Alt+Tab stays local (Alt itself goes to the host; `share_modifiers` presses it here too).
        assert!(!stays_local(false, MOD_ALT, VK_LMENU, false, true, &mut r));
        assert!(stays_local(false, MOD_ALT, VK_TAB, false, true, &mut r));
        assert!(!stays_local(false, 0, VK_LMENU, true, true, &mut r));
        assert!(stays_local(false, 0, VK_TAB, true, true, &mut r));
        // Full screen: everything goes to the host.
        assert!(!stays_local(true, win, VK_LWIN, false, true, &mut r));
        assert!(!stays_local(true, win, d, false, true, &mut r));
        assert!(!stays_local(true, win, d, true, true, &mut r));
        assert!(!stays_local(true, 0, VK_LWIN, true, true, &mut r));
        assert!(r.is_empty());
        // Pressed before the viewer had the focus: the release is not swallowed either.
        assert!(stays_local(true, 0, VK_RETURN, true, true, &mut r));
    }

    #[test]
    fn keys_after_a_lost_windows_release_reach_the_host() {
        // Win+L: the release of Win happens on the lock screen and is never seen here. Win is
        // not tracked (it is read from the system), so nothing keeps later keys local.
        let mut mods = 0;
        for vk in [VK_LWIN, VK_RWIN] {
            mods |= mod_bit(vk);
        }
        assert_eq!(mods, 0);
        assert!(!stays_local(false, mods, b'A' as u16, false, true, &mut HashMap::new()));
        assert_eq!(mod_bit(VK_RCONTROL), MOD_CTRL);
        assert_eq!(mod_bit(VK_LMENU), MOD_ALT);
    }

    #[test]
    fn keys_pressed_without_a_session_are_released_locally() {
        let mut r = HashMap::new();
        // Shift pressed while reconnecting (or view-only) goes to the local system, and so do
        // its auto-repeats and its release after the session is back: it never sticks here.
        assert!(stays_local(false, 0, VK_LSHIFT, false, false, &mut r));
        assert!(stays_local(false, 0, VK_LSHIFT, false, true, &mut r));
        assert!(stays_local(false, 0, VK_LSHIFT, true, true, &mut r));
        assert!(stays_local(true, 0, VK_LSHIFT, false, false, &mut r));
        assert!(stays_local(true, 0, VK_LSHIFT, true, true, &mut r));
        assert!(r.is_empty());
    }

    #[test]
    fn chords_staying_local_take_the_modifiers_along() {
        let (mut r, mut shared) = (HashMap::new(), HashSet::new());
        // Ctrl and Shift went to the host, then Esc stays local (Ctrl+Shift+Esc): both are
        // pressed here as well, once. A held letter is no modifier and stays with the host.
        assert!(!stays_local(false, MOD_CTRL, VK_LCONTROL, false, true, &mut r));
        assert!(!stays_local(false, MOD_CTRL, VK_LSHIFT, false, true, &mut r));
        assert!(!stays_local(false, MOD_CTRL, b'W' as u16, false, true, &mut r));
        assert!(stays_local(false, MOD_CTRL, VK_ESCAPE, false, true, &mut r));
        assert!(modifier_on_host(&r));
        assert_eq!(share_modifiers(&r, &mut shared), [VK_LSHIFT, VK_LCONTROL]);
        assert!(share_modifiers(&r, &mut shared).is_empty());
        // Their releases still follow the presses to the host (shared, they also go on here).
        assert!(!stays_local(false, 0, VK_LSHIFT, true, true, &mut r));
        assert!(!stays_local(false, 0, VK_LCONTROL, true, true, &mut r));
        assert!(!modifier_on_host(&r));
        // Win stays local itself, so nothing is handed over for Win+D.
        let mut r = HashMap::new();
        assert!(stays_local(false, MOD_WIN, VK_LWIN, false, true, &mut r));
        assert!(stays_local(false, MOD_WIN, b'D' as u16, false, true, &mut r));
        assert!(!modifier_on_host(&r));
        assert!(share_modifiers(&r, &mut HashSet::new()).is_empty());
    }

    #[test]
    fn local_chords_are_pressed_whole_and_tagged() {
        let inputs = chord_inputs(&[VK_LMENU, VK_RCONTROL], VK_TAB, 0x0f, false);
        let keys: Vec<(u16, u16, u32, usize)> = inputs
            .iter()
            .map(|i| {
                assert_eq!(i.r#type, INPUT_KEYBOARD);
                let k = unsafe { i.Anonymous.ki };
                (k.wVk, k.wScan, k.dwFlags, k.dwExtraInfo)
            })
            .collect();
        let tag = LOCAL_TAG;
        assert_eq!(keys, [(VK_LMENU, 0x38, 0, tag), (VK_RCONTROL, 0x1d, KEYEVENTF_EXTENDEDKEY, tag), (VK_TAB, 0x0f, 0, tag)]);
    }

    #[test]
    fn window_messages_name_the_same_modifiers_as_the_hook() {
        let pairs = [
            (VK_SHIFT, VK_LSHIFT),
            (VK_SHIFT, VK_RSHIFT),
            (VK_CONTROL, VK_LCONTROL),
            (VK_CONTROL, VK_RCONTROL),
            (VK_MENU, VK_LMENU),
            (VK_MENU, VK_RMENU),
        ];
        for (either, sided) in pairs {
            let (scan, extended) = modifier_scan(sided);
            assert_eq!(sided_vk(either, scan, extended), sided);
            assert_eq!(mod_bit(sided), mod_bit(either));
            assert!(is_modifier(sided) && is_modifier(either));
        }
        assert_eq!(sided_vk(b'A' as u16, 0x1e, false), b'A' as u16);
        assert!(!is_modifier(VK_TAB) && !is_modifier(VK_MASK));
    }

    #[test]
    fn altgr_left_ctrl_is_not_a_key() {
        assert!(is_simulated(VK_LCONTROL, 0x21d));
        assert!(!is_simulated(VK_LCONTROL, 0x1d));
        // A character in VK_PACKET's scancode field (U+0263) is no such mark.
        assert!(!is_simulated(VK_PACKET, 0x263));
        // Tracked under its scancode, it leaves a real Left Ctrl's route alone: that Ctrl went
        // to the host and is still released there.
        let mut r = HashMap::new();
        assert!(!stays_local(false, MOD_CTRL, VK_LCONTROL, false, true, &mut r));
        assert!(!stays_local(false, MOD_CTRL, 0x21d, false, true, &mut r));
        assert!(!stays_local(false, MOD_CTRL | MOD_ALT, VK_RMENU, false, true, &mut r));
        assert!(!stays_local(false, MOD_CTRL, 0x21d, true, true, &mut r));
        assert!(!stays_local(false, MOD_CTRL, VK_RMENU, true, true, &mut r));
        assert!(!stays_local(false, MOD_CTRL, VK_LCONTROL, true, true, &mut r));
        // Without a session that takes input it reaches the local system, like its Right Alt.
        assert!(stays_local(false, 0, 0x21d, false, false, &mut r));
        assert!(stays_local(false, 0, 0x21d, true, true, &mut r));
        assert!(r.is_empty());
    }

    fn key_msg(message: u32, vk: u16, scan: isize, extended: bool, time: u32) -> MSG {
        let lp = 1 | scan << 16 | (extended as isize) << 24;
        MSG { message, wParam: vk as WPARAM, lParam: lp, time, ..MSG::default() }
    }

    #[test]
    fn altgr_left_ctrl_is_told_from_window_messages_too() {
        let altgr = |c: &MSG, next: &MSG| altgr_ctrl(c.message, c.wParam, c.lParam, c.time, next);
        let ctrl = key_msg(WM_KEYDOWN, VK_CONTROL, 0x1d, false, 100);
        let ralt = key_msg(WM_KEYDOWN, VK_MENU, 0x38, true, 100);
        assert!(altgr(&ctrl, &ralt));
        assert!(altgr(&key_msg(WM_KEYUP, VK_CONTROL, 0x1d, false, 300), &key_msg(WM_SYSKEYUP, VK_MENU, 0x38, true, 300)));
        // A real Left Ctrl: a Right Alt at another time, a Left Alt, a release, a character
        // (Ctrl+R is 0x12, VK_MENU's number) or nothing after it.
        assert!(!altgr(&ctrl, &key_msg(WM_KEYDOWN, VK_MENU, 0x38, true, 101)));
        assert!(!altgr(&ctrl, &key_msg(WM_SYSKEYDOWN, VK_MENU, 0x38, false, 100)));
        assert!(!altgr(&ctrl, &key_msg(WM_KEYUP, VK_MENU, 0x38, true, 100)));
        assert!(!altgr(&ctrl, &key_msg(WM_CHAR, VK_MENU, 0x13, true, 100)));
        assert!(!altgr(&ctrl, &MSG::default()));
        // Right Ctrl never is.
        assert!(!altgr(&key_msg(WM_KEYDOWN, VK_CONTROL, 0x1d, true, 100), &ralt));
        // Named as the hook names it: Left Ctrl with the marked scancode, which is not tracked
        // as Ctrl and never sent.
        let scan = 0x1d | SCANCODE_SIMULATED;
        assert_eq!((sided_vk(VK_CONTROL, scan, false), scan), (VK_LCONTROL, ALTGR_CTRL));
        assert!(is_simulated(VK_LCONTROL, scan));
    }

    #[test]
    fn a_left_ctrl_is_released_where_its_press_went() {
        let mut r = HashMap::new();
        // AltGr pressed while the hook was gone and released through a fresh one: its Left
        // Ctrl is the same key both times, and nothing is left held.
        assert!(!stays_local(false, 0, ALTGR_CTRL, false, true, &mut r));
        assert_eq!(left_ctrl_scan(&r, ALTGR_CTRL, true, false), ALTGR_CTRL);
        assert!(!stays_local(false, MOD_ALT, ALTGR_CTRL, true, true, &mut r));
        assert!(r.is_empty());
        // Its press taken for a real Left Ctrl by a window message (the Right Alt was not
        // queued yet) went to the host and set Ctrl: the release, told apart, still lets go of
        // it there and here.
        assert!(!stays_local(false, MOD_CTRL, VK_LCONTROL, false, true, &mut r));
        for hooked in [true, false] {
            let scan = left_ctrl_scan(&r, ALTGR_CTRL, hooked, true);
            assert!(!is_simulated(VK_LCONTROL, scan));
            assert_eq!((scan, mod_bit(VK_LCONTROL)), (0x1d, MOD_CTRL));
        }
        // A Left Ctrl pressed through the hook is a real one: AltGr's keeps its own route.
        assert_eq!(left_ctrl_scan(&r, ALTGR_CTRL, true, false), ALTGR_CTRL);
        assert!(!stays_local(false, 0, VK_LCONTROL, true, true, &mut r));
        assert!(r.is_empty());
        // And the other way round: its release taken for a real one by a window message ends
        // its own route. Through the hook that is a real Left Ctrl, which keeps its own.
        assert!(!stays_local(false, 0, ALTGR_CTRL, false, true, &mut r));
        assert_eq!(left_ctrl_scan(&r, 0x1d, false, false), ALTGR_CTRL);
        assert_eq!(left_ctrl_scan(&r, 0x1d, true, false), 0x1d);
        assert!(!stays_local(false, 0, ALTGR_CTRL, true, true, &mut r));
        assert!(r.is_empty());
        // Both held, or neither: each event is what it says.
        assert!(!stays_local(false, MOD_CTRL, VK_LCONTROL, false, true, &mut r));
        assert!(!stays_local(false, MOD_CTRL, ALTGR_CTRL, false, true, &mut r));
        for (hooked, unsure) in [(true, false), (false, true)] {
            assert_eq!(left_ctrl_scan(&r, ALTGR_CTRL, hooked, unsure), ALTGR_CTRL);
            assert_eq!(left_ctrl_scan(&r, 0x1d, hooked, unsure), 0x1d);
            assert_eq!(left_ctrl_scan(&HashMap::new(), ALTGR_CTRL, hooked, unsure), ALTGR_CTRL);
            assert_eq!(left_ctrl_scan(&HashMap::new(), 0x1d, hooked, unsure), 0x1d);
        }
    }

    /// What `on_key` keeps about the Left Ctrl keys: `routes`, `mods`, `left_ctrl_unsure`.
    #[derive(Default)]
    struct LeftCtrl {
        routes: HashMap<u16, bool>,
        mods: u8,
        unsure: bool,
    }

    impl LeftCtrl {
        fn idle(&self) -> bool {
            self.routes.is_empty() && self.mods == 0
        }
    }

    /// `on_key` for a Left Ctrl event (`scan` as the hook or `altgr_ctrl` names it, `hooked`:
    /// seen by the hook) with a session that takes input: whether it goes to the host.
    fn left_ctrl_event(k: &mut LeftCtrl, scan: u16, up: bool, hooked: bool) -> bool {
        let scan = left_ctrl_scan(&k.routes, scan, hooked, k.unsure);
        if is_simulated(VK_LCONTROL, scan) {
            stays_local(false, k.mods, scan, up, true, &mut k.routes);
            return false;
        }
        if up {
            k.mods &= !mod_bit(VK_LCONTROL);
        } else {
            k.mods |= mod_bit(VK_LCONTROL);
        }
        if !up && !k.routes.contains_key(&VK_LCONTROL) {
            k.unsure = !hooked;
        }
        !stays_local(false, k.mods, VK_LCONTROL, up, true, &mut k.routes)
    }

    #[test]
    fn a_left_ctrl_is_repeated_where_its_press_went() {
        const HOOK: bool = true;
        const WINDOW: bool = false;
        let mut k = LeftCtrl::default();
        // AltGr held while Windows had dropped the hook: its press reached the window before
        // its Right Alt and was taken for a real Left Ctrl, which went to the host. A fresh
        // hook tells the auto-repeats and the release apart: they are still that Left Ctrl's,
        // so the host lets go of it, and Ctrl is not left set here.
        assert!(left_ctrl_event(&mut k, 0x1d, false, WINDOW));
        for _ in 0..4 {
            assert!(left_ctrl_event(&mut k, ALTGR_CTRL, false, HOOK));
        }
        assert_eq!(k.mods, MOD_CTRL);
        assert!(left_ctrl_event(&mut k, ALTGR_CTRL, true, HOOK));
        assert!(k.idle());
        // The other way round: told apart when pressed, one auto-repeat through the window not
        // told apart, released told apart. Nothing goes to the host, nothing is left held.
        assert!(!left_ctrl_event(&mut k, ALTGR_CTRL, false, HOOK));
        assert!(!left_ctrl_event(&mut k, 0x1d, false, WINDOW));
        assert!(!left_ctrl_event(&mut k, ALTGR_CTRL, false, HOOK));
        assert!(!left_ctrl_event(&mut k, ALTGR_CTRL, true, HOOK));
        assert!(k.idle());
        // A real Left Ctrl alone, and AltGr alone, are untouched.
        for path in [HOOK, WINDOW] {
            assert!(left_ctrl_event(&mut k, 0x1d, false, path) && left_ctrl_event(&mut k, 0x1d, false, path));
            assert!(left_ctrl_event(&mut k, 0x1d, true, path));
            assert!(!left_ctrl_event(&mut k, ALTGR_CTRL, false, path) && !left_ctrl_event(&mut k, ALTGR_CTRL, true, path));
            assert!(k.idle());
        }
        // A real Left Ctrl held through a tap of AltGr (Ctrl+AltGr, then Ctrl+W): the hook
        // tells the two apart, so the host keeps Left Ctrl down until the real one goes up.
        for real_first in [true, false] {
            assert!(left_ctrl_event(&mut k, 0x1d, false, HOOK));
            assert!(!left_ctrl_event(&mut k, ALTGR_CTRL, false, HOOK));
            if !real_first {
                assert!(!left_ctrl_event(&mut k, ALTGR_CTRL, true, HOOK));
                assert_eq!((k.routes.get(&VK_LCONTROL), k.mods), (Some(&false), MOD_CTRL), "let go of on the host");
            }
            assert!(left_ctrl_event(&mut k, 0x1d, true, HOOK));
            if real_first {
                assert!(!left_ctrl_event(&mut k, ALTGR_CTRL, true, HOOK));
            }
            assert!(k.idle());
        }
        // Pressed through a window message, the real one cannot be told from AltGr's, which
        // goes with it. Let go in either order, nothing stays held on the host.
        for real_first in [true, false] {
            assert!(left_ctrl_event(&mut k, 0x1d, false, WINDOW));
            assert!(left_ctrl_event(&mut k, ALTGR_CTRL, false, HOOK));
            let order = if real_first { [0x1d, ALTGR_CTRL] } else { [ALTGR_CTRL, 0x1d] };
            assert!(left_ctrl_event(&mut k, order[0], true, HOOK));
            assert!(!left_ctrl_event(&mut k, order[1], true, HOOK));
            assert!(k.idle());
        }
    }

    #[test]
    fn a_dropped_hook_is_noticed_and_replaced() {
        let mut h = KeyHook::new();
        for t in 0..HOOK_SEEN as u32 + 5 {
            h.saw(t);
        }
        // The latest key events passed the hook (it decided about them already).
        assert!(h.handled(HOOK_SEEN as u32 + 4));
        assert!(h.handled(5));
        assert!(!h.missed);
        // A working hook stays, however long: a fresh one would go ahead of other programs'.
        assert!((0..1000).all(|_| !h.due()));
        // At the next tick once a key reached the window without passing it, and only then.
        assert!(!h.handled(4));
        assert!(h.missed && h.due());
        assert!(!h.due());
        // A hook that could not be installed is tried again once a key comes.
        let mut none = KeyHook::new();
        assert!(!none.due());
        assert!(!none.handled(7) && none.due());
    }

    #[test]
    fn a_key_held_across_a_new_hook_is_released_once() {
        let (mut h, mut r, a) = (KeyHook::new(), HashMap::new(), b'A' as u16);
        // Pressed while the hook was gone: sent to the host from the window message.
        assert!(!h.handled(500));
        assert!(!stays_local(false, 0, a, false, true, &mut r));
        assert!(h.due());
        // Released through the fresh hook: sent once more, as the release (and passed on to
        // this PC, which saw the press). Its message then is no key of its own.
        h.saw(900);
        assert!(!stays_local(false, 0, a, true, true, &mut r));
        assert!(h.handled(900) && !h.due());
        assert!(r.is_empty());
    }

    #[test]
    fn host_text_is_printable() {
        // Line breaks stay in toasts; escapes, bidi and invisible characters do not.
        assert_eq!(host_text("a\u{2028}b\x1b[31m\nc\u{200b}\u{202e}d\te", true), "a?b[31m\nc?d e");
        assert_eq!(host_text("ok\r\nerror:\u{2029}forged", false), "ok error:?forged");
        // One line in the log and in the final message, whatever the host sent.
        assert_eq!(host_line("x\nerror: forged"), "x error: forged");
        assert_eq!(host_line("\x1b]0;t\x07\r"), "?]0;t??");
        assert!(!host_line(&host_text(&"a\n".repeat(3000), true)).contains('\n'));
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
