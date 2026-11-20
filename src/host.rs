//! Host side: listens on the Tailscale interface, authenticates viewers and streams the screen.
//!
//! One session at a time; a new viewer replaces the current one. Inside a session:
//! * the capture thread grabs, encodes and sends frames (at most `MAX_IN_FLIGHT` unacknowledged),
//!   applies quality, scale and monitor changes and spends idle ticks on lossless refinement;
//! * the input thread handles everything the viewer sends: input, clipboard, settings, uploads;
//! * helpers run beside them: the text clipboard bridge, audio capture with its sender thread,
//!   and a file-pull thread that yields the socket to frames between chunks.
//!
//! Audio capture and privacy mode live on threads of their own and are switched off when the
//! session ends, however it ends.

use crate::channel::{self, RecordReader, RecordWriter};
use crate::codec::{self, EncodedRect, Encoder};
use crate::files::{self, Incoming, Outgoing};
use crate::net::{self, PeerPolicy};
use crate::platform::audio::AudioCapture;
use crate::platform::capture::{self, Capturer, CursorTracker};
use crate::platform::clipboard::{self, Clipboard};
use crate::platform::desktop::DesktopFollower;
use crate::platform::input::Injector;
use crate::platform::mem::LockedBuf;
use crate::platform::privacy::Privacy;
use crate::proto::*;
use crate::screen::{Area, MonitorSel};
use crate::util::{Result, Secret};
use crate::{bail, log};
use crate::audio::AdpcmEncoder;
#[cfg(windows)]
use crate::platform::clipboard::FileUser;
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub struct HostOptions {
    pub bind: Option<IpAddr>,
    pub port: u16,
    pub policy: PeerPolicy,
    pub monitor: MonitorSel,
    pub max_fps: u32,
    pub clipboard: bool,
    pub view_only: bool,
    /// Ctrl+Alt+Del is forwarded to the service (only when running under it).
    pub sas: bool,
    /// Viewers may upload files and pull the host's copied files (never in view-only mode).
    pub files: bool,
    /// Viewers may listen to the host's sound.
    pub audio: bool,
    /// Viewers may switch on privacy mode; it stays off until one asks for it.
    pub privacy: bool,
    /// `proto::QUALITY_*` for viewers whose hello names no known quality.
    pub default_quality: u32,
    /// Where uploads are saved (default: `files::transfer_dir()`).
    pub transfer_dir: Option<PathBuf>,
    /// The files a `FilePull` sends: the platform clipboard (replaceable for tests). Called on
    /// the file-pull thread.
    pub copied_files: fn() -> Vec<PathBuf>,
}

impl Default for HostOptions {
    fn default() -> Self {
        HostOptions {
            bind: None,
            port: DEFAULT_PORT,
            policy: PeerPolicy { allow: vec![], allow_non_tailscale: false, loopback_ok: false },
            monitor: MonitorSel::Primary,
            max_fps: 30,
            clipboard: false,
            view_only: false,
            sas: false,
            files: true,
            audio: true,
            privacy: true,
            default_quality: QUALITY_BALANCED,
            transfer_dir: None,
            copied_files: clipboard::copied_files,
        }
    }
}

/// Longest a handshake may take in all, however the peer paces its bytes.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Handshakes in progress at once, in all and per source address.
const MAX_PENDING: usize = 8;
const MAX_PENDING_PER_ADDR: usize = 2;
/// How long a failed handshake keeps its address's slot (slows down guessing).
const FAILURE_PENALTY: Duration = Duration::from_secs(1);
const MAX_IN_FLIGHT: u32 = 2;
/// How often the accept loop looks at its stop flag.
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// How often `bind` looks for a Tailscale address.
const TAILSCALE_POLL: Duration = Duration::from_secs(5);
/// Lines about connections that did not authenticate: logged per window, per address and in all.
const QUIET_WINDOW: Duration = Duration::from_secs(60);
const QUIET_PER_ADDR: u32 = 3;
const QUIET_TOTAL: u32 = 20;
/// Lines a viewer can cause at will (refusals) that one session logs.
const SESSION_LOG_LINES: u32 = 20;
/// Lossless refinement sent per idle capture tick.
const REFINE_BUDGET: usize = 256 * 1024;
/// Uploads a viewer may have open at once.
const MAX_UPLOADS: usize = 4;
/// Longest a file chunk waits for frames and replies to go first.
const BULK_YIELD: Duration = Duration::from_millis(100);
/// Audio packet length.
const AUDIO_PACKET_MS: usize = 20;
/// Audio packets waiting for the network before new ones are dropped (~160 ms).
const AUDIO_QUEUE: usize = 8;
const MAX_AUDIO_CHANNELS: u8 = 8;
const MAX_AUDIO_RATE: u32 = 384_000;
/// Decode limit for `Notice` and `FileResult` text.
const MAX_TEXT: usize = 4096;

/// Locks `m` even if a thread panicked while holding it: nothing guarded here can be left
/// half-updated in a harmful way (a torn record fails authentication and ends the session).
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Cuts `s` to what a viewer accepts in a notice or file result.
fn short(mut s: String) -> String {
    s.truncate(s.floor_char_boundary(MAX_TEXT));
    s
}

struct SessionCtl {
    stop: AtomicBool,
    finished: AtomicBool,
    sock: TcpStream,
}

impl SessionCtl {
    fn kick(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.sock.shutdown(Shutdown::Both);
        wake_blocked_io(&self.sock);
    }
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
    /// Waits (bounded) until the session released the screen, injected keys and its features.
    fn wait_finished(&self, limit: Duration) {
        let t = Instant::now();
        while !self.finished.load(Ordering::SeqCst) && t.elapsed() < limit {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Windows does not wake a recv or send blocked in another thread when the socket is shut down
/// (Linux does), so a kicked session would linger until its I/O timeout, privacy mode and held
/// keys included. Cancelling the socket's I/O wakes them. `sock` is a handle to the session's
/// socket that stays open as long as its `SessionCtl`, so this never touches a reused handle.
#[cfg(windows)]
fn wake_blocked_io(sock: &TcpStream) {
    use std::os::windows::io::AsRawSocket;
    unsafe { windows_sys::Win32::System::IO::CancelIoEx(sock.as_raw_socket() as _, std::ptr::null()) };
}

#[cfg(not(windows))]
fn wake_blocked_io(_sock: &TcpStream) {}

/// Ends the session when dropped, also when the owning thread panics.
struct KickOnDrop(Arc<SessionCtl>);

impl Drop for KickOnDrop {
    fn drop(&mut self) {
        self.0.kick();
    }
}

struct Host {
    opts: HostOptions,
    psk: Secret<32>,
    current: Mutex<Option<Arc<SessionCtl>>>,
    pending: Mutex<Pending>,
    quiet: Mutex<Quiet>,
    /// `serve` was told to stop: no new session may start.
    stopping: AtomicBool,
}

impl Host {
    /// Stops accepting sessions and ends the current one.
    fn shutdown(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        let cur = lock(&self.current).clone();
        if let Some(c) = cur {
            c.kick();
            c.wait_finished(Duration::from_secs(10));
        }
    }

    /// Logs a line about a connection that has not authenticated, unless `Quiet` holds it back.
    fn log_unauthenticated(&self, ip: IpAddr, line: std::fmt::Arguments) {
        let (dropped, show) = {
            let mut q = lock(&self.quiet);
            (q.roll(Instant::now()), q.allow(ip))
        };
        report_dropped(dropped);
        if show {
            log!("{line}");
        }
    }

    /// Sums up the lines `Quiet` held back once their window is over.
    fn flush_quiet(&self) {
        let dropped = lock(&self.quiet).roll(Instant::now());
        report_dropped(dropped);
    }
}

fn report_dropped(n: u64) {
    if n > 0 {
        log!("{n} more refused or failed connection attempts in the last minute were not logged");
    }
}

/// Handshakes in progress: at most `MAX_PENDING` in all and `MAX_PENDING_PER_ADDR` from one
/// address, so one peer without the key cannot keep everybody else out.
#[derive(Default)]
struct Pending {
    total: usize,
    per_addr: HashMap<IpAddr, usize>,
}

impl Pending {
    fn admit(&mut self, ip: IpAddr) -> std::result::Result<(), &'static str> {
        let n = self.per_addr.get(&ip).copied().unwrap_or(0);
        if n >= MAX_PENDING_PER_ADDR {
            return Err("too many pending handshakes from this address");
        }
        if self.total >= MAX_PENDING {
            return Err("too many pending handshakes");
        }
        self.total += 1;
        self.per_addr.insert(ip, n + 1);
        Ok(())
    }

    fn leave_total(&mut self) {
        self.total = self.total.saturating_sub(1);
    }

    fn leave_addr(&mut self, ip: IpAddr) {
        if let Some(n) = self.per_addr.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                self.per_addr.remove(&ip);
            }
        }
    }
}

/// A handshake's place in `Host::pending`, given back when dropped.
struct Slot {
    host: Arc<Host>,
    ip: IpAddr,
    /// Still counted against `MAX_PENDING`.
    counted: bool,
}

impl Slot {
    /// Gives back the place in the total but keeps the address's own (the failure penalty).
    fn uncount(&mut self) {
        if std::mem::take(&mut self.counted) {
            lock(&self.host.pending).leave_total();
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut p = lock(&self.host.pending);
        if self.counted {
            p.leave_total();
        }
        p.leave_addr(self.ip);
    }
}

/// Keeps lines about connections that never authenticated from flooding the log (anyone who
/// reaches the port causes them, as fast as it can connect): per `QUIET_WINDOW` at most
/// `QUIET_PER_ADDR` per address and `QUIET_TOTAL` in all, then one line counting the rest.
struct Quiet {
    since: Instant,
    shown: u32,
    per_addr: HashMap<IpAddr, u32>,
    dropped: u64,
}

impl Quiet {
    fn new(now: Instant) -> Quiet {
        Quiet { since: now, shown: 0, per_addr: HashMap::new(), dropped: 0 }
    }

    /// Starts a new window once the current one is over; returns how many lines the old one held back.
    fn roll(&mut self, now: Instant) -> u64 {
        if now.saturating_duration_since(self.since) < QUIET_WINDOW {
            return 0;
        }
        (self.since, self.shown) = (now, 0);
        self.per_addr.clear();
        std::mem::take(&mut self.dropped)
    }

    /// Whether a line about `ip` may be logged in the current window.
    fn allow(&mut self, ip: IpAddr) -> bool {
        let n = self.per_addr.get(&ip).copied().unwrap_or(0);
        if self.shown >= QUIET_TOTAL || n >= QUIET_PER_ADDR {
            self.dropped += 1;
            return false;
        }
        self.shown += 1;
        self.per_addr.insert(ip, n + 1);
        true
    }
}

/// Lets the first lines of a kind through, then one saying that the rest are not logged.
struct LogBudget(u32);

impl LogBudget {
    fn line(&mut self, line: String) -> Option<String> {
        match self.0 {
            0 => None,
            1 => {
                self.0 = 0;
                Some(format!("{line} (more like this in this session are not logged)"))
            }
            _ => {
                self.0 -= 1;
                Some(line)
            }
        }
    }
}

/// The handshake socket with an absolute deadline: each read and write gets only the time that
/// is left. The socket's own timeouts restart with every byte, so a peer trickling its hello
/// could otherwise hold a handshake slot for many minutes.
struct Deadline<'a> {
    s: &'a TcpStream,
    until: Instant,
}

impl Deadline<'_> {
    fn left(&self) -> std::io::Result<Duration> {
        match self.until.checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => Ok(d),
            _ => Err(ErrorKind::TimedOut.into()),
        }
    }
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.s.set_read_timeout(Some(self.left()?))?;
        let mut s = self.s;
        s.read(buf)
    }
}

impl Write for Deadline<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.s.set_write_timeout(Some(self.left()?))?;
        let mut s = self.s;
        s.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Listens on the configured address and serves viewers until the process ends.
pub fn run(opts: HostOptions, psk: Secret<32>) -> Result<()> {
    let stop = AtomicBool::new(false);
    let listener = bind(&opts, &stop)?;
    serve(listener, opts, psk, &stop)
}

/// Opens the listening socket on `opts.bind`, or on this machine's Tailscale address once
/// Tailscale is up. Fails promptly if `stop` is set while it waits.
pub fn bind(opts: &HostOptions, stop: &AtomicBool) -> Result<TcpListener> {
    let ip = match opts.bind {
        Some(ip) => ip,
        None => wait_for_address(|| net::tailscale_ipv4().map(IpAddr::V4), stop, TAILSCALE_POLL)?,
    };
    if !net::is_tailscale(ip) && !ip.is_loopback() && !opts.policy.allow_non_tailscale {
        bail!("{ip} is not a Tailscale address; pass --allow-non-tailscale to bind it anyway");
    }
    let addr = SocketAddr::new(ip, opts.port);
    let listener = TcpListener::bind(addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    log!(
        "safe-rdp host listening on {addr} (view-only: {}, clipboard: {}, files: {}, audio: {}, privacy mode: {})",
        opts.view_only,
        opts.clipboard,
        opts.files && !opts.view_only,
        opts.audio,
        if opts.privacy && !opts.view_only { "on request" } else { "never" }
    );
    Ok(listener)
}

/// Polls `find` every `every` until it yields an address; fails as soon as `stop` is set.
fn wait_for_address(find: impl Fn() -> Option<IpAddr>, stop: &AtomicBool, every: Duration) -> Result<IpAddr> {
    let mut warned = false;
    loop {
        if stop.load(Ordering::SeqCst) {
            bail!("stopped while waiting for Tailscale");
        }
        if let Some(ip) = find() {
            return Ok(ip);
        }
        if !warned {
            log!("waiting for Tailscale to come up (no 100.64.0.0/10 address yet)...");
            warned = true;
        }
        let t = Instant::now();
        while t.elapsed() < every && !stop.load(Ordering::SeqCst) {
            std::thread::sleep(ACCEPT_POLL);
        }
    }
}

/// Accepts and serves viewers on `listener` until `stop` is set, then ends the current session.
pub fn serve(listener: TcpListener, opts: HostOptions, psk: Secret<32>, stop: &AtomicBool) -> Result<()> {
    // Non-blocking accepts let the loop notice `stop`.
    listener.set_nonblocking(true)?;
    let host = Arc::new(Host {
        opts,
        psk,
        current: Mutex::new(None),
        pending: Mutex::new(Pending::default()),
        quiet: Mutex::new(Quiet::new(Instant::now())),
        stopping: AtomicBool::new(false),
    });
    while !stop.load(Ordering::SeqCst) {
        let (stream, peer) = match listener.accept() {
            Ok(c) => c,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                host.flush_quiet();
                std::thread::sleep(ACCEPT_POLL);
                continue;
            }
            Err(e) => {
                log!("accept failed: {e}");
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
        };
        // Accepted sockets can inherit the listener's non-blocking mode (they do on Windows).
        if stream.set_nonblocking(false).is_err() {
            continue;
        }
        if !host.opts.policy.allows(peer.ip()) {
            host.log_unauthenticated(peer.ip(), format_args!("refused {peer}: address not allowed"));
            continue;
        }
        let admitted = lock(&host.pending).admit(peer.ip());
        if let Err(why) = admitted {
            host.log_unauthenticated(peer.ip(), format_args!("refused {peer}: {why}"));
            continue;
        }
        let mut slot = Slot { host: host.clone(), ip: peer.ip(), counted: true };
        let h = host.clone();
        // If the thread cannot start, dropping the closure gives the slot back.
        let spawned = std::thread::Builder::new().name("session".into()).spawn(move || {
            match authenticate(&h, &stream, peer) {
                Some(keys) => {
                    drop(slot);
                    serve_session(&h, stream, peer, keys);
                }
                None => {
                    // Slow down guessing from this address without holding up anybody else.
                    slot.uncount();
                    drop(stream);
                    std::thread::sleep(FAILURE_PENALTY);
                }
            }
        });
        if let Err(e) = spawned {
            host.log_unauthenticated(peer.ip(), format_args!("refused {peer}: {e}"));
        }
    }
    host.shutdown();
    Ok(())
}

fn authenticate(host: &Host, stream: &TcpStream, peer: SocketAddr) -> Option<channel::SessionKeys> {
    let _ = stream.set_nodelay(true);
    match handshake(stream, &host.psk.0, Instant::now() + HANDSHAKE_TIMEOUT) {
        Ok(k) => Some(k),
        Err(e) => {
            host.log_unauthenticated(peer.ip(), format_args!("authentication failed for {peer}: {e}"));
            None
        }
    }
}

/// The host's side of the handshake, over by `until` however slowly the peer sends.
fn handshake(stream: &TcpStream, psk: &[u8; 32], until: Instant) -> Result<channel::SessionKeys> {
    channel::server_handshake(&mut Deadline { s: stream, until }, psk)
}

fn serve_session(host: &Arc<Host>, stream: TcpStream, peer: SocketAddr, keys: channel::SessionKeys) {
    let Ok(sock) = stream.try_clone() else { return };
    let ctl = Arc::new(SessionCtl { stop: AtomicBool::new(false), finished: AtomicBool::new(false), sock });
    let old = {
        let mut cur = lock(&host.current);
        if host.stopping.load(Ordering::SeqCst) {
            return;
        }
        cur.replace(ctl.clone())
    };
    if let Some(old) = old {
        log!("replacing the existing session");
        old.kick();
        // Let it release its screen duplication, injected keys and privacy mode first.
        old.wait_finished(Duration::from_secs(5));
    }
    log!("session started: {peer}");
    let r = run_session(host, stream, keys, &ctl);
    ctl.kick();
    {
        let mut cur = lock(&host.current);
        if cur.as_ref().is_some_and(|c| Arc::ptr_eq(c, &ctl)) {
            *cur = None;
        }
    }
    ctl.finished.store(true, Ordering::SeqCst);
    match r {
        Err(e) if e.to_string() != channel::CLOSED => log!("session ended: {peer}: {e}"),
        _ => log!("session ended: {peer} disconnected"),
    }
}

/// The sending half of a session, shared by the capture, input, clipboard, audio and file threads.
struct Out {
    w: Mutex<RecordWriter<TcpStream>>,
    /// Threads waiting to send frames or replies; bulk file data lets them go first.
    waiting: AtomicUsize,
}

impl Out {
    fn new(w: RecordWriter<TcpStream>) -> Out {
        Out { w: Mutex::new(w), waiting: AtomicUsize::new(0) }
    }

    /// Sends one complete message (type byte included).
    fn send_record(&self, rec: &[u8]) -> Result<()> {
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let mut w = lock(&self.w);
        self.waiting.fetch_sub(1, Ordering::SeqCst);
        w.send(rec)
    }

    fn send(&self, m: &ServerMsg) -> Result<()> {
        let mut b = Vec::new();
        m.encode(&mut b);
        self.send_record(&b)
    }

    /// Sends bulk data after anything that is waiting, so frames and replies keep flowing.
    fn send_bulk(&self, m: &ServerMsg) -> Result<()> {
        let t = Instant::now();
        while self.waiting.load(Ordering::SeqCst) > 0 && t.elapsed() < BULK_YIELD {
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut b = Vec::new();
        m.encode(&mut b);
        lock(&self.w).send(&b)
    }

    fn notice(&self, text: String) -> Result<()> {
        self.send(&ServerMsg::Notice(short(text)))
    }
}

/// What the viewer's coordinates refer to: the captured area at 1/`downscale` resolution.
#[derive(Clone, Copy)]
struct View {
    area: Area,
    downscale: usize,
}

struct Shared {
    acked: AtomicU32,
    refresh: AtomicBool,
    /// Milliseconds since session start of the latest input event.
    last_input_ms: AtomicU64,
    view: Mutex<View>,
    start: Instant,
}

/// How a session starts, from the viewer's hello and the host's options.
#[derive(Debug, PartialEq)]
struct Start {
    sel: MonitorSel,
    /// The host's own monitor (`HostOptions::monitor`) is not connected: `sel` is the primary one.
    monitor_missing: bool,
    downscale: usize,
    quality: u32,
    audio: bool,
    privacy: bool,
}

fn negotiate(opts: &HostOptions, downscale: u8, quality: u8, monitor: u8, flags: u8, exists: impl Fn(MonitorSel) -> bool) -> Start {
    let fallback = if opts.default_quality <= QUALITY_LOW { opts.default_quality } else { QUALITY_BALANCED };
    // What the viewer asked for, else the host's choice, else (unplugged) the primary monitor.
    let (sel, monitor_missing) = match monitor_sel(monitor as u32, opts.monitor).filter(|&s| exists(s)) {
        Some(s) => (s, false),
        None if exists(opts.monitor) => (opts.monitor, false),
        None => (MonitorSel::Primary, opts.monitor != MonitorSel::Primary),
    };
    Start {
        sel,
        monitor_missing,
        downscale: downscale.clamp(1, 4) as usize,
        quality: if quality as u32 <= QUALITY_LOW { quality as u32 } else { fallback },
        audio: flags & HELLO_AUDIO != 0,
        privacy: flags & HELLO_PRIVACY != 0,
    }
}

/// The capture source a hello / `SET_MONITOR` value names (`None` if it names none).
fn monitor_sel(v: u32, default: MonitorSel) -> Option<MonitorSel> {
    match v {
        v if v == MONITOR_DEFAULT as u32 => Some(default),
        v if v == MONITOR_ALL as u32 => Some(MonitorSel::All),
        v if v < MONITOR_DEFAULT as u32 => Some(MonitorSel::Index(v as usize)),
        _ => None,
    }
}

/// The wire value for a capture source (the primary monitor is index 0).
fn monitor_code(sel: MonitorSel) -> u8 {
    match sel {
        MonitorSel::Primary => 0,
        MonitorSel::Index(i) => i.min(0xfd) as u8,
        MonitorSel::All => MONITOR_ALL,
    }
}

/// The requested 1..=4 downscale, reduced so that the scaled picture is at least 1x1.
fn effective_downscale(area: Area, d: usize) -> usize {
    d.clamp(1, 4).min(area.width.max(1) as usize).min(area.height.max(1) as usize)
}

/// Capabilities announced in the hello.
fn host_flags(opts: &HostOptions, audio_available: bool, privacy_available: bool) -> u32 {
    let mut flags = 0;
    if opts.clipboard {
        flags |= F_CLIPBOARD;
    }
    if opts.view_only {
        flags |= F_VIEW_ONLY;
    }
    if opts.sas {
        flags |= F_SAS;
    }
    if opts.audio && audio_available {
        flags |= F_AUDIO;
    }
    if opts.files && !opts.view_only {
        flags |= F_FILES;
    }
    if opts.privacy && privacy_available && !opts.view_only {
        flags |= F_PRIVACY;
    }
    flags
}

/// Whether clipboard text from the viewer may replace the host's: not in view-only sessions,
/// which must not change anything on the host. The host's clipboard still reaches the viewer.
fn accepts_clipboard(opts: &HostOptions) -> bool {
    opts.clipboard && !opts.view_only
}

fn run_session(host: &Arc<Host>, stream: TcpStream, keys: channel::SessionKeys, ctl: &Arc<SessionCtl>) -> Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let out = Arc::new(Out::new(RecordWriter::new(stream.try_clone()?, keys.send)));
    let mut reader = RecordReader::new(stream, keys.recv);
    let opts = &host.opts;
    let start = match ClientMsg::decode(reader.recv()?)? {
        ClientMsg::Hello { downscale, quality, monitor, flags } => {
            negotiate(opts, downscale, quality, monitor, flags, |s| capture::resolve(s).is_some())
        }
        _ => bail!("protocol error: viewer did not start with a hello"),
    };

    let area = capture::resolve(start.sel).ok_or("selected monitor not found")?;
    let flags = host_flags(opts, AudioCapture::available(), Privacy::available());
    let d = effective_downscale(area, start.downscale);
    let monitors = capture::monitors()
        .iter()
        .map(|m| MonitorInfo { left: m.left, top: m.top, width: m.width.clamp(0, 0xffff) as u16, height: m.height.clamp(0, 0xffff) as u16 })
        .collect();
    out.send(&ServerMsg::Hello {
        width: (area.width as usize / d) as u16,
        height: (area.height as usize / d) as u16,
        flags,
        monitor: monitor_code(start.sel),
        monitors,
        name: crate::platform::hostname(),
    })?;
    if start.monitor_missing {
        log!("the configured monitor is not connected; sharing the primary monitor");
        out.notice("the monitor this host is set to share is not connected; showing the primary monitor".into())?;
    }

    let shared = Arc::new(Shared {
        acked: AtomicU32::new(0),
        refresh: AtomicBool::new(false),
        last_input_ms: AtomicU64::new(0),
        view: Mutex::new(View { area, downscale: d }),
        start: Instant::now(),
    });

    let clip = if opts.clipboard {
        let o = out.clone();
        let c = ctl.clone();
        Some(Clipboard::spawn(move |text| {
            if !c.stopped() {
                let _ = o.send(&ServerMsg::Clipboard(text));
            }
        })?)
    } else {
        None
    };

    let (settings_tx, settings_rx) = mpsc::channel();
    let input_thread = {
        let (host, out, shared, ctl) = (host.clone(), out.clone(), shared.clone(), ctl.clone());
        let wishes = (start.audio, start.privacy);
        std::thread::Builder::new().name("input".into()).spawn(move || {
            let _kick = KickOnDrop(ctl.clone());
            Input::new(host, out, shared, ctl, clip, settings_tx, flags).run(reader, wishes)
        })?
    };

    let r = capture_loop(opts, &out, &shared, ctl, &start, settings_rx);
    // Stopped from elsewhere (input side, replacement, host shutdown) before the capture side ended?
    let kicked = ctl.stopped();
    ctl.kick();
    let ir = input_thread.join().unwrap_or_else(|_| Err("input thread panicked".into()));
    // Report the real cause; errors that only follow from the kick are not one.
    match (r, ir) {
        (_, Err(e)) => Err(e),
        (Err(e), _) if !kicked => Err(e),
        _ => Ok(()),
    }
}

/// The input thread: everything the viewer sends after its hello. Dropping it releases held
/// keys, removes partial uploads and switches audio and privacy mode off.
struct Input {
    host: Arc<Host>,
    out: Arc<Out>,
    shared: Arc<Shared>,
    ctl: Arc<SessionCtl>,
    clip: Option<Clipboard>,
    /// Quality, scale and monitor changes for the capture thread, which confirms them.
    settings: mpsc::Sender<(u8, u32)>,
    inj: Injector,
    follower: DesktopFollower,
    last_sync: Instant,
    /// Uploads and pulls are allowed in this session.
    files: bool,
    uploads: HashMap<u32, Incoming>,
    upload_dir: Option<PathBuf>,
    pulling: Arc<AtomicBool>,
    /// The id of the next file pulled.
    pull_ids: Arc<AtomicU32>,
    /// Refusals the viewer causes are logged up to `SESSION_LOG_LINES`.
    refusals: LogBudget,
    audio: Toggle<AudioStream>,
    privacy: Toggle<Held>,
}

impl Input {
    fn new(
        host: Arc<Host>,
        out: Arc<Out>,
        shared: Arc<Shared>,
        ctl: Arc<SessionCtl>,
        clip: Option<Clipboard>,
        settings: mpsc::Sender<(u8, u32)>,
        flags: u32,
    ) -> Input {
        Input {
            host,
            out,
            shared,
            ctl,
            clip,
            settings,
            inj: Injector::default(),
            follower: DesktopFollower::new(),
            last_sync: Instant::now() - Duration::from_secs(1),
            files: flags & F_FILES != 0,
            uploads: HashMap::new(),
            upload_dir: None,
            pulling: Arc::new(AtomicBool::new(false)),
            pull_ids: Arc::new(AtomicU32::new(1)),
            refusals: LogBudget(SESSION_LOG_LINES),
            audio: Toggle::new("audio", flags & F_AUDIO != 0),
            privacy: Toggle::new("privacy mode", flags & F_PRIVACY != 0),
        }
    }

    fn run(mut self, reader: RecordReader<TcpStream>, wishes: (bool, bool)) -> Result<()> {
        match self.serve(reader, wishes) {
            // Ended from elsewhere (replaced, host stopping, capture failed): not this side's error.
            Err(_) if self.ctl.stopped() => Ok(()),
            r => r,
        }
    }

    fn serve(&mut self, mut reader: RecordReader<TcpStream>, (audio, privacy): (bool, bool)) -> Result<()> {
        if audio {
            self.set_feature(SET_AUDIO, 1)?;
        }
        if privacy {
            self.set_feature(SET_PRIVACY, 1)?;
        }
        loop {
            let m = ClientMsg::decode(reader.recv()?)?;
            self.handle(m)?;
        }
    }

    fn handle(&mut self, m: ClientMsg) -> Result<()> {
        match m {
            ClientMsg::Ack(id) => self.shared.acked.store(id, Ordering::SeqCst),
            ClientMsg::Refresh => self.shared.refresh.store(true, Ordering::SeqCst),
            ClientMsg::Ping(t) => self.out.send(&ServerMsg::Pong(t))?,
            ClientMsg::Hello { .. } => {}
            ClientMsg::Set { key: key @ (SET_QUALITY | SET_DOWNSCALE | SET_MONITOR), value } => {
                // Fails only once the capture thread has ended, i.e. the session is ending.
                let _ = self.settings.send((key, value));
            }
            ClientMsg::Set { key: key @ (SET_AUDIO | SET_PRIVACY), value } => self.set_feature(key, value)?,
            ClientMsg::Set { key, .. } => self.out.send(&ServerMsg::State { key, value: STATE_UNAVAILABLE })?,
            ClientMsg::FileBegin { id, size, name } => self.upload_begin(id, size, &name)?,
            ClientMsg::FileData { id, data } => self.upload_data(id, &data)?,
            ClientMsg::FileEnd { id, sha256 } => self.upload_end(id, &sha256)?,
            ClientMsg::FilePull => self.pull()?,
            ClientMsg::Clipboard(text) if accepts_clipboard(&self.host.opts) => {
                if let Some(c) = &self.clip {
                    c.set(text);
                }
            }
            ClientMsg::Clipboard(_) => {}
            ClientMsg::Sas if !self.host.opts.view_only => {
                if !self.host.opts.sas || !crate::platform::request_sas() {
                    self.log_refusal("Ctrl+Alt+Del requested but SAS forwarding is unavailable (run as service with --enable-sas)".into());
                }
            }
            ClientMsg::Sas => {}
            ClientMsg::MouseMove { .. }
            | ClientMsg::MouseButton { .. }
            | ClientMsg::Wheel { .. }
            | ClientMsg::Key { .. }
            | ClientMsg::ReleaseAll => self.inject(m),
        }
        Ok(())
    }

    fn inject(&mut self, m: ClientMsg) {
        if self.host.opts.view_only {
            return;
        }
        if self.last_sync.elapsed() > Duration::from_millis(250) {
            self.follower.sync();
            self.last_sync = Instant::now();
        }
        let view = *lock(&self.shared.view);
        self.inj.set_area(view.area);
        let d = view.downscale as u32;
        let m = match m {
            // Aim at the centre of the d*d block the viewer pointed at.
            ClientMsg::MouseMove { x, y } if d > 1 => ClientMsg::MouseMove {
                x: (x as u32 * d + d / 2).min(u16::MAX as u32) as u16,
                y: (y as u32 * d + d / 2).min(u16::MAX as u32) as u16,
            },
            m => m,
        };
        self.inj.handle(&m);
        self.shared.last_input_ms.store(self.shared.start.elapsed().as_millis() as u64, Ordering::SeqCst);
    }

    /// `SET_AUDIO` / `SET_PRIVACY`: switches the feature and confirms the state in effect.
    fn set_feature(&mut self, key: u8, value: u32) -> Result<()> {
        let want = value != 0;
        let (state, failure) = if key == SET_AUDIO {
            let (out, ctl) = (self.out.clone(), self.ctl.clone());
            self.audio.set(want, move || AudioStream::start(out, ctl))
        } else {
            self.privacy.set(want, || Held::start("privacy", Privacy::enable))
        };
        if let Some(e) = failure {
            log!("{e}");
            self.out.notice(e)?;
        }
        self.out.send(&ServerMsg::State { key, value: state })
    }

    fn file_result(&self, id: u32, ok: bool, message: String) -> Result<()> {
        self.out.send(&ServerMsg::FileResult { id, ok, message: short(message) })
    }

    fn log_refusal(&mut self, line: String) {
        if let Some(line) = self.refusals.line(line) {
            log!("{line}");
        }
    }

    fn refusal(&self) -> String {
        if self.host.opts.view_only {
            "file transfer is not available in a view-only session".into()
        } else {
            "file transfer is disabled on this host".into()
        }
    }

    fn upload_dir(&mut self) -> Result<PathBuf> {
        if let Some(d) = &self.upload_dir {
            return Ok(d.clone());
        }
        let d = match &self.host.opts.transfer_dir {
            Some(d) => {
                std::fs::create_dir_all(d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
                d.clone()
            }
            None => files::transfer_dir()?,
        };
        self.upload_dir = Some(d.clone());
        Ok(d)
    }

    fn upload_begin(&mut self, id: u32, size: u64, name: &str) -> Result<()> {
        let r = if !self.files {
            Err(self.refusal().into())
        } else if self.uploads.remove(&id).is_some() {
            // A reused id makes the stream ambiguous: abort the earlier upload as well.
            Err(format!("upload {id} was already in progress; both are cancelled").into())
        } else if self.uploads.len() >= MAX_UPLOADS {
            Err(format!("too many uploads at once (at most {MAX_UPLOADS})").into())
        } else {
            self.upload_dir().and_then(|dir| Incoming::begin(&dir, id, size, name))
        };
        match r {
            Ok(inc) => {
                log!("receiving file {name} ({size} bytes)");
                self.uploads.insert(id, inc);
                Ok(())
            }
            Err(e) => {
                self.log_refusal(format!("refused upload of {name} ({size} bytes): {e}"));
                self.file_result(id, false, e.to_string())
            }
        }
    }

    fn upload_data(&mut self, id: u32, data: &[u8]) -> Result<()> {
        // Data for an upload that was refused or failed earlier is dropped silently.
        let Some(inc) = self.uploads.get_mut(&id) else { return Ok(()) };
        let Err(e) = inc.write(data) else { return Ok(()) };
        log!("upload of {} ({} bytes) failed: {e}", inc.name, inc.size);
        // Dropping it removes the partial file.
        self.uploads.remove(&id);
        self.file_result(id, false, e.to_string())
    }

    fn upload_end(&mut self, id: u32, sha256: &[u8; 32]) -> Result<()> {
        let Some(inc) = self.uploads.remove(&id) else { return Ok(()) };
        let (name, size) = (inc.name.clone(), inc.size);
        match inc.finish(sha256) {
            Ok(path) => {
                log!("received file {name} ({size} bytes)");
                self.file_result(id, true, path.display().to_string())
            }
            Err(e) => {
                log!("upload of {name} ({size} bytes) failed: {e}");
                self.file_result(id, false, e.to_string())
            }
        }
    }

    /// `FilePull`: sends the files copied on the host from a thread of its own.
    fn pull(&mut self) -> Result<()> {
        if !self.files {
            return self.out.notice(self.refusal());
        }
        if self.pulling.swap(true, Ordering::SeqCst) {
            return self.out.notice("files are already being sent".into());
        }
        let (out, ctl, busy, ids) = (self.out.clone(), self.ctl.clone(), self.pulling.clone(), self.pull_ids.clone());
        let copied = self.host.opts.copied_files;
        let spawned = std::thread::Builder::new().name("file-pull".into()).spawn(move || {
            pull_files(copied, &ids, &out, &ctl);
            busy.store(false, Ordering::SeqCst);
        });
        if let Err(e) = spawned {
            self.pulling.store(false, Ordering::SeqCst);
            return self.out.notice(format!("cannot send files: {e}"));
        }
        Ok(())
    }
}

/// Elsewhere the host runs as the user whose screen it shares: files are read as itself.
#[cfg(not(windows))]
struct FileUser;

#[cfg(not(windows))]
impl FileUser {
    fn get() -> Result<FileUser> {
        Ok(FileUser)
    }

    fn act<T>(&self, f: impl FnOnce() -> T) -> Result<T> {
        Ok(f())
    }
}

/// Sends the files copied on the host, each opened as the user the host's session belongs to
/// (`FileUser`: the host may be SYSTEM).
fn pull_files(copied: fn() -> Vec<PathBuf>, ids: &AtomicU32, out: &Out, ctl: &SessionCtl) {
    let user = match FileUser::get() {
        Ok(u) => u,
        Err(e) => {
            let _ = out.notice(format!("cannot send copied files: {e}"));
            return;
        }
    };
    let paths = copied();
    if paths.is_empty() {
        let _ = out.notice("no files are copied on the host".into());
        return;
    }
    let first_id = ids.fetch_add(paths.len() as u32, Ordering::SeqCst);
    send_files(&paths, first_id, &user, out, ctl);
}

/// Sends `paths` one after another as `S_FILE_BEGIN` / `S_FILE_DATA`... / `S_FILE_END`.
fn send_files(paths: &[PathBuf], first_id: u32, user: &FileUser, out: &Out, ctl: &SessionCtl) {
    let mut buf = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        if ctl.stopped() {
            return;
        }
        if let Err(e) = send_file(path, first_id.wrapping_add(i as u32), user, out, ctl, &mut buf) {
            if ctl.stopped() {
                return;
            }
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            log!("sending {name} failed: {e}");
            if out.notice(format!("could not send {name}: {e}")).is_err() {
                return;
            }
        }
    }
}

fn send_file(path: &Path, id: u32, user: &FileUser, out: &Out, ctl: &SessionCtl, buf: &mut Vec<u8>) -> Result<()> {
    // Opened as the user; reading through the open handle needs no further rights.
    let mut file = user.act(|| Outgoing::open(path, id))??;
    let (name, size) = (file.name.clone(), file.size);
    log!("sending file {name} ({size} bytes)");
    out.send_bulk(&ServerMsg::FileBegin { id, size, name })?;
    let mut body = || -> Result<()> {
        while file.next_chunk(buf)? {
            if ctl.stopped() {
                bail!("{}", channel::CLOSED);
            }
            out.send_bulk(&ServerMsg::FileData { id, data: buf })?;
        }
        Ok(())
    };
    match body() {
        Ok(()) => out.send_bulk(&ServerMsg::FileEnd { id, sha256: file.finish() }),
        Err(e) => {
            // Make the viewer discard what it received: this checksum never matches.
            let _ = out.send_bulk(&ServerMsg::FileEnd { id, sha256: [0; 32] });
            Err(e)
        }
    }
}

/// A feature the viewer switches on and off (audio, privacy mode). Holding `T` keeps it on;
/// dropping the toggle, at the latest when the session ends, switches it off.
struct Toggle<T> {
    name: &'static str,
    supported: bool,
    on: Option<T>,
}

impl<T> Toggle<T> {
    fn new(name: &'static str, supported: bool) -> Toggle<T> {
        Toggle { name, supported, on: None }
    }

    /// Applies the viewer's wish. Returns the `State` value now in effect and, if switching
    /// on failed, why.
    fn set(&mut self, want: bool, enable: impl FnOnce() -> Result<T>) -> (u32, Option<String>) {
        if !self.supported {
            return (STATE_UNAVAILABLE, None);
        }
        if !want {
            if let Some(t) = self.on.take() {
                drop(t);
                log!("{} off", self.name);
            }
            return (0, None);
        }
        if self.on.is_none() {
            match enable() {
                Ok(t) => {
                    self.on = Some(t);
                    log!("{} on", self.name);
                }
                Err(e) => return (0, Some(format!("{} could not be switched on: {e}", self.name))),
            }
        }
        (1, None)
    }
}

impl<T> Drop for Toggle<T> {
    fn drop(&mut self) {
        if let Some(t) = self.on.take() {
            drop(t);
            log!("{} off (session ended)", self.name);
        }
    }
}

/// Keeps a platform object on a thread of its own: it is created there, lives until the `Held`
/// is dropped and is dropped there too. So it may be thread-affine (COM, hooks, windows), it
/// never ties the input thread to a desktop, and dropping the `Held` waits until it is gone.
struct Held {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Held {
    fn start<T: 'static>(name: &str, make: impl FnOnce() -> Result<T> + Send + 'static) -> Result<Held> {
        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let thread = std::thread::Builder::new().name(name.into()).spawn(move || match make() {
            Ok(obj) => {
                let _ = ready_tx.send(Ok(()));
                // Returns when the `Held` drops its sender.
                let _ = stop_rx.recv();
                drop(obj);
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e));
            }
        })?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Held { stop: Some(stop_tx), thread: Some(thread) }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                bail!("{name} thread failed")
            }
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Interleaved PCM covering `AUDIO_PACKET_MS`.
struct AudioPacket {
    seq: u32,
    rate: u32,
    channels: u8,
    pcm: Vec<i16>,
}

/// Cuts the capture callback's PCM into packets for the sender thread. It never blocks: when
/// the network falls behind, packets are dropped and the gap shows in `seq`.
struct Packetizer {
    tx: mpsc::SyncSender<AudioPacket>,
    rate: u32,
    channels: u8,
    pending: Vec<i16>,
    seq: u32,
}

impl Packetizer {
    fn new(tx: mpsc::SyncSender<AudioPacket>) -> Packetizer {
        Packetizer { tx, rate: 0, channels: 0, pending: Vec::new(), seq: 0 }
    }

    fn push(&mut self, pcm: &[i16], rate: u32, channels: u8) {
        if rate == 0 || rate > MAX_AUDIO_RATE || channels == 0 || channels > MAX_AUDIO_CHANNELS {
            return;
        }
        if (rate, channels) != (self.rate, self.channels) {
            (self.rate, self.channels) = (rate, channels);
            self.pending.clear();
        }
        let ch = channels as usize;
        let n = (rate as usize * AUDIO_PACKET_MS / 1000).max(1) * ch;
        // Only whole sample frames, so the channels stay interleaved correctly.
        let mut pcm = &pcm[..pcm.len() - pcm.len() % ch];
        while !pcm.is_empty() {
            let take = (n - self.pending.len()).min(pcm.len());
            self.pending.extend_from_slice(&pcm[..take]);
            pcm = &pcm[take..];
            if self.pending.len() == n {
                let pcm = std::mem::replace(&mut self.pending, Vec::with_capacity(n));
                let _ = self.tx.try_send(AudioPacket { seq: self.seq, rate, channels, pcm });
                self.seq = self.seq.wrapping_add(1);
            }
        }
    }
}

/// Streams the host's sound while held: capture callback -> `Packetizer` -> bounded queue ->
/// sender thread (ADPCM, then the network).
struct AudioStream {
    _capture: Held,
    stop: Arc<AtomicBool>,
}

impl AudioStream {
    fn start(out: Arc<Out>, ctl: Arc<SessionCtl>) -> Result<AudioStream> {
        let (tx, rx) = mpsc::sync_channel(AUDIO_QUEUE);
        let stop = Arc::new(AtomicBool::new(false));
        {
            let stop = stop.clone();
            std::thread::Builder::new().name("audio-send".into()).spawn(move || audio_sender(rx, &out, &ctl, &stop))?;
        }
        let mut packets = Packetizer::new(tx);
        let capture = Held::start("audio", move || {
            AudioCapture::start(Box::new(move |pcm: &[i16], rate: u32, channels: u8| packets.push(pcm, rate, channels)))
        });
        match capture {
            Ok(c) => Ok(AudioStream { _capture: c, stop }),
            Err(e) => {
                stop.store(true, Ordering::SeqCst);
                Err(e)
            }
        }
    }
}

impl Drop for AudioStream {
    fn drop(&mut self) {
        // The sender stops right away; the capture stops when `_capture` drops after this.
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn audio_sender(rx: mpsc::Receiver<AudioPacket>, out: &Out, ctl: &SessionCtl, stop: &AtomicBool) {
    let mut enc: Option<(u8, AdpcmEncoder)> = None;
    let mut data = Vec::new();
    loop {
        let p = match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(p) => p,
            Err(mpsc::RecvTimeoutError::Timeout) if !stop.load(Ordering::SeqCst) && !ctl.stopped() => continue,
            Err(_) => return,
        };
        if stop.load(Ordering::SeqCst) || ctl.stopped() {
            return;
        }
        // The ADPCM encoder takes mono or stereo only; silence is not worth sending.
        if !(1..=2).contains(&p.channels) || p.pcm.iter().all(|&s| s == 0) {
            continue;
        }
        if enc.as_ref().is_some_and(|(ch, _)| *ch != p.channels) {
            enc = None;
        }
        let (_, e) = enc.get_or_insert_with(|| (p.channels, AdpcmEncoder::new(p.channels)));
        data.clear();
        e.encode(&p.pcm, &mut data);
        if data.is_empty() {
            continue;
        }
        let m = ServerMsg::Audio { seq: p.seq, rate: p.rate, channels: p.channels, codec: AUDIO_IMA_ADPCM, data: &data };
        if out.send(&m).is_err() {
            return;
        }
    }
}

fn send_frame(out: &Out, frame: &mut u32, w: usize, h: usize, rects: &[EncodedRect]) -> Result<()> {
    *frame = frame.wrapping_add(1);
    for msg in codec::pack(*frame, w, h, rects) {
        out.send_record(&msg)?;
    }
    Ok(())
}

fn capture_loop(
    opts: &HostOptions,
    out: &Out,
    shared: &Shared,
    ctl: &SessionCtl,
    start: &Start,
    settings: mpsc::Receiver<(u8, u32)>,
) -> Result<()> {
    let fast = Duration::from_millis(1000 / opts.max_fps.clamp(1, 120) as u64);
    let slow = Duration::from_millis(100);
    let mut follower = DesktopFollower::new();
    let mut encoder = Encoder::new()?;
    let mut quality = start.quality;
    encoder.set_quality(quality);
    let mut sel = start.sel;
    let mut downscale = start.downscale;
    let cursors = CursorTracker::new();
    let mut capturer: Option<Capturer> = None;
    // The capturer delivered a picture since it was opened (a new duplication starts out blank).
    let mut cap_ready = false;
    // Encode even if the capturer reports no change: new scale, new source or a refresh.
    let mut force = false;
    // The encoder holds the current picture at the current size, which refinement works on.
    let mut encoded = false;
    let mut last_cursor = None;
    let mut frame: u32 = 0;
    let mut last_geometry_check = Instant::now();
    let mut last_change = Instant::now();
    let mut last_send = Instant::now();
    let mut capture_failures = 0u32;
    let mut scaled = LockedBuf::new(0);
    let mut last_upgrade_try = Instant::now();

    while !ctl.stopped() {
        let t0 = Instant::now();
        // Settings from the viewer, applied between frames and confirmed with the value in effect.
        while let Ok((key, value)) = settings.try_recv() {
            let state = match key {
                SET_QUALITY => {
                    if value <= QUALITY_LOW && value != quality {
                        quality = value;
                        encoder.set_quality(quality);
                    }
                    quality
                }
                SET_DOWNSCALE => {
                    if (1..=4).contains(&value) && value as usize != downscale {
                        downscale = value as usize;
                        if let Some(c) = &capturer {
                            let a = c.area();
                            *lock(&shared.view) = View { area: a, downscale: effective_downscale(a, downscale) };
                        }
                        encoder.request_full();
                        (force, encoded) = (true, false);
                    }
                    downscale as u32
                }
                SET_MONITOR => {
                    let wanted = monitor_sel(value, opts.monitor).filter(|&s| capture::resolve(s).is_some());
                    if let Some(s) = wanted.filter(|&s| monitor_code(s) != monitor_code(sel)) {
                        sel = s;
                        capturer = None; // reopened below for the new source
                    }
                    monitor_code(sel) as u32
                }
                _ => STATE_UNAVAILABLE,
            };
            out.send(&ServerMsg::State { key, value: state })?;
        }

        if frame.wrapping_sub(shared.acked.load(Ordering::SeqCst)) >= MAX_IN_FLIGHT {
            if last_send.elapsed() > IO_TIMEOUT {
                bail!("viewer stopped acknowledging frames");
            }
            std::thread::sleep(Duration::from_millis(2));
            continue;
        }

        let switched = follower.sync();
        if switched || capturer.is_none() || last_geometry_check.elapsed() > Duration::from_millis(500) {
            last_geometry_check = Instant::now();
            let current = capturer.as_ref().map(|c| c.area());
            match capture::resolve(sel) {
                Some(a) if switched || current != Some(a) => {
                    capturer = None; // release the old device/DCs before creating new ones
                    match Capturer::open(sel, a) {
                        Ok(c) => {
                            if current != Some(a) {
                                log!("capturing {}x{} via {}", a.width, a.height, c.backend());
                            }
                            capturer = Some(c);
                            *lock(&shared.view) = View { area: a, downscale: effective_downscale(a, downscale) };
                            encoder.request_full();
                            (cap_ready, force, encoded) = (false, true, false);
                        }
                        Err(e) => log!("capture setup failed: {e}"),
                    }
                }
                Some(_) if last_upgrade_try.elapsed() > Duration::from_secs(10) => {
                    last_upgrade_try = Instant::now();
                    if let Some(c) = capturer.as_mut() {
                        if c.try_upgrade(sel) {
                            log!("switched to {} capture", c.backend());
                            encoder.request_full();
                            (cap_ready, force, encoded) = (false, true, false);
                        }
                    }
                }
                Some(_) => {}
                None if capturer.is_none() => log!("monitor not available"),
                None => {}
            }
        }
        let Some(cap) = capturer.as_mut() else {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        };

        let cursor = cursors.current();
        if last_cursor != Some(cursor) {
            out.send(&ServerMsg::Cursor(cursor))?;
            last_cursor = Some(cursor);
        }

        // DXGI blocks until something changes; GDI is polled at the pace computed below.
        let wait_ms = if cap.waits_for_changes() { 50 } else { 0 };
        match cap.next_frame(wait_ms) {
            Ok(changed) => {
                if capture_failures >= 3 {
                    log!("screen capture resumed");
                }
                capture_failures = 0;
                cap_ready |= changed;
                if shared.refresh.swap(false, Ordering::SeqCst) {
                    encoder.request_full();
                    force = true;
                }
                let area = cap.area();
                let (fw, fh) = (area.width as usize, area.height as usize);
                let d = effective_downscale(area, downscale);
                let (w, h) = (fw / d, fh / d);
                let mut sent = false;
                if cap_ready && (changed || force) {
                    force = false;
                    let pixels = if d > 1 {
                        if scaled.len() != w * h * 4 {
                            scaled = LockedBuf::new(w * h * 4);
                        }
                        codec::downscale(cap.pixels(), fw, fh, d, scaled.as_mut_slice());
                        scaled.as_slice()
                    } else {
                        cap.pixels()
                    };
                    let rects = encoder.encode(pixels, w, h);
                    encoded = true;
                    if !rects.is_empty() {
                        send_frame(out, &mut frame, w, h, &rects)?;
                        last_change = Instant::now();
                        last_send = last_change;
                        sent = true;
                    }
                }
                // Nothing new on screen: spend the tick on lossless refinement of lossy regions.
                if !sent && encoded && encoder.needs_refine() {
                    let pixels = if d > 1 { scaled.as_slice() } else { cap.pixels() };
                    if pixels.len() == w * h * 4 {
                        let rects = encoder.refine(pixels, w, h, REFINE_BUDGET);
                        if !rects.is_empty() {
                            send_frame(out, &mut frame, w, h, &rects)?;
                            last_send = Instant::now();
                        }
                    }
                }
            }
            Err(e) => {
                // Desktop switches and mode changes invalidate the duplication; recreate it.
                capture_failures += 1;
                if capture_failures == 3 {
                    log!("screen capture failing ({e}); is the session locked? retrying");
                }
                capturer = None;
                std::thread::sleep(Duration::from_millis(if capture_failures < 3 { 20 } else { 250 }));
                continue;
            }
        }

        if last_send.elapsed() > Duration::from_secs(5) {
            out.send(&ServerMsg::Ping)?;
            last_send = Instant::now();
        }

        // Cap the frame rate. GDI is also polled slowly while the screen is idle;
        // DXGI already slept inside next_frame until something changed.
        let now_ms = shared.start.elapsed().as_millis() as u64;
        let since_input = now_ms.saturating_sub(shared.last_input_ms.load(Ordering::SeqCst));
        let idle = last_change.elapsed() > Duration::from_secs(2) && since_input > 2000;
        let polling = capturer.as_ref().is_some_and(|c| !c.waits_for_changes());
        let interval = if idle && polling { slow } else { fast };
        if let Some(rest) = interval.checked_sub(t0.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> HostOptions {
        HostOptions { monitor: MonitorSel::Index(1), ..HostOptions::default() }
    }

    #[test]
    fn hello_negotiation() {
        let o = opts();
        let all = |_| true;
        let s = negotiate(&o, 2, QUALITY_LOW as u8, MONITOR_DEFAULT, HELLO_AUDIO | HELLO_PRIVACY, all);
        let sel = MonitorSel::Index(1);
        assert_eq!(s, Start { sel, monitor_missing: false, downscale: 2, quality: QUALITY_LOW, audio: true, privacy: true });
        let s = negotiate(&o, 0, 9, MONITOR_ALL, 0, all);
        let sel = MonitorSel::All;
        assert_eq!(s, Start { sel, monitor_missing: false, downscale: 1, quality: QUALITY_BALANCED, audio: false, privacy: false });
        assert_eq!(negotiate(&o, 200, 0, 0, 0, all).downscale, 4);
        assert_eq!(negotiate(&o, 1, 0, 3, 0, all).sel, MonitorSel::Index(3));
        // An unknown monitor falls back to the host's choice.
        assert_eq!(negotiate(&o, 1, 0, 3, 0, |s| s != MonitorSel::Index(3)).sel, MonitorSel::Index(1));
        // The host's own monitor was unplugged: the primary one, and the viewer is told.
        let unplugged = |s| s != MonitorSel::Index(1) && s != MonitorSel::Index(3);
        for m in [MONITOR_DEFAULT, 3] {
            let s = negotiate(&o, 1, 0, m, 0, unplugged);
            assert_eq!((s.sel, s.monitor_missing), (MonitorSel::Primary, true));
        }
        let s = negotiate(&o, 1, 0, 2, 0, unplugged);
        assert_eq!((s.sel, s.monitor_missing), (MonitorSel::Index(2), false));
        // Nothing to fall back to: the primary monitor, which then fails to open.
        let o = HostOptions { monitor: MonitorSel::Primary, ..opts() };
        let s = negotiate(&o, 1, 0, MONITOR_DEFAULT, 0, |_| false);
        assert_eq!((s.sel, s.monitor_missing), (MonitorSel::Primary, false));
        // The host default applies to unknown qualities only, and only if it is a valid one.
        let o = HostOptions { default_quality: QUALITY_LOSSLESS, ..opts() };
        assert_eq!(negotiate(&o, 1, 0xff, 0, 0, all).quality, QUALITY_LOSSLESS);
        assert_eq!(negotiate(&o, 1, QUALITY_LOW as u8, 0, 0, all).quality, QUALITY_LOW);
        let o = HostOptions { default_quality: 42, ..opts() };
        assert_eq!(negotiate(&o, 1, 0xff, 0, 0, all).quality, QUALITY_BALANCED);
    }

    #[test]
    fn monitor_values() {
        assert_eq!(monitor_sel(MONITOR_DEFAULT as u32, MonitorSel::All), Some(MonitorSel::All));
        assert_eq!(monitor_sel(MONITOR_ALL as u32, MonitorSel::Primary), Some(MonitorSel::All));
        assert_eq!(monitor_sel(0, MonitorSel::All), Some(MonitorSel::Index(0)));
        assert_eq!(monitor_sel(0xfd, MonitorSel::All), Some(MonitorSel::Index(0xfd)));
        assert_eq!(monitor_sel(0x100, MonitorSel::All), None);
        assert_eq!(monitor_sel(u32::MAX, MonitorSel::All), None);
        assert_eq!(monitor_code(MonitorSel::Primary), 0);
        assert_eq!(monitor_code(MonitorSel::Index(2)), 2);
        assert_eq!(monitor_code(MonitorSel::Index(5000)), 0xfd);
        assert_eq!(monitor_code(MonitorSel::All), MONITOR_ALL);
    }

    #[test]
    fn downscale_never_empties_the_picture() {
        let a = |w, h| Area { left: 0, top: 0, width: w, height: h };
        assert_eq!(effective_downscale(a(1920, 1080), 2), 2);
        assert_eq!(effective_downscale(a(1920, 1080), 0), 1);
        assert_eq!(effective_downscale(a(1920, 1080), 9), 4);
        assert_eq!(effective_downscale(a(3, 1080), 4), 3);
        assert_eq!(effective_downscale(a(0, 0), 4), 1);
    }

    #[test]
    fn capability_flags() {
        let base = HostOptions { clipboard: true, ..HostOptions::default() };
        assert_eq!(host_flags(&base, true, true), F_CLIPBOARD | F_AUDIO | F_FILES | F_PRIVACY);
        assert_eq!(host_flags(&base, false, false), F_CLIPBOARD | F_FILES);
        let o = HostOptions { view_only: true, sas: true, ..HostOptions::default() };
        assert_eq!(host_flags(&o, true, true), F_VIEW_ONLY | F_SAS | F_AUDIO);
        let o = HostOptions { files: false, audio: false, privacy: false, ..HostOptions::default() };
        assert_eq!(host_flags(&o, true, true), 0);
    }

    #[test]
    fn view_only_viewers_cannot_set_the_clipboard() {
        let o = |clipboard, view_only| HostOptions { clipboard, view_only, ..HostOptions::default() };
        assert!(accepts_clipboard(&o(true, false)));
        assert!(!accepts_clipboard(&o(true, true)));
        assert!(!accepts_clipboard(&o(false, false)));
        // The host's clipboard is still offered to view-only viewers.
        assert_ne!(host_flags(&o(true, true), false, false) & F_CLIPBOARD, 0);
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([100, 64, 0, last])
    }

    #[test]
    fn pending_handshakes_are_capped_in_all_and_per_address() {
        let mut p = Pending::default();
        for _ in 0..MAX_PENDING_PER_ADDR {
            p.admit(ip(1)).unwrap();
        }
        assert!(p.admit(ip(1)).unwrap_err().contains("this address"));
        // Others still get in, up to the total.
        let mut n = MAX_PENDING_PER_ADDR;
        let mut last = 2;
        while n < MAX_PENDING {
            p.admit(ip(last)).unwrap();
            n += 1;
            if n % MAX_PENDING_PER_ADDR == 0 {
                last += 1;
            }
        }
        assert_eq!(p.admit(ip(200)), Err("too many pending handshakes"));
        // A failed handshake leaves the total at once but keeps its address's place.
        p.leave_total();
        assert!(p.admit(ip(1)).is_err());
        p.admit(ip(200)).unwrap();
        p.leave_addr(ip(1));
        p.leave_total();
        p.admit(ip(1)).unwrap();
        // Nothing is kept for addresses without handshakes.
        let mut p = Pending::default();
        p.admit(ip(7)).unwrap();
        assert!(p.admit(ip(7)).is_ok() && p.admit(ip(7)).is_err());
        for _ in 0..2 {
            p.leave_total();
            p.leave_addr(ip(7));
        }
        p.leave_addr(ip(7));
        assert!(p.per_addr.is_empty() && p.total == 0);
    }

    #[test]
    fn unauthenticated_lines_are_rate_limited() {
        let t0 = Instant::now();
        let mut q = Quiet::new(t0);
        let shown = (0..10).filter(|_| q.allow(ip(1))).count();
        assert_eq!(shown, QUIET_PER_ADDR as usize);
        assert_eq!(q.roll(t0 + Duration::from_secs(30)), 0);
        // Many addresses: no more than the total per window.
        let shown = (0..200u8).filter(|&i| q.allow(ip(i.max(2)))).count();
        assert_eq!(shown + QUIET_PER_ADDR as usize, QUIET_TOTAL as usize);
        let dropped = (10 - QUIET_PER_ADDR as u64) + (200 - shown as u64);
        // The next window reports what the last one held back, and lets lines through again.
        assert_eq!(q.roll(t0 + QUIET_WINDOW), dropped);
        assert_eq!(q.roll(t0 + QUIET_WINDOW + Duration::from_secs(1)), 0);
        assert!(q.allow(ip(1)));
        assert_eq!(q.roll(t0 + 3 * QUIET_WINDOW), 0);
    }

    #[test]
    fn session_refusals_are_logged_up_to_a_budget() {
        let mut b = LogBudget(3);
        let lines: Vec<_> = (0..6).map(|i| b.line(format!("refused {i}"))).collect();
        assert_eq!(lines[..2], [Some("refused 0".to_string()), Some("refused 1".to_string())]);
        assert!(lines[2].as_ref().is_some_and(|l| l.starts_with("refused 2 (") && l.contains("not logged")));
        assert!(lines[3..].iter().all(Option::is_none));
    }

    #[test]
    fn waiting_for_tailscale_ends_when_stopped() {
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let setter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            s.store(true, Ordering::SeqCst);
        });
        let t = Instant::now();
        let r = wait_for_address(|| None, &stop, Duration::from_secs(60));
        setter.join().unwrap();
        assert!(r.unwrap_err().to_string().contains("stopped"));
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        // Already stopped: not even one look.
        assert!(wait_for_address(|| panic!("looked"), &stop, Duration::from_secs(60)).is_err());
        // Found on the third look.
        let looks = AtomicU32::new(0);
        let find = || (looks.fetch_add(1, Ordering::SeqCst) == 2).then(|| ip(9));
        assert_eq!(wait_for_address(find, &AtomicBool::new(false), Duration::from_millis(1)).unwrap(), ip(9));
    }

    #[test]
    fn handshake_works_through_the_deadline() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let viewer = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            channel::client_handshake(&mut s, &[3; 32]).is_ok()
        });
        let (s, _) = l.accept().unwrap();
        assert!(handshake(&s, &[3; 32], Instant::now() + Duration::from_secs(10)).is_ok());
        assert!(viewer.join().unwrap());
    }

    #[test]
    fn a_trickling_handshake_is_cut_off_at_the_deadline() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let trickle = {
            let done = done.clone();
            std::thread::spawn(move || {
                let mut s = TcpStream::connect(addr).unwrap();
                // A byte every 50 ms: never quiet long enough for a per-read timeout to fire.
                while !done.load(Ordering::SeqCst) && s.write_all(&[0x53]).is_ok() {
                    std::thread::sleep(Duration::from_millis(50));
                }
            })
        };
        let (s, _) = l.accept().unwrap();
        let t = Instant::now();
        let r = handshake(&s, &[1; 32], t + Duration::from_millis(800));
        let took = t.elapsed();
        done.store(true, Ordering::SeqCst);
        drop(s);
        trickle.join().unwrap();
        let e = r.err().expect("a trickled handshake succeeded").to_string();
        assert!(e.contains("timed out"), "{e}");
        assert!(took >= Duration::from_millis(700) && took < Duration::from_secs(3), "{took:?}");
    }

    /// Whether the host keeps `s` open (a pending handshake) rather than closing it at once.
    fn held_open(s: &TcpStream) -> bool {
        s.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
        match (&mut &*s).read(&mut [0u8; 1]) {
            Err(e) => matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
            Ok(_) => false,
        }
    }

    #[test]
    fn one_address_cannot_take_every_handshake_slot() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let policy = PeerPolicy { allow: vec![], allow_non_tailscale: false, loopback_ok: true };
        let opts = HostOptions { policy, copied_files: Vec::new, ..HostOptions::default() };
        let stop = Arc::new(AtomicBool::new(false));
        let host = {
            let stop = stop.clone();
            std::thread::spawn(move || serve(l, opts, Secret([9; 32]), &stop))
        };
        let a = TcpStream::connect(addr).unwrap();
        let b = TcpStream::connect(addr).unwrap();
        assert!(held_open(&a) && held_open(&b));
        // A third silent connection from the same address is turned away at once.
        let c = TcpStream::connect(addr).unwrap();
        assert!(!held_open(&c));
        // A failed handshake keeps its address's slot for the penalty, then gives it back.
        drop(a);
        let d = TcpStream::connect(addr).unwrap();
        assert!(!held_open(&d));
        std::thread::sleep(FAILURE_PENALTY + Duration::from_secs(1));
        let e = TcpStream::connect(addr).unwrap();
        assert!(held_open(&e));
        stop.store(true, Ordering::SeqCst);
        host.join().unwrap().unwrap();
        drop((b, e));
    }

    #[test]
    fn text_is_cut_on_a_char_boundary() {
        assert_eq!(short("ok".into()), "ok");
        let s = short("가".repeat(2000));
        assert_eq!(s.len(), 4095);
        assert!(s.chars().all(|c| c == '가'));
    }

    fn packets(rx: &mpsc::Receiver<AudioPacket>) -> Vec<AudioPacket> {
        rx.try_iter().collect()
    }

    #[test]
    fn audio_is_cut_into_20ms_packets() {
        let (tx, rx) = mpsc::sync_channel(16);
        let mut p = Packetizer::new(tx);
        // 44.1 kHz stereo: 882 frames = 1764 samples per packet, fed in 10 ms pieces.
        let piece: Vec<i16> = (0..882).map(|i| i as i16).collect();
        for _ in 0..5 {
            p.push(&piece, 44100, 2);
        }
        let got = packets(&rx);
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|a| a.pcm.len() == 1764 && a.rate == 44100 && a.channels == 2));
        assert_eq!((got[0].seq, got[1].seq), (0, 1));
        assert_eq!(&got[0].pcm[..882], &piece[..]);
        // A format change drops the partial packet; a stray half frame is ignored.
        p.push(&[1; 961], 48000, 1);
        p.push(&[5, 5, 5], 48000, 2);
        p.push(&[2; 1919], 48000, 2);
        let got = packets(&rx);
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].seq, got[0].pcm.len(), got[0].channels), (2, 960, 1));
        assert_eq!((got[1].seq, got[1].pcm.len(), got[1].channels), (3, 1920, 2));
        assert_eq!(&got[1].pcm[..3], &[5, 5, 2]);
        // Nonsense formats are dropped.
        p.push(&[1; 4000], 0, 2);
        p.push(&[1; 4000], 48000, 0);
        p.push(&[1; 4000], 48000, 9);
        p.push(&[1; 4000], 10_000_000, 1);
        assert!(packets(&rx).is_empty());
    }

    #[test]
    fn audio_never_blocks_when_the_network_is_behind() {
        let (tx, rx) = mpsc::sync_channel(2);
        let mut p = Packetizer::new(tx);
        let t = Instant::now();
        for _ in 0..10 {
            p.push(&[0; 960], 48000, 1);
        }
        assert!(t.elapsed() < Duration::from_secs(1));
        // The queue kept the first two; the rest were dropped but still counted.
        assert_eq!(packets(&rx).iter().map(|a| a.seq).collect::<Vec<_>>(), [0, 1]);
        p.push(&[0; 960], 48000, 1);
        assert_eq!(packets(&rx).iter().map(|a| a.seq).collect::<Vec<_>>(), [10]);
        // Nobody listening any more: still no blocking and no panic.
        drop(rx);
        p.push(&[0; 960], 48000, 1);
    }

    type Events = Arc<Mutex<Vec<(&'static str, std::thread::ThreadId)>>>;

    /// Stands in for a platform feature: records the threads it was created and dropped on.
    struct Fake {
        log: Events,
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            lock(&self.log).push(("off", std::thread::current().id()));
        }
    }

    fn fake(log: &Events) -> impl FnOnce() -> Result<Held> + use<> {
        let log = log.clone();
        move || {
            Held::start("fake", move || {
                lock(&log).push(("on", std::thread::current().id()));
                Ok(Fake { log })
            })
        }
    }

    fn kinds(log: &Events) -> Vec<&'static str> {
        lock(log).iter().map(|e| e.0).collect()
    }

    #[test]
    fn toggles_switch_on_off_and_always_off_at_the_end() {
        let log: Events = Arc::new(Mutex::new(Vec::new()));
        let mut t: Toggle<Held> = Toggle::new("fake", true);
        assert_eq!(t.set(true, fake(&log)), (1, None));
        // Already on: not switched on twice.
        assert_eq!(t.set(true, || -> Result<Held> { panic!("switched on twice") }), (1, None));
        assert_eq!(t.set(false, fake(&log)), (0, None));
        {
            let l = lock(&log);
            assert_eq!(l.len(), 2);
            // Created and dropped on the same thread, and not on the caller's.
            assert_eq!(l[0].1, l[1].1);
            assert_ne!(l[0].1, std::thread::current().id());
        }
        assert_eq!(kinds(&log), ["on", "off"]);
        assert_eq!(t.set(true, fake(&log)), (1, None));
        drop(t);
        assert_eq!(kinds(&log), ["on", "off", "on", "off"]);
    }

    #[test]
    fn toggles_report_unavailable_and_failures() {
        let mut calls = 0;
        let mut t: Toggle<Held> = Toggle::new("fake", false);
        let r = t.set(true, || {
            calls += 1;
            bail!("nope")
        });
        assert_eq!(r, (STATE_UNAVAILABLE, None));
        assert_eq!(t.set(false, || bail!("nope")), (STATE_UNAVAILABLE, None));
        assert_eq!(calls, 0);
        let mut t: Toggle<Held> = Toggle::new("fake", true);
        let (v, why) = t.set(true, || Held::start("fake", || -> Result<Fake> { bail!("device busy") }));
        assert_eq!(v, 0);
        assert!(why.unwrap().contains("device busy"));
        // A panic while switching on is a failure, not a crash of the caller.
        let (v, why) = t.set(true, || Held::start("fake", || -> Result<Fake> { panic!("driver bug") }));
        assert_eq!(v, 0);
        assert!(why.is_some());
        assert_eq!(t.set(false, || bail!("unused")), (0, None));
    }
}

/// End-to-end sessions over loopback against the real host, capturing this PC's screen
/// (read-only). Audio and privacy mode stay disabled: tests must not touch the speakers or
/// blank the screen.
#[cfg(all(test, windows))]
mod session_tests {
    use super::*;
    use crate::codec::Decoder;
    use crate::viewer::{Connection, ViewerOptions, connect};
    use std::sync::OnceLock;

    const PSK: [u8; 32] = [0x5a; 32];
    /// One host at a time: they share the screen (and DXGI duplications are limited).
    static SERIAL: Mutex<()> = Mutex::new(());
    static PULL_FILES: OnceLock<Vec<PathBuf>> = OnceLock::new();

    fn tmpdir(tag: &str) -> PathBuf {
        let mut r = [0u8; 8];
        crate::crypto::random(&mut r).unwrap();
        let d = std::env::temp_dir().join(format!("srdp-host-{tag}-{}", crate::util::hex_encode(&r)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    struct TestHost {
        port: u16,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<Result<()>>>,
    }

    impl TestHost {
        fn start(port: u16, configure: impl FnOnce(&mut HostOptions)) -> TestHost {
            let mut opts = HostOptions {
                bind: Some(IpAddr::from([127, 0, 0, 1])),
                port,
                policy: PeerPolicy { allow: vec![], allow_non_tailscale: false, loopback_ok: true },
                audio: false,
                privacy: false,
                copied_files: Vec::new,
                ..HostOptions::default()
            };
            configure(&mut opts);
            let listener = bind(&opts, &AtomicBool::new(false)).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let s = stop.clone();
            let thread = std::thread::spawn(move || serve(listener, opts, Secret(PSK), &s));
            TestHost { port, stop, thread: Some(thread) }
        }

        fn connect(&self, o: ViewerOptions) -> Client {
            let conn = connect(&format!("127.0.0.1:{}", self.port), &o, &Secret(PSK)).unwrap();
            conn.stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
            Client { conn, dec: Decoder::new().unwrap(), fb: Vec::new(), size: (0, 0), frames: Vec::new(), ack: true }
        }
    }

    impl Drop for TestHost {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let r = t.join();
                if !std::thread::panicking() {
                    r.unwrap().unwrap();
                }
            }
        }
    }

    struct Client {
        conn: Connection,
        dec: Decoder,
        fb: Vec<u8>,
        size: (usize, usize),
        /// Complete frames so far: (id, width, height).
        frames: Vec<(u32, usize, usize)>,
        ack: bool,
    }

    impl Client {
        fn send(&mut self, m: ClientMsg) {
            let mut b = Vec::new();
            m.encode(&mut b);
            self.conn.writer.send(&b).unwrap();
        }

        /// Reads one message, applying (and normally acknowledging) frames, and returns `f` of it.
        fn read<T>(&mut self, what: &str, f: impl FnOnce(&ServerMsg) -> Option<T>) -> Option<T> {
            let rec = match self.conn.reader.recv() {
                Ok(r) => r.to_vec(),
                Err(e) => panic!("waiting for {what}: {e}"),
            };
            let m = ServerMsg::decode(&rec).unwrap_or_else(|e| panic!("bad message while waiting for {what}: {e}"));
            if let ServerMsg::Tiles(p) = &m {
                let hdr = codec::parse_header(p).unwrap();
                if (hdr.width, hdr.height) != self.size {
                    self.size = (hdr.width, hdr.height);
                    self.fb = vec![0; hdr.width * hdr.height * 4];
                }
                self.dec.apply(p, &mut self.fb, hdr.width, hdr.height).unwrap();
                if hdr.last {
                    self.frames.push((hdr.frame, hdr.width, hdr.height));
                    if self.ack {
                        self.send(ClientMsg::Ack(hdr.frame));
                    }
                }
            }
            f(&m)
        }

        /// Reads until `f` picks a message.
        fn wait<T>(&mut self, what: &str, mut f: impl FnMut(&ServerMsg) -> Option<T>) -> T {
            let deadline = Instant::now() + Duration::from_secs(20);
            while Instant::now() < deadline {
                if let Some(v) = self.read(what, &mut f) {
                    return v;
                }
            }
            panic!("timed out waiting for {what}");
        }

        /// The `n`th complete frame (1-based), reading until it is there.
        fn frame(&mut self, n: usize) -> (u32, usize, usize) {
            let deadline = Instant::now() + Duration::from_secs(20);
            while self.frames.len() < n {
                assert!(Instant::now() < deadline, "timed out waiting for frame {n}");
                self.read("a frame", |_| Some(()));
            }
            self.frames[n - 1]
        }

        /// Waits for a frame of `w`x`h` (frames of the old size may still be in flight).
        fn frame_sized(&mut self, w: usize, h: usize) {
            let mut seen = self.frames.len();
            loop {
                let (_, fw, fh) = self.frame(seen + 1);
                if (fw, fh) == (w, h) {
                    return;
                }
                seen += 1;
            }
        }

        fn state(&mut self, key: u8, value: u32) -> u32 {
            self.send(ClientMsg::Set { key, value });
            self.wait("a state reply", |m| match m {
                ServerMsg::State { key: k, value } if *k == key => Some(*value),
                _ => None,
            })
        }

        fn ping(&mut self, t: u64) {
            self.send(ClientMsg::Ping(t));
            self.wait("pong", |m| matches!(m, ServerMsg::Pong(x) if *x == t).then_some(()));
        }

        fn notice(&mut self) -> String {
            self.wait("a notice", |m| match m {
                ServerMsg::Notice(t) => Some(t.clone()),
                _ => None,
            })
        }

        fn upload_result(&mut self, id: u32) -> (bool, String) {
            self.wait("an upload result", |m| match m {
                ServerMsg::FileResult { id: i, ok, message } if *i == id => Some((*ok, message.clone())),
                _ => None,
            })
        }
    }

    #[test]
    fn session_end_to_end() {
        let _serial = lock(&SERIAL);
        let dir = tmpdir("uploads");
        let host = TestHost::start(47410, |o| o.transfer_dir = Some(dir.clone()));
        let primary = capture::resolve(MonitorSel::Primary).expect("no monitor");
        let (pw, ph) = (primary.width as usize, primary.height as usize);
        let mut c = host.connect(ViewerOptions { audio: true, ..ViewerOptions::default() });

        // Hello: the primary monitor and accurate capabilities.
        assert_eq!((c.conn.width, c.conn.height, c.conn.monitor), (pw, ph, 0));
        assert_eq!(c.conn.flags & (F_FILES | F_AUDIO | F_PRIVACY | F_VIEW_ONLY | F_CLIPBOARD), F_FILES);
        // The audio wish is answered: audio is disabled on this host.
        let v = c.wait("the audio state", |m| match m {
            ServerMsg::State { key: SET_AUDIO, value } => Some(*value),
            _ => None,
        });
        assert_eq!(v, STATE_UNAVAILABLE);
        let first = c.frame(1);
        assert_eq!((first.1, first.2), (pw, ph), "first frame {first:?}, frames {:?}", c.frames);
        c.ping(0x1234_5678_9abc);

        // Settings are confirmed with the value in effect.
        assert_eq!(c.state(SET_QUALITY, QUALITY_LOW), QUALITY_LOW);
        assert_eq!(c.state(SET_QUALITY, 77), QUALITY_LOW);
        assert_eq!(c.state(SET_QUALITY, QUALITY_LOSSLESS), QUALITY_LOSSLESS);
        assert_eq!(c.state(SET_PRIVACY, 1), STATE_UNAVAILABLE);
        assert_eq!(c.state(SET_AUDIO, 1), STATE_UNAVAILABLE);
        assert_eq!(c.state(99, 1), STATE_UNAVAILABLE);
        assert_eq!(c.state(SET_MONITOR, 200), 0);

        // Half resolution; frames keep coming as long as they are acknowledged.
        assert_eq!(c.state(SET_DOWNSCALE, 2), 2);
        c.frame_sized(pw / 2, ph / 2);
        assert_eq!(c.state(SET_DOWNSCALE, 9), 2);
        for _ in 0..3 {
            let n = c.frames.len();
            c.send(ClientMsg::Refresh);
            assert_eq!(c.frame(n + 1).1, pw / 2);
        }
        assert_eq!(c.state(SET_DOWNSCALE, 1), 1);
        c.frame_sized(pw, ph);

        // The whole desktop, then back to the default monitor.
        let all = capture::resolve(MonitorSel::All).unwrap();
        assert_eq!(c.state(SET_MONITOR, MONITOR_ALL as u32), MONITOR_ALL as u32);
        c.frame_sized(all.width as usize, all.height as usize);
        assert_eq!(c.state(SET_MONITOR, MONITOR_DEFAULT as u32), 0);
        c.frame_sized(pw, ph);

        // Flow control: without acks at most MAX_IN_FLIGHT frames are outstanding.
        c.ack = false;
        let acked = c.frames.last().unwrap().0;
        for _ in 0..4 {
            c.send(ClientMsg::Refresh);
            std::thread::sleep(Duration::from_millis(250));
        }
        c.ping(1);
        let outstanding = c.frames.iter().filter(|f| f.0 > acked).count();
        assert!((1..=MAX_IN_FLIGHT as usize).contains(&outstanding), "{outstanding} frames outstanding");
        c.ack = true;
        let last = c.frames.last().unwrap().0;
        c.send(ClientMsg::Ack(last));
        let n = c.frames.len();
        c.send(ClientMsg::Refresh);
        c.frame(n + 1);

        // Upload: saved under its name, content intact, the path reported back.
        let content: Vec<u8> = (0..700_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let name = "upload 시험.bin";
        c.send(ClientMsg::FileBegin { id: 7, size: content.len() as u64, name: name.into() });
        for chunk in content.chunks(256 * 1024) {
            c.send(ClientMsg::FileData { id: 7, data: chunk.to_vec() });
        }
        c.send(ClientMsg::FileEnd { id: 7, sha256: crate::crypto::sha256(&[&content]) });
        let (ok, msg) = c.upload_result(7);
        assert!(ok, "{msg}");
        assert_eq!(PathBuf::from(&msg), dir.join(name));
        assert!(std::fs::read(dir.join(name)).unwrap() == content);

        // A corrupted upload is refused and leaves nothing behind.
        c.send(ClientMsg::FileBegin { id: 8, size: 3, name: "bad.bin".into() });
        c.send(ClientMsg::FileData { id: 8, data: b"abc".to_vec() });
        c.send(ClientMsg::FileEnd { id: 8, sha256: [0; 32] });
        let (ok, msg) = c.upload_result(8);
        assert!(!ok && msg.contains("checksum"), "{msg}");
        // Stray data for unknown uploads is ignored without a reply.
        c.send(ClientMsg::FileData { id: 99, data: vec![1] });
        c.send(ClientMsg::FileEnd { id: 99, sha256: [0; 32] });
        c.ping(2);
        assert_eq!(entries(&dir), [name]);

        // Nothing copied on the host.
        c.send(ClientMsg::FilePull);
        assert!(c.notice().contains("no files"));

        // At most MAX_UPLOADS at once; a reused id cancels both.
        for id in 20..20 + MAX_UPLOADS as u32 {
            c.send(ClientMsg::FileBegin { id, size: 10, name: format!("part{id}.bin") });
            c.send(ClientMsg::FileData { id, data: vec![1; 4] });
        }
        c.send(ClientMsg::FileBegin { id: 30, size: 10, name: "one too many.bin".into() });
        let (ok, msg) = c.upload_result(30);
        assert!(!ok && msg.contains("too many"), "{msg}");
        c.send(ClientMsg::FileBegin { id: 20, size: 10, name: "again.bin".into() });
        assert!(!c.upload_result(20).0);
        c.ping(3);
        // The finished upload plus the three partial ones still open (hidden .part files).
        assert_eq!(entries(&dir).len(), 1 + MAX_UPLOADS - 1);

        // A protocol error ends the session, and the partial uploads go with it.
        c.conn.writer.send(&[0x7f]).unwrap();
        let t = Instant::now();
        while c.conn.reader.recv().is_ok() {
            assert!(t.elapsed() < Duration::from_secs(10), "the session survived a protocol error");
        }
        let t = Instant::now();
        while entries(&dir).len() > 1 && t.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(entries(&dir), [name]);
        drop(host);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn view_only_pull_and_replacement() {
        let _serial = lock(&SERIAL);
        {
            let dir = tmpdir("view-only");
            let host = TestHost::start(47411, |o| {
                o.view_only = true;
                o.transfer_dir = Some(dir.clone());
            });
            // Privacy mode is refused in view-only sessions, also when asked for in the hello.
            let mut c = host.connect(ViewerOptions { privacy: true, ..ViewerOptions::default() });
            assert_eq!(c.conn.flags & (F_FILES | F_VIEW_ONLY | F_PRIVACY), F_VIEW_ONLY);
            let v = c.wait("the privacy state", |m| match m {
                ServerMsg::State { key: SET_PRIVACY, value } => Some(*value),
                _ => None,
            });
            assert_eq!(v, STATE_UNAVAILABLE);
            c.send(ClientMsg::FileBegin { id: 1, size: 1, name: "x.bin".into() });
            c.send(ClientMsg::FileData { id: 1, data: vec![1] });
            c.send(ClientMsg::FileEnd { id: 1, sha256: crate::crypto::sha256(&[&[1]]) });
            let (ok, msg) = c.upload_result(1);
            assert!(!ok && msg.contains("view-only"), "{msg}");
            c.send(ClientMsg::FilePull);
            assert!(c.notice().contains("view-only"));
            assert_eq!(c.state(SET_PRIVACY, 1), STATE_UNAVAILABLE);
            c.frame(1);
            assert!(entries(&dir).is_empty());
            let _ = std::fs::remove_dir_all(&dir);
        }

        // Pull: the copied files arrive one after another; one that vanished is reported.
        let src = tmpdir("pull-src");
        let dst = tmpdir("pull-dst");
        let a: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        std::fs::write(src.join("a.txt"), &a).unwrap();
        std::fs::write(src.join("empty.bin"), b"").unwrap();
        PULL_FILES.set(vec![src.join("a.txt"), src.join("missing.txt"), src.join("empty.bin")]).unwrap();
        let host = TestHost::start(47412, |o| o.copied_files = || PULL_FILES.get().cloned().unwrap_or_default());
        let mut c = host.connect(ViewerOptions::default());
        c.send(ClientMsg::FilePull);
        let mut current: Option<Incoming> = None;
        let mut received = Vec::new();
        let mut notices = Vec::new();
        while received.len() < 2 {
            let done = c.wait("pulled files", |m| match m {
                ServerMsg::FileBegin { id, size, name } => {
                    assert!(current.is_none());
                    current = Some(Incoming::begin(&dst, *id, *size, name).unwrap());
                    Some(None)
                }
                ServerMsg::FileData { id, data } => {
                    let inc = current.as_mut().unwrap();
                    assert_eq!(inc.id, *id);
                    inc.write(data).unwrap();
                    Some(None)
                }
                ServerMsg::FileEnd { id, sha256 } => {
                    let inc = current.take().unwrap();
                    assert_eq!(inc.id, *id);
                    Some(Some((*id, inc.finish(sha256).unwrap())))
                }
                ServerMsg::Notice(t) => {
                    notices.push(t.clone());
                    Some(None)
                }
                _ => None,
            });
            received.extend(done);
        }
        assert_eq!(received.iter().map(|r| r.0).collect::<Vec<_>>(), [1, 3]);
        assert!(std::fs::read(&received[0].1).unwrap() == a);
        assert_eq!(received[1].1.file_name().unwrap(), "empty.bin");
        assert!(std::fs::read(&received[1].1).unwrap().is_empty());
        assert!(notices.len() == 1 && notices[0].contains("missing.txt"), "{notices:?}");
        c.frame(1);

        // A second viewer replaces the first at once, although the first keeps its socket open
        // (the old session must not linger in a blocked read until its I/O timeout).
        let t = Instant::now();
        let mut c2 = host.connect(ViewerOptions::default());
        assert!(t.elapsed() < Duration::from_secs(3), "handover took {:?}", t.elapsed());
        let t = Instant::now();
        while c.conn.reader.recv().is_ok() {
            assert!(t.elapsed() < Duration::from_secs(10), "the first viewer was not disconnected");
        }
        c2.frame(1);
        c2.ping(9);

        // Stopping the host ends its session promptly, with the viewer still connected.
        let t = Instant::now();
        drop(host);
        assert!(t.elapsed() < Duration::from_secs(3), "stopping took {:?}", t.elapsed());
        let t = Instant::now();
        while c2.conn.reader.recv().is_ok() {
            assert!(t.elapsed() < Duration::from_secs(10), "the session outlived the host");
        }
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }
}
