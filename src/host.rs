//! Host side: listens on the Tailscale interface, authenticates viewers and streams the screen.
//!
//! One session at a time; a new viewer replaces the current one (an automatic reconnect only
//! its own viewer's, see `takes_over`), which is told why. Inside a session:
//! * the capture thread grabs, encodes and sends frames (at most `MAX_IN_FLIGHT` unacknowledged),
//!   applies quality, scale and monitor changes and refines lossy regions once they settle;
//! * the receiving thread reads what the viewer sends, and the input thread handles it: input,
//!   clipboard, settings, uploads;
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
use std::sync::{Arc, Mutex, MutexGuard, TryLockError, mpsc};
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
    /// `transfer_dir` is the service's own folder, which only SYSTEM and Administrators can
    /// change: uploads are saved there with the host's own rights, up to `OWN_DIR_BYTES` /
    /// `OWN_DIR_FILES`. Any other folder is written as the user signed in on the console
    /// (`FileUser`), so a host running as SYSTEM never follows a path that user can redirect.
    pub own_transfer_dir: bool,
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
            own_transfer_dir: false,
            copied_files: clipboard::copied_files,
        }
    }
}

/// Longest a handshake may take in all, however the peer paces its bytes.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Handshakes in progress at once, in all and per source (see `source`).
const MAX_PENDING: usize = 8;
const MAX_PENDING_PER_ADDR: usize = 2;
const MAX_PENDING_PER_NET: usize = 4;
/// How long a failed handshake keeps its source's slot (slows down guessing).
const FAILURE_PENALTY: Duration = Duration::from_secs(1);
/// Failed handshakes serving their penalty at once; while this many are, nobody is admitted.
const MAX_PENALTIES: usize = 64;
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
/// Bytes one capture tick spends on changed regions and lossless refinement together;
/// refinement still adds one run when the changes took all of it, so it always progresses.
const REFINE_BUDGET: usize = 256 * 1024;
/// Setting changes waiting for the capture thread, which applies at most this many per tick.
/// A viewer that sends more waits for it, so a flood of `Set`s neither grows the queue nor
/// keeps the capture thread from frames and its checks.
const SETTINGS_QUEUE: usize = 16;
/// Longest a replaced viewer's farewell waits for a record already being sent, and how long a
/// turned-away viewer's connection is drained.
const FAREWELL: Duration = Duration::from_secs(1);
/// How long a replaced viewer's connection stays open after its farewell, for the viewer to
/// work through what it has not read yet up to the notice (`drain`), and how many connections
/// may wait like that at once; beyond that a replaced session's connection closes at once.
const DRAIN_FOR: Duration = Duration::from_secs(20);
const MAX_DRAINS: usize = 4;
/// Messages the receiving thread reads ahead of the input thread.
const RECEIVED_QUEUE: usize = 4;
/// How soon the input thread notices that its session was stopped while it waits for messages.
const STOP_POLL: Duration = Duration::from_millis(50);
/// Uploads a viewer may have open at once.
const MAX_UPLOADS: usize = 4;
/// What the service's own upload folder may hold, uploads still arriving included: only an
/// administrator can empty it.
const OWN_DIR_BYTES: u64 = MAX_FILE_SIZE;
const OWN_DIR_FILES: usize = 1000;
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
    /// The session's sending half while it has one, for `kick_with_notice`.
    out: Mutex<Option<Arc<Out>>>,
    /// The viewer's instance (0: none), which an automatic reconnect must match: from its hello,
    /// else from its `ClientMsg::Instance` (`name`).
    instance: AtomicU64,
    link: Mutex<Link>,
}

/// What ending a session does to its connection.
enum Link {
    /// In use: `kick` shuts it down, waking every thread blocked on it.
    Live,
    /// A farewell is on its way to the viewer: nothing the session does closes the connection,
    /// which stays open after the session until the receiving thread has drained it with this
    /// slot (`drain`), so that no reset overtakes the notice.
    Parting(Option<DrainSlot>),
    Closed,
}

impl SessionCtl {
    fn new(sock: TcpStream, instance: u64) -> SessionCtl {
        SessionCtl {
            stop: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            sock,
            out: Mutex::new(None),
            instance: AtomicU64::new(instance),
            link: Mutex::new(Link::Live),
        }
    }
    /// Names a session whose viewer has no instance yet; the first name stays.
    fn name(&self, instance: u64) {
        let _ = self.instance.compare_exchange(0, instance, Ordering::SeqCst, Ordering::SeqCst);
    }
    fn kick(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let mut link = lock(&self.link);
        if !matches!(*link, Link::Parting(_)) {
            *link = Link::Closed;
            let _ = self.sock.shutdown(Shutdown::Both);
            wake_blocked_io(&self.sock);
        }
    }
    /// `kick`, a parting connection included.
    fn kill(&self) {
        *lock(&self.link) = Link::Closed;
        self.kick();
    }
    /// Ends the session after telling the viewer why. A viewer reconnects after a close it was
    /// not told about, which for a replaced one would throw the newcomer out in turn. The
    /// session winds down at once; the notice goes out behind whatever the viewer has not read
    /// yet, on a thread of its own, so the newcomer never waits for that, and the connection
    /// stays open until the viewer has read it. With `MAX_DRAINS` connections parting already,
    /// or if the notice cannot go out, the connection is shut down instead.
    fn kick_with_notice(self: &Arc<Self>, text: &str, drains: &Arc<AtomicUsize>) {
        let out = lock(&self.out).clone();
        if let (Some(out), Some(slot)) = (out, DrainSlot::take(drains))
            && self.part(slot)
        {
            self.stop.store(true, Ordering::SeqCst);
            // From now on only the farewell sends.
            out.parting.store(true, Ordering::SeqCst);
            let (ctl, text) = (self.clone(), text.to_string());
            let farewell = move || {
                if !out.farewell(&ctl.sock, &text) {
                    ctl.kill();
                }
            };
            if std::thread::Builder::new().name("farewell".into()).spawn(farewell).is_ok() {
                return;
            }
        }
        self.kill();
    }
    /// Leaves the connection open past the session (`Link::Parting`); false if it is closed already.
    fn part(&self, slot: DrainSlot) -> bool {
        let mut link = lock(&self.link);
        let live = matches!(*link, Link::Live);
        if live {
            *link = Link::Parting(Some(slot));
        }
        live
    }
    /// The drain slot of a parting connection, once.
    fn drain_slot(&self) -> Option<DrainSlot> {
        match &mut *lock(&self.link) {
            Link::Parting(slot) => slot.take(),
            _ => None,
        }
    }
    /// Returns once a parting connection is closed, and closes it at its drain deadline. The
    /// receiving thread drains it only once its read returns, which for a viewer that sends
    /// nothing takes up to `IO_TIMEOUT`, and a farewell the viewer does not read waits as long to
    /// be sent: closing the connection wakes both, and gives the drain slot back.
    fn close_parted(&self) {
        loop {
            match &*lock(&self.link) {
                Link::Parting(Some(slot)) if Instant::now() >= slot.until => break,
                // Without its slot the receiving thread is draining, up to the same deadline.
                Link::Parting(_) => {}
                Link::Live | Link::Closed => return,
            }
            std::thread::sleep(STOP_POLL);
        }
        self.kill();
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

/// One of `MAX_DRAINS` connections left open after their session for the viewer to read its
/// farewell, until `until`.
struct DrainSlot {
    count: Arc<AtomicUsize>,
    until: Instant,
}

impl DrainSlot {
    fn take(count: &Arc<AtomicUsize>) -> Option<DrainSlot> {
        count.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < MAX_DRAINS).then_some(n + 1)).ok()?;
        Some(DrainSlot { count: count.clone(), until: Instant::now() + DRAIN_FOR })
    }
}

impl Drop for DrainSlot {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Reads and discards what a viewer still sends until it hangs up, or until `until`, so that
/// its connection closes in order. Closing a connection the viewer still sends on (or shutting
/// it down for reading) resets it, and a reset discards what the viewer has not read yet: a
/// farewell queued behind frames it is still working through.
fn drain(sock: &TcpStream, until: Instant) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() || sock.set_read_timeout(Some(left)).is_err() {
            return;
        }
        let read = match (&mut &*sock).read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => 0,
        };
        if read == 0 {
            return;
        }
    }
}

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
    /// Replaced sessions' connections being drained (`DrainSlot`).
    drains: Arc<AtomicUsize>,
}

impl Host {
    fn new(opts: HostOptions, psk: Secret<32>) -> Host {
        Host {
            opts,
            psk,
            current: Mutex::new(None),
            pending: Mutex::new(Pending::default()),
            quiet: Mutex::new(Quiet::new(Instant::now())),
            stopping: AtomicBool::new(false),
            drains: Arc::new(AtomicUsize::new(0)),
        }
    }

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

/// Who a connection counts as for the per-address limits (an IPv4-mapped address as IPv4).
fn source(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Outside Tailscale (whose addresses each belong to one node) one peer can often pick any
/// address in an IPv6 /64, so the /64 has a limit of its own, larger than one address's.
fn network(ip: IpAddr) -> Option<IpAddr> {
    match source(ip) {
        IpAddr::V6(v6) if !net::is_tailscale(ip) => Some(IpAddr::V6((u128::from(v6) & (u128::MAX << 64)).into())),
        _ => None,
    }
}

fn count_down(map: &mut HashMap<IpAddr, usize>, key: IpAddr) {
    if let Some(n) = map.get_mut(&key) {
        *n -= 1;
        if *n == 0 {
            map.remove(&key);
        }
    }
}

/// Handshakes in progress: at most `MAX_PENDING` in all, `MAX_PENDING_PER_ADDR` from one
/// address and `MAX_PENDING_PER_NET` from one non-Tailscale IPv6 /64, so one peer without the
/// key cannot keep everybody else out. A failed one leaves the total but keeps its source's
/// place for `FAILURE_PENALTY`; at most `MAX_PENALTIES` do at once, so peers with many
/// addresses cannot make the host hold ever more threads.
#[derive(Default)]
struct Pending {
    total: usize,
    penalties: usize,
    per_addr: HashMap<IpAddr, usize>,
    per_net: HashMap<IpAddr, usize>,
}

impl Pending {
    fn admit(&mut self, ip: IpAddr) -> std::result::Result<(), &'static str> {
        let src = source(ip);
        let n = self.per_addr.get(&src).copied().unwrap_or(0);
        if n >= MAX_PENDING_PER_ADDR {
            return Err("too many pending handshakes from this address");
        }
        let net = network(ip);
        if net.is_some_and(|k| self.per_net.get(&k).copied().unwrap_or(0) >= MAX_PENDING_PER_NET) {
            return Err("too many pending handshakes from this network");
        }
        if self.total >= MAX_PENDING {
            return Err("too many pending handshakes");
        }
        if self.penalties >= MAX_PENALTIES {
            return Err("too many failed handshakes");
        }
        self.total += 1;
        self.per_addr.insert(src, n + 1);
        if let Some(k) = net {
            *self.per_net.entry(k).or_default() += 1;
        }
        Ok(())
    }

    /// A handshake failed: it leaves the total and starts its penalty.
    fn penalize(&mut self) {
        self.total = self.total.saturating_sub(1);
        self.penalties += 1;
    }

    /// A handshake (`penalized`: its penalty) is over.
    fn leave(&mut self, ip: IpAddr, penalized: bool) {
        let n = if penalized { &mut self.penalties } else { &mut self.total };
        *n = n.saturating_sub(1);
        count_down(&mut self.per_addr, source(ip));
        if let Some(k) = network(ip) {
            count_down(&mut self.per_net, k);
        }
    }
}

/// A handshake's place in `Host::pending`, given back when dropped.
struct Slot {
    host: Arc<Host>,
    ip: IpAddr,
    /// Serving the failure penalty: counted against `MAX_PENALTIES`, not `MAX_PENDING`.
    penalized: bool,
}

impl Slot {
    /// Gives back the place in the total but keeps the source's own (the failure penalty).
    fn penalize(&mut self) {
        if !std::mem::replace(&mut self.penalized, true) {
            lock(&self.host.pending).penalize();
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        lock(&self.host.pending).leave(self.ip, self.penalized);
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
        // Only logging: a whole /64 may share one budget.
        let src = network(ip).unwrap_or_else(|| source(ip));
        let n = self.per_addr.get(&src).copied().unwrap_or(0);
        if self.shown >= QUIET_TOTAL || n >= QUIET_PER_ADDR {
            self.dropped += 1;
            return false;
        }
        self.shown += 1;
        self.per_addr.insert(src, n + 1);
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
    let host = Arc::new(Host::new(opts, psk));
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
        let mut slot = Slot { host: host.clone(), ip: peer.ip(), penalized: false };
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
                    slot.penalize();
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

/// The viewer's first message (`ClientMsg::Hello`).
struct Hello {
    downscale: u8,
    quality: u8,
    monitor: u8,
    flags: u8,
    instance: u64,
}

/// Sets up an authenticated connection's records and reads the viewer's hello.
fn read_hello(stream: TcpStream, keys: channel::SessionKeys) -> Result<(Arc<Out>, RecordReader<TcpStream>, Hello)> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let out = Arc::new(Out::new(RecordWriter::new(stream.try_clone()?, keys.send)));
    let mut reader = RecordReader::new(stream, keys.recv);
    match ClientMsg::decode(reader.recv()?)? {
        ClientMsg::Hello { downscale, quality, monitor, flags, instance } => {
            Ok((out, reader, Hello { downscale, quality, monitor, flags, instance }))
        }
        _ => bail!("protocol error: viewer did not start with a hello"),
    }
}

/// Whether a viewer whose hello has `flags` and `instance` may replace the live session, whose
/// viewer's instance is `live` (`None`: no session). A new connection does, as a user who moves
/// to another PC expects. An automatic reconnect takes back only its own viewer's session (one
/// whose connection it lost), never another viewer's: the one connected since must stay.
fn takes_over(flags: u8, instance: u64, live: Option<u64>) -> bool {
    flags & HELLO_RECONNECT == 0 || live.is_none_or(|l| l != 0 && l == instance)
}

/// Turns a viewer away: tells it why in place of the host's hello, which ends its reconnects,
/// and closes the connection in order.
fn refuse(out: &Out, sock: &TcpStream, text: &str) {
    if out.send(&ServerMsg::Notice(short(text.into()))).is_ok() && sock.shutdown(Shutdown::Write).is_ok() {
        drain(sock, Instant::now() + FAREWELL);
    }
}

fn serve_session(host: &Arc<Host>, stream: TcpStream, peer: SocketAddr, keys: channel::SessionKeys) {
    let Ok(sock) = stream.try_clone() else { return };
    // The hello first: whether this viewer may replace the live session depends on it.
    let (out, reader, hello) = match read_hello(stream, keys) {
        Ok(h) => h,
        Err(e) => {
            log!("no session for {peer}: {e}");
            return;
        }
    };
    let ctl = Arc::new(SessionCtl::new(sock, hello.instance));
    let old = {
        let mut cur = lock(&host.current);
        if host.stopping.load(Ordering::SeqCst) {
            return;
        }
        let live = cur.as_ref().filter(|c| !c.stopped()).map(|c| c.instance.load(Ordering::SeqCst));
        if !takes_over(hello.flags, hello.instance, live) {
            drop(cur);
            log!("refused {peer}: an automatic reconnect does not replace another viewer's session");
            refuse(&out, &ctl.sock, "another viewer is using this host");
            return;
        }
        cur.replace(ctl.clone())
    };
    if let Some(old) = old {
        log!("replacing the existing session");
        old.kick_with_notice("another viewer connected to this host", &host.drains);
        // Let it release its screen duplication, injected keys and privacy mode first.
        old.wait_finished(Duration::from_secs(5));
    }
    log!("session started: {peer}");
    let r = run_session(host, out, reader, &hello, &ctl);
    lock(&ctl.out).take();
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
    // A replaced session's connection may still be parting: it closes by its drain deadline.
    ctl.close_parted();
}

/// The sending half of a session, shared by the capture, input, clipboard, audio and file threads.
struct Out {
    /// The writer; the farewell takes it away (`farewell`).
    w: Mutex<Option<RecordWriter<TcpStream>>>,
    /// Threads waiting to send frames or replies; bulk file data lets them go first.
    waiting: AtomicUsize,
    /// The writer is the farewell's: every other send fails.
    parting: AtomicBool,
}

impl Out {
    fn new(w: RecordWriter<TcpStream>) -> Out {
        Out { w: Mutex::new(Some(w)), waiting: AtomicUsize::new(0), parting: AtomicBool::new(false) }
    }

    fn writer<'a>(&self, w: &'a mut Option<RecordWriter<TcpStream>>) -> Result<&'a mut RecordWriter<TcpStream>> {
        match w {
            Some(w) if !self.parting.load(Ordering::SeqCst) => Ok(w),
            _ => bail!("the session is ending"),
        }
    }

    /// Sends one complete message (type byte included).
    fn send_record(&self, rec: &[u8]) -> Result<()> {
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let mut w = lock(&self.w);
        self.waiting.fetch_sub(1, Ordering::SeqCst);
        self.writer(&mut w)?.send(rec)
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
        self.writer(&mut lock(&self.w))?.send(&b)
    }

    fn notice(&self, text: String) -> Result<()> {
        self.send(&ServerMsg::Notice(short(text)))
    }

    /// Sends `text` as the session's last message and ends the stream behind it; true if both
    /// went out. Every other send fails once `parting` is set, so only a record already being
    /// sent holds the writer, for at most `FAREWELL`: a writer stuck that long means no notice
    /// (its send still holds the session, the screen included). The farewell then takes the
    /// writer away, so that no thread of the session waits while the notice waits behind what
    /// the viewer has not read yet, until the connection closes (`close_parted`).
    fn farewell(&self, sock: &TcpStream, text: &str) -> bool {
        let t = Instant::now();
        let w = loop {
            match self.w.try_lock() {
                Ok(mut w) => break w.take(),
                Err(TryLockError::Poisoned(e)) => break e.into_inner().take(),
                Err(TryLockError::WouldBlock) if t.elapsed() < FAREWELL => std::thread::sleep(Duration::from_millis(5)),
                Err(TryLockError::WouldBlock) => return false,
            }
        };
        let mut b = Vec::new();
        ServerMsg::Notice(short(text.into())).encode(&mut b);
        w.is_some_and(|mut w| w.send(&b).is_ok()) && sock.shutdown(Shutdown::Write).is_ok()
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
    /// The hello named no quality (`QUALITY_DEFAULT`, or one this host does not know):
    /// `quality` is the host's default, and the viewer is told which.
    host_quality: bool,
    audio: bool,
    privacy: bool,
}

fn negotiate(opts: &HostOptions, downscale: u8, quality: u8, monitor: u8, flags: u8, exists: impl Fn(MonitorSel) -> bool) -> Start {
    let fallback = if opts.default_quality <= QUALITY_LOW { opts.default_quality } else { QUALITY_BALANCED };
    let host_quality = quality as u32 > QUALITY_LOW;
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
        quality: if host_quality { fallback } else { quality as u32 },
        host_quality,
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
    // What every session of this host does (viewers send instances only to hosts that say so).
    let mut flags = F_INSTANCE | F_QUALITY_STATE;
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

fn run_session(host: &Arc<Host>, out: Arc<Out>, reader: RecordReader<TcpStream>, hello: &Hello, ctl: &Arc<SessionCtl>) -> Result<()> {
    let opts = &host.opts;
    let start = negotiate(opts, hello.downscale, hello.quality, hello.monitor, hello.flags, |s| capture::resolve(s).is_some());

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
    let (received_tx, received) = mpsc::sync_channel(RECEIVED_QUEUE);
    {
        let ctl = ctl.clone();
        std::thread::Builder::new().name("receive".into()).spawn(move || receive(reader, received_tx, &ctl))?;
    }
    // From here on a replacement can say goodbye: the viewer has its hello, and the receiving
    // thread is there to drain the connection afterwards.
    *lock(&ctl.out) = Some(out.clone());
    if start.host_quality {
        // The viewer left the quality to this host: tell it which one is in effect.
        out.send(&ServerMsg::State { key: SET_QUALITY, value: start.quality })?;
    }
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

    let (settings_tx, settings_rx) = mpsc::sync_channel(SETTINGS_QUEUE);
    let input_thread = {
        let (host, out, shared, ctl) = (host.clone(), out.clone(), shared.clone(), ctl.clone());
        let wishes = (start.audio, start.privacy);
        std::thread::Builder::new().name("input".into()).spawn(move || {
            let _kick = KickOnDrop(ctl.clone());
            Input::new(host, out, shared, ctl, clip, settings_tx, flags).run(received, wishes)
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

/// The receiving thread: reads the viewer's messages for the input thread until the session or
/// the connection ends (its last message is the error that ended it), then drains a replaced
/// session's connection and closes it, a farewell still waiting to be sent included. It holds
/// nothing of the session but the connection.
fn receive(mut reader: RecordReader<TcpStream>, to_input: mpsc::SyncSender<Result<ClientMsg>>, ctl: &SessionCtl) {
    while !ctl.stopped() {
        let m = reader.recv().and_then(ClientMsg::decode);
        let end = m.is_err();
        if to_input.send(m).is_err() || end {
            break;
        }
    }
    if let Some(slot) = ctl.drain_slot() {
        drain(&ctl.sock, slot.until);
        ctl.kill();
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
    settings: mpsc::SyncSender<(u8, u32)>,
    inj: Injector,
    follower: DesktopFollower,
    last_sync: Instant,
    /// Uploads and pulls are allowed in this session.
    files: bool,
    uploads: HashMap<u32, Upload>,
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
        settings: mpsc::SyncSender<(u8, u32)>,
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

    fn run(mut self, received: mpsc::Receiver<Result<ClientMsg>>, wishes: (bool, bool)) -> Result<()> {
        match self.serve(received, wishes) {
            // Ended from elsewhere (replaced, host stopping, capture failed): not this side's error.
            Err(_) if self.ctl.stopped() => Ok(()),
            r => r,
        }
    }

    fn serve(&mut self, received: mpsc::Receiver<Result<ClientMsg>>, (audio, privacy): (bool, bool)) -> Result<()> {
        if audio {
            self.set_feature(SET_AUDIO, 1)?;
        }
        if privacy {
            self.set_feature(SET_PRIVACY, 1)?;
        }
        // Not blocked on the socket (the receiving thread is), so a stopped session lets go of
        // its keys, privacy mode and the rest at once, even while its connection stays open.
        while !self.ctl.stopped() {
            match received.recv_timeout(STOP_POLL) {
                Ok(_) if self.ctl.stopped() => {}
                Ok(m) => self.handle(m?)?,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => bail!("the receiving thread ended"),
            }
            // Releases Windows refused, an earlier session's included, go out soon after the
            // input desktop is back, also when the viewer sends no input. Not only on the
            // timeout: a viewer's frame acks may keep it from ever coming.
            #[cfg(windows)]
            if !self.host.opts.view_only {
                self.inj.retry_owed();
            }
        }
        Ok(())
    }

    fn handle(&mut self, m: ClientMsg) -> Result<()> {
        match m {
            ClientMsg::Ack(id) => self.shared.acked.store(id, Ordering::SeqCst),
            ClientMsg::Refresh => self.shared.refresh.store(true, Ordering::SeqCst),
            ClientMsg::Ping(t) => self.out.send(&ServerMsg::Pong(t))?,
            ClientMsg::Hello { .. } => {}
            ClientMsg::Instance(id) => self.ctl.name(id),
            ClientMsg::Set { key: key @ (SET_QUALITY | SET_DOWNSCALE | SET_MONITOR), value } => {
                // Waits while `SETTINGS_QUEUE` changes are pending (the capture thread takes them
                // within a tick), so a flood slows down its sender instead of growing the queue.
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
            self.open_upload(id, size, name)
        };
        match r {
            Ok(up) => {
                log!("receiving file {name} ({size} bytes)");
                self.uploads.insert(id, up);
                Ok(())
            }
            Err(e) => {
                self.log_refusal(format!("refused upload of {} ({size} bytes): {e}", printable(name)));
                self.file_result(id, false, e.to_string())
            }
        }
    }

    /// Creates the partial file of an upload. A host running as SYSTEM (the service's agent)
    /// saves uploads as the user signed in on the console, like pulls, and so takes them only
    /// while somebody is; into the service's own folder it saves them itself, also at the
    /// sign-in screen, leaving that folder's volume the larger reserve.
    fn open_upload(&mut self, id: u32, size: u64, name: &str) -> Result<Upload> {
        let own = self.host.opts.own_transfer_dir;
        let user = upload_user(own, FileUser::get)?;
        let file = as_user(user.as_ref(), || -> Result<Incoming> {
            let dir = self.upload_dir()?;
            if own {
                let arriving = self.uploads.values().map(|u| u.file.size - u.file.received()).sum();
                own_dir_room(&dir, arriving, size, OWN_DIR_BYTES, OWN_DIR_FILES)?;
                return Incoming::begin_keeping(&dir, id, size, name, files::Reserve::ServiceFolder);
            }
            Incoming::begin(&dir, id, size, name)
        })??;
        Ok(Upload { file, user })
    }

    fn upload_data(&mut self, id: u32, data: &[u8]) -> Result<()> {
        // Data for an upload that was refused or failed earlier is dropped silently.
        let Some(up) = self.uploads.get_mut(&id) else { return Ok(()) };
        // Written through the open file: no path is looked up, so no need to act as the user.
        let Err(e) = up.file.write(data) else { return Ok(()) };
        log!("upload of {} ({} bytes) failed: {e}", up.file.name, up.file.size);
        // Dropping it removes the partial file.
        self.uploads.remove(&id);
        self.file_result(id, false, e.to_string())
    }

    fn upload_end(&mut self, id: u32, sha256: &[u8; 32]) -> Result<()> {
        let Some(up) = self.uploads.remove(&id) else { return Ok(()) };
        let (name, size) = (up.file.name.clone(), up.file.size);
        match up.finish(sha256) {
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

/// An upload in progress, and the user it is saved as (None: the host itself, in the
/// service's own folder).
struct Upload {
    file: Incoming,
    user: Option<FileUser>,
}

impl Upload {
    /// Moves the file into place as its user: the folder it goes to is looked up again.
    fn finish(self, sha256: &[u8; 32]) -> Result<PathBuf> {
        let Upload { file, user } = self;
        as_user(user.as_ref(), || file.finish(sha256))?
    }
}

/// Who an upload is saved as: the host itself (None) in the service's own folder (`own`), which
/// only SYSTEM and administrators can change, so no console user is looked up and uploads arrive
/// at the sign-in screen too; otherwise the console user (`get`), and no upload without one.
fn upload_user<U>(own: bool, get: impl FnOnce() -> Result<U>) -> Result<Option<U>> {
    if own { Ok(None) } else { get().map(Some) }
}

/// Runs `f` as `user`, or as the host itself.
fn as_user<T>(user: Option<&FileUser>, f: impl FnOnce() -> T) -> Result<T> {
    match user {
        Some(u) => u.act(f),
        None => Ok(f()),
    }
}

/// Refuses an upload of `size` bytes that would take `dir` beyond `max_bytes` or `max_files`,
/// counting `arriving` bytes of the uploads still in progress (their parts are entries already).
fn own_dir_room(dir: &Path, arriving: u64, size: u64, max_bytes: u64, max_files: usize) -> Result<()> {
    let (bytes, entries) = files::dir_usage(dir)?;
    if entries >= max_files || bytes.saturating_add(arriving).saturating_add(size) > max_bytes {
        bail!(
            "{} is full (it takes at most {max_files} files and {} GiB in all); an administrator has to empty it",
            dir.display(),
            max_bytes >> 30
        );
    }
    Ok(())
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

/// Adds to a tick's `rects` (what `encode` found changed in `pixels`, the frame it last saw)
/// the lossless refinement of lossy regions that have settled, within what is left of
/// `REFINE_BUDGET`. Tiles just encoded have normally not settled yet, so they are not sent
/// twice; an encode slower than the settle delay can have them refined in the same frame,
/// which only costs bytes: each tile is in it at most twice, within the decoder's limit of
/// twice the screen. One frame per tick keeps flow control as it was.
fn add_refinement(encoder: &mut Encoder, pixels: &[u8], w: usize, h: usize, rects: &mut Vec<EncodedRect>) {
    if pixels.len() != w * h * 4 {
        return;
    }
    let spent: usize = rects.iter().map(EncodedRect::wire_len).sum();
    rects.extend(encoder.refine(pixels, w, h, REFINE_BUDGET.saturating_sub(spent)));
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
        // Settings from the viewer, applied between frames and confirmed with the value in effect;
        // at most a queue's worth per tick, however fast the viewer refills it.
        for (key, value) in settings.try_iter().take(SETTINGS_QUEUE) {
            if ctl.stopped() {
                break;
            }
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
                let mut rects = Vec::new();
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
                    rects = encoder.encode(pixels, w, h);
                    encoded = true;
                    if !rects.is_empty() {
                        last_change = Instant::now();
                    }
                }
                // Lossless refinement of lossy regions that have settled, on every tick: a video
                // or animation elsewhere on the screen must not keep them lossy.
                if encoded && encoder.needs_refine() {
                    let pixels = if d > 1 { scaled.as_slice() } else { cap.pixels() };
                    add_refinement(&mut encoder, pixels, w, h, &mut rects);
                }
                if !rects.is_empty() {
                    send_frame(out, &mut frame, w, h, &rects)?;
                    last_send = Instant::now();
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
        let want = Start { sel, monitor_missing: false, downscale: 2, quality: QUALITY_LOW, host_quality: false, audio: true, privacy: true };
        assert_eq!(s, want);
        let s = negotiate(&o, 0, 9, MONITOR_ALL, 0, all);
        let sel = MonitorSel::All;
        let want = Start { sel, monitor_missing: false, downscale: 1, quality: QUALITY_BALANCED, host_quality: true, audio: false, privacy: false };
        assert_eq!(s, want);
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
        // The host default applies to viewers that leave the choice to the host (and to unknown
        // qualities), and only if it is a valid one.
        let o = HostOptions { default_quality: QUALITY_LOSSLESS, ..opts() };
        let s = negotiate(&o, 1, QUALITY_DEFAULT, 0, 0, all);
        assert_eq!((s.quality, s.host_quality), (QUALITY_LOSSLESS, true));
        let s = negotiate(&o, 1, QUALITY_LOW as u8, 0, 0, all);
        assert_eq!((s.quality, s.host_quality), (QUALITY_LOW, false));
        let o = HostOptions { default_quality: 42, ..opts() };
        assert_eq!(negotiate(&o, 1, QUALITY_DEFAULT, 0, 0, all).quality, QUALITY_BALANCED);
        // What a viewer started without --quality asks for.
        assert_eq!(crate::viewer::ViewerOptions::default().quality, QUALITY_DEFAULT);
    }

    /// Photo-like BGRA noise: busy enough that every tile is sent lossy outside lossless mode.
    fn noise(pixels: &mut [u8], seed: u32) {
        let mut s = seed;
        for px in pixels.as_chunks_mut::<4>().0 {
            s = s.wrapping_mul(1664525).wrapping_add(1013904223);
            *px = [(s >> 24) as u8, (s >> 16) as u8, (s >> 8) as u8, 255];
        }
    }

    /// One capture tick by the host's rule on a screen whose top-left tile changes every
    /// time (a video): encode, then refinement; the frame is applied to `fb`.
    fn busy_tick(enc: &mut Encoder, dec: &mut codec::Decoder, cur: &mut [u8], fb: &mut [u8], w: usize, h: usize, n: u32) {
        let line = codec::TILE * 4;
        let mut tile = vec![0u8; codec::TILE * line];
        noise(&mut tile, 1000 + n);
        for row in 0..codec::TILE {
            cur[row * w * 4..row * w * 4 + line].copy_from_slice(&tile[row * line..(row + 1) * line]);
        }
        let mut rects = enc.encode(cur, w, h);
        assert!(!rects.is_empty(), "tick {n} was idle");
        add_refinement(enc, cur, w, h, &mut rects);
        for m in codec::pack(n, w, h, &rects) {
            dec.apply(&m[1..], fb, w, h).unwrap();
        }
    }

    /// Whether `fb` holds `cur` exactly outside the changing top-left tile.
    fn exact_outside_first_tile(fb: &[u8], cur: &[u8], w: usize) -> bool {
        let (fb, cur) = (fb.as_chunks::<4>().0, cur.as_chunks::<4>().0);
        fb.iter().zip(cur).enumerate().all(|(i, (a, b))| (i % w < codec::TILE && i / w < codec::TILE) || a[..3] == b[..3])
    }

    #[test]
    fn lossy_regions_are_refined_while_something_else_keeps_changing() {
        let (w, h) = (4 * codec::TILE, 3 * codec::TILE);
        let mut cur = vec![0u8; w * h * 4];
        noise(&mut cur, 1);
        let mut fb = vec![0u8; w * h * 4];
        let mut dec = codec::Decoder::new().unwrap();
        let mut enc = Encoder::new().unwrap();
        enc.set_quality(QUALITY_BALANCED);
        let t = Instant::now();
        busy_tick(&mut enc, &mut dec, &mut cur, &mut fb, w, h, 1);
        assert!(!exact_outside_first_tile(&fb, &cur, w), "the photo was not sent lossy");
        // Not settled yet: nothing is refined. This runs on the real clock, so it holds only if
        // the two ticks took less than the settle delay; codec::tests checks it on a clock of its own.
        busy_tick(&mut enc, &mut dec, &mut cur, &mut fb, w, h, 2);
        if t.elapsed() < Duration::from_millis(300) {
            assert!(!exact_outside_first_tile(&fb, &cur, w));
        }
        // Settled (300 ms): refined although no tick is idle.
        std::thread::sleep(Duration::from_millis(400));
        busy_tick(&mut enc, &mut dec, &mut cur, &mut fb, w, h, 3);
        assert!(exact_outside_first_tile(&fb, &cur, w), "settled lossy tiles were not refined");

        // Switching to lossless refines what is already lossy at once, animation or not.
        let mut fb = vec![0u8; w * h * 4];
        let mut dec = codec::Decoder::new().unwrap();
        let mut enc = Encoder::new().unwrap();
        enc.set_quality(QUALITY_LOW);
        busy_tick(&mut enc, &mut dec, &mut cur, &mut fb, w, h, 1);
        assert!(!exact_outside_first_tile(&fb, &cur, w));
        enc.set_quality(QUALITY_LOSSLESS);
        busy_tick(&mut enc, &mut dec, &mut cur, &mut fb, w, h, 2);
        assert!(fb == cur, "lossless did not make the picture exact");
        assert!(!enc.needs_refine());
    }

    #[test]
    fn refinement_keeps_to_the_tick_budget_but_always_progresses() {
        // A screen of noise sent lossy, then lossless: more exact data than one tick may carry.
        let (w, h) = (16 * codec::TILE, 8 * codec::TILE);
        let mut cur = vec![0u8; w * h * 4];
        noise(&mut cur, 7);
        let mut enc = Encoder::new().unwrap();
        enc.set_quality(QUALITY_BALANCED);
        assert!(!enc.encode(&cur, w, h).is_empty());
        enc.set_quality(QUALITY_LOSSLESS);
        let size = |r: &[EncodedRect]| r.iter().map(EncodedRect::wire_len).sum::<usize>();
        let mut rects = Vec::new();
        add_refinement(&mut enc, &cur, w, h, &mut rects);
        let first = size(&rects);
        assert!(first > 0 && first <= REFINE_BUDGET, "{first}");
        // A tick whose changes used up the budget still refines one run.
        let mut rects = enc.encode(&cur, w, h);
        assert!(rects.is_empty());
        rects.push(EncodedRect { rect: codec::Rect { x: 0, y: 0, w: 1, h: 1 }, enc: codec::ENC_RAW, data: vec![0; REFINE_BUDGET] });
        add_refinement(&mut enc, &cur, w, h, &mut rects);
        assert!(rects.len() == 2 && size(&rects[1..]) <= 4 * codec::TILE * codec::TILE * 3 + 13, "{}", rects.len());
        // A picture of another size is left alone.
        let mut rects = Vec::new();
        add_refinement(&mut enc, &cur[..w * 4], w, h, &mut rects);
        assert!(rects.is_empty());
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
        // Announced by every host of this version, whatever its options.
        let always = F_INSTANCE | F_QUALITY_STATE;
        let base = HostOptions { clipboard: true, ..HostOptions::default() };
        assert_eq!(host_flags(&base, true, true), always | F_CLIPBOARD | F_AUDIO | F_FILES | F_PRIVACY);
        assert_eq!(host_flags(&base, false, false), always | F_CLIPBOARD | F_FILES);
        let o = HostOptions { view_only: true, sas: true, ..HostOptions::default() };
        assert_eq!(host_flags(&o, true, true), always | F_VIEW_ONLY | F_SAS | F_AUDIO);
        let o = HostOptions { files: false, audio: false, privacy: false, ..HostOptions::default() };
        assert_eq!(host_flags(&o, true, true), always);
    }

    #[test]
    fn the_services_own_folder_fills_only_so_far() {
        let mut r = [0u8; 8];
        crate::crypto::random(&mut r).unwrap();
        let dir = std::env::temp_dir().join(format!("srdp-host-own-{}", crate::util::hex_encode(&r)));
        std::fs::create_dir_all(&dir).unwrap();
        own_dir_room(&dir, 0, 100, 100, 3).unwrap();
        assert!(own_dir_room(&dir, 0, 101, 100, 3).is_err());
        std::fs::write(dir.join("a"), [0u8; 40]).unwrap();
        std::fs::write(dir.join("b"), [0u8; 10]).unwrap();
        own_dir_room(&dir, 0, 50, 100, 3).unwrap();
        // Uploads still arriving count with everything they announced.
        let e = own_dir_room(&dir, 30, 21, 100, 3).unwrap_err().to_string();
        assert!(e.contains("is full") && e.contains("administrator"), "{e}");
        own_dir_room(&dir, 30, 20, 100, 3).unwrap();
        // And every entry counts against the number of files, whatever its size.
        std::fs::create_dir(dir.join("c")).unwrap();
        assert!(own_dir_room(&dir, 0, 0, 100, 3).is_err());
        own_dir_room(&dir, 0, 0, 100, 4).unwrap();
        assert!(own_dir_room(&dir.join("missing"), 0, 0, 100, 4).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_services_own_folder_needs_nobody_signed_in() {
        let nobody = || -> Result<u32> { Err("nobody is signed in on the host".into()) };
        let looked_up = std::cell::Cell::new(false);
        let user = upload_user(true, || {
            looked_up.set(true);
            nobody()
        });
        assert!(matches!(user, Ok(None)) && !looked_up.get());
        // Any other folder is written as the console user, so it takes uploads only with one.
        assert!(upload_user(false, nobody).unwrap_err().to_string().contains("nobody is signed in"));
        assert!(matches!(upload_user(false, || Ok(7)), Ok(Some(7))));
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
        p.penalize();
        assert!(p.admit(ip(1)).is_err());
        p.admit(ip(200)).unwrap();
        p.leave(ip(1), true);
        p.leave(ip(2), false);
        p.admit(ip(1)).unwrap();
        // Nothing is kept for addresses without handshakes.
        let mut p = Pending::default();
        p.admit(ip(7)).unwrap();
        assert!(p.admit(ip(7)).is_ok() && p.admit(ip(7)).is_err());
        p.penalize();
        p.leave(ip(7), true);
        p.leave(ip(7), false);
        p.leave(ip(7), false);
        assert!(p.per_addr.is_empty() && p.total == 0 && p.penalties == 0);
    }

    #[test]
    fn failed_handshakes_serving_their_penalty_are_capped_in_all() {
        let host = Arc::new(Host::new(opts(), Secret([0; 32])));
        // Each from an address of its own, as a peer with many of them could.
        let admit = |i: usize| {
            let ip = IpAddr::from([10, 0, (i >> 8) as u8, i as u8]);
            lock(&host.pending).admit(ip).map(|()| Slot { host: host.clone(), ip, penalized: false })
        };
        let mut failed = Vec::new();
        for i in 0..MAX_PENALTIES {
            let mut s = admit(i).unwrap();
            s.penalize();
            s.penalize();
            failed.push(s);
        }
        let counts = |p: &Pending| (p.total, p.penalties);
        assert_eq!(counts(&lock(&host.pending)), (0, MAX_PENALTIES));
        assert_eq!(admit(MAX_PENALTIES).err(), Some("too many failed handshakes"));
        // Once a penalty is over, others get in again, until that one fails too.
        failed.pop();
        let mut s = admit(MAX_PENALTIES).unwrap();
        s.penalize();
        assert!(admit(MAX_PENALTIES + 1).is_err());
        drop((s, failed));
        let p = lock(&host.pending);
        assert!(p.per_addr.is_empty() && p.total == 0 && p.penalties == 0);
    }

    #[test]
    fn ipv6_peers_count_by_address_and_by_their_64() {
        let v6 = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(source(v6("2001:db8:1:2:aaaa::1")), v6("2001:db8:1:2:aaaa::1"));
        assert_eq!(network(v6("2001:db8:1:2:aaaa::1")), Some(v6("2001:db8:1:2::")));
        assert_eq!(source(v6("::ffff:100.64.0.1")), ip(1));
        assert_eq!((source(ip(1)), network(ip(1))), (ip(1), None));
        // Tailscale gives every node an address of its own.
        assert_eq!(network(v6("fd7a:115c:a1e0::1")), None);
        let mut p = Pending::default();
        p.admit(v6("2001:db8::1")).unwrap();
        p.admit(v6("2001:db8::1")).unwrap();
        assert!(p.admit(v6("2001:db8::1")).unwrap_err().contains("this address"));
        // A neighbour in the same /64 still gets in while the first holds its share...
        p.admit(v6("2001:db8::2")).unwrap();
        p.admit(v6("2001:db8::3")).unwrap();
        // ...but the /64 as a whole cannot take every place.
        assert!(p.admit(v6("2001:db8::4")).unwrap_err().contains("this network"));
        p.admit(v6("2001:db8:0:1::1")).unwrap();
        p.admit(v6("fd7a:115c:a1e0::1")).unwrap();
        p.admit(ip(1)).unwrap();
        p.admit(v6("::ffff:100.64.0.1")).unwrap();
        assert!(p.admit(ip(1)).unwrap_err().contains("this address"));
        for a in ["2001:db8::1", "2001:db8::1", "2001:db8::2", "2001:db8::3"] {
            p.leave(v6(a), false);
        }
        assert!(p.per_net.get(&v6("2001:db8::")).is_none() && !p.per_addr.contains_key(&v6("2001:db8::1")));
        // The log throttle counts them the same way.
        let mut q = Quiet::new(Instant::now());
        let shown = (0..10u16).filter(|&i| q.allow(IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, i]))).count();
        assert_eq!(shown, QUIET_PER_ADDR as usize);
        assert!(q.allow(v6("2001:db8:0:1::1")) && q.allow(v6("fd7a:115c:a1e0::1")));
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

    #[test]
    fn who_may_take_over() {
        // A new connection replaces the live session, also an older viewer's (no instance).
        assert!(takes_over(0, 0, None) && takes_over(0, 5, Some(9)) && takes_over(HELLO_AUDIO, 0, Some(0)));
        // An automatic reconnect when nobody is connected, or to take back its own viewer's session.
        assert!(takes_over(HELLO_RECONNECT, 5, None) && takes_over(HELLO_RECONNECT | HELLO_PRIVACY, 5, Some(5)));
        // Never another viewer's session, nor one of a viewer without an instance.
        assert!(!takes_over(HELLO_RECONNECT, 5, Some(9)));
        assert!(!takes_over(HELLO_RECONNECT, 0, Some(0)) && !takes_over(HELLO_RECONNECT, 5, Some(0)));
    }

    #[test]
    fn a_session_is_named_once() {
        let ((s, _), _viewer) = session_pair();
        // Named after the hellos (the hello of a new connection carries no instance).
        let ctl = SessionCtl::new(s.try_clone().unwrap(), 0);
        ctl.name(5);
        ctl.name(6);
        assert_eq!(ctl.instance.load(Ordering::SeqCst), 5);
        // Named by its hello already.
        let ctl = SessionCtl::new(s, 7);
        ctl.name(8);
        assert_eq!(ctl.instance.load(Ordering::SeqCst), 7);
    }

    const PAIR_KEY: [u8; 32] = [4; 32];

    /// An authenticated loopback connection: the host's end and the viewer's, with their keys.
    fn session_pair() -> ((TcpStream, channel::SessionKeys), (TcpStream, channel::SessionKeys)) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let viewer = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let keys = channel::client_handshake(&mut s, &PAIR_KEY).unwrap();
            (s, keys)
        });
        let (s, _) = l.accept().unwrap();
        let keys = handshake(&s, &PAIR_KEY, Instant::now() + Duration::from_secs(10)).unwrap();
        ((s, keys), viewer.join().unwrap())
    }

    /// Reads until the connection ends: the tiles records and the last notice that came.
    fn read_to_end(reader: &mut RecordReader<TcpStream>) -> (usize, Option<String>) {
        let (mut tiles, mut notice) = (0, None);
        while let Ok(rec) = reader.recv() {
            match ServerMsg::decode(rec) {
                Ok(ServerMsg::Tiles(_)) => tiles += 1,
                Ok(ServerMsg::Notice(text)) => notice = Some(text),
                _ => {}
            }
        }
        (tiles, notice)
    }

    #[test]
    fn a_farewell_reaches_a_viewer_that_is_behind_and_still_sending() {
        let ((hs, hk), (vs, vk)) = session_pair();
        let drains = Arc::new(AtomicUsize::new(0));
        let ctl = Arc::new(SessionCtl::new(hs.try_clone().unwrap(), 1));
        let out = Arc::new(Out::new(RecordWriter::new(hs.try_clone().unwrap(), hk.send)));
        *lock(&ctl.out) = Some(out.clone());
        let (to_input, received) = mpsc::sync_channel(RECEIVED_QUEUE);
        let receiver = {
            let (ctl, reader) = (ctl.clone(), RecordReader::new(hs, hk.recv));
            std::thread::spawn(move || receive(reader, to_input, &ctl))
        };
        // Frames the viewer has not read yet; it pings all the while, as the GUI viewer does.
        let mut frame = vec![7u8; 4096];
        frame[0] = S_TILES;
        for _ in 0..8 {
            out.send_record(&frame).unwrap();
        }
        let pinging = Arc::new(AtomicBool::new(true));
        let pinger = {
            let (pinging, mut w) = (pinging.clone(), RecordWriter::new(vs.try_clone().unwrap(), vk.send));
            std::thread::spawn(move || {
                let mut b = Vec::new();
                ClientMsg::Ping(1).encode(&mut b);
                while pinging.load(Ordering::SeqCst) {
                    if w.send(&b).is_err() {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                true
            })
        };
        std::thread::sleep(Duration::from_millis(100));
        ctl.kick_with_notice("another viewer connected to this host", &drains);
        assert!(ctl.stopped() && matches!(*lock(&ctl.link), Link::Parting(_)));
        assert!(out.send(&ServerMsg::Ping).is_err(), "a session thread sent after the farewell");
        // The input thread is gone (it leaves as soon as it sees the stop), and the session's
        // own end kicks it once more: the connection stays open.
        drop(received);
        ctl.kick();
        // Well past `FAREWELL`, the viewer reads: everything, then the notice, then the end.
        std::thread::sleep(FAREWELL + Duration::from_millis(500));
        let mut reader = RecordReader::new(vs, vk.recv);
        let (tiles, notice) = read_to_end(&mut reader);
        assert_eq!((tiles, notice.as_deref()), (8, Some("another viewer connected to this host")));
        pinging.store(false, Ordering::SeqCst);
        assert!(pinger.join().unwrap(), "the host reset the connection under the viewer's pings");
        assert_eq!(drains.load(Ordering::SeqCst), 1);
        // The viewer hangs up, and the drain ends with it.
        drop(reader);
        let t = Instant::now();
        receiver.join().unwrap();
        assert!(t.elapsed() < Duration::from_secs(5), "drained for {:?}", t.elapsed());
        assert_eq!(drains.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn without_a_drain_slot_a_replaced_connection_closes_at_once() {
        let drains = Arc::new(AtomicUsize::new(0));
        let slots: Vec<DrainSlot> = std::iter::from_fn(|| DrainSlot::take(&drains)).collect();
        assert_eq!(slots.len(), MAX_DRAINS);
        let ((hs, hk), (vs, vk)) = session_pair();
        let ctl = Arc::new(SessionCtl::new(hs.try_clone().unwrap(), 1));
        *lock(&ctl.out) = Some(Arc::new(Out::new(RecordWriter::new(hs, hk.send))));
        ctl.kick_with_notice("another viewer connected to this host", &drains);
        assert!(ctl.stopped() && matches!(*lock(&ctl.link), Link::Closed));
        let (_, notice) = read_to_end(&mut RecordReader::new(vs, vk.recv));
        assert_eq!(notice, None);
        assert_eq!(drains.load(Ordering::SeqCst), MAX_DRAINS);
        drop(slots);
        assert_eq!(drains.load(Ordering::SeqCst), 0);
        // A session that ended already is not parted later.
        assert!(!ctl.part(DrainSlot::take(&drains).unwrap()));
        assert_eq!(drains.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_silent_replaced_viewer_is_closed_at_its_drain_deadline() {
        let ((hs, hk), (vs, vk)) = session_pair();
        // As `read_hello` sets them: the receiving thread's read waits this long for a viewer
        // that sends nothing.
        hs.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        hs.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        let drains = Arc::new(AtomicUsize::new(0));
        let ctl = Arc::new(SessionCtl::new(hs.try_clone().unwrap(), 1));
        *lock(&ctl.out) = Some(Arc::new(Out::new(RecordWriter::new(hs.try_clone().unwrap(), hk.send))));
        let (to_input, received) = mpsc::sync_channel(RECEIVED_QUEUE);
        let receiver = {
            let (ctl, reader) = (ctl.clone(), RecordReader::new(hs, hk.recv));
            std::thread::spawn(move || receive(reader, to_input, &ctl))
        };
        // The viewer sends once, then goes silent (frozen, or a link that went quiet): the
        // receiving thread waits in its next read.
        let mut b = Vec::new();
        ClientMsg::Ping(1).encode(&mut b);
        RecordWriter::new(vs.try_clone().unwrap(), vk.send).send(&b).unwrap();
        assert!(matches!(received.recv().unwrap(), Ok(ClientMsg::Ping(1))));
        ctl.kick_with_notice("another viewer connected to this host", &drains);
        drop(received);
        // The deadline, brought forward from `DRAIN_FOR` after the kick.
        let until = Instant::now() + Duration::from_secs(2);
        match &mut *lock(&ctl.link) {
            Link::Parting(Some(slot)) => slot.until = until,
            _ => panic!("the connection is not parting"),
        }
        // What the replaced session's own thread does last (`serve_session`).
        ctl.close_parted();
        let late = Instant::now().saturating_duration_since(until);
        assert!(Instant::now() >= until && late < Duration::from_secs(2), "closed {late:?} after the deadline");
        assert!(matches!(*lock(&ctl.link), Link::Closed));
        assert_eq!(drains.load(Ordering::SeqCst), 0);
        // The receiving thread was woken rather than left waiting for `IO_TIMEOUT`.
        let t = Instant::now();
        receiver.join().unwrap();
        assert!(t.elapsed() < Duration::from_secs(5), "the receiving thread took {:?}", t.elapsed());
        // The viewer, reading at last, finds the notice and the end.
        let (_, notice) = read_to_end(&mut RecordReader::new(vs, vk.recv));
        assert_eq!(notice.as_deref(), Some("another viewer connected to this host"));
        // A connection that is not parting is left as it is.
        let ((s, _), _viewer) = session_pair();
        let ctl = SessionCtl::new(s, 1);
        ctl.close_parted();
        assert!(matches!(*lock(&ctl.link), Link::Live));
    }

    #[test]
    fn an_automatic_reconnect_does_not_replace_another_viewers_session() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let host = Arc::new(Host::new(HostOptions { copied_files: Vec::new, ..HostOptions::default() }, Secret(PAIR_KEY)));
        // Another viewer's live session.
        let ((other, _), _other_viewer) = session_pair();
        let live = Arc::new(SessionCtl::new(other, 7));
        *lock(&host.current) = Some(live.clone());
        let served = {
            let host = host.clone();
            std::thread::spawn(move || {
                for _ in 0..2 {
                    let (s, peer) = l.accept().unwrap();
                    let keys = handshake(&s, &PAIR_KEY, Instant::now() + Duration::from_secs(10)).unwrap();
                    serve_session(&host, s, peer, keys);
                }
            })
        };
        // With its instance in the hello, and without (the hello it falls back to when an attempt
        // like that went unanswered, which older hosts take like any other).
        for instance_in_hello in [true, false] {
            let o = crate::viewer::ViewerOptions { instance: 8, reconnect: true, instance_in_hello, ..Default::default() };
            let e = match crate::viewer::connect(&addr.to_string(), &o, &Secret(PAIR_KEY)) {
                Ok(_) => panic!("an automatic reconnect replaced another viewer's session"),
                Err(e) => e,
            };
            assert_eq!(e.to_string(), format!("{}another viewer is using this host", crate::viewer::REFUSED));
            assert!(!crate::viewer::retryable(&e));
        }
        served.join().unwrap();
        assert!(!live.stopped() && lock(&host.current).as_ref().is_some_and(|c| Arc::ptr_eq(c, &live)));
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
        /// A host on a port the system picks, so that test runs side by side never collide.
        fn start(configure: impl FnOnce(&mut HostOptions)) -> TestHost {
            let mut opts = HostOptions {
                bind: Some(IpAddr::from([127, 0, 0, 1])),
                port: 0,
                policy: PeerPolicy { allow: vec![], allow_non_tailscale: false, loopback_ok: true },
                audio: false,
                privacy: false,
                copied_files: Vec::new,
                ..HostOptions::default()
            };
            configure(&mut opts);
            let listener = bind(&opts, &AtomicBool::new(false)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let stop = Arc::new(AtomicBool::new(false));
            let s = stop.clone();
            let thread = std::thread::spawn(move || serve(listener, opts, Secret(PSK), &s));
            TestHost { port, stop, thread: Some(thread) }
        }

        fn connect(&self, o: ViewerOptions) -> Client {
            Client::new(connect(&format!("127.0.0.1:{}", self.port), &o, &Secret(PSK)).unwrap())
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
        fn new(conn: Connection) -> Client {
            conn.stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
            Client { conn, dec: Decoder::new().unwrap(), fb: Vec::new(), size: (0, 0), frames: Vec::new(), ack: true }
        }

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

        /// Stops acknowledging and takes frames until `MAX_IN_FLIGHT` wait to be acknowledged:
        /// the host then sends no more of them, so none can hold its writer when this viewer
        /// stops reading and is replaced (a record stuck for all of `FAREWELL` means no notice).
        fn hold_frames(&mut self) {
            let acked = self.frames.last().map_or(0, |f| f.0);
            self.ack = false;
            while self.frames.iter().filter(|f| f.0 > acked).count() < MAX_IN_FLIGHT as usize {
                let n = self.frames.len();
                self.send(ClientMsg::Refresh);
                self.frame(n + 1);
            }
            self.ping(0x401d);
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
        let host = TestHost::start(|o| o.transfer_dir = Some(dir.clone()));
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
    fn the_services_own_folder_takes_only_so_many_uploads() {
        let _serial = lock(&SERIAL);
        let dir = tmpdir("own");
        for i in 0..OWN_DIR_FILES - 1 {
            std::fs::File::create(dir.join(format!("old{i}"))).unwrap();
        }
        let host = TestHost::start(|o| {
            o.transfer_dir = Some(dir.clone());
            o.own_transfer_dir = true;
        });
        let mut c = host.connect(ViewerOptions::default());
        let upload = |c: &mut Client, id, name: &str| {
            c.send(ClientMsg::FileBegin { id, size: 1, name: name.into() });
            c.send(ClientMsg::FileData { id, data: vec![1] });
            c.send(ClientMsg::FileEnd { id, sha256: crate::crypto::sha256(&[&[1]]) });
            c.upload_result(id)
        };
        // One more fits; after that an administrator has to make room.
        let (ok, msg) = upload(&mut c, 1, "last.bin");
        assert!(ok, "{msg}");
        let (ok, msg) = upload(&mut c, 2, "one too many.bin");
        assert!(!ok && msg.contains("is full"), "{msg}");
        assert_eq!(entries(&dir).len(), OWN_DIR_FILES);
        std::fs::remove_file(dir.join("old0")).unwrap();
        assert!(upload(&mut c, 3, "after cleaning.bin").0);
        // An upload still arriving when the session ends is removed with it.
        std::fs::remove_file(dir.join("old1")).unwrap();
        c.send(ClientMsg::FileBegin { id: 4, size: 10, name: "cut off.bin".into() });
        c.send(ClientMsg::FileData { id: 4, data: vec![1; 4] });
        c.ping(4);
        assert_eq!(entries(&dir).len(), OWN_DIR_FILES);
        c.conn.writer.send(&[0x7f]).unwrap();
        let t = Instant::now();
        while entries(&dir).len() == OWN_DIR_FILES {
            assert!(t.elapsed() < Duration::from_secs(10), "the partial upload outlived its session");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(entries(&dir).iter().all(|n| !n.starts_with(".srdp-")));
        drop(host);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn view_only_pull_and_replacement() {
        let _serial = lock(&SERIAL);
        {
            let dir = tmpdir("view-only");
            let host = TestHost::start(|o| {
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
        let host = TestHost::start(|o| o.copied_files = || PULL_FILES.get().cloned().unwrap_or_default());
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

    #[test]
    fn host_quality_and_a_flood_of_settings() {
        let _serial = lock(&SERIAL);
        let host = TestHost::start(|o| o.default_quality = QUALITY_LOW);
        // A viewer started without --quality gets the host's default and is told which.
        let mut c = host.connect(ViewerOptions::default());
        assert_ne!(c.conn.flags & F_QUALITY_STATE, 0);
        let v = c.wait("the quality in effect", |m| match m {
            ServerMsg::State { key: SET_QUALITY, value } => Some(*value),
            _ => None,
        });
        assert_eq!(v, QUALITY_LOW);

        // A viewer that sends settings without waiting for the answers (and stops acknowledging
        // frames meanwhile): the host takes them a queue's worth at a time, and every one is
        // still answered, in order.
        const N: u32 = 10 * SETTINGS_QUEUE as u32;
        let (reader, writer) = (&mut c.conn.reader, &mut c.conn.writer);
        let (states, last_frame) = std::thread::scope(|s| {
            s.spawn(move || {
                let mut b = Vec::new();
                for i in 0..N {
                    b.clear();
                    ClientMsg::Set { key: SET_QUALITY, value: i % 3 }.encode(&mut b);
                    writer.send(&b).unwrap();
                }
            });
            let (mut states, mut last_frame) = (Vec::new(), None);
            let deadline = Instant::now() + Duration::from_secs(30);
            while states.len() < N as usize {
                assert!(Instant::now() < deadline, "{} of {N} settings answered", states.len());
                let rec = reader.recv().unwrap();
                match ServerMsg::decode(rec).unwrap() {
                    ServerMsg::State { key: SET_QUALITY, value } => states.push(value),
                    ServerMsg::Tiles(p) => {
                        let hdr = codec::parse_header(p).unwrap();
                        if hdr.last {
                            last_frame = Some(hdr.frame);
                        }
                    }
                    _ => {}
                }
            }
            (states, last_frame)
        });
        assert!(states.iter().zip(0..).all(|(&v, i)| v == i % 3), "answers out of order");
        // The session carries on as before.
        if let Some(f) = last_frame {
            c.send(ClientMsg::Ack(f));
        }
        c.ping(5);
        assert_eq!(c.state(SET_QUALITY, QUALITY_LOSSLESS), QUALITY_LOSSLESS);
    }

    #[test]
    fn a_replaced_viewer_is_told_why_before_the_close() {
        let _serial = lock(&SERIAL);
        let host = TestHost::start(|_| {});
        let mut c = host.connect(ViewerOptions::default());
        c.ping(1);
        // The first viewer keeps reading, as a real one does, and hangs up once the host has.
        let Client { mut conn, .. } = c;
        let first = std::thread::spawn(move || {
            let mut notice = None;
            while let Ok(rec) = conn.reader.recv() {
                if let Ok(ServerMsg::Notice(text)) = ServerMsg::decode(rec) {
                    notice = Some(text);
                }
            }
            notice
        });
        let t = Instant::now();
        let mut c2 = host.connect(ViewerOptions::default());
        assert!(t.elapsed() < Duration::from_secs(3), "handover took {:?}", t.elapsed());
        let notice = first.join().unwrap();
        // The viewer stops instead of reconnecting when a notice comes this shortly before the end.
        assert!(notice.as_deref().is_some_and(|n| n.contains("another viewer")), "{notice:?}");
        c2.ping(6);
    }

    #[test]
    fn a_replaced_viewer_far_behind_still_gets_the_notice() {
        let _serial = lock(&SERIAL);
        let host = TestHost::start(|_| {});
        let mut c = host.connect(ViewerOptions::default());
        c.frame(1);
        c.hold_frames();
        // The first viewer pings as the GUI viewer does, but reads nothing for a while: what the
        // host sends meanwhile, the notice included, waits for it.
        let Connection { mut reader, writer, .. } = c.conn;
        let pinging = Arc::new(AtomicBool::new(true));
        let pinger = {
            let (pinging, mut w) = (pinging.clone(), writer);
            std::thread::spawn(move || {
                let mut b = Vec::new();
                ClientMsg::Ping(1).encode(&mut b);
                while pinging.load(Ordering::SeqCst) {
                    if w.send(&b).is_err() {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                true
            })
        };
        let t = Instant::now();
        let mut c2 = host.connect(ViewerOptions::default());
        assert!(t.elapsed() < Duration::from_secs(3), "handover took {:?}", t.elapsed());
        std::thread::sleep((FAREWELL + Duration::from_millis(500)).saturating_sub(t.elapsed()));
        let mut notice = None;
        while let Ok(rec) = reader.recv() {
            if let Ok(ServerMsg::Notice(text)) = ServerMsg::decode(rec) {
                notice = Some(text);
            }
        }
        assert!(notice.as_deref().is_some_and(|n| n.contains("another viewer")), "{notice:?}");
        pinging.store(false, Ordering::SeqCst);
        assert!(pinger.join().unwrap(), "the host reset the connection under the viewer's pings");
        c2.ping(7);
    }

    #[test]
    fn automatic_reconnects_take_back_only_their_own_session() {
        let _serial = lock(&SERIAL);
        let host = TestHost::start(|_| {});
        let target = format!("127.0.0.1:{}", host.port);
        let reconnect = |instance| ViewerOptions { instance, reconnect: true, instance_in_hello: true, ..ViewerOptions::default() };
        // The first connection's hello carries no instance (older hosts would reject it): the
        // viewer names the session afterwards, since this host says it takes that.
        let mut c1 = host.connect(ViewerOptions { instance: 11, ..ViewerOptions::default() });
        assert_ne!(c1.conn.flags & F_INSTANCE, 0);
        c1.ping(1);
        // Another viewer's automatic reconnect is turned away for good; the session carries on.
        match connect(&target, &reconnect(12), &Secret(PSK)) {
            Ok(_) => panic!("an automatic reconnect replaced another viewer's session"),
            Err(e) => assert!(e.to_string().starts_with(crate::viewer::REFUSED) && !crate::viewer::retryable(&e), "{e}"),
        }
        c1.ping(2);
        // The viewer that lost this session takes it back.
        c1.hold_frames();
        let mut c2 = host.connect(reconnect(11));
        assert!(c1.notice().contains("another viewer"));
        c2.ping(3);
        // A new connection replaces whoever is connected.
        c2.hold_frames();
        let mut c3 = host.connect(ViewerOptions::default());
        assert!(c2.notice().contains("another viewer"));
        c3.ping(4);
        // Once that viewer has hung up, any automatic reconnect is let in.
        drop(c3);
        let t = Instant::now();
        let mut c4 = loop {
            match connect(&target, &reconnect(13), &Secret(PSK)) {
                Ok(conn) => break Client::new(conn),
                Err(e) => assert!(t.elapsed() < Duration::from_secs(5), "{e}"),
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        c4.ping(5);
    }
}
