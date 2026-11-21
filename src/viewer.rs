//! Portable viewer plumbing: resolving the host, connecting, authenticating and the hello
//! exchange (used by the platform viewers and by `probe`), plus the session helpers the
//! platform viewers share: a prioritised send queue, the reconnect policy, link statistics
//! and PCM helpers.

// Until the X11 viewer is implemented only the Windows viewer uses this module.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::channel::{self, RecordReader, RecordWriter};
use crate::proto::*;
use crate::util::{Error, Result, Secret};
use crate::{bail, log};
use std::collections::VecDeque;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, LockResult, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

pub struct ViewerOptions {
    pub fullscreen: bool,
    pub clipboard: bool,
    pub view_only: bool,
    /// Allow local screenshot/recording tools to capture the viewer window.
    pub allow_capture: bool,
    /// Ask the host for 1/N resolution (1 = full).
    pub downscale: u8,
    /// `proto::QUALITY_*`.
    pub quality: u8,
    /// Zero-based monitor index, `proto::MONITOR_ALL` or `proto::MONITOR_DEFAULT`.
    pub monitor: u8,
    /// Play the host's audio.
    pub audio: bool,
    /// Ask the host to blank its screen and block local input while connected.
    pub privacy: bool,
}

impl Default for ViewerOptions {
    fn default() -> Self {
        ViewerOptions {
            fullscreen: false,
            clipboard: false,
            view_only: false,
            allow_capture: false,
            downscale: 1,
            quality: QUALITY_BALANCED as u8,
            monitor: MONITOR_DEFAULT,
            audio: false,
            privacy: false,
        }
    }
}

/// Largest remote screen accepted (64 Mpx, 256 MiB as BGRA), bounding what a host can make a
/// viewer allocate and scan.
pub const MAX_PIXELS: usize = 64 << 20;

/// Rejects an empty remote screen or one larger than `MAX_PIXELS`.
pub fn check_screen_size(width: usize, height: usize) -> Result<()> {
    if width == 0 || height == 0 {
        bail!("host reported an empty screen");
    }
    if width * height > MAX_PIXELS {
        bail!("the host's screen ({width}x{height}) is too large");
    }
    Ok(())
}

/// An authenticated session, after the hello exchange.
pub struct Connection {
    /// Host name (`proto::printable`), monitors and the monitor being shown, from the host's hello.
    pub host_name: String,
    pub monitors: Vec<MonitorInfo>,
    pub monitor: u8,
    pub addr: SocketAddr,
    pub stream: TcpStream,
    pub reader: RecordReader<TcpStream>,
    pub writer: RecordWriter<TcpStream>,
    pub width: usize,
    pub height: usize,
    pub flags: u32,
}

/// Resolves `host`, `host:port`, an IP literal or a MagicDNS name; prefers Tailscale addresses.
pub fn resolve(target: &str) -> Result<SocketAddr> {
    let with_port = if target.parse::<SocketAddr>().is_ok()
        || target.rsplit_once(':').is_some_and(|(h, p)| !h.contains(':') && p.parse::<u16>().is_ok())
    {
        target.to_string()
    } else if target.contains(':') {
        format!("[{target}]:{DEFAULT_PORT}")
    } else {
        format!("{target}:{DEFAULT_PORT}")
    };
    let addrs: Vec<SocketAddr> = with_port.to_socket_addrs().map_err(|e| format!("cannot resolve {target}: {e}"))?.collect();
    addrs
        .iter()
        .find(|a| crate::net::is_tailscale(a.ip()))
        .or(addrs.first())
        .copied()
        .ok_or_else(|| Error::msg(format!("{target} has no addresses")))
}

pub fn connect(target: &str, opts: &ViewerOptions, psk: &Secret<32>) -> Result<Connection> {
    let addr = resolve(target)?;
    if !crate::net::is_tailscale(addr.ip()) && !addr.ip().is_loopback() {
        log!("warning: {addr} is not a Tailscale address; traffic is still end-to-end encrypted");
    }
    log!("connecting to {addr}...");
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|e| format!("cannot connect to {addr}: {e}"))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let keys = channel::client_handshake(&mut &stream, &psk.0)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut reader = RecordReader::new(stream.try_clone()?, keys.recv);
    let mut writer = RecordWriter::new(stream.try_clone()?, keys.send);
    let mut hello = Vec::new();
    let mut flags = 0;
    if opts.audio {
        flags |= HELLO_AUDIO;
    }
    if opts.privacy {
        flags |= HELLO_PRIVACY;
    }
    ClientMsg::Hello { downscale: opts.downscale, quality: opts.quality, monitor: opts.monitor, flags }.encode(&mut hello);
    writer.send(&hello)?;
    let (width, height, flags, monitor, monitors, host_name) = match ServerMsg::decode(reader.recv()?)? {
        ServerMsg::Hello { width, height, flags, monitor, monitors, name } => {
            (width as usize, height as usize, flags, monitor, monitors, printable(&name))
        }
        _ => bail!("unexpected first message from host"),
    };
    check_screen_size(width, height)?;
    log!("connected to {host_name}: remote screen {width}x{height}");
    Ok(Connection { host_name, monitors, monitor, addr, stream, reader, writer, width, height, flags })
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Bulk messages allowed to wait in an `OutQueue` before `send_bulk` blocks.
pub const BULK_DEPTH: usize = 8;
/// Control messages allowed to wait in an `OutQueue`. Only local input, settings and the
/// clipboard queue up there (acks keep just the newest, mouse moves merge), so this many
/// waiting means the host stopped reading: the queue gives up rather than grow without end.
pub const CONTROL_DEPTH: usize = 4096;
/// Why a session ends when its `OutQueue` gave up.
pub const STALLED: &str = "the host stopped reading what this viewer sends";
/// Size of one file-data message on the wire: small enough that input queued behind it
/// waits at most a few milliseconds on a typical link.
pub const FILE_MSG_CHUNK: usize = 64 * 1024;

/// Outgoing messages of one session, in two priorities. Control traffic (input, acks,
/// pings, settings) always leaves before bulk traffic (file data), and bulk producers block
/// while `BULK_DEPTH` messages are waiting, so a file transfer never starves input.
pub struct OutQueue {
    state: Mutex<OutState>,
    ready: Condvar,
    space: Condvar,
}

#[derive(Default)]
struct OutState {
    control: VecDeque<ClientMsg>,
    bulk: VecDeque<ClientMsg>,
    /// The newest frame acknowledgement not sent yet: the host keeps only the latest, and one
    /// per frame would let a host that floods frames and reads slowly fill the queue.
    ack: Option<u32>,
    closed: bool,
    /// Closed because `CONTROL_DEPTH` control messages were waiting.
    stalled: bool,
}

/// What `OutQueue::next` produced.
#[derive(Debug, PartialEq)]
pub enum Next {
    Msg(ClientMsg),
    /// Nothing to send within the timeout.
    Idle,
    /// The queue was closed; the writer should stop.
    Closed,
}

impl Default for OutQueue {
    fn default() -> Self {
        OutQueue { state: Mutex::new(OutState::default()), ready: Condvar::new(), space: Condvar::new() }
    }
}

impl OutQueue {
    /// Queues a control message; false once the queue is closed. A mouse move replaces a
    /// mouse move still waiting at the end of the queue, so a slow link does not replay a
    /// backlog of stale positions, and an ack replaces any waiting ack. With `CONTROL_DEPTH`
    /// messages waiting the queue closes as `stalled`: the caller should end the session.
    pub fn send(&self, m: ClientMsg) -> bool {
        let mut s = lock(&self.state);
        if s.closed {
            return false;
        }
        match (s.control.back_mut(), &m) {
            (_, &ClientMsg::Ack(id)) => s.ack = Some(id),
            (Some(last @ ClientMsg::MouseMove { .. }), ClientMsg::MouseMove { .. }) => *last = m,
            _ => {
                if s.control.len() >= CONTROL_DEPTH {
                    s.stalled = true;
                    drop(s);
                    self.close();
                    return false;
                }
                s.control.push_back(m)
            }
        }
        self.ready.notify_one();
        true
    }

    /// The queue gave up because the peer stopped reading (see `send`).
    pub fn stalled(&self) -> bool {
        lock(&self.state).stalled
    }

    /// Queues a bulk message, waiting while the bulk queue is full; false once closed.
    pub fn send_bulk(&self, m: ClientMsg) -> bool {
        let mut s = lock(&self.state);
        while !s.closed && s.bulk.len() >= BULK_DEPTH {
            s = self.space.wait(s).unwrap_or_else(PoisonError::into_inner);
        }
        if s.closed {
            return false;
        }
        s.bulk.push_back(m);
        self.ready.notify_one();
        true
    }

    /// The next message to send: the waiting ack, then control traffic, then bulk.
    pub fn next(&self, timeout: Duration) -> Next {
        let deadline = Instant::now() + timeout;
        let mut s = lock(&self.state);
        loop {
            if s.closed {
                return Next::Closed;
            }
            if let Some(id) = s.ack.take() {
                return Next::Msg(ClientMsg::Ack(id));
            }
            if let Some(m) = s.control.pop_front() {
                return Next::Msg(m);
            }
            if let Some(m) = s.bulk.pop_front() {
                self.space.notify_all();
                return Next::Msg(m);
            }
            let now = Instant::now();
            if now >= deadline {
                return Next::Idle;
            }
            s = self.ready.wait_timeout(s, deadline - now).unwrap_or_else(PoisonError::into_inner).0;
        }
    }

    /// Drops everything queued and wakes all waiters; later sends fail.
    pub fn close(&self) {
        let mut s = lock(&self.state);
        s.closed = true;
        s.ack = None;
        s.control.clear();
        s.bulk.clear();
        self.ready.notify_all();
        self.space.notify_all();
    }
}

/// Remote screen size changes a host may make back to back, and the pace after that. Each one
/// costs the viewer a new page-locked framebuffer (up to 256 MiB), a wipe of the old one and a
/// full repaint, for a few bytes from the host. A real host changes size only when its display
/// or the user's settings change; a faster one has its reader wait, so it only slows its own
/// session.
pub const RESIZE_BURST: u32 = 8;
pub const RESIZE_GAP: Duration = Duration::from_secs(1);

/// Paces remote screen size changes (see `RESIZE_BURST`).
pub struct ResizePacer {
    /// When the next change is due at the sustained pace.
    due: Instant,
}

impl ResizePacer {
    pub fn new(now: Instant) -> ResizePacer {
        ResizePacer { due: now }
    }

    /// A size change arrived at `now`: how long to wait before making it.
    pub fn wait(&mut self, now: Instant) -> Duration {
        let due = self.due.max(now);
        self.due = due + RESIZE_GAP;
        (due - now).saturating_sub(RESIZE_GAP * (RESIZE_BURST - 1))
    }
}

/// The framebuffer's lock, shared by the UI thread (painting) and a session's reader
/// (decoding). The reader takes it again right after each message, and a mutex is not fair,
/// so under a stream of messages the UI thread (on Windows also the keyboard hook it serves)
/// could wait through message after message. The UI thread announces its wait instead, and
/// the reader lets it in before decoding the next message.
pub struct FrameLock<T> {
    m: Mutex<T>,
    ui_waiting: AtomicBool,
}

/// How long a reader defers to the UI thread at most (it normally takes microseconds).
const UI_FIRST_FOR: Duration = Duration::from_millis(50);

impl<T> FrameLock<T> {
    pub fn new(v: T) -> FrameLock<T> {
        FrameLock { m: Mutex::new(v), ui_waiting: AtomicBool::new(false) }
    }

    /// Locks on the UI thread: waits for the message being decoded, not for every one after it.
    pub fn ui(&self) -> LockResult<MutexGuard<'_, T>> {
        self.ui_waiting.store(true, Ordering::SeqCst);
        let g = self.m.lock();
        self.ui_waiting.store(false, Ordering::SeqCst);
        g
    }

    /// Locks on a reader, after the UI thread if that is waiting.
    pub fn reader(&self) -> LockResult<MutexGuard<'_, T>> {
        let until = Instant::now() + UI_FIRST_FOR;
        while self.ui_waiting.load(Ordering::SeqCst) && Instant::now() < until {
            std::thread::yield_now();
        }
        self.m.lock()
    }
}

/// How a session ended, as far as reconnecting is concerned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EndKind {
    /// The host closed (or reset) the connection.
    Closed,
    /// The link failed: a timeout or a socket error.
    Network,
    /// Tampering, a protocol violation or a decoding failure: a new connection would not help.
    Fatal,
}

/// Classifies an error from sending or receiving records.
pub fn classify_link_error(e: &Error) -> EndKind {
    let s = e.to_string();
    if s == channel::CLOSED {
        EndKind::Closed
    } else if ["invalid record length", "record counter exhausted", "record authentication failed"].iter().any(|p| s.starts_with(p)) {
        EndKind::Fatal
    } else {
        EndKind::Network
    }
}

/// Whether a failed connection attempt is worth repeating. A wrong key, a protocol version
/// mismatch or a peer that is not safe-rdp will not fix itself.
pub fn retryable(e: &Error) -> bool {
    let s = e.to_string();
    !["host failed authentication", "protocol version mismatch", "peer is not a safe-rdp endpoint"].iter().any(|p| s.starts_with(p))
}

/// A host notice this shortly before an orderly close means the host announced the end.
pub const NOTICE_GRACE: Duration = Duration::from_secs(3);
/// An auto-reconnected session closed by the host within this time was most likely taken
/// over by another viewer: stop instead of fighting over the host.
pub const QUICK_CLOSE: Duration = Duration::from_secs(10);
/// Reconnect attempts stop after this long.
pub const RECONNECT_FOR: Duration = Duration::from_secs(120);

/// Whether to reconnect automatically after a session ended.
///
/// `lifetime` is how long the session ran, `was_reconnect` whether it was itself
/// established by an automatic reconnect, `since_notice` the time since the host's last notice.
pub fn should_reconnect(kind: EndKind, lifetime: Duration, was_reconnect: bool, since_notice: Option<Duration>) -> bool {
    match kind {
        EndKind::Fatal => false,
        EndKind::Network => true,
        EndKind::Closed => !since_notice.is_some_and(|d| d < NOTICE_GRACE) && !(was_reconnect && lifetime < QUICK_CLOSE),
    }
}

/// Delay before reconnect attempt `attempt` (0-based): 1, 2, 4, 8, 16, then 30 s.
pub fn reconnect_delay(attempt: u32) -> Duration {
    Duration::from_secs((1u64 << attempt.min(5)).min(30))
}

/// Frames per second and Mbit/s over windows of at least one second.
pub struct RateMeter {
    at: Instant,
    frames: u64,
    bytes: u64,
}

impl RateMeter {
    pub fn new(now: Instant) -> RateMeter {
        RateMeter { at: now, frames: 0, bytes: 0 }
    }

    /// Feeds running totals; returns `(fps, mbit_per_s)` once a second has passed.
    pub fn update(&mut self, now: Instant, frames: u64, bytes: u64) -> Option<(f64, f64)> {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        if dt < 1.0 {
            return None;
        }
        let fps = frames.saturating_sub(self.frames) as f64 / dt;
        let mbps = bytes.saturating_sub(self.bytes) as f64 * 8.0 / dt / 1e6;
        *self = RateMeter { at: now, frames, bytes };
        Some((fps, mbps))
    }
}

/// "12 ms · 30 fps · 4.2 Mbit/s" (round trip unknown: "– ms").
pub fn stats_text(rtt_ms: Option<u64>, fps: f64, mbps: f64) -> String {
    let rtt = rtt_ms.map_or_else(|| "–".to_string(), |r| r.min(99_999).to_string());
    let rate = if mbps < 10.0 { format!("{mbps:.1}") } else { format!("{:.0}", mbps.min(99_999.0)) };
    format!("{rtt} ms · {:.0} fps · {rate} Mbit/s", fps.clamp(0.0, 999.0))
}

/// Sample rates and channel counts the viewer accepts for playback.
pub fn audio_format_ok(rate: u32, channels: u8) -> bool {
    (8000..=192_000).contains(&rate) && (1..=2).contains(&channels)
}

/// Decodes `AUDIO_PCM16` (little-endian interleaved samples) into `out`.
pub fn pcm16_le(data: &[u8], out: &mut Vec<i16>) -> Result<()> {
    if data.len() % 2 != 0 {
        bail!("odd PCM16 payload length");
    }
    out.clear();
    out.extend(data.chunks_exact(2).map(|b| i16::from_le_bytes([b[0], b[1]])));
    Ok(())
}

/// "45 %" style progress of `done` out of `total` bytes (an empty file is complete).
pub fn percent(done: u64, total: u64) -> u32 {
    if total == 0 { 100 } else { (done.min(total) as u128 * 100 / total as u128) as u32 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn control_overtakes_bulk_and_bulk_is_bounded() {
        let q = Arc::new(OutQueue::default());
        for i in 0..BULK_DEPTH as u32 {
            assert!(q.send_bulk(ClientMsg::FileData { id: i, data: vec![1] }));
        }
        // A further bulk message must wait until the writer takes one.
        let producer = {
            let q = q.clone();
            std::thread::spawn(move || q.send_bulk(ClientMsg::FileEnd { id: 99, sha256: [0; 32] }))
        };
        std::thread::sleep(Duration::from_millis(50));
        assert!(!producer.is_finished());
        assert!(q.send(ClientMsg::Ack(7)));
        assert_eq!(q.next(Duration::ZERO), Next::Msg(ClientMsg::Ack(7)));
        assert_eq!(q.next(Duration::ZERO), Next::Msg(ClientMsg::FileData { id: 0, data: vec![1] }));
        assert!(producer.join().unwrap());
        let mut ids = vec![];
        while let Next::Msg(m) = q.next(Duration::from_millis(10)) {
            ids.push(match m {
                ClientMsg::FileData { id, .. } | ClientMsg::FileEnd { id, .. } => id,
                other => panic!("unexpected {other:?}"),
            });
        }
        assert_eq!(ids, [1, 2, 3, 4, 5, 6, 7, 99]);
        assert_eq!(q.next(Duration::from_millis(5)), Next::Idle);
    }

    #[test]
    fn close_wakes_blocked_producers_and_coalesces_moves() {
        let q = Arc::new(OutQueue::default());
        q.send(ClientMsg::MouseMove { x: 1, y: 1 });
        q.send(ClientMsg::MouseMove { x: 2, y: 2 });
        q.send(ClientMsg::MouseButton { button: BTN_LEFT, down: true });
        q.send(ClientMsg::MouseMove { x: 3, y: 3 });
        assert_eq!(q.next(Duration::ZERO), Next::Msg(ClientMsg::MouseMove { x: 2, y: 2 }));
        assert_eq!(q.next(Duration::ZERO), Next::Msg(ClientMsg::MouseButton { button: BTN_LEFT, down: true }));
        assert_eq!(q.next(Duration::ZERO), Next::Msg(ClientMsg::MouseMove { x: 3, y: 3 }));
        for _ in 0..BULK_DEPTH {
            q.send_bulk(ClientMsg::FilePull);
        }
        let blocked = {
            let q = q.clone();
            std::thread::spawn(move || q.send_bulk(ClientMsg::FilePull))
        };
        std::thread::sleep(Duration::from_millis(30));
        q.close();
        assert!(!blocked.join().unwrap());
        assert!(!q.send(ClientMsg::Refresh));
        assert_eq!(q.next(Duration::from_secs(5)), Next::Closed);
    }

    #[test]
    fn acks_keep_only_the_newest_and_go_first() {
        let q = OutQueue::default();
        q.send(ClientMsg::MouseButton { button: BTN_LEFT, down: true });
        // A host flooding tiny frames while reading slowly: one ack waits, not a million.
        for id in 1..=1_000_000 {
            assert!(q.send(ClientMsg::Ack(id)));
        }
        q.send(ClientMsg::Refresh);
        assert_eq!(q.next(Duration::ZERO), Next::Msg(ClientMsg::Ack(1_000_000)));
        assert_eq!(q.next(Duration::ZERO), Next::Msg(ClientMsg::MouseButton { button: BTN_LEFT, down: true }));
        assert_eq!(q.next(Duration::ZERO), Next::Msg(ClientMsg::Refresh));
        assert_eq!(q.next(Duration::ZERO), Next::Idle);
        q.send(ClientMsg::Ack(7));
        q.close();
        assert_eq!(q.next(Duration::ZERO), Next::Closed);
    }

    #[test]
    fn a_host_that_stops_reading_stalls_the_queue() {
        let q = Arc::new(OutQueue::default());
        let key = |i: usize| ClientMsg::Key { vk: i as u16, scan: 0, flags: 0 };
        for i in 0..CONTROL_DEPTH - 1 {
            assert!(q.send(key(i)));
        }
        assert!(q.send(ClientMsg::MouseMove { x: 1, y: 1 }));
        // Full, but merged messages still fit.
        assert!(q.send(ClientMsg::MouseMove { x: 2, y: 2 }) && q.send(ClientMsg::Ack(3)));
        assert!(!q.stalled());
        let producer = {
            let q = q.clone();
            std::thread::spawn(move || {
                for _ in 0..=BULK_DEPTH {
                    if !q.send_bulk(ClientMsg::FilePull) {
                        return false;
                    }
                }
                true
            })
        };
        assert!(!q.send(key(0)));
        assert!(q.stalled());
        // Closed: memory released, the writer and blocked producers stop, later sends fail.
        assert!(!producer.join().unwrap());
        assert_eq!(q.next(Duration::ZERO), Next::Closed);
        assert!(!q.send(ClientMsg::Ack(4)) && !q.send(ClientMsg::MouseMove { x: 3, y: 3 }));
        // An ordinary close is not a stall.
        let q = OutQueue::default();
        q.close();
        assert!(!q.send(key(0)) && !q.stalled());
    }

    #[test]
    fn size_changes_are_paced() {
        let t0 = Instant::now();
        let mut p = ResizePacer::new(t0);
        for _ in 0..RESIZE_BURST {
            assert_eq!(p.wait(t0), Duration::ZERO);
        }
        // Beyond the burst, one per `RESIZE_GAP`, never a longer wait than that.
        assert_eq!(p.wait(t0), RESIZE_GAP);
        assert_eq!(p.wait(t0 + RESIZE_GAP), RESIZE_GAP);
        assert_eq!(p.wait(t0 + RESIZE_GAP * 3), Duration::ZERO);
        assert_eq!(p.wait(t0 + RESIZE_GAP * 3), RESIZE_GAP);
        // A quiet host earns its burst back.
        let later = t0 + RESIZE_GAP * 100;
        for _ in 0..RESIZE_BURST {
            assert_eq!(p.wait(later), Duration::ZERO);
        }
        assert!(p.wait(later) > Duration::ZERO);
    }

    #[test]
    fn frame_lock_lets_a_waiting_ui_in_first() {
        let fb = Arc::new(FrameLock::new(0u32));
        // The UI thread announced that it waits (as `ui` does while blocked on the mutex).
        fb.ui_waiting.store(true, Ordering::SeqCst);
        let t = Instant::now();
        let reader = {
            let fb = fb.clone();
            std::thread::spawn(move || *fb.reader().unwrap() += 1)
        };
        std::thread::sleep(UI_FIRST_FOR / 5);
        // (Unless this thread slept so long that the reader stopped deferring.)
        assert!(!reader.is_finished() || t.elapsed() >= UI_FIRST_FOR, "the reader went ahead of the waiting UI thread");
        *fb.ui().unwrap() += 10;
        reader.join().unwrap();
        assert_eq!(*fb.ui().unwrap(), 11);
        assert!(!fb.ui_waiting.load(Ordering::SeqCst));
        // A UI thread that never takes its turn delays the reader only briefly.
        fb.ui_waiting.store(true, Ordering::SeqCst);
        let t = Instant::now();
        *fb.reader().unwrap() += 1;
        assert!(t.elapsed() >= UI_FIRST_FOR && t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn reconnect_policy() {
        assert_eq!(classify_link_error(&Error::msg(channel::CLOSED)), EndKind::Closed);
        assert_eq!(classify_link_error(&"connection timed out".into()), EndKind::Network);
        assert_eq!(classify_link_error(&"An existing connection was forcibly closed (os error 10054)".into()), EndKind::Network);
        assert_eq!(classify_link_error(&"record authentication failed".into()), EndKind::Fatal);
        assert_eq!(classify_link_error(&"invalid record length 3".into()), EndKind::Fatal);

        let long = Duration::from_secs(3600);
        let short = Duration::from_secs(2);
        assert!(should_reconnect(EndKind::Network, short, true, Some(Duration::ZERO)));
        assert!(!should_reconnect(EndKind::Fatal, long, false, None));
        assert!(should_reconnect(EndKind::Closed, long, false, None));
        assert!(should_reconnect(EndKind::Closed, short, false, Some(Duration::from_secs(60))));
        // Announced end, or kicked again right after reconnecting: stop.
        assert!(!should_reconnect(EndKind::Closed, long, false, Some(Duration::from_secs(1))));
        assert!(!should_reconnect(EndKind::Closed, short, true, None));
        assert!(should_reconnect(EndKind::Closed, long, true, None));

        let delays: Vec<u64> = (0..9).map(|a| reconnect_delay(a).as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30, 30, 30]);
        assert_eq!(reconnect_delay(u32::MAX).as_secs(), 30);

        assert!(!retryable(&"host failed authentication (wrong key, or someone is impersonating the host)".into()));
        assert!(!retryable(&"protocol version mismatch (peer 1, ours 2)".into()));
        assert!(retryable(&"cannot connect to 100.64.0.1:47300: refused".into()));
        assert!(retryable(&Error::msg(channel::CLOSED)));
    }

    #[test]
    fn meters_and_formatting() {
        let t0 = Instant::now();
        let mut m = RateMeter::new(t0);
        assert_eq!(m.update(t0 + Duration::from_millis(500), 10, 1000), None);
        let (fps, mbps) = m.update(t0 + Duration::from_secs(2), 60, 2_000_000).unwrap();
        assert!((fps - 30.0).abs() < 1e-9 && (mbps - 8.0).abs() < 1e-9);
        // Counters of a new session start again from zero.
        let (fps, _) = m.update(t0 + Duration::from_secs(3), 5, 0).unwrap();
        assert_eq!(fps, 0.0);

        assert_eq!(stats_text(Some(12), 29.6, 4.26), "12 ms · 30 fps · 4.3 Mbit/s");
        assert_eq!(stats_text(None, 0.0, 123.4), "– ms · 0 fps · 123 Mbit/s");
        assert_eq!(percent(1, 3), 33);
        assert_eq!(percent(5, 0), 100);
        assert_eq!(percent(u64::MAX, u64::MAX), 100);
    }

    #[test]
    fn screen_size_limits() {
        assert!(check_screen_size(1920, 1080).is_ok());
        assert!(check_screen_size(2 * 7680, 4320).is_ok());
        assert!(check_screen_size(8192, 8192).is_ok());
        assert!(check_screen_size(0, 1080).is_err() && check_screen_size(1920, 0).is_err());
        assert!(check_screen_size(8193, 8192).is_err());
        assert!(check_screen_size(65535, 65535).is_err());
    }

    #[test]
    fn pcm_and_audio_formats() {
        let mut out = vec![9];
        pcm16_le(&[0x01, 0x00, 0xff, 0xff, 0x00, 0x80], &mut out).unwrap();
        assert_eq!(out, [1, -1, i16::MIN]);
        assert!(pcm16_le(&[1, 2, 3], &mut out).is_err());
        assert!(audio_format_ok(48000, 2) && audio_format_ok(8000, 1));
        assert!(!audio_format_ok(48000, 0) && !audio_format_ok(48000, 3) && !audio_format_ok(1, 2) && !audio_format_ok(u32::MAX, 1));
    }
}
