//! Host side: listens on the Tailscale interface, authenticates viewers and streams the screen.

use crate::capture::{self, Area, Capturer, CursorTracker, MonitorSel};
use crate::channel::{self, RecordReader, RecordWriter};
use crate::clipboard::Clipboard;
use crate::codec::{self, Encoder};
use crate::desktop::DesktopFollower;
use crate::input::Injector;
use crate::net::{self, PeerPolicy};
use crate::proto::*;
use crate::util::{Result, Secret};
use crate::{bail, log};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PENDING: usize = 4;
const MAX_IN_FLIGHT: u32 = 2;

struct SessionCtl {
    stop: AtomicBool,
    finished: AtomicBool,
    sock: TcpStream,
}

impl SessionCtl {
    fn kick(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.sock.shutdown(Shutdown::Both);
    }
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

struct Host {
    opts: HostOptions,
    psk: Secret<32>,
    current: Mutex<Option<Arc<SessionCtl>>>,
    pending: AtomicUsize,
}

pub fn run(opts: HostOptions, psk: Secret<32>) -> Result<()> {
    let ip = match opts.bind {
        Some(ip) => ip,
        None => {
            let mut warned = false;
            loop {
                if let Some(ip) = net::tailscale_ipv4() {
                    break IpAddr::V4(ip);
                }
                if !warned {
                    log!("waiting for Tailscale to come up (no 100.64.0.0/10 address yet)...");
                    warned = true;
                }
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    };
    if !net::is_tailscale(ip) && !ip.is_loopback() && !opts.policy.allow_non_tailscale {
        bail!("{ip} is not a Tailscale address; pass --allow-non-tailscale to bind it anyway");
    }
    let addr = SocketAddr::new(ip, opts.port);
    let listener = TcpListener::bind(addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    log!("safe-rdp host listening on {addr} (view-only: {}, clipboard: {})", opts.view_only, opts.clipboard);

    let host = Arc::new(Host { opts, psk, current: Mutex::new(None), pending: AtomicUsize::new(0) });
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                log!("accept failed: {e}");
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
        };
        let Ok(peer) = stream.peer_addr() else { continue };
        if !host.opts.policy.allows(peer.ip()) {
            log!("refused {peer}: address not allowed");
            continue;
        }
        if host.pending.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING {
            host.pending.fetch_sub(1, Ordering::SeqCst);
            log!("refused {peer}: too many pending handshakes");
            continue;
        }
        let host = host.clone();
        std::thread::spawn(move || {
            let authed = authenticate(&host, &stream, peer);
            host.pending.fetch_sub(1, Ordering::SeqCst);
            if let Some(keys) = authed {
                serve(&host, stream, peer, keys);
            }
        });
    }
    Ok(())
}

fn authenticate(host: &Host, stream: &TcpStream, peer: SocketAddr) -> Option<channel::SessionKeys> {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    match channel::server_handshake(&mut &*stream, &host.psk.0) {
        Ok(k) => Some(k),
        Err(e) => {
            log!("authentication failed for {peer}: {e}");
            // Slow down guessing; the slot stays occupied meanwhile.
            std::thread::sleep(Duration::from_secs(1));
            None
        }
    }
}

fn serve(host: &Host, stream: TcpStream, peer: SocketAddr, keys: channel::SessionKeys) {
    let Ok(sock) = stream.try_clone() else { return };
    let ctl = Arc::new(SessionCtl { stop: AtomicBool::new(false), finished: AtomicBool::new(false), sock });
    let old = host.current.lock().unwrap().replace(ctl.clone());
    if let Some(old) = old {
        log!("replacing the existing session");
        old.kick();
        // Let it release its screen duplication and injected keys first.
        let t = Instant::now();
        while !old.finished.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    log!("session started: {peer}");
    let r = run_session(host, stream, keys, &ctl);
    ctl.kick();
    {
        let mut cur = host.current.lock().unwrap();
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

type Writer = Arc<Mutex<RecordWriter<TcpStream>>>;

fn send(w: &Writer, m: &ServerMsg) -> Result<()> {
    let mut b = Vec::new();
    m.encode(&mut b);
    w.lock().unwrap().send(&b)
}

struct Shared {
    acked: AtomicU32,
    refresh: AtomicBool,
    /// Milliseconds since session start of the latest input event.
    last_input_ms: AtomicU64,
    area: Mutex<Area>,
    start: Instant,
}

fn run_session(host: &Host, stream: TcpStream, keys: channel::SessionKeys, ctl: &Arc<SessionCtl>) -> Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let writer: Writer = Arc::new(Mutex::new(RecordWriter::new(stream.try_clone()?, keys.send)));
    let reader = RecordReader::new(stream, keys.recv);
    let opts = &host.opts;

    let area = capture::resolve(opts.monitor).ok_or("selected monitor not found")?;
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
    send(&writer, &ServerMsg::Hello { width: area.width as u16, height: area.height as u16, flags })?;

    let shared = Arc::new(Shared {
        acked: AtomicU32::new(0),
        refresh: AtomicBool::new(false),
        last_input_ms: AtomicU64::new(0),
        area: Mutex::new(area),
        start: Instant::now(),
    });

    let clip = if opts.clipboard {
        let w = writer.clone();
        let c = ctl.clone();
        Some(Clipboard::spawn(move |text| {
            if !c.stopped() {
                let _ = send(&w, &ServerMsg::Clipboard(text));
            }
        })?)
    } else {
        None
    };

    let input_thread = {
        let (shared, ctl) = (shared.clone(), ctl.clone());
        let (view_only, sas) = (opts.view_only, opts.sas);
        std::thread::spawn(move || {
            let r = input_loop(reader, &shared, view_only, sas, clip.as_ref());
            ctl.kick();
            r
        })
    };

    let r = capture_loop(opts, &writer, &shared, ctl);
    ctl.kick();
    let ir = input_thread.join().unwrap_or(Ok(()));
    // Report the first real cause: a closed viewer shows up as a read error.
    match (r, ir) {
        (Err(e), _) if !ctl.stopped() => Err(e),
        (_, Err(e)) => Err(e),
        (r, _) => r,
    }
}

fn input_loop(
    mut reader: RecordReader<TcpStream>,
    shared: &Shared,
    view_only: bool,
    sas: bool,
    clip: Option<&Clipboard>,
) -> Result<()> {
    let mut inj = Injector::default();
    let mut follower = DesktopFollower::new();
    let mut last_sync = Instant::now() - Duration::from_secs(1);
    loop {
        let m = ClientMsg::decode(reader.recv()?)?;
        match m {
            ClientMsg::Ack(id) => shared.acked.store(id, Ordering::SeqCst),
            ClientMsg::Refresh => shared.refresh.store(true, Ordering::SeqCst),
            ClientMsg::Ping => {}
            ClientMsg::Clipboard(text) => {
                if let Some(c) = clip {
                    c.set(text);
                }
            }
            ClientMsg::Sas => {
                if view_only {
                } else if !sas || !crate::service::request_sas() {
                    log!("Ctrl+Alt+Del requested but SAS forwarding is unavailable (run as service with --enable-sas)");
                }
            }
            ClientMsg::MouseMove { .. }
            | ClientMsg::MouseButton { .. }
            | ClientMsg::Wheel { .. }
            | ClientMsg::Key { .. }
            | ClientMsg::ReleaseAll => {
                if view_only {
                    continue;
                }
                if last_sync.elapsed() > Duration::from_millis(250) {
                    follower.sync();
                    last_sync = Instant::now();
                }
                inj.set_area(*shared.area.lock().unwrap());
                inj.handle(&m);
                shared.last_input_ms.store(shared.start.elapsed().as_millis() as u64, Ordering::SeqCst);
            }
        }
    }
}

fn capture_loop(opts: &HostOptions, writer: &Writer, shared: &Shared, ctl: &SessionCtl) -> Result<()> {
    let fast = Duration::from_millis(1000 / opts.max_fps.clamp(1, 120) as u64);
    let slow = Duration::from_millis(100);
    let mut follower = DesktopFollower::new();
    let mut encoder = Encoder::new()?;
    let cursors = CursorTracker::new();
    let mut capturer: Option<Capturer> = None;
    let mut last_cursor = None;
    let mut frame: u32 = 0;
    let mut last_geometry_check = Instant::now();
    let mut last_change = Instant::now();
    let mut last_send = Instant::now();
    let mut capture_failures = 0u32;
    let mut last_dxgi_try = Instant::now();
    let multi_all = opts.monitor == MonitorSel::All && capture::monitors().len() > 1;

    while !ctl.stopped() {
        let t0 = Instant::now();
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
            match capture::resolve(opts.monitor) {
                Some(a) if switched || current != Some(a) => {
                    capturer = None; // release the old device/DCs before creating new ones
                    let c = if multi_all {
                        Capturer::gdi(a)
                    } else {
                        Capturer::new(a)
                    };
                    match c {
                        Ok(c) => {
                            if current != Some(a) {
                                log!("capturing {}x{} via {}", a.width, a.height, if c.waits_for_changes() { "DXGI" } else { "GDI" });
                            }
                            capturer = Some(c);
                            *shared.area.lock().unwrap() = a;
                            encoder.request_full();
                        }
                        Err(e) => log!("capture setup failed: {e}"),
                    }
                }
                Some(a) if !multi_all && last_dxgi_try.elapsed() > Duration::from_secs(10) && capturer.as_ref().is_some_and(|c| !c.waits_for_changes()) => {
                    // A transient DXGI failure (secure desktop, full-screen app, driver reset) may have passed.
                    last_dxgi_try = Instant::now();
                    if let Ok(d) = crate::dxgi::DxgiCapture::new(a) {
                        log!("switched back to DXGI capture");
                        capturer = Some(Capturer::Dxgi(d));
                        encoder.request_full();
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
            send(writer, &ServerMsg::Cursor(cursor))?;
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
                let refresh = shared.refresh.swap(false, Ordering::SeqCst);
                if refresh {
                    encoder.request_full();
                }
                if changed || refresh {
                    let area = cap.area();
                    let (w, h) = (area.width as usize, area.height as usize);
                    let rects = encoder.encode(cap.pixels(), w, h);
                    if !rects.is_empty() {
                        frame = frame.wrapping_add(1);
                        for msg in codec::pack(frame, w, h, &rects) {
                            writer.lock().unwrap().send(&msg)?;
                        }
                        last_change = Instant::now();
                        last_send = last_change;
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
            send(writer, &ServerMsg::Ping)?;
            last_send = Instant::now();
        }

        // Cap the frame rate. GDI is also polled slowly while the screen is idle;
        // DXGI already slept inside next_frame until something changed.
        let since_input = shared.start.elapsed().as_millis() as u64 - shared.last_input_ms.load(Ordering::SeqCst);
        let idle = last_change.elapsed() > Duration::from_secs(2) && since_input > 2000;
        let polling = capturer.as_ref().is_some_and(|c| !c.waits_for_changes());
        let interval = if idle && polling { slow } else { fast };
        if let Some(rest) = interval.checked_sub(t0.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    Ok(())
}
