//! Audio via PipeWire's command-line clients: `pw-record` taps the default sink's monitor
//! (what is playing) on the host and `pw-play` plays the stream on the viewer. Raw 16-bit
//! PCM flows over pipes, so nothing links against PipeWire.

use crate::log;
use crate::platform::jitter::JitterBuffer;
use crate::util::{Error, Result};
use std::ffi::{c_int, c_ulong};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

unsafe extern "C" {
    /// Takes four `unsigned long` arguments after `option`.
    fn prctl(option: c_int, ...) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn getuid() -> u32;
}

const PR_SET_PDEATHSIG: c_int = 1;
const SIGKILL: c_ulong = 9;
const F_SETPIPE_SZ: c_int = 1031;

/// Capture format: what `pw-record` converts the sink monitor to.
const CAPTURE_RATE: u32 = 48_000;
const CAPTURE_CHANNELS: u8 = 2;
/// Capture is handed to `on_pcm` in chunks of this length.
const CHUNK_MS: u32 = 20;
/// Node latency asked of PipeWire for both streams.
const LATENCY: &str = "20ms";
/// How long `AudioCapture::start` (on the host's input thread) gives `pw-record` to fail
/// before trusting it: an idle sink's monitor sends nothing, not even silence.
const START_GRACE: Duration = Duration::from_millis(100);
/// Pipe to `pw-play`, kept small (about 40 ms at 48 kHz stereo) so it adds little latency.
const PLAY_PIPE_BYTES: c_int = 8192;
/// Jitter buffer: start at 40 ms queued (the pipe and PipeWire add the rest), cap at 300 ms.
const START_MS: u32 = 40;
const MAX_MS: u32 = 300;
/// Audio handed to the pipe per write.
const WRITE_MS: u32 = 10;
const RETRY: Duration = Duration::from_secs(1);
/// A restarted child counts as recovered once it has streamed this much audio.
const HEALTHY_MS: u32 = 1000;

/// First absolute `PATH` entry holding an executable `name`.
fn find_binary(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// Where the PipeWire client library looks for its socket; falls back to the systemd
/// per-user directory when the environment does not say (e.g. a host started outside a login).
fn runtime_dir() -> Option<PathBuf> {
    env_dir("PIPEWIRE_RUNTIME_DIR").or_else(|| env_dir("XDG_RUNTIME_DIR")).or_else(|| {
        let dir = PathBuf::from(format!("/run/user/{}", unsafe { getuid() }));
        dir.is_dir().then_some(dir)
    })
}

/// The PipeWire daemon socket, if one is listening for this user.
fn pipewire_socket() -> Option<PathBuf> {
    let remote = env_dir("PIPEWIRE_REMOTE").unwrap_or_else(|| PathBuf::from("pipewire-0"));
    let path = if remote.is_absolute() { remote } else { runtime_dir()?.join(remote) };
    path.exists().then_some(path)
}

/// A child program and its arguments (`pw-record` / `pw-play` outside of tests).
struct Program {
    binary: PathBuf,
    args: Vec<String>,
}

/// A PipeWire client command that dies with the thread that started it.
fn pw_command(program: &Program) -> Command {
    let mut c = Command::new(&program.binary);
    c.args(&program.args).stderr(Stdio::null());
    if env_dir("PIPEWIRE_RUNTIME_DIR").is_none()
        && env_dir("XDG_RUNTIME_DIR").is_none()
        && let Some(dir) = runtime_dir()
    {
        c.env("XDG_RUNTIME_DIR", dir);
    }
    // The parent-death signal follows the spawning thread, which lives exactly as long as
    // the child is needed.
    unsafe {
        c.pre_exec(|| {
            prctl(PR_SET_PDEATHSIG, SIGKILL, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong);
            Ok(())
        });
    }
    c
}

/// The running child, shared so `Drop` can kill it while its thread is blocked on the pipe.
type Slot = Arc<Mutex<Option<Child>>>;

fn reap(slot: &Mutex<Option<Child>>) {
    if let Some(mut child) = slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Stops the worker: no new child after this, the current one is killed, the thread joined.
fn shut_down(stop: &AtomicBool, slot: &Mutex<Option<Child>>, thread: Option<JoinHandle<()>>) {
    {
        let mut child = slot.lock().unwrap_or_else(|e| e.into_inner());
        stop.store(true, Ordering::SeqCst);
        if let Some(c) = child.as_mut() {
            let _ = c.kill();
        }
    }
    if let Some(t) = thread {
        let _ = t.join();
    }
    reap(slot);
}

/// Sleeps up to `d`, waking early when `stop` is set.
fn nap(d: Duration, stop: &AtomicBool) {
    let end = Instant::now() + d;
    while !stop.load(Ordering::SeqCst) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
}

type OnPcm = Box<dyn FnMut(&[i16], u32, u8) + Send>;

/// Captures what the host is playing. Dropping it stops capture.
pub struct AudioCapture {
    stop: Arc<AtomicBool>,
    child: Slot,
    thread: Option<JoinHandle<()>>,
}

impl AudioCapture {
    /// True when `pw-record` is installed and a PipeWire daemon is listening for this user.
    pub fn available() -> bool {
        find_binary("pw-record").is_some() && pipewire_socket().is_some()
    }

    /// `on_pcm(samples, rate, channels)` receives interleaved 16-bit PCM (48 kHz stereo) from
    /// a capture thread in 20 ms chunks. Fails when `pw-record` cannot start or exits within
    /// `START_GRACE`; later exits (PipeWire restarts) are retried.
    pub fn start(on_pcm: Box<dyn FnMut(&[i16], u32, u8) + Send>) -> Result<AudioCapture> {
        let binary = find_binary("pw-record").ok_or("pw-record not found (install pipewire-bin)")?;
        if pipewire_socket().is_none() {
            return Err("PipeWire is not running for this user".into());
        }
        AudioCapture::run(Program { binary, args: record_args() }, on_pcm)
    }

    fn run(program: Program, on_pcm: OnPcm) -> Result<AudioCapture> {
        let stop = Arc::new(AtomicBool::new(false));
        let child: Slot = Arc::new(Mutex::new(None));
        // A rendezvous: the thread's report is either taken by this wait or refused, never left queued.
        let (tx, rx) = mpsc::sync_channel(0);
        let (s, c) = (stop.clone(), child.clone());
        let thread = std::thread::Builder::new().name("audio-capture".into()).spawn(move || capture_thread(&program, on_pcm, &s, &c, tx))?;
        let r = match rx.recv_timeout(START_GRACE) {
            Ok(r) => r,
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(()), // running, nothing routed to it yet
            Err(mpsc::RecvTimeoutError::Disconnected) => Err("audio capture thread exited".into()),
        };
        let cap = AudioCapture { stop, child, thread: Some(thread) };
        r.map(|()| cap)
    }
}

impl Drop for AudioCapture {
    fn drop(&mut self) {
        shut_down(&self.stop, &self.child, self.thread.take());
    }
}

fn record_args() -> Vec<String> {
    vec![
        "--rate".into(),
        CAPTURE_RATE.to_string(),
        "--channels".into(),
        CAPTURE_CHANNELS.to_string(),
        "--format".into(),
        "s16".into(),
        "--latency".into(),
        LATENCY.into(),
        // Record the monitor of the default sink, following it when the default changes.
        "-P".into(),
        "{ stream.capture.sink = true node.name = safe-rdp-capture media.name = \"safe-rdp host audio\" }".into(),
        "-".into(),
    ]
}

/// Tells `AudioCapture::run` how the start went while it is still waiting. False once it has
/// stopped waiting: the problem is then logged and retried like any later one.
fn report(ready: &mut Option<mpsc::SyncSender<Result<()>>>, r: Result<()>) -> bool {
    ready.take().is_some_and(|tx| tx.send(r).is_ok())
}

fn capture_thread(program: &Program, mut on_pcm: OnPcm, stop: &AtomicBool, slot: &Mutex<Option<Child>>, ready: mpsc::SyncSender<Result<()>>) {
    let chunk_frames = (CAPTURE_RATE * CHUNK_MS / 1000) as usize;
    let mut bytes = vec![0u8; chunk_frames * CAPTURE_CHANNELS as usize * 2];
    let mut pcm = vec![0i16; chunk_frames * CAPTURE_CHANNELS as usize];
    let healthy_chunks = (HEALTHY_MS / CHUNK_MS) as usize;
    let mut ready = Some(ready);
    let mut failing = false;
    loop {
        let stdout = {
            let mut child = slot.lock().unwrap_or_else(|e| e.into_inner());
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let spawned = pw_command(program).stdin(Stdio::null()).stdout(Stdio::piped()).spawn();
            match spawned {
                Ok(mut c) => {
                    let out = c.stdout.take();
                    *child = Some(c);
                    out
                }
                Err(e) => {
                    let e = format!("cannot start {}: {e}", program.binary.display());
                    if report(&mut ready, Err(Error::msg(e.clone()))) {
                        return;
                    }
                    log!("audio capture: {e}");
                    None
                }
            }
        };
        if let Some(mut out) = stdout {
            let mut chunks = 0usize;
            while out.read_exact(&mut bytes).is_ok() {
                for (s, b) in pcm.iter_mut().zip(bytes.as_chunks::<2>().0) {
                    *s = i16::from_le_bytes(*b);
                }
                report(&mut ready, Ok(()));
                chunks += 1;
                if failing && chunks == healthy_chunks {
                    log!("audio capture resumed");
                    failing = false;
                }
                on_pcm(&pcm, CAPTURE_RATE, CAPTURE_CHANNELS);
            }
        }
        reap(slot);
        if stop.load(Ordering::SeqCst) {
            break;
        }
        if report(&mut ready, Err("pw-record exited without audio (is PipeWire running?)".into())) {
            return;
        }
        if !failing {
            log!("audio capture: pw-record stopped; restarting");
            failing = true;
        }
        nap(RETRY, stop);
    }
}

/// Plays a PCM stream with a small jitter buffer. Dropping it stops playback.
pub struct AudioPlayer {
    buf: Arc<Mutex<JitterBuffer>>,
    stop: Arc<AtomicBool>,
    child: Slot,
    thread: Option<JoinHandle<()>>,
}

impl AudioPlayer {
    /// Starts `pw-play` for `rate` Hz, 1 or 2 channel 16-bit PCM.
    pub fn new(rate: u32, channels: u8) -> Result<AudioPlayer> {
        if !(8_000..=384_000).contains(&rate) || !(1..=2).contains(&channels) {
            return Err(Error::msg(format!("unsupported playback format: {rate} Hz, {channels} channels")));
        }
        let binary = find_binary("pw-play").ok_or("pw-play not found (install pipewire-bin)")?;
        if pipewire_socket().is_none() {
            return Err("PipeWire is not running for this user".into());
        }
        AudioPlayer::run(Program { binary, args: play_args(rate, channels) }, rate, channels)
    }

    fn run(program: Program, rate: u32, channels: u8) -> Result<AudioPlayer> {
        let buf = Arc::new(Mutex::new(JitterBuffer::new(rate, channels, START_MS, MAX_MS)));
        let stop = Arc::new(AtomicBool::new(false));
        let child: Slot = Arc::new(Mutex::new(None));
        let (tx, rx) = mpsc::sync_channel(1);
        let (b, s, c) = (buf.clone(), stop.clone(), child.clone());
        let thread = std::thread::Builder::new().name("audio-render".into()).spawn(move || play_thread(&program, rate, channels, &b, &s, &c, tx))?;
        let r = rx.recv().unwrap_or_else(|_| Err("audio playback thread exited".into()));
        let player = AudioPlayer { buf, stop, child, thread: Some(thread) };
        r.map(|()| player)
    }

    /// Queues interleaved 16-bit PCM.
    pub fn push(&mut self, pcm: &[i16]) {
        self.buf.lock().unwrap_or_else(|e| e.into_inner()).push(pcm);
    }
}

impl Drop for AudioPlayer {
    fn drop(&mut self) {
        shut_down(&self.stop, &self.child, self.thread.take());
    }
}

fn play_args(rate: u32, channels: u8) -> Vec<String> {
    vec![
        "--rate".into(),
        rate.to_string(),
        "--channels".into(),
        channels.to_string(),
        "--format".into(),
        "s16".into(),
        "--latency".into(),
        LATENCY.into(),
        "-P".into(),
        "{ node.name = safe-rdp-playback media.name = \"safe-rdp remote audio\" }".into(),
        "-".into(),
    ]
}

fn play_thread(
    program: &Program,
    rate: u32,
    channels: u8,
    buf: &Mutex<JitterBuffer>,
    stop: &AtomicBool,
    slot: &Mutex<Option<Child>>,
    ready: mpsc::SyncSender<Result<()>>,
) {
    let mut chunk = vec![0i16; (rate * WRITE_MS / 1000).max(1) as usize * channels as usize];
    let mut bytes = Vec::with_capacity(chunk.len() * 2);
    let healthy_writes = (HEALTHY_MS / WRITE_MS) as usize;
    let mut ready = Some(ready);
    let mut failing = false;
    loop {
        let stdin = {
            let mut child = slot.lock().unwrap_or_else(|e| e.into_inner());
            if stop.load(Ordering::SeqCst) {
                break;
            }
            match pw_command(program).stdin(Stdio::piped()).stdout(Stdio::null()).spawn() {
                Ok(mut c) => {
                    let input = c.stdin.take();
                    if let Some(i) = &input {
                        // Best effort: a smaller pipe means less queued audio (Linux >= 2.6.35).
                        unsafe { fcntl(i.as_raw_fd(), F_SETPIPE_SZ, PLAY_PIPE_BYTES) };
                    }
                    *child = Some(c);
                    if let Some(tx) = ready.take() {
                        let _ = tx.send(Ok(()));
                    }
                    input
                }
                Err(e) => {
                    let e = Error::msg(format!("cannot start {}: {e}", program.binary.display()));
                    match ready.take() {
                        Some(tx) => {
                            let _ = tx.send(Err(e));
                            return;
                        }
                        None => {
                            log!("audio playback: {e}");
                            None
                        }
                    }
                }
            }
        };
        if let Some(mut input) = stdin {
            // Silence keeps flowing while the jitter buffer refills, so the pipe always paces us.
            let mut writes = 0usize;
            while !stop.load(Ordering::SeqCst) {
                buf.lock().unwrap_or_else(|e| e.into_inner()).pull(&mut chunk);
                bytes.clear();
                bytes.extend(chunk.iter().flat_map(|s| s.to_le_bytes()));
                if input.write_all(&bytes).is_err() {
                    break;
                }
                writes += 1;
                if failing && writes == healthy_writes {
                    log!("audio playback resumed");
                    failing = false;
                }
            }
        }
        reap(slot);
        if stop.load(Ordering::SeqCst) {
            break;
        }
        if !failing {
            log!("audio playback: pw-play stopped; restarting");
            failing = true;
        }
        nap(RETRY, stop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::AtomicUsize;

    /// A stand-in for the PipeWire tools.
    fn sh(script: &str) -> Program {
        Program { binary: find_binary("sh").unwrap(), args: vec!["-c".into(), script.into()] }
    }

    fn running(pid: u32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
    }

    fn pid(slot: &Slot) -> u32 {
        slot.lock().unwrap().as_ref().map(Child::id).expect("no child running")
    }

    #[test]
    fn capture_fails_when_the_recorder_exits_without_audio() {
        let t = Instant::now();
        assert!(AudioCapture::run(sh("exit 1"), Box::new(|_, _, _| panic!("no audio expected"))).is_err());
        assert!(t.elapsed() < START_GRACE, "noticed only after {:?}", t.elapsed());
        let missing = Program { binary: PathBuf::from("/nonexistent/pw-record"), args: vec![] };
        assert!(AudioCapture::run(missing, Box::new(|_, _, _| {})).is_err());
    }

    #[test]
    fn capture_of_an_idle_sink_starts_at_once() {
        // An idle sink's monitor: a recorder that runs and sends nothing.
        let t = Instant::now();
        let cap = AudioCapture::run(sh("exec sleep 30"), Box::new(|_, _, _| panic!("no audio expected"))).unwrap();
        assert!(t.elapsed() < Duration::from_millis(200), "start took {:?}", t.elapsed());
        let child = pid(&cap.child);
        drop(cap);
        assert!(!running(child), "recorder survived the drop");

        // One that exits without audio only after the start returned is restarted, not given up on.
        let mark = std::env::temp_dir().join(format!("safe-rdp-test-capture-{}", std::process::id()));
        let _ = std::fs::remove_file(&mark);
        let script = format!("if [ -e '{0}' ]; then head -c 3840 /dev/zero; else touch '{0}'; sleep 0.3; fi", mark.display());
        let chunks = Arc::new(AtomicUsize::new(0));
        let c = chunks.clone();
        let cap = AudioCapture::run(sh(&script), Box::new(move |_, _, _| _ = c.fetch_add(1, Ordering::SeqCst))).unwrap();
        let t = Instant::now();
        while chunks.load(Ordering::SeqCst) == 0 && t.elapsed() < RETRY * 3 {
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(cap);
        let _ = std::fs::remove_file(&mark);
        assert!(chunks.load(Ordering::SeqCst) > 0, "recorder was not restarted");
    }

    #[test]
    fn capture_delivers_chunks_and_kills_the_recorder_on_drop() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        // Ten 20 ms chunks, then a recorder that stays alive but quiet.
        let cap = AudioCapture::run(
            sh("head -c 38400 /dev/zero; exec sleep 30"),
            Box::new(move |pcm, rate, ch| s.lock().unwrap().push((pcm.len(), pcm.iter().all(|&v| v == 0), rate, ch))),
        )
        .unwrap();
        let t = Instant::now();
        while seen.lock().unwrap().len() < 10 && t.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let child = pid(&cap.child);
        let t = Instant::now();
        drop(cap);
        assert!(t.elapsed() < Duration::from_millis(500));
        assert!(!running(child), "recorder survived the drop");
        assert_eq!(*seen.lock().unwrap(), vec![(1920, true, 48_000, 2); 10]);
    }

    #[test]
    fn capture_restarts_a_recorder_that_dies() {
        let chunks = Arc::new(AtomicUsize::new(0));
        let c = chunks.clone();
        let cap = AudioCapture::run(sh("head -c 3840 /dev/zero"), Box::new(move |_, _, _| _ = c.fetch_add(1, Ordering::SeqCst))).unwrap();
        std::thread::sleep(RETRY + Duration::from_millis(500));
        let t = Instant::now();
        drop(cap);
        assert!(t.elapsed() < Duration::from_millis(500));
        assert!(chunks.load(Ordering::SeqCst) >= 2, "recorder was not restarted");
    }

    #[test]
    fn player_feeds_the_pipe_and_stops_promptly() {
        // A sink that swallows audio as fast as it comes: the queue drains at once.
        let mut p = AudioPlayer::run(sh("exec cat > /dev/null"), 48_000, 2).unwrap();
        p.push(&vec![1i16; 2 * 4800]);
        let t = Instant::now();
        while p.buf.lock().unwrap().queued_frames() > 0 && t.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(p.buf.lock().unwrap().queued_frames(), 0);
        let child = pid(&p.child);
        let t = Instant::now();
        drop(p);
        assert!(t.elapsed() < Duration::from_millis(500));
        assert!(!running(child), "player survived the drop");
    }

    #[test]
    fn player_outlives_a_dying_sink() {
        let mut p = AudioPlayer::run(sh("exit 0"), 44_100, 1).unwrap();
        let t = Instant::now();
        for _ in 0..20 {
            p.push(&[0; 441]); // never blocks, whatever the child does
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(t.elapsed() < Duration::from_millis(500));
        let t = Instant::now();
        drop(p);
        assert!(t.elapsed() < Duration::from_millis(500));
        let missing = Program { binary: PathBuf::from("/nonexistent/pw-play"), args: vec![] };
        assert!(AudioPlayer::run(missing, 48_000, 2).is_err());
    }

    #[test]
    fn finds_binaries_on_path_only() {
        assert!(find_binary("sh").is_some_and(|p| p.is_absolute()));
        assert!(find_binary("safe-rdp-no-such-tool").is_none());
        assert!(AudioPlayer::new(1_000, 2).is_err());
        assert!(AudioPlayer::new(48_000, 3).is_err());
    }

    #[test]
    fn stream_arguments() {
        let rec = record_args();
        assert!(rec.windows(2).any(|w| w == ["--format", "s16"]));
        assert!(rec.iter().any(|a| a.contains("stream.capture.sink = true")));
        assert_eq!(rec.last().map(String::as_str), Some("-"));
        let play = play_args(44_100, 1);
        assert!(play.windows(2).any(|w| w == ["--rate", "44100"]));
        assert!(play.windows(2).any(|w| w == ["--channels", "1"]));
        assert_eq!(play.last().map(String::as_str), Some("-"));
    }

    /// Needs a PipeWire session. Plays silence only.
    #[test]
    #[ignore = "uses PipeWire (silent)"]
    fn smoke_monitor_capture_and_silent_playback() {
        assert!(AudioCapture::available(), "pw-record or the PipeWire socket is missing");
        let mut player = AudioPlayer::new(48_000, 2).unwrap();
        player.push(&vec![0i16; 2 * 9600]); // 200 ms of silence
        let seen = Arc::new(Mutex::new((0usize, 0usize, 0u32, 0u8)));
        let s = seen.clone();
        let t = Instant::now();
        let cap = AudioCapture::start(Box::new(move |pcm, rate, channels| {
            let mut s = s.lock().unwrap();
            s.0 += 1;
            s.1 += pcm.len();
            (s.2, s.3) = (rate, channels);
        }))
        .unwrap();
        let started_in = t.elapsed();
        std::thread::sleep(Duration::from_millis(300));
        let pid = cap.child.lock().unwrap().as_ref().map(|c| c.id());
        let t = Instant::now();
        drop(cap);
        let stopped_in = t.elapsed();
        let left = player.buf.lock().unwrap().queued_frames();
        let play_pid = player.child.lock().unwrap().as_ref().map(|c| c.id());
        drop(player);
        let (calls, samples, rate, channels) = *seen.lock().unwrap();
        eprintln!(
            "monitor: {calls} callbacks, {samples} samples, {rate} Hz x{channels}; started in {started_in:?}, stopped in {stopped_in:?}; {left} frames unplayed"
        );
        assert!(calls > 0 && (rate, channels) == (48_000, 2));
        assert_eq!(samples, calls * 960 * 2, "20 ms chunks");
        assert!(stopped_in < Duration::from_millis(500));
        assert_eq!(left, 0, "pw-play did not drain the jitter buffer");
        for pid in [pid, play_pid].into_iter().flatten() {
            assert!(!Path::new(&format!("/proc/{pid}")).exists(), "child {pid} still running");
        }
    }
}
