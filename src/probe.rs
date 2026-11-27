//! Headless test client: connects like a viewer, measures the session and can drive it.
//!
//! `safe-rdp probe <host> [--seconds N] [--type TEXT] [--move X,Y] [--click X,Y]
//!  [--set KEY=VALUE]... [--upload FILE]... [--pull] [--expect-change] [--snapshot FILE.ppm]`
//!
//! It prints the host's hello, frame/byte rates, round-trip times, setting confirmations and
//! file-transfer results (`--pull` saves into `files::transfer_dir()`, like the viewer), and
//! exits non-zero if an expectation fails. `--snapshot` is the only thing in safe-rdp that
//! writes screen contents to disk, and only when explicitly asked.

use crate::codec::{self, Decoder};
use crate::files::{Incoming, Outgoing};
use crate::platform::mem::LockedBuf;
use crate::proto::*;
use crate::util::{Error, Result, Secret, SecureVec};
use crate::viewer::{Next, OutQueue, ViewerOptions, check_screen_size, connect};
use crate::{bail, log};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct ProbeOptions {
    pub viewer: ViewerOptions,
    pub seconds: f64,
    pub type_text: Option<String>,
    pub moves: Vec<(u16, u16)>,
    pub clicks: Vec<(u16, u16)>,
    pub sets: Vec<(u8, u32)>,
    pub uploads: Vec<String>,
    pub pull: bool,
    /// Where `--pull` saves (None: `files::transfer_dir()`; tests use one of their own).
    pub pull_dir: Option<std::path::PathBuf>,
    pub expect_change: bool,
    pub snapshot: Option<String>,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        ProbeOptions {
            viewer: ViewerOptions { view_only: false, ..ViewerOptions::default() },
            seconds: 5.0,
            type_text: None,
            moves: Vec::new(),
            clicks: Vec::new(),
            sets: Vec::new(),
            uploads: Vec::new(),
            pull: false,
            pull_dir: None,
            expect_change: false,
            snapshot: None,
        }
    }
}

pub fn set_key(name: &str) -> Option<u8> {
    Some(match name {
        "quality" => SET_QUALITY,
        "downscale" | "scale" => SET_DOWNSCALE,
        "monitor" => SET_MONITOR,
        "audio" => SET_AUDIO,
        "privacy" => SET_PRIVACY,
        _ => return None,
    })
}

/// US-layout set-1 scancode and whether Shift is needed, for typing ASCII.
fn scancode_for(c: char) -> Option<(u16, bool)> {
    const ROW_NUM: &str = "1234567890-=";
    const ROW_NUM_SHIFT: &str = "!@#$%^&*()_+";
    const ROW_Q: &str = "qwertyuiop[]";
    const ROW_Q_SHIFT: &str = "QWERTYUIOP{}";
    const ROW_A: &str = "asdfghjkl;'`";
    const ROW_A_SHIFT: &str = "ASDFGHJKL:\"~";
    const ROW_Z: &str = "zxcvbnm,./";
    const ROW_Z_SHIFT: &str = "ZXCVBNM<>?";
    let find = |row: &str, base: u16| row.chars().position(|x| x == c).map(|i| base + i as u16);
    match c {
        ' ' => return Some((0x39, false)),
        '\n' => return Some((0x1c, false)),
        '\t' => return Some((0x0f, false)),
        '\\' => return Some((0x2b, false)),
        '|' => return Some((0x2b, true)),
        _ => {}
    }
    for (row, shift_row, base) in [(ROW_NUM, ROW_NUM_SHIFT, 0x02), (ROW_Q, ROW_Q_SHIFT, 0x10), (ROW_A, ROW_A_SHIFT, 0x1e), (ROW_Z, ROW_Z_SHIFT, 0x2c)] {
        if let Some(s) = find(row, base) {
            return Some((s, false));
        }
        if let Some(s) = find(shift_row, base) {
            return Some((s, true));
        }
    }
    None
}

fn key_msgs(text: &str) -> Result<Vec<ClientMsg>> {
    const LSHIFT: u16 = 0x2a;
    let mut v = Vec::new();
    for c in text.chars() {
        let (scan, shift) = scancode_for(c).ok_or_else(|| Error::msg(format!("--type: cannot type {c:?}")))?;
        if shift {
            v.push(ClientMsg::Key { vk: 0xa0, scan: LSHIFT, flags: 0 });
        }
        v.push(ClientMsg::Key { vk: 0, scan, flags: 0 });
        v.push(ClientMsg::Key { vk: 0, scan, flags: KEY_UP });
        if shift {
            v.push(ClientMsg::Key { vk: 0xa0, scan: LSHIFT, flags: KEY_UP });
        }
    }
    Ok(v)
}

fn checksum(fb: &[u8]) -> u64 {
    // FNV-1a over the colour bytes; enough to notice that the picture changed.
    fb.chunks_exact(4).fold(0xcbf29ce484222325u64, |h, p| {
        let h = (h ^ p[0] as u64).wrapping_mul(0x100000001b3);
        let h = (h ^ p[1] as u64).wrapping_mul(0x100000001b3);
        (h ^ p[2] as u64).wrapping_mul(0x100000001b3)
    })
}

/// Where pulled files go: the user's own `files::transfer_dir()`, never a shared temp directory.
/// Files the host sends without `--pull` are refused.
fn download_dir(o: &ProbeOptions) -> Result<std::path::PathBuf> {
    if !o.pull {
        bail!("the host sent a file that was not asked for (no --pull)");
    }
    match &o.pull_dir {
        Some(d) => Ok(d.clone()),
        None => crate::files::transfer_dir(),
    }
}

/// The `--set` keys with fewer `State` replies in `states` than settings, and how many are
/// missing. The host answers every `Set`, and with one unasked `State` each, which answers no
/// `Set`: the quality when the hello left it to a host that says which (`F_QUALITY_STATE`), and
/// the hello's sound and privacy wishes.
fn unanswered(sets: &[(u8, u32)], states: &[(u8, u32)], (quality, audio, privacy): (bool, bool, bool)) -> Vec<(u8, usize)> {
    let mut keys: Vec<u8> = sets.iter().map(|s| s.0).collect();
    keys.sort_unstable();
    keys.dedup();
    keys.into_iter()
        .filter_map(|key| {
            let asked = sets.iter().filter(|s| s.0 == key).count();
            let wished = (key == SET_QUALITY && quality) || (key == SET_AUDIO && audio) || (key == SET_PRIVACY && privacy);
            let answers = states.iter().filter(|s| s.0 == key).count().saturating_sub(wished as usize);
            (answers < asked).then_some((key, asked - answers))
        })
        .collect()
}

fn write_ppm(path: &str, fb: &[u8], w: usize, h: usize) -> Result<()> {
    let mut out = format!("P6\n{w} {h}\n255\n").into_bytes();
    out.reserve(w * h * 3);
    for p in fb.chunks_exact(4) {
        out.extend_from_slice(&[p[2], p[1], p[0]]);
    }
    let r = std::fs::write(path, &out);
    crate::util::wipe(&mut out);
    r?;
    Ok(())
}

/// What the probe sends, sent on threads of its own (see `run`); the first failure among them.
#[derive(Clone)]
struct Sender {
    queue: Arc<OutQueue>,
    failed: Arc<Mutex<Option<String>>>,
}

impl Sender {
    /// Starts the writer thread.
    fn start(mut w: crate::channel::RecordWriter<std::net::TcpStream>) -> Sender {
        let s = Sender { queue: Arc::default(), failed: Arc::default() };
        let t = s.clone();
        std::thread::spawn(move || {
            let mut b = Vec::new();
            loop {
                match t.queue.next(Duration::from_millis(500)) {
                    Next::Msg(m) => {
                        b.clear();
                        m.encode(&mut b);
                        if let Err(e) = w.send(&b) {
                            return t.fail(e);
                        }
                    }
                    Next::Idle => {}
                    Next::Closed => return,
                }
            }
        });
        s
    }

    /// Ends all sending with `e`, unless something failed before.
    fn fail(&self, e: Error) {
        self.failed.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert(e.to_string());
        self.queue.close();
    }

    /// Why sending ended, if it did.
    fn failure(&self) -> Option<String> {
        if self.queue.stalled() {
            return Some(crate::viewer::STALLED.into());
        }
        self.failed.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Queues a control message (never waits).
    fn send(&self, m: ClientMsg) -> Result<()> {
        if !self.queue.send(m) {
            bail!("{}", self.failure().unwrap_or_else(|| "connection closed".into()));
        }
        Ok(())
    }

    /// Sends `msgs` in order behind the control messages, from a thread of its own.
    fn send_bulk(&self, msgs: Vec<ClientMsg>) {
        let queue = self.queue.clone();
        std::thread::spawn(move || msgs.into_iter().all(|m| queue.send_bulk(m)));
    }

    /// Sends the files `uploads`, then a `FilePull` if `pull`, behind the control messages from
    /// a thread of its own, which it returns.
    fn upload(&self, uploads: Vec<Outgoing>, pull: bool) -> std::thread::JoinHandle<()> {
        let s = self.clone();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            for mut out in uploads {
                let id = out.id;
                if !s.queue.send_bulk(ClientMsg::FileBegin { id, size: out.size, name: out.name.clone() }) {
                    return;
                }
                loop {
                    match out.next_chunk(&mut buf) {
                        Ok(true) if s.queue.send_bulk(ClientMsg::FileData { id, data: buf.clone() }) => {}
                        Ok(true) => return,
                        Ok(false) => break,
                        Err(e) => return s.fail(e),
                    }
                }
                if !s.queue.send_bulk(ClientMsg::FileEnd { id, sha256: out.finish() }) {
                    return;
                }
            }
            if pull {
                s.queue.send_bulk(ClientMsg::FilePull);
            }
        })
    }
}

/// Ends the sending threads when the probe is done, however it ends.
struct StopSending(Arc<OutQueue>);

impl Drop for StopSending {
    fn drop(&mut self) {
        self.0.close();
    }
}

pub fn run(target: &str, o: ProbeOptions, psk: Secret<32>) -> Result<()> {
    let t_connect = Instant::now();
    let conn = connect(target, &o.viewer, &psk)?;
    drop(psk);
    println!("handshake:   {:.1} ms to {}", t_connect.elapsed().as_secs_f64() * 1000.0, conn.addr);
    // `connect` already made the host name printable and checked the screen size.
    println!("host:        {} ({}x{}), flags {:#x}, monitor {}", conn.host_name, conn.width, conn.height, conn.flags, conn.monitor);
    for (i, m) in conn.monitors.iter().enumerate() {
        println!("  monitor {}: {}x{} at ({}, {})", i + 1, m.width, m.height, m.left, m.top);
    }
    // A host left to pick the quality says which, unasked, if it is one that announces it
    // (older hosts do not): that `State` answers no `--set quality`.
    let announced = conn.flags & F_QUALITY_STATE != 0 && o.viewer.quality as u32 > QUALITY_LOW;
    // Records are read on their own thread with blocking reads (a timeout mid-record would
    // desynchronise the stream); the main loop polls the channel. A few records at most wait
    // in it: while the main loop is busy, the reader stops reading instead of buffering
    // whatever the host sends.
    let (tx, rx) = std::sync::mpsc::sync_channel::<Result<SecureVec>>(4);
    let mut reader = conn.reader;
    std::thread::spawn(move || {
        loop {
            let r = reader.recv().map(|b| SecureVec(b.to_vec()));
            let stop = r.is_err();
            if tx.send(r).is_err() || stop {
                break;
            }
        }
    });
    // Everything is sent from other threads, so the main loop never waits for the host to read
    // and keeps the reader going. A host whose sends to the probe wait (its writer is shared)
    // stops reading too, until an upload's result has gone out: uploads sent from the main loop
    // would then wait for the main loop to read, and the host for the uploads to stop.
    let sender = Sender::start(conn.writer);
    let _stop = StopSending(sender.queue.clone());
    let uploads = o.uploads.iter().enumerate().map(|(i, path)| Outgoing::open(std::path::Path::new(path), 1000 + i as u32));
    let uploads = uploads.collect::<Result<Vec<_>>>()?;

    let start = Instant::now();
    let (mut fw, mut fh) = (conn.width, conn.height);
    let mut fb = LockedBuf::new(fw * fh * 4);
    let mut dec = Decoder::new()?;
    let (mut frames, mut bytes, mut audio_packets) = (0u64, 0u64, 0u64);
    let mut first_frame: Option<f64> = None;
    let mut rtts: Vec<f64> = Vec::new();
    let mut next_ping = Instant::now();
    let mut failures = Vec::new();
    let mut baseline: Option<u64> = None;
    let mut changed_after_input = false;
    let mut input_sent = false;
    let mut states: Vec<(u8, u32)> = Vec::new();
    let mut download: Option<Incoming> = None;
    let mut pending_uploads = uploads.len();
    // The host says nothing when it has sent all it pulls: the pull is taken as answered once a
    // file or notice came after it and nothing more began for a second.
    let (mut pulled, mut pull_quiet): (usize, Option<Instant>) = (0, None);

    for &(key, value) in &o.sets {
        sender.send(ClientMsg::Set { key, value })?;
    }
    let uploading = sender.upload(uploads, o.pull);
    // Results are awaited for 10 s past the measurement, and past the end of the uploads.
    let mut results_due = start + Duration::from_secs_f64(o.seconds + 10.0);
    let mut uploaded = false;

    loop {
        if !uploaded && uploading.is_finished() {
            uploaded = true;
            results_due = results_due.max(Instant::now() + Duration::from_secs(10));
        }
        let pull_done = !o.pull || (download.is_none() && pull_quiet.is_some_and(|t| Instant::now() >= t));
        if start.elapsed().as_secs_f64() >= o.seconds && uploaded && ((pending_uploads == 0 && pull_done) || Instant::now() >= results_due) {
            break;
        }
        if let Some(e) = sender.failure() {
            bail!("{e}");
        }
        if Instant::now() >= next_ping {
            sender.send(ClientMsg::Ping(start.elapsed().as_micros() as u64))?;
            next_ping = Instant::now() + Duration::from_millis(500);
        }
        // Input is sent once the first frame established a baseline picture, in order and in
        // full (no move merged into the next), like file data behind pings and acks.
        if !input_sent && baseline.is_some() {
            input_sent = true;
            let mut input = Vec::new();
            for &(x, y) in &o.moves {
                input.push(ClientMsg::MouseMove { x, y });
            }
            for &(x, y) in &o.clicks {
                input.push(ClientMsg::MouseMove { x, y });
                input.push(ClientMsg::MouseButton { button: BTN_LEFT, down: true });
                input.push(ClientMsg::MouseButton { button: BTN_LEFT, down: false });
            }
            if let Some(t) = &o.type_text {
                input.extend(key_msgs(t)?);
            }
            sender.send_bulk(input);
        }
        let owned = match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(r) => r?,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => bail!("connection closed"),
        };
        let rec = &owned.0[..];
        bytes += rec.len() as u64 + 20;
        match ServerMsg::decode(rec)? {
            ServerMsg::Tiles(p) => {
                let hdr = codec::parse_header(p)?;
                if (hdr.width, hdr.height) != (fw, fh) {
                    check_screen_size(hdr.width, hdr.height)?;
                    (fw, fh) = (hdr.width, hdr.height);
                    // The old copy is wiped and freed before the new one is allocated.
                    drop(fb);
                    fb = LockedBuf::new(fw * fh * 4);
                    println!("resized:     {fw}x{fh}");
                }
                dec.apply(p, fb.as_mut_slice(), fw, fh)?;
                if hdr.last {
                    frames += 1;
                    first_frame.get_or_insert(start.elapsed().as_secs_f64() * 1000.0);
                    sender.send(ClientMsg::Ack(hdr.frame))?;
                    let sum = checksum(fb.as_slice());
                    match baseline {
                        None => baseline = Some(sum),
                        Some(b) if input_sent && b != sum => changed_after_input = true,
                        _ => {}
                    }
                }
            }
            ServerMsg::Pong(t) => rtts.push((start.elapsed().as_micros() as u64).saturating_sub(t) as f64 / 1000.0),
            ServerMsg::State { key, value } => {
                println!("state:       key {key} = {}", if value == STATE_UNAVAILABLE { "unavailable".into() } else { value.to_string() });
                states.push((key, value));
            }
            ServerMsg::Notice(t) => {
                println!("notice:      {}", printable(&t));
                // Such as why nothing (more) is sent.
                if o.pull && uploaded && download.is_none() {
                    pull_quiet = Some(Instant::now() + Duration::from_secs(1));
                }
            }
            ServerMsg::Audio { .. } => audio_packets += 1,
            ServerMsg::FileResult { id, ok, message } => {
                let message = printable(&message);
                println!("upload {id}:  {} {message}", if ok { "ok" } else { "FAILED" });
                if !ok {
                    failures.push(format!("upload {id} failed: {message}"));
                }
                pending_uploads = pending_uploads.saturating_sub(1);
            }
            ServerMsg::FileBegin { id, size, name } => {
                if let Some(d) = &download {
                    bail!("the host began file {id} while file {} was still arriving", d.id);
                }
                download = Some(Incoming::begin(&download_dir(&o)?, id, size, &name)?);
            }
            ServerMsg::FileData { id, data } => match download.as_mut() {
                Some(d) if d.id == id => {
                    d.write(data)?;
                    // A download that keeps arriving is waited for, however long it takes.
                    results_due = results_due.max(Instant::now() + Duration::from_secs(10));
                }
                _ => bail!("file data without a matching begin"),
            },
            ServerMsg::FileEnd { id, sha256 } => match download.take() {
                Some(d) if d.id == id => {
                    let name = printable(&d.name);
                    match d.finish(&sha256) {
                        Ok(path) => {
                            println!("download:    {}", printable(&path.display().to_string()));
                            pulled += 1;
                        }
                        Err(e) => {
                            println!("download:    {name} FAILED {e}");
                            failures.push(format!("download of {name} failed: {e}"));
                        }
                    }
                    pull_quiet = Some(Instant::now() + Duration::from_secs(1));
                }
                _ => bail!("file end without a matching begin"),
            },
            ServerMsg::Cursor(_) | ServerMsg::Clipboard(_) | ServerMsg::Ping | ServerMsg::Hello { .. } => {}
        }
    }

    let secs = start.elapsed().as_secs_f64();
    println!(
        "frames:      {frames} in {secs:.1} s ({:.1} fps), first after {:.0} ms",
        frames as f64 / secs,
        first_frame.unwrap_or(f64::NAN)
    );
    println!("traffic:     {:.2} MB ({:.2} Mbit/s)", bytes as f64 / 1e6, bytes as f64 * 8.0 / 1e6 / secs);
    if !rtts.is_empty() {
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().cloned().fold(0.0, f64::max);
        println!("rtt:         min {min:.1} / avg {avg:.1} / max {max:.1} ms ({} samples)", rtts.len());
    }
    if audio_packets > 0 {
        println!("audio:       {audio_packets} packets");
    }
    if frames == 0 {
        failures.push("no frames received".into());
    }
    for (key, missing) in unanswered(&o.sets, &states, (announced, o.viewer.audio, o.viewer.privacy)) {
        failures.push(format!("no State reply for {missing} --set of setting {key}"));
    }
    if pending_uploads > 0 {
        failures.push(format!("{pending_uploads} upload(s) without a result"));
    }
    // An unfinished download is deleted as it is dropped.
    if let Some(d) = download.take() {
        failures.push(format!("download of {} did not finish", printable(&d.name)));
    }
    if o.pull && pulled == 0 {
        failures.push("--pull: no file was received".into());
    }
    if o.expect_change {
        if changed_after_input {
            println!("input:       screen changed after input");
        } else {
            failures.push("screen did not change after input".into());
        }
    }
    if let Some(path) = &o.snapshot {
        write_ppm(path, fb.as_slice(), fw, fh)?;
        println!("snapshot:    {path} ({fw}x{fh})");
    }
    drop(fb);
    if !failures.is_empty() {
        for f in &failures {
            log!("probe: {f}");
        }
        bail!("{} check(s) failed", failures.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_map() {
        assert_eq!(scancode_for('a'), Some((0x1e, false)));
        assert_eq!(scancode_for('A'), Some((0x1e, true)));
        assert_eq!(scancode_for('!'), Some((0x02, true)));
        assert_eq!(scancode_for('/'), Some((0x35, false)));
        assert_eq!(scancode_for('~'), Some((0x29, true)));
        assert_eq!(scancode_for('\n'), Some((0x1c, false)));
        assert!(scancode_for('한').is_none());
        assert_eq!(key_msgs("Hi").unwrap().len(), 6);
    }

    #[test]
    fn every_setting_needs_its_own_reply() {
        let sets = [(SET_QUALITY, 0), (SET_QUALITY, 2), (SET_AUDIO, 1), (SET_DOWNSCALE, 2)];
        // All answered.
        let states = [(SET_QUALITY, 0), (SET_AUDIO, 1), (SET_QUALITY, 2), (SET_DOWNSCALE, 2)];
        assert!(unanswered(&sets, &states, (false, false, false)).is_empty());
        // One reply for two settings of a key; nothing at all for another.
        let states = [(SET_QUALITY, 2), (SET_AUDIO, 1)];
        assert_eq!(unanswered(&sets, &states, (false, false, false)), [(SET_QUALITY, 1), (SET_DOWNSCALE, 1)]);
        // The answer to the hello's sound wish answers no `--set audio`.
        let states = [(SET_QUALITY, 0), (SET_QUALITY, 2), (SET_AUDIO, 1), (SET_DOWNSCALE, 2)];
        assert_eq!(unanswered(&sets, &states, (false, true, false)), [(SET_AUDIO, 1)]);
        let states = [(SET_AUDIO, 1), (SET_QUALITY, 0), (SET_QUALITY, 2), (SET_AUDIO, 1), (SET_DOWNSCALE, 2), (SET_PRIVACY, 0)];
        assert!(unanswered(&sets, &states, (false, true, true)).is_empty());
        // Nor does a host's quality announcement answer a `--set quality`, wherever it comes; from a
        // host that makes none, the first `State` after the hello may well be the answer.
        let sets = [(SET_QUALITY, 0)];
        assert_eq!(unanswered(&sets, &[(SET_QUALITY, 1)], (true, false, false)), [(SET_QUALITY, 1)]);
        assert!(unanswered(&sets, &[(SET_QUALITY, 0), (SET_QUALITY, 1)], (true, false, false)).is_empty());
        assert!(unanswered(&sets, &[(SET_QUALITY, 0)], (false, false, false)).is_empty());
    }

    const KEY: [u8; 32] = [0x3c; 32];

    /// A host that keeps sending (sound, as fast as its socket takes it) while it reads uploads
    /// at `rate` bytes/s, answering each under the same writer lock, as the real host does.
    /// Returns the results it sent before the probe hung up.
    fn busy_host(l: std::net::TcpListener, rate: f64) -> usize {
        use crate::channel::{RecordReader, RecordWriter, server_handshake};
        let (mut s, _) = l.accept().unwrap();
        let keys = server_handshake(&mut s, &KEY).unwrap();
        let w = Arc::new(Mutex::new(RecordWriter::new(s.try_clone().unwrap(), keys.send)));
        let send = |w: &Mutex<RecordWriter<std::net::TcpStream>>, m: ServerMsg| {
            let mut b = Vec::new();
            m.encode(&mut b);
            w.lock().unwrap().send(&b)
        };
        let mut r = RecordReader::new(s, keys.recv);
        assert!(matches!(ClientMsg::decode(r.recv().unwrap()).unwrap(), ClientMsg::Hello { .. }));
        let hello = ServerMsg::Hello { width: 64, height: 64, flags: F_FILES | F_AUDIO, monitor: 0, monitors: vec![], name: "linux-host".into() };
        send(&w, hello).unwrap();
        let rects = codec::Encoder::new().unwrap().encode(&[0; 64 * 64 * 4], 64, 64);
        for m in codec::pack(1, 64, 64, &rects) {
            w.lock().unwrap().send(&m).unwrap();
        }
        let sound = {
            let w = w.clone();
            std::thread::spawn(move || {
                let data = [0u8; 16 * 1024];
                for seq in 0.. {
                    if send(&w, ServerMsg::Audio { seq, rate: 48000, channels: 2, codec: AUDIO_PCM16, data: &data }).is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        };
        let (t, mut read, mut results) = (Instant::now(), 0, 0);
        while let Ok(rec) = r.recv() {
            match ClientMsg::decode(rec).unwrap() {
                ClientMsg::FileData { data, .. } => {
                    read += data.len();
                    std::thread::sleep(Duration::from_secs_f64(read as f64 / rate).saturating_sub(t.elapsed()));
                }
                ClientMsg::FileEnd { id, .. } => {
                    send(&w, ServerMsg::FileResult { id, ok: true, message: "saved".into() }).unwrap();
                    results += 1;
                }
                _ => {}
            }
        }
        drop(r);
        sound.join().unwrap();
        results
    }

    #[test]
    fn uploads_keep_going_while_the_host_keeps_sending() {
        let mut r = [0u8; 8];
        crate::crypto::random(&mut r).unwrap();
        let dir = std::env::temp_dir().join(format!("srdp-probe-{}", crate::util::hex_encode(&r)));
        std::fs::create_dir_all(&dir).unwrap();
        let files: Vec<String> = [("a.bin", 4 << 20), ("b.bin", 6 << 20)]
            .iter()
            .map(|&(name, size)| {
                let path = dir.join(name);
                std::fs::write(&path, vec![0x5a; size]).unwrap();
                path.to_string_lossy().into_owned()
            })
            .collect();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let host = std::thread::spawn(move || busy_host(l, 16e6));
        let o = ProbeOptions { seconds: 0.2, uploads: files, ..ProbeOptions::default() };
        let t = Instant::now();
        let r = run(&addr.to_string(), o, Secret(KEY));
        let took = t.elapsed();
        let _ = std::fs::remove_dir_all(&dir);
        r.unwrap();
        assert!(took < Duration::from_secs(15), "the uploads took {took:?}");
        assert_eq!(host.join().unwrap(), 2);
    }

    /// A host that answers every `Set` with the value asked for (if `answer`), then sends its first
    /// frame, and pings all the while, so that it notices when the probe has gone. One with
    /// `F_QUALITY_STATE` announces the quality right after its hello, as such hosts do for a hello
    /// that leaves it to them; an older one does not, so the answer comes first.
    fn settings_host(l: std::net::TcpListener, flags: u32, answer: bool) {
        use crate::channel::{RecordReader, RecordWriter, server_handshake};
        let (mut s, _) = l.accept().unwrap();
        let keys = server_handshake(&mut s, &KEY).unwrap();
        let w = Arc::new(Mutex::new(RecordWriter::new(s.try_clone().unwrap(), keys.send)));
        let send = |w: &Mutex<RecordWriter<std::net::TcpStream>>, m: ServerMsg| {
            let mut b = Vec::new();
            m.encode(&mut b);
            w.lock().unwrap().send(&b)
        };
        let mut r = RecordReader::new(s, keys.recv);
        assert!(matches!(ClientMsg::decode(r.recv().unwrap()).unwrap(), ClientMsg::Hello { quality: QUALITY_DEFAULT, .. }));
        send(&w, ServerMsg::Hello { width: 64, height: 64, flags, monitor: 0, monitors: vec![], name: "linux-host".into() }).unwrap();
        if flags & F_QUALITY_STATE != 0 {
            send(&w, ServerMsg::State { key: SET_QUALITY, value: QUALITY_BALANCED }).unwrap();
        }
        let pinger = {
            let w = w.clone();
            std::thread::spawn(move || {
                while send(&w, ServerMsg::Ping).is_ok() {
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
        };
        let mut framed = false;
        while let Ok(rec) = r.recv() {
            if let ClientMsg::Set { key, value } = ClientMsg::decode(rec).unwrap() {
                if answer {
                    send(&w, ServerMsg::State { key, value }).unwrap();
                }
                if !std::mem::replace(&mut framed, true) {
                    let rects = codec::Encoder::new().unwrap().encode(&[0; 64 * 64 * 4], 64, 64);
                    for m in codec::pack(1, 64, 64, &rects) {
                        w.lock().unwrap().send(&m).unwrap();
                    }
                }
            }
        }
        drop(r);
        pinger.join().unwrap();
    }

    #[test]
    fn a_set_quality_is_answered_by_hosts_with_and_without_the_announcement() {
        let probe = |flags, answer| {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            let host = std::thread::spawn(move || settings_host(l, flags, answer));
            let o = ProbeOptions { seconds: 0.3, sets: vec![(SET_QUALITY, QUALITY_LOSSLESS)], ..ProbeOptions::default() };
            let r = run(&addr.to_string(), o, Secret(KEY));
            host.join().unwrap();
            r
        };
        // An older host's answer is the first record after its hello, and it counts.
        probe(F_FILES, true).unwrap();
        // A newer host's announcement comes first, and does not count.
        probe(F_FILES | F_QUALITY_STATE, true).unwrap();
        let e = probe(F_FILES | F_QUALITY_STATE, false).unwrap_err();
        assert_eq!(e.to_string(), "1 check(s) failed");
    }

    /// How `pull_host` answers a `FilePull`.
    #[derive(Clone, Copy)]
    enum Pull {
        /// A notice, and nothing else.
        Refuse,
        /// The file, slowly: it takes longer than the probe's `--seconds`.
        Slowly,
        /// A second file begun before the first one ended.
        Overlapping,
    }

    /// A host that sends its first frame, pings all the while and answers a `FilePull` with the
    /// file `src` as `how` says.
    fn pull_host(l: std::net::TcpListener, src: std::path::PathBuf, how: Pull) {
        use crate::channel::{RecordReader, RecordWriter, server_handshake};
        let (mut s, _) = l.accept().unwrap();
        let keys = server_handshake(&mut s, &KEY).unwrap();
        let w = Arc::new(Mutex::new(RecordWriter::new(s.try_clone().unwrap(), keys.send)));
        let send = |w: &Mutex<RecordWriter<std::net::TcpStream>>, m: ServerMsg| {
            let mut b = Vec::new();
            m.encode(&mut b);
            w.lock().unwrap().send(&b)
        };
        let mut r = RecordReader::new(s, keys.recv);
        assert!(matches!(ClientMsg::decode(r.recv().unwrap()).unwrap(), ClientMsg::Hello { .. }));
        send(&w, ServerMsg::Hello { width: 64, height: 64, flags: F_FILES, monitor: 0, monitors: vec![], name: "linux-host".into() }).unwrap();
        let rects = codec::Encoder::new().unwrap().encode(&[0; 64 * 64 * 4], 64, 64);
        for m in codec::pack(1, 64, 64, &rects) {
            w.lock().unwrap().send(&m).unwrap();
        }
        let pinger = {
            let w = w.clone();
            std::thread::spawn(move || {
                while send(&w, ServerMsg::Ping).is_ok() {
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
        };
        while let Ok(rec) = r.recv() {
            if !matches!(ClientMsg::decode(rec).unwrap(), ClientMsg::FilePull) {
                continue;
            }
            if let Pull::Refuse = how {
                send(&w, ServerMsg::Notice("file transfer is not allowed".into())).unwrap();
                continue;
            }
            let mut out = Outgoing::open(&src, 7).unwrap();
            send(&w, ServerMsg::FileBegin { id: 7, size: out.size, name: out.name.clone() }).unwrap();
            if let Pull::Overlapping = how {
                send(&w, ServerMsg::FileBegin { id: 8, size: out.size, name: out.name.clone() }).unwrap();
            }
            let mut buf = Vec::new();
            while out.next_chunk(&mut buf).unwrap() {
                std::thread::sleep(Duration::from_millis(300));
                if send(&w, ServerMsg::FileData { id: 7, data: &buf }).is_err() {
                    break;
                }
            }
            let _ = send(&w, ServerMsg::FileEnd { id: 7, sha256: out.finish() });
        }
        drop(r);
        pinger.join().unwrap();
    }

    #[test]
    fn pull_waits_for_the_download_and_fails_without_one() {
        let mut r = [0u8; 8];
        crate::crypto::random(&mut r).unwrap();
        let dir = std::env::temp_dir().join(format!("srdp-pull-{}", crate::util::hex_encode(&r)));
        let (src, into) = (dir.join("src"), dir.join("into"));
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&into).unwrap();
        let body: Vec<u8> = (0..crate::files::SEND_CHUNK * 3 + 100).map(|i| i as u8).collect();
        std::fs::write(src.join("copied.bin"), &body).unwrap();
        let probe = |how| {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            let file = src.join("copied.bin");
            let host = std::thread::spawn(move || pull_host(l, file, how));
            let o = ProbeOptions { seconds: 0.2, pull: true, pull_dir: Some(into.clone()), ..ProbeOptions::default() };
            let r = run(&addr.to_string(), o, Secret(KEY));
            host.join().unwrap();
            r
        };
        // Four chunks 300 ms apart: well past --seconds.
        let slow = probe(Pull::Slowly);
        let saved = std::fs::read(into.join("copied.bin"));
        let refused = probe(Pull::Refuse);
        let overlapping = probe(Pull::Overlapping);
        let left = std::fs::read_dir(&into).unwrap().count();
        let _ = std::fs::remove_dir_all(&dir);
        slow.unwrap();
        assert!(saved.unwrap() == body, "the pulled file differs");
        assert_eq!(refused.unwrap_err().to_string(), "1 check(s) failed");
        let e = overlapping.unwrap_err().to_string();
        assert!(e.contains("still arriving"), "{e}");
        assert_eq!(left, 1, "a partial download was left behind");
    }

    #[test]
    fn unrequested_files_are_refused() {
        // With --pull the directory is `files::transfer_dir()` (not created here: it is the
        // user's real Downloads folder).
        assert!(download_dir(&ProbeOptions::default()).is_err());
    }
}
