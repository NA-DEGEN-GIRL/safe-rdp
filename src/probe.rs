//! Headless test client: connects like a viewer, measures the session and can drive it.
//!
//! `safe-rdp probe <host> [--seconds N] [--type TEXT] [--move X,Y] [--click X,Y]
//!  [--set KEY=VALUE]... [--upload FILE]... [--pull] [--expect-change] [--snapshot FILE.ppm]`
//!
//! It prints the host's hello, frame/byte rates, round-trip times, setting confirmations and
//! file-transfer results, and exits non-zero if an expectation fails. `--snapshot` is the only
//! thing in safe-rdp that writes screen contents to disk, and only when explicitly asked.

use crate::codec::{self, Decoder};
use crate::files::{Incoming, Outgoing};
use crate::proto::*;
use crate::util::{Error, Result, Secret};
use crate::viewer::{ViewerOptions, connect};
use crate::{bail, log};
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

fn write_ppm(path: &str, fb: &[u8], w: usize, h: usize) -> Result<()> {
    let mut out = format!("P6\n{w} {h}\n255\n").into_bytes();
    out.reserve(w * h * 3);
    for p in fb.chunks_exact(4) {
        out.extend_from_slice(&[p[2], p[1], p[0]]);
    }
    std::fs::write(path, out)?;
    Ok(())
}

pub fn run(target: &str, o: ProbeOptions, psk: Secret<32>) -> Result<()> {
    let t_connect = Instant::now();
    let mut conn = connect(target, &o.viewer, &psk)?;
    drop(psk);
    println!("handshake:   {:.1} ms to {}", t_connect.elapsed().as_secs_f64() * 1000.0, conn.addr);
    println!("host:        {} ({}x{}), flags {:#x}, monitor {}", conn.host_name, conn.width, conn.height, conn.flags, conn.monitor);
    for (i, m) in conn.monitors.iter().enumerate() {
        println!("  monitor {}: {}x{} at ({}, {})", i + 1, m.width, m.height, m.left, m.top);
    }
    // Records are read on their own thread with blocking reads (a timeout mid-record would
    // desynchronise the stream); the main loop polls the channel.
    let (tx, rx) = std::sync::mpsc::channel::<Result<Vec<u8>>>();
    let mut reader = conn.reader;
    std::thread::spawn(move || {
        loop {
            let r = reader.recv().map(|b| b.to_vec());
            let stop = r.is_err();
            if tx.send(r).is_err() || stop {
                break;
            }
        }
    });

    let mut send = |w: &mut crate::channel::RecordWriter<std::net::TcpStream>, m: ClientMsg| -> Result<()> {
        let mut b = Vec::new();
        m.encode(&mut b);
        w.send(&b)
    };

    let start = Instant::now();
    let (mut fw, mut fh) = (conn.width, conn.height);
    let mut fb = vec![0u8; fw * fh * 4];
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
    let mut pending_uploads = o.uploads.len();

    for &(key, value) in &o.sets {
        send(&mut conn.writer, ClientMsg::Set { key, value })?;
    }
    for (i, path) in o.uploads.iter().enumerate() {
        let mut out = Outgoing::open(std::path::Path::new(path), 1000 + i as u32)?;
        send(&mut conn.writer, ClientMsg::FileBegin { id: out.id, size: out.size, name: out.name.clone() })?;
        let mut buf = Vec::new();
        while out.next_chunk(&mut buf)? {
            send(&mut conn.writer, ClientMsg::FileData { id: out.id, data: buf.clone() })?;
        }
        let id = out.id;
        send(&mut conn.writer, ClientMsg::FileEnd { id, sha256: out.finish() })?;
    }
    if o.pull {
        send(&mut conn.writer, ClientMsg::FilePull)?;
    }

    while start.elapsed().as_secs_f64() < o.seconds || (pending_uploads > 0 && start.elapsed().as_secs_f64() < o.seconds + 10.0) {
        if Instant::now() >= next_ping {
            send(&mut conn.writer, ClientMsg::Ping(start.elapsed().as_micros() as u64))?;
            next_ping = Instant::now() + Duration::from_millis(500);
        }
        // Input is sent once the first frame established a baseline picture.
        if !input_sent && baseline.is_some() {
            input_sent = true;
            for &(x, y) in &o.moves {
                send(&mut conn.writer, ClientMsg::MouseMove { x, y })?;
            }
            for &(x, y) in &o.clicks {
                send(&mut conn.writer, ClientMsg::MouseMove { x, y })?;
                send(&mut conn.writer, ClientMsg::MouseButton { button: BTN_LEFT, down: true })?;
                send(&mut conn.writer, ClientMsg::MouseButton { button: BTN_LEFT, down: false })?;
            }
            if let Some(t) = &o.type_text {
                for m in key_msgs(t)? {
                    send(&mut conn.writer, m)?;
                }
            }
        }
        let owned = match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(r) => r?,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => bail!("connection closed"),
        };
        let rec = &owned[..];
        bytes += rec.len() as u64 + 20;
        match ServerMsg::decode(rec)? {
            ServerMsg::Tiles(p) => {
                let hdr = codec::parse_header(p)?;
                if (hdr.width, hdr.height) != (fw, fh) {
                    (fw, fh) = (hdr.width, hdr.height);
                    fb = vec![0u8; fw * fh * 4];
                    println!("resized:     {fw}x{fh}");
                }
                dec.apply(p, &mut fb, fw, fh)?;
                if hdr.last {
                    frames += 1;
                    first_frame.get_or_insert(start.elapsed().as_secs_f64() * 1000.0);
                    send(&mut conn.writer, ClientMsg::Ack(hdr.frame))?;
                    let sum = checksum(&fb);
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
            ServerMsg::Notice(t) => println!("notice:      {t}"),
            ServerMsg::Audio { .. } => audio_packets += 1,
            ServerMsg::FileResult { id, ok, message } => {
                println!("upload {id}:  {} {message}", if ok { "ok" } else { "FAILED" });
                if !ok {
                    failures.push(format!("upload {id} failed: {message}"));
                }
                pending_uploads = pending_uploads.saturating_sub(1);
            }
            ServerMsg::FileBegin { id, size, name } => {
                let dir = std::env::temp_dir().join("safe-rdp-probe");
                std::fs::create_dir_all(&dir)?;
                download = Some(Incoming::begin(&dir, id, size, &name)?);
            }
            ServerMsg::FileData { id, data } => match download.as_mut() {
                Some(d) if d.id == id => d.write(data)?,
                _ => bail!("file data without a matching begin"),
            },
            ServerMsg::FileEnd { id, sha256 } => match download.take() {
                Some(d) if d.id == id => println!("download:    {}", d.finish(&sha256)?.display()),
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
    for &(key, _) in &o.sets {
        if !states.iter().any(|&(k, _)| k == key) {
            failures.push(format!("no State reply for setting {key}"));
        }
    }
    if pending_uploads > 0 {
        failures.push(format!("{pending_uploads} upload(s) without a result"));
    }
    if o.expect_change {
        if changed_after_input {
            println!("input:       screen changed after input");
        } else {
            failures.push("screen did not change after input".into());
        }
    }
    if let Some(path) = &o.snapshot {
        write_ppm(path, &fb, fw, fh)?;
        println!("snapshot:    {path} ({fw}x{fh})");
    }
    crate::util::wipe(&mut fb);
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
}
