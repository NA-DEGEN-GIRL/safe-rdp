//! Tile codec.
//!
//! The screen is split into 64x64 tiles; tiles that differ from the last frame sent are
//! grouped into horizontal runs. Exact runs are predicted from the left neighbour (PNG "Sub"
//! filter on BGR) and compressed with XPRESS+Huffman (`lz`); uniform runs are sent as a single
//! colour.
//!
//! Quality modes (`proto::QUALITY_*`): lossless sends every tile exactly. Balanced (the default)
//! and low classify each changed tile first: tiles with few distinct colours or that mostly
//! repeat their left neighbour (text, UI, flat areas) stay exact, busy tiles (photos, video) go
//! through the lossy coder in `lossy` at quality 80 or 50. The encoder remembers which tiles the
//! viewer only holds approximately, and `refine` re-sends them exactly once they have stayed
//! unchanged for 300 ms (balanced) or 1.5 s (low), so a still screen always converges to the
//! exact pixels. Change detection compares captured pixels, never decoded ones.
//!
//! Wire format (payload of an `S_TILES` message):
//! `frame:u32 | flags:u8 | width:u16 | height:u16 | count:u16 | rect*`
//! `rect = x:u16 | y:u16 | w:u16 | h:u16 | enc:u8 | len:u32 | data[len]`
//! `enc`: `ENC_SOLID` (`b g r`), `ENC_XPRESS` (compressed Sub-filtered BGR rows), `ENC_RAW`
//! (the same uncompressed) or `ENC_LOSSY` (see `lossy`).

use crate::bail;
use crate::platform::mem::LockedBuf;
use crate::proto::{QUALITY_BALANCED, QUALITY_LOSSLESS, QUALITY_LOW, Rd};
use crate::util::Result;
use lz::{Compressor, Decompressor};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub mod lossy;
pub mod lz;

pub const TILE: usize = 64;
pub const ENC_SOLID: u8 = 0;
pub const ENC_XPRESS: u8 = 1;
pub const ENC_RAW: u8 = 2;
pub const ENC_LOSSY: u8 = 3;
pub const FLAG_LAST: u8 = 1;
/// Split a frame into several messages once a message grows past this.
pub const CHUNK_BYTES: usize = 4 << 20;

/// Tiles with at most this many distinct colours count as text/UI and stay exact.
const FEW_COLORS: usize = 48;
/// Lossy quality and refinement delay of the balanced and low modes.
const BALANCED: (u8, Duration) = (80, Duration::from_millis(300));
const LOW: (u8, Duration) = (50, Duration::from_millis(1500));
/// Busy runs are cut after this many tiles so the workers share the load evenly.
const LOSSY_RUN_TILES: usize = 8;
/// Refinement runs stay short so `refine` can keep close to its byte budget.
const REFINE_RUN_TILES: usize = 4;
/// Jobs covering fewer pixels than this are encoded on the calling thread.
const PARALLEL_PIXELS: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rect {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
}

pub struct EncodedRect {
    pub rect: Rect,
    pub enc: u8,
    pub data: Vec<u8>,
}

impl EncodedRect {
    pub fn wire_len(&self) -> usize {
        13 + self.data.len()
    }
}

struct Worker {
    comp: Compressor,
    filtered: Vec<u8>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        crate::util::wipe(&mut self.filtered);
    }
}

/// One rectangle to encode: exactly, or lossy at the given quality.
#[derive(Clone, Copy)]
struct Job {
    rect: Rect,
    lossy: Option<u8>,
}

#[derive(Clone, Copy)]
struct TileState {
    /// The viewer holds a lossy approximation of this tile.
    lossy: bool,
    /// When the tile was last sent.
    sent: Instant,
}

pub struct Encoder {
    /// The captured pixels last sent for every tile (never the decoded lossy ones).
    prev: LockedBuf,
    width: usize,
    height: usize,
    force_full: bool,
    workers: Vec<Worker>,
    quality: u32,
    tiles: Vec<TileState>,
    lossy_tiles: usize,
}

fn sub_filter(src: &[u8], stride: usize, r: Rect, out: &mut Vec<u8>) {
    out.clear();
    out.reserve(r.w * r.h * 3);
    for row in r.y..r.y + r.h {
        let line = &src[(row * stride + r.x) * 4..(row * stride + r.x + r.w) * 4];
        let (mut lb, mut lg, mut lr) = (0u8, 0u8, 0u8);
        for px in line.chunks_exact(4) {
            out.push(px[0].wrapping_sub(lb));
            out.push(px[1].wrapping_sub(lg));
            out.push(px[2].wrapping_sub(lr));
            (lb, lg, lr) = (px[0], px[1], px[2]);
        }
    }
}

/// Undoes `sub_filter` into rectangle `r` of `fb` (`filtered` holds exactly `r.w * r.h * 3` bytes).
fn unfilter(filtered: &[u8], fb: &mut [u8], fbw: usize, r: Rect) {
    let mut src = filtered.chunks_exact(3);
    for row in r.y..r.y + r.h {
        let (mut lb, mut lg, mut lr) = (0u8, 0u8, 0u8);
        for (px, s) in fb[(row * fbw + r.x) * 4..(row * fbw + r.x + r.w) * 4].chunks_exact_mut(4).zip(&mut src) {
            lb = lb.wrapping_add(s[0]);
            lg = lg.wrapping_add(s[1]);
            lr = lr.wrapping_add(s[2]);
            px.copy_from_slice(&[lb, lg, lr, 255]);
        }
    }
}

fn solid_color(src: &[u8], stride: usize, r: Rect) -> Option<[u8; 3]> {
    let o = (r.y * stride + r.x) * 4;
    let first = [src[o], src[o + 1], src[o + 2]];
    for row in r.y..r.y + r.h {
        let line = &src[(row * stride + r.x) * 4..(row * stride + r.x + r.w) * 4];
        if !line.chunks_exact(4).all(|p| p[..3] == first) {
            return None;
        }
    }
    Some(first)
}

fn tile_differs(a: &[u8], b: &[u8], stride: usize, r: Rect) -> bool {
    (r.y..r.y + r.h).any(|row| {
        let o = (row * stride + r.x) * 4;
        a[o..o + r.w * 4] != b[o..o + r.w * 4]
    })
}

/// True for tiles worth sending lossy: more than `FEW_COLORS` distinct colours (unlike text and
/// UI) and at least half of the pixels differing from their left neighbour (unlike anti-aliased
/// text on flat backgrounds). Busy content stops the scan early.
fn is_busy(src: &[u8], stride: usize, r: Rect) -> bool {
    // Open-addressed set of the colours seen so far; the forced alpha byte keeps keys nonzero.
    let mut seen = [0u32; 128];
    let mut colors = 0;
    let (mut changes, limit) = (0, r.w * r.h / 2);
    for row in r.y..r.y + r.h {
        let line = &src[(row * stride + r.x) * 4..(row * stride + r.x + r.w) * 4];
        let mut left = 0;
        for px in line.chunks_exact(4) {
            let c = u32::from_le_bytes([px[0], px[1], px[2], 1]);
            if c == left {
                continue;
            }
            left = c;
            changes += 1;
            if colors <= FEW_COLORS {
                let mut h = (c.wrapping_mul(0x9e37_79b1) >> 25) as usize;
                while seen[h] != c {
                    if seen[h] == 0 {
                        seen[h] = c;
                        colors += 1;
                        break;
                    }
                    h = (h + 1) & 127;
                }
            }
            if colors > FEW_COLORS && changes > limit {
                return true;
            }
        }
    }
    false
}

fn encode_rect(w: &mut Worker, src: &[u8], stride: usize, job: Job) -> EncodedRect {
    let r = job.rect;
    if let Some(q) = job.lossy {
        let mut data = Vec::new();
        lossy::encode(src, stride, r, q, &mut data);
        return EncodedRect { rect: r, enc: ENC_LOSSY, data };
    }
    if let Some(c) = solid_color(src, stride, r) {
        return EncodedRect { rect: r, enc: ENC_SOLID, data: c.to_vec() };
    }
    sub_filter(src, stride, r, &mut w.filtered);
    let mut data = Vec::new();
    if w.comp.compress(&w.filtered, &mut data) {
        EncodedRect { rect: r, enc: ENC_XPRESS, data }
    } else {
        EncodedRect { rect: r, enc: ENC_RAW, data: w.filtered.clone() }
    }
}

/// Runs `f(worker, i)` for every `i < n` on up to `threads` workers (on the calling thread when
/// that is 1); the results come back in index order.
fn parallel<T: Send>(workers: &mut [Worker], threads: usize, n: usize, f: impl Fn(&mut Worker, usize) -> T + Sync) -> Vec<T> {
    let threads = threads.min(n).min(workers.len());
    if threads <= 1 {
        let wk = &mut workers[0];
        return (0..n).map(|i| f(wk, i)).collect();
    }
    let next = AtomicUsize::new(0);
    let mut out: Vec<(usize, T)> = std::thread::scope(|s| {
        let handles: Vec<_> = workers[..threads]
            .iter_mut()
            .map(|wk| {
                let (next, f) = (&next, &f);
                s.spawn(move || {
                    let mut mine = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= n {
                            break;
                        }
                        mine.push((i, f(wk, i)));
                    }
                    mine
                })
            })
            .collect();
        handles.into_iter().flat_map(|h| h.join().expect("encoder thread panicked")).collect()
    });
    out.sort_unstable_by_key(|e| e.0);
    out.into_iter().map(|(_, v)| v).collect()
}

impl Encoder {
    pub fn new() -> Result<Encoder> {
        let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(1, 8);
        let workers = (0..n)
            .map(|_| Ok(Worker { comp: Compressor::new()?, filtered: Vec::new() }))
            .collect::<Result<Vec<_>>>()?;
        Ok(Encoder {
            prev: LockedBuf::new(0),
            width: 0,
            height: 0,
            force_full: true,
            workers,
            quality: QUALITY_BALANCED,
            tiles: Vec::new(),
            lossy_tiles: 0,
        })
    }

    /// Selects lossless / balanced / low-bandwidth encoding (`proto::QUALITY_*`); other values
    /// are ignored (see `quality`). Tiles already sent lossy are refined under the new mode's
    /// delay, which is zero for lossless.
    pub fn set_quality(&mut self, quality: u32) {
        if matches!(quality, QUALITY_LOSSLESS | QUALITY_BALANCED | QUALITY_LOW) {
            self.quality = quality;
        }
    }

    /// The quality mode in effect (`proto::QUALITY_*`).
    #[cfg(test)]
    pub fn quality(&self) -> u32 {
        self.quality
    }

    /// Lossy quality (None: exact only) and refinement delay of the current mode.
    fn mode(&self) -> (Option<u8>, Duration) {
        match self.quality {
            QUALITY_BALANCED => (Some(BALANCED.0), BALANCED.1),
            QUALITY_LOW => (Some(LOW.0), LOW.1),
            _ => (None, Duration::ZERO),
        }
    }

    /// True while some regions were sent lossy and still await a lossless refinement.
    pub fn needs_refine(&self) -> bool {
        self.lossy_tiles > 0
    }

    /// Lossless re-sends of lossy regions that have stayed unchanged long enough, oldest first,
    /// limited to about `budget_bytes` on the wire (at least one run is sent, so refinement
    /// always progresses). Call with the current frame when nothing changed; tiles that differ
    /// from the last encoded frame are left to the next `encode`.
    pub fn refine(&mut self, cur: &[u8], w: usize, h: usize, budget_bytes: usize) -> Vec<EncodedRect> {
        self.refine_at(cur, w, h, budget_bytes, Instant::now())
    }

    pub fn request_full(&mut self) {
        self.force_full = true;
    }

    fn tiles_x(&self) -> usize {
        self.width.div_ceil(TILE)
    }

    fn tile_rect(&self, t: usize) -> Rect {
        let (x, y) = (t % self.tiles_x() * TILE, t / self.tiles_x() * TILE);
        Rect { x, y, w: TILE.min(self.width - x), h: TILE.min(self.height - y) }
    }

    /// Worker threads worth using for `rects`.
    fn threads_for(&self, rects: impl Iterator<Item = Rect>) -> usize {
        let (mut pixels, mut n) = (0, 0);
        for r in rects {
            pixels += r.w * r.h;
            n += 1;
        }
        if pixels < PARALLEL_PIXELS { 1 } else { self.workers.len().min(n) }
    }

    fn mark(&mut self, t: usize, lossy: bool, now: Instant) {
        let s = &mut self.tiles[t];
        match (s.lossy, lossy) {
            (false, true) => self.lossy_tiles += 1,
            (true, false) => self.lossy_tiles -= 1,
            _ => {}
        }
        *s = TileState { lossy, sent: now };
    }

    fn encode_jobs(&mut self, cur: &[u8], w: usize, jobs: &[Job]) -> Vec<EncodedRect> {
        let threads = self.threads_for(jobs.iter().map(|j| j.rect));
        parallel(&mut self.workers, threads, jobs.len(), |wk, i| encode_rect(wk, cur, w, jobs[i]))
    }

    /// Indices of the tiles of `cur` (BGRA, top-down, `w*h*4` bytes) that differ from the
    /// previous frame, in row-major order.
    fn changed_tiles(&self, cur: &[u8], full: bool) -> Vec<usize> {
        let prev = self.prev.as_slice();
        (0..self.tiles.len()).filter(|&t| full || tile_differs(cur, prev, self.width, self.tile_rect(t))).collect()
    }

    /// Encodes the regions of `cur` that changed since the last call.
    pub fn encode(&mut self, cur: &[u8], w: usize, h: usize) -> Vec<EncodedRect> {
        self.encode_at(cur, w, h, Instant::now())
    }

    fn encode_at(&mut self, cur: &[u8], w: usize, h: usize, now: Instant) -> Vec<EncodedRect> {
        assert_eq!(cur.len(), w * h * 4);
        if w != self.width || h != self.height {
            self.prev = LockedBuf::new(w * h * 4);
            self.width = w;
            self.height = h;
            self.force_full = true;
            self.tiles = vec![TileState { lossy: false, sent: now }; w.div_ceil(TILE) * h.div_ceil(TILE)];
            self.lossy_tiles = 0;
        }
        let full = std::mem::take(&mut self.force_full);
        let changed = self.changed_tiles(cur, full);
        if changed.is_empty() {
            return Vec::new();
        }

        let rects: Vec<Rect> = changed.iter().map(|&t| self.tile_rect(t)).collect();
        let (quality, _) = self.mode();
        let busy = if quality.is_some() {
            let threads = self.threads_for(rects.iter().copied());
            parallel(&mut self.workers, threads, rects.len(), |_, i| is_busy(cur, w, rects[i]))
        } else {
            vec![false; rects.len()]
        };

        // Horizontal runs of changed tiles of the same class.
        let mut jobs: Vec<Job> = Vec::new();
        let mut run_tiles = 0;
        for (i, (&t, &b)) in changed.iter().zip(&busy).enumerate() {
            self.mark(t, b, now);
            let (r, lossy) = (rects[i], if b { quality } else { None });
            let cap = if b { LOSSY_RUN_TILES } else { usize::MAX };
            match jobs.last_mut() {
                Some(j) if changed[i - 1] + 1 == t && r.x != 0 && j.lossy == lossy && run_tiles < cap => {
                    j.rect.w += r.w;
                    run_tiles += 1;
                }
                _ => {
                    jobs.push(Job { rect: r, lossy });
                    run_tiles = 1;
                }
            }
        }
        let out = self.encode_jobs(cur, w, &jobs);

        let prev = self.prev.as_mut_slice();
        for r in jobs.iter().map(|j| j.rect) {
            for row in r.y..r.y + r.h {
                let a = (row * w + r.x) * 4;
                prev[a..a + r.w * 4].copy_from_slice(&cur[a..a + r.w * 4]);
            }
        }
        out
    }

    fn refine_at(&mut self, cur: &[u8], w: usize, h: usize, budget_bytes: usize, now: Instant) -> Vec<EncodedRect> {
        if self.lossy_tiles == 0 || w != self.width || h != self.height || cur.len() != w * h * 4 {
            return Vec::new();
        }
        let (_, settle) = self.mode();
        let prev = self.prev.as_slice();
        // Runs of settled lossy tiles sent together, as (send time, first tile, tile count).
        let mut runs: Vec<(Instant, usize, usize)> = Vec::new();
        for (t, s) in self.tiles.iter().enumerate() {
            if !s.lossy || now.saturating_duration_since(s.sent) < settle || tile_differs(cur, prev, w, self.tile_rect(t)) {
                continue;
            }
            match runs.last_mut() {
                Some((sent, first, n)) if *first + *n == t && t % self.tiles_x() != 0 && *sent == s.sent && *n < REFINE_RUN_TILES => {
                    *n += 1;
                }
                _ => runs.push((s.sent, t, 1)),
            }
        }
        runs.sort_by_key(|&(sent, first, _)| (sent, first));
        let jobs: Vec<Job> = runs
            .iter()
            .map(|&(_, first, n)| {
                let (a, b) = (self.tile_rect(first), self.tile_rect(first + n - 1));
                Job { rect: Rect { w: b.x + b.w - a.x, ..a }, lossy: None }
            })
            .collect();

        let (mut out, mut total) = (Vec::new(), 0);
        for batch in jobs.chunks(self.workers.len()) {
            for (job, e) in batch.iter().zip(self.encode_jobs(cur, w, batch)) {
                if !out.is_empty() && total + e.wire_len() > budget_bytes {
                    return out;
                }
                total += e.wire_len();
                let first = job.rect.y / TILE * self.tiles_x() + job.rect.x / TILE;
                for t in first..first + job.rect.w.div_ceil(TILE) {
                    self.mark(t, false, now);
                }
                out.push(e);
            }
        }
        out
    }
}

/// Box-filters `src` (BGRA, `w*h`) down by `d` into `dst` (`(w/d)*(h/d)*4` bytes).
pub fn downscale(src: &[u8], w: usize, h: usize, d: usize, dst: &mut [u8]) {
    let (dw, dh) = (w / d, h / d);
    assert_eq!(dst.len(), dw * dh * 4);
    let n = (d * d) as u32;
    for (y, out_row) in dst.chunks_exact_mut(dw * 4).enumerate() {
        let mut acc = vec![[0u32; 3]; dw];
        for sy in y * d..y * d + d {
            let row = &src[sy * w * 4..(sy * w + dw * d) * 4];
            for (x, a) in acc.iter_mut().enumerate() {
                for px in row[x * d * 4..(x + 1) * d * 4].chunks_exact(4) {
                    a[0] += px[0] as u32;
                    a[1] += px[1] as u32;
                    a[2] += px[2] as u32;
                }
            }
        }
        for (px, a) in out_row.chunks_exact_mut(4).zip(&acc) {
            px.copy_from_slice(&[((a[0] + n / 2) / n) as u8, ((a[1] + n / 2) / n) as u8, ((a[2] + n / 2) / n) as u8, 255]);
        }
    }
}

/// Packs encoded rects into one or more complete `S_TILES` messages (type byte included).
pub fn pack(frame: u32, width: usize, height: usize, rects: &[EncodedRect]) -> Vec<Vec<u8>> {
    let mut msgs = Vec::new();
    let mut i = 0;
    loop {
        let mut cur = Vec::with_capacity(64);
        cur.push(crate::proto::S_TILES);
        cur.extend_from_slice(&frame.to_le_bytes());
        cur.push(0);
        cur.extend_from_slice(&(width as u16).to_le_bytes());
        cur.extend_from_slice(&(height as u16).to_le_bytes());
        cur.extend_from_slice(&[0, 0]);
        let mut count = 0u16;
        while i < rects.len() && count < u16::MAX && (count == 0 || cur.len() + rects[i].wire_len() <= CHUNK_BYTES) {
            let e = &rects[i];
            for v in [e.rect.x, e.rect.y, e.rect.w, e.rect.h] {
                cur.extend_from_slice(&(v as u16).to_le_bytes());
            }
            cur.push(e.enc);
            cur.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
            cur.extend_from_slice(&e.data);
            count += 1;
            i += 1;
        }
        cur[10..12].copy_from_slice(&count.to_le_bytes());
        let last = i >= rects.len();
        if last {
            cur[5] = FLAG_LAST;
        }
        msgs.push(cur);
        if last {
            return msgs;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TilesHeader {
    pub frame: u32,
    pub last: bool,
    pub width: usize,
    pub height: usize,
}

pub fn parse_header(payload: &[u8]) -> Result<TilesHeader> {
    let mut r = Rd(payload);
    let frame = r.u32()?;
    let flags = r.u8()?;
    let width = r.u16()? as usize;
    let height = r.u16()? as usize;
    if width == 0 || height == 0 {
        bail!("empty frame size");
    }
    Ok(TilesHeader { frame, last: flags & FLAG_LAST != 0, width, height })
}

pub struct Decoder {
    decomp: Decompressor,
    scratch: Vec<u8>,
}

impl Drop for Decoder {
    fn drop(&mut self) {
        crate::util::wipe(&mut self.scratch);
    }
}

impl Decoder {
    pub fn new() -> Result<Decoder> {
        Ok(Decoder { decomp: Decompressor::new()?, scratch: Vec::new() })
    }

    /// Applies the rects in `payload` to `fb` (BGRA, `fbw*fbh*4`); returns the dirty bounding box.
    pub fn apply(&mut self, payload: &[u8], fb: &mut [u8], fbw: usize, fbh: usize) -> Result<Option<Rect>> {
        assert_eq!(fb.len(), fbw * fbh * 4);
        let mut r = Rd(payload);
        r.bytes(9)?;
        let count = r.u16()?;
        let mut bbox: Option<Rect> = None;
        for _ in 0..count {
            let (x, y, w, h) = (r.u16()? as usize, r.u16()? as usize, r.u16()? as usize, r.u16()? as usize);
            let enc = r.u8()?;
            let len = r.u32()? as usize;
            let data = r.bytes(len)?;
            if w == 0 || h == 0 || x + w > fbw || y + h > fbh {
                bail!("tile out of bounds");
            }
            let nr = Rect { x, y, w, h };
            match enc {
                ENC_SOLID => {
                    if data.len() != 3 {
                        bail!("bad solid tile");
                    }
                    for row in y..y + h {
                        for px in fb[(row * fbw + x) * 4..(row * fbw + x + w) * 4].chunks_exact_mut(4) {
                            px.copy_from_slice(&[data[0], data[1], data[2], 255]);
                        }
                    }
                }
                ENC_RAW => {
                    if data.len() != w * h * 3 {
                        bail!("bad raw tile");
                    }
                    unfilter(data, fb, fbw, nr);
                }
                ENC_XPRESS => {
                    self.scratch.resize(w * h * 3, 0);
                    self.decomp.decompress(data, &mut self.scratch)?;
                    unfilter(&self.scratch, fb, fbw, nr);
                }
                ENC_LOSSY => lossy::decode(data, fb, fbw, nr)?,
                _ => bail!("unknown tile encoding {enc}"),
            }
            bbox = Some(match bbox {
                None => nr,
                Some(b) => {
                    let (x0, y0) = (b.x.min(x), b.y.min(y));
                    let (x1, y1) = ((b.x + b.w).max(x + w), (b.y + b.h).max(y + h));
                    Rect { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }
                }
            });
        }
        r.end()?;
        Ok(bbox)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lossy::tests::{photo, psnr};

    fn frame(w: usize, h: usize, seed: u32) -> Vec<u8> {
        let mut v = vec![0u8; w * h * 4];
        let mut s = seed;
        for (i, px) in v.chunks_exact_mut(4).enumerate() {
            let (x, y) = (i % w, i / w);
            // Mix of flat areas, gradients and noise, like a real desktop.
            let c = if y < h / 3 {
                [40, 40, 40]
            } else if y < 2 * h / 3 {
                [(x % 256) as u8, (y % 256) as u8, 128]
            } else {
                s = s.wrapping_mul(1664525).wrapping_add(1013904223);
                [(s >> 24) as u8, (s >> 16) as u8, (s >> 8) as u8]
            };
            px.copy_from_slice(&[c[0], c[1], c[2], 255]);
        }
        v
    }

    /// Text-like BGRA content: dark glyph strokes with a few anti-aliasing greys on white.
    fn text(w: usize, h: usize, seed: u32) -> Vec<u8> {
        let mut v = vec![255u8; w * h * 4];
        for (i, px) in v.chunks_exact_mut(4).enumerate() {
            let (x, y) = (i % w, i / w);
            let (line, col) = (y % 16, x % 7);
            let glyph = (x / 7 * 31 + y / 16 * 17 + seed as usize) % 5;
            let ink = (2..12).contains(&line) && (col == glyph || (glyph == 0 && line == 6) || (glyph == 3 && line == 11));
            let edge = (2..12).contains(&line) && (col == glyph + 1);
            let g = if ink { 30 } else if edge { 140 + (line as u8 & 3) * 20 } else { 255 };
            px.copy_from_slice(&[g, g, g, 255]);
        }
        v
    }

    /// Copies a `w`x`h` BGRA image into `dst` (stride `dw`) at (`x`, `y`).
    fn blit(dst: &mut [u8], dw: usize, src: &[u8], w: usize, x: usize, y: usize) {
        for (row, line) in src.chunks_exact(w * 4).enumerate() {
            let o = ((y + row) * dw + x) * 4;
            dst[o..o + w * 4].copy_from_slice(line);
        }
    }

    fn apply(dec: &mut Decoder, fb: &mut [u8], w: usize, h: usize, id: u32, rects: &[EncodedRect]) {
        for m in pack(id, w, h, rects) {
            dec.apply(&m[1..], fb, w, h).unwrap();
        }
    }

    fn lossless() -> Encoder {
        let mut enc = Encoder::new().unwrap();
        enc.set_quality(QUALITY_LOSSLESS);
        enc
    }

    fn roundtrip(enc: &mut Encoder, dec: &mut Decoder, fb: &mut [u8], cur: &[u8], w: usize, h: usize, id: u32) -> usize {
        let rects = enc.encode(cur, w, h);
        let msgs = pack(id, w, h, &rects);
        for (i, m) in msgs.iter().enumerate() {
            let hdr = parse_header(&m[1..]).unwrap();
            assert_eq!((hdr.frame, hdr.width, hdr.height), (id, w, h));
            assert_eq!(hdr.last, i == msgs.len() - 1);
            dec.apply(&m[1..], fb, w, h).unwrap();
        }
        assert!(fb == cur, "decoded frame differs");
        rects.len()
    }

    #[test]
    fn lossless_roundtrip_and_diffs() {
        let (w, h) = (333, 250); // not a multiple of the tile size
        let mut enc = lossless();
        let mut dec = Decoder::new().unwrap();
        let mut fb = vec![0u8; w * h * 4];
        let f1 = frame(w, h, 1);
        assert!(roundtrip(&mut enc, &mut dec, &mut fb, &f1, w, h, 1) > 0);
        // Unchanged frame encodes to nothing.
        assert!(enc.encode(&f1, w, h).is_empty());
        // A single changed pixel produces exactly one tile.
        let mut f2 = f1.clone();
        f2[(200 * w + 300) * 4] ^= 0xff;
        let rects = enc.encode(&f2, w, h);
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0].rect, Rect { x: 256, y: 192, w: 64, h: 58 });
        let msgs = pack(2, w, h, &rects);
        dec.apply(&msgs[0][1..], &mut fb, w, h).unwrap();
        assert!(fb == f2);
        // Full refresh re-sends everything, as one run per tile row.
        enc.request_full();
        assert_eq!(roundtrip(&mut enc, &mut dec, &mut fb, &f2, w, h, 3), 4);
    }

    #[test]
    fn large_frame_is_chunked() {
        let (w, h) = (1920, 1080);
        let mut enc = lossless();
        let mut dec = Decoder::new().unwrap();
        let mut fb = vec![0u8; w * h * 4];
        let mut s = 7u32;
        let f: Vec<u8> = (0..w * h * 4)
            .map(|_| {
                s = s.wrapping_mul(1664525).wrapping_add(1013904223);
                (s >> 24) as u8
            })
            .collect();
        let mut expect = f.clone();
        expect.chunks_exact_mut(4).for_each(|p| p[3] = 255);
        let rects = enc.encode(&f, w, h);
        let msgs = pack(1, w, h, &rects);
        assert!(msgs.len() > 1, "incompressible frame should span several chunks");
        for m in &msgs {
            assert!(m.len() <= CHUNK_BYTES + w * TILE * 3 + 64);
            dec.apply(&m[1..], &mut fb, w, h).unwrap();
        }
        assert!(fb == expect);
    }

    #[test]
    fn downscale_box_filter() {
        // 5x2 -> 2x1 with d=2 (odd column dropped)
        let px = |v: u8| [v, v, v, 0];
        let src: Vec<u8> = [10, 20, 30, 40, 99, 30, 40, 50, 60, 99].iter().flat_map(|&v| px(v)).collect();
        let mut dst = vec![0u8; 2 * 4];
        downscale(&src, 5, 2, 2, &mut dst);
        assert_eq!(dst, [25, 25, 25, 255, 45, 45, 45, 255]);
    }

    #[test]
    fn decoder_rejects_bad_input() {
        let mut dec = Decoder::new().unwrap();
        let mut fb = vec![0u8; 16 * 16 * 4];
        let r = EncodedRect { rect: Rect { x: 10, y: 10, w: 10, h: 10 }, enc: ENC_SOLID, data: vec![1, 2, 3] };
        assert!(dec.apply(&pack(1, 16, 16, &[r])[0][1..], &mut fb, 16, 16).is_err());
        let r = EncodedRect { rect: Rect { x: 0, y: 0, w: 4, h: 4 }, enc: ENC_XPRESS, data: vec![9; 20] };
        assert!(dec.apply(&pack(1, 16, 16, &[r])[0][1..], &mut fb, 16, 16).is_err());
        let r = EncodedRect { rect: Rect { x: 0, y: 0, w: 4, h: 4 }, enc: ENC_RAW, data: vec![9; 47] };
        assert!(dec.apply(&pack(1, 16, 16, &[r])[0][1..], &mut fb, 16, 16).is_err());
        let r = EncodedRect { rect: Rect { x: 0, y: 0, w: 4, h: 4 }, enc: ENC_LOSSY, data: vec![80, 0] };
        assert!(dec.apply(&pack(1, 16, 16, &[r])[0][1..], &mut fb, 16, 16).is_err());
        let r = EncodedRect { rect: Rect { x: 0, y: 0, w: 4, h: 4 }, enc: 4, data: vec![] };
        assert!(dec.apply(&pack(1, 16, 16, &[r])[0][1..], &mut fb, 16, 16).is_err());
        assert!(dec.apply(&[0; 5], &mut fb, 16, 16).is_err());
    }

    #[test]
    fn classifier_separates_photos_from_text() {
        let full = Rect { x: 0, y: 0, w: 64, h: 64 };
        assert!(is_busy(&photo(64, 64, 1), 64, full));
        assert!(!is_busy(&text(64, 64, 1), 64, full));
        assert!(!is_busy(&vec![7u8; 64 * 64 * 4], 64, full));
        // Smooth anti-aliasing with many greys on a flat background still counts as text.
        let mut aa = vec![255u8; 64 * 64 * 4];
        for (i, px) in aa.chunks_exact_mut(4).enumerate().filter(|(i, _)| i % 64 % 8 == 0) {
            let g = (i * 7 % 200) as u8;
            px.copy_from_slice(&[g, g, g.wrapping_add(1), 255]);
        }
        assert!(!is_busy(&aa, 64, full));
        // Random noise with only a few colours is text-like too (palette content).
        let mut s = 3u32;
        let pal: Vec<u8> = (0..64 * 64)
            .flat_map(|_| {
                s = s.wrapping_mul(1664525).wrapping_add(1013904223);
                let c = (s >> 28) as u8 * 16;
                [c, c, c, 255]
            })
            .collect();
        assert!(!is_busy(&pal, 64, full));
        // Edge tiles of any size work.
        assert!(!is_busy(&photo(1, 1, 1), 1, Rect { x: 0, y: 0, w: 1, h: 1 }));
        assert!(is_busy(&photo(20, 64, 1), 20, Rect { x: 0, y: 0, w: 20, h: 64 }));
    }

    /// 256x128: photo-like tiles at x < 128, text-like tiles at x >= 128.
    fn mixed(seed: u32) -> (Vec<u8>, usize, usize) {
        let (w, h) = (256, 128);
        let mut f = text(w, h, seed);
        blit(&mut f, w, &photo(128, h, seed), 128, 0, 0);
        (f, w, h)
    }

    #[test]
    fn balanced_sends_busy_tiles_lossy_then_refines_to_exact() {
        let (f, w, h) = mixed(1);
        let mut enc = Encoder::new().unwrap();
        assert_eq!(enc.quality(), QUALITY_BALANCED);
        let mut dec = Decoder::new().unwrap();
        let mut fb = vec![0u8; w * h * 4];
        let t0 = Instant::now();
        let rects = enc.encode_at(&f, w, h, t0);
        assert!(rects.iter().any(|r| r.enc == ENC_LOSSY));
        for r in &rects {
            if r.rect.x < 128 {
                assert_eq!((r.enc, r.data[0]), (ENC_LOSSY, BALANCED.0), "busy {:?}", r.rect);
                assert!(r.rect.x + r.rect.w <= 128);
            } else {
                assert_ne!(r.enc, ENC_LOSSY, "text {:?}", r.rect);
            }
        }
        apply(&mut dec, &mut fb, w, h, 1, &rects);
        let text_area = Rect { x: 128, y: 0, w: 128, h };
        assert_eq!(psnr(&f, &fb, w, text_area), f64::INFINITY);
        assert!(psnr(&f, &fb, w, Rect { x: 0, y: 0, w: 128, h }) >= 34.0);
        assert!(enc.needs_refine());

        // Change detection compares captured pixels, so an unchanged screen sends nothing.
        assert!(enc.encode_at(&f, w, h, t0 + Duration::from_millis(100)).is_empty());
        // Nothing is refined before the region has settled for 300 ms.
        assert!(enc.refine_at(&f, w, h, usize::MAX, t0 + Duration::from_millis(299)).is_empty());
        let rects = enc.refine_at(&f, w, h, usize::MAX, t0 + Duration::from_millis(300));
        assert!(!rects.is_empty() && rects.iter().all(|r| r.enc != ENC_LOSSY && r.rect.x + r.rect.w <= 128));
        apply(&mut dec, &mut fb, w, h, 2, &rects);
        assert!(fb == f, "refined frame differs");
        assert!(!enc.needs_refine());
        assert!(enc.refine_at(&f, w, h, usize::MAX, t0 + Duration::from_secs(5)).is_empty());
        assert!(enc.encode_at(&f, w, h, t0 + Duration::from_secs(5)).is_empty());
    }

    #[test]
    fn changed_tiles_are_reclassified() {
        let (f, w, h) = mixed(2);
        let mut enc = Encoder::new().unwrap();
        let t0 = Instant::now();
        enc.encode_at(&f, w, h, t0);
        let lossy_before = enc.lossy_tiles;
        assert_eq!(lossy_before, 4);

        // A busy tile turns into text and a text tile into a photo.
        let mut g = f.clone();
        blit(&mut g, w, &text(64, 64, 9), 64, 0, 0);
        blit(&mut g, w, &photo(64, 64, 9), 64, 192, 64);
        let t1 = t0 + Duration::from_millis(200);
        let rects = enc.encode_at(&g, w, h, t1);
        let kinds: Vec<(usize, usize, bool)> = rects.iter().map(|r| (r.rect.x, r.rect.y, r.enc == ENC_LOSSY)).collect();
        assert_eq!(kinds, [(0, 0, false), (192, 64, true)]);
        assert_eq!(enc.lossy_tiles, lossy_before);

        // At t0 + 300 ms only the three tiles sent at t0 have settled; the new one waits.
        let rects = enc.refine_at(&g, w, h, usize::MAX, t0 + Duration::from_millis(300));
        let area: usize = rects.iter().map(|r| r.rect.w * r.rect.h).sum();
        assert_eq!(area, 3 * TILE * TILE);
        assert!(enc.needs_refine());
        // A frame that changed since the last encode is not refined from stale state.
        let mut moved = g.clone();
        moved[(70 * w + 200) * 4] ^= 0x40;
        assert!(enc.refine_at(&moved, w, h, usize::MAX, t1 + Duration::from_secs(1)).is_empty());
        assert_eq!(enc.refine_at(&g, w, h, usize::MAX, t1 + Duration::from_millis(300)).len(), 1);
        assert!(!enc.needs_refine());
    }

    #[test]
    fn refinement_respects_budget_oldest_first() {
        let (w, h) = (640, 384);
        let f = photo(w, h, 4);
        let mut enc = Encoder::new().unwrap();
        let mut dec = Decoder::new().unwrap();
        let mut fb = vec![0u8; w * h * 4];
        let t0 = Instant::now();
        let rects = enc.encode_at(&f, w, h, t0);
        assert!(rects.iter().all(|r| r.enc == ENC_LOSSY));
        apply(&mut dec, &mut fb, w, h, 1, &rects);
        assert_eq!(enc.lossy_tiles, 60);

        // The bottom-right tile changes later; it must be refined last.
        let mut g = f.clone();
        blit(&mut g, w, &photo(64, 64, 77), 64, 576, 320);
        let rects = enc.encode_at(&g, w, h, t0 + Duration::from_millis(100));
        apply(&mut dec, &mut fb, w, h, 2, &rects);

        let budget = 40_000;
        let now = t0 + Duration::from_secs(2);
        let mut calls = 0;
        let mut last_rect = None;
        loop {
            let rects = enc.refine_at(&g, w, h, budget, now);
            if rects.is_empty() {
                break;
            }
            let total: usize = rects.iter().map(EncodedRect::wire_len).sum();
            assert!(total <= budget || rects.len() == 1, "{total} bytes in {} rects", rects.len());
            last_rect = rects.last().map(|r| r.rect);
            apply(&mut dec, &mut fb, w, h, 3 + calls, &rects);
            calls += 1;
            assert!(calls < 100);
        }
        assert!(calls > 1, "budget should spread refinement over several calls");
        assert_eq!(last_rect, Some(Rect { x: 576, y: 320, w: 64, h: 64 }));
        assert!(fb == g, "refined frame differs");
        assert!(!enc.needs_refine());

        // A zero budget still makes progress, one run per call.
        enc.request_full();
        enc.encode_at(&g, w, h, now);
        let rects = enc.refine_at(&g, w, h, 0, now + Duration::from_secs(1));
        assert_eq!(rects.len(), 1);
        assert!(rects[0].rect.w <= REFINE_RUN_TILES * TILE);
    }

    #[test]
    fn low_mode_uses_lower_quality_and_waits_longer() {
        let (f, w, h) = mixed(3);
        let mut enc = Encoder::new().unwrap();
        enc.set_quality(QUALITY_LOW);
        assert_eq!(enc.quality(), QUALITY_LOW);
        let t0 = Instant::now();
        let rects = enc.encode_at(&f, w, h, t0);
        let lossy: Vec<_> = rects.iter().filter(|r| r.enc == ENC_LOSSY).collect();
        assert!(!lossy.is_empty() && lossy.iter().all(|r| r.data[0] == LOW.0));
        assert!(enc.refine_at(&f, w, h, usize::MAX, t0 + Duration::from_millis(300)).is_empty());
        assert!(enc.refine_at(&f, w, h, usize::MAX, t0 + Duration::from_millis(1499)).is_empty());
        assert!(!enc.refine_at(&f, w, h, usize::MAX, t0 + Duration::from_millis(1500)).is_empty());
        assert!(!enc.needs_refine());

        // Low quality spends fewer bytes on the same busy content than balanced.
        let bytes = |q: u32| {
            let mut e = Encoder::new().unwrap();
            e.set_quality(q);
            e.encode(&f, w, h).iter().filter(|r| r.enc == ENC_LOSSY).map(|r| r.data.len()).sum::<usize>()
        };
        assert!(bytes(QUALITY_LOW) < bytes(QUALITY_BALANCED));
    }

    #[test]
    fn lossless_mode_never_sends_lossy() {
        let (w, h) = (640, 384);
        let f = photo(w, h, 5);
        let mut enc = lossless();
        let mut dec = Decoder::new().unwrap();
        let mut fb = vec![0u8; w * h * 4];
        let rects = enc.encode(&f, w, h);
        assert!(rects.iter().all(|r| r.enc != ENC_LOSSY));
        assert_eq!(rects.len(), 6); // one run per tile row, as before quality modes existed
        apply(&mut dec, &mut fb, w, h, 1, &rects);
        assert!(fb == f);
        assert!(!enc.needs_refine());
        enc.set_quality(99); // unknown values are ignored
        assert_eq!(enc.quality(), QUALITY_LOSSLESS);

        // Switching to lossless refines what was sent lossy without waiting.
        let mut enc = Encoder::new().unwrap();
        let t0 = Instant::now();
        apply(&mut dec, &mut fb, w, h, 2, &enc.encode_at(&f, w, h, t0));
        assert!(enc.needs_refine());
        enc.set_quality(QUALITY_LOSSLESS);
        let rects = enc.refine_at(&f, w, h, usize::MAX, t0);
        assert!(rects.iter().all(|r| r.enc != ENC_LOSSY));
        apply(&mut dec, &mut fb, w, h, 3, &rects);
        assert!(fb == f && !enc.needs_refine());
        // A size change drops all refinement state.
        let mut enc = Encoder::new().unwrap();
        enc.encode_at(&f, w, h, t0);
        let small = photo(64, 64, 1);
        enc.encode_at(&small, 64, 64, t0);
        assert_eq!(enc.lossy_tiles, 1);
        assert!(enc.refine_at(&f, w, h, usize::MAX, t0 + Duration::from_secs(9)).is_empty());
    }

    #[test]
    #[ignore]
    fn timing_1080p_photo() {
        let (w, h) = (1920, 1080);
        let f = photo(w, h, 21);
        let mut dec = Decoder::new().unwrap();
        let mut fb = vec![0u8; w * h * 4];
        for (name, q) in [("balanced", QUALITY_BALANCED), ("low", QUALITY_LOW), ("lossless", QUALITY_LOSSLESS)] {
            let mut enc = Encoder::new().unwrap();
            enc.set_quality(q);
            let mut best = f64::MAX;
            let mut rects = Vec::new();
            for _ in 0..5 {
                enc.request_full();
                let t = Instant::now();
                rects = enc.encode(&f, w, h);
                best = best.min(t.elapsed().as_secs_f64() * 1000.0);
            }
            let msgs = pack(1, w, h, &rects);
            let bytes: usize = msgs.iter().map(Vec::len).sum();
            let mut dec_ms = f64::MAX;
            for _ in 0..5 {
                let t = Instant::now();
                for m in &msgs {
                    dec.apply(&m[1..], &mut fb, w, h).unwrap();
                }
                dec_ms = dec_ms.min(t.elapsed().as_secs_f64() * 1000.0);
            }
            let db = psnr(&f, &fb, w, Rect { x: 0, y: 0, w, h });
            println!(
                "{name:8}: encode {best:.1} ms ({} threads), decode {dec_ms:.1} ms, {:.0} KiB, {db:.1} dB",
                enc.workers.len(),
                bytes as f64 / 1024.0
            );
        }
    }
}
