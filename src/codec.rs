//! Lossless tile codec.
//!
//! The screen is split into 64x64 tiles; tiles that differ from the last frame sent are
//! grouped into horizontal runs, predicted from the left neighbour (PNG "Sub" filter on BGR)
//! and compressed with the OS's XPRESS+Huffman codec (cabinet.dll). Uniform runs are sent
//! as a single colour.
//!
//! Wire format (payload of an `S_TILES` message):
//! `frame:u32 | flags:u8 | width:u16 | height:u16 | count:u16 | rect*`
//! `rect = x:u16 | y:u16 | w:u16 | h:u16 | enc:u8 | len:u32 | data[len]`

use crate::bail;
use crate::mem::LockedBuf;
use crate::proto::Rd;
use crate::util::{Error, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::Storage::Compression::*;

pub const TILE: usize = 64;
pub const ENC_SOLID: u8 = 0;
pub const ENC_XPRESS: u8 = 1;
pub const ENC_RAW: u8 = 2;
pub const FLAG_LAST: u8 = 1;
/// Split a frame into several messages once a message grows past this.
pub const CHUNK_BYTES: usize = 4 << 20;

struct Compressor(COMPRESSOR_HANDLE);
unsafe impl Send for Compressor {}

impl Compressor {
    fn new() -> Result<Self> {
        let mut h = std::ptr::null_mut();
        if unsafe { CreateCompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, std::ptr::null(), &mut h) } == 0 {
            return Err(Error::last_os("CreateCompressor"));
        }
        Ok(Compressor(h))
    }

    /// Compresses `src` into `dst`; returns false if the output would not be smaller.
    fn compress(&mut self, src: &[u8], dst: &mut Vec<u8>) -> bool {
        dst.clear();
        dst.reserve(src.len());
        let mut n = 0usize;
        let ok = unsafe {
            Compress(self.0, src.as_ptr().cast(), src.len(), dst.as_mut_ptr().cast(), dst.capacity(), &mut n)
        };
        if ok == 0 || n == 0 || n >= src.len() {
            return false;
        }
        unsafe { dst.set_len(n) };
        true
    }
}

impl Drop for Compressor {
    fn drop(&mut self) {
        unsafe { CloseCompressor(self.0) };
    }
}

struct Decompressor(DECOMPRESSOR_HANDLE);
unsafe impl Send for Decompressor {}

impl Decompressor {
    fn new() -> Result<Self> {
        let mut h = std::ptr::null_mut();
        if unsafe { CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, std::ptr::null(), &mut h) } == 0 {
            return Err(Error::last_os("CreateDecompressor"));
        }
        Ok(Decompressor(h))
    }

    fn decompress(&mut self, src: &[u8], dst: &mut [u8]) -> Result<()> {
        let mut n = 0usize;
        let ok = unsafe { Decompress(self.0, src.as_ptr().cast(), src.len(), dst.as_mut_ptr().cast(), dst.len(), &mut n) };
        if ok == 0 || n != dst.len() {
            bail!("corrupt tile data");
        }
        Ok(())
    }
}

impl Drop for Decompressor {
    fn drop(&mut self) {
        unsafe { CloseDecompressor(self.0) };
    }
}

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

pub struct Encoder {
    prev: LockedBuf,
    width: usize,
    height: usize,
    force_full: bool,
    workers: Vec<Worker>,
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

fn encode_rect(w: &mut Worker, src: &[u8], stride: usize, r: Rect) -> EncodedRect {
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

impl Encoder {
    pub fn new() -> Result<Encoder> {
        let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(1, 8);
        let workers = (0..n)
            .map(|_| Ok(Worker { comp: Compressor::new()?, filtered: Vec::new() }))
            .collect::<Result<Vec<_>>>()?;
        Ok(Encoder { prev: LockedBuf::new(0), width: 0, height: 0, force_full: true, workers })
    }

    pub fn request_full(&mut self) {
        self.force_full = true;
    }

    /// Tiles of `cur` (BGRA, top-down, `w*h*4` bytes) that differ from the previous frame.
    fn changed_rects(&self, cur: &[u8], full: bool) -> Vec<Rect> {
        let (w, h) = (self.width, self.height);
        let prev = self.prev.as_slice();
        let mut rects = Vec::new();
        for ty in (0..h).step_by(TILE) {
            let th = TILE.min(h - ty);
            let mut run: Option<Rect> = None;
            for tx in (0..w).step_by(TILE) {
                let tw = TILE.min(w - tx);
                let changed = full
                    || (ty..ty + th).any(|row| {
                        let a = (row * w + tx) * 4;
                        cur[a..a + tw * 4] != prev[a..a + tw * 4]
                    });
                match (changed, &mut run) {
                    (true, Some(r)) => r.w += tw,
                    (true, None) => run = Some(Rect { x: tx, y: ty, w: tw, h: th }),
                    (false, r @ Some(_)) => rects.push(r.take().unwrap()),
                    (false, None) => {}
                }
            }
            rects.extend(run);
        }
        rects
    }

    /// Encodes the regions of `cur` that changed since the last call.
    pub fn encode(&mut self, cur: &[u8], w: usize, h: usize) -> Vec<EncodedRect> {
        assert_eq!(cur.len(), w * h * 4);
        if w != self.width || h != self.height {
            self.prev = LockedBuf::new(w * h * 4);
            self.width = w;
            self.height = h;
            self.force_full = true;
        }
        let full = std::mem::take(&mut self.force_full);
        let rects = self.changed_rects(cur, full);
        if rects.is_empty() {
            return Vec::new();
        }

        let pixels: usize = rects.iter().map(|r| r.w * r.h).sum();
        let threads = if pixels < 128 * 1024 { 1 } else { self.workers.len().min(rects.len()) };
        let next = AtomicUsize::new(0);
        let mut out: Vec<EncodedRect> = std::thread::scope(|s| {
            let handles: Vec<_> = self.workers[..threads]
                .iter_mut()
                .map(|wk| {
                    let (rects, next) = (&rects, &next);
                    s.spawn(move || {
                        let mut mine = Vec::new();
                        loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            let Some(&r) = rects.get(i) else { break };
                            mine.push(encode_rect(wk, cur, w, r));
                        }
                        mine
                    })
                })
                .collect();
            handles.into_iter().flat_map(|h| h.join().expect("encoder thread panicked")).collect()
        });
        out.sort_by_key(|e| (e.rect.y, e.rect.x));

        let prev = self.prev.as_mut_slice();
        for r in &rects {
            for row in r.y..r.y + r.h {
                let a = (row * w + r.x) * 4;
                prev[a..a + r.w * 4].copy_from_slice(&cur[a..a + r.w * 4]);
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
            let n = w * h * 3;
            let filtered: &[u8] = match enc {
                ENC_SOLID => {
                    if data.len() != 3 {
                        bail!("bad solid tile");
                    }
                    for row in y..y + h {
                        for px in fb[(row * fbw + x) * 4..(row * fbw + x + w) * 4].chunks_exact_mut(4) {
                            px.copy_from_slice(&[data[0], data[1], data[2], 255]);
                        }
                    }
                    &[]
                }
                ENC_RAW => {
                    if data.len() != n {
                        bail!("bad raw tile");
                    }
                    data
                }
                ENC_XPRESS => {
                    self.scratch.resize(n, 0);
                    self.decomp.decompress(data, &mut self.scratch)?;
                    &self.scratch
                }
                _ => bail!("unknown tile encoding {enc}"),
            };
            if enc != ENC_SOLID {
                let mut src = filtered.chunks_exact(3);
                for row in y..y + h {
                    let (mut lb, mut lg, mut lr) = (0u8, 0u8, 0u8);
                    for px in fb[(row * fbw + x) * 4..(row * fbw + x + w) * 4].chunks_exact_mut(4) {
                        let s = src.next().unwrap();
                        lb = lb.wrapping_add(s[0]);
                        lg = lg.wrapping_add(s[1]);
                        lr = lr.wrapping_add(s[2]);
                        px.copy_from_slice(&[lb, lg, lr, 255]);
                    }
                }
            }
            let nr = Rect { x, y, w, h };
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
        let mut enc = Encoder::new().unwrap();
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
        // Full refresh re-sends everything.
        enc.request_full();
        assert!(roundtrip(&mut enc, &mut dec, &mut fb, &f2, w, h, 3) >= 4);
    }

    #[test]
    fn large_frame_is_chunked() {
        let (w, h) = (1920, 1080);
        let mut enc = Encoder::new().unwrap();
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
        assert!(dec.apply(&[0; 5], &mut fb, 16, 16).is_err());
    }
}
