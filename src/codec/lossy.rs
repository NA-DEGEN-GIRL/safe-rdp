//! Lossy tile coding for busy screen regions (photos, video, scrolled images).
//!
//! A baseline-JPEG-style transform coder for one rectangle of a BGRA frame: BT.601 full-range
//! YCbCr, 4:2:0 chroma subsampling in 16x16 MCUs (the rectangle's last column and row are
//! replicated where it does not fill an MCU), an AAN float DCT, the Annex K quantisation tables
//! scaled like IJG's `quality` setting, zigzag order, DC prediction, AC run-length symbols and the
//! fixed Annex K Huffman tables. The tables are never transmitted.
//!
//! Payload (`ENC_LOSSY` tile data); the rectangle's position and size come from the tile header:
//! `quality:u8 (1..=100) | scan`
//! - `scan` holds the MCUs left to right, top to bottom, each as the 8x8 blocks
//!   `Y(0,0) Y(0,8) Y(8,0) Y(8,8) Cb Cr` (luma block offsets inside the MCU as (row, column)).
//!   DC predictors start at 0 for every rectangle. Bits are packed most significant first with
//!   no markers or byte stuffing; the final byte is padded with 1 bits. Apart from the missing
//!   stuffing this is exactly a baseline JPEG scan with the standard tables.
//!
//! The decoder's work is bounded by the rectangle size (and every block consumes input), and it
//! rejects quality values outside 1..=100, invalid codes, coefficient overruns, DC values outside
//! the 8-bit range, reads past the end and trailing bytes.

use super::Rect;
use crate::bail;
use crate::util::Result;
use std::f32::consts::{FRAC_1_SQRT_2, SQRT_2};

/// Natural (row-major) index of the k-th coefficient in zigzag order.
const ZIGZAG: [u8; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55,
    62, 63,
];

/// Annex K.1 luminance quantisation table (natural order), quality 50.
const LUMA_Q: [u8; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80,
    62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95,
    98, 112, 100, 103, 99,
];

/// Annex K.2 chrominance quantisation table (natural order), quality 50.
const CHROMA_Q: [u8; 64] = [
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99, 99, 47, 66, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99,
];

/// AAN scale factors: 1 for k = 0, else cos(k*pi/16) * sqrt(2).
#[allow(clippy::excessive_precision)]
const AAN: [f32; 8] = [1.0, 1.387039845, 1.306562965, 1.175875602, 1.0, 0.785694958, 0.541196100, 0.275899379];

// Annex K.3 Huffman tables: number of codes of each length 1..=16, then the symbols in code order.
const DC_VALS: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
const LUMA_DC_BITS: [u8; 16] = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
const CHROMA_DC_BITS: [u8; 16] = [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0];
const LUMA_AC_BITS: [u8; 16] = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d];
const LUMA_AC_VALS: [u8; 162] = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32,
    0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0, 0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45,
    0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x92, 0x93, 0x94,
    0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
    0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    0xd9, 0xda, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
];
const CHROMA_AC_BITS: [u8; 16] = [0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77];
const CHROMA_AC_VALS: [u8; 162] = [
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71, 0x13, 0x22, 0x32, 0x81,
    0x08, 0x14, 0x42, 0x91, 0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0, 0x15, 0x62, 0x72, 0xd1, 0x0a, 0x16, 0x24, 0x34,
    0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44,
    0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x92,
    0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4,
    0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
    0xd7, 0xd8, 0xd9, 0xda, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
];

const EOB: usize = 0x00;
const ZRL: usize = 0xf0;

/// Encoder view of a Huffman table: code and code length per symbol (length 0 = unused).
struct HuffEnc {
    code: [u16; 256],
    len: [u8; 256],
}

/// Canonical code assignment of JPEG Annex C.
const fn huff_enc(bits: &[u8; 16], vals: &[u8]) -> HuffEnc {
    let mut t = HuffEnc { code: [0; 256], len: [0; 256] };
    let (mut code, mut k, mut l) = (0u16, 0usize, 0usize);
    while l < 16 {
        let mut j = 0;
        while j < bits[l] {
            t.code[vals[k] as usize] = code;
            t.len[vals[k] as usize] = l as u8 + 1;
            code += 1;
            k += 1;
            j += 1;
        }
        code <<= 1;
        l += 1;
    }
    t
}

const FAST_BITS: usize = 9;

/// Decoder view of a Huffman table: a lookup table for short codes plus the per-length code
/// limits of JPEG F.2.2.3 for the rest.
struct HuffDec {
    /// `len << 8 | symbol` for each `FAST_BITS`-bit prefix that starts with a code of at most
    /// `FAST_BITS` bits, else 0.
    fast: [u16; 1 << FAST_BITS],
    /// Largest code of each length 1..=16, -1 when there is none.
    maxcode: [i32; 17],
    /// Added to a code of each length to index `vals`.
    valoff: [i32; 17],
    vals: [u8; 256],
}

const fn huff_dec(bits: &[u8; 16], vals: &[u8]) -> HuffDec {
    let mut t = HuffDec { fast: [0; 1 << FAST_BITS], maxcode: [-1; 17], valoff: [0; 17], vals: [0; 256] };
    let mut i = 0;
    while i < vals.len() {
        t.vals[i] = vals[i];
        i += 1;
    }
    let (mut code, mut k, mut l) = (0i32, 0i32, 1usize);
    while l <= 16 {
        let n = bits[l - 1] as i32;
        t.valoff[l] = k - code;
        let mut j = 0;
        while j < n {
            if l <= FAST_BITS {
                let shift = FAST_BITS - l;
                let base = (code as usize) << shift;
                let mut f = 0;
                while f < 1 << shift {
                    t.fast[base + f] = (l as u16) << 8 | vals[k as usize] as u16;
                    f += 1;
                }
            }
            code += 1;
            k += 1;
            j += 1;
        }
        if n > 0 {
            t.maxcode[l] = code - 1;
        }
        code <<= 1;
        l += 1;
    }
    t
}

static LUMA_DC_ENC: HuffEnc = huff_enc(&LUMA_DC_BITS, &DC_VALS);
static LUMA_AC_ENC: HuffEnc = huff_enc(&LUMA_AC_BITS, &LUMA_AC_VALS);
static CHROMA_DC_ENC: HuffEnc = huff_enc(&CHROMA_DC_BITS, &DC_VALS);
static CHROMA_AC_ENC: HuffEnc = huff_enc(&CHROMA_AC_BITS, &CHROMA_AC_VALS);
static LUMA_DC_DEC: HuffDec = huff_dec(&LUMA_DC_BITS, &DC_VALS);
static LUMA_AC_DEC: HuffDec = huff_dec(&LUMA_AC_BITS, &LUMA_AC_VALS);
static CHROMA_DC_DEC: HuffDec = huff_dec(&CHROMA_DC_BITS, &DC_VALS);
static CHROMA_AC_DEC: HuffDec = huff_dec(&CHROMA_AC_BITS, &CHROMA_AC_VALS);

/// IJG quality scaling of a quality-50 table, limited to baseline's 1..=255.
fn quant_table(base: &[u8; 64], quality: u8) -> [u16; 64] {
    let q = quality.clamp(1, 100) as u32;
    let scale = if q < 50 { 5000 / q } else { 200 - 2 * q };
    std::array::from_fn(|i| ((base[i] as u32 * scale + 50) / 100).clamp(1, 255) as u16)
}

/// Quantiser reciprocals with the AAN forward DCT's output scaling (8 * aan[u] * aan[v]) folded in.
fn fdct_scale(q: &[u16; 64]) -> [f32; 64] {
    std::array::from_fn(|i| 1.0 / (q[i] as f32 * AAN[i / 8] * AAN[i % 8] * 8.0))
}

/// Dequantisation multipliers with the AAN inverse DCT's input scaling and final 1/8 folded in.
fn idct_scale(q: &[u16; 64]) -> [f32; 64] {
    std::array::from_fn(|i| q[i] as f32 * AAN[i / 8] * AAN[i % 8] / 8.0)
}

/// One-dimensional AAN forward DCT (IJG jfdctflt); outputs are scaled by 8 * aan[k] overall
/// once both passes ran.
#[inline(always)]
#[allow(clippy::excessive_precision)]
fn fdct_1d(d: [f32; 8]) -> [f32; 8] {
    let (t0, t7) = (d[0] + d[7], d[0] - d[7]);
    let (t1, t6) = (d[1] + d[6], d[1] - d[6]);
    let (t2, t5) = (d[2] + d[5], d[2] - d[5]);
    let (t3, t4) = (d[3] + d[4], d[3] - d[4]);
    // Even part.
    let (t10, t13) = (t0 + t3, t0 - t3);
    let (t11, t12) = (t1 + t2, t1 - t2);
    let z1 = (t12 + t13) * FRAC_1_SQRT_2;
    // Odd part.
    let (t10o, t11o, t12o) = (t4 + t5, t5 + t6, t6 + t7);
    let z5 = (t10o - t12o) * 0.382683433;
    let z2 = 0.541196100 * t10o + z5;
    let z4 = 1.306562965 * t12o + z5;
    let z3 = t11o * FRAC_1_SQRT_2;
    let (z11, z13) = (t7 + z3, t7 - z3);
    [t10 + t11, z11 + z4, t13 + z1, z13 - z2, t10 - t11, z13 + z2, t13 - z1, z11 - z4]
}

/// One-dimensional AAN inverse DCT (IJG jidctflt); expects inputs pre-scaled by `idct_scale`.
#[inline(always)]
#[allow(clippy::excessive_precision)]
fn idct_1d(i: [f32; 8]) -> [f32; 8] {
    // Even part.
    let (t10, t11) = (i[0] + i[4], i[0] - i[4]);
    let t13 = i[2] + i[6];
    let t12 = (i[2] - i[6]) * SQRT_2 - t13;
    let (t0, t3) = (t10 + t13, t10 - t13);
    let (t1, t2) = (t11 + t12, t11 - t12);
    // Odd part.
    let (z13, z10) = (i[5] + i[3], i[5] - i[3]);
    let (z11, z12) = (i[1] + i[7], i[1] - i[7]);
    let t7 = z11 + z13;
    let t11o = (z11 - z13) * SQRT_2;
    let z5 = (z10 + z12) * 1.847759065;
    let t10o = 1.082392200 * z12 - z5;
    let t12o = -2.613125930 * z10 + z5;
    let t6 = t12o - t7;
    let t5 = t11o - t6;
    let t4 = t10o + t5;
    [t0 + t7, t1 + t6, t2 + t5, t3 - t4, t3 + t4, t2 - t5, t1 - t6, t0 - t7]
}

fn fdct(b: &mut [f32; 64]) {
    for row in b.as_chunks_mut::<8>().0 {
        *row = fdct_1d(*row);
    }
    for c in 0..8 {
        let col = fdct_1d(std::array::from_fn(|k| b[k * 8 + c]));
        for (k, v) in col.into_iter().enumerate() {
            b[k * 8 + c] = v;
        }
    }
}

fn idct(b: &mut [f32; 64]) {
    for c in 0..8 {
        let col = idct_1d(std::array::from_fn(|k| b[k * 8 + c]));
        for (k, v) in col.into_iter().enumerate() {
            b[k * 8 + c] = v;
        }
    }
    for row in b.as_chunks_mut::<8>().0 {
        *row = idct_1d(*row);
    }
}

/// Rounds half up; |v| stays far below 16384 for 8-bit samples.
#[inline(always)]
fn quantize(v: f32) -> i32 {
    (v + 16384.5) as i32 - 16384
}

/// JPEG magnitude category of `v` and its `n` low-order bits (one's complement for negatives).
#[inline(always)]
fn magnitude(v: i32) -> (u32, u32) {
    let n = 32 - v.unsigned_abs().leading_zeros();
    let bits = if v < 0 { (v - 1) as u32 & ((1 << n) - 1) } else { v as u32 };
    (bits, n)
}

/// Inverse of `magnitude`.
#[inline(always)]
fn extend(bits: u32, n: u32) -> i32 {
    if n == 0 {
        0
    } else if bits < 1 << (n - 1) {
        bits as i32 - (1 << n) + 1
    } else {
        bits as i32
    }
}

struct BitWriter<'a> {
    out: &'a mut Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitWriter<'_> {
    /// Appends the low `len` (at most 32) bits of `bits`, most significant first.
    #[inline(always)]
    fn put(&mut self, bits: u32, len: u32) {
        self.acc = self.acc << len | bits as u64;
        self.n += len;
        if self.n >= 32 {
            self.n -= 32;
            self.out.extend_from_slice(&((self.acc >> self.n) as u32).to_be_bytes());
        }
    }

    /// Pads the last byte with 1 bits and flushes it.
    fn finish(mut self) {
        let pad = (8 - self.n % 8) % 8;
        self.put((1 << pad) - 1, pad);
        while self.n >= 8 {
            self.n -= 8;
            self.out.push((self.acc >> self.n) as u8);
        }
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    /// Bytes moved into `acc` so far, including the virtual ones past the end.
    pos: usize,
    /// Next bits, most significant first.
    acc: u64,
    n: u32,
}

impl BitReader<'_> {
    /// Tops `acc` up to at least 56 bits. Past the end it shifts in 1 bits; `overrun` reports
    /// when any of those were consumed.
    fn refill(&mut self) {
        if let Some(chunk) = self.data.get(self.pos..).and_then(<[u8]>::first_chunk::<8>) {
            // Whole bytes only, so the bits below the accumulator's fill level stay zero.
            let take = (63 - self.n) / 8;
            let fill = self.n + take * 8;
            self.acc |= (u64::from_be_bytes(*chunk) >> self.n) & !(u64::MAX >> fill);
            self.pos += take as usize;
            self.n = fill;
            return;
        }
        while self.n <= 56 {
            let b = self.data.get(self.pos).copied().unwrap_or(0xff);
            self.pos += 1;
            self.acc |= (b as u64) << (56 - self.n);
            self.n += 8;
        }
    }

    #[inline(always)]
    fn skip(&mut self, n: u32) {
        self.acc <<= n;
        self.n -= n;
    }

    fn symbol(&mut self, t: &HuffDec) -> Result<u8> {
        if self.n < 16 {
            self.refill();
        }
        let peek = (self.acc >> 48) as usize;
        let f = t.fast[peek >> (16 - FAST_BITS)];
        if f != 0 {
            self.skip(u32::from(f >> 8));
            return Ok(f as u8);
        }
        for l in FAST_BITS + 1..=16 {
            let code = (peek >> (16 - l)) as i32;
            if code <= t.maxcode[l] {
                self.skip(l as u32);
                if let Some(&v) = t.vals.get((code + t.valoff[l]) as usize) {
                    return Ok(v);
                }
                break;
            }
        }
        bail!("invalid Huffman code in lossy tile")
    }

    /// Next `n` (at most 16) raw bits.
    #[inline(always)]
    fn bits(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        if self.n < n {
            self.refill();
        }
        let v = (self.acc >> (64 - n)) as u32;
        self.skip(n);
        v
    }

    fn consumed(&self) -> usize {
        self.pos * 8 - self.n as usize
    }

    fn overrun(&self) -> bool {
        self.consumed() > self.data.len() * 8
    }

    /// Accepts the end of the scan only if nothing but the 1-bit padding of the last byte is left.
    fn finish(mut self) -> Result<()> {
        if self.overrun() {
            bail!("truncated lossy tile");
        }
        let pad = self.data.len() * 8 - self.consumed();
        if pad >= 8 || self.bits(pad as u32) != (1 << pad) - 1 {
            bail!("trailing data in lossy tile");
        }
        Ok(())
    }
}

/// Converts the 16x16 MCU at (`x0`, `y0`) inside `r` to level-shifted luma blocks and 2x2-averaged
/// chroma blocks, replicating the rectangle's last column and row.
#[allow(clippy::too_many_arguments)]
fn load_mcu(src: &[u8], stride: usize, r: Rect, x0: usize, y0: usize, ys: &mut [[f32; 64]; 4], cb: &mut [f32; 64], cr: &mut [f32; 64]) {
    let mut sums = [[0f32; 3]; 64];
    for yy in 0..16 {
        let sy = r.y + (y0 + yy).min(r.h - 1);
        let line = &src[(sy * stride + r.x) * 4..(sy * stride + r.x + r.w) * 4];
        for xx in 0..16 {
            let p = &line[(x0 + xx).min(r.w - 1) * 4..][..3];
            let (b, g, rd) = (p[0] as f32, p[1] as f32, p[2] as f32);
            ys[(yy >> 3) * 2 + (xx >> 3)][(yy & 7) * 8 + (xx & 7)] = 0.299 * rd + 0.587 * g + 0.114 * b - 128.0;
            let s = &mut sums[(yy >> 1) * 8 + (xx >> 1)];
            s[0] += b;
            s[1] += g;
            s[2] += rd;
        }
    }
    // Chroma of the 2x2 average (the transform is affine, so this equals averaging Cb/Cr).
    for (i, &[b, g, rd]) in sums.iter().enumerate() {
        cb[i] = 0.25 * (-0.168_736 * rd - 0.331_264 * g + 0.5 * b);
        cr[i] = 0.25 * (0.5 * rd - 0.418_688 * g - 0.081_312 * b);
    }
}

fn encode_block(bw: &mut BitWriter, block: &mut [f32; 64], recip: &[f32; 64], pred: &mut i32, dc: &HuffEnc, ac: &HuffEnc) {
    fdct(block);
    let mut zz = [0i32; 64];
    let mut last = 0;
    for (k, &n) in ZIGZAG.iter().enumerate() {
        let v = quantize(block[n as usize] * recip[n as usize]);
        zz[k] = v;
        if v != 0 {
            last = k;
        }
    }
    // Clamping keeps every DC difference within category 11 and AC values within category 10.
    let dcv = zz[0].clamp(-1024, 1023);
    let (bits, n) = magnitude(dcv - *pred);
    *pred = dcv;
    bw.put(u32::from(dc.code[n as usize]) << n | bits, u32::from(dc.len[n as usize]) + n);
    let mut run = 0;
    for &v in &zz[1..=last] {
        if v == 0 {
            run += 1;
            continue;
        }
        while run > 15 {
            bw.put(u32::from(ac.code[ZRL]), u32::from(ac.len[ZRL]));
            run -= 16;
        }
        let (bits, n) = magnitude(v.clamp(-1023, 1023));
        let s = (run << 4 | n) as usize;
        bw.put(u32::from(ac.code[s]) << n | bits, u32::from(ac.len[s]) + n);
        run = 0;
    }
    if last < 63 {
        bw.put(u32::from(ac.code[EOB]), u32::from(ac.len[EOB]));
    }
}

/// Encodes rectangle `r` of `src` (BGRA, `stride_px` pixels per row) at `quality` (clamped to
/// 1..=100), replacing the contents of `out` with the payload described in the module docs.
pub fn encode(src: &[u8], stride_px: usize, r: Rect, quality: u8, out: &mut Vec<u8>) {
    let quality = quality.clamp(1, 100);
    out.clear();
    out.reserve(r.w * r.h / 4 + 16);
    out.push(quality);
    if r.w == 0 || r.h == 0 {
        return;
    }
    assert!(r.x + r.w <= stride_px && (r.y + r.h) * stride_px * 4 <= src.len(), "lossy rect outside the frame");
    let lq = fdct_scale(&quant_table(&LUMA_Q, quality));
    let cq = fdct_scale(&quant_table(&CHROMA_Q, quality));
    let mut bw = BitWriter { out, acc: 0, n: 0 };
    let mut pred = [0i32; 3];
    let mut ys = [[0f32; 64]; 4];
    let (mut cb, mut cr) = ([0f32; 64], [0f32; 64]);
    for y0 in (0..r.h).step_by(16) {
        for x0 in (0..r.w).step_by(16) {
            load_mcu(src, stride_px, r, x0, y0, &mut ys, &mut cb, &mut cr);
            for y in &mut ys {
                encode_block(&mut bw, y, &lq, &mut pred[0], &LUMA_DC_ENC, &LUMA_AC_ENC);
            }
            encode_block(&mut bw, &mut cb, &cq, &mut pred[1], &CHROMA_DC_ENC, &CHROMA_AC_ENC);
            encode_block(&mut bw, &mut cr, &cq, &mut pred[2], &CHROMA_DC_ENC, &CHROMA_AC_ENC);
        }
    }
    bw.finish();
}

/// Decodes one block into `block` (spatial samples, level shift not yet undone).
fn decode_block(br: &mut BitReader, block: &mut [f32; 64], mult: &[f32; 64], pred: &mut i32, dc: &HuffDec, ac: &HuffDec) -> Result<()> {
    let s = u32::from(br.symbol(dc)?);
    if s > 11 {
        bail!("bad DC symbol in lossy tile");
    }
    let dcv = *pred + extend(br.bits(s), s);
    if !(-2048..=2047).contains(&dcv) {
        bail!("DC coefficient out of range in lossy tile");
    }
    *pred = dcv;
    *block = [0.0; 64];
    block[0] = dcv as f32 * mult[0];
    let (mut k, mut has_ac) = (1usize, false);
    while k < 64 {
        let rs = br.symbol(ac)?;
        let (run, size) = ((rs >> 4) as usize, u32::from(rs & 15));
        if size == 0 {
            match run {
                0 => break,
                15 => {
                    k += 16;
                    if k > 63 {
                        bail!("AC coefficients overrun the block in lossy tile");
                    }
                    continue;
                }
                _ => bail!("bad AC symbol in lossy tile"),
            }
        }
        k += run;
        if k > 63 || size > 10 {
            bail!("AC coefficients overrun the block in lossy tile");
        }
        let i = ZIGZAG[k] as usize;
        block[i] = extend(br.bits(size), size) as f32 * mult[i];
        has_ac = true;
        k += 1;
    }
    if br.overrun() {
        bail!("truncated lossy tile");
    }
    if has_ac {
        idct(block);
    } else {
        let v = block[0];
        block.fill(v);
    }
    Ok(())
}

#[inline(always)]
fn to_u8(v: f32) -> u8 {
    (v + 0.5).clamp(0.0, 255.0) as u8
}

/// Writes the part of the MCU at (`x0`, `y0`) that lies inside `r` to `fb` as BGRA. The luma
/// blocks still carry the -128 level shift.
#[allow(clippy::too_many_arguments)]
fn store_mcu(fb: &mut [u8], fb_w: usize, r: Rect, x0: usize, y0: usize, ys: &[[f32; 64]; 4], cb: &[f32; 64], cr: &[f32; 64]) {
    let w = 16.min(r.w - x0);
    let mut line = [0u8; 64];
    for yy in 0..16.min(r.h - y0) {
        let (lo, co) = ((yy & 7) * 8, (yy >> 1) * 8);
        let (left, right) = (&ys[(yy >> 3) * 2][lo..lo + 8], &ys[(yy >> 3) * 2 + 1][lo..lo + 8]);
        let (u, v) = (&cb[co..co + 8], &cr[co..co + 8]);
        for (xx, px) in line.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let l = if xx < 8 { left[xx] } else { right[xx - 8] } + 128.0;
            let (u, v) = (u[xx >> 1], v[xx >> 1]);
            *px = [to_u8(l + 1.772 * u), to_u8(l - 0.344_136 * u - 0.714_136 * v), to_u8(l + 1.402 * v), 255];
        }
        let o = ((r.y + y0 + yy) * fb_w + r.x + x0) * 4;
        fb[o..o + w * 4].copy_from_slice(&line[..w * 4]);
    }
}

/// Decodes a payload made by `encode` into rectangle `r` of `fb` (BGRA, `fb_w` pixels per row,
/// alpha set to 255). On error the rectangle may be partially written.
pub fn decode(data: &[u8], fb: &mut [u8], fb_w: usize, r: Rect) -> Result<()> {
    let fb_h = fb_w.checked_mul(4).filter(|&s| s > 0).map_or(0, |s| fb.len() / s);
    if r.w == 0 || r.h == 0 || r.x.checked_add(r.w).is_none_or(|e| e > fb_w) || r.y.checked_add(r.h).is_none_or(|e| e > fb_h) {
        bail!("lossy tile out of bounds");
    }
    let Some((&quality, scan)) = data.split_first() else { bail!("empty lossy tile") };
    if !(1..=100).contains(&quality) {
        bail!("bad lossy tile quality {quality}");
    }
    let lq = idct_scale(&quant_table(&LUMA_Q, quality));
    let cq = idct_scale(&quant_table(&CHROMA_Q, quality));
    let mut br = BitReader { data: scan, pos: 0, acc: 0, n: 0 };
    let mut pred = [0i32; 3];
    let mut ys = [[0f32; 64]; 4];
    let (mut cb, mut cr) = ([0f32; 64], [0f32; 64]);
    for y0 in (0..r.h).step_by(16) {
        for x0 in (0..r.w).step_by(16) {
            for y in &mut ys {
                decode_block(&mut br, y, &lq, &mut pred[0], &LUMA_DC_DEC, &LUMA_AC_DEC)?;
            }
            decode_block(&mut br, &mut cb, &cq, &mut pred[1], &CHROMA_DC_DEC, &CHROMA_AC_DEC)?;
            decode_block(&mut br, &mut cr, &cq, &mut pred[2], &CHROMA_DC_DEC, &CHROMA_AC_DEC)?;
            store_mcu(fb, fb_w, r, x0, y0, &ys, &cb, &cr);
        }
    }
    br.finish()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Photo-like BGRA content: broad shading, a soft highlight, fine texture and sensor noise
    /// (mostly luminance, as in real photos).
    pub(crate) fn photo(w: usize, h: usize, seed: u32) -> Vec<u8> {
        let mut s = seed.wrapping_mul(0x9e37_79b9) | 1;
        let k = seed as f32 * 0.37;
        let mut v = vec![0u8; w * h * 4];
        for (i, px) in v.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let (x, y) = ((i % w) as f32, (i / w) as f32);
            let shade = 0.45 + 0.3 * (x * 0.013 + k).sin() * (y * 0.009 - k).cos();
            let (dx, dy) = (x - w as f32 * 0.6, y - h as f32 * 0.4);
            let blob = 0.25 / (1.0 + (dx * dx + dy * dy) * 0.0004);
            let texture = 0.06 * (x * 0.8 + 2.5 * (y * 0.15).sin()).sin() * (y * 0.55 + x * 0.1).cos();
            let l = shade + blob + texture;
            let hue = (x * 0.004 - y * 0.006 + k).sin();
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            let luma_noise = ((s >> 24) & 15) as f32 - 7.5;
            let ch = |tint: f32, sh: u32| (255.0 * l * tint + luma_noise + ((s >> sh) & 3) as f32 - 1.5).clamp(0.0, 255.0) as u8;
            px.copy_from_slice(&[ch(0.8 - 0.2 * hue, 0), ch(0.9 + 0.05 * hue, 8), ch(0.8 + 0.2 * hue, 16), 255]);
        }
        v
    }

    /// PSNR over the BGR channels of rectangle `r` of two BGRA images with the same stride.
    pub(crate) fn psnr(a: &[u8], b: &[u8], stride: usize, r: Rect) -> f64 {
        let mut se = 0f64;
        for y in r.y..r.y + r.h {
            let o = (y * stride + r.x) * 4;
            for (p, q) in a[o..o + r.w * 4].as_chunks::<4>().0.iter().zip(b[o..o + r.w * 4].as_chunks::<4>().0) {
                se += (0..3).map(|c| (p[c] as f64 - q[c] as f64).powi(2)).sum::<f64>();
            }
        }
        let mse = se / (r.w * r.h * 3) as f64;
        if mse == 0.0 { f64::INFINITY } else { 10.0 * (255.0 * 255.0 / mse).log10() }
    }

    fn roundtrip(src: &[u8], stride: usize, r: Rect, q: u8) -> (Vec<u8>, usize) {
        let mut data = Vec::new();
        encode(src, stride, r, q, &mut data);
        assert_eq!(data[0], q.clamp(1, 100));
        let mut fb = src.to_vec();
        decode(&data, &mut fb, stride, r).unwrap();
        (fb, data.len())
    }

    fn rng(s: &mut u32) -> u32 {
        *s ^= *s << 13;
        *s ^= *s >> 17;
        *s ^= *s << 5;
        *s
    }

    #[test]
    fn zigzag_order() {
        // Walk the anti-diagonals in alternating directions (JPEG figure A.6).
        let mut expect = Vec::new();
        for d in 0..15usize {
            let cells: Vec<usize> = (0..=d).filter(|&i| i < 8 && d - i < 8).map(|i| i * 8 + (d - i)).collect();
            if d % 2 == 0 {
                expect.extend(cells.iter().rev());
            } else {
                expect.extend(cells.iter());
            }
        }
        assert_eq!(ZIGZAG.iter().map(|&z| z as usize).collect::<Vec<_>>(), expect);
    }

    #[test]
    fn quant_tables_follow_ijg_scaling() {
        assert_eq!(quant_table(&LUMA_Q, 50).map(|v| v as u8), LUMA_Q);
        assert_eq!(quant_table(&CHROMA_Q, 50).map(|v| v as u8), CHROMA_Q);
        assert!(quant_table(&LUMA_Q, 100).iter().all(|&v| v == 1));
        assert!(quant_table(&CHROMA_Q, 1).iter().all(|&v| v == 255));
        let q80 = quant_table(&LUMA_Q, 80);
        assert_eq!((q80[0], q80[1], q80[63]), (6, 4, 40)); // (16*40+50)/100, (11*40+50)/100, (99*40+50)/100
        assert_eq!(quant_table(&LUMA_Q, 25)[0], 32); // scale 200
    }

    #[test]
    fn huffman_tables_match_annex_k() {
        let code = |t: &HuffEnc, s: usize| (t.code[s], t.len[s]);
        // Spot checks against tables K.3 to K.6.
        assert_eq!(code(&LUMA_DC_ENC, 0), (0b00, 2));
        assert_eq!(code(&LUMA_DC_ENC, 6), (0b1110, 4));
        assert_eq!(code(&LUMA_DC_ENC, 11), (0b1_1111_1110, 9));
        assert_eq!(code(&CHROMA_DC_ENC, 2), (0b10, 2));
        assert_eq!(code(&CHROMA_DC_ENC, 11), (0b111_1111_1110, 11));
        assert_eq!(code(&LUMA_AC_ENC, EOB), (0b1010, 4));
        assert_eq!(code(&LUMA_AC_ENC, 0x01), (0b00, 2));
        assert_eq!(code(&LUMA_AC_ENC, 0x05), (0b11010, 5));
        assert_eq!(code(&LUMA_AC_ENC, 0x11), (0b1100, 4));
        assert_eq!(code(&LUMA_AC_ENC, ZRL), (0b111_1111_1001, 11));
        assert_eq!(code(&LUMA_AC_ENC, 0xfa), (0xfffe, 16));
        assert_eq!(code(&CHROMA_AC_ENC, EOB), (0b00, 2));
        assert_eq!(code(&CHROMA_AC_ENC, 0x01), (0b01, 2));
        assert_eq!(code(&CHROMA_AC_ENC, ZRL), (0b11_1111_1010, 10));
        assert_eq!(code(&CHROMA_AC_ENC, 0xfa), (0xfffe, 16));

        // Every baseline symbol is present exactly once and no code is all ones.
        let ac: Vec<u8> = [0x00, 0xf0].into_iter().chain((0..16u8).flat_map(|r| (1..=10u8).map(move |s| r << 4 | s))).collect();
        for (bits, vals, all) in [
            (&LUMA_DC_BITS, &DC_VALS[..], &DC_VALS[..]),
            (&CHROMA_DC_BITS, &DC_VALS[..], &DC_VALS[..]),
            (&LUMA_AC_BITS, &LUMA_AC_VALS[..], &ac[..]),
            (&CHROMA_AC_BITS, &CHROMA_AC_VALS[..], &ac[..]),
        ] {
            assert_eq!(bits.iter().map(|&b| b as usize).sum::<usize>(), vals.len());
            let (mut a, mut b) = (vals.to_vec(), all.to_vec());
            a.sort_unstable();
            b.sort_unstable();
            assert_eq!(a, b);
            let kraft: f64 = bits.iter().enumerate().map(|(l, &n)| n as f64 / 2f64.powi(l as i32 + 1)).sum();
            assert!(kraft < 1.0);
        }

        // Each code decodes back to its symbol, through the fast table and the slow path.
        for (enc, dec, vals) in [
            (&LUMA_DC_ENC, &LUMA_DC_DEC, &DC_VALS[..]),
            (&CHROMA_DC_ENC, &CHROMA_DC_DEC, &DC_VALS[..]),
            (&LUMA_AC_ENC, &LUMA_AC_DEC, &LUMA_AC_VALS[..]),
            (&CHROMA_AC_ENC, &CHROMA_AC_DEC, &CHROMA_AC_VALS[..]),
        ] {
            let mut out = Vec::new();
            let mut bw = BitWriter { out: &mut out, acc: 0, n: 0 };
            for &s in vals {
                bw.put(u32::from(enc.code[s as usize]), u32::from(enc.len[s as usize]));
            }
            bw.finish();
            let mut br = BitReader { data: &out, pos: 0, acc: 0, n: 0 };
            for &s in vals {
                assert_eq!(br.symbol(dec).unwrap(), s);
            }
            br.finish().unwrap();
        }
    }

    #[test]
    fn magnitude_and_extend_roundtrip() {
        for v in -2047..=2047 {
            let (bits, n) = magnitude(v);
            assert!(n <= 11 && bits < 1 << n);
            assert_eq!(extend(bits, n), v);
        }
        assert_eq!(magnitude(-1), (0, 1));
        assert_eq!(magnitude(-3), (0, 2));
        assert_eq!(magnitude(5), (5, 3));
    }

    #[test]
    fn aan_dct_matches_reference() {
        use std::f64::consts::PI;
        let c = |k: usize| if k == 0 { 1.0 / 2f64.sqrt() } else { 1.0 };
        let mut s = 99u32;
        for _ in 0..20 {
            let px: [f32; 64] = std::array::from_fn(|_| (rng(&mut s) % 256) as f32 - 128.0);
            // F(u,v) = C(u)C(v)/4 * sum f(y,x) cos((2y+1)u pi/16) cos((2x+1)v pi/16)
            let reference: [f64; 64] = std::array::from_fn(|i| {
                let (u, v) = ((i / 8) as f64, (i % 8) as f64);
                let mut sum = 0.0;
                for (j, &f) in px.iter().enumerate() {
                    let (y, x) = ((j / 8) as f64, (j % 8) as f64);
                    sum += f as f64 * ((2.0 * y + 1.0) * u * PI / 16.0).cos() * ((2.0 * x + 1.0) * v * PI / 16.0).cos();
                }
                c(i / 8) * c(i % 8) / 4.0 * sum
            });
            let mut b = px;
            fdct(&mut b);
            for i in 0..64 {
                let scaled = b[i] as f64 / (8.0 * AAN[i / 8] as f64 * AAN[i % 8] as f64);
                assert!((scaled - reference[i]).abs() < 0.01, "coefficient {i}: {scaled} vs {}", reference[i]);
            }
            // The inverse with unit quantisers reproduces the samples.
            let mult = idct_scale(&[1; 64]);
            let mut b: [f32; 64] = std::array::from_fn(|i| reference[i] as f32 * mult[i]);
            idct(&mut b);
            for i in 0..64 {
                assert!((b[i] - px[i]).abs() < 0.01, "sample {i}: {} vs {}", b[i], px[i]);
            }
        }
    }

    #[test]
    fn flat_colors_are_nearly_exact() {
        let (w, h) = (40, 24);
        for color in [[0, 0, 0], [255, 255, 255], [0, 0, 255], [0, 255, 0], [255, 0, 0], [128, 128, 128], [99, 200, 12], [37, 61, 240]] {
            let src: Vec<u8> = (0..w * h).flat_map(|_| [color[0], color[1], color[2], 255]).collect();
            let r = Rect { x: 0, y: 0, w, h };
            for (q, tolerance) in [(100, 1), (80, 2), (50, 3)] {
                let (fb, len) = roundtrip(&src, w, r, q);
                let worst = src.iter().zip(&fb).map(|(&a, &b)| a.abs_diff(b)).max().unwrap();
                assert!(worst <= tolerance, "color {color:?} q{q}: off by {worst}");
                // DC-only blocks cost a handful of bits each.
                assert!(len <= 1 + 6 * 6, "flat 40x24 took {len} bytes");
            }
        }
    }

    #[test]
    fn photographic_psnr() {
        let (w, h) = (256, 192);
        let src = photo(w, h, 7);
        let r = Rect { x: 0, y: 0, w, h };
        let raw = w * h * 3;
        let mut last = 0;
        for (q, min_db) in [(50, 30.0), (80, 34.0), (95, 40.0)] {
            let (fb, len) = roundtrip(&src, w, r, q);
            let db = psnr(&src, &fb, w, r);
            println!("q{q}: {db:.2} dB, {len} bytes ({:.1}x smaller than 24-bit raw)", raw as f64 / len as f64);
            assert!(db >= min_db, "q{q}: {db:.2} dB < {min_db}");
            assert!(len > last && len < raw / 2);
            last = len;
            assert!(fb.as_chunks::<4>().0.iter().all(|p| p[3] == 255));
        }
    }

    #[test]
    fn odd_sizes_and_offsets() {
        for (w, h) in [(1, 1), (17, 9), (64, 64), (333, 250), (16, 33), (2, 300)] {
            for (ox, oy) in [(0, 0), (5, 3), (13, 7)] {
                let (fw, fh) = (w + ox + 4, h + oy + 2);
                let src = photo(fw, fh, (w * 31 + h) as u32);
                let r = Rect { x: ox, y: oy, w, h };
                let mut data = Vec::new();
                encode(&src, fw, r, 80, &mut data);
                let mut fb = vec![0x5au8; fw * fh * 4];
                decode(&data, &mut fb, fw, r).unwrap();
                for y in 0..fh {
                    for x in 0..fw {
                        let p = &fb[(y * fw + x) * 4..][..4];
                        if (ox..ox + w).contains(&x) && (oy..oy + h).contains(&y) {
                            assert_eq!(p[3], 255);
                        } else {
                            assert_eq!(p, [0x5a; 4], "pixel ({x},{y}) outside {r:?} was written");
                        }
                    }
                }
                let db = psnr(&src, &fb, fw, r);
                assert!(db >= 30.0, "{w}x{h}+{ox}+{oy}: {db:.2} dB");
            }
        }
    }

    #[test]
    fn rejects_bad_payloads() {
        let (w, h) = (80, 48);
        let src = photo(w, h, 3);
        let r = Rect { x: 3, y: 5, w: 70, h: 40 };
        let mut good = Vec::new();
        encode(&src, w, r, 75, &mut good);
        let mut fb = vec![0u8; w * h * 4];
        decode(&good, &mut fb, w, r).unwrap();

        for n in 0..good.len() {
            assert!(decode(&good[..n], &mut fb, w, r).is_err(), "truncated to {n} bytes was accepted");
        }
        for extra in [0x00, 0xff] {
            let mut long = good.clone();
            long.push(extra);
            assert!(decode(&long, &mut fb, w, r).is_err());
        }
        for q in [0, 101, 255] {
            let mut bad = good.clone();
            bad[0] = q;
            assert!(decode(&bad, &mut fb, w, r).is_err());
        }
        // Rectangles outside the frame, empty ones and overflowing ones.
        for bad in [
            Rect { x: 11, y: 0, w: 70, h: 40 },
            Rect { x: 0, y: 9, w: 70, h: 40 },
            Rect { x: 0, y: 0, w: 0, h: 40 },
            Rect { x: usize::MAX, y: 0, w: 2, h: 2 },
            Rect { x: 0, y: usize::MAX, w: 2, h: 2 },
        ] {
            assert!(decode(&good, &mut fb, w, bad).is_err());
        }
        assert!(decode(&good, &mut [], 0, r).is_err());
        assert!(decode(&good, &mut fb, usize::MAX, r).is_err());
    }

    #[test]
    fn hostile_payloads_never_panic() {
        let (w, h) = (96, 64);
        let src = photo(w, h, 5);
        let r = Rect { x: 8, y: 4, w: 80, h: 50 };
        let mut good = Vec::new();
        encode(&src, w, r, 60, &mut good);
        let mut fb = vec![0u8; w * h * 4];
        // Damage to magnitude bits leaves a well-formed scan, so some mutants decode to a slightly
        // different image; integrity is the record layer's job. They must never panic.
        let mut s = 0x1234_5678u32;
        for i in 0..4000 {
            let mut m = good.clone();
            for _ in 0..1 + rng(&mut s) % 4 {
                let at = 1 + rng(&mut s) as usize % (m.len() - 1);
                match i % 3 {
                    0 => m[at] ^= 1 << (rng(&mut s) % 8),
                    1 => m[at] = rng(&mut s) as u8,
                    _ => m.truncate(at.max(2)),
                }
            }
            let _ = decode(&m, &mut fb, w, r);
        }
        for n in 0..3000 {
            let mut data: Vec<u8> = (0..n % 400).map(|_| rng(&mut s) as u8).collect();
            if let Some(q) = data.first_mut() {
                *q = 1 + *q % 100;
            }
            let _ = decode(&data, &mut fb, w, r);
        }
    }

    #[test]
    fn decoding_work_is_bounded_by_the_input() {
        // A huge rectangle with a tiny scan fails after a few blocks instead of filling it.
        let (w, h) = (2048, 2048);
        let mut fb = vec![0u8; w * h * 4];
        let r = Rect { x: 0, y: 0, w, h };
        let t = std::time::Instant::now();
        for scan in [&[80u8, 0x00, 0x00][..], &[80, 0xff, 0xff], &[80]] {
            assert!(decode(scan, &mut fb, w, r).is_err());
        }
        assert!(t.elapsed().as_millis() < 100);
        assert!(fb[64 * 4 * w..].iter().all(|&b| b == 0), "decoder ran far past its input");
    }

    /// Wraps a payload in a baseline JFIF file so an independent JPEG decoder can check it.
    fn jfif(payload: &[u8], w: usize, h: usize) -> Vec<u8> {
        let segment = |f: &mut Vec<u8>, marker: u8, body: &[u8]| {
            f.extend_from_slice(&[0xff, marker]);
            f.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
            f.extend_from_slice(body);
        };
        let mut f = vec![0xff, 0xd8];
        segment(&mut f, 0xe0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
        let mut dqt = Vec::new();
        for (id, base) in [(0u8, &LUMA_Q), (1, &CHROMA_Q)] {
            let q = quant_table(base, payload[0]);
            dqt.push(id);
            dqt.extend(ZIGZAG.iter().map(|&n| q[n as usize] as u8));
        }
        segment(&mut f, 0xdb, &dqt);
        let mut sof = vec![8];
        sof.extend_from_slice(&(h as u16).to_be_bytes());
        sof.extend_from_slice(&(w as u16).to_be_bytes());
        sof.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
        segment(&mut f, 0xc0, &sof);
        let mut dht = Vec::new();
        for (class, bits, vals) in [
            (0x00u8, &LUMA_DC_BITS, &DC_VALS[..]),
            (0x10, &LUMA_AC_BITS, &LUMA_AC_VALS[..]),
            (0x01, &CHROMA_DC_BITS, &DC_VALS[..]),
            (0x11, &CHROMA_AC_BITS, &CHROMA_AC_VALS[..]),
        ] {
            dht.push(class);
            dht.extend_from_slice(bits);
            dht.extend_from_slice(vals);
        }
        segment(&mut f, 0xc4, &dht);
        segment(&mut f, 0xda, &[3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]);
        for &b in &payload[1..] {
            f.push(b);
            if b == 0xff {
                f.push(0); // byte stuffing
            }
        }
        f.extend_from_slice(&[0xff, 0xd9]);
        f
    }

    /// Writes `lossy-check.{jpg,src.rgb,dec.rgb}` (333x250) to `$SRDP_JFIF_DIR` (default: the
    /// temp dir) for comparison with an independent decoder, e.g.
    /// `ffmpeg -i lossy-check.jpg -f rawvideo -pix_fmt rgb24 lossy-check.ffmpeg.rgb`.
    #[test]
    #[ignore]
    fn export_jfif_for_external_check() {
        let (w, h) = (333, 250);
        let src = photo(w, h, 11);
        let r = Rect { x: 0, y: 0, w, h };
        let mut data = Vec::new();
        encode(&src, w, r, 80, &mut data);
        let mut fb = vec![0u8; w * h * 4];
        decode(&data, &mut fb, w, r).unwrap();
        let rgb = |p: &[u8]| p.as_chunks::<4>().0.iter().flat_map(|p| [p[2], p[1], p[0]]).collect::<Vec<u8>>();
        let dir = std::env::var_os("SRDP_JFIF_DIR").map_or_else(std::env::temp_dir, Into::into);
        std::fs::write(dir.join("lossy-check.jpg"), jfif(&data, w, h)).unwrap();
        std::fs::write(dir.join("lossy-check.src.rgb"), rgb(&src)).unwrap();
        std::fs::write(dir.join("lossy-check.dec.rgb"), rgb(&fb)).unwrap();
        println!("wrote {w}x{h} check files to {}", dir.display());
    }
}
