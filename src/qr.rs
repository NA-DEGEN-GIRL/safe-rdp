//! QR codes for moving the pre-shared key to a phone: an encoder for byte-mode payloads and
//! a decoder for camera frames, after ISO/IEC 18004 and limited to versions 1-10 (up to 57x57
//! modules), which is far more than a 70-byte key needs.
//!
//! The decoder is the classic pipeline: local-mean binarization, finder patterns located by
//! their 1:1:3:1:1 run lengths, a homography from the three finders and the bottom-right
//! alignment pattern, module sampling, format and version information, Reed-Solomon
//! correction and segment parsing. Every stage is bounded by the image size and anything it
//! cannot read is `None`: Reed-Solomon either corrects a block or rejects it, never guesses.

use std::ops::{Add, Mul, Sub};

use crate::bail;
use crate::util::{Result, SecureVec};

/// Error-correction level: roughly 7, 15, 25 and 30 percent of codewords recoverable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ecc {
    L,
    M,
    Q,
    H,
}

const LEVELS: [Ecc; 4] = [Ecc::L, Ecc::M, Ecc::Q, Ecc::H];
const MAX_VERSION: usize = 10;

/// Error-correction codewords per block, by level (L, M, Q, H) and version (index 0 unused).
const ECC_PER_BLOCK: [[u8; 11]; 4] = [
    [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18],
    [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26],
    [0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24],
    [0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28],
];

/// Number of Reed-Solomon blocks, by level and version.
const BLOCKS: [[u8; 11]; 4] = [
    [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4],
    [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5],
    [0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8],
    [0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8],
];

/// Alignment pattern centre coordinates, shared by rows and columns, by version.
const ALIGN: [&[usize]; 11] = [
    &[], &[], &[6, 18], &[6, 22], &[6, 26], &[6, 30], &[6, 34], &[6, 22, 38], &[6, 24, 42], &[6, 26, 46], &[6, 28, 50],
];

impl Ecc {
    /// The two format-information bits, which the standard assigns out of order.
    fn format_bits(self) -> u32 {
        match self {
            Ecc::L => 1,
            Ecc::M => 0,
            Ecc::Q => 3,
            Ecc::H => 2,
        }
    }
}

/// GF(256) antilogarithms (doubled, so a product of two logs needs no reduction) and
/// logarithms over the QR field polynomial x^8 + x^4 + x^3 + x^2 + 1.
static GF: ([u8; 512], [u8; 256]) = {
    let (mut exp, mut log) = ([0u8; 512], [0u8; 256]);
    let (mut x, mut i) = (1u32, 0);
    while i < 255 {
        exp[i] = x as u8;
        exp[i + 255] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
        i += 1;
    }
    (exp, log)
};

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 { 0 } else { GF.0[GF.1[a as usize] as usize + GF.1[b as usize] as usize] }
}

/// `a / b`; callers guarantee `b != 0`.
fn div(a: u8, b: u8) -> u8 {
    if a == 0 { 0 } else { GF.0[GF.1[a as usize] as usize + 255 - GF.1[b as usize] as usize] }
}

/// alpha^e.
fn alpha(e: usize) -> u8 {
    GF.0[e % 255]
}

fn gf_pow(x: u8, e: usize) -> u8 {
    if x == 0 { u8::from(e == 0) } else { alpha(GF.1[x as usize] as usize * e) }
}

/// The generator polynomial of degree `degree` (roots alpha^0..alpha^(degree-1)), highest
/// coefficient first and the leading 1 omitted.
fn rs_divisor(degree: usize) -> Vec<u8> {
    let mut poly = vec![0u8; degree];
    poly[degree - 1] = 1;
    let mut root = 1u8;
    for _ in 0..degree {
        for j in 0..degree {
            poly[j] = mul(poly[j], root);
            if j + 1 < degree {
                poly[j] ^= poly[j + 1];
            }
        }
        root = mul(root, 2);
    }
    poly
}

fn rs_remainder(data: &[u8], divisor: &[u8]) -> Vec<u8> {
    let mut rem = vec![0u8; divisor.len()];
    for &b in data {
        let factor = b ^ rem.remove(0);
        rem.push(0);
        for (r, &d) in rem.iter_mut().zip(divisor) {
            *r ^= mul(d, factor);
        }
    }
    rem
}

/// Corrects `block` (data then ECC codewords, highest degree first) in place, returning false
/// when it holds more than `nsym / 2` errors. Syndromes, Berlekamp-Massey for the error
/// locator, Chien search for the positions and Forney for the values; the result is checked
/// again, so a locator whose roots are not all inside the block can never pass as a repair.
fn rs_correct(block: &mut [u8], nsym: usize) -> bool {
    let n = block.len();
    let syndromes = |b: &[u8]| -> Vec<u8> {
        (0..nsym).map(|j| b.iter().fold(0, |acc, &c| mul(acc, alpha(j)) ^ c)).collect()
    };
    let s = syndromes(block);
    if s.iter().all(|&x| x == 0) {
        return true;
    }
    // Berlekamp-Massey; polynomials are lowest degree first.
    let mut lambda = vec![0u8; nsym + 1];
    lambda[0] = 1;
    let mut prev = lambda.clone();
    let (mut errors, mut shift, mut prev_d) = (0usize, 1usize, 1u8);
    for k in 0..nsym {
        let d = (1..=errors).fold(s[k], |acc, i| acc ^ mul(lambda[i], s[k - i]));
        if d == 0 {
            shift += 1;
            continue;
        }
        let coef = div(d, prev_d);
        let saved = lambda.clone();
        for (i, &p) in prev.iter().take(nsym + 1 - shift).enumerate() {
            lambda[i + shift] ^= mul(coef, p);
        }
        if 2 * errors <= k {
            errors = k + 1 - errors;
            prev = saved;
            prev_d = d;
            shift = 1;
        } else {
            shift += 1;
        }
    }
    if 2 * errors > nsym {
        return false;
    }
    let lambda = &lambda[..=errors];
    let eval = |p: &[u8], x: u8| p.iter().rev().fold(0, |acc, &c| mul(acc, x) ^ c);
    // The error evaluator S(x) * lambda(x) mod x^nsym.
    let omega: Vec<u8> = (0..nsym)
        .map(|k| (0..=k.min(errors)).fold(0, |acc, i| acc ^ mul(lambda[i], s[k - i])))
        .collect();
    let mut found = 0;
    for i in 0..n {
        let x_inv = alpha(255 - i);
        if eval(lambda, x_inv) != 0 {
            continue;
        }
        // In characteristic 2 only the odd terms survive differentiation.
        let deriv = (1..=errors).step_by(2).fold(0, |acc, j| acc ^ mul(lambda[j], gf_pow(x_inv, j - 1)));
        if deriv == 0 {
            return false;
        }
        block[n - 1 - i] ^= mul(alpha(i), div(eval(&omega, x_inv), deriv));
        found += 1;
    }
    found == errors && syndromes(block).iter().all(|&x| x == 0)
}

/// Codewords in a symbol of `version`, data and ECC together, without the remainder bits.
fn raw_codewords(version: usize) -> usize {
    let mut bits = (16 * version + 128) * version + 64;
    if version >= 2 {
        let n = version / 7 + 2;
        bits -= (25 * n - 10) * n - 55;
        if version >= 7 {
            bits -= 36;
        }
    }
    bits / 8
}

/// How a symbol's codewords split into Reed-Solomon blocks: `short` blocks of `short_data`
/// data codewords, then the rest with one more, each followed by `ecc` ECC codewords.
#[derive(Clone, Copy)]
struct Layout {
    blocks: usize,
    short: usize,
    short_data: usize,
    ecc: usize,
}

impl Layout {
    fn new(version: usize, ecc: Ecc) -> Layout {
        let raw = raw_codewords(version);
        let blocks = BLOCKS[ecc as usize][version] as usize;
        let per = ECC_PER_BLOCK[ecc as usize][version] as usize;
        Layout { blocks, short: blocks - raw % blocks, short_data: raw / blocks - per, ecc: per }
    }

    fn data_len(self, block: usize) -> usize {
        self.short_data + usize::from(block >= self.short)
    }

    fn data_codewords(self) -> usize {
        self.blocks * self.short_data + self.blocks - self.short
    }

    /// (block, index) of each codeword in transmission order: data codewords column by column
    /// across the blocks (the short ones have no last column), then the ECC codewords.
    fn order(self) -> impl Iterator<Item = (usize, usize)> {
        let data = (0..=self.short_data).flat_map(move |i| {
            (0..self.blocks).filter(move |&b| i < self.data_len(b)).map(move |b| (b, i))
        });
        let ecc = (0..self.ecc).flat_map(move |i| (0..self.blocks).map(move |b| (b, self.data_len(b) + i)));
        data.chain(ecc)
    }
}

/// Length of a segment's character count field: (numeric, alphanumeric, byte) by mode bits.
fn count_bits(version: usize, mode: u32) -> usize {
    let wide = version >= 10;
    match mode {
        1 => [10, 12][usize::from(wide)],
        2 => [9, 11][usize::from(wide)],
        _ => [8, 16][usize::from(wide)],
    }
}

fn byte_capacity(version: usize, ecc: Ecc) -> usize {
    (Layout::new(version, ecc).data_codewords() * 8 - 4 - count_bits(version, 4)) / 8
}

/// The 15-bit format information: level and mask under BCH(15,5), XORed with 0x5412 so that
/// it is never all light.
fn format_bits(ecc: Ecc, mask: u8) -> u32 {
    let data = (ecc.format_bits() << 3) | u32::from(mask);
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    ((data << 10) | rem) ^ 0x5412
}

/// The 18-bit version information (Golay(18,6)), present from version 7.
fn version_bits(version: usize) -> u32 {
    let mut rem = version as u32;
    for _ in 0..12 {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1f25);
    }
    ((version as u32) << 12) | rem
}

/// (x, y) of format bit `i` (0 = least significant) in each of its two copies.
fn format_pos(size: usize, i: usize) -> [(usize, usize); 2] {
    let first = match i {
        0..=5 => (8, i),
        6 => (8, 7),
        7 => (8, 8),
        8 => (7, 8),
        _ => (14 - i, 8),
    };
    let second = if i < 8 { (size - 1 - i, 8) } else { (8, size - 15 + i) };
    [first, second]
}

/// (x, y) of version bit `i` in the top-right and bottom-left copies.
fn version_pos(size: usize, i: usize) -> [(usize, usize); 2] {
    let (a, b) = (size - 11 + i % 3, i / 3);
    [(a, b), (b, a)]
}

fn mask_bit(mask: u8, x: usize, y: usize) -> bool {
    let (sum, product) = (x + y, x * y);
    match mask {
        0 => sum.is_multiple_of(2),
        1 => y.is_multiple_of(2),
        2 => x.is_multiple_of(3),
        3 => sum.is_multiple_of(3),
        4 => (x / 3 + y / 2).is_multiple_of(2),
        5 => product % 2 + product % 3 == 0,
        6 => (product % 2 + product % 3).is_multiple_of(2),
        _ => (sum % 2 + product % 3).is_multiple_of(2),
    }
}

/// A symbol under construction, or the template the decoder reads data modules against.
#[derive(Clone)]
struct Grid {
    size: usize,
    dark: Vec<bool>,
    function: Vec<bool>,
}

impl Grid {
    /// The function patterns of `version`, with the format areas reserved (light).
    fn new(version: usize) -> Grid {
        let size = 17 + 4 * version;
        let mut g = Grid { size, dark: vec![false; size * size], function: vec![false; size * size] };
        for i in 0..size {
            g.set(6, i, i.is_multiple_of(2));
            g.set(i, 6, i.is_multiple_of(2));
        }
        for (cx, cy) in [(3, 3), (size - 4, 3), (3, size - 4)] {
            for dy in -4..=4isize {
                for dx in -4..=4isize {
                    let (x, y) = (cx.wrapping_add_signed(dx), cy.wrapping_add_signed(dy));
                    if x < size && y < size {
                        let ring = dx.abs().max(dy.abs());
                        g.set(x, y, ring != 2 && ring != 4);
                    }
                }
            }
        }
        let align = ALIGN[version];
        for &ay in align {
            for &ax in align {
                // The three positions that would overlap finder patterns are left out.
                if (ax < 9 || ax + 9 >= size) && ay < 9 || ax < 9 && ay + 9 >= size {
                    continue;
                }
                for dy in -2..=2isize {
                    for dx in -2..=2isize {
                        let dark = dx.abs().max(dy.abs()) != 1;
                        g.set(ax.wrapping_add_signed(dx), ay.wrapping_add_signed(dy), dark);
                    }
                }
            }
        }
        for i in 0..15 {
            for (x, y) in format_pos(size, i) {
                g.set(x, y, false);
            }
        }
        g.set(8, size - 8, true);
        if version >= 7 {
            let bits = version_bits(version);
            for i in 0..18 {
                for (x, y) in version_pos(size, i) {
                    g.set(x, y, (bits >> i) & 1 != 0);
                }
            }
        }
        g
    }

    fn set(&mut self, x: usize, y: usize, dark: bool) {
        self.dark[y * self.size + x] = dark;
        self.function[y * self.size + x] = true;
    }

    /// Indices of the data modules in the order codeword bits fill them: two-module columns
    /// from the right, alternately upward and downward, stepping over the vertical timing line.
    fn data_order(&self) -> Vec<usize> {
        let n = self.size;
        let mut order = Vec::with_capacity(n * n);
        let mut right = n - 1;
        loop {
            if right == 6 {
                right = 5;
            }
            let upward = (right + 1) & 2 == 0;
            for vert in 0..n {
                let y = if upward { n - 1 - vert } else { vert };
                for x in [right, right - 1] {
                    if !self.function[y * n + x] {
                        order.push(y * n + x);
                    }
                }
            }
            if right < 2 {
                return order;
            }
            right -= 2;
        }
    }

    fn apply_mask(&mut self, mask: u8) {
        for i in 0..self.dark.len() {
            if !self.function[i] {
                self.dark[i] ^= mask_bit(mask, i % self.size, i / self.size);
            }
        }
    }

    fn draw_format(&mut self, ecc: Ecc, mask: u8) {
        let bits = format_bits(ecc, mask);
        for i in 0..15 {
            for (x, y) in format_pos(self.size, i) {
                self.set(x, y, (bits >> i) & 1 != 0);
            }
        }
    }

    /// The standard's mask penalty: long runs, 2x2 blocks, finder look-alikes and imbalance.
    fn penalty(&self) -> usize {
        let n = self.size;
        let mut score = 0;
        let mut line = vec![false; n];
        for transposed in [false, true] {
            for a in 0..n {
                for (b, m) in line.iter_mut().enumerate() {
                    *m = self.dark[if transposed { b * n + a } else { a * n + b }];
                }
                let mut run = 1;
                for b in 1..=n {
                    if b < n && line[b] == line[b - 1] {
                        run += 1;
                    } else {
                        score += if run >= 5 { run - 2 } else { 0 };
                        run = 1;
                    }
                }
                // Outside the symbol counts as light.
                let light = |from: usize, to: usize| (from..to.min(n)).all(|i| !line[i]);
                for s in 0..n - 6 {
                    if line[s..s + 7] == [true, false, true, true, true, false, true]
                        && (light(s.saturating_sub(4), s) || light(s + 7, s + 11))
                    {
                        score += 40;
                    }
                }
            }
        }
        for y in 1..n {
            for x in 1..n {
                let c = self.dark[y * n + x];
                let above = (y - 1) * n + x;
                if c == self.dark[y * n + x - 1] && c == self.dark[above] && c == self.dark[above - 1] {
                    score += 3;
                }
            }
        }
        let dark = self.dark.iter().filter(|&&d| d).count();
        score + (dark * 100).abs_diff(n * n * 50) / (n * n) / 5 * 10
    }
}

#[derive(Default)]
struct Bits(Vec<bool>);

/// Overwrites modules or bits: what the encoder handles is the key, drawn.
fn wipe_bools(v: &mut [bool]) {
    for b in v.iter_mut() {
        unsafe { std::ptr::write_volatile(b, false) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

impl Drop for Bits {
    fn drop(&mut self) {
        wipe_bools(&mut self.0);
    }
}

impl Drop for Grid {
    fn drop(&mut self) {
        wipe_bools(&mut self.dark);
    }
}

impl Drop for QrCode {
    fn drop(&mut self) {
        wipe_bools(&mut self.modules);
    }
}

fn wipe_blocks(blocks: &mut [Vec<u8>]) {
    for b in blocks {
        crate::util::wipe(b);
    }
}

impl Bits {
    fn push(&mut self, value: u32, n: usize) {
        self.0.extend((0..n).rev().map(|i| (value >> i) & 1 != 0));
    }
}

/// Terminates and pads a bit stream to the data capacity of `layout` (the caller has checked
/// it fits).
fn data_codewords(layout: Layout, mut bits: Bits) -> Vec<u8> {
    let capacity = layout.data_codewords() * 8;
    bits.push(0, (capacity - bits.0.len()).min(4));
    bits.push(0, bits.0.len().wrapping_neg() % 8);
    let byte = |c: &[bool]| c.iter().fold(0, |a, &b| (a << 1) | u8::from(b));
    let mut bytes: Vec<u8> = bits.0.chunks(8).map(byte).collect();
    for pad in [0xec, 0x11].into_iter().cycle() {
        if bytes.len() >= layout.data_codewords() {
            break;
        }
        bytes.push(pad);
    }
    bytes
}

/// Splits data codewords into blocks, each with its ECC codewords appended.
fn rs_blocks(layout: Layout, data: &[u8]) -> Vec<Vec<u8>> {
    let divisor = rs_divisor(layout.ecc);
    let mut rest = data;
    (0..layout.blocks)
        .map(|b| {
            let (block, tail) = rest.split_at(layout.data_len(b));
            rest = tail;
            [block, &rs_remainder(block, &divisor)].concat()
        })
        .collect()
}

fn interleave(layout: Layout, blocks: &[Vec<u8>]) -> Vec<u8> {
    layout.order().map(|(b, i)| blocks[b][i]).collect()
}

fn deinterleave(layout: Layout, codewords: &[u8]) -> Vec<Vec<u8>> {
    let mut blocks: Vec<_> = (0..layout.blocks).map(|b| vec![0; layout.data_len(b) + layout.ecc]).collect();
    for ((b, i), &c) in layout.order().zip(codewords) {
        blocks[b][i] = c;
    }
    blocks
}

/// Smallest version (1..=10) that fits `data` in byte mode at `ecc`; best mask by the standard
/// penalty rules.
pub fn encode(data: &[u8], ecc: Ecc) -> Result<QrCode> {
    let Some(version) = (1..=MAX_VERSION).find(|&v| data.len() <= byte_capacity(v, ecc)) else {
        bail!("{} bytes do not fit a version {MAX_VERSION} QR code at level {ecc:?}", data.len());
    };
    Ok(QrCode::from_bits(version, ecc, byte_segment(version, data), None))
}

fn byte_segment(version: usize, data: &[u8]) -> Bits {
    let mut bits = Bits::default();
    bits.push(4, 4);
    bits.push(data.len() as u32, count_bits(version, 4));
    for &b in data {
        bits.push(b.into(), 8);
    }
    bits
}

/// An encoded symbol: `size` x `size` modules, dark or light.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrCode {
    size: usize,
    modules: Vec<bool>,
}

impl QrCode {
    fn from_bits(version: usize, ecc: Ecc, bits: Bits, mask: Option<u8>) -> QrCode {
        let layout = Layout::new(version, ecc);
        let mut data = data_codewords(layout, bits);
        let mut blocks = rs_blocks(layout, &data);
        let mut codewords = interleave(layout, &blocks);
        let code = QrCode::from_codewords(version, ecc, &codewords, mask);
        crate::util::wipe(&mut data);
        wipe_blocks(&mut blocks);
        crate::util::wipe(&mut codewords);
        code
    }

    /// Places the final codeword sequence and applies `mask`, or the one with the lowest penalty.
    fn from_codewords(version: usize, ecc: Ecc, codewords: &[u8], mask: Option<u8>) -> QrCode {
        let mut grid = Grid::new(version);
        for (k, idx) in grid.data_order().into_iter().enumerate() {
            grid.dark[idx] = codewords.get(k / 8).is_some_and(|c| (c << (k % 8)) & 0x80 != 0);
        }
        let mut best = mask
            .map_or(0..8, |m| m..m + 1)
            .map(|m| {
                let mut g = grid.clone();
                g.apply_mask(m);
                g.draw_format(ecc, m);
                g
            })
            .min_by_key(Grid::penalty)
            .unwrap_or(grid);
        QrCode { size: best.size, modules: std::mem::take(&mut best.dark) }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// Whether module (x, y) is dark; anything outside the symbol is light (quiet zone).
    pub fn dark(&self, x: usize, y: usize) -> bool {
        x < self.size && y < self.size && self.modules[y * self.size + x]
    }

    /// Terminal rendering with Unicode half blocks, two module rows per text line, with a
    /// 4-module quiet zone. Colours are set explicitly (black on bright white) because a dark
    /// terminal theme would otherwise invert the code, and reset at each line end so they do
    /// not run on past it when the terminal wraps or scrolls.
    pub fn to_terminal(&self) -> String {
        const QUIET: usize = 4;
        let total = self.size + 2 * QUIET;
        let dark = |x: usize, y: usize| self.dark(x.wrapping_sub(QUIET), y.wrapping_sub(QUIET));
        // Sized up front: a buffer that grows leaves copies behind, which the caller cannot wipe.
        let mut out = String::with_capacity(total * total.div_ceil(2) * 16 + total * 8);
        for y in (0..total).step_by(2) {
            let mut current = None;
            for x in 0..total {
                let colours = (dark(x, y), dark(x, y + 1));
                if current != Some(colours) {
                    let fg = if colours.0 { 30 } else { 97 };
                    let bg = if colours.1 { 40 } else { 107 };
                    out.push_str(&format!("\x1b[{fg};{bg}m"));
                    current = Some(colours);
                }
                out.push('▀');
            }
            out.push_str("\x1b[0m\n");
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Pt {
    x: f64,
    y: f64,
}

impl Pt {
    fn new(x: f64, y: f64) -> Pt {
        Pt { x, y }
    }
    fn norm(self) -> f64 {
        self.x.hypot(self.y)
    }
    fn dot(self, o: Pt) -> f64 {
        self.x * o.x + self.y * o.y
    }
    fn cross(self, o: Pt) -> f64 {
        self.x * o.y - self.y * o.x
    }
}

impl Add for Pt {
    type Output = Pt;
    fn add(self, o: Pt) -> Pt {
        Pt::new(self.x + o.x, self.y + o.y)
    }
}

impl Sub for Pt {
    type Output = Pt;
    fn sub(self, o: Pt) -> Pt {
        Pt::new(self.x - o.x, self.y - o.y)
    }
}

impl Mul<f64> for Pt {
    type Output = Pt;
    fn mul(self, k: f64) -> Pt {
        Pt::new(self.x * k, self.y * k)
    }
}

/// A plane projective transform as a row-major 3x3 matrix.
struct Homography([f64; 9]);

impl Homography {
    /// Maps the unit square's corners (0,0), (1,0), (1,1), (0,1) onto `q` (Heckbert's closed form).
    fn from_square(q: [Pt; 4]) -> Option<[f64; 9]> {
        let [p0, p1, p2, p3] = q;
        let d3 = p0 - p1 + p2 - p3;
        let (d1, d2) = (p1 - p2, p3 - p2);
        let den = d1.cross(d2);
        if den.abs() < 1e-9 {
            return None;
        }
        let g = d3.cross(d2) / den;
        let h = d1.cross(d3) / den;
        Some([
            p1.x - p0.x + g * p1.x,
            p3.x - p0.x + h * p3.x,
            p0.x,
            p1.y - p0.y + g * p1.y,
            p3.y - p0.y + h * p3.y,
            p0.y,
            g,
            h,
            1.0,
        ])
    }

    /// The transform taking each `from[i]` to `to[i]`; both quadrilaterals in cyclic order.
    fn quad_to_quad(from: [Pt; 4], to: [Pt; 4]) -> Option<Homography> {
        let a = Homography::from_square(from)?;
        let b = Homography::from_square(to)?;
        // The adjugate inverts `a` up to a scale factor, which a homography ignores.
        let inv = [
            a[4] * a[8] - a[5] * a[7],
            a[2] * a[7] - a[1] * a[8],
            a[1] * a[5] - a[2] * a[4],
            a[5] * a[6] - a[3] * a[8],
            a[0] * a[8] - a[2] * a[6],
            a[2] * a[3] - a[0] * a[5],
            a[3] * a[7] - a[4] * a[6],
            a[1] * a[6] - a[0] * a[7],
            a[0] * a[4] - a[1] * a[3],
        ];
        Some(Homography(std::array::from_fn(|i| (0..3).map(|k| b[i / 3 * 3 + k] * inv[k * 3 + i % 3]).sum())))
    }

    /// The image of `p`, non-finite for points mapped to infinity (which `Binary::at` rejects).
    fn map(&self, p: Pt) -> Pt {
        let m = &self.0;
        let w = m[6] * p.x + m[7] * p.y + m[8];
        Pt::new((m[0] * p.x + m[1] * p.y + m[2]) / w, (m[3] * p.x + m[4] * p.y + m[5]) / w)
    }
}

/// A thresholded frame; pixel centres are at integer coordinates.
struct Binary {
    width: usize,
    height: usize,
    dark: Vec<bool>,
}

impl Binary {
    /// Marks a pixel dark when it and its neighbours (which tames sensor noise) are a little
    /// below the mean of a wide window around it (which follows uneven lighting). The window
    /// is a sixteenth of the frame, wider than a large code's finder centre, so that the centre
    /// does not wash out. The summed-area table wraps: every window sum fits in u32, so
    /// differences of wrapped prefix sums are still exact.
    fn new(luma: &[u8], width: usize, height: usize, stride: usize) -> Binary {
        let w1 = width + 1;
        let mut sat = vec![0u32; w1 * (height + 1)];
        for y in 0..height {
            let (done, rest) = sat.split_at_mut((y + 1) * w1);
            let (above, row) = (&done[y * w1..], &mut rest[..w1]);
            let mut acc = 0u32;
            for (x, &p) in luma[y * stride..y * stride + width].iter().enumerate() {
                acc = acc.wrapping_add(u32::from(p));
                row[x + 1] = above[x + 1].wrapping_add(acc);
            }
        }
        let r = (width.min(height) / 16).max(7);
        let mut dark = vec![false; width * height];
        let mut columns = vec![0u32; w1];
        for (y, out) in dark.chunks_exact_mut(width).enumerate() {
            let (y0, y1) = (y.saturating_sub(r), (y + r + 1).min(height));
            // Column sums over the window's rows, so each window sum is one subtraction.
            let (top, bottom) = (&sat[y0 * w1..(y0 + 1) * w1], &sat[y1 * w1..(y1 + 1) * w1]);
            for ((c, &b), &t) in columns.iter_mut().zip(bottom).zip(top) {
                *c = b.wrapping_sub(t);
            }
            let line = |y: usize| &luma[y * stride..y * stride + width];
            let (up, mid, down) = (line(y.saturating_sub(1)), line(y), line((y + 1).min(height - 1)));
            for (x, d) in out.iter_mut().enumerate() {
                let (x0, x1) = (x.saturating_sub(r), (x + r + 1).min(width));
                let sum = columns[x1].wrapping_sub(columns[x0]);
                // Weight 4 for the pixel and 1 for each neighbour: noise drops by almost half
                // while a lone dark module two pixels wide still stays dark.
                let local = 4 * u32::from(mid[x])
                    + u32::from(up[x])
                    + u32::from(down[x])
                    + u32::from(mid[x.saturating_sub(1)])
                    + u32::from(mid[(x + 1).min(width - 1)]);
                let area = ((x1 - x0) * (y1 - y0)) as u64;
                *d = u64::from(local) * area * 32 < u64::from(sum) * 8 * 31;
            }
        }
        Binary { width, height, dark }
    }

    fn at(&self, p: Pt) -> Option<bool> {
        let (x, y) = (p.x.round(), p.y.round());
        // Written so that NaN fails every comparison.
        if x >= 0.0 && y >= 0.0 && x < self.width as f64 && y < self.height as f64 {
            Some(self.dark[y as usize * self.width + x as usize])
        } else {
            None
        }
    }

    /// Measures the runs through `c` along the unit vector `dir`, both ways, and checks them
    /// for a finder's 1:1:3:1:1. Returns the pattern centre's offset along `dir` and its
    /// length; no run may exceed `limit` pixels, which bounds the walk.
    fn cross_check(&self, c: Pt, dir: Pt, limit: u32, tolerance: f64) -> Option<(f64, f64)> {
        let run = |from: i64, step: i64, want: bool| {
            let mut n = 0;
            while n <= limit && self.at(c + dir * (from + step * i64::from(n)) as f64) == Some(want) {
                n += 1;
            }
            n
        };
        let back2 = run(0, -1, true);
        let back1 = run(-i64::from(back2), -1, false);
        let back0 = run(-i64::from(back2 + back1), -1, true);
        let fwd2 = run(1, 1, true);
        let fwd3 = run(1 + i64::from(fwd2), 1, false);
        let fwd4 = run(1 + i64::from(fwd2 + fwd3), 1, true);
        let runs = [back0, back1, back2 + fwd2, fwd3, fwd4];
        if runs.iter().any(|&r| r == 0 || r > limit) || !finder_ratio(&runs, tolerance) {
            return None;
        }
        let first = 1.0 - f64::from(back0 + back1 + back2);
        let last = f64::from(fwd2 + fwd3 + fwd4);
        Some(((first + last) / 2.0, last - first + 1.0))
    }
}

/// Whether five run lengths look like a finder's 1:1:3:1:1 cross-section; `tolerance` is
/// the allowed deviation per module, plus half a pixel for quantisation.
fn finder_ratio(runs: &[u32; 5], tolerance: f64) -> bool {
    let total: u32 = runs.iter().sum();
    let m = f64::from(total) / 7.0;
    // Below two pixels a module cannot be sampled anyway, and noise is full of tiny matches.
    total >= 12
        && runs
            .iter()
            .zip([1.0, 1.0, 3.0, 1.0, 1.0])
            .all(|(&r, k)| (f64::from(r) - k * m).abs() <= k * m * tolerance + 0.5)
}

#[derive(Clone, Copy, Debug)]
struct Finder {
    at: Pt,
    /// Seven modules' worth of pixels, measured horizontally and vertically, divided by 7.
    module: f64,
    hits: u32,
}

/// Bound on distinct candidates, which keeps merging and triple selection cheap.
const MAX_FINDERS: usize = 64;

/// Scans every row for 1:1:3:1:1 runs and keeps the ones that pass the cross-checks.
fn find_finders(img: &Binary) -> Vec<Finder> {
    let mut found = Vec::new();
    let mut edges = vec![0u32; img.width + 2];
    // A finder worth sampling has a centre at least five pixels tall, so large frames can
    // skip rows: every other one at 1080p, which halves the scan.
    for y in (0..img.height).step_by((img.height / 540).clamp(1, 3)) {
        let row = &img.dark[y * img.width..(y + 1) * img.width];
        // Run boundaries, collected without a branch per pixel: on noisy frames the colour
        // changes unpredictably and mispredictions would dominate the scan.
        let mut n = 1;
        for x in 1..row.len() {
            edges[n] = x as u32;
            n += usize::from(row[x] != row[x - 1]);
        }
        edges[n] = row.len() as u32;
        let edges = &edges[..=n];
        // Runs alternate in colour; start from the first dark one.
        for i in (usize::from(!row[0])..n.saturating_sub(4)).step_by(2) {
            if edges[i + 5] - edges[i] < 12 {
                continue;
            }
            let r = std::array::from_fn(|k| edges[i + k + 1] - edges[i + k]);
            if finder_ratio(&r, 0.5) {
                let cx = f64::from(edges[i + 2]) + (f64::from(r[2]) - 1.0) / 2.0;
                confirm(img, &mut found, Pt::new(cx, y as f64), r.iter().sum());
            }
        }
    }
    found
}

/// Cross-checks a row hit vertically, horizontally again and diagonally, then merges it with
/// an earlier sighting of the same pattern or records it. A finder is a nested square, so its
/// horizontal and vertical extents agree at any rotation.
fn confirm(img: &Binary, found: &mut Vec<Finder>, c: Pt, total: u32) -> Option<()> {
    let (dy, tv) = img.cross_check(c, Pt::new(0.0, 1.0), total, 0.5)?;
    let c = Pt::new(c.x, c.y + dy);
    let (dx, th) = img.cross_check(c, Pt::new(1.0, 0.0), total, 0.5)?;
    let c = Pt::new(c.x + dx, c.y);
    if (tv - th).abs() > 0.4 * tv.max(th) {
        return None;
    }
    let diagonal = Pt::new(std::f64::consts::FRAC_1_SQRT_2, std::f64::consts::FRAC_1_SQRT_2);
    img.cross_check(c, diagonal, 2 * total, 0.75)?;
    let module = (tv + th) / 14.0;
    let same = |f: &&mut Finder| {
        let m = f.module.max(module);
        (f.at - c).norm() < 1.5 * m && (f.module - module).abs() < 0.5 * m
    };
    if let Some(f) = found.iter_mut().find(same) {
        let n = f64::from(f.hits);
        f.at = (f.at * n + c) * (1.0 / (n + 1.0));
        f.module = (f.module * n + module) / (n + 1.0);
        f.hits += 1;
    } else if found.len() < MAX_FINDERS {
        found.push(Finder { at: c, module, hits: 1 });
    } else {
        // Noise fills the list with one-off sightings; a real finder is seen on many
        // consecutive rows, so the one-off seen longest ago is the one to give up.
        let stale = found.iter_mut().filter(|f| f.hits == 1).min_by(|a, b| a.at.y.total_cmp(&b.at.y))?;
        *stale = Finder { at: c, module, hits: 1 };
    }
    Some(())
}

/// The most plausible finder triples, ordered top-left, top-right, bottom-left: similar
/// module sizes, two near-equal sides at a near-right angle, and a module distance that some
/// version 1-10 could produce. The candidates seen in the most rows come first.
fn triples(found: &[Finder]) -> Vec<[Finder; 3]> {
    let mut best = found.to_vec();
    best.sort_by_key(|f| std::cmp::Reverse(f.hits));
    best.truncate(16);
    let n = best.len();
    let mut scored: Vec<(f64, [Finder; 3])> = Vec::new();
    for i in 0..n {
        for j in i + 1..n {
            for k in j + 1..n {
                let mut t = [best[i], best[j], best[k]];
                let lo = t.iter().map(|f| f.module).fold(f64::MAX, f64::min);
                let hi = t.iter().map(|f| f.module).fold(0.0, f64::max);
                if hi > 1.6 * lo {
                    continue;
                }
                // The top-left finder is the corner opposite the longest side.
                let side = |a: usize, b: usize| (t[a].at - t[b].at).norm();
                let opposite = [side(1, 2), side(0, 2), side(0, 1)];
                let corner = (0..3).max_by(|&a, &b| opposite[a].total_cmp(&opposite[b])).unwrap_or(0);
                t.swap(0, corner);
                let (a, b) = (t[1].at - t[0].at, t[2].at - t[0].at);
                let (la, lb) = (a.norm(), b.norm());
                let cos = a.dot(b) / (la * lb);
                let modules = (la + lb) / (lo + hi);
                if la.min(lb) < 0.6 * la.max(lb) || cos.abs() > 0.35 || !(8.0..=75.0).contains(&modules) {
                    continue;
                }
                // With y pointing down, (top-right - top-left) x (bottom-left - top-left) > 0.
                if a.cross(b) < 0.0 {
                    t.swap(1, 2);
                }
                let shape = 1.0 - la.min(lb) / la.max(lb) + cos.abs() + hi / lo - 1.0;
                // Noise rarely passes the cross-checks on two rows; a real finder does on many.
                let rarity: f64 = t.iter().map(|f| 0.5 / f64::from(f.hits)).sum();
                scored.push((shape + rarity, t));
            }
        }
    }
    scored.sort_by(|a, b| a.0.total_cmp(&b.0));
    scored.into_iter().take(6).map(|(_, t)| t).collect()
}

/// Finds the bottom-right alignment pattern near where the finders put it, by matching its
/// 5x5 template in steps of a third of a module; the template is laid out along the code's
/// own axes, so rotation does not matter. Returns the centre of the best-matching spot.
fn find_alignment(img: &Binary, dim: usize, tl: Pt, tr: Pt, bl: Pt) -> Option<Pt> {
    let span = (dim - 7) as f64;
    let (u, v) = ((tr - tl) * (1.0 / span), (bl - tl) * (1.0 / span));
    let predicted = tl + (u + v) * (span - 3.0);
    let reach = 3 * (3 + dim as i32 / 8);
    let score = |c: Pt| {
        let mut s = 0;
        for dy in -2..=2i32 {
            for dx in -2..=2i32 {
                let want = dx.abs().max(dy.abs()) != 1;
                s += u32::from(img.at(c + u * f64::from(dx) + v * f64::from(dy)) == Some(want));
            }
        }
        s
    };
    let (mut best, mut spots) = (0, Vec::new());
    for j in -reach..=reach {
        for i in -reach..=reach {
            let c = predicted + u * (f64::from(i) / 3.0) + v * (f64::from(j) / 3.0);
            let s = score(c);
            if s > best {
                (best, spots) = (s, vec![c]);
            } else if s == best {
                spots.push(c);
            }
        }
    }
    if best < 21 {
        return None;
    }
    // Equal scores form a plateau around the true centre: average the one nearest the prediction.
    let distance = |p: &&Pt| (**p - predicted).norm();
    let anchor = *spots.iter().min_by(|a, b| distance(a).total_cmp(&distance(b)))?;
    let module = u.norm().max(v.norm());
    let near: Vec<Pt> = spots.into_iter().filter(|&p| (p - anchor).norm() <= module).collect();
    Some(near.iter().fold(Pt::new(0.0, 0.0), |a, &p| a + p) * (1.0 / near.len() as f64))
}

enum Read {
    Payload(Vec<u8>),
    /// The version information names another version.
    OtherVersion(usize),
    /// No valid version or format information: the geometry or the version guess is wrong.
    NoFormat,
    /// Format information but uncorrectable data.
    Damaged,
}

/// The codeword nearest to either copy read, if within the codes' correction radius of 3.
fn nearest<T>(codes: impl Iterator<Item = (u32, T)>, read: [u32; 2]) -> Option<T> {
    codes
        .map(|(c, t)| ((c ^ read[0]).count_ones().min((c ^ read[1]).count_ones()), t))
        .filter(|(d, _)| *d <= 3)
        .min_by_key(|(d, _)| *d)
        .map(|(_, t)| t)
}

/// Decodes the symbol of `version` whose module (x, y) is `dark(x, y)`. Modules are asked
/// for lazily, version and format information first, so a wrong guess costs a few samples.
fn read_symbol(version: usize, dark: impl Fn(usize, usize) -> bool) -> Read {
    let size = 17 + 4 * version;
    let word = |copy: usize, n: usize, pos: fn(usize, usize) -> [(usize, usize); 2]| {
        (0..n).fold(0u32, |acc, i| {
            let (x, y) = pos(size, i)[copy];
            acc | (u32::from(dark(x, y)) << i)
        })
    };
    if version >= 7 {
        let read = [word(0, 18, version_pos), word(1, 18, version_pos)];
        match nearest((7..=MAX_VERSION).map(|v| (version_bits(v), v)), read) {
            Some(v) if v != version => return Read::OtherVersion(v),
            Some(_) => {}
            None => return Read::NoFormat,
        }
    }
    let read = [word(0, 15, format_pos), word(1, 15, format_pos)];
    let formats = LEVELS.iter().flat_map(|&e| (0..8).map(move |m| (format_bits(e, m), (e, m))));
    let Some((ecc, mask)) = nearest(formats, read) else {
        return Read::NoFormat;
    };
    let layout = Layout::new(version, ecc);
    // What is read is a key: every buffer holding it is wiped when dropped (`SecureVec`).
    let mut codewords = SecureVec(vec![0u8; raw_codewords(version)]);
    for (k, idx) in Grid::new(version).data_order().into_iter().take(codewords.0.len() * 8).enumerate() {
        let (x, y) = (idx % size, idx / size);
        if dark(x, y) ^ mask_bit(mask, x, y) {
            codewords.0[k / 8] |= 0x80 >> (k % 8);
        }
    }
    let mut data = SecureVec(Vec::with_capacity(layout.data_codewords()));
    let mut blocks = deinterleave(layout, &codewords.0);
    let mut ok = true;
    for (b, block) in blocks.iter_mut().enumerate() {
        if !rs_correct(block, layout.ecc) {
            ok = false;
            break;
        }
        data.0.extend_from_slice(&block[..layout.data_len(b)]);
    }
    wipe_blocks(&mut blocks);
    if !ok {
        return Read::Damaged;
    }
    parse_segments(&data.0, version).map_or(Read::Damaged, Read::Payload)
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl BitReader<'_> {
    fn remaining(&self) -> usize {
        self.data.len() * 8 - self.pos
    }

    fn read(&mut self, n: usize) -> Option<u32> {
        if n > self.remaining() {
            return None;
        }
        let mut v = 0;
        for _ in 0..n {
            v = (v << 1) | u32::from((self.data[self.pos / 8] >> (7 - self.pos % 8)) & 1);
            self.pos += 1;
        }
        Some(v)
    }
}

/// Concatenates the numeric, alphanumeric and byte segments. ECI designators are skipped (the
/// payload's bytes are returned as they are), as are FNC1 and structured-append headers.
fn parse_segments(data: &[u8], version: usize) -> Option<Vec<u8>> {
    const ALNUM: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    let mut r = BitReader { data, pos: 0 };
    // Room for the most a segment can expand to (numeric: 2.4 characters a byte), so the buffer
    // never moves and leaves a copy behind; wiped if parsing fails (`SecureVec`).
    let mut out = SecureVec(Vec::with_capacity(data.len() * 3));
    while r.remaining() >= 4 {
        match r.read(4)? {
            0 => break,
            1 => {
                let mut n = r.read(count_bits(version, 1))?;
                while n > 0 {
                    let digits = n.min(3);
                    let v = r.read([0, 4, 7, 10][digits as usize])?;
                    if v >= 10u32.pow(digits) {
                        return None;
                    }
                    out.0.extend((0..digits).rev().map(|k| b'0' + (v / 10u32.pow(k) % 10) as u8));
                    n -= digits;
                }
            }
            2 => {
                let mut n = r.read(count_bits(version, 2))?;
                while n >= 2 {
                    let v = r.read(11)? as usize;
                    out.0.extend_from_slice(&[*ALNUM.get(v / 45)?, ALNUM[v % 45]]);
                    n -= 2;
                }
                if n == 1 {
                    out.0.push(*ALNUM.get(r.read(6)? as usize)?);
                }
            }
            4 => {
                for _ in 0..r.read(count_bits(version, 4))? {
                    out.0.push(r.read(8)? as u8);
                }
            }
            7 => {
                let first = r.read(8)?;
                r.read(match (first << 24).leading_ones() {
                    0 => 0,
                    1 => 8,
                    2 => 16,
                    _ => return None,
                })?;
            }
            3 => {
                r.read(16)?;
            }
            5 => {}
            9 => {
                r.read(8)?;
            }
            _ => return None,
        }
    }
    Some(std::mem::take(&mut out.0))
}

/// Reads the symbol framed by three finders, trying the estimated version and its neighbours.
/// The fourth point of the homography is the alignment pattern found in the image or, failing
/// that (and always for version 1, which has none), the parallelogram's fourth corner and the
/// positions around it, since perspective moves it. That search is the expensive part, so
/// `searches` caps how many symbols with valid format information but bad data get one.
fn decode_at(img: &Binary, [tl, tr, bl]: [Finder; 3], searches: &mut u32) -> Option<Vec<u8>> {
    // Runs across a rotated finder are stretched by 1/cos of the rotation (mod 90 degrees).
    let axis = (tr.at - tl.at) * (1.0 / (tr.at - tl.at).norm());
    let stretch = axis.x.abs().max(axis.y.abs());
    let modules = |a: Finder, b: Finder| (a.at - b.at).norm() / ((a.module + b.module) / 2.0 * stretch);
    let dim = (modules(tl, tr) + modules(tl, bl)) / 2.0 + 7.0;
    let estimate = (((dim - 17.0) / 4.0).round() as usize).clamp(1, MAX_VERSION);
    let mut versions = vec![estimate];
    for d in 1..=2 {
        let near = [estimate.wrapping_sub(d), estimate + d];
        versions.extend(near.into_iter().filter(|v| (1..=MAX_VERSION).contains(v)));
    }
    // Offsets of the fourth corner in half modules, nearest first, (0, 0) leading.
    let mut offsets: Vec<(i32, i32)> = (-4..=4).flat_map(|y| (-4..=4).map(move |x| (x, y))).collect();
    offsets.sort_by_key(|&(x, y)| x * x + y * y);
    let mut i = 0;
    while let Some(&version) = versions.get(i) {
        i += 1;
        let dim = 17 + 4 * version;
        let d = dim as f64;
        let (u, v) = ((tr.at - tl.at) * (1.0 / (d - 7.0)), (bl.at - tl.at) * (1.0 / (d - 7.0)));
        let corner = tr.at + bl.at - tl.at;
        let read = |module: Pt, pixel: Pt| {
            let from = [Pt::new(3.5, 3.5), Pt::new(d - 3.5, 3.5), module, Pt::new(3.5, d - 3.5)];
            let h = Homography::quad_to_quad(from, [tl.at, tr.at, pixel, bl.at])?;
            // A module centre outside the frame reads as light; Reed-Solomon sorts it out.
            let centre = |x: usize, y: usize| h.map(Pt::new(x as f64 + 0.5, y as f64 + 0.5));
            Some(read_symbol(version, |x, y| img.at(centre(x, y)) == Some(true)))
        };
        // Format and version information sit next to the finders, where the fourth point
        // hardly matters, so the plain parallelogram tells whether this version is worth a
        // search for the alignment pattern.
        match read(Pt::new(d - 3.5, d - 3.5), corner) {
            Some(Read::Payload(data)) => return Some(data),
            Some(Read::OtherVersion(v)) if !versions.contains(&v) => versions.push(v),
            Some(Read::Damaged) if *searches > 0 => {
                *searches -= 1;
                let alignment = if version >= 2 { find_alignment(img, dim, tl.at, tr.at, bl.at) } else { None };
                let anchors = alignment.map(|p| (Pt::new(d - 6.5, d - 6.5), p)).into_iter().chain(
                    offsets.iter().skip(1).map(|&(x, y)| {
                        (Pt::new(d - 3.5, d - 3.5), corner + (u * f64::from(x) + v * f64::from(y)) * 0.5)
                    }),
                );
                for (module, pixel) in anchors {
                    if let Some(Read::Payload(data)) = read(module, pixel) {
                        return Some(data);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// Finds and decodes one QR code in an 8-bit luminance image (camera Y plane), `stride` bytes
/// per row. The payload bytes, or None if no code could be read.
///
/// The last row need only be `width` bytes long: Android's Y plane buffers often omit the
/// padding after it. Frames above 16 megapixels are refused to bound memory.
pub fn decode(luma: &[u8], width: usize, height: usize, stride: usize) -> Option<Vec<u8>> {
    if width < 21 || height < 21 || stride < width || width.checked_mul(height)? > 1 << 24 {
        return None;
    }
    if luma.len() < stride.checked_mul(height - 1)?.checked_add(width)? {
        return None;
    }
    let img = Binary::new(luma, width, height, stride);
    let mut searches = 2;
    triples(&find_finders(&img)).into_iter().find_map(|t| decode_at(&img, t, &mut searches))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// splitmix64: deterministic and good enough for test data.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        fn range(&mut self, lo: f64, hi: f64) -> f64 {
            lo + (hi - lo) * (self.next() >> 11) as f64 / (1u64 << 53) as f64
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    /// How the simulated camera sees the code.
    #[derive(Clone, Copy)]
    struct Shot {
        module: f64,
        angle: f64,
        tilt: f64,
        blur: bool,
        noise: f64,
        gradient: f64,
        dark: f64,
        light: f64,
    }

    impl Default for Shot {
        fn default() -> Shot {
            let (dark, light) = (30.0, 220.0);
            Shot { module: 4.0, angle: 0.0, tilt: 0.0, blur: false, noise: 0.0, gradient: 0.0, dark, light }
        }
    }

    impl Shot {
        fn random(rng: &mut Rng) -> Shot {
            let (dark, light) = (rng.range(20.0, 90.0), rng.range(150.0, 240.0));
            Shot {
                module: rng.range(3.0, 6.0),
                angle: rng.range(0.0, std::f64::consts::TAU),
                tilt: rng.range(0.0, 0.05),
                blur: rng.below(2) == 0,
                noise: (light - dark) * rng.range(0.0, 0.15),
                gradient: rng.range(0.0, 0.4),
                dark,
                light,
            }
        }
    }

    struct Frame {
        luma: Vec<u8>,
        width: usize,
        height: usize,
        stride: usize,
    }

    impl Frame {
        fn decode(&self) -> Option<Vec<u8>> {
            decode(&self.luma, self.width, self.height, self.stride)
        }
    }

    /// Renders the code (with its quiet zone) through a rotation and perspective jitter of the
    /// corners, 2x2 supersampled as a sensor integrates, then shades it with a linear
    /// illumination gradient, optionally box-blurs it and adds uniform noise. Rows are padded
    /// past `width` with junk, as camera planes are.
    fn photograph(code: &QrCode, shot: &Shot, rng: &mut Rng, size: Option<(usize, usize)>) -> Frame {
        let side = (code.size() + 8) as f64;
        let extent = side * shot.module;
        let (width, height) = size.unwrap_or(((extent * 1.5) as usize + 16, (extent * 1.45) as usize + 16));
        let mid = Pt::new(width as f64, height as f64) * 0.5;
        let centre = mid + Pt::new(rng.range(-4.0, 4.0), rng.range(-4.0, 4.0));
        let (sin, cos) = shot.angle.sin_cos();
        let jitter = shot.tilt * extent;
        let corners = [(0.0, 0.0), (1.0, 0.0), (1.0, 1.0), (0.0, 1.0)].map(|(u, v)| {
            let (dx, dy) = ((u - 0.5) * extent, (v - 0.5) * extent);
            let tilt = Pt::new(rng.range(-jitter, jitter), rng.range(-jitter, jitter));
            centre + Pt::new(dx * cos - dy * sin, dx * sin + dy * cos) + tilt
        });
        let square = [(0.0, 0.0), (side, 0.0), (side, side), (0.0, side)].map(|(x, y)| Pt::new(x, y));
        let to_code = Homography::quad_to_quad(corners, square).unwrap();
        let (s, c) = rng.range(0.0, std::f64::consts::TAU).sin_cos();
        let light_dir = Pt::new(c, s) * (1.0 / width.max(height) as f64);
        let mut img = vec![0.0; width * height];
        for y in 0..height {
            for x in 0..width {
                let mut acc = 0.0;
                for (sx, sy) in [(-0.25, -0.25), (0.25, -0.25), (-0.25, 0.25), (0.25, 0.25)] {
                    let p = to_code.map(Pt::new(x as f64 + sx, y as f64 + sy));
                    let inside = p.x >= 0.0 && p.y >= 0.0 && p.x < side && p.y < side;
                    let (mx, my) = ((p.x as usize).wrapping_sub(4), (p.y as usize).wrapping_sub(4));
                    let dark = inside && code.dark(mx, my);
                    acc += if dark { shot.dark } else if inside { shot.light } else { shot.light * 0.9 };
                }
                let t = (Pt::new(x as f64, y as f64) - mid).dot(light_dir) + 0.5;
                img[y * width + x] = acc / 4.0 * (1.0 - shot.gradient * t.clamp(0.0, 1.0));
            }
        }
        if shot.blur {
            let src = img.clone();
            for y in 0..height {
                for x in 0..width {
                    let mut sum = 0.0;
                    for (dx, dy) in (0..9).map(|k| (k % 3, k / 3)) {
                        let sx = (x + dx).saturating_sub(1).min(width - 1);
                        let sy = (y + dy).saturating_sub(1).min(height - 1);
                        sum += src[sy * width + sx];
                    }
                    img[y * width + x] = sum / 9.0;
                }
            }
        }
        let stride = width + 3;
        let mut luma = rng.bytes(stride * height);
        for y in 0..height {
            for x in 0..width {
                let v = img[y * width + x] + rng.range(-shot.noise, shot.noise);
                luma[y * stride + x] = v.round().clamp(0.0, 255.0) as u8;
            }
        }
        Frame { luma, width, height, stride }
    }

    fn version_of(code: &QrCode) -> usize {
        (code.size() - 17) / 4
    }

    #[test]
    fn format_and_version_information() {
        assert_eq!(format_bits(Ecc::L, 0), 0b111011111000100);
        assert_eq!(format_bits(Ecc::M, 0), 0b101010000010010);
        assert_eq!(format_bits(Ecc::Q, 7), 0b010101111101101);
        assert_eq!(format_bits(Ecc::H, 4), 0b000011101100010);
        assert_eq!(version_bits(7), 0x07c94);
        assert_eq!(version_bits(10), 0x0a4d3);
    }

    #[test]
    fn iso_annex_i_codewords() {
        // "01234567" at 1-M: one numeric segment.
        let mut bits = Bits::default();
        for (v, n) in [(1, 4), (8, 10), (12, 10), (345, 10), (67, 7)] {
            bits.push(v, n);
        }
        let layout = Layout::new(1, Ecc::M);
        let data = data_codewords(layout, bits);
        let mut expected = vec![0x10, 0x20, 0x0c, 0x56, 0x61, 0x80];
        expected.extend([0xec, 0x11].repeat(5));
        assert_eq!(data, expected);
        let blocks = rs_blocks(layout, &data);
        assert_eq!(blocks[0][16..], [0xa5, 0x24, 0xd4, 0xc1, 0xed, 0x36, 0xc7, 0x87, 0x2c, 0x55]);
        assert_eq!(parse_segments(&data, 1).unwrap(), b"01234567");
    }

    #[test]
    fn hello_world_codewords() {
        // The widely published "HELLO WORLD" 1-M example (one alphanumeric segment).
        let mut bits = Bits::default();
        for (v, n) in [(2, 4), (11, 9), (779, 11), (966, 11), (1116, 11), (1464, 11), (1236, 11), (13, 6)] {
            bits.push(v, n);
        }
        let layout = Layout::new(1, Ecc::M);
        let data = data_codewords(layout, bits);
        assert_eq!(data, [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17]);
        assert_eq!(rs_blocks(layout, &data)[0][16..], [196, 35, 39, 119, 235, 215, 231, 226, 93, 23]);
        assert_eq!(parse_segments(&data, 1).unwrap(), b"HELLO WORLD");
    }

    #[test]
    fn byte_capacities() {
        let table = [
            [17, 14, 11, 7],
            [32, 26, 20, 14],
            [53, 42, 32, 24],
            [78, 62, 46, 34],
            [106, 84, 60, 44],
            [134, 106, 74, 58],
            [154, 122, 86, 64],
            [192, 152, 108, 84],
            [230, 180, 130, 98],
            [271, 213, 151, 119],
        ];
        for (v, row) in table.iter().enumerate() {
            for (ecc, &cap) in LEVELS.iter().zip(row) {
                assert_eq!(byte_capacity(v + 1, *ecc), cap, "version {} {ecc:?}", v + 1);
                assert_eq!(version_of(&encode(&vec![b'x'; cap], *ecc).unwrap()), v + 1);
            }
        }
        assert!(encode(&[0; 272], Ecc::L).is_err());
    }

    #[test]
    fn symbols_read_back_exactly() {
        // Placement, masking, format/version information and blocks, without the camera.
        let mut rng = Rng(1);
        for version in 1..=MAX_VERSION {
            for ecc in LEVELS {
                for mask in 0..8 {
                    let len = rng.below(byte_capacity(version, ecc) + 1);
                    let payload = rng.bytes(len);
                    let code = QrCode::from_bits(version, ecc, byte_segment(version, &payload), Some(mask));
                    match read_symbol(version, |x, y| code.dark(x, y)) {
                        Read::Payload(p) => assert_eq!(p, payload),
                        _ => panic!("version {version} {ecc:?} mask {mask}"),
                    }
                }
            }
        }
    }

    #[test]
    fn reed_solomon_corrects_to_capacity_and_rejects_beyond() {
        let mut rng = Rng(2);
        for nsym in [7, 10, 16, 22, 30] {
            for _ in 0..50 {
                let len = 1 + rng.below(80);
                let data = rng.bytes(len);
                let block = [data.clone(), rs_remainder(&data, &rs_divisor(nsym))].concat();
                let mut damaged = block.clone();
                let mut positions: Vec<usize> = (0..block.len()).collect();
                for k in 0..nsym / 2 {
                    let j = k + rng.below(positions.len() - k);
                    positions.swap(k, j);
                    damaged[positions[k]] ^= 1 + rng.below(255) as u8;
                }
                assert!(rs_correct(&mut damaged, nsym));
                assert_eq!(damaged, block);
                // A random word is within nsym/2 symbols of some codeword with probability
                // below 1e-4 at these sizes, so far beyond capacity means rejection.
                let mut garbage = rng.bytes(block.len());
                assert!(!rs_correct(&mut garbage, nsym));
            }
        }
    }

    #[test]
    fn round_trips_through_the_camera() {
        let mut rng = Rng(3);
        for ecc in LEVELS {
            for version in 1..=MAX_VERSION {
                let cap = byte_capacity(version, ecc);
                let lo = if version == 1 { 0 } else { byte_capacity(version - 1, ecc) + 1 };
                let len = lo + rng.below(cap - lo + 1);
                let payload = rng.bytes(len);
                let code = encode(&payload, ecc).unwrap();
                assert_eq!(version_of(&code), version);
                let shot = Shot::random(&mut rng);
                let frame = photograph(&code, &shot, &mut rng, None);
                assert_eq!(frame.decode().as_deref(), Some(&payload[..]), "{ecc:?} v{version} {len} bytes");
            }
        }
    }

    #[test]
    fn module_sizes_and_angles() {
        let mut rng = Rng(4);
        let payload = rng.bytes(40);
        let code = encode(&payload, Ecc::Q).unwrap();
        for module in [2.0, 3.0, 5.0, 8.0] {
            for angle in [0.0, 0.3, 0.785, 1.6, 2.5, 3.9, 5.0] {
                let shot = Shot { module, angle, ..Shot::default() };
                let frame = photograph(&code, &shot, &mut rng, None);
                assert_eq!(frame.decode().as_deref(), Some(&payload[..]), "module {module} angle {angle}");
            }
        }
    }

    #[test]
    fn hard_lighting() {
        let mut rng = Rng(5);
        let payload = rng.bytes(70);
        let code = encode(&payload, Ecc::M).unwrap();
        // Low contrast, strong gradient, blur, noise and tilt together.
        for seed in 0..6 {
            let shot = Shot {
                module: 4.0 + f64::from(seed) * 0.5,
                angle: f64::from(seed),
                tilt: 0.04,
                blur: true,
                noise: 6.0,
                gradient: 0.5,
                dark: 110.0,
                light: 160.0,
            };
            let frame = photograph(&code, &shot, &mut rng, None);
            assert_eq!(frame.decode().as_deref(), Some(&payload[..]), "seed {seed}");
        }
    }

    #[test]
    fn segments_and_masks() {
        let mut rng = Rng(6);
        for mask in 0..8 {
            // Numeric "0123", alphanumeric "AB-1", an ECI header, then bytes, at version 2-H.
            let mut bits = Bits::default();
            let numeric = [(1, 4), (4, 10), (12, 10), (3, 4)];
            let alphanumeric = [(2, 4), (4, 9), (461, 11), (1846, 11)];
            let eci_utf8 = [(7, 4), (26, 8)];
            let bytes = [(4, 4), (2, 8), (0xc3, 8), (0xa9, 8)];
            for (v, n) in [&numeric[..], &alphanumeric, &eci_utf8, &bytes].concat() {
                bits.push(v, n);
            }
            let code = QrCode::from_bits(2, Ecc::H, bits, Some(mask));
            let shot = Shot { angle: f64::from(mask), ..Shot::default() };
            let frame = photograph(&code, &shot, &mut rng, None);
            assert_eq!(frame.decode().as_deref(), Some(&b"0123AB-1\xc3\xa9"[..]), "mask {mask}");
        }
    }

    /// The symbol for `payload` with `per_block` codewords of every block damaged.
    fn damaged(payload: &[u8], ecc: Ecc, per_block: impl Fn(Layout) -> usize, rng: &mut Rng) -> QrCode {
        let version = version_of(&encode(payload, ecc).unwrap());
        let layout = Layout::new(version, ecc);
        let mut blocks = rs_blocks(layout, &data_codewords(layout, byte_segment(version, payload)));
        for block in &mut blocks {
            let mut positions: Vec<usize> = (0..block.len()).collect();
            for k in 0..per_block(layout).min(block.len()) {
                let j = k + rng.below(positions.len() - k);
                positions.swap(k, j);
                block[positions[k]] ^= 1 + rng.below(255) as u8;
            }
        }
        QrCode::from_codewords(version, ecc, &interleave(layout, &blocks), None)
    }

    #[test]
    fn corrects_damage_up_to_capacity() {
        let mut rng = Rng(7);
        for ecc in LEVELS {
            for len in [5, 30, 70, 110] {
                let payload = rng.bytes(len.min(byte_capacity(MAX_VERSION, ecc)));
                let code = damaged(&payload, ecc, |l| l.ecc / 2, &mut rng);
                let frame = photograph(&code, &Shot { angle: rng.range(0.0, 6.0), ..Shot::default() }, &mut rng, None);
                assert_eq!(frame.decode().as_deref(), Some(&payload[..]), "{ecc:?} {len}");
            }
        }
    }

    #[test]
    fn rejects_damage_beyond_capacity() {
        let mut rng = Rng(8);
        for ecc in LEVELS {
            for len in [5, 30, 70] {
                let payload = rng.bytes(len);
                let code = damaged(&payload, ecc, |l| l.ecc / 2 + l.ecc, &mut rng);
                let frame = photograph(&code, &Shot { angle: rng.range(0.0, 6.0), ..Shot::default() }, &mut rng, None);
                assert_eq!(frame.decode(), None, "{ecc:?} {len}");
            }
        }
    }

    #[test]
    fn format_information_survives_three_bit_errors() {
        let payload = b"format".to_vec();
        let mut code = encode(&payload, Ecc::L).unwrap();
        let size = code.size();
        for i in [0, 7, 13] {
            for (x, y) in format_pos(size, i) {
                code.modules[y * size + x] ^= true;
            }
        }
        let frame = photograph(&code, &Shot::default(), &mut Rng(9), None);
        assert_eq!(frame.decode(), Some(payload));
    }

    #[test]
    fn pre_shared_key() {
        let mut rng = Rng(10);
        let key: String = (0..64).map(|_| char::from(b"0123456789abcdef"[rng.below(16)])).collect();
        let text = format!("srdp1-{key}");
        assert_eq!(text.len(), 70);
        let code = encode(text.as_bytes(), Ecc::M).unwrap();
        assert_eq!(code.size(), 37);
        let terminal = code.to_terminal();
        assert_eq!(terminal.lines().count(), (37usize + 8).div_ceil(2));
        for line in terminal.lines() {
            assert!(line.ends_with("\x1b[0m") && line.chars().filter(|&c| c == '▀').count() == 45);
        }
        let frame = photograph(&code, &Shot::random(&mut rng), &mut rng, None);
        assert_eq!(frame.decode().as_deref(), Some(text.as_bytes()));
    }

    #[test]
    fn junk_input_is_none() {
        let mut rng = Rng(11);
        assert_eq!(decode(&[], 0, 0, 0), None);
        assert_eq!(decode(&[0; 400], 20, 20, 20), None);
        assert_eq!(decode(&[0; 10_000], 100, 100, 99), None);
        assert_eq!(decode(&[0; 10_000], 100, 101, 100), None);
        assert_eq!(decode(&[0; 10_000], 100, 100, usize::MAX), None);
        assert_eq!(decode(&[0; 10_000], usize::MAX, 2, usize::MAX), None);
        for (w, h) in [(21, 21), (64, 48), (320, 240)] {
            assert_eq!(decode(&vec![0; w * h], w, h, w), None);
            assert_eq!(decode(&vec![255; w * h], w, h, w), None);
            for _ in 0..5 {
                assert_eq!(decode(&rng.bytes(w * h), w, h, w), None);
            }
        }
        // A real code with the buffer cut short, and with its last row unpadded (accepted).
        let code = encode(b"truncated", Ecc::M).unwrap();
        let frame = photograph(&code, &Shot::default(), &mut rng, None);
        let (w, h, stride) = (frame.width, frame.height, frame.stride);
        let full = stride * (h - 1) + w;
        assert_eq!(decode(&frame.luma[..full], w, h, stride).as_deref(), Some(&b"truncated"[..]));
        assert_eq!(decode(&frame.luma[..full - 1], w, h, stride), None);
        // Many finder look-alikes: a tiling of finder patterns.
        let (w, h) = (300, 300);
        let tile = |x: usize, y: usize| {
            let ring = ((x % 30) as i32 - 15).abs().max(((y % 30) as i32 - 15).abs()) / 3;
            if ring <= 1 || ring == 3 { 20 } else { 230 }
        };
        let luma: Vec<u8> = (0..w * h).map(|i| tile(i % w, i / w)).collect();
        assert_eq!(decode(&luma, w, h, w), None);
    }

    #[test]
    #[ignore = "timing; run with --release -- --ignored --nocapture"]
    fn full_hd_timing() {
        let mut rng = Rng(12);
        let payload = format!("srdp1-{}", "0123456789abcdef".repeat(4));
        let (dark, light) = (40.0, 200.0);
        let shot = Shot { module: 11.0, angle: 0.2, tilt: 0.03, blur: true, noise: 8.0, gradient: 0.4, dark, light };
        let code = encode(payload.as_bytes(), Ecc::M).unwrap();
        let frame = photograph(&code, &shot, &mut rng, Some((1920, 1080)));
        // Readable format information but uncorrectable data: the costliest case.
        let wrecked = damaged(payload.as_bytes(), Ecc::M, |l| l.ecc, &mut rng);
        let wrecked = photograph(&wrecked, &shot, &mut rng, Some((1920, 1080)));
        let noise = Frame { luma: rng.bytes(1920 * 1080), width: 1920, height: 1080, stride: 1920 };
        let cases = [("code", &frame, Some(payload.as_bytes())), ("damaged code", &wrecked, None), ("noise", &noise, None)];
        for (name, frame, expect) in cases {
            let start = std::time::Instant::now();
            for _ in 0..10 {
                assert_eq!(frame.decode().as_deref(), expect);
            }
            println!("1920x1080 {name}: {:.1} ms per decode", start.elapsed().as_secs_f64() * 100.0);
        }
    }
}
