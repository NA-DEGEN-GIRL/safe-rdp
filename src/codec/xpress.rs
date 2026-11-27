//! Portable LZ77+Huffman ("XPRESS Huffman") codec, [MS-XCA] sections 2.1 and 2.2.
//!
//! Produces and accepts the raw stream that Windows' Compression API emits for
//! `COMPRESS_ALGORITHM_XPRESS_HUFF | COMPRESS_RAW`:
//!
//! * The output is a series of blocks. Each block starts with a 256-byte table holding the
//!   4-bit code lengths of the 512 Huffman symbols (even symbols in the low nibble) and covers
//!   at least 65536 bytes of output, or what is left of it. A match may run past the end of a
//!   block; the next block then starts where that match ends.
//! * Symbols 0-255 are literals. Symbol `256 + 16 * h + l` is a match whose distance has its
//!   highest set bit at index `h` (the `h` low bits follow the symbol in the bit stream) and
//!   whose length is `l + 3`. `l == 15` means the length continues in the byte stream: a byte
//!   holding `length - 18`, or `0xff` and a 16-bit `length - 3`, or `0xff 0x0000` and a
//!   32-bit `length - 3`.
//! * Bits are read most significant first from little-endian 16-bit words. The decoder keeps
//!   32 bits loaded, so the extra length bytes sit after the next word it has not consumed.
//! * The data ends with the end-of-stream symbol (256) in the last block.
//!
//! Decoding never panics and never touches memory outside its buffers; its work is bounded by
//! the output size (every block yields at least 65536 bytes, every symbol at least one byte).
//!
//! The encoder is a greedy LZ77 parser tuned for sub-filtered screen pixels: it tries the
//! previous match distance first, then a short hash chain of 4-byte prefixes, and skips ahead
//! through stretches without matches, so incompressible content stays cheap.

use crate::bail;
use crate::util::Result;

/// Output bytes covered by one block's Huffman table.
const BLOCK: usize = 1 << 16;
/// Size of the code-length table that starts every block.
const TABLE_BYTES: usize = 256;
const SYMBOLS: usize = 512;
const EOF_SYMBOL: usize = 256;
const MAX_CODE_LEN: usize = 15;
/// Codes up to this length are decoded with one table lookup; longer ones take a short loop.
const FAST_BITS: u32 = 12;

const MIN_MATCH: usize = 3;
const MAX_DIST: usize = (1 << 16) - 1;
/// Distance kept between the stored positions of successive inputs (more than `MAX_DIST`).
const GAP: u32 = 1 << 16;
const HASH_BITS: u32 = 14;
/// Hash chain links kept (a ring of distances; older links may be overwritten, which only
/// costs candidates since every candidate is verified).
const CHAIN: usize = 1 << 15;
/// Hash chain candidates examined per position (after the last match distance).
const MAX_CHAIN: u32 = 3;
/// A match this long ends the search.
const NICE_MATCH: usize = 32;
/// Matches up to this long have every position indexed; longer ones only their tail.
const INSERT_ALL: usize = 8;
/// After `2^SKIP_SHIFT` positions in a row without a match, the search starts skipping
/// positions (they stay literals), faster the longer the stretch: incompressible content
/// costs little time.
const SKIP_SHIFT: u32 = 5;
/// Three-byte matches farther away than this cost more bits than three literals.
const FAR_MIN_MATCH: usize = 4096;
/// Largest input the encoder accepts (positions are kept as `u32`).
const MAX_INPUT: usize = 1 << 30;

/// Decompresses the raw stream `src` into exactly `dst.len()` bytes.
///
/// Fails if the stream is malformed or does not encode exactly `dst.len()` bytes: once `dst`
/// is full, the stream must continue with the end-of-stream symbol and end there.
pub fn decompress(src: &[u8], dst: &mut [u8]) -> Result<()> {
    let mut table = DecodeTable::new();
    let (mut pos, mut out) = (0usize, 0usize);
    loop {
        if out == dst.len() && pos == src.len() {
            return Ok(());
        }
        let Some(lengths) = src.get(pos..pos + TABLE_BYTES) else {
            bail!("truncated XPRESS stream")
        };
        table.build(lengths)?;
        pos += TABLE_BYTES;

        // The [MS-XCA] bit reader: `bits` holds 16 + `extra` unread bits at the top and is
        // refilled one word at a time once fewer than 16 remain; extra length bytes are read
        // at `pos`, after the words already loaded.
        let mut bits = read_word(src, &mut pos)? << 16;
        bits |= read_word(src, &mut pos)?;
        let mut extra = 16i32;
        macro_rules! consume {
            ($n:expr) => {
                let n: u32 = $n;
                bits <<= n;
                extra -= n as i32;
                if extra < 0 {
                    bits |= read_word(src, &mut pos)? << (-extra) as u32;
                    extra += 16;
                }
            };
        }

        // A block ends once it has produced 65536 bytes; its last match may run past that.
        let stop = dst.len().min(out.saturating_add(BLOCK));
        while out < stop {
            let (sym, n) = table.decode(bits)?;
            consume!(n);
            if sym < 256 {
                dst[out] = sym as u8;
                out += 1;
                continue;
            }
            let sym = sym - 256;
            let len = match sym & 15 {
                15 => match read_byte(src, &mut pos)? {
                    255 => {
                        let v = match read_word(src, &mut pos)? {
                            0 => read_word(src, &mut pos)? | read_word(src, &mut pos)? << 16,
                            v => v,
                        } as usize;
                        if v < 15 {
                            bail!("corrupt XPRESS stream (match length)");
                        }
                        v.saturating_add(MIN_MATCH)
                    }
                    b => b as usize + 15 + MIN_MATCH,
                },
                l => l + MIN_MATCH,
            };
            let dist_bits = (sym >> 4) as u32;
            let dist = (1usize << dist_bits) | ((bits >> 1) >> (31 - dist_bits)) as usize;
            consume!(dist_bits);
            if dist > out || len > dst.len() - out {
                bail!("corrupt XPRESS stream (match out of range)");
            }
            copy_match(dst, out, dist, len);
            out += len;
        }
        if out == dst.len() {
            // The end-of-stream symbol must follow, and its word be the last of the input.
            let (sym, n) = table.decode(bits)?;
            if extra < n as i32 {
                read_word(src, &mut pos)?;
            }
            if sym != EOF_SYMBOL || pos != src.len() {
                bail!("corrupt XPRESS stream (data past the end)");
            }
            return Ok(());
        }
    }
}

#[inline(always)]
fn read_word(src: &[u8], pos: &mut usize) -> Result<u32> {
    match src.get(*pos..*pos + 2) {
        Some(w) => {
            *pos += 2;
            Ok(u16::from_le_bytes([w[0], w[1]]) as u32)
        }
        None => bail!("truncated XPRESS stream"),
    }
}

#[inline(always)]
fn read_byte(src: &[u8], pos: &mut usize) -> Result<u8> {
    match src.get(*pos) {
        Some(&b) => {
            *pos += 1;
            Ok(b)
        }
        None => bail!("truncated XPRESS stream"),
    }
}

/// Copies `len` bytes starting `dist` bytes back to `out`; the ranges may overlap.
/// The caller has checked `dist <= out` and `out + len <= dst.len()`.
#[inline(always)]
fn copy_match(dst: &mut [u8], out: usize, dist: usize, len: usize) {
    let from = out - dist;
    if dist >= 8 && dst.len() - out >= len + 16 {
        // Fixed-size chunks, each reading only bytes already final (at least one chunk
        // behind what it writes). Bytes written past the match are overwritten by the
        // output that follows.
        let mut i = 0;
        if dist >= 16 {
            while i < len {
                dst.copy_within(from + i..from + i + 16, out + i);
                i += 16;
            }
        } else {
            while i < len {
                dst.copy_within(from + i..from + i + 8, out + i);
                i += 8;
            }
        }
    } else if dist == 1 {
        let b = dst[from];
        dst[out..out + len].fill(b);
    } else if len <= 32 {
        for i in 0..len {
            dst[out + i] = dst[from + i];
        }
    } else if dist >= len {
        dst.copy_within(from..from + len, out);
    } else {
        // Long overlapping copy of a short pattern: grow the copy by whole periods.
        let mut done = 0;
        while done < len {
            let n = (len - done).min(dist + done);
            dst.copy_within(from..from + n, out + done);
            done += n;
        }
    }
}

/// Canonical Huffman decoder for one block: a `FAST_BITS` lookup table for short codes and
/// per-length ranges for the rest.
struct DecodeTable {
    /// `symbol << 4 | length` by the next `FAST_BITS` bits; length 0 marks a longer code.
    fast: [u16; 1 << FAST_BITS],
    /// Symbols in canonical order (by code length, then symbol value).
    sorted: [u16; SYMBOLS],
    /// First canonical code, one past the last code and first `sorted` index, by length.
    first: [u32; MAX_CODE_LEN + 1],
    limit: [u32; MAX_CODE_LEN + 1],
    base: [u32; MAX_CODE_LEN + 1],
}

impl DecodeTable {
    fn new() -> Self {
        DecodeTable {
            fast: [0; 1 << FAST_BITS],
            sorted: [0; SYMBOLS],
            first: [0; MAX_CODE_LEN + 1],
            limit: [0; MAX_CODE_LEN + 1],
            base: [0; MAX_CODE_LEN + 1],
        }
    }

    /// Builds the decoder from a block's 256-byte length table. Like the reference method,
    /// it rejects tables whose codes do not exactly fill the code space.
    fn build(&mut self, table: &[u8]) -> Result<()> {
        let len_of = |sym: usize| ((table[sym / 2] >> (4 * (sym % 2))) & 15) as usize;
        let mut count = [0u32; MAX_CODE_LEN + 1];
        for sym in 0..SYMBOLS {
            count[len_of(sym)] += 1;
        }
        count[0] = 0;
        let space: u32 = (1..=MAX_CODE_LEN).map(|l| count[l] << (MAX_CODE_LEN - l)).sum();
        if space != 1 << MAX_CODE_LEN {
            bail!("corrupt XPRESS stream (Huffman table)");
        }
        let (mut code, mut index) = (0u32, 0u32);
        for (l, &c) in count.iter().enumerate().skip(1) {
            self.first[l] = code;
            self.limit[l] = code + c;
            self.base[l] = index;
            code = (code + c) << 1;
            index += c;
        }
        let mut next = self.base;
        for sym in 0..SYMBOLS {
            let l = len_of(sym);
            if l != 0 {
                self.sorted[next[l] as usize] = sym as u16;
                next[l] += 1;
            }
        }
        // Short codes occupy a prefix of the fast table, in canonical order.
        let mut e = 0usize;
        for &sym in &self.sorted[..self.base[FAST_BITS as usize + 1] as usize] {
            let l = len_of(sym as usize);
            let span = 1usize << (FAST_BITS as usize - l);
            self.fast[e..e + span].fill(sym << 4 | l as u16);
            e += span;
        }
        self.fast[e..].fill(0);
        Ok(())
    }

    /// Decodes the symbol at the top of `bits`; returns it with its code length.
    #[inline(always)]
    fn decode(&self, bits: u32) -> Result<(usize, u32)> {
        let e = self.fast[(bits >> (32 - FAST_BITS)) as usize];
        if e & 15 != 0 {
            return Ok(((e >> 4) as usize, (e & 15) as u32));
        }
        self.decode_long(bits)
    }

    #[inline(never)]
    fn decode_long(&self, bits: u32) -> Result<(usize, u32)> {
        let next15 = bits >> (32 - MAX_CODE_LEN);
        for l in FAST_BITS as usize + 1..=MAX_CODE_LEN {
            let code = next15 >> (MAX_CODE_LEN - l);
            if code < self.limit[l] {
                let i = code.wrapping_sub(self.first[l]).wrapping_add(self.base[l]);
                if let Some(&sym) = self.sorted.get(i as usize) {
                    return Ok((sym as usize, l as u32));
                }
                break;
            }
        }
        bail!("corrupt XPRESS stream (Huffman code)")
    }
}

/// Compresses `src` into `dst` (cleared first); returns false, leaving `dst` unspecified, if
/// the result would not be smaller than `src`. Allocates fresh match-finder state; reuse an
/// [`Encoder`] to avoid that.
#[allow(dead_code)]
pub fn compress(src: &[u8], dst: &mut Vec<u8>) -> bool {
    Encoder::new().compress(src, dst)
}

/// A match (`len > 0`) preceded by `lits` literals; `len == 0` marks trailing literals.
#[derive(Clone, Copy)]
struct Seq {
    lits: u32,
    len: u32,
    dist: u32,
}

/// Reusable compressor state: hash chains over the last 64 KiB and per-block scratch.
pub struct Encoder {
    /// Most recent position (plus `base`) for each hash of four bytes.
    head: Vec<u32>,
    /// Distance from a position to the previous one with the same hash (0: none), indexed by
    /// position modulo `CHAIN`.
    link: Vec<u16>,
    /// Added to positions so entries left over from earlier inputs are out of reach.
    base: u32,
    seqs: Vec<Seq>,
    freq: [u32; SYMBOLS],
    /// Distance bits and extra length bytes in the current block.
    extra_bits: u64,
    extra_bytes: usize,
    lens: [u8; SYMBOLS],
    codes: [u16; SYMBOLS],
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    pub fn new() -> Self {
        Encoder {
            head: vec![0; 1 << HASH_BITS],
            link: vec![0; CHAIN],
            base: GAP,
            seqs: Vec::new(),
            freq: [0; SYMBOLS],
            extra_bits: 0,
            extra_bytes: 0,
            lens: [0; SYMBOLS],
            codes: [0; SYMBOLS],
        }
    }

    /// Compresses `src` into `dst` (cleared first); returns false, leaving `dst`
    /// unspecified, if the result would not be smaller than `src`.
    pub fn compress(&mut self, src: &[u8], dst: &mut Vec<u8>) -> bool {
        self.encode(src, dst, src.len())
    }

    /// Encodes `src` into `dst` unless the output would reach `limit` bytes.
    fn encode(&mut self, src: &[u8], dst: &mut Vec<u8>, limit: usize) -> bool {
        dst.clear();
        if src.is_empty() || src.len() > MAX_INPUT {
            return false;
        }
        // Positions are stored as `base + pos`, with a gap wider than any match distance
        // between inputs, so nothing from a previous input looks close enough to match.
        if self.base as usize > u32::MAX as usize - src.len() - 2 * GAP as usize {
            self.head.fill(0);
            self.base = GAP;
        }
        dst.reserve(limit.min(src.len()));
        let mut start = 0;
        let ok = loop {
            let end = self.parse_block(src, start);
            let last = end >= src.len();
            if !self.write_block(src, start, last, dst, limit) {
                break false;
            }
            if last {
                break dst.len() < limit;
            }
            start = end;
        };
        self.base += src.len() as u32 + GAP;
        ok
    }

    /// LZ77 pass over one block: from `start` until at least `BLOCK` bytes are covered (the
    /// last match may run further) or the input ends. Fills `seqs` and `freq`; returns the end.
    fn parse_block(&mut self, src: &[u8], start: usize) -> usize {
        self.seqs.clear();
        self.freq = [0; SYMBOLS];
        self.extra_bits = 0;
        self.extra_bytes = 0;
        let limit = src.len().min(start + BLOCK);
        // Hashing reads four bytes; the last three positions are only ever literals.
        let hash_end = src.len().saturating_sub(MIN_MATCH);
        let (mut p, mut lit) = (start, start);
        let (mut last_dist, mut misses) = (0usize, 0u32);
        while p < limit {
            let (len, dist) = if p < hash_end {
                let cand = self.insert(src, p);
                self.longest_match(src, p, cand, last_dist)
            } else {
                (0, 0)
            };
            if len == 0 {
                let end = limit.min(p + 1 + (misses >> SKIP_SHIFT) as usize);
                misses += 1;
                for &b in &src[p..end] {
                    self.freq[b as usize] += 1;
                }
                p = end;
                continue;
            }
            misses = 0;
            last_dist = dist;
            self.seqs.push(Seq { lits: (p - lit) as u32, len: len as u32, dist: dist as u32 });
            let dist_bits = dist.ilog2();
            self.freq[match_symbol(len, dist_bits)] += 1;
            self.extra_bits += dist_bits as u64;
            self.extra_bytes += extra_length_bytes(len);
            let end = p + len;
            let from = if len <= INSERT_ALL { p + 1 } else { end - 4 };
            for q in from..end.min(hash_end) {
                self.insert(src, q);
            }
            p = end;
            lit = p;
        }
        if lit < p {
            self.seqs.push(Seq { lits: (p - lit) as u32, len: 0, dist: 0 });
        }
        p
    }

    /// Records position `p` (at least four bytes before the end) in the hash chains; returns
    /// the previous position with the same hash (plus `base`).
    #[inline(always)]
    fn insert(&mut self, src: &[u8], p: usize) -> u32 {
        let h = read_u32(src, p).wrapping_mul(0x9e37_79b1) >> (32 - HASH_BITS);
        let cur = self.base + p as u32;
        let cand = std::mem::replace(&mut self.head[h as usize], cur);
        let d = cur.wrapping_sub(cand);
        self.link[p % CHAIN] = if d <= MAX_DIST as u32 { d as u16 } else { 0 };
        cand
    }

    /// Longest match for position `p` among the last match distance and the hash chain
    /// starting at `cand`; `(0, 0)` if there is none worth coding.
    #[inline(always)]
    fn longest_match(&self, src: &[u8], p: usize, cand: u32, last_dist: usize) -> (usize, usize) {
        let max = src.len() - p;
        let (mut best, mut best_dist) = (MIN_MATCH - 1, 0);
        let here = read_u32(src, p) & 0x00ff_ffff;
        // Screen content repeats at the same distance (rows of glyphs, patterns): try that first.
        if last_dist != 0 && last_dist <= p && read_u32(src, p - last_dist) & 0x00ff_ffff == here {
            best = match_length(src, p - last_dist, p, max);
            best_dist = last_dist;
        }
        let mut dist = (self.base + p as u32).wrapping_sub(cand) as usize;
        for _ in 0..MAX_CHAIN {
            if best >= NICE_MATCH || best == max || dist == 0 || dist > MAX_DIST || dist > p {
                break;
            }
            let q = p - dist;
            if src[q + best] == src[p + best] && dist != best_dist {
                let len = match_length(src, q, p, max);
                if len > best {
                    (best, best_dist) = (len, dist);
                }
            }
            match self.link[q % CHAIN] {
                0 => break,
                l => dist += l as usize,
            }
        }
        if best < MIN_MATCH || (best == MIN_MATCH && best_dist > FAR_MIN_MATCH) {
            return (0, 0);
        }
        (best, best_dist)
    }

    /// Huffman-codes the parsed block into `dst`. Returns false, writing nothing, once the
    /// output would reach `limit` bytes.
    fn write_block(&mut self, src: &[u8], start: usize, last: bool, dst: &mut Vec<u8>, limit: usize) -> bool {
        if last {
            self.freq[EOF_SYMBOL] += 1;
        }
        huffman_lengths(&self.freq, &mut self.lens);
        canonical_codes(&self.lens, &mut self.codes);
        // Exact size: the table, the words holding the bits plus the reserved trailing word,
        // and the extra length bytes.
        let bits: u64 = self.freq.iter().zip(&self.lens).map(|(&f, &l)| f as u64 * l as u64).sum::<u64>() + self.extra_bits;
        let size = TABLE_BYTES + 2 * (bits.div_ceil(16) as usize + 1) + self.extra_bytes;
        if dst.len() + size >= limit {
            return false;
        }

        let base = dst.len();
        dst.resize(base + size, 0);
        let (table, stream) = dst[base..].split_at_mut(TABLE_BYTES);
        for (t, l) in table.iter_mut().zip(self.lens.as_chunks::<2>().0) {
            *t = l[0] | l[1] << 4;
        }
        let mut w = BitWriter::new(stream);
        let mut p = start;
        for s in &self.seqs {
            for &b in &src[p..p + s.lits as usize] {
                w.put(self.lens[b as usize] as u32, self.codes[b as usize] as u32);
            }
            p += s.lits as usize;
            if s.len == 0 {
                continue;
            }
            let (len, dist) = (s.len as usize, s.dist);
            let dist_bits = dist.ilog2();
            let sym = match_symbol(len, dist_bits);
            let (n, code) = (self.lens[sym] as u32, self.codes[sym] as u32);
            let low = dist - (1 << dist_bits);
            if len - MIN_MATCH < 15 {
                w.put(n + dist_bits, code << dist_bits | low);
            } else {
                w.put(n, code);
                let l = len - MIN_MATCH - 15;
                if l < 255 {
                    w.bytes(&[l as u8]);
                } else if len - MIN_MATCH < 1 << 16 {
                    w.bytes(&[255]);
                    w.bytes(&((len - MIN_MATCH) as u16).to_le_bytes());
                } else {
                    w.bytes(&[255, 0, 0]);
                    w.bytes(&((len - MIN_MATCH) as u32).to_le_bytes());
                }
                w.put(dist_bits, low);
            }
            p += len;
        }
        if last {
            w.put(self.lens[EOF_SYMBOL] as u32, self.codes[EOF_SYMBOL] as u32);
        }
        let written = w.flush();
        debug_assert_eq!(written, size - TABLE_BYTES);
        true
    }
}

/// Huffman symbol of a match of `len` bytes whose distance has `dist_bits` low bits.
#[inline]
fn match_symbol(len: usize, dist_bits: u32) -> usize {
    256 + (len - MIN_MATCH).min(15) + 16 * dist_bits as usize
}

/// Bytes the length of a `len`-byte match occupies outside the bit stream.
fn extra_length_bytes(len: usize) -> usize {
    match len - MIN_MATCH {
        0..15 => 0,
        15..270 => 1,
        270..65536 => 3,
        _ => 7,
    }
}

#[inline(always)]
fn read_u32(src: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(src[i..i + 4].try_into().unwrap_or_default())
}

#[inline(always)]
fn read_u64(src: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(src[i..i + 8].try_into().unwrap_or_default())
}

/// Number of equal bytes at `src[q..]` and `src[p..]` (`q < p`), at most `max`.
#[inline]
fn match_length(src: &[u8], q: usize, p: usize, max: usize) -> usize {
    let mut n = 0;
    while n + 8 <= max {
        let x = read_u64(src, q + n) ^ read_u64(src, p + n);
        if x != 0 {
            return n + (x.trailing_zeros() / 8) as usize;
        }
        n += 8;
    }
    while n < max && src[q + n] == src[p + n] {
        n += 1;
    }
    n
}

/// The [MS-XCA] bit writer: bits fill little-endian 16-bit words most significant first. Two
/// word slots are reserved ahead, so bytes written in between land exactly where the decoder,
/// which keeps 32 bits loaded, reads them. A word is only emitted once more than 16 bits are
/// pending, mirroring when the decoder refills.
///
/// Writes into a zeroed buffer sized exactly for the block (see `write_block`).
struct BitWriter<'a> {
    buf: &'a mut [u8],
    end: usize,
    acc: u64,
    n: u32,
    slot1: usize,
    slot2: usize,
}

impl<'a> BitWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        BitWriter { buf, end: 4, acc: 0, n: 0, slot1: 0, slot2: 2 }
    }

    /// Appends the `n` (at most 30) low bits of `v`.
    #[inline(always)]
    fn put(&mut self, n: u32, v: u32) {
        self.acc = self.acc << n | v as u64;
        self.n += n;
        while self.n > 16 {
            self.n -= 16;
            let w = (self.acc >> self.n) as u16;
            self.buf[self.slot1..self.slot1 + 2].copy_from_slice(&w.to_le_bytes());
            self.slot1 = self.slot2;
            self.slot2 = self.end;
            self.end += 2;
        }
    }

    /// Appends bytes outside the bit stream.
    fn bytes(&mut self, b: &[u8]) {
        self.buf[self.end..self.end + b.len()].copy_from_slice(b);
        self.end += b.len();
    }

    /// Writes the pending bits (the second reserved word stays zero); returns the size.
    fn flush(self) -> usize {
        let w = (self.acc << (16 - self.n)) as u16;
        self.buf[self.slot1..self.slot1 + 2].copy_from_slice(&w.to_le_bytes());
        self.end
    }
}

/// Length-limited Huffman code lengths for `freq` (at least two symbols always get a code,
/// so the code is complete). Ties are broken by symbol value, as in the [MS-XCA] examples.
fn huffman_lengths(freq: &[u32; SYMBOLS], lens: &mut [u8; SYMBOLS]) {
    *lens = [0; SYMBOLS];
    // Sort keys: frequency above the symbol value (a block has fewer than 2^23 symbols).
    let mut keys = [0u32; SYMBOLS];
    let mut n = 0;
    for (s, &f) in freq.iter().enumerate() {
        if f != 0 {
            keys[n] = f.min((1 << 23) - 1) << 9 | s as u32;
            n += 1;
        }
    }
    // A complete code needs two symbols; add unused ones (weight 0) if necessary.
    for (s, &f) in freq.iter().enumerate().take(2) {
        if n < 2 && f == 0 {
            keys[n] = s as u32;
            n += 1;
        }
    }
    let keys = &mut keys[..n];
    keys.sort_unstable();
    let mut depth = [0u32; SYMBOLS];
    let depth = &mut depth[..n];
    for (d, k) in depth.iter_mut().zip(keys.iter()) {
        *d = k >> 9;
    }
    minimum_redundancy(depth);

    // Clamp to 15 bits, then until the code fits again: drop one 15-bit code and split the
    // longest shorter code in two, which frees one unit of 2^-15 and keeps the code count.
    let mut count = [0u32; MAX_CODE_LEN + 1];
    for &d in depth.iter() {
        count[(d as usize).clamp(1, MAX_CODE_LEN)] += 1;
    }
    let mut space: u32 = (1..=MAX_CODE_LEN).map(|l| count[l] << (MAX_CODE_LEN - l)).sum();
    while space > 1 << MAX_CODE_LEN {
        let Some(l) = (1..MAX_CODE_LEN).rev().find(|&l| count[l] != 0) else { break };
        if count[MAX_CODE_LEN] == 0 {
            break;
        }
        count[MAX_CODE_LEN] -= 1;
        count[l] -= 1;
        count[l + 1] += 2;
        space -= 1;
    }
    // Rarest symbols get the longest codes.
    let mut it = keys.iter();
    for l in (1..=MAX_CODE_LEN).rev() {
        for _ in 0..count[l] {
            if let Some(&k) = it.next() {
                lens[(k & 511) as usize] = l as u8;
            }
        }
    }
}

/// Moffat and Katajainen's in-place minimum-redundancy code computation: `a` holds weights
/// in ascending order (at least two) and receives the code length of each.
fn minimum_redundancy(a: &mut [u32]) {
    let n = a.len();
    if n < 2 {
        a.fill(1);
        return;
    }
    // Pass 1: combine, leaving parent pointers in a[..n-1].
    a[0] += a[1];
    let (mut root, mut leaf) = (0usize, 2usize);
    for next in 1..n - 1 {
        if leaf >= n || a[root] < a[leaf] {
            a[next] = a[root];
            a[root] = next as u32;
            root += 1;
        } else {
            a[next] = a[leaf];
            leaf += 1;
        }
        if leaf >= n || (root < next && a[root] < a[leaf]) {
            a[next] += a[root];
            a[root] = next as u32;
            root += 1;
        } else {
            a[next] += a[leaf];
            leaf += 1;
        }
    }
    // Pass 2: internal node depths.
    a[n - 2] = 0;
    for next in (0..n - 2).rev() {
        a[next] = a[a[next] as usize] + 1;
    }
    // Pass 3: leaf depths.
    let (mut avail, mut used, mut depth) = (1usize, 0usize, 0u32);
    let (mut root, mut next) = (n as isize - 2, n as isize - 1);
    while avail > 0 {
        while root >= 0 && a[root as usize] == depth {
            used += 1;
            root -= 1;
        }
        while avail > used {
            a[next as usize] = depth;
            next -= 1;
            avail -= 1;
        }
        avail = 2 * used;
        depth += 1;
        used = 0;
    }
}

/// Canonical codes: by length, then symbol value, counting up (as the decoder's table).
fn canonical_codes(lens: &[u8; SYMBOLS], codes: &mut [u16; SYMBOLS]) {
    let mut count = [0u32; MAX_CODE_LEN + 1];
    for &l in lens {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; MAX_CODE_LEN + 1];
    let mut code = 0u32;
    for l in 1..=MAX_CODE_LEN {
        next[l] = code;
        code = (code + count[l]) << 1;
    }
    for (c, &l) in codes.iter_mut().zip(lens) {
        if l != 0 {
            *c = next[l as usize] as u16;
            next[l as usize] += 1;
        }
    }
}

#[cfg(test)]
pub(in crate::codec) mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        crate::util::hex_decode(s).unwrap()
    }

    fn noise(n: usize, seed: u32, mask: u8) -> Vec<u8> {
        let mut s = seed;
        (0..n)
            .map(|_| {
                s = s.wrapping_mul(1664525).wrapping_add(1013904223);
                (s >> 24) as u8 & mask
            })
            .collect()
    }

    /// The two worked examples of [MS-XCA] section 3.2: (data, compressed).
    fn spec_examples() -> [(Vec<u8>, Vec<u8>); 2] {
        let mut alphabet = vec![0u8; TABLE_BYTES];
        alphabet[48] = 0x50;
        alphabet[49..59].fill(0x55);
        alphabet[59..62].copy_from_slice(&[0x45, 0x44, 0x04]);
        alphabet[128] = 0x04;
        alphabet.extend(hex("d8523ed794115be9195ff9d67cdf8d0400000000"));
        let mut abc = vec![0u8; TABLE_BYTES];
        abc[48..50].copy_from_slice(&[0x30, 0x23]);
        abc[128] = 0x02;
        abc[143] = 0x20;
        abc.extend(hex("a8dc0000ff2601"));
        [
            (b"abcdefghijklmnopqrstuvwxyz".to_vec(), alphabet),
            (b"abc".iter().cycle().take(300).copied().collect(), abc),
        ]
    }

    /// Text, then a run of 140000 spaces that crosses the first block boundary (32-bit
    /// length), then a second block.
    fn golden_input() -> Vec<u8> {
        let mut v: Vec<u8> = b"MS-XCA golden vector; ".iter().cycle().take(440).copied().collect();
        v.extend(std::iter::repeat_n(b' ', 140_000));
        v.extend((0..200u32).map(|i| ((i * i) >> 3) as u8));
        v
    }

    /// cabinet.dll's output (`COMPRESS_ALGORITHM_XPRESS_HUFF | COMPRESS_RAW`) for `golden_input()`.
    const GOLDEN: &[&str] = &[
        "0000000000000000000000000000000003000000000050000000000000500000",
        "5050000000005000005000000500000000504550000004440004040400000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000040000000000000000000000000000000000000000000000000",
        "0000000000000040000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "edd6e0cc4f7d82c4ae0b71ad244c0000ff9f01ff0000dc220200858807088688",
        "0780088887000800070005060708080887088708088088000700080687800680",
        "0708088808080788808088870800870008888807880807080800060700800600",
        "8000880708887707770777777700077007700776770700700077070707007600",
        "7700770600700700070707077777070700000777070077707770070000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000001008b896b8c",
        "4c1c7993b97907fa7b42534b655fc30872f0a573f2ee41506b3fb819047b26b3",
        "b1d4437c3f81bbb5d3c5eedff34f91574f250caeebc0c70decdbd74a8c306ca5",
        "76d8e807f24fa2b85ae717ca856f0a31c6dd74a1a8e67ee9ca3f549150d0f5a4",
        "ea54613d513429760e650378d6b9a4a5625aa36954f165faa2e0f44dbb548fc2",
        "fbe18602044237847093ff5d05463bd89dbc76798d8263431f3025e61cfdbce1",
        "c9d80e02c8af4f96e1720000",
    ];

    #[test]
    fn decodes_spec_examples() {
        for (data, packed) in spec_examples() {
            let mut out = vec![0u8; data.len()];
            decompress(&packed, &mut out).unwrap();
            assert_eq!(out, data);
        }
    }

    #[test]
    fn encodes_spec_examples_bit_exactly() {
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        for (data, packed) in spec_examples() {
            assert!(enc.encode(&data, &mut out, usize::MAX));
            assert_eq!(out, packed);
        }
    }

    #[test]
    fn decodes_cabinet_golden_stream() {
        let packed = hex(&GOLDEN.concat());
        let data = golden_input();
        let mut out = vec![0u8; data.len()];
        decompress(&packed, &mut out).unwrap();
        assert!(out == data);
        let mut ours = Vec::new();
        assert!(compress(&data, &mut ours));
        decompress(&ours, &mut out).unwrap();
        assert!(out == data);
    }

    fn roundtrip(enc: &mut Encoder, data: &[u8]) -> Option<usize> {
        let mut packed = Vec::new();
        if !enc.compress(data, &mut packed) {
            return None;
        }
        assert!(packed.len() < data.len());
        let mut out = vec![0u8; data.len()];
        decompress(&packed, &mut out).unwrap();
        assert!(out == data, "roundtrip of {} bytes differs", data.len());
        Some(packed.len())
    }

    #[test]
    fn extended_lengths_and_block_boundaries() {
        let mut enc = Encoder::new();
        // Runs whose matches need no, one, three and seven extra length bytes, at varying
        // bit alignments, some crossing block boundaries.
        for lead in [1usize, 3, 7, 12, 30] {
            for run in [17usize, 18, 19, 20, 272, 273, 274, 65538, 65539, 65540, 70_000, 200_000] {
                let mut data = noise(lead, run as u32, 0xff);
                data.extend(std::iter::repeat_n(0x5a, run));
                data.extend(noise(lead * 5 + 100, lead as u32, 0x0f));
                roundtrip(&mut enc, &data);
            }
        }
        // Exactly one and two full blocks, and one byte more or less.
        for n in [65535, 65536, 65537, 131_071, 131_072, 131_073] {
            assert!(roundtrip(&mut enc, &noise(n, n as u32, 0x0f)).is_some());
        }
        // One match spanning many blocks: a single block with a 32-bit length.
        assert!(roundtrip(&mut enc, &vec![0u8; 1 << 20]).unwrap() < 300);
    }

    /// A full block of noise, then a run that a single match covers: the second block holds
    /// one symbol, so its code is padded with an unused one.
    pub(in crate::codec) fn single_symbol_block_input() -> Vec<u8> {
        [vec![0; 8], noise(65528, 9, 0x0f), vec![0; 100_000], noise(100, 10, 0xff)].concat()
    }

    #[test]
    fn single_symbol_block() {
        let data = single_symbol_block_input();
        let mut enc = Encoder::new();
        let end = enc.parse_block(&data, 0);
        enc.parse_block(&data, end);
        assert_eq!(enc.freq.iter().filter(|&&f| f != 0).count(), 1);
        roundtrip(&mut Encoder::new(), &data).unwrap();
    }

    #[test]
    fn encoder_output_does_not_depend_on_history() {
        let inputs: Vec<Vec<u8>> =
            (0..12u32).map(|i| noise(1000 + 7000 * i as usize, i, if i % 2 == 0 { 0x07 } else { 0x3f })).collect();
        let mut reused = Encoder::new();
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for (i, data) in inputs.iter().enumerate() {
            if i == 6 {
                // Make the position counter wrap around on this input.
                reused.base = u32::MAX - 1000;
            }
            assert_eq!(reused.compress(data, &mut a), Encoder::new().compress(data, &mut b));
            assert!(a == b, "input {i} encoded differently");
            roundtrip(&mut reused, data);
        }
    }

    #[test]
    fn incompressible_input_is_refused() {
        let mut out = Vec::new();
        assert!(!compress(&[], &mut out));
        assert!(!compress(&[7], &mut out));
        assert!(!compress(&noise(100_000, 1, 0xff), &mut out));
        assert!(compress(&noise(100_000, 1, 0x0f), &mut out));
    }

    /// Checks that the code lengths for `freq` are complete (Kraft sum exactly 1), at most
    /// 15 bits, and present for every used symbol.
    fn check_lengths(freq: &[u32; SYMBOLS]) -> [u8; SYMBOLS] {
        let mut lens = [0u8; SYMBOLS];
        huffman_lengths(freq, &mut lens);
        let space: u32 = lens.iter().filter(|&&l| l != 0).map(|&l| 1 << (MAX_CODE_LEN - l as usize)).sum();
        assert_eq!(space, 1 << MAX_CODE_LEN);
        for (f, l) in freq.iter().zip(&lens) {
            assert!(*l as usize <= MAX_CODE_LEN);
            assert!(*f == 0 || *l != 0);
        }
        lens
    }

    #[test]
    fn huffman_lengths_are_limited_and_complete() {
        // Fibonacci weights would need codes far longer than 15 bits.
        let mut freq = [0u32; SYMBOLS];
        let (mut a, mut b) = (1u32, 1u32);
        for f in freq.iter_mut().take(30) {
            *f = a;
            (a, b) = (b, a + b);
        }
        assert_eq!(check_lengths(&freq).iter().copied().max(), Some(15));
        // A single symbol still gets a complete code.
        let mut freq = [0u32; SYMBOLS];
        freq[300] = 5;
        let lens = check_lengths(&freq);
        assert_eq!((lens[0], lens[300]), (1, 1));
        // All symbols equally likely: 9 bits each.
        assert!(check_lengths(&[3; SYMBOLS]).iter().all(|&l| l == 9));
        for seed in 0..50 {
            let mut freq = [0u32; SYMBOLS];
            for (f, r) in freq.iter_mut().zip(noise(SYMBOLS, seed, 0xff)) {
                *f = if r < 128 { 0 } else { (r as u32 - 127).pow(3) };
            }
            check_lengths(&freq);
        }
    }

    /// A stream with a hand-made table of `(symbol, code length)` and a body of
    /// `(bit count, bits, bytes after them)`, laid out as the encoder does.
    fn craft(codes: &[(usize, u8)], body: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut out = vec![0u8; TABLE_BYTES + 64];
        for &(s, l) in codes {
            out[s / 2] |= l << (4 * (s % 2));
        }
        let mut w = BitWriter::new(&mut out[TABLE_BYTES..]);
        for &(n, v, bytes) in body {
            w.put(n, v);
            w.bytes(bytes);
        }
        let n = w.flush();
        out.truncate(TABLE_BYTES + n);
        out
    }

    #[test]
    fn rejects_malformed_streams() {
        // Codes: 'x' = 0, end of stream = 10, match with extended length at distance 1 = 11.
        let table = [(b'x' as usize, 1), (EOF_SYMBOL, 2), (256 + 15, 2)];
        let ok = craft(&table, &[(1, 0, &[]), (2, 3, &[0]), (2, 2, &[])]);
        let mut out = [0u8; 19];
        decompress(&ok, &mut out).unwrap();
        assert_eq!(out, [b'x'; 19]);
        // 16-bit and 32-bit extended lengths (300 + 3).
        let mut out = vec![0u8; 304];
        let ok16 = craft(&table, &[(1, 0, &[]), (2, 3, &[255, 0x2c, 0x01]), (2, 2, &[])]);
        decompress(&ok16, &mut out).unwrap();
        let ok32 = craft(&table, &[(1, 0, &[]), (2, 3, &[255, 0, 0, 0x2c, 0x01, 0, 0]), (2, 2, &[])]);
        decompress(&ok32, &mut out).unwrap();
        assert!(out.iter().all(|&b| b == b'x'));

        let mut out = [0u8; 20];
        let bad: [(&str, Vec<u8>); 9] = [
            ("empty", Vec::new()),
            ("table only", ok[..TABLE_BYTES].to_vec()),
            ("truncated", ok[..ok.len() - 1].to_vec()),
            ("incomplete code", craft(&[(b'x' as usize, 1), (EOF_SYMBOL, 2)], &[(1, 0, &[])])),
            ("oversubscribed code", craft(&[(b'x' as usize, 1), (EOF_SYMBOL, 1), (b'y' as usize, 1)], &[(1, 0, &[])])),
            ("match before any output", craft(&table, &[(2, 3, &[5])])),
            ("16-bit length below 15", craft(&table, &[(1, 0, &[]), (2, 3, &[255, 14, 0])])),
            ("32-bit length below 15", craft(&table, &[(1, 0, &[]), (2, 3, &[255, 0, 0, 3, 0, 0, 0])])),
            ("no end of stream", craft(&table, &[(1, 0, &[]), (2, 3, &[0]), (1, 0, &[])])),
        ];
        for (name, src) in bad {
            assert!(decompress(&src, &mut out[..19]).is_err(), "{name} accepted");
        }
        // Input left after the end-of-stream symbol, and output sizes off by one.
        let mut long = ok.clone();
        long.extend_from_slice(&[0, 0]);
        assert!(decompress(&long, &mut out[..19]).is_err());
        assert!(decompress(&ok, &mut out[..18]).is_err());
        assert!(decompress(&ok, &mut out[..20]).is_err());
        // Nothing to produce: only an empty stream or an encoded empty input fit.
        assert!(decompress(&[], &mut []).is_ok());
        assert!(decompress(&craft(&table, &[(2, 2, &[])]), &mut []).is_ok());
        assert!(decompress(&ok, &mut []).is_err());
    }

    /// Hostile input: random streams, random bits behind valid tables and mutations of valid
    /// streams. Decoding must never panic, and whenever it succeeds the stream must encode
    /// exactly that many bytes (one more or one fewer is an error).
    #[test]
    fn malformed_input_loop() {
        let mut s = 0x1234_5678u32;
        let mut rnd = move |n: usize| {
            s = s.wrapping_mul(1664525).wrapping_add(1013904223);
            ((s >> 8) as usize) % n.max(1)
        };
        let samples = [
            noise(5000, 1, 0x07),
            [noise(300, 2, 0xff), vec![0; 70_000], noise(3000, 3, 0x03)].concat(),
            b"abc".iter().cycle().take(5000).copied().collect(),
            golden_input(),
        ];
        let mut valid: Vec<(Vec<u8>, usize)> = samples
            .iter()
            .map(|d| {
                let mut v = Vec::new();
                assert!(compress(d, &mut v));
                (v, d.len())
            })
            .collect();
        valid.push((hex(&GOLDEN.concat()), golden_input().len()));

        let mut out = vec![0u8; 200_000];
        let mut check = |src: &[u8], n: usize| {
            let ok = decompress(src, &mut out[..n]).is_ok();
            if ok {
                assert!(decompress(src, &mut out[..n + 1]).is_err(), "accepted with one byte more");
                if n > 0 {
                    assert!(decompress(src, &mut out[..n - 1]).is_err(), "accepted with one byte less");
                }
            }
            ok
        };
        for (src, n) in &valid {
            assert!(check(src, *n));
        }
        for i in 0..30_000 {
            let (base, n) = &valid[i % valid.len()];
            let mut m = base.clone();
            match i % 3 {
                0 => m = noise(rnd(2000), i as u32, 0xff),
                1 => {
                    m.truncate(TABLE_BYTES);
                    m.extend(noise(rnd(3000), i as u32, 0xff));
                }
                _ => {
                    for _ in 0..1 + rnd(4) {
                        if m.is_empty() {
                            break;
                        }
                        let at = rnd(m.len());
                        match rnd(5) {
                            0 => m[at] ^= 1 << rnd(8),
                            1 => m[at] = rnd(256) as u8,
                            2 => m.truncate(at),
                            3 => m.insert(at, rnd(256) as u8),
                            _ => {
                                m.remove(at);
                            }
                        }
                    }
                }
            }
            check(&m, if i % 7 == 0 { rnd(*n + 1) } else { *n });
        }
    }
}
