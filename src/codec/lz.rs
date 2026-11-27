//! Lossless back end for tile data: the raw LZ77+Huffman ("XPRESS Huffman") stream of
//! [MS-XCA] section 2, with no framing (the decoder is told the exact output size).
//!
//! `xpress.rs` implements the format in pure Rust and is what every platform uses. On
//! Windows the OS codec in cabinet.dll speaks the same stream through the Compression API in
//! raw mode (`native` below); the tests use it as the reference implementation and check
//! that streams interoperate in both directions.
//!
//! Why not cabinet.dll on Windows (see the `throughput` test): on sub-filtered screen tiles
//! it compresses about 1.4x faster, but its output is 8-14% larger, which costs more time on
//! any network link than the encoder saves; decoding speed is on par, and decoding untrusted
//! input in memory-safe code keeps cabinet.dll out of the viewer's attack surface. Switching
//! is a matter of re-exporting `native::{Compressor, Decompressor}`.
//!
//! An `ENC_XPRESS` payload is always strictly smaller than the data it encodes: the
//! compressor gives up otherwise, and the decompressor rejects anything else (cabinet.dll
//! treats a raw stream as large as its output as stored, uncompressed data).

#[path = "xpress.rs"]
pub mod xpress;

pub use portable::{Compressor, Decompressor};

mod portable {
    use super::xpress;
    use crate::bail;
    use crate::util::Result;

    pub struct Compressor(Box<xpress::Encoder>);

    impl Compressor {
        pub fn new() -> Result<Self> {
            Ok(Compressor(Box::default()))
        }

        /// Compresses `src` into `dst`; returns false if the output would not be smaller.
        pub fn compress(&mut self, src: &[u8], dst: &mut Vec<u8>) -> bool {
            self.0.compress(src, dst)
        }
    }

    pub struct Decompressor;

    impl Decompressor {
        pub fn new() -> Result<Self> {
            Ok(Decompressor)
        }

        /// Decompresses `src` into exactly `dst.len()` bytes.
        pub fn decompress(&mut self, src: &[u8], dst: &mut [u8]) -> Result<()> {
            if src.len() >= dst.len() {
                bail!("corrupt tile data");
            }
            xpress::decompress(src, dst).map_err(|_| "corrupt tile data".into())
        }
    }
}

/// The Compression API's XPRESS Huffman codec in raw mode (cabinet.dll).
#[cfg(windows)]
#[allow(dead_code)]
pub mod native {
    use crate::bail;
    use crate::util::{Error, Result};
    use windows_sys::Win32::Storage::Compression::*;

    const ALGORITHM: u32 = COMPRESS_ALGORITHM_XPRESS_HUFF | COMPRESS_RAW;

    pub struct Compressor(COMPRESSOR_HANDLE);
    unsafe impl Send for Compressor {}

    impl Compressor {
        pub fn new() -> Result<Self> {
            let mut h = std::ptr::null_mut();
            if unsafe { CreateCompressor(ALGORITHM, std::ptr::null(), &mut h) } == 0 {
                return Err(Error::last_os("CreateCompressor"));
            }
            Ok(Compressor(h))
        }

        /// Compresses `src` into `dst`; returns false if the output would not be smaller.
        pub fn compress(&mut self, src: &[u8], dst: &mut Vec<u8>) -> bool {
            dst.clear();
            if src.is_empty() {
                return false;
            }
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

    pub struct Decompressor(DECOMPRESSOR_HANDLE);
    unsafe impl Send for Decompressor {}

    impl Decompressor {
        pub fn new() -> Result<Self> {
            let mut h = std::ptr::null_mut();
            if unsafe { CreateDecompressor(ALGORITHM, std::ptr::null(), &mut h) } == 0 {
                return Err(Error::last_os("CreateDecompressor"));
            }
            Ok(Decompressor(h))
        }

        /// Decompresses `src` into exactly `dst.len()` bytes.
        pub fn decompress(&mut self, src: &[u8], dst: &mut [u8]) -> Result<()> {
            if src.len() >= dst.len() {
                bail!("corrupt tile data");
            }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes.
    fn noise(n: usize, seed: u32, mask: u8) -> Vec<u8> {
        let mut s = seed;
        (0..n)
            .map(|_| {
                s = s.wrapping_mul(1664525).wrapping_add(1013904223);
                (s >> 24) as u8 & mask
            })
            .collect()
    }

    /// A synthetic desktop (BGR, `w*h*3`): title bar, sidebar and document with anti-aliased
    /// text, a gradient panel and a photo-like area.
    fn desktop(w: usize, h: usize, seed: u32) -> Vec<u8> {
        let mut s = seed;
        let mut rnd = move || {
            s = s.wrapping_mul(1664525).wrapping_add(1013904223);
            s >> 8
        };
        // 64 glyphs of 7x12 coverage values.
        let glyphs: Vec<[u8; 84]> = (0..64)
            .map(|_| {
                let mut g = [0u8; 84];
                for c in g.iter_mut().skip(14).take(56) {
                    *c = [0, 0, 0, 96, 255, 255, 160, 0][rnd() as usize % 8];
                }
                g
            })
            .collect();
        let line: Vec<usize> = (0..w / 8 + 1).map(|_| if rnd() % 6 == 0 { usize::MAX } else { rnd() as usize % 64 }).collect();
        let mut px = vec![0u8; w * h * 3];
        for y in 0..h {
            for x in 0..w {
                let (bg, fg): ([u8; 3], [u8; 3]) = if y < 30 {
                    ([120, 70, 30], [255, 255, 255])
                } else if x < w / 5 {
                    ([243, 243, 243], [60, 60, 60])
                } else {
                    ([255, 255, 255], [30, 30, 30])
                };
                let mut c = bg;
                if x >= w / 5 && x < w / 2 && y >= h / 2 {
                    c = [(x / 3) as u8, (y / 3) as u8, 180];
                } else if x > 2 * w / 3 && y > h / 3 {
                    let n = (rnd() % 9) as u8;
                    c = [(x / 5 + y / 7) as u8 / 2 + n, (y / 3) as u8 / 2 + n, 90 + n];
                } else if (y % 16) >= 2 && (y % 16) < 14 {
                    // Text lines: each line of the screen reuses a shifted glyph sequence.
                    let gi = line[(x / 8 + y / 16 * 7) % line.len()];
                    if gi != usize::MAX && x % 8 < 7 {
                        let cov = glyphs[gi][(y % 16 - 2) * 7 + x % 8] as u32;
                        c = std::array::from_fn(|i| ((bg[i] as u32 * (255 - cov) + fg[i] as u32 * cov) / 255) as u8);
                    }
                }
                px[(y * w + x) * 3..(y * w + x) * 3 + 3].copy_from_slice(&c);
            }
        }
        px
    }

    /// Left-neighbour prediction per row, as the tile encoder applies before compressing.
    fn sub_filter(px: &[u8], w: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(px.len());
        for row in px.chunks_exact(w * 3) {
            let mut last = [0u8; 3];
            for p in row.as_chunks::<3>().0 {
                out.extend((0..3).map(|i| p[i].wrapping_sub(last[i])));
                last.copy_from_slice(p);
            }
        }
        out
    }

    /// Sub-filtered synthetic desktop, as the tile encoder hands it to the compressor.
    fn screen(w: usize, h: usize, seed: u32) -> Vec<u8> {
        sub_filter(&desktop(w, h, seed), w)
    }

    fn shapes() -> Vec<(&'static str, Vec<u8>)> {
        let text: Vec<u8> = b"The quick brown fox jumps over the lazy dog; 0123456789. "
            .iter()
            .cycle()
            .take(200_000)
            .copied()
            .collect();
        let mut runs = Vec::new();
        for i in 0..40u32 {
            runs.extend(std::iter::repeat_n((i * 7) as u8, 1 + (i as usize * 4099) % 30_000));
        }
        vec![
            ("1 byte", vec![42]),
            ("small text", b"abcabcabcabcabcabcabcabc hello hello hello hello".to_vec()),
            ("spec example", b"abc".iter().cycle().take(300).copied().collect()),
            ("exactly 64 KiB", screen(512, 64, 1)[..65536].to_vec()),
            ("exactly 128 KiB", noise(131_072, 7, 0x1f)),
            ("64 KiB + 1", noise(65537, 2, 0x0f)),
            ("multi-block", screen(1000, 64, 3)),
            ("random", noise(100_000, 4, 0xff)),
            ("low entropy", noise(150_000, 5, 0x03)),
            ("zeros 1 MiB", vec![0; 1 << 20]),
            ("long runs", runs),
            ("repetitive text", text),
            ("screen 1920x64", screen(1920, 64, 6)),
        ]
    }

    #[test]
    fn roundtrip_shapes() {
        let mut c = Compressor::new().unwrap();
        let mut d = Decompressor::new().unwrap();
        let mut buf = Vec::new();
        for (name, data) in shapes() {
            if c.compress(&data, &mut buf) {
                assert!(buf.len() < data.len(), "{name}");
                let mut out = vec![0u8; data.len()];
                d.decompress(&buf, &mut out).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert!(out == data, "{name}: output differs");
                // Wrong sizes are rejected.
                let mut short = vec![0u8; data.len() - 1];
                assert!(d.decompress(&buf, &mut short).is_err(), "{name}: shorter output accepted");
                let mut long = vec![0u8; data.len() + 1];
                assert!(d.decompress(&buf, &mut long).is_err(), "{name}: longer output accepted");
            } else {
                assert!(matches!(name, "1 byte" | "small text" | "random"), "{name} did not compress");
            }
        }
    }

    #[test]
    fn decompressor_rejects_stored_sized_input() {
        let mut d = Decompressor::new().unwrap();
        let mut out = vec![0u8; 8];
        assert!(d.decompress(&[1; 8], &mut out).is_err());
        assert!(d.decompress(&[1; 300], &mut out).is_err());
    }

    /// cabinet.dll as the reference: streams must interoperate in both directions.
    #[cfg(windows)]
    mod oracle {
        use super::super::{native, xpress};
        use super::*;

        fn cabinet_compress(data: &[u8]) -> Option<Vec<u8>> {
            let mut buf = Vec::new();
            native::Compressor::new().unwrap().compress(data, &mut buf).then_some(buf)
        }

        fn cabinet_decompress(src: &[u8], n: usize) -> Option<Vec<u8>> {
            let mut out = vec![0u8; n];
            native::Decompressor::new().unwrap().decompress(src, &mut out).ok().map(|_| out)
        }

        #[test]
        fn cabinet_to_rust() {
            let mut checked = 0;
            for (name, data) in shapes() {
                let Some(c) = cabinet_compress(&data) else { continue };
                let mut out = vec![0u8; data.len()];
                xpress::decompress(&c, &mut out).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert!(out == data, "{name}: output differs");
                checked += 1;
            }
            assert!(checked >= 8, "cabinet.dll compressed only {checked} shapes");
        }

        #[test]
        fn rust_to_cabinet() {
            let mut enc = xpress::Encoder::new();
            let mut buf = Vec::new();
            for (name, data) in shapes() {
                if !enc.compress(&data, &mut buf) {
                    continue;
                }
                let out = cabinet_decompress(&buf, data.len()).unwrap_or_else(|| panic!("{name}: cabinet.dll rejected it"));
                assert!(out == data, "{name}: output differs");
            }
        }

        /// Every length/position combination around the extended-length thresholds and block
        /// boundaries, so extra length bytes land at every bit alignment.
        #[test]
        fn match_length_edges_both_ways() {
            let mut enc = xpress::Encoder::new();
            let mut buf = Vec::new();
            let mut checked = 0;
            for prefix in [1usize, 2, 5, 9, 16, 33] {
                for run in [17usize, 18, 19, 272, 273, 274, 65537, 65538, 65539, 70000, 140_000] {
                    let mut data = noise(prefix, prefix as u32, 0xff);
                    data.extend(std::iter::repeat_n(b'x', run));
                    data.extend(noise(prefix * 3 + 400, run as u32, 0x07));
                    data.extend(std::iter::repeat_n(b'y', run / 2 + 3));
                    if enc.compress(&data, &mut buf) {
                        let out = cabinet_decompress(&buf, data.len()).unwrap_or_else(|| panic!("{prefix}/{run}: rejected"));
                        assert!(out == data, "{prefix}/{run}: cabinet output differs");
                        checked += 1;
                    }
                    if let Some(c) = cabinet_compress(&data) {
                        let mut out = vec![0u8; data.len()];
                        xpress::decompress(&c, &mut out).unwrap_or_else(|e| panic!("{prefix}/{run}: {e}"));
                        assert!(out == data, "{prefix}/{run}: our output differs");
                        checked += 1;
                    }
                }
            }
            assert!(checked > 100);
        }

        /// A block whose code holds a single symbol (padded with an unused one).
        #[test]
        fn single_symbol_block_both_ways() {
            let data = xpress::tests::single_symbol_block_input();
            let mut buf = Vec::new();
            assert!(xpress::compress(&data, &mut buf));
            assert!(cabinet_decompress(&buf, data.len()).unwrap() == data);
            let c = cabinet_compress(&data).unwrap();
            let mut out = vec![0u8; data.len()];
            xpress::decompress(&c, &mut out).unwrap();
            assert!(out == data);
        }

        /// Mutated streams: whenever both decoders accept one, they produce the same bytes.
        #[test]
        fn malformed_streams_agree_with_cabinet() {
            let data = screen(320, 64, 9);
            let mut ours = Vec::new();
            assert!(xpress::compress(&data, &mut ours));
            let valid = [cabinet_compress(&data).unwrap(), ours];
            let mut s = 12345u32;
            let mut rnd = |n: usize| {
                s = s.wrapping_mul(1664525).wrapping_add(1013904223);
                (s >> 8) as usize % n
            };
            let mut out = vec![0u8; data.len()];
            for i in 0..3000 {
                let mut m = valid[i % 2].clone();
                for _ in 0..1 + rnd(4) {
                    let at = rnd(m.len());
                    match rnd(3) {
                        0 => m[at] ^= 1 << rnd(8),
                        1 => m[at] = rnd(256) as u8,
                        _ => m.truncate(at.max(1)),
                    }
                }
                if xpress::decompress(&m, &mut out).is_ok()
                    && let Some(reference) = cabinet_decompress(&m, data.len())
                {
                    assert!(out == reference, "mutation {i}: decoders disagree");
                }
            }
        }

        /// Inputs as the tile encoder produces them from a 1920x1080 synthetic desktop:
        /// 1920x64 stripes (full refresh) and single 64x64 tiles, sub-filtered; plus noise.
        fn tile_inputs() -> [(&'static str, Vec<Vec<u8>>); 3] {
            let (w, h) = (1920, 1080);
            let px = desktop(w, h, 21);
            let stripes = px.chunks(w * 3 * 64).map(|s| sub_filter(s, w)).collect();
            let mut tiles = Vec::new();
            for ty in (0..h).step_by(64) {
                for tx in (0..w).step_by(64) {
                    let rows = ty..(ty + 64).min(h);
                    let tile: Vec<u8> = rows.flat_map(|y| px[(y * w + tx) * 3..(y * w + tx + 64) * 3].to_vec()).collect();
                    tiles.push(sub_filter(&tile, 64));
                }
            }
            let noisy = (0..8).map(|i| noise(368_640, i, 0xff)).collect();
            [("1920x64 stripes", stripes), ("64x64 tiles", tiles), ("random 1920x64", noisy)]
        }

        /// MB/s and ratio of both implementations:
        /// `cargo test --release throughput -- --ignored --nocapture`.
        #[test]
        #[ignore]
        fn throughput() {
            use windows_sys::Win32::System::Threading::GetCurrentThread;
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn QueryThreadCycleTime(thread: windows_sys::Win32::Foundation::HANDLE, cycles: *mut u64) -> i32;
            }
            // CPU cycles spent by this thread: unaffected by other processes taking turns.
            let cycles = || {
                let mut c = 0u64;
                unsafe { QueryThreadCycleTime(GetCurrentThread(), &mut c) };
                c
            };
            for (name, inputs) in tile_inputs() {
                let total: usize = inputs.iter().map(Vec::len).sum();
                let mut out = vec![0u8; 1 << 20];
                let (mut nc, mut nd, mut enc) = (native::Compressor::new().unwrap(), native::Decompressor::new().unwrap(), xpress::Encoder::new());
                let mut packed: [Vec<Option<Vec<u8>>>; 2] = [vec![None; inputs.len()], vec![None; inputs.len()]];
                // Best (wall seconds, cycles) per implementation, for compression and decompression.
                let mut best = [[(f64::MAX, u64::MAX); 2]; 2];
                for _ in 0..15 {
                    for imp in 0..2 {
                        let (t, c) = (std::time::Instant::now(), cycles());
                        let mut buf = Vec::new();
                        for (i, d) in inputs.iter().enumerate() {
                            let ok = if imp == 1 { enc.compress(d, &mut buf) } else { nc.compress(d, &mut buf) };
                            packed[imp][i] = ok.then(|| buf.clone());
                        }
                        let b = &mut best[imp][0];
                        *b = (b.0.min(t.elapsed().as_secs_f64()), b.1.min(cycles() - c));

                        let (t, c) = (std::time::Instant::now(), cycles());
                        for (p, d) in packed[imp].iter().zip(&inputs) {
                            if let Some(p) = p {
                                let o = &mut out[..d.len()];
                                if imp == 1 { xpress::decompress(p, o).unwrap() } else { nd.decompress(p, o).unwrap() }
                            }
                        }
                        let b = &mut best[imp][1];
                        *b = (b.0.min(t.elapsed().as_secs_f64()), b.1.min(cycles() - c));
                    }
                }
                println!("{name}: {} inputs, {total} bytes", inputs.len());
                for (imp, label) in ["cabinet.dll", "xpress.rs"].iter().enumerate() {
                    for (p, d) in packed[imp].iter().zip(&inputs) {
                        if let Some(p) = p {
                            let mut o = vec![0u8; d.len()];
                            xpress::decompress(p, &mut o).unwrap();
                            assert!(&o == d);
                        }
                    }
                    let size: usize = packed[imp].iter().zip(&inputs).map(|(p, d)| p.as_ref().map_or(d.len(), Vec::len)).sum();
                    let [c, d] = best[imp].map(|(secs, cyc)| (total as f64 / 1e6 / secs, cyc as f64 / total as f64));
                    println!(
                        "  {label:12} compress {:7.1} MB/s {:5.2} c/B   decompress {:7.1} MB/s {:5.2} c/B   ratio {:.4}",
                        c.0, c.1, d.0, d.1, size as f64 / total as f64
                    );
                }
            }
        }
    }
}
