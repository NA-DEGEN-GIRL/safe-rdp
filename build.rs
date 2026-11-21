//! Build script: on MSVC targets, embeds `app.manifest` (common controls v6, per-monitor
//! DPI awareness, Windows 10/11) and an application icon into the executable.
//!
//! No resource compiler is needed: the icon is drawn here and written as a `.res` file, which
//! link.exe accepts as an input like an object file. Only binaries (and their unit-test harness)
//! get these, not integration tests. `assets/icon.svg` is the same drawing for documents; keep
//! the two in step. Binaries also never take a DLL from their own folder (see `/DELAYLOAD` below).

use std::path::{Path, PathBuf};

/// Resource ID of the icon group (`launcher::ICON_ID`).
const ICON_ID: u16 = 1;
/// Sizes Windows picks from at 100-250% scaling; from 64 up they are stored as PNG.
const ICON_SIZES: [u32; 10] = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256];
/// The DLLs safe-rdp.exe imports that are not KnownDLLs, loaded on first use (see main()).
/// crypt32 is a KnownDLL only as an import of other KnownDLLs, which differs between Windows
/// versions (it is used only for the stored key). A new import that is not a KnownDLL belongs
/// here: tests/dll_imports.rs says so.
const DELAY_LOADED: [&str; 9] =
    ["avrt.dll", "bcrypt.dll", "crypt32.dll", "d3d11.dll", "dxgi.dll", "iphlpapi.dll", "sas.dll", "uxtheme.dll", "wtsapi32.dll"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=app.manifest");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os != "windows" || env != "msvc" {
        return;
    }
    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let manifest = root.join("app.manifest");
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}", manifest.display());
    // The manifest carries its own trustInfo (asInvoker); do not let the linker add another.
    println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:NO");
    // No DLL may come from the executable's own folder. The loader looks there first by
    // default, so a DLL that lands beside safe-rdp.exe (a received file, a download, another
    // user's file in a shared folder) would run as code in it, elevated during `service
    // install`. A DLL imported at start-up is loaded before main() can change that, and its own
    // imports follow its own load flags, usually none: wtsapi32 brought sspicli.dll, dxgi
    // brought powrprof.dll and with it umpdc.dll, from beside the executable. So:
    // - The DLLs in DELAY_LOADED load on first use, after main() has made System32 the only
    //   place DLLs come from (SetDefaultDllDirectories), and their imports with them.
    // - Everything still imported at start-up is a KnownDLL: Windows maps those, and what they
    //   import, from its own copies. /DEPENDENTLOADFLAG 0x800 (LOAD_LIBRARY_SEARCH_SYSTEM32)
    //   also looks for the executable's own imports in System32 only.
    // tests/dll_imports.rs checks the built executable for both.
    println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    for dll in DELAY_LOADED {
        println!("cargo:rustc-link-arg-bins=/DELAYLOAD:{dll}");
    }
    println!("cargo:rustc-link-arg-bins=delayimp.lib");
    // .cargo/config.toml links the C runtime statically, so the executable needs no Visual C++
    // redistributable on the other PC. RUSTFLAGS from the environment, or building from outside
    // this directory, replaces that setting without a word: say so.
    let features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    if !features.split(',').any(|f| f == "crt-static") {
        println!(
            "cargo:warning=the C runtime is linked dynamically (RUSTFLAGS overrides .cargo/config.toml?): \
             safe-rdp.exe will need the Visual C++ runtime (VCRUNTIME140.dll) on every PC; \
             add `-C target-feature=+crt-static` to build a self-contained executable"
        );
    }

    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR")).join("safe-rdp.res");
    write_res(&out).expect("writing the icon resource");
    println!("cargo:rustc-link-arg-bins={}", out.display());
}

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;

/// Appends one entry of a 32-bit `.res` file (ordinal type and name, language neutral).
fn res_entry(out: &mut Vec<u8>, kind: u16, id: u16, flags: u16, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // DataSize
    out.extend_from_slice(&32u32.to_le_bytes()); // HeaderSize
    out.extend_from_slice(&[0xff, 0xff]);
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&[0xff, 0xff]);
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // DataVersion
    out.extend_from_slice(&flags.to_le_bytes()); // MemoryFlags
    out.extend_from_slice(&0u16.to_le_bytes()); // LanguageId: neutral
    out.extend_from_slice(&0u32.to_le_bytes()); // Version
    out.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn write_res(path: &Path) -> std::io::Result<()> {
    let mut res = Vec::new();
    res_entry(&mut res, 0, 0, 0, &[]); // the empty entry that starts every .res file
    let mut group = Vec::new();
    group.extend_from_slice(&0u16.to_le_bytes());
    group.extend_from_slice(&1u16.to_le_bytes()); // icon
    group.extend_from_slice(&(ICON_SIZES.len() as u16).to_le_bytes());
    for (i, &size) in ICON_SIZES.iter().enumerate() {
        let px = render(size);
        let image = if size >= 64 { png(size, &px) } else { icon_dib(size, &px) };
        let id = 100 + i as u16;
        res_entry(&mut res, RT_ICON, id, 0x1010, &image);
        let side = (size % 256) as u8; // 0 means 256
        group.extend_from_slice(&[side, side, 0, 0]);
        group.extend_from_slice(&1u16.to_le_bytes()); // planes
        group.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
        group.extend_from_slice(&(image.len() as u32).to_le_bytes());
        group.extend_from_slice(&id.to_le_bytes());
    }
    res_entry(&mut res, RT_GROUP_ICON, ICON_ID, 0x1030, &group);
    std::fs::write(path, res)
}

/// One icon image: BITMAPINFOHEADER, bottom-up 32-bit BGRA pixels, then the 1-bit AND mask.
fn icon_dib(size: u32, px: &[[u8; 4]]) -> Vec<u8> {
    let mask_stride = size.div_ceil(32) * 4;
    let mut out = Vec::new();
    for v in [40u32, size, size * 2] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
    out.extend_from_slice(&(size * size * 4 + mask_stride * size).to_le_bytes());
    out.extend_from_slice(&[0u8; 16]);
    for y in (0..size).rev() {
        for x in 0..size {
            let [r, g, b, a] = px[(y * size + x) as usize];
            out.extend_from_slice(&[b, g, r, a]);
        }
    }
    for y in (0..size).rev() {
        let mut row = vec![0u8; mask_stride as usize];
        for x in 0..size {
            if px[(y * size + x) as usize][3] == 0 {
                row[(x / 8) as usize] |= 0x80 >> (x % 8);
            }
        }
        out.extend_from_slice(&row);
    }
    out
}

// ---------------------------------------------------------------------------------------
// PNG: per-row filter choice, then deflate with the fixed Huffman code and a few likely
// match distances (same pixel, previous pixel, row above), which suits flat icon art.

fn png(size: u32, px: &[[u8; 4]]) -> Vec<u8> {
    let stride = size as usize * 4;
    let mut raw = Vec::with_capacity((stride + 1) * size as usize);
    let mut prev = vec![0u8; stride];
    for line in px.chunks(size as usize) {
        let row: Vec<u8> = line.iter().flatten().copied().collect();
        let sub: Vec<u8> = (0..stride).map(|i| row[i].wrapping_sub(if i >= 4 { row[i - 4] } else { 0 })).collect();
        let up: Vec<u8> = (0..stride).map(|i| row[i].wrapping_sub(prev[i])).collect();
        let cost = |v: &[u8]| v.iter().map(|&b| (b as i8).unsigned_abs() as u32).sum::<u32>();
        let (filter, data) = [(0u8, &row), (1, &sub), (2, &up)].into_iter().min_by_key(|(_, v)| cost(v)).unwrap();
        raw.push(filter);
        raw.extend_from_slice(data);
        prev = row;
    }
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&size.to_be_bytes());
    ihdr.extend_from_slice(&size.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA, no interlace
    png_chunk(&mut out, b"IHDR", &ihdr);
    png_chunk(&mut out, b"IDAT", &zlib(&raw, stride + 1));
    png_chunk(&mut out, b"IEND", &[]);
    out
}

fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc = !0u32;
    for &v in &out[start..] {
        crc ^= v as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    out.extend_from_slice(&(!crc).to_be_bytes());
}

/// Bit writer for deflate: values go out least significant bit first.
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    acc: u32,
    n: u32,
}

impl Bits {
    fn put(&mut self, v: u32, n: u32) {
        self.acc |= v << self.n;
        self.n += n;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    /// Huffman codes are sent most significant bit first.
    fn code(&mut self, code: u32, len: u32) {
        self.put(code.reverse_bits() >> (32 - len), len);
    }

    /// A literal/length symbol in the fixed Huffman code (RFC 1951 3.2.6).
    fn symbol(&mut self, v: u32) {
        match v {
            0..=143 => self.code(0x30 + v, 8),
            144..=255 => self.code(0x190 + v - 144, 9),
            256..=279 => self.code(v - 256, 7),
            _ => self.code(0xc0 + v - 280, 8),
        }
    }
}

const LEN_BASE: [u32; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u32; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u32; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193,
    12289, 16385, 24577,
];
const DIST_EXTRA: [u32; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

fn zlib(data: &[u8], row: usize) -> Vec<u8> {
    let mut b = Bits::default();
    b.out.extend_from_slice(&[0x78, 0x01]);
    b.put(1, 1); // final block
    b.put(1, 2); // fixed Huffman
    let distances = [1, 2, 3, 4, row, 2 * row];
    let mut i = 0;
    while i < data.len() {
        let (mut len, mut dist) = (0, 0);
        for &d in &distances {
            if d > i || d > 32768 {
                continue;
            }
            let l = (0..258.min(data.len() - i)).take_while(|&k| data[i + k] == data[i + k - d]).count();
            if l > len {
                (len, dist) = (l, d);
            }
        }
        if len >= 3 {
            let li = LEN_BASE.iter().rposition(|&v| v <= len as u32).unwrap();
            b.symbol(257 + li as u32);
            b.put(len as u32 - LEN_BASE[li], LEN_EXTRA[li]);
            let di = DIST_BASE.iter().rposition(|&v| v <= dist as u32).unwrap();
            b.code(di as u32, 5);
            b.put(dist as u32 - DIST_BASE[di], DIST_EXTRA[di]);
            i += len;
        } else {
            b.symbol(data[i] as u32);
            i += 1;
        }
    }
    b.symbol(256);
    if b.n > 0 {
        b.put(0, 8 - b.n);
    }
    let (mut s1, mut s2) = (1u32, 0u32);
    for &v in data {
        s1 = (s1 + v as u32) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    b.out.extend_from_slice(&((s2 << 16) | s1).to_be_bytes());
    b.out
}

// ---------------------------------------------------------------------------------------
// Drawing: a white monitor on a blue tile with a green padlock badge, in unit coordinates.

type Rgb = [f32; 3];
type Rect = (f32, f32, f32, f32);

const WHITE: u32 = 0xffffff;
const GREEN: u32 = 0x12b981;

fn hex(v: u32) -> Rgb {
    [((v >> 16) & 255) as f32 / 255.0, ((v >> 8) & 255) as f32 / 255.0, (v & 255) as f32 / 255.0]
}

fn mix(a: Rgb, b: Rgb, t: f32) -> Rgb {
    [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t]
}

/// Inside test for a rounded rectangle.
fn in_rrect(x: f32, y: f32, (x0, y0, x1, y1): Rect, r: f32) -> bool {
    if x < x0 || x > x1 || y < y0 || y > y1 {
        return false;
    }
    let dx = (x0 + r - x).max(x - (x1 - r)).max(0.0);
    let dy = (y0 + r - y).max(y - (y1 - r)).max(0.0);
    dx * dx + dy * dy <= r * r
}

fn in_circle(x: f32, y: f32, cx: f32, cy: f32, r: f32) -> bool {
    (x - cx) * (x - cx) + (y - cy) * (y - cy) <= r * r
}

/// Moves rectangle edges onto the pixel grid at small sizes, so they stay sharp.
fn snap(r: Rect, size: u32) -> Rect {
    if size > 48 {
        return r;
    }
    let f = |v: f32| (v * size as f32).round() / size as f32;
    (f(r.0), f(r.1), f(r.2), f(r.3))
}

/// The colour at (x, y), or None outside the tile.
fn sample(x: f32, y: f32, size: u32) -> Option<Rgb> {
    let tile = mix(hex(0x3a78f0), hex(0x1a3a9e), (x + y) / 2.0);
    if !in_rrect(x, y, snap((0.03, 0.03, 0.97, 0.97), size), 0.21) {
        return None;
    }
    let mut c = tile;
    // Monitor: bezel, screen, stand.
    let bezel = snap((0.10, 0.16, 0.80, 0.60), size);
    if in_rrect(x, y, bezel, 0.07) {
        c = hex(WHITE);
    }
    let inset = if size <= 24 { 1.0 / size as f32 } else { 0.045 };
    let screen = snap((bezel.0 + inset, bezel.1 + inset, bezel.2 - inset, bezel.3 - inset), size);
    if in_rrect(x, y, screen, 0.03) {
        c = mix(hex(0xe3eeff), hex(0xb4ceff), (y - screen.1) / (screen.3 - screen.1));
    }
    if in_rrect(x, y, snap((0.34, 0.60, 0.46, 0.68), size), 0.0) || in_rrect(x, y, snap((0.22, 0.68, 0.58, 0.74), size), 0.03) {
        c = hex(WHITE);
    }
    // Badge, set off from the monitor by a ring of tile colour.
    let (bx, by, br) = (0.725, 0.705, 0.195);
    if in_circle(x, y, bx, by, br + 0.045) {
        c = tile;
    }
    if in_circle(x, y, bx, by, br) {
        c = hex(GREEN);
    }
    // Padlock, s = half the body width; shackle and body together are 2.47 s tall.
    let s = 0.076;
    let detail = size >= 32;
    let (ro, ri) = (0.68 * s, if detail { 0.38 * s } else { 0.30 * s });
    let arc_y = by - 1.235 * s + ro;
    let body = (bx - s, arc_y + 0.35 * s, bx + s, by + 1.235 * s);
    let d = ((x - bx) * (x - bx) + (y - arc_y) * (y - arc_y)).sqrt();
    let leg = (ri..=ro).contains(&(x - bx).abs()) && y > arc_y && y <= body.1 + 0.1 * s;
    if in_rrect(x, y, body, 0.2 * s) || (y <= arc_y && (ri..=ro).contains(&d)) || leg {
        c = hex(WHITE);
    }
    let h = body.3 - body.1;
    let key_y = body.1 + 0.42 * h;
    if detail && (in_circle(x, y, bx, key_y, 0.2 * s) || in_rrect(x, y, (bx - 0.08 * s, key_y, bx + 0.08 * s, body.1 + 0.75 * h), 0.0)) {
        c = hex(GREEN);
    }
    Some(c)
}

/// Renders the icon with supersampling; straight (not premultiplied) RGBA.
fn render(size: u32) -> Vec<[u8; 4]> {
    let ss: u32 = if size <= 64 { 8 } else { 4 };
    let mut out = Vec::with_capacity((size * size) as usize);
    for py in 0..size {
        for px in 0..size {
            let (mut acc, mut hits) = ([0.0f32; 3], 0u32);
            for sy in 0..ss {
                for sx in 0..ss {
                    let x = (px as f32 + (sx as f32 + 0.5) / ss as f32) / size as f32;
                    let y = (py as f32 + (sy as f32 + 0.5) / ss as f32) / size as f32;
                    if let Some(c) = sample(x, y, size) {
                        (0..3).for_each(|k| acc[k] += c[k]);
                        hits += 1;
                    }
                }
            }
            let ch = |v: f32| if hits > 0 { (v / hits as f32 * 255.0).round().clamp(0.0, 255.0) as u8 } else { 0 };
            let alpha = (hits as f32 / (ss * ss) as f32 * 255.0).round() as u8;
            out.push([ch(acc[0]), ch(acc[1]), ch(acc[2]), alpha]);
        }
    }
    out
}
