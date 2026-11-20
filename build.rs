//! Build script: on MSVC targets, embeds `app.manifest` (common controls v6, per-monitor
//! DPI awareness, Windows 10/11) and an application icon into the executable.
//!
//! No resource compiler is needed: the icon is drawn here and written as a `.res` file, which
//! link.exe accepts as an input like an object file. Only binaries get these, not test harnesses.

use std::path::{Path, PathBuf};

/// Resource ID of the icon group (`launcher::ICON_ID`).
const ICON_ID: u16 = 1;
const ICON_SIZES: [u32; 6] = [16, 20, 24, 32, 48, 64];

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
        let image = icon_dib(size);
        let id = 100 + i as u16;
        res_entry(&mut res, RT_ICON, id, 0x1010, &image);
        group.extend_from_slice(&[size as u8, size as u8, 0, 0]);
        group.extend_from_slice(&1u16.to_le_bytes()); // planes
        group.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
        group.extend_from_slice(&(image.len() as u32).to_le_bytes());
        group.extend_from_slice(&id.to_le_bytes());
    }
    res_entry(&mut res, RT_GROUP_ICON, ICON_ID, 0x1030, &group);
    std::fs::write(path, res)
}

/// One icon image: BITMAPINFOHEADER, bottom-up 32-bit BGRA pixels, then the 1-bit AND mask.
fn icon_dib(size: u32) -> Vec<u8> {
    let px = render(size);
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
            out.extend_from_slice(&px[(y * size + x) as usize]);
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

/// Inside test for a rounded rectangle in unit coordinates.
fn in_rrect(x: f32, y: f32, (x0, y0, x1, y1): (f32, f32, f32, f32), r: f32) -> bool {
    if x < x0 || x > x1 || y < y0 || y > y1 {
        return false;
    }
    let dx = (x0 + r - x).max(x - (x1 - r)).max(0.0);
    let dy = (y0 + r - y).max(y - (y1 - r)).max(0.0);
    dx * dx + dy * dy <= r * r
}

/// Draws the icon (a monitor with a padlock on a blue tile), 4x4 supersampled; BGRA.
fn render(size: u32) -> Vec<[u8; 4]> {
    const SS: u32 = 4;
    let white = [1.0, 1.0, 1.0];
    let screen = [0.85, 0.92, 0.98];
    let accent = [0.0, 0.37, 0.72];
    let detail = size >= 32;
    let mut out = Vec::with_capacity((size * size) as usize);
    for py in 0..size {
        for px in 0..size {
            let mut acc = [0.0f32; 4];
            for sy in 0..SS {
                for sx in 0..SS {
                    let x = (px as f32 + (sx as f32 + 0.5) / SS as f32) / size as f32;
                    let y = (py as f32 + (sy as f32 + 0.5) / SS as f32) / size as f32;
                    let mut c: Option<[f32; 3]> = None;
                    if in_rrect(x, y, (0.03, 0.03, 0.97, 0.97), 0.2) {
                        let t = (y - 0.03) / 0.94;
                        c = Some([0.17 * (1.0 - t), 0.53 * (1.0 - t) + 0.37 * t, 0.85 * (1.0 - t) + 0.72 * t]);
                    }
                    if in_rrect(x, y, (0.16, 0.20, 0.84, 0.66), 0.06)
                        || in_rrect(x, y, (0.44, 0.64, 0.56, 0.76), 0.0)
                        || in_rrect(x, y, (0.30, 0.74, 0.70, 0.81), 0.035)
                    {
                        c = Some(white);
                    }
                    if in_rrect(x, y, (0.23, 0.27, 0.77, 0.59), 0.02) {
                        c = Some(screen);
                    }
                    if detail {
                        let (dx, dy) = (x - 0.5, y - 0.42);
                        let d = (dx * dx + dy * dy).sqrt();
                        let shackle = dy <= 0.0 && (0.045..=0.075).contains(&d);
                        let side = (0.425..=0.455).contains(&x) || (0.545..=0.575).contains(&x);
                        if shackle || (side && (0.42..=0.45).contains(&y)) || in_rrect(x, y, (0.40, 0.44, 0.60, 0.56), 0.015) {
                            c = Some(accent);
                        }
                    }
                    if let Some(c) = c {
                        acc[0] += c[0];
                        acc[1] += c[1];
                        acc[2] += c[2];
                        acc[3] += 1.0;
                    }
                }
            }
            let n = (SS * SS) as f32;
            let a = acc[3] / n;
            let ch = |v: f32| if acc[3] > 0.0 { (v / acc[3] * 255.0).round().clamp(0.0, 255.0) as u8 } else { 0 };
            out.push([ch(acc[2]), ch(acc[1]), ch(acc[0]), (a * 255.0).round() as u8]);
        }
    }
    out
}
