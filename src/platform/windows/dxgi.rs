//! DXGI Desktop Duplication capture (GPU-side, wakes only when the screen changes).
//!
//! One duplication per output: a single monitor, or every monitor composed into the
//! virtual-screen buffer for `MonitorSel::All` (the outputs may sit on different adapters).
//! Outputs are duplicated with `IDXGIOutput5::DuplicateOutput1` asking for B8G8R8A8, so the OS
//! converts HDR / advanced-color and other non-BGRA desktops; systems without it fall back to
//! `IDXGIOutput1::DuplicateOutput`. Rotated outputs are turned upright while copying, and after
//! the first frame only the regions DXGI reports as dirty or moved are copied off the GPU.
//!
//! windows-sys has no COM interface bindings, so the handful of vtable slots used here are
//! declared by hand. Slot numbers and IIDs were taken from the Windows SDK 10.0.26100 headers
//! (dxgi.h, dxgi1_2.h, dxgi1_5.h, d3d11.h, C interface section).

use super::mem::LockedBuf;
use crate::screen::Area;
use crate::util::{Error, Result};
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{POINT, RECT};
use windows_sys::core::GUID;

type HRESULT = i32;

#[link(name = "d3d11", kind = "raw-dylib")]
unsafe extern "system" {
    fn D3D11CreateDevice(
        adapter: *mut c_void,
        driver_type: i32,
        software: *mut c_void,
        flags: u32,
        feature_levels: *const i32,
        n_feature_levels: u32,
        sdk_version: u32,
        device: *mut *mut c_void,
        feature_level: *mut i32,
        context: *mut *mut c_void,
    ) -> HRESULT;
}

#[link(name = "dxgi", kind = "raw-dylib")]
unsafe extern "system" {
    fn CreateDXGIFactory1(riid: *const GUID, factory: *mut *mut c_void) -> HRESULT;
}

const IID_IDXGIFACTORY1: GUID = GUID::from_u128(0x770aae78_f26f_4dba_a829_253c83d1b387);
const IID_IDXGIOUTPUT1: GUID = GUID::from_u128(0x00cddea8_939b_4b83_a340_a685226666cc);
const IID_IDXGIOUTPUT5: GUID = GUID::from_u128(0x80a07424_ab52_42eb_833c_0c42fd282d98);
const IID_ID3D11TEXTURE2D: GUID = GUID::from_u128(0x6f15aaf2_d208_4e89_9ab4_489535d34f9c);

const DXGI_ERROR_NOT_FOUND: HRESULT = 0x887A0002u32 as i32;
const DXGI_ERROR_MORE_DATA: HRESULT = 0x887A0003u32 as i32;
const DXGI_ERROR_WAIT_TIMEOUT: HRESULT = 0x887A0027u32 as i32;
const D3D_DRIVER_TYPE_UNKNOWN: i32 = 0;
const D3D11_SDK_VERSION: u32 = 7;
const DXGI_FORMAT_B8G8R8A8_UNORM: u32 = 87;
const DXGI_FORMAT_B8G8R8A8_UNORM_SRGB: u32 = 91;
const D3D11_USAGE_STAGING: u32 = 3;
const D3D11_CPU_ACCESS_READ: u32 = 0x20000;
const D3D11_MAP_READ: u32 = 1;

/// How long opening waits for each output's first image (normally it is there at once).
const FIRST_FRAME_MS: u32 = 200;
/// With several outputs: how long to block in one output's wait before looking at the others.
const WAIT_SLICE_MS: u32 = 8;
/// Above this many changed regions (or 3/4 of the screen) one full copy is cheaper.
const MAX_REGIONS: usize = 256;
/// Sanity limit for the dirty/move rectangle lists DXGI asks us to make room for.
const MAX_META_ENTRIES: usize = 1 << 20;

#[repr(C)]
struct DxgiOutputDesc {
    device_name: [u16; 32],
    desktop: RECT,
    attached: i32,
    rotation: u32,
    monitor: *mut c_void,
}

#[repr(C)]
struct DxgiOutduplFrameInfo {
    last_present_time: i64,
    last_mouse_update_time: i64,
    accumulated_frames: u32,
    rects_coalesced: i32,
    protected_content_masked_out: i32,
    pointer_position: POINT,
    pointer_visible: i32,
    total_metadata_buffer_size: u32,
    pointer_shape_buffer_size: u32,
}

/// `DXGI_OUTDUPL_MOVE_RECT`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MoveRect {
    source: POINT,
    dest: RECT,
}

#[repr(C)]
#[derive(Default)]
struct D3d11Texture2dDesc {
    width: u32,
    height: u32,
    mip_levels: u32,
    array_size: u32,
    format: u32,
    sample_count: u32,
    sample_quality: u32,
    usage: u32,
    bind_flags: u32,
    cpu_access_flags: u32,
    misc_flags: u32,
}

#[repr(C)]
struct D3d11Box {
    left: u32,
    top: u32,
    front: u32,
    right: u32,
    bottom: u32,
    back: u32,
}

#[repr(C)]
struct D3d11MappedSubresource {
    data: *mut c_void,
    row_pitch: u32,
    depth_pitch: u32,
}

/// Owned COM pointer.
struct Com(*mut c_void);

impl Com {
    /// Function pointer from vtable slot `i`.
    unsafe fn slot<F: Copy>(&self, i: usize) -> F {
        unsafe {
            let vtbl = *(self.0 as *const *const usize);
            std::mem::transmute_copy(&*vtbl.add(i))
        }
    }

    fn query(&self, iid: &GUID) -> Result<Com> {
        let mut out = null_mut();
        let qi: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT = unsafe { self.slot(0) };
        hr(unsafe { qi(self.0, iid, &mut out) }, "QueryInterface")?;
        Ok(Com(out))
    }

    /// Another owned reference to the same object.
    fn share(&self) -> Com {
        let add_ref: unsafe extern "system" fn(*mut c_void) -> u32 = unsafe { self.slot(1) };
        unsafe { add_ref(self.0) };
        Com(self.0)
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let release: unsafe extern "system" fn(*mut c_void) -> u32 = unsafe { self.slot(2) };
            unsafe { release(self.0) };
        }
    }
}

fn hr(h: HRESULT, what: &str) -> Result<()> {
    if h < 0 {
        return Err(Error::msg(format!("{what} failed (HRESULT {:#010x})", h as u32)));
    }
    Ok(())
}

/// Half-open pixel rectangle [x0, x1) x [y0, y1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Region {
    x0: u32,
    y0: u32,
    x1: u32,
    y1: u32,
}

impl Region {
    fn full(w: u32, h: u32) -> Region {
        Region { x0: 0, y0: 0, x1: w, y1: h }
    }

    /// `r` clipped to a `w` x `h` image; None if nothing is left.
    fn clip(r: &RECT, w: u32, h: u32) -> Option<Region> {
        let cx = |v: i32| v.clamp(0, w.min(i32::MAX as u32) as i32) as u32;
        let cy = |v: i32| v.clamp(0, h.min(i32::MAX as u32) as i32) as u32;
        let c = Region { x0: cx(r.left), y0: cy(r.top), x1: cx(r.right), y1: cy(r.bottom) };
        (c.x0 < c.x1 && c.y0 < c.y1).then_some(c)
    }

    fn pixels(&self) -> u64 {
        (self.x1 - self.x0) as u64 * (self.y1 - self.y0) as u64
    }
}

/// How an output's duplicated image must be turned to appear upright (`DXGI_MODE_ROTATION`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Rotation {
    Identity,
    Rotate90,
    Rotate180,
    Rotate270,
}

impl Rotation {
    fn from_dxgi(v: u32) -> Option<Rotation> {
        match v {
            0 | 1 => Some(Rotation::Identity), // UNSPECIFIED, IDENTITY
            2 => Some(Rotation::Rotate90),
            3 => Some(Rotation::Rotate180),
            4 => Some(Rotation::Rotate270),
            _ => None,
        }
    }

    /// Size of the duplicated (unrotated) image of an output that is `w` x `h` on the desktop.
    fn texture_size(self, w: u32, h: u32) -> (u32, u32) {
        match self {
            Rotation::Rotate90 | Rotation::Rotate270 => (h, w),
            Rotation::Identity | Rotation::Rotate180 => (w, h),
        }
    }

    /// Where pixel (x, y) of a `tw` x `th` duplicated image lands on the upright output. Same
    /// mapping as Microsoft's DesktopDuplication sample (DISPLAYMANAGER::SetDirtyVert).
    fn map(self, tw: u32, th: u32, x: u32, y: u32) -> (u32, u32) {
        match self {
            Rotation::Identity => (x, y),
            Rotation::Rotate90 => (th - 1 - y, x),
            Rotation::Rotate180 => (tw - 1 - x, th - 1 - y),
            Rotation::Rotate270 => (y, tw - 1 - x),
        }
    }

    /// The upright rectangle covered by region `r` (inside the `tw` x `th` image).
    fn map_region(self, tw: u32, th: u32, r: Region) -> Region {
        match self {
            Rotation::Identity => r,
            Rotation::Rotate90 => Region { x0: th - r.y1, y0: r.x0, x1: th - r.y0, y1: r.x1 },
            Rotation::Rotate180 => Region { x0: tw - r.x1, y0: th - r.y1, x1: tw - r.x0, y1: th - r.y0 },
            Rotation::Rotate270 => Region { x0: r.y0, y0: tw - r.x1, x1: r.y1, y1: tw - r.x0 },
        }
    }
}

/// The rotation that turns a `tw` x `th` duplicated image into the upright `w` x `h` output:
/// the reported one, or none if the image already arrives upright. None if it fits neither.
fn fit_rotation(reported: Rotation, tw: u32, th: u32, w: u32, h: u32) -> Option<Rotation> {
    if reported.texture_size(w, h) == (tw, th) {
        Some(reported)
    } else if (w, h) == (tw, th) {
        Some(Rotation::Identity)
    } else {
        None
    }
}

/// Copies region `r` of a BGRA image (`src`: `tw` x `th`, `pitch` bytes per row) into the upright
/// BGRA image `dst` (`stride` bytes per row), turning it by `rot` and placing the output's
/// top-left corner at (`ox`, `oy`). Copies nothing and returns false if any part of it would
/// fall outside either buffer.
#[allow(clippy::too_many_arguments)]
fn blit(src: &[u8], pitch: usize, tw: u32, th: u32, rot: Rotation, r: Region, dst: &mut [u8], stride: usize, ox: usize, oy: usize) -> bool {
    if r.x0 >= r.x1 || r.y0 >= r.y1 || r.x1 > tw || r.y1 > th || pitch < tw as usize * 4 {
        return false;
    }
    if (src.len() as u128) < (th as u128 - 1) * pitch as u128 + tw as u128 * 4 {
        return false;
    }
    let d = rot.map_region(tw, th, r);
    let right = (ox as u128 + d.x1 as u128) * 4;
    let end = (oy as u128 + d.y1 as u128 - 1) * stride as u128 + right;
    if right > stride as u128 || end > dst.len() as u128 {
        return false;
    }
    if rot == Rotation::Identity {
        let len = (r.x1 - r.x0) as usize * 4;
        for y in r.y0 as usize..r.y1 as usize {
            let s = y * pitch + r.x0 as usize * 4;
            let o = (oy + y) * stride + (ox + r.x0 as usize) * 4;
            dst[o..o + len].copy_from_slice(&src[s..s + len]);
        }
        return true;
    }
    // Along a source row the destination moves by a fixed step. Walk the source in tiles so
    // that the transposed writes of 90/270 degrees stay in cache.
    let step: isize = match rot {
        Rotation::Rotate90 => stride as isize,
        Rotation::Rotate180 => -4,
        Rotation::Rotate270 => -(stride as isize),
        Rotation::Identity => 4,
    };
    const TILE: u32 = 64;
    for ty in (r.y0..r.y1).step_by(TILE as usize) {
        for tx in (r.x0..r.x1).step_by(TILE as usize) {
            let tx1 = (tx + TILE).min(r.x1);
            for y in ty..(ty + TILE).min(r.y1) {
                let (dx, dy) = rot.map(tw, th, tx, y);
                let mut o = ((oy + dy as usize) * stride + (ox + dx as usize) * 4) as isize;
                let row = y as usize * pitch;
                for p in src[row + tx as usize * 4..row + tx1 as usize * 4].chunks_exact(4) {
                    let at = o as usize;
                    dst[at..at + 4].copy_from_slice(p);
                    o += step;
                }
            }
        }
    }
    true
}

/// Regions of a `tw` x `th` image to copy for a frame whose changes DXGI described as `dirty`
/// rectangles and `moves` (whose destinations hold new content). None when one full copy is
/// cheaper. The duplicated image is always complete, so moves need no replaying.
fn plan(dirty: &[RECT], moves: &[MoveRect], tw: u32, th: u32) -> Option<Vec<Region>> {
    let mut out = Vec::new();
    let mut covered = 0u64;
    for r in dirty.iter().chain(moves.iter().map(|m| &m.dest)) {
        if let Some(c) = Region::clip(r, tw, th) {
            covered += c.pixels();
            out.push(c);
        }
    }
    let large = out.len() > MAX_REGIONS || covered * 4 >= tw as u64 * th as u64 * 3;
    (!large).then_some(out)
}

/// Runs one of DXGI's "get rectangles" calls (`call(buffer_bytes, buffer, required_bytes)`),
/// growing `buf` once if asked to. Returns how many entries were written, None on failure.
fn fetch<T: Copy + Default>(buf: &mut Vec<T>, hint_bytes: u32, call: impl Fn(u32, *mut T, *mut u32) -> HRESULT) -> Option<usize> {
    let size = size_of::<T>();
    let want = (hint_bytes as usize).div_ceil(size).clamp(1, MAX_META_ENTRIES);
    if buf.len() < want {
        buf.resize(want, T::default());
    }
    for _ in 0..2 {
        let bytes = u32::try_from(buf.len() * size).ok()?;
        let mut need = 0u32;
        let r = call(bytes, buf.as_mut_ptr(), &mut need);
        if r == DXGI_ERROR_MORE_DATA {
            let n = (need as usize).div_ceil(size);
            if n <= buf.len() || n > MAX_META_ENTRIES {
                return None;
            }
            buf.resize(n, T::default());
            continue;
        }
        if r < 0 {
            return None;
        }
        return Some((need as usize / size).min(buf.len()));
    }
    None
}

fn contains(outer: Area, inner: Area) -> bool {
    let (ol, ot, il, it) = (outer.left as i64, outer.top as i64, inner.left as i64, inner.top as i64);
    inner.width > 0
        && inner.height > 0
        && il >= ol
        && it >= ot
        && il + inner.width as i64 <= ol + outer.width as i64
        && it + inner.height as i64 <= ot + outer.height as i64
}

/// One output attached to the desktop.
struct Found {
    adapter: usize,
    output: Com,
    rect: Area,
    rotation: u32,
}

/// Every output attached to the desktop, on every adapter.
fn enum_outputs() -> Result<(Vec<Com>, Vec<Found>)> {
    unsafe {
        let mut f = null_mut();
        hr(CreateDXGIFactory1(&IID_IDXGIFACTORY1, &mut f), "CreateDXGIFactory1")?;
        let factory = Com(f);
        let enum_adapters: unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> HRESULT = factory.slot(7);
        let (mut adapters, mut found) = (Vec::new(), Vec::new());
        for ai in 0.. {
            let mut a = null_mut();
            let r = enum_adapters(factory.0, ai, &mut a);
            if r == DXGI_ERROR_NOT_FOUND {
                break;
            }
            hr(r, "EnumAdapters")?;
            let adapter = Com(a);
            let enum_outputs: unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> HRESULT = adapter.slot(7);
            for oi in 0.. {
                let mut o = null_mut();
                if enum_outputs(adapter.0, oi, &mut o) < 0 {
                    break;
                }
                let output = Com(o);
                let get_desc: unsafe extern "system" fn(*mut c_void, *mut DxgiOutputDesc) -> HRESULT = output.slot(7);
                let mut d: DxgiOutputDesc = std::mem::zeroed();
                if get_desc(output.0, &mut d) < 0 || d.attached == 0 {
                    continue;
                }
                let r = d.desktop;
                let rect = Area { left: r.left, top: r.top, width: r.right.saturating_sub(r.left), height: r.bottom.saturating_sub(r.top) };
                found.push(Found { adapter: adapters.len(), output, rect, rotation: d.rotation });
            }
            adapters.push(adapter);
        }
        Ok((adapters, found))
    }
}

/// D3D11 device and immediate context on `adapter`.
fn create_device(adapter: &Com) -> Result<(Com, Com)> {
    unsafe {
        let levels = [0xb100, 0xb000, 0xa100, 0xa000]; // 11.1, 11.0, 10.1, 10.0
        let create = |levels: &[i32], dev: &mut *mut c_void, ctx: &mut *mut c_void| {
            let (driver, n, mut got) = (D3D_DRIVER_TYPE_UNKNOWN, levels.len() as u32, 0);
            D3D11CreateDevice(adapter.0, driver, null_mut(), 0, levels.as_ptr(), n, D3D11_SDK_VERSION, dev, &mut got, ctx)
        };
        let (mut dev, mut ctx) = (null_mut(), null_mut());
        let mut r = create(&levels, &mut dev, &mut ctx);
        if r < 0 {
            // Pre-11.1 runtimes reject the 11.1 level outright.
            r = create(&levels[1..], &mut dev, &mut ctx);
        }
        hr(r, "D3D11CreateDevice")?;
        Ok((Com(dev), Com(ctx)))
    }
}

/// Starts duplicating `output`, asking for B8G8R8A8 so the OS converts HDR and other formats.
fn duplicate(output: &Com, device: &Com) -> Result<Com> {
    unsafe {
        let mut d = null_mut();
        if let Ok(o5) = output.query(&IID_IDXGIOUTPUT5) {
            type Dup1 = unsafe extern "system" fn(*mut c_void, *mut c_void, u32, u32, *const u32, *mut *mut c_void) -> HRESULT;
            let dup1: Dup1 = o5.slot(26);
            let formats = [DXGI_FORMAT_B8G8R8A8_UNORM];
            let r = dup1(o5.0, device.0, 0, formats.len() as u32, formats.as_ptr(), &mut d);
            if r >= 0 && !d.is_null() {
                return Ok(Com(d));
            }
            // DXGI_ERROR_UNSUPPORTED here usually means the process is not per-monitor DPI aware.
            static NOTED: AtomicBool = AtomicBool::new(false);
            if !NOTED.swap(true, Ordering::Relaxed) {
                crate::log!("DuplicateOutput1 failed (HRESULT {:#010x}); trying DuplicateOutput", r as u32);
            }
            d = null_mut();
        }
        let o1 = output.query(&IID_IDXGIOUTPUT1)?;
        let dup: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> HRESULT = o1.slot(22);
        hr(dup(o1.0, device.0, &mut d), "DuplicateOutput")?;
        Ok(Com(d))
    }
}

/// One duplicated output and where its upright image goes in the capture buffer.
struct Output {
    device: Com,
    context: Com,
    dupl: Com,
    /// CPU-readable copy of the last image, with its size.
    staging: Option<(Com, u32, u32)>,
    /// Upright size on the desktop and position inside the capture area.
    width: u32,
    height: u32,
    ox: usize,
    oy: usize,
    rotation: Rotation,
    /// Image size and the rotation applied to it, fixed by the first frame.
    texture: Option<(u32, u32, Rotation)>,
    dirty: Vec<RECT>,
    moves: Vec<MoveRect>,
}

impl Output {
    /// Waits up to `timeout_ms` for a new image and copies what changed into `dst` (`stride`
    /// bytes per row). Ok(true) if any pixels were updated.
    fn poll(&mut self, timeout_ms: u32, dst: &mut [u8], stride: usize) -> Result<bool> {
        unsafe {
            type Acquire = unsafe extern "system" fn(*mut c_void, u32, *mut DxgiOutduplFrameInfo, *mut *mut c_void) -> HRESULT;
            let acquire: Acquire = self.dupl.slot(8);
            let release_frame: unsafe extern "system" fn(*mut c_void) -> HRESULT = self.dupl.slot(14);
            let mut info: DxgiOutduplFrameInfo = std::mem::zeroed();
            let mut res = null_mut();
            let r = acquire(self.dupl.0, timeout_ms, &mut info, &mut res);
            if r == DXGI_ERROR_WAIT_TIMEOUT {
                return Ok(false);
            }
            hr(r, "AcquireNextFrame")?;
            let resource = Com(res);
            // Pointer-only updates carry no new image.
            let changed = if resource.0.is_null() {
                Err("AcquireNextFrame returned no image".into())
            } else if info.last_present_time != 0 || self.texture.is_none() {
                self.update(&resource, &info, dst, stride)
            } else {
                Ok(false)
            };
            drop(resource);
            release_frame(self.dupl.0);
            changed
        }
    }

    /// Copies the acquired image (all of it, or only what changed) into `dst`.
    unsafe fn update(&mut self, resource: &Com, info: &DxgiOutduplFrameInfo, dst: &mut [u8], stride: usize) -> Result<bool> {
        unsafe {
            let tex = resource.query(&IID_ID3D11TEXTURE2D)?;
            let get_desc: unsafe extern "system" fn(*mut c_void, *mut D3d11Texture2dDesc) = tex.slot(10);
            let mut desc = D3d11Texture2dDesc::default();
            get_desc(tex.0, &mut desc);
            if desc.format != DXGI_FORMAT_B8G8R8A8_UNORM && desc.format != DXGI_FORMAT_B8G8R8A8_UNORM_SRGB {
                return Err(Error::msg(format!("unsupported desktop format {}", desc.format)));
            }
            let (tw, th) = (desc.width, desc.height);
            if tw == 0 || th == 0 {
                return Err("empty desktop image".into());
            }
            let rot = match self.texture {
                Some((w, h, rot)) if (w, h) == (tw, th) => rot,
                Some(_) => return Err(Error::msg(format!("desktop is now {tw}x{th}"))),
                None => fit_rotation(self.rotation, tw, th, self.width, self.height).ok_or_else(|| {
                    Error::msg(format!("desktop image is {tw}x{th}, output is {}x{} ({:?})", self.width, self.height, self.rotation))
                })?,
            };
            // Until the first image is in, everything has to be copied.
            let regions = match (self.texture, info.total_metadata_buffer_size) {
                (Some(_), n) if n > 0 => self.changed_regions(n, tw, th),
                _ => None,
            };
            if regions.as_ref().is_some_and(Vec::is_empty) {
                return Ok(false);
            }
            let staging = self.staging(tw, th, desc.format)?;
            let ctx = &self.context;
            match &regions {
                Some(list) => {
                    // (dst, dst_subresource, x, y, z, src, src_subresource, src_box)
                    type CopyRegion =
                        unsafe extern "system" fn(*mut c_void, *mut c_void, u32, u32, u32, u32, *mut c_void, u32, *const D3d11Box);
                    let copy_region: CopyRegion = ctx.slot(46);
                    for r in list {
                        let b = D3d11Box { left: r.x0, top: r.y0, front: 0, right: r.x1, bottom: r.y1, back: 1 };
                        copy_region(ctx.0, staging, 0, r.x0, r.y0, 0, tex.0, 0, &b);
                    }
                }
                None => {
                    let copy: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void) = ctx.slot(47);
                    copy(ctx.0, staging, tex.0);
                }
            }
            type Map = unsafe extern "system" fn(*mut c_void, *mut c_void, u32, u32, u32, *mut D3d11MappedSubresource) -> HRESULT;
            let map: Map = ctx.slot(14);
            let unmap: unsafe extern "system" fn(*mut c_void, *mut c_void, u32) = ctx.slot(15);
            let mut m: D3d11MappedSubresource = std::mem::zeroed();
            hr(map(ctx.0, staging, 0, D3D11_MAP_READ, 0, &mut m), "Map")?;
            let pitch = m.row_pitch as usize;
            let ok = !m.data.is_null() && pitch >= tw as usize * 4 && {
                let src = std::slice::from_raw_parts(m.data as *const u8, (th as usize - 1) * pitch + tw as usize * 4);
                let full = [Region::full(tw, th)];
                let list = regions.as_deref().unwrap_or(&full);
                list.iter().all(|&r| blit(src, pitch, tw, th, rot, r, dst, stride, self.ox, self.oy))
            };
            unmap(ctx.0, staging, 0);
            if !ok {
                return Err("desktop image does not fit the capture buffer".into());
            }
            self.texture = Some((tw, th, rot));
            Ok(true)
        }
    }

    /// The staging texture for `tw` x `th` images, created on first use.
    fn staging(&mut self, tw: u32, th: u32, format: u32) -> Result<*mut c_void> {
        if let Some((s, w, h)) = &self.staging {
            if (*w, *h) == (tw, th) {
                return Ok(s.0);
            }
        }
        self.staging = None;
        let sd = D3d11Texture2dDesc {
            width: tw,
            height: th,
            mip_levels: 1,
            array_size: 1,
            format,
            sample_count: 1,
            sample_quality: 0,
            usage: D3D11_USAGE_STAGING,
            bind_flags: 0,
            cpu_access_flags: D3D11_CPU_ACCESS_READ,
            misc_flags: 0,
        };
        unsafe {
            type Create = unsafe extern "system" fn(*mut c_void, *const D3d11Texture2dDesc, *const c_void, *mut *mut c_void) -> HRESULT;
            let create: Create = self.device.slot(5);
            let mut s = null_mut();
            hr(create(self.device.0, &sd, null(), &mut s), "CreateTexture2D")?;
            let s = Com(s);
            let ptr = s.0;
            self.staging = Some((s, tw, th));
            Ok(ptr)
        }
    }

    /// What changed in the acquired frame according to its metadata; None to copy everything.
    unsafe fn changed_regions(&mut self, hint_bytes: u32, tw: u32, th: u32) -> Option<Vec<Region>> {
        unsafe {
            type GetRects<T> = unsafe extern "system" fn(*mut c_void, u32, *mut T, *mut u32) -> HRESULT;
            let get_dirty: GetRects<RECT> = self.dupl.slot(9);
            let get_moves: GetRects<MoveRect> = self.dupl.slot(10);
            let dupl = self.dupl.0;
            let n_moves = fetch(&mut self.moves, hint_bytes, |len, buf, need| get_moves(dupl, len, buf, need))?;
            let n_dirty = fetch(&mut self.dirty, hint_bytes, |len, buf, need| get_dirty(dupl, len, buf, need))?;
            plan(&self.dirty[..n_dirty], &self.moves[..n_moves], tw, th)
        }
    }
}

pub struct DxgiCapture {
    pub area: Area,
    outputs: Vec<Output>,
    pixels: LockedBuf,
    /// The first image was read while opening and has not been reported by `next_frame` yet.
    primed: bool,
    /// Output whose wait `next_frame` blocks in next (several outputs only).
    turn: usize,
}

// The COM objects are only ever used from the capture thread that owns this value.
unsafe impl Send for DxgiCapture {}

impl DxgiCapture {
    /// Duplicates the output whose desktop rectangle is exactly `area`.
    pub fn new(area: Area) -> Result<DxgiCapture> {
        DxgiCapture::open(area, &[area])
    }

    /// Duplicates every monitor and composes them into `area` (the virtual screen); parts of
    /// it no monitor covers stay black.
    pub fn all(area: Area) -> Result<DxgiCapture> {
        DxgiCapture::open(area, &super::capture::monitors())
    }

    fn open(area: Area, monitors: &[Area]) -> Result<DxgiCapture> {
        if monitors.is_empty() || !monitors.iter().all(|m| contains(area, *m)) {
            return Err("monitors do not fit the capture area".into());
        }
        let (adapters, found) = enum_outputs()?;
        let mut devices: Vec<Option<(Com, Com)>> = adapters.iter().map(|_| None).collect();
        let mut outputs = Vec::with_capacity(monitors.len());
        for m in monitors {
            let o = found
                .iter()
                .find(|o| o.rect == *m)
                .ok_or_else(|| Error::msg(format!("no DXGI output shows the monitor at ({}, {})", m.left, m.top)))?;
            let rotation = Rotation::from_dxgi(o.rotation).ok_or("unknown display rotation")?;
            let (device, context) = match &mut devices[o.adapter] {
                Some(d) => &*d,
                slot => &*slot.insert(create_device(&adapters[o.adapter])?),
            };
            let dupl = duplicate(&o.output, device)?;
            outputs.push(Output {
                device: device.share(),
                context: context.share(),
                dupl,
                staging: None,
                width: m.width as u32,
                height: m.height as u32,
                ox: (m.left - area.left) as usize,
                oy: (m.top - area.top) as usize,
                rotation,
                texture: None,
                dirty: Vec::new(),
                moves: Vec::new(),
            });
        }
        let len = area.width as usize * area.height as usize * 4;
        let mut cap = DxgiCapture { area, outputs, pixels: LockedBuf::new(len), primed: false, turn: 0 };
        // Read the first images now: they are normally there at once, and this proves that the
        // format and size are usable before the caller commits to DXGI.
        let stride = area.width as usize * 4;
        for o in &mut cap.outputs {
            cap.primed |= o.poll(FIRST_FRAME_MS, cap.pixels.as_mut_slice(), stride)?;
        }
        Ok(cap)
    }

    pub fn pixels(&self) -> &[u8] {
        self.pixels.as_slice()
    }

    /// Waits up to `timeout_ms` for a new desktop image. Ok(true) if `pixels()` was updated.
    pub fn next_frame(&mut self, timeout_ms: u32) -> Result<bool> {
        let stride = self.area.width as usize * 4;
        let dst = self.pixels.as_mut_slice();
        if std::mem::take(&mut self.primed) {
            // Report the image read while opening, with anything newer folded in.
            for o in &mut self.outputs {
                o.poll(0, dst, stride)?;
            }
            return Ok(true);
        }
        match self.outputs.as_mut_slice() {
            [] => return Ok(false),
            [only] => return only.poll(timeout_ms, dst, stride),
            _ => {}
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        loop {
            let mut changed = false;
            for o in &mut self.outputs {
                changed |= o.poll(0, dst, stride)?;
            }
            let left = deadline.saturating_duration_since(Instant::now()).as_millis().min(u32::MAX as u128) as u32;
            if changed || left == 0 {
                return Ok(changed);
            }
            // Sleep in one output's wait for a moment, taking turns, then look at all of them.
            self.turn = (self.turn + 1) % self.outputs.len();
            if self.outputs[self.turn].poll(left.min(WAIT_SLICE_MS), dst, stride)? {
                for o in &mut self.outputs {
                    o.poll(0, dst, stride)?;
                }
                return Ok(true);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROTATIONS: [Rotation; 4] = [Rotation::Identity, Rotation::Rotate90, Rotation::Rotate180, Rotation::Rotate270];

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> RECT {
        RECT { left, top, right, bottom }
    }

    /// BGRA image whose pixel (x, y) is [x, y, tag, 255].
    fn image(w: u32, h: u32, pitch: usize, tag: u8) -> Vec<u8> {
        let mut v = vec![0xEE; pitch * h as usize];
        for y in 0..h {
            for x in 0..w {
                let o = y as usize * pitch + x as usize * 4;
                v[o..o + 4].copy_from_slice(&[x as u8, y as u8, tag, 255]);
            }
        }
        v
    }

    fn px(buf: &[u8], stride: usize, x: usize, y: usize) -> [u8; 4] {
        buf[y * stride + x * 4..][..4].try_into().unwrap()
    }

    #[test]
    fn rotation_mapping_matches_the_dxgi_sample() {
        // Texture   a b c   (a = (0,0) ... f = (2,1)), as DXGI hands it out.
        //           d e f
        let (tw, th) = (3u32, 2u32);
        let name = |x: u32, y: u32| b"abcdef"[(y * tw + x) as usize];
        let upright = |rot: Rotation| {
            let (w, h) = rot.texture_size(tw, th); // swapping is its own inverse
            let mut out = vec![b'?'; (w * h) as usize];
            for y in 0..th {
                for x in 0..tw {
                    let (dx, dy) = rot.map(tw, th, x, y);
                    out[(dy * w + dx) as usize] = name(x, y);
                }
            }
            String::from_utf8(out).unwrap()
        };
        assert_eq!(upright(Rotation::Identity), "abcdef");
        assert_eq!(upright(Rotation::Rotate90), "daebfc"); // d a / e b / f c
        assert_eq!(upright(Rotation::Rotate180), "fedcba");
        assert_eq!(upright(Rotation::Rotate270), "cfbead"); // c f / b e / a d

        // map_region agrees with map, and with the sample's DestDirty arithmetic.
        let (tw, th) = (7u32, 5u32);
        for rot in ROTATIONS {
            let (w, h) = rot.texture_size(tw, th);
            assert_eq!(rot.map_region(tw, th, Region::full(tw, th)), Region::full(w, h));
            let r = Region { x0: 1, y0: 2, x1: 4, y1: 5 };
            let d = rot.map_region(tw, th, r);
            for y in r.y0..r.y1 {
                for x in r.x0..r.x1 {
                    let (dx, dy) = rot.map(tw, th, x, y);
                    assert!(dx >= d.x0 && dx < d.x1 && dy >= d.y0 && dy < d.y1, "{rot:?}");
                }
            }
            assert_eq!(d.pixels(), r.pixels());
        }
        let r = Region { x0: 1, y0: 2, x1: 4, y1: 5 };
        // ROTATE90: left = Width - bottom, top = left, right = Width - top, bottom = right.
        assert_eq!(Rotation::Rotate90.map_region(7, 5, r), Region { x0: 0, y0: 1, x1: 3, y1: 4 });
        // ROTATE270: left = top, top = Height - right, right = bottom, bottom = Height - left.
        assert_eq!(Rotation::Rotate270.map_region(7, 5, r), Region { x0: 2, y0: 3, x1: 5, y1: 6 });
    }

    #[test]
    fn rotation_values_and_fit() {
        assert_eq!(Rotation::from_dxgi(0), Some(Rotation::Identity));
        assert_eq!(Rotation::from_dxgi(1), Some(Rotation::Identity));
        assert_eq!(Rotation::from_dxgi(2), Some(Rotation::Rotate90));
        assert_eq!(Rotation::from_dxgi(4), Some(Rotation::Rotate270));
        assert_eq!(Rotation::from_dxgi(5), None);
        // Portrait output (1080x1920 on the desktop) duplicated as a 1920x1080 image.
        assert_eq!(fit_rotation(Rotation::Rotate90, 1920, 1080, 1080, 1920), Some(Rotation::Rotate90));
        // Already upright despite the reported rotation.
        assert_eq!(fit_rotation(Rotation::Rotate270, 1080, 1920, 1080, 1920), Some(Rotation::Identity));
        assert_eq!(fit_rotation(Rotation::Rotate180, 1920, 1080, 1920, 1080), Some(Rotation::Rotate180));
        assert_eq!(fit_rotation(Rotation::Identity, 1280, 720, 1920, 1080), None);
    }

    #[test]
    fn blit_turns_every_rotation_upright() {
        let (tw, th, pitch) = (5u32, 3u32, 5 * 4 + 12);
        let src = image(tw, th, pitch, 7);
        for rot in ROTATIONS {
            let (w, h) = rot.texture_size(tw, th);
            let stride = w as usize * 4;
            let mut dst = vec![0u8; stride * h as usize];
            assert!(blit(&src, pitch, tw, th, rot, Region::full(tw, th), &mut dst, stride, 0, 0));
            for y in 0..th {
                for x in 0..tw {
                    let (dx, dy) = rot.map(tw, th, x, y);
                    assert_eq!(px(&dst, stride, dx as usize, dy as usize), [x as u8, y as u8, 7, 255], "{rot:?}");
                }
            }
        }
    }

    #[test]
    fn blit_composes_partial_regions_at_offsets() {
        // A 100x60 virtual screen: a 40x20 landscape output at (0, 0) and a portrait output at
        // (40, 0) that DXGI hands out as a 60x20 image rotated by 90 degrees.
        let (vw, vh) = (100usize, 60usize);
        let stride = vw * 4;
        let mut dst = vec![0u8; stride * vh];
        let a = image(40, 20, 160, 1);
        assert!(blit(&a, 160, 40, 20, Rotation::Identity, Region { x0: 10, y0: 5, x1: 20, y1: 8 }, &mut dst, stride, 0, 0));
        assert_eq!(px(&dst, stride, 10, 5), [10, 5, 1, 255]);
        assert_eq!(px(&dst, stride, 19, 7), [19, 7, 1, 255]);
        assert_eq!(px(&dst, stride, 20, 7), [0; 4]);
        assert_eq!(px(&dst, stride, 10, 8), [0; 4]);
        // Texture 60x20 shown as a 20x60 portrait output at (40, 0).
        let b = image(60, 20, 240, 2);
        let r = Region { x0: 3, y0: 4, x1: 9, y1: 6 };
        assert!(!blit(&b, 240, 60, 20, Rotation::Rotate90, Region::full(60, 20), &mut dst, stride, 81, 0));
        assert!(blit(&b, 240, 60, 20, Rotation::Rotate90, r, &mut dst, stride, 40, 0));
        for y in r.y0..r.y1 {
            for x in r.x0..r.x1 {
                let (dx, dy) = Rotation::Rotate90.map(60, 20, x, y);
                assert_eq!(px(&dst, stride, 40 + dx as usize, dy as usize), [x as u8, y as u8, 2, 255]);
            }
        }
        let written = dst.chunks(4).filter(|p| p[3] == 255).count();
        assert_eq!(written, 10 * 3 + 6 * 2);
    }

    #[test]
    fn blit_rejects_anything_out_of_bounds() {
        let src = image(8, 4, 32, 0);
        let mut dst = vec![0u8; 8 * 4 * 4];
        let full = Region::full(8, 4);
        assert!(blit(&src, 32, 8, 4, Rotation::Identity, full, &mut dst, 32, 0, 0));
        assert!(!blit(&src, 32, 8, 4, Rotation::Identity, full, &mut dst, 32, 1, 0)); // past the right edge
        assert!(!blit(&src, 32, 8, 4, Rotation::Identity, full, &mut dst, 32, 0, 1)); // past the bottom
        assert!(!blit(&src, 32, 8, 4, Rotation::Rotate90, full, &mut dst, 32, 0, 0)); // 4x8 does not fit 8x4
        assert!(!blit(&src, 32, 8, 4, Rotation::Identity, Region { x0: 0, y0: 0, x1: 9, y1: 4 }, &mut dst, 32, 0, 0));
        assert!(!blit(&src, 32, 8, 4, Rotation::Identity, Region { x0: 3, y0: 0, x1: 3, y1: 4 }, &mut dst, 32, 0, 0));
        assert!(!blit(&src[..100], 32, 8, 4, Rotation::Identity, full, &mut dst, 32, 0, 0)); // short source
        assert!(!blit(&src, 16, 8, 4, Rotation::Identity, full, &mut dst, 32, 0, 0)); // pitch < row
        assert!(!blit(&src, 32, 8, 4, Rotation::Identity, full, &mut dst, 32, usize::MAX / 4, 0));
        assert!(!blit(&src, 32, 8, 4, Rotation::Rotate180, full, &mut dst, 32, 0, usize::MAX));
        assert!(dst.chunks(4).all(|p| p[3] == 255)); // the first, valid copy is intact
    }

    #[test]
    fn plan_clips_and_falls_back_to_full_copies() {
        let moves = [MoveRect { source: POINT { x: 0, y: 0 }, dest: rect(10, 10, 20, 20) }];
        let got = plan(&[rect(0, 0, 4, 4), rect(-5, -5, 2, 3), rect(5, 5, 5, 9), rect(99, 0, 120, 200)], &moves, 100, 100).unwrap();
        assert_eq!(
            got,
            vec![
                Region { x0: 0, y0: 0, x1: 4, y1: 4 },
                Region { x0: 0, y0: 0, x1: 2, y1: 3 },
                Region { x0: 99, y0: 0, x1: 100, y1: 100 },
                Region { x0: 10, y0: 10, x1: 20, y1: 20 },
            ]
        );
        assert_eq!(plan(&[rect(i32::MIN, i32::MIN, i32::MAX, i32::MAX)], &[], 100, 100), None);
        assert_eq!(plan(&[rect(i32::MAX, 0, i32::MIN, 10)], &[], 100, 100), Some(vec![]));
        assert_eq!(plan(&[rect(0, 0, 100, 74)], &[], 100, 100).map(|v| v.len()), Some(1));
        assert_eq!(plan(&[rect(0, 0, 100, 75)], &[], 100, 100), None);
        let many: Vec<RECT> = (0..MAX_REGIONS as i32 + 1).map(|i| rect(i, 0, i + 1, 1)).collect();
        assert_eq!(plan(&many, &[], 1000, 1000), None);
        assert!(plan(&many[1..], &[], 1000, 1000).is_some());
    }

    #[test]
    fn fetch_grows_once_and_distrusts_sizes() {
        let mut buf: Vec<RECT> = Vec::new();
        // Asks for room for 40 rectangles, then writes 3.
        let calls = std::cell::Cell::new(0);
        let n = fetch(&mut buf, 16, |len, p, need| {
            calls.set(calls.get() + 1);
            if (len as usize) < 40 * 16 {
                unsafe { *need = 40 * 16 };
                return DXGI_ERROR_MORE_DATA;
            }
            unsafe { *p.add(2) = rect(1, 2, 3, 4) };
            unsafe { *need = 3 * 16 };
            0
        });
        assert_eq!((n, calls.get(), buf.len()), (Some(3), 2, 40));
        assert_eq!(buf[2].right, 3);
        // Absurd or shrinking "required" sizes and failures are refused instead of trusted.
        assert_eq!(fetch(&mut buf, 0, |_, _, need| { unsafe { *need = u32::MAX }; DXGI_ERROR_MORE_DATA }), None);
        assert_eq!(fetch(&mut buf, 0, |_, _, need| { unsafe { *need = 16 }; DXGI_ERROR_MORE_DATA }), None);
        assert_eq!(fetch(&mut buf, 0, |_, _, _| 0x80004005u32 as i32), None);
        // A success claiming more bytes than the buffer holds is capped.
        assert_eq!(fetch(&mut buf, 0, |_, _, need| { unsafe { *need = u32::MAX }; 0 }), Some(buf.len()));
    }

    #[test]
    fn areas_contain_monitors() {
        let v = Area { left: -1920, top: -200, width: 5760, height: 1280 };
        assert!(contains(v, Area { left: -1920, top: 0, width: 1920, height: 1080 }));
        assert!(contains(v, Area { left: 0, top: -200, width: 3840, height: 1280 }));
        assert!(!contains(v, Area { left: 0, top: -200, width: 3841, height: 1280 }));
        assert!(!contains(v, Area { left: -1921, top: 0, width: 10, height: 10 }));
        assert!(!contains(v, Area { left: 0, top: 0, width: 0, height: 10 }));
        assert!(!contains(v, Area { left: i32::MAX, top: 0, width: i32::MAX, height: 10 }));
    }

    /// Fraction of pixels that are the same in two BGRA images (alpha ignored).
    fn same(a: &[u8], b: &[u8]) -> f64 {
        let n = a.chunks(4).zip(b.chunks(4)).filter(|(p, q)| p[..3] == q[..3]).count();
        n as f64 / (a.len() / 4) as f64
    }

    #[test]
    #[ignore = "captures the real screen; run with --ignored"]
    fn dxgi_matches_gdi_and_keeps_up_with_changes() {
        use crate::screen::MonitorSel;
        use super::super::capture::{self, GdiCapture};
        crate::platform::init_process();
        for sel in [MonitorSel::Primary, MonitorSel::All] {
            let area = capture::resolve(sel).unwrap();
            let t = Instant::now();
            let mut d = if sel == MonitorSel::All { DxgiCapture::all(area) } else { DxgiCapture::new(area) }.unwrap();
            let open_ms = t.elapsed().as_secs_f64() * 1000.0;
            assert!(d.next_frame(0).unwrap(), "first frame is reported");
            // Let incremental (dirty-region) updates run for a while, then compare with GDI.
            let (mut frames, mut busy) = (0, Duration::ZERO);
            let t = Instant::now();
            while t.elapsed() < Duration::from_millis(1500) {
                let s = Instant::now();
                if d.next_frame(0).unwrap() {
                    frames += 1;
                    busy += s.elapsed();
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            while d.next_frame(30).unwrap() {}
            let mut g = GdiCapture::new(area).unwrap();
            let similarity = same(d.pixels(), g.capture().unwrap());
            eprintln!(
                "{sel:?} {}x{}: {} output(s), open {open_ms:.1} ms, {frames} updates, {:.2} ms per update, {:.2}% equal to GDI",
                area.width,
                area.height,
                d.outputs.len(),
                busy.as_secs_f64() * 1000.0 / frames.max(1) as f64,
                similarity * 100.0
            );
            assert!(similarity > 0.97);
        }
    }
}
