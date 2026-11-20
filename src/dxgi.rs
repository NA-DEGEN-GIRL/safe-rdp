//! DXGI Desktop Duplication capture (GPU-side, wakes only when the screen changes).
//!
//! windows-sys has no COM interface bindings, so the handful of vtable slots used here are
//! declared by hand. Slot numbers were taken from the Windows SDK headers (dxgi.h,
//! dxgi1_2.h, d3d11.h, C interface section).

use crate::capture::Area;
use crate::mem::LockedBuf;
use crate::util::{Error, Result};
use std::ffi::c_void;
use std::ptr::{null, null_mut};
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
const IID_ID3D11TEXTURE2D: GUID = GUID::from_u128(0x6f15aaf2_d208_4e89_9ab4_489535d34f9c);

const DXGI_ERROR_NOT_FOUND: HRESULT = 0x887A0002u32 as i32;
const DXGI_ERROR_WAIT_TIMEOUT: HRESULT = 0x887A0027u32 as i32;
const D3D_DRIVER_TYPE_UNKNOWN: i32 = 0;
const D3D11_SDK_VERSION: u32 = 7;
const DXGI_FORMAT_B8G8R8A8_UNORM: u32 = 87;
const D3D11_USAGE_STAGING: u32 = 3;
const D3D11_CPU_ACCESS_READ: u32 = 0x20000;
const D3D11_MAP_READ: u32 = 1;
const DXGI_MODE_ROTATION_UNSPECIFIED: u32 = 0;
const DXGI_MODE_ROTATION_IDENTITY: u32 = 1;

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

pub struct DxgiCapture {
    pub area: Area,
    _device: Com,
    context: Com,
    dupl: Com,
    staging: Option<Com>,
    pixels: LockedBuf,
    have_frame: bool,
}

// The COM objects are only ever used from the capture thread that owns this value.
unsafe impl Send for DxgiCapture {}

/// Finds the adapter/output pair whose desktop rectangle is exactly `area`.
fn find_output(area: Area) -> Result<(Com, Com)> {
    unsafe {
        let mut f = null_mut();
        hr(CreateDXGIFactory1(&IID_IDXGIFACTORY1, &mut f), "CreateDXGIFactory1")?;
        let factory = Com(f);
        let enum_adapters: unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> HRESULT = factory.slot(7);
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
                if get_desc(output.0, &mut d) < 0 {
                    continue;
                }
                let r = d.desktop;
                let rect = Area { left: r.left, top: r.top, width: r.right - r.left, height: r.bottom - r.top };
                if rect == area {
                    if d.rotation != DXGI_MODE_ROTATION_IDENTITY && d.rotation != DXGI_MODE_ROTATION_UNSPECIFIED {
                        return Err("rotated display (using GDI capture)".into());
                    }
                    return Ok((adapter, output));
                }
            }
        }
        Err("no DXGI output matches the selected area".into())
    }
}

impl DxgiCapture {
    pub fn new(area: Area) -> Result<DxgiCapture> {
        let (adapter, output) = find_output(area)?;
        unsafe {
            let levels = [0xb100, 0xb000, 0xa100, 0xa000]; // 11.1, 11.0, 10.1, 10.0
            let (mut dev, mut ctx, mut got) = (null_mut(), null_mut(), 0);
            let mut r = D3D11CreateDevice(adapter.0, D3D_DRIVER_TYPE_UNKNOWN, null_mut(), 0, levels.as_ptr(), 4, D3D11_SDK_VERSION, &mut dev, &mut got, &mut ctx);
            if r < 0 {
                // Pre-11.1 runtimes reject the 11.1 level outright.
                r = D3D11CreateDevice(adapter.0, D3D_DRIVER_TYPE_UNKNOWN, null_mut(), 0, levels[1..].as_ptr(), 3, D3D11_SDK_VERSION, &mut dev, &mut got, &mut ctx);
            }
            hr(r, "D3D11CreateDevice")?;
            let (device, context) = (Com(dev), Com(ctx));
            let output1 = output.query(&IID_IDXGIOUTPUT1)?;
            let duplicate: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> HRESULT = output1.slot(22);
            let mut d = null_mut();
            hr(duplicate(output1.0, device.0, &mut d), "DuplicateOutput")?;
            let len = area.width as usize * area.height as usize * 4;
            Ok(DxgiCapture { area, _device: device, context, dupl: Com(d), staging: None, pixels: LockedBuf::new(len), have_frame: false })
        }
    }

    pub fn pixels(&self) -> &[u8] {
        self.pixels.as_slice()
    }

    /// Waits up to `timeout_ms` for a new desktop image. Ok(true) if `pixels()` was updated.
    pub fn next_frame(&mut self, timeout_ms: u32) -> Result<bool> {
        unsafe {
            let acquire: unsafe extern "system" fn(*mut c_void, u32, *mut DxgiOutduplFrameInfo, *mut *mut c_void) -> HRESULT = self.dupl.slot(8);
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
            let has_image = info.last_present_time != 0 || !self.have_frame;
            let copied = if has_image { self.copy_to_staging(&resource) } else { Ok(false) };
            drop(resource);
            release_frame(self.dupl.0);
            if !copied? {
                return Ok(false);
            }
            self.read_staging()?;
            self.have_frame = true;
            Ok(true)
        }
    }

    unsafe fn copy_to_staging(&mut self, resource: &Com) -> Result<bool> {
        unsafe {
            let tex = resource.query(&IID_ID3D11TEXTURE2D)?;
            let get_desc: unsafe extern "system" fn(*mut c_void, *mut D3d11Texture2dDesc) = tex.slot(10);
            let mut desc = D3d11Texture2dDesc::default();
            get_desc(tex.0, &mut desc);
            if desc.width as i32 != self.area.width || desc.height as i32 != self.area.height {
                return Err(Error::msg(format!("desktop is now {}x{}", desc.width, desc.height)));
            }
            if desc.format != DXGI_FORMAT_B8G8R8A8_UNORM {
                return Err(Error::msg(format!("unsupported desktop format {} (HDR?)", desc.format)));
            }
            if self.staging.is_none() {
                let sd = D3d11Texture2dDesc {
                    width: desc.width,
                    height: desc.height,
                    mip_levels: 1,
                    array_size: 1,
                    format: desc.format,
                    sample_count: 1,
                    sample_quality: 0,
                    usage: D3D11_USAGE_STAGING,
                    bind_flags: 0,
                    cpu_access_flags: D3D11_CPU_ACCESS_READ,
                    misc_flags: 0,
                };
                let create: unsafe extern "system" fn(*mut c_void, *const D3d11Texture2dDesc, *const c_void, *mut *mut c_void) -> HRESULT = self._device.slot(5);
                let mut s = null_mut();
                hr(create(self._device.0, &sd, null(), &mut s), "CreateTexture2D")?;
                self.staging = Some(Com(s));
            }
            let copy: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void) = self.context.slot(47);
            copy(self.context.0, self.staging.as_ref().unwrap().0, tex.0);
            Ok(true)
        }
    }

    fn read_staging(&mut self) -> Result<()> {
        unsafe {
            let staging = self.staging.as_ref().unwrap();
            let map: unsafe extern "system" fn(*mut c_void, *mut c_void, u32, u32, u32, *mut D3d11MappedSubresource) -> HRESULT = self.context.slot(14);
            let unmap: unsafe extern "system" fn(*mut c_void, *mut c_void, u32) = self.context.slot(15);
            let mut m: D3d11MappedSubresource = std::mem::zeroed();
            hr(map(self.context.0, staging.0, 0, D3D11_MAP_READ, 0, &mut m), "Map")?;
            let row = self.area.width as usize * 4;
            let pitch = m.row_pitch as usize;
            let dst = self.pixels.as_mut_slice();
            let src = m.data as *const u8;
            for y in 0..self.area.height as usize {
                std::ptr::copy_nonoverlapping(src.add(y * pitch), dst.as_mut_ptr().add(y * row), row);
            }
            unmap(self.context.0, staging.0, 0);
            Ok(())
        }
    }
}
