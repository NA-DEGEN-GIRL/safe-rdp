//! GDI screen capture and cursor-shape tracking.

use super::mem::lock_pages;
pub use crate::screen::{Area, MonitorSel};
use crate::proto::Cursor;
use crate::util::{Error, Result};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{LPARAM, RECT, TRUE};
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

unsafe extern "system" fn enum_proc(hmon: HMONITOR, _: HDC, _: *mut RECT, data: LPARAM) -> windows_sys::core::BOOL {
    let out = unsafe { &mut *(data as *mut Vec<(Area, bool)>) };
    let mut mi: MONITORINFO = unsafe { std::mem::zeroed() };
    mi.cbSize = size_of::<MONITORINFO>() as u32;
    if unsafe { GetMonitorInfoW(hmon, &mut mi) } != 0 {
        let r = mi.rcMonitor;
        out.push((
            Area { left: r.left, top: r.top, width: r.right - r.left, height: r.bottom - r.top },
            mi.dwFlags & MONITORINFOF_PRIMARY != 0,
        ));
    }
    TRUE
}

/// Monitors with the primary first, then left-to-right.
pub fn monitors() -> Vec<Area> {
    let mut v: Vec<(Area, bool)> = Vec::new();
    unsafe { EnumDisplayMonitors(null_mut(), std::ptr::null(), Some(enum_proc), &mut v as *mut _ as LPARAM) };
    v.sort_by_key(|(a, primary)| (!primary, a.left, a.top));
    v.into_iter().map(|(a, _)| a).collect()
}

pub fn virtual_screen() -> Area {
    unsafe {
        Area {
            left: GetSystemMetrics(SM_XVIRTUALSCREEN),
            top: GetSystemMetrics(SM_YVIRTUALSCREEN),
            width: GetSystemMetrics(SM_CXVIRTUALSCREEN),
            height: GetSystemMetrics(SM_CYVIRTUALSCREEN),
        }
    }
}

pub fn resolve(sel: MonitorSel) -> Option<Area> {
    let a = match sel {
        MonitorSel::All => virtual_screen(),
        MonitorSel::Primary => *monitors().first()?,
        MonitorSel::Index(i) => *monitors().get(i)?,
    };
    // The wire format carries 16-bit dimensions.
    (a.width > 0 && a.height > 0 && a.width <= 0xffff && a.height <= 0xffff).then_some(a)
}

/// GDI fallback: copies one screen area into a page-locked DIB section. The screen's DC is
/// taken for each capture only: one kept would belong to the desktop it came from, not to the
/// one the capture thread follows.
pub struct GdiCapture {
    pub area: Area,
    mem: HDC,
    bmp: HBITMAP,
    old: HGDIOBJ,
    bits: *mut u8,
    len: usize,
}

impl GdiCapture {
    pub fn new(area: Area) -> Result<GdiCapture> {
        unsafe {
            let screen = GetDC(null_mut());
            if screen.is_null() {
                return Err(Error::last_os("GetDC"));
            }
            let mem = CreateCompatibleDC(screen);
            let mut bmi: BITMAPINFO = std::mem::zeroed();
            bmi.bmiHeader = BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: area.width,
                biHeight: -area.height, // top-down
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                ..std::mem::zeroed()
            };
            let mut bits = null_mut();
            let bmp = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
            let e = (mem.is_null() || bmp.is_null() || bits.is_null()).then(|| Error::last_os("CreateDIBSection"));
            ReleaseDC(null_mut(), screen);
            if let Some(e) = e {
                if !bmp.is_null() {
                    DeleteObject(bmp);
                }
                if !mem.is_null() {
                    DeleteDC(mem);
                }
                return Err(e);
            }
            let old = SelectObject(mem, bmp);
            let len = area.width as usize * area.height as usize * 4;
            lock_pages(bits as *const u8, len);
            Ok(GdiCapture { area, mem, bmp, old, bits: bits as *mut u8, len })
        }
    }

    /// Grabs the screen; returns BGRA pixels, top-down, `width*height*4` bytes.
    pub fn capture(&mut self) -> Result<&[u8]> {
        let a = self.area;
        unsafe {
            let screen = GetDC(null_mut());
            if screen.is_null() {
                return Err(Error::last_os("GetDC"));
            }
            let failed = BitBlt(self.mem, 0, 0, a.width, a.height, screen, a.left, a.top, SRCCOPY | CAPTUREBLT) == 0;
            let e = failed.then(|| Error::last_os("BitBlt"));
            ReleaseDC(null_mut(), screen);
            if let Some(e) = e {
                return Err(e);
            }
            GdiFlush();
            Ok(std::slice::from_raw_parts(self.bits, self.len))
        }
    }
}

impl Drop for GdiCapture {
    fn drop(&mut self) {
        unsafe {
            crate::util::wipe(std::slice::from_raw_parts_mut(self.bits, self.len));
            SelectObject(self.mem, self.old);
            DeleteObject(self.bmp);
            DeleteDC(self.mem);
        }
    }
}

/// Screen source: DXGI Desktop Duplication when possible (one monitor, or every monitor
/// composed for "all"), GDI otherwise (no GPU, DXGI refused, a monitor DXGI cannot duplicate,
/// or a desktop format it cannot convert).
pub enum Capturer {
    Dxgi(super::dxgi::DxgiCapture),
    Gdi(GdiCapture),
}

/// DXGI source for `sel` (already resolved to `area`).
fn dxgi(sel: MonitorSel, area: Area) -> Result<super::dxgi::DxgiCapture> {
    match sel {
        MonitorSel::All => super::dxgi::DxgiCapture::all(area),
        MonitorSel::Primary | MonitorSel::Index(_) => super::dxgi::DxgiCapture::new(area),
    }
}

impl Capturer {
    /// DXGI capture of the single monitor at `area`, else GDI.
    pub fn new(area: Area) -> Result<Capturer> {
        Capturer::dxgi_or_gdi(super::dxgi::DxgiCapture::new(area), area)
    }

    fn dxgi_or_gdi(d: Result<super::dxgi::DxgiCapture>, area: Area) -> Result<Capturer> {
        static LAST_REASON: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
        match d {
            Ok(d) => Ok(Capturer::Dxgi(d)),
            Err(e) => {
                let reason = e.to_string();
                let mut last = LAST_REASON.lock().unwrap_or_else(|p| p.into_inner());
                if *last != reason {
                    crate::log!("DXGI capture unavailable ({reason}); using GDI");
                    *last = reason;
                }
                Capturer::gdi(area)
            }
        }
    }

    pub fn gdi(area: Area) -> Result<Capturer> {
        Ok(Capturer::Gdi(GdiCapture::new(area)?))
    }

    /// Opens the best source for `sel` (already resolved to `area`).
    pub fn open(sel: MonitorSel, area: Area) -> Result<Capturer> {
        match sel {
            MonitorSel::All => Capturer::dxgi_or_gdi(super::dxgi::DxgiCapture::all(area), area),
            MonitorSel::Primary | MonitorSel::Index(_) => Capturer::new(area),
        }
    }

    /// After a fallback to GDI, tries DXGI again (a secure desktop, full-screen app or driver
    /// reset may have passed). Returns true if the source changed.
    pub fn try_upgrade(&mut self, sel: MonitorSel) -> bool {
        if let Capturer::Gdi(g) = self {
            if let Ok(d) = dxgi(sel, g.area) {
                *self = Capturer::Dxgi(d);
                return true;
            }
        }
        false
    }

    pub fn backend(&self) -> &'static str {
        match self {
            Capturer::Dxgi(_) => "DXGI",
            Capturer::Gdi(_) => "GDI",
        }
    }

    pub fn area(&self) -> Area {
        match self {
            Capturer::Dxgi(d) => d.area,
            Capturer::Gdi(g) => g.area,
        }
    }

    /// True if `next_frame` blocks until the screen changes (no polling needed).
    pub fn waits_for_changes(&self) -> bool {
        matches!(self, Capturer::Dxgi(_))
    }

    /// Updates `pixels()`; returns false if nothing changed within `timeout_ms` (DXGI only).
    pub fn next_frame(&mut self, timeout_ms: u32) -> Result<bool> {
        match self {
            Capturer::Dxgi(d) => d.next_frame(timeout_ms),
            Capturer::Gdi(g) => g.capture().map(|_| true),
        }
    }

    /// The most recent image: BGRA, top-down, `width*height*4` bytes.
    pub fn pixels(&self) -> &[u8] {
        match self {
            Capturer::Dxgi(d) => d.pixels(),
            Capturer::Gdi(g) => unsafe { std::slice::from_raw_parts(g.bits, g.len) },
        }
    }
}

/// Maps the system cursor handle to one of the standard shapes.
pub struct CursorTracker {
    table: Vec<(HCURSOR, Cursor)>,
}

pub const CURSOR_IDS: [(windows_sys::core::PCWSTR, Cursor); 14] = [
    (IDC_ARROW, Cursor::Arrow),
    (IDC_IBEAM, Cursor::IBeam),
    (IDC_WAIT, Cursor::Wait),
    (IDC_CROSS, Cursor::Cross),
    (IDC_UPARROW, Cursor::UpArrow),
    (IDC_SIZENWSE, Cursor::SizeNwse),
    (IDC_SIZENESW, Cursor::SizeNesw),
    (IDC_SIZEWE, Cursor::SizeWe),
    (IDC_SIZENS, Cursor::SizeNs),
    (IDC_SIZEALL, Cursor::SizeAll),
    (IDC_NO, Cursor::No),
    (IDC_HAND, Cursor::Hand),
    (IDC_APPSTARTING, Cursor::AppStarting),
    (IDC_HELP, Cursor::Help),
];

impl CursorTracker {
    pub fn new() -> CursorTracker {
        let table = CURSOR_IDS.iter().map(|&(id, c)| (unsafe { LoadCursorW(null_mut(), id) }, c)).collect();
        CursorTracker { table }
    }

    pub fn current(&self) -> Cursor {
        let mut ci: CURSORINFO = unsafe { std::mem::zeroed() };
        ci.cbSize = size_of::<CURSORINFO>() as u32;
        if unsafe { GetCursorInfo(&mut ci) } == 0 {
            return Cursor::Arrow;
        }
        if ci.flags & CURSOR_SHOWING == 0 {
            return Cursor::Hidden;
        }
        self.table.iter().find(|(h, _)| *h == ci.hCursor).map(|&(_, c)| c).unwrap_or(Cursor::Arrow)
    }
}
