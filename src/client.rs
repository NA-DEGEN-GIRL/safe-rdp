//! Viewer: a Win32 window that renders the remote screen and forwards keyboard and mouse.
//!
//! Hotkeys (handled locally, never forwarded):
//!   Ctrl+Alt+Enter  toggle full screen
//!   Ctrl+Alt+End    send Ctrl+Alt+Del to the host (service mode only)

use crate::capture::CURSOR_IDS;
use crate::channel::{self, RecordReader, RecordWriter};
use crate::clipboard::Clipboard;
use crate::codec::{self, Decoder, Rect};
use crate::mem::LockedBuf;
use crate::proto::*;
use crate::util::{Error, Result, Secret, wide};
use crate::{bail, log};
use std::collections::HashSet;
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

pub struct ViewerOptions {
    pub fullscreen: bool,
    pub clipboard: bool,
    pub view_only: bool,
    /// Allow local screenshot/recording tools to capture the viewer window.
    pub allow_capture: bool,
    /// Ask the host for 1/N resolution (1 = full).
    pub downscale: u8,
}

const WM_APP_FRAME: u32 = WM_APP + 1;
const WM_APP_CURSOR: u32 = WM_APP + 2;
const WM_APP_CLOSED: u32 = WM_APP + 3;
const WM_APP_FULLSCREEN: u32 = WM_APP + 4;

const MOD_CTRL: u8 = 1;
const MOD_ALT: u8 = 2;

struct Framebuffer {
    w: usize,
    h: usize,
    px: LockedBuf,
    dirty: Option<Rect>,
}

struct Saved {
    style: isize,
    placement: WINDOWPLACEMENT,
}

struct App {
    hwnd: AtomicUsize,
    fb: Mutex<Framebuffer>,
    fb_w: AtomicU32,
    fb_h: AtomicU32,
    out: mpsc::Sender<ClientMsg>,
    cursor: AtomicU8,
    view_only: bool,
    sas: bool,
    closed: Mutex<Option<String>>,
    hook_active: AtomicBool,
    mods: AtomicU8,
    swallowed: Mutex<HashSet<u16>>,
    fullscreen: Mutex<Option<Saved>>,
    buttons: AtomicU8,
    last_move: AtomicU32,
}

// SAFETY: WINDOWPLACEMENT inside `Saved` is plain data.
unsafe impl Send for Saved {}

static APP: OnceLock<App> = OnceLock::new();

/// True once the viewer window exists (later errors are reported in the window).
pub fn window_shown() -> bool {
    APP.get().is_some_and(|a| a.hwnd.load(Ordering::SeqCst) != 0)
}

impl App {
    fn hwnd(&self) -> HWND {
        self.hwnd.load(Ordering::SeqCst) as HWND
    }

    fn send(&self, m: ClientMsg) {
        let _ = self.out.send(m);
    }

    fn close(&self, reason: String) {
        let mut c = self.closed.lock().unwrap();
        if c.is_none() {
            *c = Some(reason);
        }
        unsafe { PostMessageW(self.hwnd(), WM_APP_CLOSED, 0, 0) };
    }

    fn is_fullscreen(&self) -> bool {
        self.fullscreen.lock().unwrap().is_some()
    }
}

fn resolve(target: &str) -> Result<SocketAddr> {
    let with_port = if target.parse::<SocketAddr>().is_ok() || target.rsplit_once(':').is_some_and(|(h, p)| !h.contains(':') && p.parse::<u16>().is_ok()) {
        target.to_string()
    } else if target.contains(':') {
        format!("[{target}]:{DEFAULT_PORT}")
    } else {
        format!("{target}:{DEFAULT_PORT}")
    };
    let addrs: Vec<SocketAddr> = with_port.to_socket_addrs().map_err(|e| format!("cannot resolve {target}: {e}"))?.collect();
    // Prefer Tailscale addresses when a name resolves to several.
    addrs
        .iter()
        .find(|a| crate::net::is_tailscale(a.ip()))
        .or(addrs.first())
        .copied()
        .ok_or_else(|| Error::msg(format!("{target} has no addresses")))
}

pub fn run(target: &str, opts: ViewerOptions, psk: Secret<32>) -> Result<()> {
    let addr = resolve(target)?;
    if !crate::net::is_tailscale(addr.ip()) && !addr.ip().is_loopback() {
        log!("warning: {addr} is not a Tailscale address; traffic is still end-to-end encrypted");
    }
    log!("connecting to {addr}...");
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|e| format!("cannot connect to {addr}: {e}"))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let keys = channel::client_handshake(&mut &stream, &psk.0)?;
    drop(psk);
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut reader = RecordReader::new(stream.try_clone()?, keys.recv);
    let mut writer = RecordWriter::new(stream.try_clone()?, keys.send);
    let mut hello = Vec::new();
    ClientMsg::Hello { downscale: opts.downscale }.encode(&mut hello);
    writer.send(&hello)?;
    let (w, h, flags) = match ServerMsg::decode(reader.recv()?)? {
        ServerMsg::Hello { width, height, flags } => (width as usize, height as usize, flags),
        _ => bail!("unexpected first message from host"),
    };
    if w == 0 || h == 0 {
        bail!("host reported an empty screen");
    }
    log!("connected: remote screen {w}x{h}");
    let view_only = opts.view_only || flags & F_VIEW_ONLY != 0;

    let (tx, rx) = mpsc::channel::<ClientMsg>();
    let app = App {
        hwnd: AtomicUsize::new(0),
        fb: Mutex::new(Framebuffer { w, h, px: LockedBuf::new(w * h * 4), dirty: None }),
        fb_w: AtomicU32::new(w as u32),
        fb_h: AtomicU32::new(h as u32),
        out: tx.clone(),
        cursor: AtomicU8::new(Cursor::Arrow as u8),
        view_only,
        sas: flags & F_SAS != 0,
        closed: Mutex::new(None),
        hook_active: AtomicBool::new(false),
        mods: AtomicU8::new(0),
        swallowed: Mutex::new(HashSet::new()),
        fullscreen: Mutex::new(None),
        buttons: AtomicU8::new(0),
        last_move: AtomicU32::new(u32::MAX),
    };
    if APP.set(app).is_err() {
        bail!("viewer already running in this process");
    }
    let app = APP.get().unwrap();

    let hwnd = create_window(target, w, h, &opts)?;
    app.hwnd.store(hwnd as usize, Ordering::SeqCst);

    std::thread::spawn(move || {
        let r = (|| -> Result<()> {
            loop {
                let m = match rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(m) => m,
                    Err(mpsc::RecvTimeoutError::Timeout) => ClientMsg::Ping,
                    Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                };
                let mut b = Vec::with_capacity(16);
                m.encode(&mut b);
                writer.send(&b)?;
            }
        })();
        if let Err(e) = r {
            APP.get().unwrap().close(format!("connection lost: {e}"));
        }
    });

    let clip = if opts.clipboard && flags & F_CLIPBOARD != 0 {
        let tx = tx.clone();
        Some(Clipboard::spawn(move |t| {
            let _ = tx.send(ClientMsg::Clipboard(t));
        })?)
    } else {
        if opts.clipboard {
            log!("host has clipboard sharing disabled");
        }
        None
    };
    drop(tx);

    std::thread::spawn(move || {
        let r = net_loop(&mut reader, clip.as_ref());
        APP.get().unwrap().close(match r {
            Err(e) if e.to_string() != channel::CLOSED => format!("connection lost: {e}"),
            _ => "the host closed the connection".into(),
        });
    });

    let hook = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(ll_keyboard), GetModuleHandleW(null()), 0) };
    if hook.is_null() {
        log!("warning: keyboard hook unavailable; system shortcuts stay local");
    } else {
        app.hook_active.store(true, Ordering::SeqCst);
    }
    if opts.fullscreen {
        toggle_fullscreen(hwnd);
    }

    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if !hook.is_null() {
            UnhookWindowsHookEx(hook);
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    // Wipe the remote screen contents before exiting.
    {
        let mut fb = app.fb.lock().unwrap();
        fb.px = LockedBuf::new(0);
    }
    match app.closed.lock().unwrap().take() {
        Some(reason) if reason != "closed" => Err(reason.into()),
        _ => Ok(()),
    }
}

fn net_loop(reader: &mut RecordReader<TcpStream>, clip: Option<&Clipboard>) -> Result<()> {
    let app = APP.get().unwrap();
    let mut dec = Decoder::new()?;
    loop {
        let rec = reader.recv()?;
        match ServerMsg::decode(rec)? {
            ServerMsg::Tiles(p) => {
                let hdr = codec::parse_header(p)?;
                let mut fb = app.fb.lock().unwrap();
                if (hdr.width, hdr.height) != (fb.w, fb.h) {
                    log!("remote screen is now {}x{}", hdr.width, hdr.height);
                    fb.px = LockedBuf::new(hdr.width * hdr.height * 4);
                    fb.w = hdr.width;
                    fb.h = hdr.height;
                    fb.dirty = Some(Rect { x: 0, y: 0, w: fb.w, h: fb.h });
                    app.fb_w.store(fb.w as u32, Ordering::SeqCst);
                    app.fb_h.store(fb.h as u32, Ordering::SeqCst);
                }
                let (fw, fh) = (fb.w, fb.h);
                let bbox = dec.apply(p, fb.px.as_mut_slice(), fw, fh)?;
                if let Some(b) = bbox {
                    fb.dirty = Some(match fb.dirty {
                        None => b,
                        Some(d) => {
                            let (x0, y0) = (d.x.min(b.x), d.y.min(b.y));
                            let (x1, y1) = ((d.x + d.w).max(b.x + b.w), (d.y + d.h).max(b.y + b.h));
                            Rect { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }
                        }
                    });
                }
                drop(fb);
                if hdr.last {
                    app.send(ClientMsg::Ack(hdr.frame));
                    unsafe { PostMessageW(app.hwnd(), WM_APP_FRAME, 0, 0) };
                }
            }
            ServerMsg::Cursor(c) => {
                app.cursor.store(c as u8, Ordering::SeqCst);
                unsafe { PostMessageW(app.hwnd(), WM_APP_CURSOR, 0, 0) };
            }
            ServerMsg::Clipboard(t) => {
                if let Some(c) = clip {
                    c.set(t);
                }
            }
            ServerMsg::Notice(t) => log!("host: {t}"),
            ServerMsg::Ping | ServerMsg::Hello { .. } => {}
        }
    }
}

fn create_window(target: &str, w: usize, h: usize, opts: &ViewerOptions) -> Result<HWND> {
    unsafe {
        let hinst = GetModuleHandleW(null());
        let class = wide("SafeRdpViewer");
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinst,
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: GetStockObject(BLACK_BRUSH),
            lpszClassName: class.as_ptr(),
            ..std::mem::zeroed()
        };
        if RegisterClassExW(&wc) == 0 {
            return Err(Error::last_os("RegisterClassExW"));
        }

        // Fit the remote screen into the primary monitor's work area, keeping aspect ratio.
        let mon = MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY);
        let mut mi: MONITORINFO = std::mem::zeroed();
        mi.cbSize = size_of::<MONITORINFO>() as u32;
        GetMonitorInfoW(mon, &mut mi);
        let work = mi.rcWork;
        let style = WS_OVERLAPPEDWINDOW;
        let mut frame = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        AdjustWindowRectEx(&mut frame, style, 0, 0);
        let (fw, fh) = (frame.right - frame.left, frame.bottom - frame.top);
        let max_w = ((work.right - work.left) - fw).max(320) as f64;
        let max_h = ((work.bottom - work.top) - fh).max(240) as f64;
        let scale = (max_w / w as f64).min(max_h / h as f64).min(1.0);
        let (cw, ch) = ((w as f64 * scale) as i32 + fw, (h as f64 * scale) as i32 + fh);

        let title = wide(&format!("safe-rdp - {target}"));
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            style,
            work.left + ((work.right - work.left) - cw).max(0) / 2,
            work.top + ((work.bottom - work.top) - ch).max(0) / 2,
            cw,
            ch,
            null_mut(),
            null_mut(),
            hinst,
            null(),
        );
        if hwnd.is_null() {
            return Err(Error::last_os("CreateWindowExW"));
        }
        if !opts.allow_capture && SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) == 0 {
            SetWindowDisplayAffinity(hwnd, WDA_MONITOR);
        }
        ShowWindow(hwnd, SW_SHOW);
        Ok(hwnd)
    }
}

/// Letterboxed destination rectangle of the remote image inside the client area.
fn dest_rect(cw: i32, ch: i32, fw: i32, fh: i32) -> RECT {
    if cw <= 0 || ch <= 0 || fw <= 0 || fh <= 0 {
        return RECT { left: 0, top: 0, right: 0, bottom: 0 };
    }
    let (dw, dh) = if cw as i64 * fh as i64 <= ch as i64 * fw as i64 {
        (cw, (cw as i64 * fh as i64 / fw as i64) as i32)
    } else {
        ((ch as i64 * fw as i64 / fh as i64) as i32, ch)
    };
    let (x, y) = ((cw - dw) / 2, (ch - dh) / 2);
    RECT { left: x, top: y, right: x + dw, bottom: y + dh }
}

fn client_size(hwnd: HWND) -> (i32, i32) {
    let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    unsafe { GetClientRect(hwnd, &mut r) };
    (r.right - r.left, r.bottom - r.top)
}

fn paint(hwnd: HWND) {
    let app = APP.get().unwrap();
    unsafe {
        let mut ps: PAINTSTRUCT = std::mem::zeroed();
        let hdc = BeginPaint(hwnd, &mut ps);
        let (cw, ch) = client_size(hwnd);
        let fb = app.fb.lock().unwrap();
        let (fw, fh) = (fb.w as i32, fb.h as i32);
        let d = dest_rect(cw, ch, fw, fh);
        let black = GetStockObject(BLACK_BRUSH);
        for r in [
            RECT { left: 0, top: 0, right: cw, bottom: d.top },
            RECT { left: 0, top: d.bottom, right: cw, bottom: ch },
            RECT { left: 0, top: d.top, right: d.left, bottom: d.bottom },
            RECT { left: d.right, top: d.top, right: cw, bottom: d.bottom },
        ] {
            if r.right > r.left && r.bottom > r.top {
                FillRect(hdc, &r, black);
            }
        }
        if fb.px.len() == (fw * fh * 4) as usize && fw > 0 {
            let mut bmi: BITMAPINFO = std::mem::zeroed();
            bmi.bmiHeader = BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: fw,
                biHeight: -fh,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                ..std::mem::zeroed()
            };
            let bits = fb.px.as_slice().as_ptr().cast();
            let (dw, dh) = (d.right - d.left, d.bottom - d.top);
            if dw == fw && dh == fh {
                SetDIBitsToDevice(hdc, d.left, d.top, fw as u32, fh as u32, 0, 0, 0, fh as u32, bits, &bmi, DIB_RGB_COLORS);
            } else {
                SetStretchBltMode(hdc, HALFTONE);
                SetBrushOrgEx(hdc, 0, 0, null_mut());
                StretchDIBits(hdc, d.left, d.top, dw, dh, 0, 0, fw, fh, bits, &bmi, DIB_RGB_COLORS, SRCCOPY);
            }
        }
        drop(fb);
        EndPaint(hwnd, &ps);
    }
}

/// Invalidates the window region covering the remote pixels that changed.
fn invalidate_dirty(hwnd: HWND) {
    let app = APP.get().unwrap();
    let (dirty, fw, fh) = {
        let mut fb = app.fb.lock().unwrap();
        (fb.dirty.take(), fb.w as i64, fb.h as i64)
    };
    let Some(r) = dirty else { return };
    let (cw, ch) = client_size(hwnd);
    let d = dest_rect(cw, ch, fw as i32, fh as i32);
    let (dw, dh) = ((d.right - d.left) as i64, (d.bottom - d.top) as i64);
    if dw <= 0 || dh <= 0 {
        return;
    }
    // Two pixels of slack for the halftone filter.
    let wr = RECT {
        left: d.left + (r.x as i64 * dw / fw) as i32 - 2,
        top: d.top + (r.y as i64 * dh / fh) as i32 - 2,
        right: d.left + (((r.x + r.w) as i64 * dw + fw - 1) / fw) as i32 + 2,
        bottom: d.top + (((r.y + r.h) as i64 * dh + fh - 1) / fh) as i32 + 2,
    };
    unsafe { InvalidateRect(hwnd, &wr, 0) };
}

/// Maps a client-area point to remote screen coordinates.
fn to_remote(hwnd: HWND, x: i32, y: i32) -> (u16, u16) {
    let app = APP.get().unwrap();
    let (fw, fh) = (app.fb_w.load(Ordering::SeqCst) as i64, app.fb_h.load(Ordering::SeqCst) as i64);
    let (cw, ch) = client_size(hwnd);
    let d = dest_rect(cw, ch, fw as i32, fh as i32);
    let (dw, dh) = ((d.right - d.left).max(1) as i64, (d.bottom - d.top).max(1) as i64);
    let rx = ((x - d.left) as i64 * fw / dw).clamp(0, fw - 1);
    let ry = ((y - d.top) as i64 * fh / dh).clamp(0, fh - 1);
    (rx as u16, ry as u16)
}

fn cursor_handle(c: u8) -> HCURSOR {
    let c = Cursor::from_u8(c);
    if c == Cursor::Hidden {
        return null_mut();
    }
    let id = CURSOR_IDS.iter().find(|(_, s)| *s == c).map(|(id, _)| *id).unwrap_or(IDC_ARROW);
    unsafe { LoadCursorW(null_mut(), id) }
}

fn cursor_inside(hwnd: HWND) -> bool {
    unsafe {
        let mut p = POINT { x: 0, y: 0 };
        GetCursorPos(&mut p);
        WindowFromPoint(p) == hwnd && {
            ScreenToClient(hwnd, &mut p);
            let (cw, ch) = client_size(hwnd);
            p.x >= 0 && p.y >= 0 && p.x < cw && p.y < ch
        }
    }
}

fn toggle_fullscreen(hwnd: HWND) {
    let app = APP.get().unwrap();
    let mut fs = app.fullscreen.lock().unwrap();
    unsafe {
        if let Some(saved) = fs.take() {
            SetWindowLongPtrW(hwnd, GWL_STYLE, saved.style);
            SetWindowPlacement(hwnd, &saved.placement);
            SetWindowPos(hwnd, null_mut(), 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
        } else {
            let style = GetWindowLongPtrW(hwnd, GWL_STYLE);
            let mut placement: WINDOWPLACEMENT = std::mem::zeroed();
            placement.length = size_of::<WINDOWPLACEMENT>() as u32;
            GetWindowPlacement(hwnd, &mut placement);
            let mut mi: MONITORINFO = std::mem::zeroed();
            mi.cbSize = size_of::<MONITORINFO>() as u32;
            GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mut mi);
            let r = mi.rcMonitor;
            SetWindowLongPtrW(hwnd, GWL_STYLE, style & !(WS_OVERLAPPEDWINDOW as isize));
            SetWindowPos(hwnd, HWND_TOP, r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
            *fs = Some(Saved { style, placement });
        }
    }
}

fn release_all(app: &App) {
    app.mods.store(0, Ordering::SeqCst);
    app.swallowed.lock().unwrap().clear();
    if app.buttons.swap(0, Ordering::SeqCst) != 0 {
        unsafe { ReleaseCapture() };
    }
    if !app.view_only {
        app.send(ClientMsg::ReleaseAll);
    }
}

/// Handles a physical key event while the viewer is in the foreground. Returns true if the
/// event was consumed (forwarded or used as a hotkey) and must not reach the local system.
fn on_key(app: &App, vk: u16, scan: u16, extended: bool, up: bool) -> bool {
    let bit = match vk {
        VK_CONTROL | VK_LCONTROL | VK_RCONTROL => MOD_CTRL,
        VK_MENU | VK_LMENU | VK_RMENU => MOD_ALT,
        _ => 0,
    };
    if bit != 0 {
        if up {
            app.mods.fetch_and(!bit, Ordering::SeqCst);
        } else {
            app.mods.fetch_or(bit, Ordering::SeqCst);
        }
    }
    let mods = app.mods.load(Ordering::SeqCst);
    let ctrl_alt = mods & (MOD_CTRL | MOD_ALT) == (MOD_CTRL | MOD_ALT);
    if up && app.swallowed.lock().unwrap().remove(&vk) {
        return true;
    }
    if !up && ctrl_alt && (vk == VK_RETURN || vk == VK_END) {
        app.swallowed.lock().unwrap().insert(vk);
        if vk == VK_RETURN {
            unsafe { PostMessageW(app.hwnd(), WM_APP_FULLSCREEN, 0, 0) };
        } else if app.sas && !app.view_only {
            app.send(ClientMsg::Sas);
        } else {
            log!("Ctrl+Alt+Del forwarding is not enabled on the host");
        }
        return true;
    }
    if app.view_only {
        return false;
    }
    // In a window, leave the Windows key and Alt+Tab / Alt+Esc / Ctrl+Esc to the local desktop
    // (like mstsc's default); in full screen everything goes to the host.
    if !app.is_fullscreen() {
        let local = matches!(vk, VK_LWIN | VK_RWIN)
            || (mods & MOD_ALT != 0 && matches!(vk, VK_TAB | VK_ESCAPE))
            || (mods & MOD_CTRL != 0 && vk == VK_ESCAPE);
        if local {
            return false;
        }
    }
    let mut flags = if up { KEY_UP } else { 0 };
    if extended {
        flags |= KEY_EXTENDED;
    }
    app.send(ClientMsg::Key { vk, scan, flags });
    true
}

unsafe extern "system" fn ll_keyboard(code: i32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        if code == HC_ACTION as i32 {
            if let Some(app) = APP.get() {
                let hwnd = app.hwnd();
                if !hwnd.is_null() && GetForegroundWindow() == hwnd {
                    let k = &*(lp as *const KBDLLHOOKSTRUCT);
                    let up = k.flags & LLKHF_UP != 0;
                    if on_key(app, k.vkCode as u16, k.scanCode as u16, k.flags & LLKHF_EXTENDED != 0, up) {
                        return 1;
                    }
                }
            }
        }
        CallNextHookEx(null_mut(), code, wp, lp)
    }
}

fn mouse_button(app: &App, hwnd: HWND, lp: LPARAM, button: u8, down: bool) {
    if app.view_only {
        return;
    }
    let (x, y) = to_remote(hwnd, (lp & 0xffff) as i16 as i32, ((lp >> 16) & 0xffff) as i16 as i32);
    app.send(ClientMsg::MouseMove { x, y });
    app.send(ClientMsg::MouseButton { button, down });
    let bit = 1u8 << button;
    unsafe {
        if down {
            if app.buttons.fetch_or(bit, Ordering::SeqCst) == 0 {
                SetCapture(hwnd);
            }
        } else if app.buttons.fetch_and(!bit, Ordering::SeqCst) & !bit == 0 {
            ReleaseCapture();
        }
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let Some(app) = APP.get() else { return unsafe { DefWindowProcW(hwnd, msg, wp, lp) } };
    unsafe {
        match msg {
            WM_PAINT => {
                paint(hwnd);
                0
            }
            WM_ERASEBKGND => 1,
            WM_APP_FRAME => {
                invalidate_dirty(hwnd);
                0
            }
            WM_SIZE => {
                InvalidateRect(hwnd, null(), 0);
                0
            }
            WM_APP_FULLSCREEN => {
                toggle_fullscreen(hwnd);
                0
            }
            WM_APP_CURSOR => {
                if cursor_inside(hwnd) {
                    SetCursor(cursor_handle(app.cursor.load(Ordering::SeqCst)));
                }
                0
            }
            WM_SETCURSOR if (lp & 0xffff) as u32 == HTCLIENT => {
                SetCursor(cursor_handle(app.cursor.load(Ordering::SeqCst)));
                1
            }
            WM_APP_CLOSED => {
                let reason = app.closed.lock().unwrap().clone();
                if let Some(r) = reason.filter(|r| r != "closed") {
                    log!("{r}");
                    let text = wide(&r);
                    MessageBoxW(hwnd, text.as_ptr(), wide("safe-rdp").as_ptr(), MB_ICONWARNING | MB_OK);
                }
                DestroyWindow(hwnd);
                0
            }
            WM_CLOSE => {
                *app.closed.lock().unwrap() = Some("closed".into());
                DestroyWindow(hwnd);
                0
            }
            WM_ACTIVATE => {
                if (wp & 0xffff) as u32 == WA_INACTIVE {
                    release_all(app);
                }
                0
            }
            WM_MOUSEMOVE => {
                if !app.view_only {
                    let (x, y) = to_remote(hwnd, (lp & 0xffff) as i16 as i32, ((lp >> 16) & 0xffff) as i16 as i32);
                    let packed = (x as u32) << 16 | y as u32;
                    if app.last_move.swap(packed, Ordering::SeqCst) != packed {
                        app.send(ClientMsg::MouseMove { x, y });
                    }
                }
                0
            }
            WM_LBUTTONDOWN | WM_LBUTTONDBLCLK => {
                mouse_button(app, hwnd, lp, BTN_LEFT, true);
                0
            }
            WM_LBUTTONUP => {
                mouse_button(app, hwnd, lp, BTN_LEFT, false);
                0
            }
            WM_RBUTTONDOWN | WM_RBUTTONDBLCLK => {
                mouse_button(app, hwnd, lp, BTN_RIGHT, true);
                0
            }
            WM_RBUTTONUP => {
                mouse_button(app, hwnd, lp, BTN_RIGHT, false);
                0
            }
            WM_MBUTTONDOWN | WM_MBUTTONDBLCLK => {
                mouse_button(app, hwnd, lp, BTN_MIDDLE, true);
                0
            }
            WM_MBUTTONUP => {
                mouse_button(app, hwnd, lp, BTN_MIDDLE, false);
                0
            }
            WM_XBUTTONDOWN | WM_XBUTTONDBLCLK | WM_XBUTTONUP => {
                let b = if ((wp >> 16) & 0xffff) as u16 == XBUTTON1 { BTN_X1 } else { BTN_X2 };
                mouse_button(app, hwnd, lp, b, msg != WM_XBUTTONUP);
                1
            }
            WM_MOUSEWHEEL | WM_MOUSEHWHEEL => {
                if !app.view_only {
                    let delta = ((wp >> 16) & 0xffff) as u16 as i16;
                    app.send(ClientMsg::Wheel { delta, horizontal: msg == WM_MOUSEHWHEEL });
                }
                0
            }
            WM_CAPTURECHANGED => {
                // Capture taken away mid-drag: let go of the buttons on the host as well.
                let held = app.buttons.swap(0, Ordering::SeqCst);
                if held != 0 && !app.view_only {
                    for b in 0..5u8 {
                        if held & (1 << b) != 0 {
                            app.send(ClientMsg::MouseButton { button: b, down: false });
                        }
                    }
                }
                0
            }
            WM_KEYDOWN | WM_KEYUP | WM_SYSKEYDOWN | WM_SYSKEYUP => {
                // Only reached when the low-level hook is unavailable or passed the key on.
                if !app.hook_active.load(Ordering::SeqCst) {
                    let scan = ((lp >> 16) & 0xff) as u16;
                    let extended = (lp >> 24) & 1 != 0;
                    let up = msg == WM_KEYUP || msg == WM_SYSKEYUP;
                    if on_key(app, wp as u16, scan, extended, up) {
                        return 0;
                    }
                }
                DefWindowProcW(hwnd, msg, wp, lp)
            }
            WM_SYSCHAR | WM_SYSCOMMAND if msg == WM_SYSCHAR || (wp & 0xfff0) as u32 == SC_KEYMENU => 0,
            WM_DPICHANGED => {
                let r = &*(lp as *const RECT);
                SetWindowPos(hwnd, null_mut(), r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER | SWP_NOACTIVATE);
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}
