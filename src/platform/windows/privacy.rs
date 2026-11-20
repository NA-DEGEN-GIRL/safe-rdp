//! Privacy mode: while a viewer is connected, blank the host's physical screen and block its
//! local keyboard and mouse.
//!
//! * Every monitor gets a black, topmost, click-through, non-activating overlay window saying
//!   that a remote session is in progress (in Korean and English). The overlays carry
//!   `WDA_EXCLUDEFROMCAPTURE`, so our own DXGI/GDI capture - and therefore the viewer - still
//!   sees the desktop beneath them. They follow monitor changes and re-assert their topmost
//!   position a few times per second.
//! * Low-level keyboard and mouse hooks swallow every event that our `input::Injector` did not
//!   send: physical input as well as input synthesised by other programs. The injector gives
//!   each event a fresh random `dwExtraInfo` tag (`input::new_tag`), and a tag lets one injected
//!   event through, once. Hooks that run after ours and the window that receives the event only
//!   ever see used tags. A program whose own low-level hook runs before ours (Windows calls the
//!   most recently installed first) can still see our events and swallow one to replay its tag
//!   with input of its own. Windows silently drops a low-level hook that once misses its time
//!   limit, so the hooks are re-installed every few seconds.
//!
//! Everything lives on one thread with its own message loop. Dropping `Privacy` removes the
//! hooks and windows before it returns; if the thread or the process dies, Windows removes
//! them as well, so local input always comes back.
//!
//! The person at the machine keeps an escape hatch: Ctrl+Alt+Del (the secure attention
//! sequence) and Win+L stay with Windows. The secure attention sequence is recognised by the
//! kernel ahead of any hook, so they can always reach the security screen and lock the machine
//! or sign out from there; Win+L, too, is handled by Windows itself rather than delivered as an
//! ordinary key press.
//!
//! Limits: the secure desktop (UAC prompts, lock and sign-in screens) is not covered; shell
//! surfaces that sit above ordinary topmost windows (Start, notifications, task switcher) show
//! through while the remote user has them open; the mouse pointer stays visible; touch and pen
//! input reach applications directly; and a host that is not elevated cannot block input
//! while an elevated window has the focus (Windows skips its hooks then). The service host,
//! running as SYSTEM, has no such gap. Needs Windows 10 version 2004 (build 19041) or later for
//! `WDA_EXCLUDEFROMCAPTURE`.

use super::input::take_tag;
use crate::bail;
use crate::screen::Area;
use crate::util::{Error, Result, wide};
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::HiDpi::{DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetThreadDpiAwarenessContext};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn RtlGetVersion(info: *mut OSVERSIONINFOW) -> i32;
}

const WM_APP_STOP: u32 = WM_APP + 1;
const WM_APP_REBUILD: u32 = WM_APP + 2;
/// Housekeeping period: put the overlays back on top, notice monitor changes.
const TICK_MS: u32 = 250;
/// Re-install the hooks every 5 s.
const REHOOK_TICKS: u32 = 20;
/// Move the notice every minute so that it does not burn into OLED panels.
const DRIFT_TICKS: u32 = 240;
/// Windows 10 version 2004, the first with `WDA_EXCLUDEFROMCAPTURE`.
const MIN_BUILD: u32 = 19041;
const TEXT_KO: &str = "원격 세션 진행 중 - 이 화면은 가려져 있습니다";
const TEXT_EN: &str = "Remote session in progress";
const FONT: &str = "Malgun Gothic";
/// Set in an overlay's GWLP_USERDATA (next to its COLORREF) when it shows the notice.
const SHOW_TEXT: isize = 1 << 24;
/// Vertical offsets of the notice, in units of half its drift range; one step per minute.
const DRIFT_STEPS: [i32; 8] = [0, 1, 2, 1, 0, -1, -2, -1];

/// Drift step shared by all overlays.
static DRIFT: AtomicU32 = AtomicU32::new(0);

/// Privacy mode while it is on; dropping the value turns it off again.
pub struct Privacy {
    thread_id: u32,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// What the privacy thread puts up. `enable` covers every monitor; tests use small areas.
struct Config {
    /// Fixed overlay rectangles instead of one per monitor.
    areas: Option<Vec<Area>>,
    /// Overlay fill (COLORREF) and whether the notice is written on it.
    color: u32,
    text: bool,
    affinity: WINDOW_DISPLAY_AFFINITY,
    hooks: bool,
    /// Re-install the hooks every this many ticks.
    rehook_ticks: u32,
}

impl Config {
    /// Privacy mode proper: every monitor black with the notice, hidden from capture, input blocked.
    fn screen() -> Config {
        Config { areas: None, color: 0, text: true, affinity: WDA_EXCLUDEFROMCAPTURE, hooks: true, rehook_ticks: REHOOK_TICKS }
    }
}

impl Privacy {
    /// Whether this host can provide privacy mode at all.
    pub fn available() -> bool {
        windows_build() >= MIN_BUILD
    }

    /// Turns privacy mode on; returns once the overlays and input hooks are in place.
    pub fn enable() -> Result<Privacy> {
        if !Privacy::available() {
            bail!("privacy mode needs Windows 10 version 2004 or later");
        }
        Privacy::start(Config::screen())
    }

    fn start(cfg: Config) -> Result<Privacy> {
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<Result<u32>>();
        let flag = stop.clone();
        let thread = std::thread::Builder::new().name("privacy".into()).spawn(move || run(cfg, &flag, tx))?;
        match rx.recv() {
            Ok(Ok(thread_id)) => Ok(Privacy { thread_id, stop, thread: Some(thread) }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err("privacy thread died".into())
            }
        }
    }
}

impl Drop for Privacy {
    fn drop(&mut self) {
        // The thread also checks the flag on every timer tick, should the message get lost.
        self.stop.store(true, Ordering::SeqCst);
        unsafe { PostThreadMessageW(self.thread_id, WM_APP_STOP, 0, 0) };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The real Windows build number (RtlGetVersion is not subject to compatibility shims).
fn windows_build() -> u32 {
    let mut v: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    v.dwOSVersionInfoSize = size_of::<OSVERSIONINFOW>() as u32;
    if unsafe { RtlGetVersion(&mut v) } < 0 {
        return 0;
    }
    v.dwBuildNumber
}

/// Body of the privacy thread: set up, report to `enable`, then serve until told to stop.
fn run(cfg: Config, stop: &AtomicBool, ready: mpsc::Sender<Result<u32>>) {
    unsafe {
        // Monitor rectangles and window positions in physical pixels, whatever the process uses.
        SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        // Create the message queue before anyone can post to it.
        let mut msg: MSG = std::mem::zeroed();
        PeekMessageW(&mut msg, null_mut(), WM_USER, WM_USER, PM_NOREMOVE);
    }
    let hooks = cfg.hooks;
    let mut shield = Shield { cfg, overlays: Vec::new(), hooks: None, timer: 0, last_error: String::new() };
    let setup = shield.sync_overlays().and_then(|()| {
        if hooks {
            shield.hooks = Some(Hooks::install()?);
        }
        shield.timer = unsafe { SetTimer(null_mut(), 0, TICK_MS, None) };
        if shield.timer == 0 {
            return Err(Error::last_os("SetTimer"));
        }
        Ok(())
    });
    if let Err(e) = setup {
        let _ = ready.send(Err(e));
        return; // `shield` takes down whatever was set up
    }
    let _ = ready.send(Ok(unsafe { GetCurrentThreadId() }));
    shield.serve(stop);
}

struct Overlay {
    hwnd: HWND,
    area: Area,
}

/// Everything the privacy thread owns; dropping it gives the screen and local input back.
struct Shield {
    cfg: Config,
    overlays: Vec<Overlay>,
    hooks: Option<Hooks>,
    /// Thread timer driving `tick`.
    timer: usize,
    last_error: String,
}

impl Shield {
    /// Message loop until `stop` is set. Other processes on the desktop can post to this thread,
    /// so a stray WM_QUIT or stop message alone does not end privacy mode; only `Privacy::drop`
    /// (which sets the flag first) does.
    fn serve(&mut self, stop: &AtomicBool) {
        unsafe {
            let mut msg: MSG = std::mem::zeroed();
            let mut ticks = 0u32;
            loop {
                let r = GetMessageW(&mut msg, null_mut(), 0, 0);
                if stop.load(Ordering::SeqCst) || r == -1 {
                    break;
                }
                if r == 0 {
                    continue; // WM_QUIT
                }
                if msg.hwnd.is_null() {
                    match msg.message {
                        WM_APP_STOP => continue,
                        WM_APP_REBUILD => {
                            // Every overlay reports the same display change.
                            while PeekMessageW(&mut msg, null_mut(), WM_APP_REBUILD, WM_APP_REBUILD, PM_REMOVE) != 0 {}
                            self.refresh();
                            continue;
                        }
                        WM_TIMER => {
                            ticks = ticks.wrapping_add(1);
                            self.tick(ticks);
                            continue;
                        }
                        _ => {}
                    }
                }
                DispatchMessageW(&msg);
            }
        }
    }

    fn tick(&mut self, n: u32) {
        self.refresh();
        if self.cfg.hooks && n % self.cfg.rehook_ticks.max(1) == 0 {
            // The new hooks are in place before the old ones are removed.
            match Hooks::install() {
                Ok(h) => self.hooks = Some(h),
                Err(e) => self.report(e),
            }
        }
        if n % DRIFT_TICKS == 0 {
            DRIFT.fetch_add(1, Ordering::Relaxed);
            for o in &self.overlays {
                unsafe { InvalidateRect(o.hwnd, null(), 0) };
            }
        }
    }

    /// Follows monitor changes and puts every overlay back on screen and on top.
    fn refresh(&mut self) {
        if let Err(e) = self.sync_overlays() {
            self.report(e);
        }
        for o in &self.overlays {
            unsafe {
                if IsWindowVisible(o.hwnd) == 0 || IsIconic(o.hwnd) != 0 {
                    ShowWindow(o.hwnd, SW_SHOWNOACTIVATE);
                }
                SetWindowPos(o.hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
            }
        }
    }

    /// Logs a housekeeping failure once (they repeat every tick).
    fn report(&mut self, e: Error) {
        let e = e.to_string();
        if e != self.last_error {
            crate::log!("privacy mode: {e}");
            self.last_error = e;
        }
    }

    /// Makes the overlays match the monitors. New windows go up before old ones come down, so
    /// the screen never shows in between; on failure the old ones stay.
    fn sync_overlays(&mut self) -> Result<()> {
        let want = match &self.cfg.areas {
            Some(a) => a.clone(),
            None => super::capture::monitors(),
        };
        if self.cfg.areas.is_none() && want.is_empty() {
            bail!("no monitors found");
        }
        let alive = self.overlays.iter().all(|o| unsafe { IsWindow(o.hwnd) } != 0);
        if alive && self.overlays.iter().map(|o| o.area).eq(want.iter().copied()) {
            return Ok(());
        }
        let mut fresh = Vec::with_capacity(want.len());
        for area in want {
            match create_overlay(area, &self.cfg) {
                Ok(hwnd) => fresh.push(Overlay { hwnd, area }),
                Err(e) => {
                    for o in fresh {
                        unsafe { DestroyWindow(o.hwnd) };
                    }
                    return Err(e);
                }
            }
        }
        for o in std::mem::replace(&mut self.overlays, fresh) {
            unsafe { DestroyWindow(o.hwnd) };
        }
        Ok(())
    }
}

impl Drop for Shield {
    fn drop(&mut self) {
        // Input first: it must come back even if taking a window down misbehaves.
        self.hooks = None;
        for o in self.overlays.drain(..) {
            unsafe { DestroyWindow(o.hwnd) };
        }
        if self.timer != 0 {
            unsafe { KillTimer(null_mut(), self.timer) };
        }
    }
}

struct Hooks {
    keyboard: HHOOK,
    mouse: HHOOK,
}

impl Hooks {
    fn install() -> Result<Hooks> {
        unsafe {
            let module = GetModuleHandleW(null());
            let keyboard = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_proc), module, 0);
            if keyboard.is_null() {
                return Err(Error::last_os("SetWindowsHookExW(keyboard)"));
            }
            let mouse = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_proc), module, 0);
            if mouse.is_null() {
                let e = Error::last_os("SetWindowsHookExW(mouse)");
                UnhookWindowsHookEx(keyboard);
                return Err(e);
            }
            Ok(Hooks { keyboard, mouse })
        }
    }
}

impl Drop for Hooks {
    fn drop(&mut self) {
        unsafe {
            UnhookWindowsHookEx(self.mouse);
            UnhookWindowsHookEx(self.keyboard);
        }
    }
}

/// Whether an input event may pass while privacy mode is on: only what our injector sent, and
/// each of its events once.
fn passes(injected: bool, extra_info: usize) -> bool {
    injected && take_tag(extra_info)
}

unsafe extern "system" fn keyboard_proc(code: i32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        if code == HC_ACTION as i32 && lp != 0 {
            let k = &*(lp as *const KBDLLHOOKSTRUCT);
            if !passes(k.flags & LLKHF_INJECTED != 0, k.dwExtraInfo) {
                return 1;
            }
        }
        CallNextHookEx(null_mut(), code, wp, lp)
    }
}

unsafe extern "system" fn mouse_proc(code: i32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        if code == HC_ACTION as i32 && lp != 0 {
            let m = &*(lp as *const MSLLHOOKSTRUCT);
            if !passes(m.flags & LLMHF_INJECTED != 0, m.dwExtraInfo) {
                return 1;
            }
        }
        CallNextHookEx(null_mut(), code, wp, lp)
    }
}

/// Shows one overlay window over `area`.
fn create_overlay(area: Area, cfg: &Config) -> Result<HWND> {
    unsafe {
        let hinst = GetModuleHandleW(null());
        let class = wide("SafeRdpPrivacy");
        let wc = WNDCLASSW { lpfnWndProc: Some(wnd_proc), hInstance: hinst, lpszClassName: class.as_ptr(), ..std::mem::zeroed() };
        RegisterClassW(&wc); // may already exist; CreateWindowExW reports real failures
        let ex = WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE;
        let title = wide("safe-rdp privacy");
        let (x, y, w, h) = (area.left, area.top, area.width, area.height);
        let hwnd = CreateWindowExW(ex, class.as_ptr(), title.as_ptr(), WS_POPUP, x, y, w, h, null_mut(), null_mut(), hinst, null());
        if hwnd.is_null() {
            return Err(Error::last_os("CreateWindowExW(privacy)"));
        }
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (cfg.color & 0xff_ffff) as isize | if cfg.text { SHOW_TEXT } else { 0 });
        // Never show an overlay that capture could see: the viewer would get a black screen.
        let mut affinity = u32::MAX;
        let err = if SetLayeredWindowAttributes(hwnd, 0, 255, LWA_ALPHA) == 0 {
            Some(Error::last_os("SetLayeredWindowAttributes"))
        } else if SetWindowDisplayAffinity(hwnd, cfg.affinity) == 0 {
            Some(Error::last_os("SetWindowDisplayAffinity"))
        } else if GetWindowDisplayAffinity(hwnd, &mut affinity) == 0 || affinity != cfg.affinity {
            Some(Error::msg("the overlay could not be excluded from screen capture"))
        } else {
            None
        };
        if let Some(e) = err {
            DestroyWindow(hwnd);
            return Err(e);
        }
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        UpdateWindow(hwnd);
        Ok(hwnd)
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_PAINT => {
                paint(hwnd);
                0
            }
            WM_ERASEBKGND => 1, // WM_PAINT fills everything
            WM_NCHITTEST => HTTRANSPARENT as LRESULT,
            WM_MOUSEACTIVATE => MA_NOACTIVATE as LRESULT,
            // Nobody but the privacy thread closes, moves or minimises an overlay.
            WM_CLOSE | WM_SYSCOMMAND => 0,
            WM_DISPLAYCHANGE => {
                PostThreadMessageW(GetCurrentThreadId(), WM_APP_REBUILD, 0, 0);
                DefWindowProcW(hwnd, msg, wp, lp)
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

/// Where the notice goes on a `w` x `h` overlay: font heights of the two lines and their boxes.
/// Centred at drift step 0, then wandering up and down the middle half of the screen.
fn text_layout(w: i32, h: i32, drift: u32) -> (i32, i32, RECT, RECT) {
    // About 22 em of Korean text has to fit across, two lines with some leading down.
    let big = (h / 22).min(w / 26).clamp(12, 120);
    let small = (big * 2 / 3).max(10);
    let (line1, line2) = (big * 3 / 2, small * 3 / 2);
    let room = (h - line1 - line2).max(0) / 2;
    let swing = room.min(h / 4) / 2;
    let top = room + DRIFT_STEPS[drift as usize % DRIFT_STEPS.len()] * swing;
    let first = RECT { left: 0, top, right: w, bottom: top + line1 };
    let second = RECT { left: 0, top: first.bottom, right: w, bottom: first.bottom + line2 };
    (big, small, first, second)
}

fn paint(hwnd: HWND) {
    unsafe {
        let mut ps: PAINTSTRUCT = std::mem::zeroed();
        let hdc = BeginPaint(hwnd, &mut ps);
        if hdc.is_null() {
            return;
        }
        let mut rc: RECT = std::mem::zeroed();
        GetClientRect(hwnd, &mut rc);
        let data = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        let brush = CreateSolidBrush((data & 0xff_ffff) as u32);
        FillRect(hdc, &rc, brush);
        DeleteObject(brush);
        if data & SHOW_TEXT != 0 {
            let (big, small, first, second) = text_layout(rc.right - rc.left, rc.bottom - rc.top, DRIFT.load(Ordering::Relaxed));
            let face = wide(FONT);
            SetBkMode(hdc, TRANSPARENT as i32);
            for (text, size, color, line) in [(TEXT_KO, big, 0x00c8c8c8, first), (TEXT_EN, small, 0x008c8c8c, second)] {
                let font = CreateFontW(
                    -size,
                    0,
                    0,
                    0,
                    FW_NORMAL as i32,
                    0,
                    0,
                    0,
                    DEFAULT_CHARSET as u32,
                    OUT_DEFAULT_PRECIS as u32,
                    CLIP_DEFAULT_PRECIS as u32,
                    CLEARTYPE_QUALITY as u32,
                    (DEFAULT_PITCH | FF_DONTCARE) as u32,
                    face.as_ptr(),
                );
                let old = SelectObject(hdc, font);
                SetTextColor(hdc, color);
                let t: Vec<u16> = text.encode_utf16().collect();
                let mut r = line;
                DrawTextW(hdc, t.as_ptr(), t.len() as i32, &mut r, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                SelectObject(hdc, old);
                DeleteObject(font);
            }
        }
        EndPaint(hwnd, &ps);
    }
}

#[cfg(test)]
mod tests {
    use super::super::input::new_tag;
    use super::*;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;

    #[test]
    fn only_our_injected_events_pass_and_each_once() {
        let tag = new_tag();
        assert!(!passes(false, tag)); // a device driver claiming our tag is still physical
        assert!(passes(true, tag));
        assert!(!passes(true, tag), "a replayed tag passed");
        let next = new_tag();
        assert_ne!(next, tag);
        assert!(!passes(true, 0));
        assert!(!passes(true, next ^ 2));
        assert!(!passes(true, next ^ (1 << 40)));
        assert!(!passes(true, 0x5344_5250)); // the fixed tag of earlier versions
        assert!(!passes(false, 0));
        assert!(passes(true, next));
    }

    #[test]
    fn availability_follows_the_build_number() {
        let build = windows_build();
        assert!(build > 7600, "RtlGetVersion returned build {build}");
        assert_eq!(Privacy::available(), build >= MIN_BUILD);
    }

    #[test]
    fn notice_stays_on_screen_and_starts_centred() {
        for (w, h) in [(3840, 2160), (1920, 1080), (1080, 1920), (1280, 1024), (800, 600), (640, 480)] {
            let (big, small, a, b) = text_layout(w, h, 0);
            assert!(big >= 12 && small >= 10 && big >= small);
            assert!(26 * big <= w, "{w}x{h}: {big} px text is too wide");
            assert!((a.top - (h - b.bottom)).abs() <= 1, "{w}x{h}: not centred ({} above, {} below)", a.top, h - b.bottom);
            for drift in 0..20 {
                let (_, _, a, b) = text_layout(w, h, drift);
                assert!(a.top >= h / 8 && b.bottom <= h - h / 8, "{w}x{h} drift {drift}: {} to {}", a.top, b.bottom);
                assert_eq!((a.left, a.right, a.bottom), (0, w, b.top));
            }
        }
        // Absurd sizes do not panic.
        text_layout(0, 0, u32::MAX);
        text_layout(i32::MAX, i32::MAX, 3);
    }

    /// Share of pixels in the `w` x `h` block at (x, y) of a BGRA image that are magenta.
    fn magenta(px: &[u8], stride: usize, (x, y): (usize, usize), (w, h): (usize, usize)) -> f64 {
        let mut n = 0;
        for row in y..y + h {
            for p in px[row * stride + x * 4..][..w * 4].chunks(4) {
                if p[0] > 200 && p[1] < 60 && p[2] > 200 {
                    n += 1;
                }
            }
        }
        n as f64 / (w * h) as f64
    }

    #[test]
    #[ignore = "shows a small magenta window in a screen corner for well under a second; run with --ignored"]
    fn overlay_is_hidden_from_our_capture() {
        use super::super::capture::{self, GdiCapture};
        use super::super::dxgi::DxgiCapture;
        use crate::screen::MonitorSel;
        crate::platform::init_process();
        let mon = capture::resolve(MonitorSel::Primary).unwrap();
        let virt = capture::resolve(MonitorSel::All).unwrap();
        let (w, h) = (300usize, 200usize);
        let spot = Area { left: mon.left, top: mon.top, width: w as i32, height: h as i32 };
        let in_virt = ((mon.left - virt.left) as usize, (mon.top - virt.top) as usize);
        // A process may duplicate each output only once at a time: one DXGI source per round.
        for (affinity, visible) in [(WDA_EXCLUDEFROMCAPTURE, false), (WDA_NONE, true)] {
            for all in [false, true] {
                // Everything slow happens before the window appears.
                let mut dxgi = if all { DxgiCapture::all(virt) } else { DxgiCapture::new(mon) }.unwrap();
                let mut gdi = GdiCapture::new(spot).unwrap();
                while dxgi.next_frame(0).unwrap() {}
                let shown = Instant::now();
                let cfg = Config { areas: Some(vec![spot]), color: 0x00ff00ff, text: false, affinity, hooks: false, ..Config::screen() };
                let p = Privacy::start(cfg).unwrap();
                std::thread::sleep(Duration::from_millis(100));
                let deadline = Instant::now() + Duration::from_millis(300);
                while Instant::now() < deadline && dxgi.next_frame(20).unwrap() {}
                let g = magenta(gdi.capture().unwrap(), w * 4, (0, 0), (w, h));
                drop(p);
                let on_screen = shown.elapsed();
                let class = wide("SafeRdpPrivacy");
                assert!(unsafe { FindWindowW(class.as_ptr(), null()) }.is_null(), "overlay left behind");
                let d = if all {
                    magenta(dxgi.pixels(), virt.width as usize * 4, in_virt, (w, h))
                } else {
                    magenta(dxgi.pixels(), mon.width as usize * 4, (0, 0), (w, h))
                };
                let name = if all { "DXGI all" } else { "DXGI" };
                eprintln!("affinity {affinity:#x}: magenta share {name} {d:.3}, GDI {g:.3}; window visible {on_screen:?}");
                assert!(on_screen < Duration::from_secs(1));
                for share in [d, g] {
                    if visible {
                        assert!(share > 0.95, "control: capture should see the window ({share})");
                    } else {
                        assert!(share < 0.01, "excluded window leaked into capture ({share})");
                    }
                }
            }
        }
    }

    static SEEN: Mutex<Vec<(bool, usize)>> = Mutex::new(Vec::new());
    /// Tags of the test's own events, ours or not.
    static SENT: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    /// Tags some other program might use.
    fn foreign() -> [usize; 2] {
        [new_tag() ^ 0x5a5a, new_tag() ^ 0x5a5a]
    }

    fn ours_or_foreign(tag: usize) -> bool {
        SENT.lock().unwrap().contains(&tag)
    }

    /// Records our test events (keyboard?, tag) and swallows them so no application sees them.
    unsafe extern "system" fn watch_keys(code: i32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        unsafe {
            let k = &*(lp as *const KBDLLHOOKSTRUCT);
            if code == HC_ACTION as i32 && k.vkCode == VK_F24 as u32 && ours_or_foreign(k.dwExtraInfo) {
                SEEN.lock().unwrap().push((true, k.dwExtraInfo));
                return 1;
            }
            CallNextHookEx(null_mut(), code, wp, lp)
        }
    }

    unsafe extern "system" fn watch_mouse(code: i32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        unsafe {
            let m = &*(lp as *const MSLLHOOKSTRUCT);
            if code == HC_ACTION as i32 && ours_or_foreign(m.dwExtraInfo) {
                SEEN.lock().unwrap().push((false, m.dwExtraInfo));
                return 1;
            }
            CallNextHookEx(null_mut(), code, wp, lp)
        }
    }

    /// Presses and releases F24, or nudges the mouse, with these two tags.
    fn inject(tags: [usize; 2], keyboard: bool) {
        SENT.lock().unwrap().extend(tags);
        let key = |flags, tag| INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: VK_F24, wScan: 0, dwFlags: flags, time: 0, dwExtraInfo: tag } },
        };
        // One pixel right and back (Windows drops moves by zero). The watcher swallows both, so
        // the pointer does not actually move.
        let nudge = |dx, tag| INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 { mi: MOUSEINPUT { dx, dy: 0, mouseData: 0, dwFlags: MOUSEEVENTF_MOVE, time: 0, dwExtraInfo: tag } },
        };
        let inputs = if keyboard {
            [key(0, tags[0]), key(KEYEVENTF_KEYUP, tags[1])]
        } else {
            [nudge(1, tags[0]), nudge(-1, tags[1])]
        };
        unsafe { SendInput(inputs.len() as u32, inputs.as_ptr(), size_of::<INPUT>() as i32) };
    }

    /// Runs this thread's message loop (and so its hooks) for `ms`.
    fn pump(ms: u64) {
        let end = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < end {
            unsafe {
                let mut msg: MSG = std::mem::zeroed();
                while PeekMessageW(&mut msg, null_mut(), 0, 0, PM_REMOVE) != 0 {
                    DispatchMessageW(&msg);
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    #[ignore = "blocks the local keyboard and mouse for about 1 s; run with --ignored"]
    fn hooks_pass_only_our_injected_input() {
        unsafe {
            let mut cursor = POINT { x: 0, y: 0 };
            GetCursorPos(&mut cursor);
            let module = GetModuleHandleW(null());
            // Installed first, these run after the privacy hooks and see only what they pass.
            let kb = SetWindowsHookExW(WH_KEYBOARD_LL, Some(watch_keys), module, 0);
            let ms = SetWindowsHookExW(WH_MOUSE_LL, Some(watch_mouse), module, 0);
            assert!(!kb.is_null() && !ms.is_null());
            // Re-install the hooks on every tick and let that happen a few times first: the
            // checks below then run on re-installed hooks, and none may be left over afterwards.
            let p = Privacy::start(Config { areas: Some(vec![]), text: false, rehook_ticks: 1, ..Config::screen() });
            let p = p.unwrap();
            pump(3 * TICK_MS as u64 + 50);
            // What anybody on the desktop could post must not end privacy mode.
            PostThreadMessageW(p.thread_id, WM_QUIT, 0, 0);
            PostThreadMessageW(p.thread_id, WM_APP_STOP, 0, 0);
            pump(20);
            let (keys, moves) = ([new_tag(), new_tag()], [new_tag(), new_tag()]);
            inject(foreign(), true);
            inject(foreign(), false);
            inject(keys, true);
            inject(moves, false);
            // Somebody who saw them sends their tags again.
            inject(keys, true);
            inject(moves, false);
            pump(150);
            let during = std::mem::take(&mut *SEEN.lock().unwrap());
            drop(p);
            let (fk, fm) = (foreign(), foreign());
            inject(fk, true);
            inject(fm, false);
            pump(100);
            let after = std::mem::take(&mut *SEEN.lock().unwrap());
            UnhookWindowsHookEx(ms);
            UnhookWindowsHookEx(kb);
            let mut now = POINT { x: 0, y: 0 };
            GetCursorPos(&mut now);
            if (now.x, now.y) != (cursor.x, cursor.y) {
                SetCursorPos(cursor.x, cursor.y);
            }
            assert_eq!(during, [(true, keys[0]), (true, keys[1]), (false, moves[0]), (false, moves[1])]);
            assert_eq!(after, [(true, fk[0]), (true, fk[1]), (false, fm[0]), (false, fm[1])]);
        }
    }
}
