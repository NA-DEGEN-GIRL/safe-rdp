//! Viewer chrome, custom-drawn with GDI: the connection bar (a slim strip docked at the top
//! of a window; in full screen a bar that slides in when the pointer touches the top edge),
//! its menus, hover hints, toasts and the centred status overlay. Everything is a child of
//! the viewer window, so it shares the window's capture exclusion. Text follows the user's
//! UI language: Korean when it is Korean, English otherwise.

use crate::proto::{MONITOR_ALL, MonitorInfo};
use crate::util::{Error, Result, wide};
use std::cell::RefCell;
use std::fmt::Display;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{ReleaseCapture, SetCapture, TME_LEAVE, TRACKMOUSEEVENT, TrackMouseEvent};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

/// Commands posted to the parent as `WM_COMMAND` (id in the low word of `wParam`).
pub const CMD_SAS: u16 = 1001;
pub const CMD_CLIPBOARD: u16 = 1002;
pub const CMD_SEND_FILES: u16 = 1003;
pub const CMD_GET_FILES: u16 = 1004;
pub const CMD_SOUND: u16 = 1005;
pub const CMD_PRIVACY: u16 = 1006;
pub const CMD_FULLSCREEN: u16 = 1007;
pub const CMD_DISCONNECT: u16 = 1008;
/// `CMD_QUALITY + proto::QUALITY_*`.
pub const CMD_QUALITY: u16 = 1100;
/// `CMD_SCALE + downscale factor` (1 = full resolution).
pub const CMD_SCALE: u16 = 1200;
/// `CMD_MONITOR + monitor index`, or `CMD_MONITOR + proto::MONITOR_ALL`.
pub const CMD_MONITOR: u16 = 1300;
/// Posted to the parent when a toast closed itself, so the others can be re-stacked.
pub const WM_CHROME: u32 = WM_APP + 40;

const WM_MOUSELEAVE: u32 = 0x02a3;

// ---------------------------------------------------------------------------------------
// Strings

macro_rules! texts {
    ($($name:ident => $en:literal, $ko:literal;)*) => {
        /// User-visible text; `tr` picks the language.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum Txt { $($name),* }

        impl Txt {
            #[cfg(test)]
            const ALL: &[Txt] = &[$(Txt::$name),*];

            fn pair(self) -> (&'static str, &'static str) {
                match self { $(Txt::$name => ($en, $ko)),* }
            }
        }
    };
}

texts! {
    PinHint => "Keep the bar visible", "연결 표시줄 항상 표시";
    UnpinHint => "Hide the bar automatically", "연결 표시줄 자동으로 숨기기";
    Monitor => "Monitor", "모니터";
    MonitorN => "Monitor {}", "모니터 {}";
    AllMonitors => "All monitors", "모든 모니터";
    Primary => "primary", "주 모니터";
    MonitorHint => "Choose which of the host's monitors to show.", "표시할 호스트 모니터를 고릅니다.";
    Quality => "Quality", "화질";
    Lossless => "Lossless", "무손실";
    Balanced => "Balanced", "균형";
    LowBandwidth => "Low bandwidth", "저대역폭";
    LosslessMenu => "Lossless – sharpest, needs a fast connection", "무손실 – 가장 선명함, 빠른 연결 필요";
    BalancedMenu => "Balanced – sharpens once the screen is still (recommended)", "균형 – 화면이 멈추면 선명해짐 (권장)";
    LowBandwidthMenu => "Low bandwidth – for slow connections", "저대역폭 – 느린 연결용";
    QualityHint => "Trade image quality for speed.", "화질과 속도의 균형을 조절합니다.";
    Scale => "Scale", "해상도";
    ScaleFull => "full resolution", "원본 해상도";
    ScaleHint => "Resolution the host sends. Lower is faster on slow connections.", "호스트가 보내는 해상도입니다. 낮을수록 느린 연결에서 빠릅니다.";
    SasHint => "Send Ctrl+Alt+Del to the host (shortcut: Ctrl+Alt+End).", "호스트에 Ctrl+Alt+Del을 보냅니다 (단축키: Ctrl+Alt+End).";
    Clipboard => "Clipboard", "클립보드";
    ClipboardHint => "Share copied text with the host in both directions.", "복사한 텍스트를 호스트와 양방향으로 공유합니다.";
    SendFiles => "Send files…", "파일 보내기…";
    SendFilesHint => "Send files to the host's Downloads\\safe-rdp folder. You can also drop files onto this window.",
        "파일을 호스트의 다운로드\\safe-rdp 폴더로 보냅니다. 이 창에 파일을 끌어다 놓아도 됩니다.";
    GetFiles => "Get copied files", "복사한 파일 받기";
    GetFilesHint => "Copy files on the host (Ctrl+C in Explorer), then click here to receive them in Downloads\\safe-rdp.",
        "호스트 탐색기에서 파일을 복사(Ctrl+C)한 뒤 누르면 다운로드\\safe-rdp 폴더로 받습니다.";
    Sound => "Sound", "소리";
    SoundHint => "Play the host's sound on this computer.", "호스트의 소리를 이 컴퓨터에서 재생합니다.";
    Privacy => "Privacy screen", "화면 가리기";
    PrivacyHint => "Blank the host's monitor and block its local keyboard and mouse while you work.",
        "작업하는 동안 호스트 모니터를 가리고 호스트의 키보드와 마우스를 막습니다.";
    FullScreen => "Full screen", "전체 화면";
    ExitFullScreen => "Exit full screen", "전체 화면 종료";
    FullScreenHint => "Shortcut: Ctrl+Alt+Enter", "단축키: Ctrl+Alt+Enter";
    Disconnect => "Disconnect", "연결 끊기";
    DisconnectHint => "End the session and close this window.", "세션을 끝내고 이 창을 닫습니다.";
    InfoHint => "Round-trip time · frames per second · incoming data rate", "왕복 시간 · 초당 프레임 · 수신 속도";
    On => "on", "켜짐";
    Off => "off", "꺼짐";
    NotOnHost => "Not available on this host.", "이 호스트에서는 사용할 수 없습니다.";
    NotOnThisPc => "Not available on this computer.", "이 컴퓨터에서는 사용할 수 없습니다.";
    WhileReconnecting => "Unavailable while reconnecting.", "다시 연결하는 동안에는 사용할 수 없습니다.";
    OpenFolder => "Open folder", "폴더 열기";
    HostMessage => "Message from the host", "호스트 메시지";
    Reconnecting => "Reconnecting to {}…", "{}에 다시 연결하는 중…";
    ReconnectingShort => "Reconnecting…", "다시 연결하는 중…";
    LostBecause => "Connection lost: {}", "연결이 끊어졌습니다: {}";
    AttemptFailed => "Attempt {} failed: {}", "{}번째 시도 실패: {}";
    NextAttempt => "Next attempt in {} s.", "{}초 후 다시 시도합니다.";
    Trying => "Connecting…", "연결하는 중…";
    Reconnected => "Reconnected to {}", "{}에 다시 연결되었습니다";
    GaveUp => "Could not reconnect to {}.\n\nLast error: {}", "{}에 다시 연결하지 못했습니다.\n\n마지막 오류: {}";
    KickedAgain => "{} closed the connection again right after reconnecting. Another viewer has probably connected to it.",
        "다시 연결하자마자 {}에서 연결을 닫았습니다. 다른 뷰어가 연결한 것 같습니다.";
    SessionEnded => "The connection to {} ended: {}", "{} 연결이 끊어졌습니다: {}";
    HostClosed => "the host closed the connection", "호스트가 연결을 닫음";
    NoAnswer => "the host stopped responding", "호스트 응답 없음";
    Received => "Received {}", "{} 받음";
    SavedTo => "Saved to {}", "저장 위치: {}";
    Sent => "Sent {}", "{} 보냄";
    SavedOnHost => "Saved on the host: {}", "호스트 저장 위치: {}";
    SendFailed => "Could not send {}", "{} 파일을 보내지 못했습니다";
    ReceiveFailed => "Could not receive {}", "{} 파일을 받지 못했습니다";
    Interrupted => "The connection dropped during the transfer.", "전송 중에 연결이 끊어졌습니다.";
    FoldersNotSupported => "Folders cannot be sent", "폴더는 보낼 수 없습니다";
    RequestedFiles => "Asked the host for its copied files", "호스트에 복사된 파일을 요청했습니다";
    RequestedFilesHint => "Files copied on the host (Ctrl+C in Explorer) arrive in Downloads\\safe-rdp.",
        "호스트에서 복사(Ctrl+C)한 파일이 다운로드\\safe-rdp 폴더로 들어옵니다.";
    Uploading => "↑ {} {}% ({} of {})", "↑ {} {}% ({}/{})";
    Downloading => "↓ {} {}%", "↓ {} {}%";
    SoundUnavailable => "Sound cannot be played on this computer", "이 컴퓨터에서 소리를 재생할 수 없습니다";
    NotConnected => "Not connected. Try again once the connection is back.", "연결되어 있지 않습니다. 다시 연결된 뒤에 시도하세요.";
    NotResponding => "No response for {} s", "{}초 동안 응답 없음";
    SettingRefused => "{}: not available on this host", "{}: 이 호스트에서는 사용할 수 없습니다";
    ChooseFiles => "Send files to {}", "{}(으)로 보낼 파일";
    AllFiles => "All files", "모든 파일";
    TooManyFiles => "Too many files were selected at once.", "한 번에 너무 많은 파일을 선택했습니다.";
    SasDisabled => "Ctrl+Alt+Del forwarding is not enabled on this host.", "이 호스트에서는 Ctrl+Alt+Del 전달이 켜져 있지 않습니다.";
}

/// True when the user's UI language is Korean (primary language 0x12).
pub fn korean() -> bool {
    static KO: OnceLock<bool> = OnceLock::new();
    *KO.get_or_init(|| unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() } & 0x3ff == 0x12)
}

pub fn tr(t: Txt) -> &'static str {
    let (en, ko) = t.pair();
    if korean() { ko } else { en }
}

/// `tr` with each `{}` replaced by the next argument.
pub fn trf(t: Txt, args: &[&dyn Display]) -> String {
    fill(tr(t), args)
}

fn fill(template: &str, args: &[&dyn Display]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut args = args.iter();
    let mut rest = template;
    while let Some(i) = rest.find("{}") {
        out.push_str(&rest[..i]);
        if let Some(a) = args.next() {
            out.push_str(&a.to_string());
        }
        rest = &rest[i + 2..];
    }
    out.push_str(rest);
    out
}

/// Characters that change how the text around them is shown without being visible
/// themselves: bidirectional marks, embeddings, overrides and isolates, and the BOM.
fn is_format_char(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

/// Text from the host made safe to show: control and bidi-formatting characters are dropped
/// (so `a\u{202e}txt.exe` cannot pass for `aexe.txt`), tabs and, unless `multiline`, line
/// breaks become spaces; at most `max_chars` characters, trimmed.
pub fn clean_text(s: &str, multiline: bool, max_chars: usize) -> String {
    s.chars()
        .filter_map(|c| match c {
            '\n' if multiline => Some('\n'),
            '\t' | '\n' => Some(' '),
            c if c.is_control() || is_format_char(c) => None,
            c => Some(c),
        })
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

/// At most `max_lines` lines (runs of blank lines count as one) and `max_chars` characters
/// of `s`, ending in "…" where something was cut.
fn shorten(s: &str, max_lines: usize, max_chars: usize) -> String {
    let mut lines: Vec<&str> = Vec::new();
    let mut cut = false;
    for l in s.trim().lines().map(str::trim_end) {
        if l.is_empty() && lines.last().is_some_and(|p| p.is_empty()) {
            continue;
        }
        if lines.len() == max_lines {
            cut = true;
            break;
        }
        lines.push(l);
    }
    let mut out = lines.join("\n");
    if out.chars().count() > max_chars {
        out = out.chars().take(max_chars).collect();
        cut = true;
    }
    if cut {
        out.truncate(out.trim_end().len());
        out.push('…');
    }
    out
}

// ---------------------------------------------------------------------------------------
// Look

const fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    r as u32 | (g as u32) << 8 | (b as u32) << 16
}

const BG: COLORREF = rgb(0x1f, 0x1f, 0x1f);
const BG_PANEL: COLORREF = rgb(0x2b, 0x2b, 0x2b);
const BORDER: COLORREF = rgb(0x4a, 0x4a, 0x4a);
const FG: COLORREF = rgb(0xff, 0xff, 0xff);
const FG_DIM: COLORREF = rgb(0xc8, 0xc8, 0xc8);
const FG_DISABLED: COLORREF = rgb(0x74, 0x74, 0x74);
const HOVER: COLORREF = rgb(0x3d, 0x3d, 0x3d);
const PRESSED: COLORREF = rgb(0x55, 0x55, 0x55);
const ACCENT: COLORREF = rgb(0x00, 0x5f, 0xb8);
const ACCENT_HOVER: COLORREF = rgb(0x19, 0x75, 0xd2);
const ACCENT_OFF: COLORREF = rgb(0x24, 0x3a, 0x52);
const DANGER: COLORREF = rgb(0xc4, 0x2b, 0x1c);
const WARN: COLORREF = rgb(0xff, 0xc8, 0x3d);
const GOOD: COLORREF = rgb(0x6c, 0xcb, 0x5f);
const BAD: COLORREF = rgb(0xff, 0x78, 0x6b);
const INFO: COLORREF = rgb(0x60, 0xcd, 0xff);

const ICON_FACE: &str = "Segoe MDL2 Assets";
const G_PIN: u16 = 0xe718;
const G_MONITOR: u16 = 0xe7f4;
const G_QUALITY: u16 = 0xe9e9;
const G_SCALE: u16 = 0xe9a6;
const G_KEYBOARD: u16 = 0xe765;
const G_CLIPBOARD: u16 = 0xe77f;
const G_UPLOAD: u16 = 0xe898;
const G_DOWNLOAD: u16 = 0xe896;
const G_SOUND: u16 = 0xe767;
const G_MUTE: u16 = 0xe74f;
const G_PRIVACY: u16 = 0xe7ef;
const G_FULL: u16 = 0xe740;
const G_UNFULL: u16 = 0xe73f;
const G_CLOSE: u16 = 0xe711;
const G_CHEVRON: u16 = 0xe70d;
const G_INFO: u16 = 0xe946;
const G_CHECK: u16 = 0xe73e;
const G_WARN: u16 = 0xe7ba;
const G_ERROR: u16 = 0xe783;
const G_SYNC: u16 = 0xe72c;

/// Bar height at 96 DPI.
pub const BAR_HEIGHT: i32 = 34;
/// Widest status text the bar reserves room for (keeps the layout from jittering).
const STATUS_SAMPLE: &str = "9999 ms · 60 fps · 99.9 Mbit/s";
const STATUS_SHORT_SAMPLE: &str = "9999 ms";

/// `v` device-independent pixels at `dpi`, rounded.
pub fn scale(v: i32, dpi: u32) -> i32 {
    ((v as i64 * dpi as i64 + 48) / 96) as i32
}

#[derive(Clone, Copy)]
struct Metrics(u32);

impl Metrics {
    fn px(self, v: i32) -> i32 {
        scale(v, self.0)
    }
}

fn dpi_of(hwnd: HWND) -> u32 {
    match unsafe { GetDpiForWindow(hwnd) } {
        0 => 96,
        d => d,
    }
}

fn client_size(hwnd: HWND) -> (i32, i32) {
    let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    unsafe { GetClientRect(hwnd, &mut r) };
    (r.right - r.left, r.bottom - r.top)
}

struct Fonts {
    dpi: u32,
    text: HFONT,
    bold: HFONT,
    icon: HFONT,
    small_icon: HFONT,
    /// The icon font exists; otherwise every button shows its label.
    icons: bool,
}

impl Fonts {
    fn new(dpi: u32) -> Fonts {
        let face = if korean() { "Malgun Gothic" } else { "Segoe UI" };
        let make = |px: i32, weight: u32, face: &str| unsafe {
            CreateFontW(
                -scale(px, dpi),
                0,
                0,
                0,
                weight as i32,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                OUT_DEFAULT_PRECIS as u32,
                CLIP_DEFAULT_PRECIS as u32,
                CLEARTYPE_QUALITY as u32,
                DEFAULT_PITCH as u32,
                wide(face).as_ptr(),
            )
        };
        let icon = make(16, FW_NORMAL, ICON_FACE);
        let icons = font_face_is(icon, ICON_FACE);
        Fonts {
            dpi,
            text: make(12, FW_NORMAL, face),
            bold: make(12, FW_SEMIBOLD, face),
            icon,
            small_icon: make(9, FW_NORMAL, ICON_FACE),
            icons,
        }
    }
}

impl Drop for Fonts {
    fn drop(&mut self) {
        for f in [self.text, self.bold, self.icon, self.small_icon] {
            if !f.is_null() {
                unsafe { DeleteObject(f) };
            }
        }
    }
}

fn font_face_is(font: HFONT, face: &str) -> bool {
    if font.is_null() {
        return false;
    }
    unsafe {
        let dc = GetDC(null_mut());
        if dc.is_null() {
            return false;
        }
        let old = SelectObject(dc, font);
        let mut name = [0u16; 64];
        let n = GetTextFaceW(dc, name.len() as i32, name.as_mut_ptr());
        SelectObject(dc, old);
        ReleaseDC(null_mut(), dc);
        n > 0 && crate::util::from_wide(&name).eq_ignore_ascii_case(face)
    }
}

thread_local! {
    static FONTS: RefCell<Option<Rc<Fonts>>> = const { RefCell::new(None) };
}

/// Fonts for `dpi`, shared by every chrome window of this thread.
fn fonts(dpi: u32) -> Rc<Fonts> {
    FONTS.with(|cell| {
        let mut cur = cell.borrow_mut();
        match cur.as_ref() {
            Some(f) if f.dpi == dpi => f.clone(),
            _ => {
                let f = Rc::new(Fonts::new(dpi));
                *cur = Some(f.clone());
                f
            }
        }
    })
}

/// Double-buffered painting of a whole client area.
struct Painter {
    hwnd: HWND,
    ps: PAINTSTRUCT,
    screen: HDC,
    dc: HDC,
    bmp: HBITMAP,
    old: HGDIOBJ,
    w: i32,
    h: i32,
}

impl Painter {
    fn begin(hwnd: HWND) -> Painter {
        unsafe {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let screen = BeginPaint(hwnd, &mut ps);
            let (w, h) = client_size(hwnd);
            let dc = CreateCompatibleDC(screen);
            let bmp = CreateCompatibleBitmap(screen, w.max(1), h.max(1));
            let old = SelectObject(dc, bmp);
            SetBkMode(dc, TRANSPARENT as i32);
            Painter { hwnd, ps, screen, dc, bmp, old, w, h }
        }
    }
}

impl Drop for Painter {
    fn drop(&mut self) {
        unsafe {
            BitBlt(self.screen, 0, 0, self.w, self.h, self.dc, 0, 0, SRCCOPY);
            SelectObject(self.dc, self.old);
            DeleteObject(self.bmp);
            DeleteDC(self.dc);
            EndPaint(self.hwnd, &self.ps);
        }
    }
}

fn fill_rect(dc: HDC, r: &RECT, color: COLORREF) {
    unsafe {
        let b = CreateSolidBrush(color);
        FillRect(dc, r, b);
        DeleteObject(b);
    }
}

/// Rounded rectangle with corner diameter `d`, optionally outlined.
fn round_rect(dc: HDC, r: &RECT, d: i32, fill: COLORREF, border: Option<COLORREF>) {
    unsafe {
        let brush = CreateSolidBrush(fill);
        let pen = border.map(|c| CreatePen(PS_SOLID, 1, c));
        let old_brush = SelectObject(dc, brush);
        let old_pen = SelectObject(dc, pen.unwrap_or_else(|| GetStockObject(NULL_PEN)));
        // Without a pen RoundRect leaves the right and bottom edge unpainted.
        let e = border.is_none() as i32;
        RoundRect(dc, r.left, r.top, r.right + e, r.bottom + e, d, d);
        SelectObject(dc, old_brush);
        SelectObject(dc, old_pen);
        DeleteObject(brush);
        if let Some(p) = pen {
            DeleteObject(p);
        }
    }
}

fn line(dc: HDC, x0: i32, y0: i32, x1: i32, y1: i32, color: COLORREF) {
    unsafe {
        let pen = CreatePen(PS_SOLID, 1, color);
        let old = SelectObject(dc, pen);
        MoveToEx(dc, x0, y0, null_mut());
        LineTo(dc, x1, y1);
        SelectObject(dc, old);
        DeleteObject(pen);
    }
}

fn draw_text(dc: HDC, font: HFONT, color: COLORREF, s: &str, r: RECT, flags: u32) {
    // DrawTextW reads the buffer even for a zero count: never hand it a dangling pointer.
    if s.is_empty() || r.right <= r.left || r.bottom <= r.top {
        return;
    }
    let w: Vec<u16> = s.encode_utf16().collect();
    let mut r = r;
    unsafe {
        SelectObject(dc, font);
        SetTextColor(dc, color);
        DrawTextW(dc, w.as_ptr(), w.len() as i32, &mut r, flags | DT_NOPREFIX);
    }
}

fn draw_glyph(dc: HDC, font: HFONT, color: COLORREF, glyph: u16, r: RECT) {
    let mut r = r;
    unsafe {
        SelectObject(dc, font);
        SetTextColor(dc, color);
        DrawTextW(dc, &glyph, 1, &mut r, DT_SINGLELINE | DT_CENTER | DT_VCENTER | DT_NOPREFIX);
    }
}

/// Size of `s`: a single line, or wrapped at `wrap` pixels (long words are broken too).
fn text_size(dc: HDC, font: HFONT, s: &str, wrap: Option<i32>) -> (i32, i32) {
    if s.is_empty() {
        return (0, 0);
    }
    let w: Vec<u16> = s.encode_utf16().collect();
    let mut r = RECT { left: 0, top: 0, right: wrap.unwrap_or(0), bottom: 0 };
    let flags = match wrap {
        Some(_) => DT_CALCRECT | DT_WORDBREAK | DT_EDITCONTROL | DT_NOPREFIX,
        None => DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX,
    };
    unsafe {
        SelectObject(dc, font);
        DrawTextW(dc, w.as_ptr(), w.len() as i32, &mut r, flags);
    }
    (r.right - r.left, r.bottom - r.top)
}

/// Runs `f` with a DC suitable for measuring text in `hwnd`.
fn with_dc<R>(hwnd: HWND, f: impl FnOnce(HDC) -> R) -> R {
    unsafe {
        let dc = GetDC(hwnd);
        let old = SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
        let r = f(dc);
        SelectObject(dc, old);
        ReleaseDC(hwnd, dc);
        r
    }
}

fn register_classes() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe {
        let hinst = GetModuleHandleW(null());
        for (name, proc) in
            [("SafeRdpBar", bar_proc as unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT), ("SafeRdpPanel", panel_proc)]
        {
            let class = wide(name);
            let wc = WNDCLASSEXW {
                cbSize: size_of::<WNDCLASSEXW>() as u32,
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(proc),
                hInstance: hinst,
                hCursor: LoadCursorW(null_mut(), IDC_ARROW),
                lpszClassName: class.as_ptr(),
                ..std::mem::zeroed()
            };
            RegisterClassExW(&wc);
        }
    });
}

fn create_child(parent: HWND, class: &str) -> Result<HWND> {
    register_classes();
    let class = wide(class);
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_NOPARENTNOTIFY,
            class.as_ptr(),
            null(),
            WS_CHILD | WS_CLIPSIBLINGS,
            0,
            0,
            0,
            0,
            parent,
            null_mut(),
            GetModuleHandleW(null()),
            null(),
        )
    };
    if hwnd.is_null() {
        return Err(Error::last_os("CreateWindowExW(chrome)"));
    }
    Ok(hwnd)
}

/// Window state behind `GWLP_USERDATA`. A `RefCell` turns re-entrant access (a window
/// message arriving while the state is in use) into a skipped message instead of aliasing.
fn attach<T>(hwnd: HWND, state: T) {
    let p = Box::into_raw(Box::new(RefCell::new(state)));
    unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, p as isize) };
}

fn with_state<T, R>(hwnd: HWND, f: impl FnOnce(&mut T) -> R) -> Option<R> {
    let p = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const RefCell<T>;
    if p.is_null() {
        return None;
    }
    // SAFETY: set by `attach` with the same `T` (one type per window class) and freed only
    // on WM_NCDESTROY, after which the pointer is cleared.
    let cell = unsafe { &*p };
    cell.try_borrow_mut().ok().map(|mut s| f(&mut s))
}

fn detach<T>(hwnd: HWND) {
    unsafe {
        let p = SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) as *mut RefCell<T>;
        if !p.is_null() {
            drop(Box::from_raw(p));
        }
    }
}

fn track_leave(hwnd: HWND) {
    let mut t = TRACKMOUSEEVENT { cbSize: size_of::<TRACKMOUSEEVENT>() as u32, dwFlags: TME_LEAVE, hwndTrack: hwnd, dwHoverTime: 0 };
    unsafe { TrackMouseEvent(&mut t) };
}

fn point(lp: LPARAM) -> (i32, i32) {
    ((lp & 0xffff) as i16 as i32, ((lp >> 16) & 0xffff) as i16 as i32)
}

fn inside(r: &RECT, x: i32, y: i32) -> bool {
    x >= r.left && x < r.right && y >= r.top && y < r.bottom
}

/// True if the mouse pointer is over `hwnd`'s window rectangle.
fn pointer_over(hwnd: HWND) -> bool {
    unsafe {
        let mut p = POINT { x: 0, y: 0 };
        let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        GetCursorPos(&mut p) != 0 && GetWindowRect(hwnd, &mut r) != 0 && IsWindowVisible(hwnd) != 0 && inside(&r, p.x, p.y)
    }
}

// ---------------------------------------------------------------------------------------
// Bar model and layout

/// How a feature appears in the bar.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Feature {
    /// The host does not offer it: no button.
    #[default]
    Hidden,
    /// The host reported it unavailable: a disabled button with an explanation.
    Unavailable,
    /// This computer cannot do it (e.g. no audio device): disabled, with an explanation.
    NoLocal,
    /// Available and off (for actions: available).
    Off,
    On,
}

/// Everything the bar shows; the viewer rebuilds it and the bar redraws when it changes.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct BarModel {
    pub host: String,
    /// Link statistics, or the transfer in progress.
    pub status: String,
    /// The same in a few characters ("12 ms", "↑ 45%"), for narrow bars.
    pub status_short: String,
    /// Show `status` as a warning (not responding, reconnecting).
    pub warn: bool,
    /// Transfer progress, 0..=1.
    pub progress: Option<f32>,
    /// False while reconnecting: session features are disabled.
    pub connected: bool,
    pub monitors: Vec<MonitorInfo>,
    pub monitor: u8,
    pub monitor_menu: Feature,
    pub quality: u8,
    pub quality_menu: Feature,
    pub downscale: u8,
    pub scale_menu: Feature,
    pub sas: Feature,
    pub clipboard: Feature,
    pub send_files: Feature,
    pub get_files: Feature,
    pub sound: Feature,
    pub privacy: Feature,
    pub fullscreen: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Item {
    Pin,
    Info,
    Monitor,
    Quality,
    Scale,
    Sas,
    Clipboard,
    SendFiles,
    GetFiles,
    Sound,
    Privacy,
    FullScreen,
    Disconnect,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Info,
    Toggle,
    Menu,
    Action,
}

#[derive(Clone, Debug, PartialEq)]
struct Spec {
    item: Item,
    /// Items of different groups are divided by a separator.
    group: u8,
    kind: Kind,
    glyph: u16,
    label: String,
    enabled: bool,
    on: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Slot {
    item: Item,
    x: i32,
    w: i32,
    label: bool,
}

#[derive(Clone, Debug, PartialEq, Default)]
struct Layout {
    width: i32,
    slots: Vec<Slot>,
    seps: Vec<i32>,
    /// Info block: host name width (0 = hidden) and status width.
    host_w: i32,
    status_w: i32,
    /// Show `BarModel::status_short` instead of `status`.
    short: bool,
    level: u8,
}

fn command(item: Item) -> Option<u16> {
    Some(match item {
        Item::Sas => CMD_SAS,
        Item::Clipboard => CMD_CLIPBOARD,
        Item::SendFiles => CMD_SEND_FILES,
        Item::GetFiles => CMD_GET_FILES,
        Item::Sound => CMD_SOUND,
        Item::Privacy => CMD_PRIVACY,
        Item::FullScreen => CMD_FULLSCREEN,
        Item::Disconnect => CMD_DISCONNECT,
        _ => return None,
    })
}

fn quality_label(q: u8) -> &'static str {
    match q as u32 {
        crate::proto::QUALITY_LOSSLESS => tr(Txt::Lossless),
        crate::proto::QUALITY_BALANCED => tr(Txt::Balanced),
        crate::proto::QUALITY_LOW => tr(Txt::LowBandwidth),
        _ => tr(Txt::Quality),
    }
}

fn scale_label(d: u8) -> String {
    format!("{}%", 100 / d.clamp(1, 4) as u32)
}

fn monitor_label(m: &BarModel) -> String {
    match m.monitor {
        MONITOR_ALL => tr(Txt::AllMonitors).to_string(),
        i if (i as usize) < m.monitors.len() => trf(Txt::MonitorN, &[&(i as u32 + 1)]),
        _ => tr(Txt::Monitor).to_string(),
    }
}

fn specs(m: &BarModel, floating: bool, pinned: bool) -> Vec<Spec> {
    let mut v = Vec::with_capacity(13);
    let spec =
        |item, group, kind, glyph, label: &str, enabled, on| Spec { item, group, kind, glyph, label: label.to_string(), enabled, on };
    if floating {
        v.push(spec(Item::Pin, 0, Kind::Toggle, G_PIN, "", true, pinned));
    }
    v.push(spec(Item::Info, 1, Kind::Info, 0, "", true, false));
    let features = [
        (Item::Monitor, 2, Kind::Menu, G_MONITOR, monitor_label(m), m.monitor_menu),
        (Item::Quality, 2, Kind::Menu, G_QUALITY, quality_label(m.quality).to_string(), m.quality_menu),
        (Item::Scale, 2, Kind::Menu, G_SCALE, scale_label(m.downscale), m.scale_menu),
        (Item::Sas, 3, Kind::Action, G_KEYBOARD, "Ctrl+Alt+Del".to_string(), m.sas),
        (Item::Clipboard, 3, Kind::Toggle, G_CLIPBOARD, tr(Txt::Clipboard).to_string(), m.clipboard),
        (Item::SendFiles, 3, Kind::Action, G_UPLOAD, tr(Txt::SendFiles).to_string(), m.send_files),
        (Item::GetFiles, 3, Kind::Action, G_DOWNLOAD, tr(Txt::GetFiles).to_string(), m.get_files),
        (Item::Sound, 3, Kind::Toggle, if m.sound == Feature::On { G_SOUND } else { G_MUTE }, tr(Txt::Sound).to_string(), m.sound),
        (Item::Privacy, 3, Kind::Toggle, G_PRIVACY, tr(Txt::Privacy).to_string(), m.privacy),
    ];
    for (item, group, kind, glyph, label, f) in features {
        if f != Feature::Hidden {
            let enabled = m.connected && matches!(f, Feature::Off | Feature::On);
            v.push(spec(item, group, kind, glyph, &label, enabled, f == Feature::On));
        }
    }
    let (glyph, label) = if m.fullscreen { (G_UNFULL, Txt::ExitFullScreen) } else { (G_FULL, Txt::FullScreen) };
    v.push(spec(Item::FullScreen, 4, Kind::Action, glyph, tr(label), true, false));
    v.push(spec(Item::Disconnect, 4, Kind::Action, G_CLOSE, tr(Txt::Disconnect), true, false));
    v
}

/// Lays the items out at detail `level`: 0 = every label, 1 = labels on menus and
/// Disconnect only, 2 = icons only, 3 = no host name, 4 = short status, 5 = no info block.
/// `measure(bold, text)` returns a text width in pixels.
fn layout_level(specs: &[Spec], level: u8, m: Metrics, icons: bool, host: &str, measure: &dyn Fn(bool, &str) -> i32) -> Layout {
    let mut l = Layout { level, ..Layout::default() };
    let mut x = m.px(6);
    let mut prev = None;
    for sp in specs {
        if sp.item == Item::Info && level >= 5 {
            continue;
        }
        match prev {
            Some(g) if g != sp.group => {
                l.seps.push(x + m.px(6));
                x += m.px(13);
            }
            Some(_) => x += m.px(2),
            None => {}
        }
        prev = Some(sp.group);
        let (w, label) = if sp.kind == Kind::Info {
            l.host_w = if level <= 2 && !host.is_empty() { measure(true, host).min(m.px(200)) } else { 0 };
            l.short = level >= 4;
            l.status_w = measure(false, if l.short { STATUS_SHORT_SAMPLE } else { STATUS_SAMPLE });
            let host = if l.host_w > 0 { l.host_w + m.px(10) } else { 0 };
            (m.px(10) * 2 + host + l.status_w, false)
        } else {
            let label =
                !sp.label.is_empty() && (!icons || level == 0 || (level == 1 && (sp.kind == Kind::Menu || sp.item == Item::Disconnect)));
            let mut w = m.px(8) * 2 + if icons { m.px(16) } else { 0 };
            if label {
                w += measure(false, &sp.label) + if icons { m.px(6) } else { 0 };
            }
            if sp.kind == Kind::Menu {
                w += m.px(12);
            }
            (w, label)
        };
        l.slots.push(Slot { item: sp.item, x, w, label });
        x += w;
    }
    l.width = x + m.px(6);
    l
}

/// The most detailed layout that fits in `avail` pixels.
fn choose_layout(specs: &[Spec], avail: i32, m: Metrics, icons: bool, host: &str, measure: &dyn Fn(bool, &str) -> i32) -> Layout {
    let mut l = Layout::default();
    for level in 0..6 {
        l = layout_level(specs, level, m, icons, host, measure);
        if l.width <= avail {
            break;
        }
    }
    l
}

/// One entry of a popup menu; `id == 0` is a separator.
#[derive(Clone, Debug, PartialEq)]
struct MenuEntry {
    id: u16,
    text: String,
    checked: bool,
}

fn menu_entries(m: &BarModel, item: Item) -> Vec<MenuEntry> {
    let entry = |id: u16, text: String, checked: bool| MenuEntry { id, text, checked };
    match item {
        Item::Monitor => {
            let mut v: Vec<MenuEntry> = m
                .monitors
                .iter()
                .take(32)
                .enumerate()
                .map(|(i, mon)| {
                    let mut text = format!("{} – {} × {}", trf(Txt::MonitorN, &[&(i + 1)]), mon.width, mon.height);
                    if i == 0 {
                        text.push_str(&format!(" ({})", tr(Txt::Primary)));
                    }
                    entry(CMD_MONITOR + i as u16, text, m.monitor as usize == i)
                })
                .collect();
            v.push(entry(0, String::new(), false));
            v.push(entry(CMD_MONITOR + MONITOR_ALL as u16, tr(Txt::AllMonitors).to_string(), m.monitor == MONITOR_ALL));
            v
        }
        Item::Quality => [
            (Txt::LosslessMenu, crate::proto::QUALITY_LOSSLESS),
            (Txt::BalancedMenu, crate::proto::QUALITY_BALANCED),
            (Txt::LowBandwidthMenu, crate::proto::QUALITY_LOW),
        ]
        .into_iter()
        .map(|(t, q)| entry(CMD_QUALITY + q as u16, tr(t).to_string(), m.quality as u32 == q))
        .collect(),
        Item::Scale => {
            let mut v = vec![entry(CMD_SCALE + 1, format!("100% – {}", tr(Txt::ScaleFull)), m.downscale <= 1)];
            let mut factors = vec![2u8, 3];
            if m.downscale == 4 {
                factors.push(4);
            }
            v.extend(factors.into_iter().map(|d| entry(CMD_SCALE + d as u16, scale_label(d), m.downscale == d)));
            v
        }
        _ => Vec::new(),
    }
}

/// Hover hint for `item`: title and explanation.
fn hint_text(m: &BarModel, item: Item, pinned: bool) -> (String, String) {
    let state = |label: &str, f: Feature| format!("{label}: {}", tr(if f == Feature::On { Txt::On } else { Txt::Off }));
    let (title, body, feature) = match item {
        Item::Pin => (tr(if pinned { Txt::UnpinHint } else { Txt::PinHint }).to_string(), String::new(), Feature::Off),
        Item::Info => (m.host.clone(), tr(Txt::InfoHint).to_string(), Feature::Off),
        Item::Monitor => (format!("{}: {}", tr(Txt::Monitor), monitor_label(m)), tr(Txt::MonitorHint).to_string(), m.monitor_menu),
        Item::Quality => (format!("{}: {}", tr(Txt::Quality), quality_label(m.quality)), tr(Txt::QualityHint).to_string(), m.quality_menu),
        Item::Scale => (format!("{}: {}", tr(Txt::Scale), scale_label(m.downscale)), tr(Txt::ScaleHint).to_string(), m.scale_menu),
        Item::Sas => ("Ctrl+Alt+Del".to_string(), tr(Txt::SasHint).to_string(), m.sas),
        Item::Clipboard => (state(tr(Txt::Clipboard), m.clipboard), tr(Txt::ClipboardHint).to_string(), m.clipboard),
        Item::SendFiles => (tr(Txt::SendFiles).to_string(), tr(Txt::SendFilesHint).to_string(), m.send_files),
        Item::GetFiles => (tr(Txt::GetFiles).to_string(), tr(Txt::GetFilesHint).to_string(), m.get_files),
        Item::Sound => (state(tr(Txt::Sound), m.sound), tr(Txt::SoundHint).to_string(), m.sound),
        Item::Privacy => (state(tr(Txt::Privacy), m.privacy), tr(Txt::PrivacyHint).to_string(), m.privacy),
        Item::FullScreen => (
            tr(if m.fullscreen { Txt::ExitFullScreen } else { Txt::FullScreen }).to_string(),
            tr(Txt::FullScreenHint).to_string(),
            Feature::Off,
        ),
        Item::Disconnect => (tr(Txt::Disconnect).to_string(), tr(Txt::DisconnectHint).to_string(), Feature::Off),
    };
    let session_item = !matches!(item, Item::Pin | Item::Info | Item::FullScreen | Item::Disconnect);
    let why = match feature {
        Feature::Unavailable => Some(Txt::NotOnHost),
        Feature::NoLocal => Some(Txt::NotOnThisPc),
        _ if session_item && !m.connected => Some(Txt::WhileReconnecting),
        _ => None,
    };
    let body = match why {
        Some(w) if body.is_empty() => tr(w).to_string(),
        Some(w) => format!("{body}\n{}", tr(w)),
        None => body,
    };
    (title, body)
}

// ---------------------------------------------------------------------------------------
// Bar window

const T_ANIM: usize = 1;
const T_HIDE: usize = 2;
const T_HINT: usize = 3;

/// The connection bar. The window (and its state) is destroyed with its parent.
pub struct Bar {
    hwnd: HWND,
}

struct BarState {
    parent: HWND,
    model: BarModel,
    floating: bool,
    pinned: bool,
    /// Never auto-hide (e.g. while reconnecting).
    keep: bool,
    menu_open: bool,
    /// Slide target: shown or hidden (floating only).
    show: bool,
    /// Vertical position in the parent: 0 = fully shown, -height = hidden.
    offset: i32,
    x: i32,
    specs: Vec<Spec>,
    layout: Layout,
    /// x of the layout inside the bar (centred when docked).
    origin: i32,
    hover: Option<Item>,
    pressed: Option<Item>,
    tracking: bool,
    hint: Option<HWND>,
}

impl Bar {
    pub fn create(parent: HWND) -> Result<Bar> {
        let hwnd = create_child(parent, "SafeRdpBar")?;
        attach(
            hwnd,
            BarState {
                parent,
                model: BarModel::default(),
                floating: false,
                pinned: false,
                keep: false,
                menu_open: false,
                show: true,
                offset: 0,
                x: 0,
                specs: Vec::new(),
                layout: Layout::default(),
                origin: 0,
                hover: None,
                pressed: None,
                tracking: false,
                hint: None,
            },
        );
        let bar = Bar { hwnd };
        bar.relayout();
        Ok(bar)
    }

    fn with<R>(&self, f: impl FnOnce(&mut BarState) -> R) -> Option<R> {
        with_state(self.hwnd, f)
    }

    /// Bar height at the current DPI.
    pub fn height(&self) -> i32 {
        scale(BAR_HEIGHT, dpi_of(self.hwnd))
    }

    /// Height the bar takes from the top of the window (0 while floating).
    pub fn docked_height(&self) -> i32 {
        if self.with(|s| s.floating).unwrap_or(false) { 0 } else { self.height() }
    }

    pub fn set_model(&self, model: &BarModel) {
        let hwnd = self.hwnd;
        self.with(|s| {
            if s.model != *model {
                let relayout = specs(model, s.floating, s.pinned) != s.specs || s.model.host != model.host;
                s.model = model.clone();
                if relayout {
                    place(hwnd, s);
                }
                unsafe { InvalidateRect(hwnd, null(), 0) };
            }
        });
    }

    /// Floating (full screen: slides in from the top edge) or docked (window).
    pub fn set_floating(&self, floating: bool) {
        let hwnd = self.hwnd;
        let h = self.height();
        self.with(|s| {
            if s.floating == floating {
                return;
            }
            s.floating = floating;
            s.show = !floating;
            s.offset = if floating { -h } else { 0 };
            hide_hint(s);
            unsafe {
                KillTimer(hwnd, T_ANIM);
                KillTimer(hwnd, T_HIDE);
            }
            place(hwnd, s);
        });
    }

    /// Re-measures and re-positions after the parent was resized or its DPI changed.
    pub fn relayout(&self) {
        let hwnd = self.hwnd;
        self.with(|s| place(hwnd, s));
    }

    /// Floating: slide in and hide again after `hold_ms` unless pinned or hovered.
    pub fn reveal(&self, hold_ms: u32) {
        let hwnd = self.hwnd;
        self.with(|s| {
            if !s.floating {
                return;
            }
            if !s.show {
                s.show = true;
                place(hwnd, s);
                unsafe { SetTimer(hwnd, T_ANIM, 15, None) };
            }
            arm_hide(hwnd, s, hold_ms);
        });
    }

    /// Keeps the bar on screen (and floating bars revealed) while `keep` is set.
    pub fn set_keep_visible(&self, keep: bool) {
        let changed = self.with(|s| std::mem::replace(&mut s.keep, keep) != keep).unwrap_or(false);
        if changed {
            if keep {
                self.reveal(0);
            } else {
                let hwnd = self.hwnd;
                self.with(|s| arm_hide(hwnd, s, 2000));
            }
        }
    }

    /// True if a pointer at `(x, y)` in parent coordinates should reveal the floating bar:
    /// it touches the top edge near the bar.
    pub fn in_reveal_zone(&self, x: i32, y: i32) -> bool {
        let m = Metrics(dpi_of(self.hwnd));
        self.with(|s| s.floating && !s.show && y <= m.px(1) && x >= s.x - m.px(80) && x < s.x + s.layout.width + m.px(80)).unwrap_or(false)
    }
}

/// Measures and positions the bar for the current parent size, mode and model.
fn place(hwnd: HWND, s: &mut BarState) {
    let dpi = dpi_of(hwnd);
    let m = Metrics(dpi);
    let h = m.px(BAR_HEIGHT);
    let (pw, _) = client_size(s.parent);
    let f = fonts(dpi);
    s.specs = specs(&s.model, s.floating, s.pinned);
    let avail = if s.floating { pw - m.px(48) } else { pw };
    s.layout = with_dc(hwnd, |dc| {
        let measure = |bold: bool, t: &str| text_size(dc, if bold { f.bold } else { f.text }, t, None).0;
        choose_layout(&s.specs, avail, m, f.icons, &s.model.host, &measure)
    });
    unsafe {
        if s.floating {
            let w = s.layout.width.min(pw).max(1);
            s.origin = 0;
            s.x = (pw - w) / 2;
            let visible = s.show || s.offset > -h;
            let flags = SWP_NOACTIVATE | if visible { SWP_SHOWWINDOW } else { SWP_HIDEWINDOW };
            SetWindowPos(hwnd, HWND_TOP, s.x, s.offset, w, h, flags);
            let d = m.px(14);
            SetWindowRgn(hwnd, CreateRoundRectRgn(0, -d, w + 1, h + 1, d, d), 0);
        } else {
            s.offset = 0;
            s.x = 0;
            s.origin = ((pw - s.layout.width) / 2).max(0);
            SetWindowRgn(hwnd, null_mut(), 0);
            SetWindowPos(hwnd, HWND_TOP, 0, 0, pw.max(1), h, SWP_NOACTIVATE | SWP_SHOWWINDOW);
        }
        InvalidateRect(hwnd, null(), 0);
    }
}

fn arm_hide(hwnd: HWND, s: &BarState, ms: u32) {
    unsafe {
        KillTimer(hwnd, T_HIDE);
        if s.floating && !s.pinned && !s.keep && !s.menu_open {
            SetTimer(hwnd, T_HIDE, ms.max(500), None);
        }
    }
}

fn animate(hwnd: HWND, s: &mut BarState) {
    let h = scale(BAR_HEIGHT, dpi_of(hwnd));
    let step = (h / 4).max(1);
    let target = if s.show { 0 } else { -h };
    s.offset = if s.offset < target { (s.offset + step).min(target) } else { (s.offset - step).max(target) };
    unsafe {
        SetWindowPos(hwnd, null_mut(), s.x, s.offset, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        if s.offset == target {
            KillTimer(hwnd, T_ANIM);
            if !s.show {
                ShowWindow(hwnd, SW_HIDE);
            }
        }
    }
}

fn slot_at(s: &BarState, x: i32) -> Option<Item> {
    s.layout.slots.iter().find(|sl| x >= s.origin + sl.x && x < s.origin + sl.x + sl.w).map(|sl| sl.item)
}

fn spec_of(s: &BarState, item: Item) -> Option<&Spec> {
    s.specs.iter().find(|sp| sp.item == item)
}

fn hide_hint(s: &mut BarState) {
    if let Some(h) = s.hint.take() {
        unsafe { DestroyWindow(h) };
    }
}

fn show_hint(hwnd: HWND, s: &mut BarState) {
    hide_hint(s);
    let Some(item) = s.hover else { return };
    let Some(slot) = s.layout.slots.iter().find(|sl| sl.item == item).copied() else { return };
    let (title, body) = hint_text(&s.model, item, s.pinned);
    let Some(h) = create_panel(s.parent, PanelKind::Hint, None, &title, &body, None) else { return };
    let m = Metrics(dpi_of(hwnd));
    let (w, ph) = panel_size(h);
    let (pw, _) = client_size(s.parent);
    let x = (s.x + s.origin + slot.x).min(pw - w - m.px(4)).max(m.px(4));
    let y = s.offset + m.px(BAR_HEIGHT) + m.px(6);
    unsafe { SetWindowPos(h, HWND_TOP, x, y, w, ph, SWP_NOACTIVATE | SWP_SHOWWINDOW) };
    s.hint = Some(h);
}

fn paint_bar(hwnd: HWND, s: &BarState) {
    let p = Painter::begin(hwnd);
    let dc = p.dc;
    let dpi = dpi_of(hwnd);
    let m = Metrics(dpi);
    let f = fonts(dpi);
    let (w, h) = (p.w, p.h);
    fill_rect(dc, &RECT { left: 0, top: 0, right: w, bottom: h }, BG);
    if s.floating {
        let d = m.px(14);
        round_rect(dc, &RECT { left: 0, top: -d, right: w, bottom: h }, d, BG, Some(BORDER));
    } else {
        line(dc, 0, h - 1, w, h - 1, BORDER);
    }
    for slot in &s.layout.slots {
        let Some(sp) = spec_of(s, slot.item) else { continue };
        let x = s.origin + slot.x;
        if sp.kind == Kind::Info {
            let mut tx = x + m.px(10);
            if s.layout.host_w > 0 {
                let r = RECT { left: tx, top: 0, right: tx + s.layout.host_w, bottom: h };
                draw_text(dc, f.bold, FG, &s.model.host, r, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
                tx += s.layout.host_w + m.px(10);
            }
            let r = RECT { left: tx, top: 0, right: tx + s.layout.status_w, bottom: h };
            let status = if s.layout.short { &s.model.status_short } else { &s.model.status };
            draw_text(dc, f.text, if s.model.warn { WARN } else { FG_DIM }, status, r, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
            continue;
        }
        let r = RECT { left: x, top: m.px(4), right: x + slot.w, bottom: h - m.px(4) };
        let hover = s.hover == Some(sp.item) && sp.enabled;
        let pressed = hover && s.pressed == Some(sp.item);
        let bg = if sp.on {
            Some(if !sp.enabled {
                ACCENT_OFF
            } else if hover {
                ACCENT_HOVER
            } else {
                ACCENT
            })
        } else if pressed {
            Some(PRESSED)
        } else if hover && sp.item == Item::Disconnect {
            Some(DANGER)
        } else if hover {
            Some(HOVER)
        } else {
            None
        };
        if let Some(c) = bg {
            round_rect(dc, &r, m.px(8), c, None);
        }
        let fg = if sp.enabled { FG } else { FG_DISABLED };
        let mut cx = x + m.px(8);
        if f.icons {
            draw_glyph(dc, f.icon, fg, sp.glyph, RECT { left: cx, top: 0, right: cx + m.px(16), bottom: h });
            cx += m.px(16) + m.px(6);
        }
        if slot.label {
            let right = x + slot.w - m.px(8) - if sp.kind == Kind::Menu { m.px(12) } else { 0 };
            draw_text(dc, f.text, fg, &sp.label, RECT { left: cx, top: 0, right, bottom: h }, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
        }
        if sp.kind == Kind::Menu && f.icons {
            let right = x + slot.w - m.px(6);
            draw_glyph(
                dc,
                f.small_icon,
                if sp.enabled { FG_DIM } else { FG_DISABLED },
                G_CHEVRON,
                RECT { left: right - m.px(12), top: 0, right, bottom: h },
            );
        }
    }
    for &sx in &s.layout.seps {
        let x = s.origin + sx;
        line(dc, x, m.px(9), x, h - m.px(9), BORDER);
    }
    if let Some(frac) = s.model.progress {
        let pw = (w as f32 * frac.clamp(0.0, 1.0)) as i32;
        fill_rect(dc, &RECT { left: 0, top: h - m.px(3), right: pw, bottom: h - 1 }, INFO);
    }
}

/// Opens the popup menu of a menu button and forwards the choice to the parent.
fn open_menu(hwnd: HWND, item: Item) {
    let Some((parent, entries, anchor)) = with_state(hwnd, |s: &mut BarState| {
        s.menu_open = true;
        hide_hint(s);
        unsafe { KillTimer(hwnd, T_HIDE) };
        let slot = s.layout.slots.iter().find(|sl| sl.item == item).copied();
        let mut pt = POINT { x: s.origin + slot.map_or(0, |sl| sl.x), y: scale(BAR_HEIGHT, dpi_of(hwnd)) };
        unsafe { ClientToScreen(hwnd, &mut pt) };
        (s.parent, menu_entries(&s.model, item), pt)
    }) else {
        return;
    };
    let cmd = unsafe {
        let menu = CreatePopupMenu();
        if menu.is_null() {
            0
        } else {
            for e in &entries {
                if e.id == 0 {
                    AppendMenuW(menu, MF_SEPARATOR, 0, null());
                } else {
                    AppendMenuW(menu, MF_STRING, e.id as usize, wide(&e.text).as_ptr());
                }
            }
            let ids = entries.iter().filter(|e| e.id != 0).map(|e| e.id as u32);
            let (first, last) = (ids.clone().min().unwrap_or(0), ids.max().unwrap_or(0));
            if let Some(c) = entries.iter().find(|e| e.checked) {
                CheckMenuRadioItem(menu, first, last, c.id as u32, MF_BYCOMMAND);
            }
            let r =
                TrackPopupMenu(menu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN | TPM_LEFTBUTTON, anchor.x, anchor.y, 0, parent, null());
            DestroyMenu(menu);
            r
        }
    };
    with_state(hwnd, |s: &mut BarState| {
        s.menu_open = false;
        s.pressed = None;
        if !pointer_over(hwnd) {
            s.hover = None;
            arm_hide(hwnd, s, 1500);
        }
        unsafe { InvalidateRect(hwnd, null(), 0) };
    });
    if cmd > 0 && cmd <= u16::MAX as i32 {
        unsafe { PostMessageW(parent, WM_COMMAND, cmd as usize, 0) };
    }
}

fn activate(hwnd: HWND, item: Item) {
    match item {
        Item::Pin => {
            with_state(hwnd, |s: &mut BarState| {
                s.pinned = !s.pinned;
                hide_hint(s);
                place(hwnd, s);
                arm_hide(hwnd, s, 2000);
            });
        }
        Item::Monitor | Item::Quality | Item::Scale => open_menu(hwnd, item),
        Item::Info => {}
        other => {
            if let (Some(cmd), Some(parent)) = (command(other), with_state(hwnd, |s: &mut BarState| s.parent)) {
                unsafe { PostMessageW(parent, WM_COMMAND, cmd as usize, 0) };
            }
        }
    }
}

unsafe extern "system" fn bar_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_PAINT => {
                if with_state(hwnd, |s: &mut BarState| paint_bar(hwnd, s)).is_none() {
                    // Busy (re-entered): validate anyway and repaint later.
                    let mut ps: PAINTSTRUCT = std::mem::zeroed();
                    BeginPaint(hwnd, &mut ps);
                    EndPaint(hwnd, &ps);
                    InvalidateRect(hwnd, null(), 0);
                }
                0
            }
            WM_ERASEBKGND => 1,
            WM_MOUSEMOVE => {
                let (x, _) = point(lp);
                with_state(hwnd, |s: &mut BarState| {
                    if !s.tracking {
                        track_leave(hwnd);
                        s.tracking = true;
                    }
                    KillTimer(hwnd, T_HIDE);
                    let hit = slot_at(s, x);
                    if hit != s.hover {
                        s.hover = hit;
                        hide_hint(s);
                        KillTimer(hwnd, T_HINT);
                        if hit.is_some() && !s.menu_open {
                            SetTimer(hwnd, T_HINT, 450, None);
                        }
                        InvalidateRect(hwnd, null(), 0);
                    }
                });
                0
            }
            WM_MOUSELEAVE => {
                with_state(hwnd, |s: &mut BarState| {
                    s.tracking = false;
                    s.hover = None;
                    hide_hint(s);
                    KillTimer(hwnd, T_HINT);
                    arm_hide(hwnd, s, 2000);
                    InvalidateRect(hwnd, null(), 0);
                });
                0
            }
            WM_LBUTTONDOWN | WM_LBUTTONDBLCLK => {
                let (x, _) = point(lp);
                with_state(hwnd, |s: &mut BarState| {
                    s.pressed = slot_at(s, x).filter(|&i| spec_of(s, i).is_some_and(|sp| sp.enabled && sp.kind != Kind::Info));
                    hide_hint(s);
                    KillTimer(hwnd, T_HINT);
                    InvalidateRect(hwnd, null(), 0);
                });
                SetCapture(hwnd);
                0
            }
            WM_LBUTTONUP => {
                let (x, _) = point(lp);
                let item = with_state(hwnd, |s: &mut BarState| {
                    let pressed = s.pressed.take();
                    InvalidateRect(hwnd, null(), 0);
                    pressed.filter(|&p| slot_at(s, x) == Some(p))
                })
                .flatten();
                ReleaseCapture();
                if let Some(item) = item {
                    activate(hwnd, item);
                }
                0
            }
            WM_TIMER => {
                match wp {
                    T_ANIM => {
                        with_state(hwnd, |s: &mut BarState| animate(hwnd, s));
                    }
                    T_HIDE => {
                        KillTimer(hwnd, T_HIDE);
                        with_state(hwnd, |s: &mut BarState| {
                            if !s.floating || s.pinned || s.keep || s.menu_open {
                                return;
                            }
                            if pointer_over(hwnd) {
                                SetTimer(hwnd, T_HIDE, 1000, None);
                            } else {
                                s.show = false;
                                hide_hint(s);
                                SetTimer(hwnd, T_ANIM, 15, None);
                            }
                        });
                    }
                    T_HINT => {
                        KillTimer(hwnd, T_HINT);
                        with_state(hwnd, |s: &mut BarState| show_hint(hwnd, s));
                    }
                    _ => {}
                }
                0
            }
            WM_MOUSEWHEEL | WM_MOUSEHWHEEL => 0,
            WM_NCDESTROY => {
                with_state(hwnd, |s: &mut BarState| hide_hint(s));
                detach::<BarState>(hwnd);
                DefWindowProcW(hwnd, msg, wp, lp)
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Panels: hints, toasts and the status overlay

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tone {
    Info,
    Success,
    Warning,
    Error,
}

/// What a toast's button does.
#[derive(Clone, Debug, PartialEq)]
pub enum ToastAction {
    /// Show this folder in Explorer (never opens a file).
    OpenFolder(PathBuf),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PanelKind {
    Hint,
    Toast,
    Overlay,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Part {
    Action,
    Close,
}

const T_EXPIRE: usize = 1;
const MAX_TOASTS: usize = 4;
/// Toast and overlay text is cut to this many lines and characters before it is shown...
const MAX_TITLE_LINES: usize = 2;
const MAX_TITLE_CHARS: usize = 160;
const MAX_TEXT_LINES: usize = 6;
const MAX_TEXT_CHARS: usize = 400;
/// ...and its wrapped height to this many lines (fewer in a small window).
const MAX_TITLE_ROWS: i32 = 3;
const MAX_TEXT_ROWS: i32 = 8;

struct PanelState {
    kind: PanelKind,
    parent: HWND,
    tone: Option<Tone>,
    title: String,
    text: String,
    action: Option<ToastAction>,
    w: i32,
    h: i32,
    icon_rc: RECT,
    title_rc: RECT,
    text_rc: RECT,
    action_rc: Option<RECT>,
    close_rc: Option<RECT>,
    hover: Option<Part>,
    pressed: Option<Part>,
    tracking: bool,
}

fn empty_rect() -> RECT {
    RECT { left: 0, top: 0, right: 0, bottom: 0 }
}

fn tone_glyph(kind: PanelKind, tone: Option<Tone>) -> Option<(u16, COLORREF)> {
    if kind == PanelKind::Overlay {
        return Some((G_SYNC, WARN));
    }
    tone.map(|t| match t {
        Tone::Info => (G_INFO, INFO),
        Tone::Success => (G_CHECK, GOOD),
        Tone::Warning => (G_WARN, WARN),
        Tone::Error => (G_ERROR, BAD),
    })
}

fn action_label(a: &ToastAction) -> &'static str {
    match a {
        ToastAction::OpenFolder(_) => tr(Txt::OpenFolder),
    }
}

/// Computes the panel's size and part rectangles for its text, then sizes the window.
fn layout_panel(hwnd: HWND, s: &mut PanelState) {
    let dpi = dpi_of(hwnd);
    let m = Metrics(dpi);
    let f = fonts(dpi);
    let pad = m.px(if s.kind == PanelKind::Hint { 8 } else { 12 });
    let max_w = m.px(match s.kind {
        PanelKind::Hint => 320,
        PanelKind::Toast => 420,
        PanelKind::Overlay => 480,
    });
    let icon = if tone_glyph(s.kind, s.tone).is_some() && f.icons { m.px(20) } else { 0 };
    let left = pad + if icon > 0 { icon + m.px(10) } else { 0 };
    let close = if s.kind == PanelKind::Toast { m.px(28) } else { 0 };
    let wrap = (max_w - left - pad - close).max(m.px(80));
    let (tw, mut th, bw, mut bh, aw, rows) = with_dc(hwnd, |dc| {
        let (tw, th) = text_size(dc, f.bold, &s.title, Some(wrap));
        let (bw, bh) = text_size(dc, f.text, &s.text, Some(wrap));
        let aw = s.action.as_ref().map_or(0, |a| text_size(dc, f.text, action_label(a), None).0 + m.px(24));
        let rows = (text_size(dc, f.bold, "Ag", None).1.max(1), text_size(dc, f.text, "Ag", None).1.max(1));
        (tw.min(wrap), th, bw.min(wrap), bh, aw, rows)
    });
    if s.kind != PanelKind::Hint {
        // Whole lines only: DT_EDITCONTROL leaves out a partly visible last line.
        let (_, ph) = client_size(s.parent);
        th = th.min(rows.0 * MAX_TITLE_ROWS);
        bh = bh.min(rows.1 * (ph / 3 / rows.1).clamp(2, MAX_TEXT_ROWS));
    }
    let content = tw.max(bw).max(aw).max(if s.kind == PanelKind::Hint { 0 } else { m.px(160) });
    let mut y = pad;
    s.title_rc = RECT { left, top: y, right: left + content, bottom: y + th };
    y += th;
    if bh > 0 {
        if th > 0 {
            y += m.px(2);
        }
        s.text_rc = RECT { left, top: y, right: left + content, bottom: y + bh };
        y += bh;
    } else {
        s.text_rc = empty_rect();
    }
    s.action_rc = s.action.as_ref().map(|_| {
        y += m.px(10);
        let r = RECT { left: left + content - aw, top: y, right: left + content, bottom: y + m.px(28) };
        y += m.px(28);
        r
    });
    s.w = left + content + close + pad;
    s.h = (y + pad).max(pad * 2 + icon);
    s.icon_rc = RECT { left: pad, top: pad, right: pad + icon, bottom: pad + m.px(20) };
    s.close_rc = (close > 0).then(|| RECT { left: s.w - m.px(6) - m.px(24), top: m.px(6), right: s.w - m.px(6), bottom: m.px(30) });
    let d = m.px(12);
    unsafe {
        SetWindowPos(hwnd, null_mut(), 0, 0, s.w, s.h, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        SetWindowRgn(hwnd, CreateRoundRectRgn(0, 0, s.w + 1, s.h + 1, d, d), 0);
        InvalidateRect(hwnd, null(), 0);
    }
}

/// Creates a hidden panel; the caller positions and shows it.
fn create_panel(parent: HWND, kind: PanelKind, tone: Option<Tone>, title: &str, text: &str, action: Option<ToastAction>) -> Option<HWND> {
    let hwnd = match create_child(parent, "SafeRdpPanel") {
        Ok(h) => h,
        Err(e) => {
            crate::log!("{e}");
            return None;
        }
    };
    attach(
        hwnd,
        PanelState {
            kind,
            parent,
            tone,
            title: title.to_string(),
            text: text.to_string(),
            action,
            w: 0,
            h: 0,
            icon_rc: empty_rect(),
            title_rc: empty_rect(),
            text_rc: empty_rect(),
            action_rc: None,
            close_rc: None,
            hover: None,
            pressed: None,
            tracking: false,
        },
    );
    with_state(hwnd, |s: &mut PanelState| layout_panel(hwnd, s));
    Some(hwnd)
}

fn panel_size(hwnd: HWND) -> (i32, i32) {
    with_state(hwnd, |s: &mut PanelState| (s.w, s.h)).unwrap_or((0, 0))
}

fn paint_panel(hwnd: HWND, s: &PanelState) {
    let p = Painter::begin(hwnd);
    let dc = p.dc;
    let dpi = dpi_of(hwnd);
    let m = Metrics(dpi);
    let f = fonts(dpi);
    fill_rect(dc, &RECT { left: 0, top: 0, right: p.w, bottom: p.h }, BG_PANEL);
    round_rect(dc, &RECT { left: 0, top: 0, right: p.w, bottom: p.h }, m.px(12), BG_PANEL, Some(BORDER));
    if let (Some((glyph, color)), true) = (tone_glyph(s.kind, s.tone), f.icons) {
        draw_glyph(dc, f.icon, color, glyph, s.icon_rc);
    }
    let wrap = DT_WORDBREAK | DT_EDITCONTROL;
    draw_text(dc, f.bold, FG, &s.title, s.title_rc, wrap);
    draw_text(dc, f.text, FG_DIM, &s.text, s.text_rc, wrap);
    if let (Some(r), Some(a)) = (s.action_rc, s.action.as_ref()) {
        round_rect(dc, &r, m.px(8), if s.hover == Some(Part::Action) { ACCENT_HOVER } else { ACCENT }, None);
        draw_text(dc, f.text, FG, action_label(a), r, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
    }
    if let Some(r) = s.close_rc {
        if s.hover == Some(Part::Close) {
            round_rect(dc, &r, m.px(6), HOVER, None);
        }
        if f.icons {
            draw_glyph(dc, f.small_icon, FG_DIM, G_CLOSE, r);
        } else {
            draw_text(dc, f.text, FG_DIM, "×", r, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
        }
    }
}

fn part_at(s: &PanelState, x: i32, y: i32) -> Option<Part> {
    if s.action_rc.is_some_and(|r| inside(&r, x, y)) {
        Some(Part::Action)
    } else if s.close_rc.is_some_and(|r| inside(&r, x, y)) {
        Some(Part::Close)
    } else {
        None
    }
}

fn close_toast(hwnd: HWND) {
    let parent = with_state(hwnd, |s: &mut PanelState| s.parent);
    unsafe {
        DestroyWindow(hwnd);
        if let Some(p) = parent {
            PostMessageW(p, WM_CHROME, 0, 0);
        }
    }
}

fn run_action(a: &ToastAction) {
    match a {
        ToastAction::OpenFolder(dir) => {
            let (verb, path) = (wide("explore"), wide(&dir.to_string_lossy()));
            let r = unsafe { ShellExecuteW(null_mut(), verb.as_ptr(), path.as_ptr(), null(), null(), SW_SHOWNORMAL) };
            if (r as isize) <= 32 {
                crate::log!("could not open {}", dir.display());
            }
        }
    }
}

unsafe extern "system" fn panel_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_PAINT => {
                if with_state(hwnd, |s: &mut PanelState| paint_panel(hwnd, s)).is_none() {
                    let mut ps: PAINTSTRUCT = std::mem::zeroed();
                    BeginPaint(hwnd, &mut ps);
                    EndPaint(hwnd, &ps);
                    InvalidateRect(hwnd, null(), 0);
                }
                0
            }
            WM_ERASEBKGND => 1,
            WM_MOUSEMOVE => {
                let (x, y) = point(lp);
                with_state(hwnd, |s: &mut PanelState| {
                    if !s.tracking {
                        track_leave(hwnd);
                        s.tracking = true;
                    }
                    let hit = part_at(s, x, y);
                    if hit != s.hover {
                        s.hover = hit;
                        InvalidateRect(hwnd, null(), 0);
                    }
                });
                0
            }
            WM_MOUSELEAVE => {
                with_state(hwnd, |s: &mut PanelState| {
                    s.tracking = false;
                    s.hover = None;
                    InvalidateRect(hwnd, null(), 0);
                });
                0
            }
            WM_LBUTTONDOWN => {
                let (x, y) = point(lp);
                with_state(hwnd, |s: &mut PanelState| s.pressed = part_at(s, x, y));
                SetCapture(hwnd);
                0
            }
            WM_LBUTTONUP => {
                let (x, y) = point(lp);
                let clicked = with_state(hwnd, |s: &mut PanelState| {
                    let p = s.pressed.take();
                    (p.filter(|&p| part_at(s, x, y) == Some(p)), s.action.clone())
                });
                ReleaseCapture();
                match clicked {
                    Some((Some(Part::Action), Some(a))) => {
                        run_action(&a);
                        close_toast(hwnd);
                    }
                    Some((Some(Part::Close), _)) => close_toast(hwnd),
                    _ => {}
                }
                0
            }
            WM_TIMER if wp == T_EXPIRE => {
                if pointer_over(hwnd) {
                    SetTimer(hwnd, T_EXPIRE, 1500, None);
                } else {
                    KillTimer(hwnd, T_EXPIRE);
                    close_toast(hwnd);
                }
                0
            }
            WM_MOUSEWHEEL | WM_MOUSEHWHEEL => 0,
            WM_NCDESTROY => {
                detach::<PanelState>(hwnd);
                DefWindowProcW(hwnd, msg, wp, lp)
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

/// Toasts, stacked at the bottom centre of the parent, newest at the bottom.
pub struct Toasts {
    parent: HWND,
    list: Vec<HWND>,
}

impl Toasts {
    pub fn new(parent: HWND) -> Toasts {
        Toasts { parent, list: Vec::new() }
    }

    /// Shows a toast. Its text may come from the host: it is cleaned and cut short here.
    pub fn show(&mut self, tone: Tone, title: &str, text: &str, action: Option<ToastAction>) {
        self.prune();
        while self.list.len() >= MAX_TOASTS {
            unsafe { DestroyWindow(self.list.remove(0)) };
        }
        let lifetime = match (tone, &action) {
            (_, Some(_)) => 12_000,
            (Tone::Warning | Tone::Error, _) => 10_000,
            _ => 6_000,
        };
        let (title, text) = panel_texts(title, text);
        if let Some(h) = create_panel(self.parent, PanelKind::Toast, Some(tone), &title, &text, action) {
            unsafe { SetTimer(h, T_EXPIRE, lifetime, None) };
            self.list.push(h);
        }
        self.relayout();
    }

    /// Drops closed toasts and re-stacks the rest (after a resize, DPI change or close).
    /// Older toasts that would reach the bar are closed, so they never cover it.
    pub fn relayout(&mut self) {
        self.prune();
        if unsafe { IsIconic(self.parent) } != 0 {
            return; // no room while minimised: keep them as they are
        }
        let (pw, ph) = client_size(self.parent);
        let m = Metrics(dpi_of(self.parent));
        let sizes: Vec<(i32, i32)> = self
            .list
            .iter()
            .rev()
            .map(|&h| {
                with_state(h, |s: &mut PanelState| layout_panel(h, s));
                panel_size(h)
            })
            .collect();
        let heights: Vec<i32> = sizes.iter().map(|&(_, th)| th).collect();
        let tops = stack(ph, m.px(24), m.px(8), m.px(BAR_HEIGHT + 8), &heights);
        let gone = self.list.len() - tops.len();
        for h in self.list.drain(..gone) {
            unsafe { DestroyWindow(h) };
        }
        for ((&h, &(w, th)), &y) in self.list.iter().rev().zip(&sizes).zip(&tops) {
            unsafe { SetWindowPos(h, HWND_TOP, (pw - w) / 2, y, w, th, SWP_NOACTIVATE | SWP_SHOWWINDOW) };
        }
    }

    fn prune(&mut self) {
        self.list.retain(|&h| unsafe { IsWindow(h) } != 0);
    }
}

/// A toast's or the overlay's title and text, cleaned and cut short.
fn panel_texts(title: &str, text: &str) -> (String, String) {
    (
        shorten(&clean_text(title, true, 4096), MAX_TITLE_LINES, MAX_TITLE_CHARS),
        shorten(&clean_text(text, true, 4096), MAX_TEXT_LINES, MAX_TEXT_CHARS),
    )
}

/// Tops of toasts stacked upwards from `margin` above the bottom of a `ph`-high parent,
/// `gap` apart (heights newest first). Only toasts that stay below `min_top` get a place,
/// except the newest: one too tall for that goes at `min_top`, or higher if it has to in
/// order to end inside the parent (never above 0), so its close button stays visible.
fn stack(ph: i32, margin: i32, gap: i32, min_top: i32, heights: &[i32]) -> Vec<i32> {
    let mut tops = Vec::with_capacity(heights.len());
    let mut y = ph - margin;
    for &h in heights {
        let top = y - h;
        if top < min_top {
            if tops.is_empty() {
                tops.push((ph - h).min(min_top).max(0));
            }
            break;
        }
        tops.push(top);
        y = top - gap;
    }
    tops
}

/// A status panel centred over the remote screen (e.g. "Reconnecting...").
pub struct Overlay {
    parent: HWND,
    hwnd: Option<HWND>,
}

impl Overlay {
    pub fn new(parent: HWND) -> Overlay {
        Overlay { parent, hwnd: None }
    }

    pub fn show(&mut self, title: &str, text: &str) {
        let (title, text) = panel_texts(title, text);
        match self.hwnd {
            Some(h) => {
                with_state(h, |s: &mut PanelState| {
                    if s.title != title || s.text != text {
                        s.title = title;
                        s.text = text;
                        layout_panel(h, s);
                    }
                });
            }
            None => self.hwnd = create_panel(self.parent, PanelKind::Overlay, None, &title, &text, None),
        }
        self.relayout();
    }

    pub fn hide(&mut self) {
        if let Some(h) = self.hwnd.take() {
            unsafe { DestroyWindow(h) };
        }
    }

    pub fn relayout(&self) {
        let Some(h) = self.hwnd else { return };
        with_state(h, |s: &mut PanelState| layout_panel(h, s));
        let (pw, ph) = client_size(self.parent);
        let (w, oh) = panel_size(h);
        unsafe { SetWindowPos(h, HWND_TOP, (pw - w) / 2, (ph - oh) / 2, w, oh, SWP_NOACTIVATE | SWP_SHOWWINDOW) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_text_is_translated_with_the_same_placeholders() {
        for t in Txt::ALL {
            let (en, ko) = t.pair();
            assert!(!en.is_empty() && !ko.is_empty(), "{t:?}");
            assert_eq!(en.matches("{}").count(), ko.matches("{}").count(), "{t:?}");
        }
        assert_eq!(fill("{} of {}", &[&1, &"two"]), "1 of two");
        assert_eq!(fill("{}에 저장", &[&"C:\\x"]), "C:\\x에 저장");
        assert_eq!(fill("no args {}", &[]), "no args ");
        assert_eq!(fill("plain", &[&5]), "plain");
    }

    fn model() -> BarModel {
        BarModel {
            host: "desk".into(),
            status: "12 ms".into(),
            connected: true,
            monitors: vec![
                MonitorInfo { left: 0, top: 0, width: 2560, height: 1440 },
                MonitorInfo { left: 2560, top: 0, width: 1920, height: 1080 },
            ],
            monitor: 0,
            monitor_menu: Feature::Off,
            quality: 1,
            quality_menu: Feature::Off,
            downscale: 1,
            scale_menu: Feature::Off,
            sas: Feature::Off,
            clipboard: Feature::On,
            send_files: Feature::Off,
            get_files: Feature::Off,
            sound: Feature::Unavailable,
            privacy: Feature::Hidden,
            ..BarModel::default()
        }
    }

    fn measure(_bold: bool, s: &str) -> i32 {
        7 * s.chars().count() as i32
    }

    #[test]
    fn specs_follow_the_model() {
        let m = model();
        let items: Vec<Item> = specs(&m, false, false).iter().map(|s| s.item).collect();
        use Item::*;
        assert_eq!(items, [Info, Monitor, Quality, Scale, Sas, Clipboard, SendFiles, GetFiles, Sound, FullScreen, Disconnect]);
        let floating = specs(&m, true, true);
        assert_eq!(floating[0].item, Pin);
        assert!(floating[0].on);
        let sound = floating.iter().find(|s| s.item == Sound).unwrap();
        assert!(!sound.enabled && sound.glyph == G_MUTE);
        assert!(floating.iter().find(|s| s.item == Clipboard).unwrap().on);
        // While reconnecting session features are disabled, window controls are not.
        let offline = BarModel { connected: false, ..m };
        for s in specs(&offline, false, false) {
            assert_eq!(s.enabled, matches!(s.item, Info | FullScreen | Disconnect), "{:?}", s.item);
        }
    }

    #[test]
    fn layout_degrades_to_fit() {
        let m = model();
        let sp = specs(&m, true, false);
        let px = Metrics(96);
        let full = layout_level(&sp, 0, px, true, &m.host, &measure);
        let chosen = choose_layout(&sp, full.width, px, true, &m.host, &measure);
        assert_eq!(chosen.level, 0);
        assert!(chosen.slots.iter().filter(|s| s.item != Item::Info && s.item != Item::Pin).all(|s| s.label));
        let l1 = choose_layout(&sp, full.width - 1, px, true, &m.host, &measure);
        assert_eq!(l1.level, 1);
        assert!(l1.slots.iter().find(|s| s.item == Item::Quality).unwrap().label);
        assert!(!l1.slots.iter().find(|s| s.item == Item::Clipboard).unwrap().label);
        // Narrower: the host name goes first, then the status shrinks to the round trip.
        let l2 = layout_level(&sp, 2, px, true, &m.host, &measure);
        let l3 = choose_layout(&sp, l2.width - 1, px, true, &m.host, &measure);
        assert_eq!((l3.level, l3.host_w, l3.short), (3, 0, false));
        let l4 = layout_level(&sp, 4, px, true, &m.host, &measure);
        assert!(l4.short && l4.status_w < l3.status_w && l4.slots.iter().any(|s| s.item == Item::Info));
        let l5 = choose_layout(&sp, 10, px, true, &m.host, &measure);
        assert_eq!(l5.level, 5);
        assert!(l5.slots.iter().all(|s| s.item != Item::Info && !s.label));
        for l in [&full, &l1, &l2, &l3, &l4, &l5] {
            // Slots are ordered, never overlap and fit inside the bar.
            for w in l.slots.windows(2) {
                assert!(w[0].x + w[0].w <= w[1].x);
            }
            assert!(l.slots.last().unwrap().x + l.slots.last().unwrap().w < l.width);
        }
        // Group changes get a separator: pin | info | menus | features | window.
        assert_eq!(full.seps.len(), 4);
        // At 200% the icon-only bar is exactly twice as wide.
        let big = layout_level(&sp, 5, Metrics(192), true, &m.host, &measure);
        let small = layout_level(&sp, 5, px, true, &m.host, &measure);
        assert_eq!(big.width, small.width * 2);
        // Without the icon font every button keeps its label.
        let plain = choose_layout(&sp, 10, px, false, &m.host, &measure);
        assert!(plain.slots.iter().filter(|s| s.item != Item::Pin).all(|s| s.label));
    }

    #[test]
    fn menus_and_hints() {
        let mut m = model();
        let mon = menu_entries(&m, Item::Monitor);
        assert_eq!(mon.len(), 4);
        assert_eq!(mon[0].id, CMD_MONITOR);
        assert!(mon[0].checked && !mon[1].checked);
        assert_eq!(mon[2].id, 0);
        assert_eq!(mon[3].id, CMD_MONITOR + MONITOR_ALL as u16);
        m.monitor = MONITOR_ALL;
        assert!(menu_entries(&m, Item::Monitor)[3].checked);
        let q = menu_entries(&m, Item::Quality);
        assert_eq!(q.iter().map(|e| e.id).collect::<Vec<_>>(), [CMD_QUALITY, CMD_QUALITY + 1, CMD_QUALITY + 2]);
        assert!(q[1].checked);
        let s = menu_entries(&m, Item::Scale);
        assert_eq!(s.iter().map(|e| e.id).collect::<Vec<_>>(), [CMD_SCALE + 1, CMD_SCALE + 2, CMD_SCALE + 3]);
        m.downscale = 4;
        let s = menu_entries(&m, Item::Scale);
        assert_eq!(s.len(), 4);
        assert!(s[3].checked);
        assert!(menu_entries(&m, Item::Sas).is_empty());

        let (_, body) = hint_text(&m, Item::Sound, false);
        assert!(body.ends_with(tr(Txt::NotOnHost)));
        let (title, _) = hint_text(&m, Item::Clipboard, false);
        assert!(title.ends_with(tr(Txt::On)));
        m.connected = false;
        assert!(hint_text(&m, Item::SendFiles, false).1.ends_with(tr(Txt::WhileReconnecting)));
        assert!(!hint_text(&m, Item::Disconnect, false).1.contains(tr(Txt::WhileReconnecting)));
        assert_eq!(command(Item::Disconnect), Some(CMD_DISCONNECT));
        assert_eq!(command(Item::Quality), None);
    }

    #[test]
    fn host_text_is_cleaned_and_cut() {
        assert_eq!(clean_text("invoice\u{202e}fdp.exe", false, 255), "invoicefdp.exe");
        let tricks = " a\u{200e}\u{200f}\u{061c}\u{feff}\u{2066}b\u{2069}\u{202a}c\u{202c}\u{2067}\u{2068} ";
        assert_eq!(clean_text(tricks, false, 255), "abc");
        assert_eq!(clean_text("one\ntwo\tthree\r\u{7}\u{1b}[2J", false, 255), "one two three[2J");
        assert_eq!(clean_text("one\r\ntwo\n", true, 255), "one\ntwo");
        assert_eq!(clean_text("호스트 이름", false, 3), "호스트");
        // Joiners that emoji and some scripts need are kept.
        assert_eq!(clean_text("a\u{200d}b", false, 10), "a\u{200d}b");

        assert_eq!(shorten("short", 6, 400), "short");
        assert_eq!(shorten(&("\n".repeat(4000) + "x"), 6, 400), "x");
        assert_eq!(shorten(&format!("a{}b", "\n".repeat(4000)), 6, 400), "a\n\nb");
        let many: String = (0..20).map(|i| format!("line {i}\n\n\n")).collect();
        assert_eq!(shorten(&many, 6, 400), "line 0\n\nline 1\n\nline 2…");
        let long = shorten(&"word ".repeat(200), 6, 400);
        assert_eq!(long.chars().count(), 400);
        assert!(long.ends_with("word…"));
        let (title, text) = panel_texts(&"t".repeat(1000), &"x\n".repeat(1000));
        assert!(title.chars().count() <= MAX_TITLE_CHARS + 1 && text.lines().count() <= MAX_TEXT_LINES);
    }

    #[test]
    fn toasts_stack_below_the_bar() {
        // 600 px tall parent, 24 px margin, 8 px gap, nothing above 42 px.
        assert_eq!(stack(600, 24, 8, 42, &[100, 100]), [476, 368]);
        // The third would reach the bar: no place for it (it is closed).
        assert_eq!(stack(600, 24, 8, 42, &[200, 200, 200]), [376, 168]);
        // A newest toast too tall for the room left still shows its top and close button.
        assert_eq!(stack(600, 24, 8, 42, &[540]), [42]);
        assert_eq!(stack(600, 24, 8, 42, &[580]), [20]);
        assert_eq!(stack(100, 24, 8, 42, &[300]), [0]);
        assert!(stack(600, 24, 8, 42, &[]).is_empty());
    }

    #[test]
    fn scaling_rounds() {
        assert_eq!(scale(34, 96), 34);
        assert_eq!(scale(34, 144), 51);
        assert_eq!(scale(1, 120), 1);
        assert_eq!(scale(10, 120), 13);
    }
}
