//! Launcher: a small window for people who would rather not use the command line.
//!
//! * Connect: Tailscale devices (online first), a host field with recent hosts and viewer
//!   options; runs `safe-rdp connect ...` as a child process and reports how it went.
//! * Share this PC: starts and stops `safe-rdp host ...` (hidden, stderr shown as a live log),
//!   shows who is connected, and installs or removes the service (elevated through UAC).
//! * Key: create, import, show, copy or remove the shared key.
//!
//! The viewer and host run as separate processes, so a failure there never takes the launcher
//! down. The host is tied to the launcher with a kill-on-close job object: sharing never
//! outlives the window that shows it. A host keeps the key it started with, so sharing is
//! restarted (or stopped) whenever the stored key changes, here or in a terminal. The service
//! keeps the key it was given: the fingerprint it recorded is compared with the stored key's,
//! and changing the key here offers to give the service the new one (its options stay).
//! Plain Win32 with common controls v6 (`app.manifest`),
//! per-monitor DPI aware; Korean strings when the Windows display language is Korean.
//!
//! Testing knobs: `SAFE_RDP_LANG=en|ko` picks the language; `SAFE_RDP_LAUNCHER_BIND=<ip>` and
//! `SAFE_RDP_LAUNCHER_PORT=<n>` make "Start sharing" listen there (e.g. on 127.0.0.1).

use super::{clipboard, keystore, service};
use crate::keys;
use crate::proto::DEFAULT_PORT;
use crate::tailscale::{self, Device, Problem};
use crate::util::{wide, wipe};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, SocketAddr};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize};
use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber};
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::SystemServices::{LANG_KOREAN, SS_ENDELLIPSIS, SS_LEFT, SS_LEFTNOWORDWRAP, SS_NOPREFIX};
use windows_sys::Win32::System::Threading::{CreateMutexW, DETACHED_PROCESS, GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows_sys::Win32::UI::Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW};
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow, GetSystemMetricsForDpi};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
use windows_sys::Win32::UI::Shell::{
    DefSubclassProc, RemoveWindowSubclass, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    SetWindowSubclass, ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::{PCWSTR, w};

/// Resource ID of the application icon embedded by build.rs.
pub const ICON_ID: u16 = 1;

const CLASS: &str = "SafeRdpLauncher";
const INSTANCE_MUTEX: &str = "Local\\SafeRdpLauncher";
const WM_APP_EVENT: u32 = WM_APP + 1;
const TIMER_DEVICES: usize = 1;
const TIMER_CLIPBOARD: usize = 2;
const TIMER_KEY: usize = 3;
const DEVICE_REFRESH_MS: u32 = 15_000;
const CLIPBOARD_CLEAR_MS: u32 = 60_000;
/// Next try at emptying the clipboard while another program holds it open.
const CLIPBOARD_RETRY_MS: u32 = 1_000;
/// How often a running host's key is compared with the stored one.
const KEY_CHECK_MS: u32 = 2_000;
/// Time a stopping host gets to exit on its own (its stdin is closed first) before it is killed.
const STOP_GRACE: Duration = Duration::from_millis(1500);
const MAX_LOG_LINES: usize = 400;
const MAX_LINE: u64 = 4096;
const MAX_RECENT: usize = 10;

// Layout, in device-independent pixels (96 DPI).
const SIDEBAR: i32 = 208;
const MARGIN: i32 = 32;
const DEFAULT_SIZE: (i32, i32) = (900, 690);
const MIN_SIZE: (i32, i32) = (780, 600);

// Control IDs.
const ID_NAV: u16 = 100;
const ID_REFRESH: u16 = 200;
const ID_LIST: u16 = 201;
const ID_HOST: u16 = 202;
const ID_CONNECT: u16 = 203;
const ID_FULLSCREEN: u16 = 204;
const ID_CLIPBOARD: u16 = 205;
const ID_SOUND: u16 = 206;
const ID_PRIVACY: u16 = 207;
const ID_VIEW_ONLY: u16 = 208;
const ID_QUALITY: u16 = 209;
const ID_SCALE: u16 = 210;
const ID_MONITOR: u16 = 211;
const ID_SHARE: u16 = 300;
const ID_ALLOW_CONTROL: u16 = 301;
const ID_ALLOW_CLIPBOARD: u16 = 302;
const ID_ALLOW_FILES: u16 = 303;
const ID_ALLOW_SOUND: u16 = 304;
const ID_ALLOW_PRIVACY: u16 = 305;
const ID_LOG: u16 = 306;
const ID_INSTALL: u16 = 307;
const ID_UNINSTALL: u16 = 308;
const ID_SAS: u16 = 309;
const ID_CREATE: u16 = 400;
const ID_SHOW: u16 = 401;
const ID_REMOVE: u16 = 402;
const ID_IMPORT_TEXT: u16 = 403;
const ID_IMPORT: u16 = 404;
const ID_KEY_TEXT: u16 = 405;
const ID_COPY: u16 = 406;
const ID_HIDE: u16 = 407;

/// `--quality` values in the order of the quality list ("" = the host's choice). Balanced
/// comes last so that saved choices keep their indices.
const QUALITY_ARGS: [&str; 4] = ["", "lossless", "low", "balanced"];
/// `--monitor` values in the order of the monitor list ("" = the host's choice).
const MONITOR_ARGS: [&str; 6] = ["", "1", "2", "3", "4", "all"];

// ---------------------------------------------------------------------------------------
// Strings

struct Text {
    tagline: &'static str,
    nav: [&'static str; 3],
    connect_title: &'static str,
    connect_sub: &'static str,
    devices: &'static str,
    refresh: &'static str,
    columns: [&'static str; 4],
    online: &'static str,
    offline: &'static str,
    ts_loading: &'static str,
    ts_none: &'static str,
    ts_not_installed: &'static str,
    ts_not_running: &'static str,
    ts_state: fn(&str) -> String,
    ts_failed: fn(&str) -> String,
    ts_count: fn(usize, usize) -> String,
    host_title: &'static str,
    host_cue: &'static str,
    connect: &'static str,
    options: &'static str,
    opt_fullscreen: &'static str,
    opt_clipboard: &'static str,
    opt_sound: &'static str,
    opt_privacy: &'static str,
    opt_view_only: &'static str,
    quality: &'static str,
    qualities: [&'static str; 4],
    scale: &'static str,
    scales: [&'static str; 4],
    monitor: &'static str,
    monitors: [&'static str; 6],
    connecting: fn(&str) -> String,
    connected: fn(&str) -> String,
    ended: fn(&str) -> String,
    connect_failed: fn(&str, &str) -> String,
    lost: fn(&str, &str) -> String,
    viewer_crashed: &'static str,
    need_host: &'static str,
    bad_host: &'static str,
    launch_failed: fn(&str) -> String,
    share_title: &'static str,
    share_sub: &'static str,
    start: &'static str,
    stop: &'static str,
    st_off: &'static str,
    st_off_detail: &'static str,
    st_service_detail: &'static str,
    st_service_old_key: &'static str,
    /// While it cannot be told which key the running service has.
    st_service_unknown_key: &'static str,
    st_starting: &'static str,
    st_wait_ts: &'static str,
    st_wait_ts_detail: &'static str,
    st_ready: &'static str,
    st_ready_detail: fn(&str) -> String,
    st_connected: fn(&str) -> String,
    st_connected_control: &'static str,
    st_connected_view: &'static str,
    st_stopping: &'static str,
    st_failed: &'static str,
    host_exited: fn(i32) -> String,
    allow: &'static str,
    allow_control: &'static str,
    allow_clipboard: &'static str,
    allow_files: &'static str,
    allow_sound: &'static str,
    allow_privacy: &'static str,
    activity: &'static str,
    svc_title: &'static str,
    svc_text: &'static str,
    svc_sas: &'static str,
    install: &'static str,
    reinstall: &'static str,
    /// The install button while the service has another key than the stored one.
    update_key: &'static str,
    uninstall: &'static str,
    svc_status: fn(&str) -> String,
    /// checking, not installed, running, stopped, changing, unknown
    svc_states: [&'static str; 6],
    /// Added to the status while the service has another key than the stored one.
    svc_key_status: &'static str,
    /// Added to the status while that cannot be told.
    svc_key_unknown: &'static str,
    svc_install_confirm: &'static str,
    svc_reinstall_confirm: &'static str,
    svc_rekey_confirm: &'static str,
    svc_uninstall_confirm: &'static str,
    svc_failed: fn(u32) -> String,
    /// The elevated command refused the approving account's key (`service::EXIT_OTHER_KEY`).
    svc_other_key: &'static str,
    /// The service did not stop, so nothing was replaced (`service::EXIT_NOT_STOPPED`).
    svc_not_stopped: &'static str,
    /// The service got the key but did not start (`service::EXIT_NOT_STARTED`).
    svc_not_started: &'static str,
    close_sharing: &'static str,
    key_title: &'static str,
    key_sub: &'static str,
    key_welcome: &'static str,
    key_need: &'static str,
    key_stored: &'static str,
    key_missing: &'static str,
    key_unreadable: &'static str,
    key_about: &'static str,
    create: &'static str,
    show: &'static str,
    remove: &'static str,
    import_title: &'static str,
    import_cue: &'static str,
    import: &'static str,
    shown_title: &'static str,
    copy: &'static str,
    hide: &'static str,
    key_warning: &'static str,
    replace_confirm: &'static str,
    remove_confirm: &'static str,
    /// Added to the two above when the service is installed.
    key_svc_confirm: &'static str,
    svc_key_offer: &'static str,
    /// Instead of `svc_key_offer` while it cannot be told which key the service has.
    svc_key_reinstall_offer: &'static str,
    svc_key_remove_offer: &'static str,
    /// The Key-tab note while the Share tab offers Update key for the service (`svc_note`).
    svc_key_note: &'static str,
    /// Instead of `svc_key_note` while it offers Reinstall.
    svc_reinstall_note: &'static str,
    sharing_restarts: &'static str,
    sharing_stopped: &'static str,
    created: &'static str,
    imported: &'static str,
    same_key: &'static str,
    removed: &'static str,
    nothing_removed: &'static str,
    copied: &'static str,
    copy_failed: &'static str,
    import_empty: &'static str,
    bad_key: fn(&str) -> String,
    key_failed: fn(&str) -> String,
}

static EN: Text = Text {
    tagline: "Remote desktop over Tailscale",
    nav: ["Connect", "Share this PC", "Key"],
    connect_title: "Connect to a PC",
    connect_sub: "Pick one of your devices, or type its name or Tailscale IP.",
    devices: "Your devices",
    refresh: "Refresh",
    columns: ["Device", "System", "Tailscale IP", "Status"],
    online: "Online",
    offline: "Offline",
    ts_loading: "Looking for your devices…",
    ts_none: "No other devices in your tailnet yet. Install Tailscale on your other PC and sign in with the same account.",
    ts_not_installed: "Tailscale is not installed. Get it from tailscale.com and sign in on both PCs.",
    ts_not_running: "Tailscale is not running. Start Tailscale, then press Refresh.",
    ts_state: |s| match s {
        "NeedsLogin" => "Tailscale needs you to sign in. Open Tailscale and log in.".into(),
        "Stopped" => "Tailscale is disconnected. Open Tailscale and connect.".into(),
        "Starting" => "Tailscale is starting…".into(),
        "NeedsMachineAuth" => "This device is waiting for approval in the Tailscale admin console.".into(),
        s => format!("Tailscale is not connected ({s})."),
    },
    ts_failed: |e| format!("Could not list your devices: {e}"),
    ts_count: |on, all| format!("{on} of {all} online · double-click a device to connect"),
    host_title: "PC to connect to",
    host_cue: "Device name or Tailscale IP",
    connect: "Connect",
    options: "Options",
    opt_fullscreen: "Full screen",
    opt_clipboard: "Share clipboard",
    opt_sound: "Play sound",
    opt_privacy: "Blank the remote screen",
    opt_view_only: "View only",
    quality: "Quality",
    qualities: ["Default", "Best (lossless)", "Low bandwidth", "Balanced"],
    scale: "Resolution",
    scales: ["Full", "1/2", "1/3", "1/4"],
    monitor: "Monitor",
    monitors: ["Default", "1", "2", "3", "4", "All"],
    connecting: |h| format!("Connecting to {h}…"),
    connected: |h| format!("Connected to {h}. The remote screen is in its own window."),
    ended: |h| format!("Disconnected from {h}."),
    connect_failed: |h, e| format!("Could not connect to {h}: {e}"),
    lost: |h, e| format!("The connection to {h} ended: {e}"),
    viewer_crashed: "the viewer closed unexpectedly",
    need_host: "Pick a device from the list, or type a device name or Tailscale IP.",
    bad_host: "That is not a device name or IP address.",
    launch_failed: |e| format!("Could not start the viewer: {e}"),
    share_title: "Share this PC",
    share_sub: "Let your other devices see and control this PC through Tailscale.",
    start: "Start sharing",
    stop: "Stop sharing",
    st_off: "Not sharing",
    st_off_detail: "Start sharing to let your other PCs connect. Only devices in your tailnet that have the same key can.",
    st_service_detail: "The background service is running, so this PC can already be reached.",
    st_service_old_key: "The background service is running with another key than yours (perhaps a previous one). Update its key \
                         or remove it below.",
    st_service_unknown_key: "The background service is running, but it cannot be told which key it has (an earlier safe-rdp \
                             installed it, or changing its key failed), so it may still accept a previous key. Reinstall it \
                             below: that gives it your key and this version of safe-rdp.",
    st_starting: "Starting…",
    st_wait_ts: "Waiting for Tailscale…",
    st_wait_ts_detail: "Sharing begins as soon as Tailscale is connected.",
    st_ready: "Waiting for a connection",
    st_ready_detail: |a| format!("On your other PC, connect to {a}."),
    st_connected: |w| format!("{w} is connected"),
    st_connected_control: "They can see this screen and use its keyboard and mouse. Stop sharing to disconnect them.",
    st_connected_view: "They can see this screen but cannot control it. Stop sharing to disconnect them.",
    st_stopping: "Stopping…",
    st_failed: "Sharing stopped",
    host_exited: |c| format!("The host process exited (code {c})."),
    allow: "While sharing, allow",
    allow_control: "Keyboard and mouse control",
    allow_clipboard: "Clipboard",
    allow_files: "File transfer",
    allow_sound: "Sound",
    allow_privacy: "Blanking this screen on request",
    activity: "Activity",
    svc_title: "Background service",
    svc_text: "Install the service to reach this PC at any time: it starts with Windows, works before anyone signs in, on the \
               lock screen and on UAC prompts, and uses the key of the account that installs it (update its key after \
               changing that key). Connections are only accepted from Tailscale addresses. Installing or removing it needs \
               administrator rights.",
    svc_sas: "Allow sending Ctrl+Alt+Del (changes a Windows policy)",
    install: "Install",
    reinstall: "Reinstall",
    update_key: "Update key",
    uninstall: "Remove",
    svc_status: |s| format!("Status: {s}"),
    svc_states: ["checking…", "not installed", "running", "stopped", "changing…", "unknown"],
    svc_key_status: " · not using your key",
    svc_key_unknown: " · key unknown",
    svc_install_confirm: "Install the background service?\n\nIt uses the key stored for your account and the options ticked under \
                          \"While sharing, allow\". Windows will ask for administrator permission; if another account approves \
                          it, that account needs the same key.",
    svc_reinstall_confirm: "Reinstall the background service?\n\nIt then uses the key stored for your account and only the options \
                            ticked under \"While sharing, allow\": settings it was installed with in a terminal, such as its port, \
                            allowed addresses or upload folder, are dropped. Windows will ask for administrator permission; if \
                            another account approves it, that account needs the same key.",
    svc_rekey_confirm: "Give the background service the key stored for your account?\n\nOnly its key changes; its other settings \
                        stay as they are. It restarts, which disconnects anyone connected through it. Windows will ask for \
                        administrator permission; if another account approves it, that account needs the same key.",
    svc_uninstall_confirm: "Remove the background service?\n\nAfterwards this PC can only be reached while you share it from this window.",
    svc_failed: |c| format!("The service command failed (exit code {c})."),
    svc_other_key: "Nothing was changed: the account that approved the administrator prompt does not have your current key, \
                    and the service gets the key of that account. Import your key into that account first (sign in to it and \
                    use Key → Import), or approve with an account that has it, then try again.",
    svc_not_stopped: "Nothing was replaced: the background service did not stop when asked, so it keeps the key it had. Try \
                      again in a moment, or restart Windows first.",
    svc_not_started: "The background service now has your key, but Windows could not start it, so this PC cannot be reached \
                      through it until it runs. Start \"safe-rdp host\" in Windows Services (if it is disabled there, \
                      Reinstall turns it back on).",
    close_sharing: "This PC is being shared. Closing safe-rdp stops sharing and disconnects anyone viewing it.\n\nClose anyway?",
    key_title: "Security key",
    key_sub: "Your PCs use this key to recognize each other. Every PC needs the same key.",
    key_welcome: "Welcome! Start by setting up the key. If this is your first PC, create a new key here and then import it on \
                  your other PC. If you already created one on another PC, import it here.",
    key_need: "You need a key before you can connect or share. Create one, or import the key from your other PC.",
    key_stored: "● A key is stored on this PC (encrypted for your Windows account).",
    key_missing: "● No key on this PC yet.",
    key_unreadable: "● The stored key cannot be read (it may belong to another Windows account). Create or import a key to replace it.",
    key_about: "Anyone who has this key and can reach a sharing PC through your tailnet can control it. Treat it like a \
                password: copy it only to your own PCs and never send it by chat or email.",
    create: "Create new key",
    show: "Show key",
    remove: "Remove key",
    import_title: "Import the key from your other PC",
    import_cue: "Paste the key here (srdp1-…)",
    import: "Import",
    shown_title: "Your key",
    copy: "Copy",
    hide: "Hide",
    key_warning: "Enter it on your other PC (Key → Import). A copy is removed from the clipboard after one minute.",
    replace_confirm: "Replace the stored key?\n\nYour other PCs cannot connect to or from this PC until they have the new key. If this \
                      window is sharing this PC, sharing restarts with the new key and anyone connected is disconnected.",
    remove_confirm: "Remove the key from this PC?\n\nThis PC cannot connect or share until you create or import a key again. If this \
                     window is sharing this PC, sharing stops and anyone connected is disconnected.",
    key_svc_confirm: "\n\nThe background service is installed and keeps the key it was given until it gets the new one or is \
                      removed; you can do that next.",
    svc_key_offer: "The background service keeps the key it was given, so it does not use the new key yet and may still accept \
                    the previous one.\n\nGive it the new key now? Only its key changes; its other settings stay as they are. \
                    Windows will ask for administrator permission; if another account approves it, that account needs the new \
                    key too.",
    svc_key_reinstall_offer: "The background service keeps the key it was given, and it cannot be told which key that is (an \
                              earlier safe-rdp installed it, or changing its key failed), so it may still accept the previous \
                              one.\n\nReinstall it now with the new key? It then runs this version of safe-rdp with only the \
                              options ticked under \"While sharing, allow\": settings it was installed with in a terminal, such \
                              as its port, allowed addresses or upload folder, are dropped. Windows will ask for administrator \
                              permission; if another account approves it, that account needs the new key too.",
    svc_key_remove_offer: "The background service keeps the key it was given, so it may still accept the removed key.\n\n\
                           Remove the background service now? Windows will ask for administrator permission.",
    svc_key_note: " The background service keeps the key it had until you update its key or remove it (Share this PC).",
    svc_reinstall_note: " The background service keeps the key it had until you reinstall it or remove it (Share this PC).",
    sharing_restarts: " Sharing restarts with the new key; anyone connected was disconnected.",
    sharing_stopped: " Sharing from this window stopped; anyone connected was disconnected.",
    created: "New key created. Copy it to your other PC.",
    imported: "Key imported. This PC can now connect to and share with your other PCs.",
    same_key: "This key is already stored.",
    removed: "Key removed.",
    nothing_removed: "No key was stored.",
    copied: "Copied. It will be removed from the clipboard in one minute.",
    copy_failed: "Could not use the clipboard. Try Copy again in a moment.",
    import_empty: "Paste the key into the field first.",
    bad_key: |e| format!("That is not a valid key: {e}"),
    key_failed: |e| format!("Could not update the key: {e}"),
};

static KO: Text = Text {
    tagline: "Tailscale 원격 데스크톱",
    nav: ["접속하기", "이 PC 공유", "보안 키"],
    connect_title: "다른 PC에 접속",
    connect_sub: "내 기기를 고르거나 기기 이름 또는 Tailscale IP를 입력하세요.",
    devices: "내 기기",
    refresh: "새로 고침",
    columns: ["기기", "OS", "Tailscale IP", "상태"],
    online: "온라인",
    offline: "오프라인",
    ts_loading: "기기를 찾는 중…",
    ts_none: "tailnet에 다른 기기가 없습니다. 다른 PC에도 Tailscale을 설치하고 같은 계정으로 로그인하세요.",
    ts_not_installed: "Tailscale이 설치되어 있지 않습니다. tailscale.com에서 설치한 뒤 두 PC에서 로그인하세요.",
    ts_not_running: "Tailscale이 실행되고 있지 않습니다. Tailscale을 실행한 뒤 새로 고침을 누르세요.",
    ts_state: |s| match s {
        "NeedsLogin" => "Tailscale 로그인이 필요합니다. Tailscale을 열고 로그인하세요.".into(),
        "Stopped" => "Tailscale 연결이 꺼져 있습니다. Tailscale을 열고 연결하세요.".into(),
        "Starting" => "Tailscale이 시작하는 중입니다…".into(),
        "NeedsMachineAuth" => "이 기기는 Tailscale 관리 콘솔에서 승인을 기다리고 있습니다.".into(),
        s => format!("Tailscale이 연결되어 있지 않습니다 ({s})."),
    },
    ts_failed: |e| format!("기기 목록을 가져오지 못했습니다: {e}"),
    ts_count: |on, all| format!("{all}대 중 {on}대 온라인 · 기기를 두 번 클릭하면 접속합니다"),
    host_title: "접속할 PC",
    host_cue: "기기 이름 또는 Tailscale IP",
    connect: "접속",
    options: "옵션",
    opt_fullscreen: "전체 화면",
    opt_clipboard: "클립보드 공유",
    opt_sound: "소리 재생",
    opt_privacy: "원격 PC 화면 가리기",
    opt_view_only: "보기 전용",
    quality: "화질",
    qualities: ["기본", "최고 (무손실)", "저대역폭", "균형"],
    scale: "해상도",
    scales: ["원본", "1/2", "1/3", "1/4"],
    monitor: "모니터",
    monitors: ["기본", "1", "2", "3", "4", "전체"],
    connecting: |h| format!("{h}에 접속하는 중…"),
    connected: |h| format!("{h}에 연결되었습니다. 원격 화면은 별도 창에 표시됩니다."),
    ended: |h| format!("{h} 연결을 종료했습니다."),
    connect_failed: |h, e| format!("{h}에 접속하지 못했습니다: {e}"),
    lost: |h, e| format!("{h} 연결이 끊어졌습니다: {e}"),
    viewer_crashed: "뷰어가 예기치 않게 종료되었습니다",
    need_host: "목록에서 기기를 고르거나 기기 이름 또는 Tailscale IP를 입력하세요.",
    bad_host: "기기 이름이나 IP 주소가 아닙니다.",
    launch_failed: |e| format!("뷰어를 시작하지 못했습니다: {e}"),
    share_title: "이 PC 공유",
    share_sub: "Tailscale로 연결된 내 다른 기기에서 이 PC를 보고 조작할 수 있게 합니다.",
    start: "공유 시작",
    stop: "공유 중지",
    st_off: "공유하지 않음",
    st_off_detail: "공유를 시작하면 다른 PC에서 접속할 수 있습니다. 같은 키를 가진 내 tailnet 기기만 접속할 수 있습니다.",
    st_service_detail: "백그라운드 서비스가 실행 중이므로 이미 이 PC에 접속할 수 있습니다.",
    st_service_old_key: "백그라운드 서비스가 내 키가 아닌 다른 키(이전 키일 수 있음)로 실행 중입니다. 아래에서 키를 업데이트하거나 \
                         서비스를 제거하세요.",
    st_service_unknown_key: "백그라운드 서비스가 실행 중이지만 어떤 키를 쓰는지 확인할 수 없어 (이전 버전의 safe-rdp로 설치했거나 \
                             키 변경이 실패함) 이전 키로도 접속될 수 있습니다. 아래에서 다시 설치하면 내 키와 이 버전의 \
                             safe-rdp를 사용합니다.",
    st_starting: "시작하는 중…",
    st_wait_ts: "Tailscale 연결을 기다리는 중…",
    st_wait_ts_detail: "Tailscale이 연결되면 바로 공유를 시작합니다.",
    st_ready: "접속 대기 중",
    st_ready_detail: |a| format!("다른 PC에서 {a}에 접속하세요."),
    st_connected: |w| format!("{w} 접속 중"),
    st_connected_control: "상대방이 이 화면을 보고 키보드와 마우스를 조작할 수 있습니다. 공유를 중지하면 연결이 끊어집니다.",
    st_connected_view: "상대방이 이 화면을 볼 수 있지만 조작할 수는 없습니다. 공유를 중지하면 연결이 끊어집니다.",
    st_stopping: "중지하는 중…",
    st_failed: "공유가 중지되었습니다",
    host_exited: |c| format!("호스트 프로세스가 종료되었습니다 (코드 {c})."),
    allow: "공유 중 허용할 기능",
    allow_control: "키보드·마우스 조작",
    allow_clipboard: "클립보드",
    allow_files: "파일 전송",
    allow_sound: "소리",
    allow_privacy: "요청 시 이 화면 가리기",
    activity: "활동 기록",
    svc_title: "백그라운드 서비스",
    svc_text: "서비스를 설치하면 언제든 이 PC에 접속할 수 있습니다. Windows와 함께 시작되고, 로그인 전 화면·잠금 화면·UAC 창에서도 \
               동작하며, 설치한 계정의 키를 사용합니다 (키를 바꾼 뒤에는 서비스의 키도 업데이트하세요). 접속은 Tailscale 주소에서만 \
               받습니다. 설치와 제거에는 관리자 권한이 필요합니다.",
    svc_sas: "Ctrl+Alt+Del 보내기 허용 (Windows 정책 변경)",
    install: "설치",
    reinstall: "다시 설치",
    update_key: "키 업데이트",
    uninstall: "제거",
    svc_status: |s| format!("상태: {s}"),
    svc_states: ["확인 중…", "설치 안 됨", "실행 중", "중지됨", "변경 중…", "알 수 없음"],
    svc_key_status: " · 내 키를 쓰지 않음",
    svc_key_unknown: " · 키 확인 불가",
    svc_install_confirm: "백그라운드 서비스를 설치할까요?\n\n현재 계정에 저장된 키와 '공유 중 허용할 기능'에서 선택한 옵션을 사용합니다. \
                          Windows가 관리자 권한을 요청하며, 다른 계정이 승인한다면 그 계정에도 같은 키가 있어야 합니다.",
    svc_reinstall_confirm: "백그라운드 서비스를 다시 설치할까요?\n\n현재 계정에 저장된 키와 '공유 중 허용할 기능'에서 선택한 옵션만 \
                            사용하므로, 터미널에서 설치할 때 지정한 포트·허용 주소·업로드 폴더 같은 설정은 사라집니다. Windows가 \
                            관리자 권한을 요청하며, 다른 계정이 승인한다면 그 계정에도 같은 키가 있어야 합니다.",
    svc_rekey_confirm: "백그라운드 서비스에 현재 계정에 저장된 키를 넣을까요?\n\n키만 바뀌고 다른 설정은 그대로 유지됩니다. 서비스가 \
                        다시 시작되므로 서비스로 접속해 있던 사람은 연결이 끊어집니다. Windows가 관리자 권한을 요청하며, 다른 \
                        계정이 승인한다면 그 계정에도 같은 키가 있어야 합니다.",
    svc_uninstall_confirm: "백그라운드 서비스를 제거할까요?\n\n이후에는 이 창에서 공유하는 동안에만 이 PC에 접속할 수 있습니다.",
    svc_failed: |c| format!("서비스 명령이 실패했습니다 (종료 코드 {c})."),
    svc_other_key: "아무것도 바꾸지 않았습니다. 관리자 권한을 승인한 계정에 현재 키가 없습니다 (서비스는 승인한 계정의 키를 \
                    받습니다). 먼저 그 계정으로 로그인해 '보안 키 → 가져오기'로 키를 넣거나, 같은 키가 있는 계정으로 승인한 뒤 \
                    다시 시도하세요.",
    svc_not_stopped: "아무것도 바꾸지 않았습니다. 백그라운드 서비스가 중지 요청에도 멈추지 않아 기존 키를 계속 사용합니다. 잠시 후 \
                      다시 시도하거나, Windows를 다시 시작한 뒤 시도하세요.",
    svc_not_started: "백그라운드 서비스에 내 키를 넣었지만 Windows가 서비스를 시작하지 못했습니다. 서비스가 실행되기 전까지는 \
                      서비스로 이 PC에 접속할 수 없습니다. Windows 서비스에서 'safe-rdp host'를 시작하세요 ('사용 안 함'으로 \
                      되어 있다면 다시 설치하면 다시 켜집니다).",
    close_sharing: "이 PC를 공유하는 중입니다. safe-rdp를 닫으면 공유가 중지되고 접속한 사람의 연결이 끊어집니다.\n\n그래도 닫을까요?",
    key_title: "보안 키",
    key_sub: "내 PC들은 이 키로 서로를 확인합니다. 모든 PC에 같은 키가 있어야 합니다.",
    key_welcome: "환영합니다! 먼저 보안 키를 준비하세요. 첫 번째 PC라면 여기에서 새 키를 만든 뒤 다른 PC에서 가져오면 됩니다. \
                  이미 다른 PC에서 만들었다면 여기에서 가져오세요.",
    key_need: "접속하거나 공유하려면 먼저 키가 필요합니다. 새로 만들거나 다른 PC의 키를 가져오세요.",
    key_stored: "● 이 PC에 키가 저장되어 있습니다 (Windows 계정 전용으로 암호화됨).",
    key_missing: "● 이 PC에는 아직 키가 없습니다.",
    key_unreadable: "● 저장된 키를 읽을 수 없습니다 (다른 Windows 계정의 키일 수 있습니다). 새로 만들거나 가져와서 바꾸세요.",
    key_about: "이 키를 가진 사람은 tailnet을 통해 공유 중인 PC를 조작할 수 있습니다. 비밀번호처럼 다루고, 내 PC에만 옮기며 \
                메신저나 이메일로 보내지 마세요.",
    create: "새 키 만들기",
    show: "키 보기",
    remove: "키 삭제",
    import_title: "다른 PC의 키 가져오기",
    import_cue: "여기에 키를 붙여넣으세요 (srdp1-…)",
    import: "가져오기",
    shown_title: "보안 키",
    copy: "복사",
    hide: "숨기기",
    key_warning: "다른 PC의 '보안 키 → 가져오기'에 입력하세요. 복사한 키는 1분 뒤 클립보드에서 지워집니다.",
    replace_confirm: "저장된 키를 바꿀까요?\n\n다른 PC에도 새 키를 넣기 전까지는 서로 접속할 수 없습니다. 이 창에서 공유 중이면 새 \
                      키로 공유를 다시 시작하며 접속한 사람의 연결이 끊어집니다.",
    remove_confirm: "이 PC에서 키를 삭제할까요?\n\n다시 키를 만들거나 가져오기 전까지 접속하거나 공유할 수 없습니다. 이 창에서 공유 \
                     중이면 공유가 중지되고 접속한 사람의 연결이 끊어집니다.",
    key_svc_confirm: "\n\n백그라운드 서비스가 설치되어 있으며, 새 키를 넣거나 제거하기 전까지 받은 키를 계속 사용합니다. 이어서 \
                      바로 할 수 있습니다.",
    svc_key_offer: "백그라운드 서비스는 받은 키를 계속 사용하므로 아직 새 키를 쓰지 않으며 이전 키로도 접속될 수 있습니다.\n\n\
                    지금 서비스에 새 키를 넣을까요? 키만 바뀌고 다른 설정은 그대로 유지됩니다. Windows가 관리자 권한을 \
                    요청하며, 다른 계정이 승인한다면 그 계정에도 새 키가 있어야 합니다.",
    svc_key_reinstall_offer: "백그라운드 서비스는 받은 키를 계속 사용하는데, 그 키가 무엇인지 확인할 수 없어 (이전 버전의 \
                              safe-rdp로 설치했거나 키 변경이 실패함) 이전 키로도 접속될 수 있습니다.\n\n지금 새 키로 서비스를 \
                              다시 설치할까요? 이 버전의 safe-rdp와 '공유 중 허용할 기능'에서 선택한 옵션만 사용하므로, 터미널에서 \
                              설치할 때 지정한 포트·허용 주소·업로드 폴더 같은 설정은 사라집니다. Windows가 관리자 권한을 \
                              요청하며, 다른 계정이 승인한다면 그 계정에도 새 키가 있어야 합니다.",
    svc_key_remove_offer: "백그라운드 서비스는 받은 키를 계속 사용하므로 삭제한 키로도 아직 접속될 수 있습니다.\n\n지금 \
                           백그라운드 서비스를 제거할까요? Windows가 관리자 권한을 요청합니다.",
    svc_key_note: " 백그라운드 서비스는 키를 업데이트하거나 제거하기 전까지 기존 키를 계속 사용합니다 ('이 PC 공유').",
    svc_reinstall_note: " 백그라운드 서비스는 다시 설치하거나 제거하기 전까지 기존 키를 계속 사용합니다 ('이 PC 공유').",
    sharing_restarts: " 공유를 새 키로 다시 시작합니다. 접속해 있던 사람은 연결이 끊어졌습니다.",
    sharing_stopped: " 이 창의 공유를 중지했습니다. 접속해 있던 사람은 연결이 끊어졌습니다.",
    created: "새 키를 만들었습니다. 다른 PC로 복사하세요.",
    imported: "키를 가져왔습니다. 이제 다른 PC와 서로 접속하고 공유할 수 있습니다.",
    same_key: "이미 저장된 키입니다.",
    removed: "키를 삭제했습니다.",
    nothing_removed: "저장된 키가 없습니다.",
    copied: "복사했습니다. 1분 뒤 클립보드에서 지워집니다.",
    copy_failed: "클립보드를 사용할 수 없습니다. 잠시 후 복사를 다시 눌러 보세요.",
    import_empty: "먼저 입력란에 키를 붙여넣으세요.",
    bad_key: |e| format!("올바른 키가 아닙니다: {e}"),
    key_failed: |e| format!("키를 저장하지 못했습니다: {e}"),
};

/// Korean when the Windows display language is Korean; `SAFE_RDP_LANG` overrides.
fn use_korean() -> bool {
    match std::env::var("SAFE_RDP_LANG").as_deref() {
        Ok(l) if l.starts_with("ko") => true,
        Ok(l) if l.starts_with("en") => false,
        _ => u32::from(unsafe { GetUserDefaultUILanguage() }) & 0x3ff == LANG_KOREAN,
    }
}

// ---------------------------------------------------------------------------------------
// Options, settings and command lines (no Win32 here)

/// Everything starts off. As on the command line, clipboard and sound are the viewer's own
/// opt-in: that the host must allow them too protects nothing from a host that wants them.
#[derive(Clone, Debug, Default, PartialEq)]
struct ConnectOptions {
    fullscreen: bool,
    clipboard: bool,
    audio: bool,
    privacy: bool,
    view_only: bool,
    /// Index into `QUALITY_ARGS`.
    quality: usize,
    /// 0 = full resolution, n = 1/(n+1).
    scale: usize,
    /// Index into `MONITOR_ARGS`.
    monitor: usize,
}

#[derive(Clone, Debug, PartialEq)]
struct ShareOptions {
    control: bool,
    clipboard: bool,
    files: bool,
    audio: bool,
    privacy: bool,
}

impl Default for ShareOptions {
    fn default() -> Self {
        ShareOptions { control: true, clipboard: false, files: false, audio: false, privacy: false }
    }
}

/// Format of `launcher.txt`. Before version 2 the viewer's clipboard and sound started ticked
/// and were saved back after every connection, so an "on" saved then was not the user's choice.
const SETTINGS_VERSION: u32 = 2;

#[derive(Clone, Debug, Default, PartialEq)]
struct Settings {
    connect: ConnectOptions,
    share: ShareOptions,
    /// Pass `--enable-sas` when installing the service.
    sas: bool,
}

enum Field<'a> {
    Flag(&'a mut bool),
    Choice(&'a mut usize, usize),
}

impl Settings {
    fn fields(&mut self) -> [(&'static str, Field<'_>); 14] {
        let (c, s) = (&mut self.connect, &mut self.share);
        [
            ("fullscreen", Field::Flag(&mut c.fullscreen)),
            ("clipboard", Field::Flag(&mut c.clipboard)),
            ("sound", Field::Flag(&mut c.audio)),
            ("privacy", Field::Flag(&mut c.privacy)),
            ("view_only", Field::Flag(&mut c.view_only)),
            ("quality", Field::Choice(&mut c.quality, QUALITY_ARGS.len())),
            ("scale", Field::Choice(&mut c.scale, 4)),
            ("monitor", Field::Choice(&mut c.monitor, MONITOR_ARGS.len())),
            ("share_control", Field::Flag(&mut s.control)),
            ("share_clipboard", Field::Flag(&mut s.clipboard)),
            ("share_files", Field::Flag(&mut s.files)),
            ("share_sound", Field::Flag(&mut s.audio)),
            ("share_privacy", Field::Flag(&mut s.privacy)),
            ("service_sas", Field::Flag(&mut self.sas)),
        ]
    }

    /// Reads `key=value` lines; unknown keys and invalid values keep their defaults.
    fn parse(text: &str) -> Settings {
        let mut s = Settings::default();
        let mut fields = s.fields();
        let mut version = 0;
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            let (k, v) = (k.trim(), v.trim());
            if k == "version" {
                version = v.parse().unwrap_or(0);
                continue;
            }
            match fields.iter_mut().find(|(name, _)| *name == k).map(|(_, f)| f) {
                Some(Field::Flag(b)) => match v {
                    "1" => **b = true,
                    "0" => **b = false,
                    _ => {}
                },
                Some(Field::Choice(i, n)) => {
                    if let Some(x) = v.parse::<usize>().ok().filter(|x| x < n) {
                        **i = x;
                    }
                }
                None => {}
            }
        }
        if version < SETTINGS_VERSION {
            // Saved by a launcher that ticked them by default: back to off until the user opts in.
            let d = ConnectOptions::default();
            (s.connect.clipboard, s.connect.audio) = (d.clipboard, d.audio);
        }
        s
    }

    fn format(&self) -> String {
        let mut copy = self.clone();
        let mut out = format!("version={SETTINGS_VERSION}\n");
        for (name, f) in copy.fields() {
            let v = match f {
                Field::Flag(b) => usize::from(*b),
                Field::Choice(i, _) => *i,
            };
            out.push_str(&format!("{name}={v}\n"));
        }
        out
    }
}

/// A host name, MagicDNS name, IP literal or `host:port` (never something that looks like an option).
fn valid_host(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && !s.starts_with('-') && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._:[]%".contains(&b))
}

/// What to connect to for the text in the host field, and the name to show for it: a known
/// device by its address (so MagicDNS need not be on, and any name the list shows works,
/// "Beta box" included), else the text itself if it is a valid host. `None`: neither.
fn resolve_target<'a>(typed: &str, devices: impl IntoIterator<Item = &'a Device>) -> Option<(String, String)> {
    match devices.into_iter().find(|d| d.matches(typed)).and_then(|d| Some((d.address()?, d))) {
        Some((ip, d)) => Some((ip.to_string(), d.name.clone())),
        None => valid_host(typed).then(|| (typed.to_string(), typed.to_string())),
    }
}

/// Host field text for device `i` of the list: its name, or its address when another device
/// has the same name (`resolve_target` would pick the first of them).
fn picked_text(devices: &[Device], me: Option<&Device>, i: usize) -> Option<String> {
    let d = devices.get(i)?;
    let shared = devices.iter().chain(me).filter(|o| o.name.eq_ignore_ascii_case(&d.name)).count() > 1;
    Some(match d.address() {
        Some(ip) if shared => ip.to_string(),
        _ => d.name.clone(),
    })
}

fn parse_recent(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| valid_host(l)) {
        if !out.iter().any(|h| h.eq_ignore_ascii_case(line)) && out.len() < MAX_RECENT {
            out.push(line.to_string());
        }
    }
    out
}

/// Moves `host` to the front of the list, case-insensitively unique and bounded.
fn add_recent(list: &mut Vec<String>, host: &str) {
    if !valid_host(host) {
        return;
    }
    list.retain(|h| !h.eq_ignore_ascii_case(host));
    list.insert(0, host.to_string());
    list.truncate(MAX_RECENT);
}

fn viewer_args(target: &str, o: &ConnectOptions) -> Vec<String> {
    let mut a = vec!["connect".to_string(), target.to_string()];
    for (on, flag) in [
        (o.fullscreen, "--fullscreen"),
        (o.clipboard, "--clipboard"),
        (o.view_only, "--view-only"),
        (o.audio, "--audio"),
        (o.privacy, "--privacy"),
    ] {
        if on {
            a.push(flag.into());
        }
    }
    if let Some(q) = QUALITY_ARGS.get(o.quality).filter(|q| !q.is_empty()) {
        a.extend(["--quality".into(), q.to_string()]);
    }
    if (1..=3).contains(&o.scale) {
        a.extend(["--downscale".into(), (o.scale + 1).to_string()]);
    }
    if let Some(m) = MONITOR_ARGS.get(o.monitor).filter(|m| !m.is_empty()) {
        a.extend(["--monitor".into(), m.to_string()]);
    }
    a
}

fn share_flags(o: &ShareOptions) -> Vec<String> {
    [(!o.control, "--view-only"), (o.clipboard, "--clipboard"), (o.files, "--files"), (o.audio, "--audio"), (o.privacy, "--privacy")]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, f)| f.to_string())
        .collect()
}

fn host_args(o: &ShareOptions, bind: Option<IpAddr>, port: Option<u16>) -> Vec<String> {
    let mut a = vec!["host".to_string(), "--stop-on-eof".to_string()];
    a.extend(share_flags(o));
    if let Some(ip) = bind {
        a.extend(["--bind".into(), ip.to_string()]);
    }
    if let Some(p) = port {
        a.extend(["--port".into(), p.to_string()]);
    }
    a
}

/// Arguments for the elevated `service install` (plain tokens, so joining with spaces is safe).
/// `key`: the fingerprint of the stored key. The elevated process finds the key of the account
/// that approved the prompt, which for a standard user is another one: it refuses any other key.
fn service_install_args(o: &ShareOptions, sas: bool, key: &str) -> Vec<String> {
    let mut a = vec!["service".to_string(), "install".to_string(), "--expect-key".to_string(), key.to_string()];
    a.extend(share_flags(o));
    if sas {
        a.push("--enable-sas".into());
    }
    a
}

/// Arguments for the elevated `service rekey`, which leaves the service's options alone.
fn service_rekey_args(key: &str) -> Vec<String> {
    ["service", "rekey", "--expect-key", key].map(String::from).to_vec()
}

/// Which key the installed service has, as far as the fingerprint it recorded tells.
#[derive(Clone, Copy, Debug, PartialEq)]
enum SvcKey {
    /// The stored one.
    Mine,
    /// Another one (or no key is stored).
    Other,
    /// It recorded none (as an earlier safe-rdp did not), or that cannot be read.
    Unknown,
}

/// `recorded`: the fingerprint the service recorded; `mine`: that of the stored key.
fn svc_key(recorded: Option<&str>, mine: Option<&str>) -> SvcKey {
    match recorded {
        None => SvcKey::Unknown,
        Some(r) if mine == Some(r) => SvcKey::Mine,
        Some(_) => SvcKey::Other,
    }
}

/// After the stored key was replaced (`present`) or removed: what gives the service, whose key is
/// `key`, the stored one or removes it. A reinstall while its key cannot be told: then an earlier
/// safe-rdp, which recorded none, may have installed it, and its program is that version too.
fn svc_key_update(present: bool, key: SvcKey) -> SvcOp {
    match (present, key) {
        (false, _) => SvcOp::Remove,
        (true, SvcKey::Unknown) => SvcOp::Install,
        (true, SvcKey::Other | SvcKey::Mine) => SvcOp::Rekey,
    }
}

/// Whether the service, as found after a service command that did not succeed (`svc`, whose key
/// is `key`), may still accept another key than the stored one.
fn svc_lacks_key(svc: Svc, key: SvcKey) -> bool {
    svc != Svc::NotInstalled && key != SvcKey::Mine
}

/// The Key-tab note that the service keeps a key other than the stored one (`stored`: a key is
/// stored), worded after the button the Share tab shows for it (`key_update_due`): Update key
/// for a service known to have another key, Reinstall otherwise.
fn svc_note(t: &Text, stored: bool, key: SvcKey) -> &'static str {
    if stored && key == SvcKey::Other { t.svc_key_note } else { t.svc_reinstall_note }
}

/// Key-tab message `text` without the note (`svc_note`) it ends with; `None` if it has none.
fn without_svc_note<'a>(t: &Text, text: &'a str) -> Option<&'a str> {
    [t.svc_key_note, t.svc_reinstall_note].into_iter().find_map(|n| text.strip_suffix(n.trim())).map(str::trim_end)
}

/// After the stored key changed from the one with fingerprint `old` to `new` (None: removed):
/// whether the service, which recorded `recorded`, should get the new key or be removed.
fn svc_needs_update(recorded: Option<&str>, old: Option<&str>, new: Option<&str>) -> bool {
    match (recorded, new) {
        (Some(r), Some(n)) => r != n,
        // Unless it has some key that was never the removed one.
        (Some(r), None) => old.is_none_or(|o| o == r),
        (None, _) => true,
    }
}

/// `SAFE_RDP_LAUNCHER_BIND` / `SAFE_RDP_LAUNCHER_PORT`, for testing sharing on another address.
fn sharing_overrides(bind: Option<&str>, port: Option<&str>) -> Result<(Option<IpAddr>, Option<u16>), String> {
    let bind = match bind.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => Some(v.parse().map_err(|_| format!("SAFE_RDP_LAUNCHER_BIND: '{v}' is not an IP address"))?),
        None => None,
    };
    let port = match port.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => Some(v.parse().ok().filter(|p| *p != 0).ok_or_else(|| format!("SAFE_RDP_LAUNCHER_PORT: '{v}' is not a port"))?),
        None => None,
    };
    Ok((bind, port))
}

/// Splits a log line written by `log!` ("YYYY-MM-DD HH:MM:SS message") into time and message.
fn split_log(line: &str) -> (&str, &str) {
    let b = line.as_bytes();
    let stamped = b.len() >= 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b' '
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b' '
        && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18].iter().all(|&i| b[i].is_ascii_digit());
    if stamped { (&line[11..19], &line[20..]) } else { ("", line) }
}

#[derive(Debug, PartialEq)]
enum HostEvent {
    Listening(String),
    WaitingForTailscale,
    SessionStarted(String),
    SessionEnded,
    Error(String),
}

/// Recognises the host's status lines (`host.rs` and `main.rs` wording).
fn host_event(msg: &str) -> Option<HostEvent> {
    let first_word = |s: &str| s.split_whitespace().next().unwrap_or("").to_string();
    if let Some(rest) = msg.strip_prefix("safe-rdp host listening on ") {
        return Some(HostEvent::Listening(first_word(rest)));
    }
    if msg.starts_with("waiting for Tailscale") {
        return Some(HostEvent::WaitingForTailscale);
    }
    if let Some(rest) = msg.strip_prefix("session started: ") {
        return Some(HostEvent::SessionStarted(first_word(rest)));
    }
    if msg.starts_with("session ended: ") {
        return Some(HostEvent::SessionEnded);
    }
    msg.strip_prefix("error: ").map(|e| HostEvent::Error(e.to_string()))
}

#[derive(Debug, PartialEq)]
enum ViewerLine {
    Connected,
    Error(String),
}

fn viewer_line(msg: &str) -> Option<ViewerLine> {
    if msg.starts_with("connected to ") {
        return Some(ViewerLine::Connected);
    }
    msg.strip_prefix("error: ").map(|e| ViewerLine::Error(e.to_string()))
}

/// "name (ip)" for a listening address; the port is shown only when it is not the default.
fn listen_label(addr: &str, me: Option<&str>) -> String {
    let Ok(sa) = addr.parse::<SocketAddr>() else { return addr.to_string() };
    let ip = match sa.port() {
        DEFAULT_PORT => sa.ip().to_string(),
        p if sa.is_ipv6() => format!("[{}]:{p}", sa.ip()),
        p => format!("{}:{p}", sa.ip()),
    };
    match me {
        Some(name) if !sa.ip().is_loopback() && !name.is_empty() => format!("{name} ({ip})"),
        _ => ip,
    }
}

/// The device name for a peer address ("ip:port"), or its IP.
fn peer_label(peer: &str, devices: &[Device]) -> String {
    let ip = peer.parse::<SocketAddr>().map(|s| s.ip()).or_else(|_| peer.parse::<IpAddr>());
    match ip {
        Ok(ip) => {
            let ip = match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
                v4 => v4,
            };
            devices.iter().find(|d| d.ips.contains(&ip)).map(|d| d.name.clone()).unwrap_or_else(|| ip.to_string())
        }
        Err(_) => peer.to_string(),
    }
}

/// `%APPDATA%\safe-rdp`, next to the key.
fn data_dir() -> Option<PathBuf> {
    keystore::user_key_path().ok()?.parent().map(PathBuf::from)
}

fn read_data_file(name: &str) -> String {
    let Some(path) = data_dir().map(|d| d.join(name)) else { return String::new() };
    // These files are tiny; refuse anything unreasonable.
    match std::fs::metadata(&path) {
        Ok(m) if m.len() <= 64 << 10 => std::fs::read_to_string(&path).unwrap_or_default(),
        _ => String::new(),
    }
}

fn write_data_file(name: &str, text: &str) {
    if let Some(dir) = data_dir() {
        let _ = std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(dir.join(name), text));
    }
}

/// The stored key file as it is (a DPAPI blob, never the key itself), to notice that it changed.
fn read_key_file() -> std::io::Result<Vec<u8>> {
    let path = keystore::user_key_path().map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut data = Vec::new();
    // A key file is a few hundred bytes; never read more than enough to see that it differs.
    std::fs::File::open(path)?.take(64 << 10).read_to_end(&mut data)?;
    Ok(data)
}

/// Whether the key file now differs from `started`, the file a running host was started with.
/// A file caught empty in the middle of being rewritten, or one that cannot be read right now,
/// is no change (yet); a file that is gone is.
fn key_file_changed(started: &[u8], now: &std::io::Result<Vec<u8>>) -> bool {
    match now {
        Ok(data) => !data.is_empty() && data.as_slice() != started,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// After the stored key changed: the host generation whose exit should start sharing again,
/// now with the stored key. That is the host running now, or the one an earlier restart still
/// waits for; with no key left, nothing restarts.
fn restart_after_key_change(present: bool, running: Option<u64>, pending: Option<u64>) -> Option<u64> {
    if present { running.or(pending) } else { None }
}

/// Overwrites a string's bytes (for key text) before it is freed.
fn wipe_string(s: &mut str) {
    // SAFETY: zero bytes are valid UTF-8.
    wipe(unsafe { s.as_bytes_mut() });
}

fn wipe_wide(w: &mut [u16]) {
    for c in w.iter_mut() {
        unsafe { std::ptr::write_volatile(c, 0) };
    }
}

// ---------------------------------------------------------------------------------------
// Background work

enum Event {
    Devices(Result<tailscale::Status, Problem>),
    HostLine(u64, String),
    HostExit(u64),
    /// A host that `stop_sharing` stopped has exited (its port is free again).
    HostStopped(u64),
    Viewer { host: String, entry: String, update: ViewerUpdate },
    Service(ServiceInfo),
    ServiceDone { op: SvcOp, result: Result<u32, Elevation> },
}

/// What a check of the service found.
struct ServiceInfo {
    /// `service status`.
    status: Result<String, String>,
    /// The fingerprint the service recorded for its key (unreadable counts as none).
    key: Option<String>,
    /// The fingerprint of the stored key.
    mine: Option<String>,
}

fn service_info() -> ServiceInfo {
    ServiceInfo {
        status: service::status().map_err(|e| e.to_string()),
        key: service::key_fingerprint().ok().flatten(),
        mine: keystore::user_key_fingerprint(),
    }
}

/// An elevated service command.
#[derive(Clone, Copy, Debug, PartialEq)]
enum SvcOp {
    /// `service install` with the options ticked under "While sharing, allow".
    Install,
    /// `service rekey`: the stored key, nothing else.
    Rekey,
    Remove,
}

enum ViewerUpdate {
    Connected,
    /// `error` is set when the viewer failed (empty if it gave no reason).
    Exited {
        connected: bool,
        error: Option<String>,
    },
}

enum Elevation {
    Cancelled,
    Failed(String),
}

/// Sends events to the window thread and wakes it.
#[derive(Clone)]
struct Notifier {
    tx: Sender<Event>,
    hwnd: usize,
}

impl Notifier {
    fn send(&self, e: Event) {
        if self.tx.send(e).is_ok() {
            unsafe { PostMessageW(self.hwnd as HWND, WM_APP_EVENT, 0, 0) };
        }
    }
}

fn spawn_thread(name: &str, f: impl FnOnce() + Send + 'static) -> bool {
    std::thread::Builder::new().name(name.into()).spawn(f).is_ok()
}

/// Calls `f` for each line (lossy UTF-8, bounded length) until EOF.
fn for_each_line(r: impl Read, mut f: impl FnMut(String)) {
    let mut r = BufReader::new(r);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match (&mut r).take(MAX_LINE).read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => f(String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string()),
        }
    }
}

/// Starts this executable without a console, with stderr piped (and stdin, if asked).
///
/// `DETACHED_PROCESS` rather than `CREATE_NO_WINDOW`: the latter gives the child a hidden console
/// of its own, which the viewer takes for an Explorer launch and then reports errors in its own
/// message box as well. Without a console every message reaches us through stderr.
fn spawn_self(args: &[String], stdin: bool) -> std::io::Result<Child> {
    Command::new(std::env::current_exe()?)
        .args(args)
        .stdin(if stdin { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .creation_flags(DETACHED_PROCESS)
        .spawn()
}

struct HostProc {
    child: Child,
    stdin: Option<ChildStdin>,
}

/// Closes the host's stdin (a cooperating host exits cleanly), then kills it after `grace`.
fn stop_host(mut p: HostProc, grace: Duration) {
    drop(p.stdin.take());
    let t = Instant::now();
    while t.elapsed() < grace {
        if let Ok(Some(_)) = p.child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = p.child.kill();
    let _ = p.child.wait();
}

fn kill_on_close_job() -> HANDLE {
    unsafe {
        let job = CreateJobObjectW(null(), null());
        if !job.is_null() {
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
        }
        job
    }
}

/// Runs this executable elevated (UAC prompt) with `params` and waits for its exit code.
fn run_elevated(owner: usize, params: &str) -> Result<u32, Elevation> {
    let exe = std::env::current_exe().map_err(|e| Elevation::Failed(e.to_string()))?;
    let (verb, file, params) = (wide("runas"), wide(&exe.to_string_lossy()), wide(params));
    unsafe {
        let com = CoInitializeEx(null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32);
        let mut sei: SHELLEXECUTEINFOW = std::mem::zeroed();
        sei.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        sei.hwnd = owner as HWND;
        sei.lpVerb = verb.as_ptr();
        sei.lpFile = file.as_ptr();
        sei.lpParameters = params.as_ptr();
        sei.nShow = SW_HIDE;
        let r = if ShellExecuteExW(&mut sei) == 0 {
            match GetLastError() {
                ERROR_CANCELLED => Err(Elevation::Cancelled),
                e => Err(Elevation::Failed(std::io::Error::from_raw_os_error(e as i32).to_string())),
            }
        } else if sei.hProcess.is_null() {
            Err(Elevation::Failed("no process was started".into()))
        } else {
            WaitForSingleObject(sei.hProcess, INFINITE);
            let mut code = 0u32;
            GetExitCodeProcess(sei.hProcess, &mut code);
            CloseHandle(sei.hProcess);
            Ok(code)
        };
        if com >= 0 {
            CoUninitialize();
        }
        r
    }
}

// ---------------------------------------------------------------------------------------
// Look

fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    r as u32 | (g as u32) << 8 | (b as u32) << 16
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Tone {
    Normal,
    Muted,
    Accent,
    Good,
    Warn,
    Bad,
}

#[derive(Clone, Copy, PartialEq)]
enum Surface {
    Page,
    Sidebar,
    Card,
    Info,
}

#[derive(Clone, Copy)]
struct Palette {
    page: COLORREF,
    sidebar: COLORREF,
    separator: COLORREF,
    card: COLORREF,
    card_border: COLORREF,
    info: COLORREF,
    info_border: COLORREF,
    text: COLORREF,
    muted: COLORREF,
    accent: COLORREF,
    accent_hot: COLORREF,
    accent_down: COLORREF,
    danger: COLORREF,
    danger_hot: COLORREF,
    danger_down: COLORREF,
    disabled: COLORREF,
    on_accent: COLORREF,
    good: COLORREF,
    warn: COLORREF,
    bad: COLORREF,
    nav_hot: COLORREF,
    nav_selected: COLORREF,
}

impl Palette {
    fn light() -> Palette {
        Palette {
            page: rgb(0xff, 0xff, 0xff),
            sidebar: rgb(0xf3, 0xf3, 0xf3),
            separator: rgb(0xe5, 0xe5, 0xe5),
            card: rgb(0xf7, 0xf7, 0xf7),
            card_border: rgb(0xe5, 0xe5, 0xe5),
            info: rgb(0xef, 0xf6, 0xfc),
            info_border: rgb(0xc7, 0xe0, 0xf4),
            text: rgb(0x1b, 0x1b, 0x1b),
            muted: rgb(0x5f, 0x5f, 0x5f),
            accent: rgb(0x00, 0x5f, 0xb8),
            accent_hot: rgb(0x19, 0x6e, 0xbf),
            accent_down: rgb(0x33, 0x7f, 0xc6),
            danger: rgb(0xc4, 0x2b, 0x1c),
            danger_hot: rgb(0xca, 0x40, 0x33),
            danger_down: rgb(0xd0, 0x55, 0x49),
            disabled: rgb(0xc5, 0xc5, 0xc5),
            on_accent: rgb(0xff, 0xff, 0xff),
            good: rgb(0x0f, 0x7b, 0x0f),
            warn: rgb(0x9d, 0x5d, 0x00),
            bad: rgb(0xc4, 0x2b, 0x1c),
            nav_hot: rgb(0xea, 0xea, 0xea),
            nav_selected: rgb(0xe3, 0xe3, 0xe3),
        }
    }

    /// System colours when a high-contrast theme is on.
    fn high_contrast() -> Palette {
        let sys = |i| unsafe { GetSysColor(i) };
        let (window, text, face, hi, hi_text, gray) = (
            sys(COLOR_WINDOW),
            sys(COLOR_WINDOWTEXT),
            sys(COLOR_BTNFACE),
            sys(COLOR_HIGHLIGHT),
            sys(COLOR_HIGHLIGHTTEXT),
            sys(COLOR_GRAYTEXT),
        );
        Palette {
            page: window,
            sidebar: face,
            separator: text,
            card: window,
            card_border: text,
            info: window,
            info_border: text,
            text,
            muted: text,
            accent: hi,
            accent_hot: hi,
            accent_down: hi,
            danger: hi,
            danger_hot: hi,
            danger_down: hi,
            disabled: gray,
            on_accent: hi_text,
            good: text,
            warn: text,
            bad: text,
            nav_hot: hi,
            nav_selected: hi,
        }
    }

    fn current() -> Palette {
        let mut hc: HIGHCONTRASTW = unsafe { std::mem::zeroed() };
        hc.cbSize = size_of::<HIGHCONTRASTW>() as u32;
        let ok = unsafe { SystemParametersInfoW(SPI_GETHIGHCONTRAST, hc.cbSize, &mut hc as *mut _ as *mut _, 0) } != 0;
        if ok && hc.dwFlags & HCF_HIGHCONTRASTON != 0 { Palette::high_contrast() } else { Palette::light() }
    }

    fn tone(&self, t: Tone) -> COLORREF {
        match t {
            Tone::Normal => self.text,
            Tone::Muted => self.muted,
            Tone::Accent => self.accent,
            Tone::Good => self.good,
            Tone::Warn => self.warn,
            Tone::Bad => self.bad,
        }
    }

    fn surface(&self, s: Surface) -> COLORREF {
        match s {
            Surface::Page => self.page,
            Surface::Sidebar => self.sidebar,
            Surface::Card => self.card,
            Surface::Info => self.info,
        }
    }
}

/// One solid brush per surface, for WM_CTLCOLOR*.
struct Brushes([HBRUSH; 4]);

impl Brushes {
    fn new(p: &Palette) -> Brushes {
        let b = |c| unsafe { CreateSolidBrush(c) };
        Brushes([b(p.page), b(p.sidebar), b(p.card), b(p.info)])
    }

    fn get(&self, s: Surface) -> HBRUSH {
        self.0[s as usize]
    }
}

impl Drop for Brushes {
    fn drop(&mut self) {
        for b in self.0 {
            unsafe { DeleteObject(b) };
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum FontKind {
    Body,
    Small,
    Bold,
    Section,
    Title,
    Brand,
    Status,
    Mono,
    Icon,
}

struct Fonts([HFONT; 9]);

impl Fonts {
    fn new(dpi: u32, korean: bool) -> Fonts {
        let ui = if korean { "Malgun Gothic" } else { "Segoe UI" };
        // (size in tenths of a point, weight, face) in FontKind order.
        let spec: [(i32, u32, &str); 9] = [
            (100, FW_NORMAL, ui),
            (90, FW_NORMAL, ui),
            (100, FW_SEMIBOLD, ui),
            (110, FW_SEMIBOLD, ui),
            (180, FW_SEMIBOLD, ui),
            (140, FW_SEMIBOLD, ui),
            (120, FW_SEMIBOLD, ui),
            (105, FW_NORMAL, "Consolas"),
            (120, FW_NORMAL, "Segoe MDL2 Assets"),
        ];
        Fonts(spec.map(|(size, weight, face)| unsafe {
            let face = wide(face);
            CreateFontW(
                -mul_div(size, dpi as i32, 720),
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
                (DEFAULT_PITCH | FF_DONTCARE) as u32,
                face.as_ptr(),
            )
        }))
    }

    fn get(&self, k: FontKind) -> HFONT {
        self.0[k as usize]
    }
}

impl Drop for Fonts {
    fn drop(&mut self) {
        for f in self.0 {
            unsafe { DeleteObject(f) };
        }
    }
}

// ---------------------------------------------------------------------------------------
// Window state

#[derive(Clone, Copy, PartialEq, Debug)]
enum Page {
    Connect,
    Share,
    Key,
}

const PAGES: [Page; 3] = [Page::Connect, Page::Share, Page::Key];
const NAV_GLYPHS: [&str; 3] = ["\u{e703}", "\u{e72d}", "\u{e192}"];

#[derive(Clone, Copy, PartialEq)]
enum Banner {
    Welcome,
    NeedKey,
}

#[derive(Clone, Copy, PartialEq)]
enum KeyState {
    Missing,
    Present,
    Unreadable,
}

fn key_state() -> KeyState {
    match keystore::user_key_path() {
        Ok(p) if p.exists() => match keystore::load_user_key() {
            Ok(_) => KeyState::Present,
            Err(_) => KeyState::Unreadable,
        },
        _ => KeyState::Missing,
    }
}

#[derive(Clone, PartialEq, Debug)]
enum Share {
    Off,
    Starting,
    WaitingForTailscale,
    Ready(String),
    Connected(String),
    Stopping,
    Failed(String),
}

#[derive(Clone, Copy, PartialEq)]
enum Svc {
    Checking,
    NotInstalled,
    Running,
    Stopped,
    Changing,
    Unknown,
}

impl Svc {
    fn installed(self) -> bool {
        matches!(self, Svc::Running | Svc::Stopped | Svc::Changing)
    }
}

struct State {
    banner: Option<Banner>,
    key: KeyState,
    key_shown: bool,
    clip_seq: Option<u32>,
    /// Peers in list order.
    devices: Vec<Device>,
    me: Option<Device>,
    ts_busy: bool,
    ts_updated: Option<Instant>,
    recent: Vec<String>,
    host: Option<HostProc>,
    host_gen: u64,
    /// The key file as it was just before the running host read it (`read_key_file`).
    host_key: Option<Vec<u8>>,
    /// The fingerprint of the key stored then: a file that changed but holds the same key (saved
    /// again: a fresh DPAPI blob) is no key change.
    host_key_fp: Option<String>,
    /// Start sharing again once the host of this generation has exited: it was stopped because
    /// the stored key changed.
    restart_after: Option<u64>,
    host_error: Option<String>,
    listen: Option<String>,
    share: Share,
    share_view_only: bool,
    log: VecDeque<String>,
    svc: Svc,
    svc_busy: bool,
    /// The fingerprint the installed service recorded for the key it was given, and that of the
    /// stored key, both as of the last check of the service (`ServiceInfo`).
    svc_key: Option<String>,
    key_fp: Option<String>,
    /// The tone of the Key-tab message without the note it ends with (`set_svc_note`).
    key_tone: Tone,
}

struct Controls {
    brand: HWND,
    tagline: HWND,
    nav: [HWND; 3],
    version: HWND,

    c_title: HWND,
    c_sub: HWND,
    c_devices: HWND,
    c_refresh: HWND,
    c_list: HWND,
    c_ts: HWND,
    c_host_title: HWND,
    c_host: HWND,
    c_connect: HWND,
    c_msg: HWND,
    c_options: HWND,
    c_fullscreen: HWND,
    c_clipboard: HWND,
    c_sound: HWND,
    c_privacy: HWND,
    c_view_only: HWND,
    c_quality_label: HWND,
    c_quality: HWND,
    c_scale_label: HWND,
    c_scale: HWND,
    c_monitor_label: HWND,
    c_monitor: HWND,

    s_title: HWND,
    s_sub: HWND,
    s_status: HWND,
    s_detail: HWND,
    s_toggle: HWND,
    s_allow: HWND,
    s_control: HWND,
    s_clipboard: HWND,
    s_files: HWND,
    s_sound: HWND,
    s_privacy: HWND,
    s_activity: HWND,
    s_log: HWND,
    s_svc: HWND,
    s_svc_status: HWND,
    s_install: HWND,
    s_uninstall: HWND,
    s_sas: HWND,
    s_svc_text: HWND,

    k_title: HWND,
    k_sub: HWND,
    k_banner: HWND,
    k_status: HWND,
    k_about: HWND,
    k_create: HWND,
    k_show: HWND,
    k_remove: HWND,
    k_import_title: HWND,
    k_import_text: HWND,
    k_import: HWND,
    k_shown_title: HWND,
    k_shown: HWND,
    k_copy: HWND,
    k_hide: HWND,
    k_warning: HWND,
    k_msg: HWND,

    /// Page of every control (None: always visible), in creation (= tab) order.
    pages: Vec<(HWND, Option<Page>)>,
    fonts: Vec<(HWND, FontKind)>,
    surfaces: Vec<(HWND, Surface)>,
}

impl Controls {
    fn surface(&self, h: HWND) -> Surface {
        self.surfaces.iter().find(|(c, _)| *c == h).map(|(_, s)| *s).unwrap_or(Surface::Page)
    }

    fn key_display(&self) -> [HWND; 5] {
        [self.k_shown_title, self.k_shown, self.k_copy, self.k_hide, self.k_warning]
    }

    fn connect_options(&self) -> [HWND; 5] {
        [self.c_fullscreen, self.c_clipboard, self.c_sound, self.c_privacy, self.c_view_only]
    }

    fn share_options(&self) -> [HWND; 5] {
        [self.s_control, self.s_clipboard, self.s_files, self.s_sound, self.s_privacy]
    }
}

/// Creates child controls and records their page, font and background.
struct Builder {
    parent: HWND,
    hinst: HINSTANCE,
    page: Option<Page>,
    surface: Surface,
    pages: Vec<(HWND, Option<Page>)>,
    fonts: Vec<(HWND, FontKind)>,
    surfaces: Vec<(HWND, Surface)>,
    tones: HashMap<usize, Tone>,
}

impl Builder {
    fn make(&mut self, class: PCWSTR, text: &str, style: u32, ex: u32, id: u16, font: FontKind) -> HWND {
        let t = wide(text);
        let h = unsafe {
            CreateWindowExW(ex, class, t.as_ptr(), WS_CHILD | style, 0, 0, 0, 0, self.parent, id as usize as HMENU, self.hinst, null())
        };
        self.pages.push((h, self.page));
        self.fonts.push((h, font));
        if self.surface != Surface::Page {
            self.surfaces.push((h, self.surface));
        }
        h
    }

    /// Single-line text, cut with an ellipsis when too long.
    fn label(&mut self, text: &str, font: FontKind, tone: Tone) -> HWND {
        let h = self.make(w!("STATIC"), text, SS_LEFTNOWORDWRAP | SS_ENDELLIPSIS | SS_NOPREFIX, 0, 0, font);
        self.tones.insert(h as usize, tone);
        h
    }

    /// Wrapping text.
    fn para(&mut self, text: &str, font: FontKind, tone: Tone) -> HWND {
        let h = self.make(w!("STATIC"), text, SS_LEFT | SS_NOPREFIX, 0, 0, font);
        self.tones.insert(h as usize, tone);
        h
    }

    fn button(&mut self, text: &str, id: u16) -> HWND {
        self.make(w!("BUTTON"), text, WS_TABSTOP | BS_PUSHBUTTON as u32, 0, id, FontKind::Body)
    }

    /// Owner-drawn button (navigation item or accent-coloured action).
    fn drawn(&mut self, text: &str, id: u16, font: FontKind) -> HWND {
        let h = self.make(w!("BUTTON"), text, WS_TABSTOP | BS_OWNERDRAW as u32, 0, id, font);
        unsafe { SetWindowSubclass(h, Some(hover_proc), 1, 0) };
        h
    }

    fn check(&mut self, text: &str, id: u16) -> HWND {
        self.make(w!("BUTTON"), text, WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, id, FontKind::Body)
    }

    fn dropdown(&mut self, id: u16, items: &[&str]) -> HWND {
        let h = self.make(w!("COMBOBOX"), "", WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32, 0, id, FontKind::Body);
        for item in items {
            let t = wide(item);
            unsafe { SendMessageW(h, CB_ADDSTRING, 0, t.as_ptr() as LPARAM) };
        }
        unsafe { SendMessageW(h, CB_SETCURSEL, 0, 0) };
        h
    }

    fn edit(&mut self, id: u16, style: u32, cue: &str, font: FontKind) -> HWND {
        let h = self.make(w!("EDIT"), "", WS_TABSTOP | ES_AUTOHSCROLL as u32 | style, WS_EX_CLIENTEDGE, id, font);
        if !cue.is_empty() {
            let t = wide(cue);
            unsafe { SendMessageW(h, EM_SETCUEBANNER, 1, t.as_ptr() as LPARAM) };
        }
        h
    }
}

fn create_controls(parent: HWND, t: &Text) -> (Controls, HashMap<usize, Tone>) {
    let hinst = unsafe { GetModuleHandleW(null()) };
    let mut b = Builder {
        parent,
        hinst,
        page: None,
        surface: Surface::Sidebar,
        pages: vec![],
        fonts: vec![],
        surfaces: vec![],
        tones: HashMap::new(),
    };
    use FontKind::*;

    let brand = b.label("safe-rdp", Brand, Tone::Normal);
    let tagline = b.label(t.tagline, Small, Tone::Muted);
    let nav = [0, 1, 2].map(|i| b.drawn(t.nav[i], ID_NAV + i as u16, Body));
    let version = b.label(&format!("v{}", env!("CARGO_PKG_VERSION")), Small, Tone::Muted);

    b.surface = Surface::Page;
    b.page = Some(Page::Connect);
    let c_title = b.label(t.connect_title, Title, Tone::Normal);
    let c_sub = b.label(t.connect_sub, Body, Tone::Muted);
    let c_host_title = b.label(t.host_title, Section, Tone::Normal);
    let c_host = b.make(w!("COMBOBOX"), "", WS_TABSTOP | WS_VSCROLL | (CBS_DROPDOWN | CBS_AUTOHSCROLL) as u32, 0, ID_HOST, Body);
    let c_connect = b.drawn(t.connect, ID_CONNECT, Bold);
    let c_msg = b.label("", Body, Tone::Muted);
    let c_devices = b.label(t.devices, Section, Tone::Normal);
    let c_refresh = b.button(t.refresh, ID_REFRESH);
    let c_list = b.make(
        WC_LISTVIEWW,
        "",
        WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER,
        WS_EX_CLIENTEDGE,
        ID_LIST,
        Body,
    );
    let c_ts = b.label("", Small, Tone::Muted);
    let c_options = b.label(t.options, Section, Tone::Normal);
    let c_fullscreen = b.check(t.opt_fullscreen, ID_FULLSCREEN);
    let c_clipboard = b.check(t.opt_clipboard, ID_CLIPBOARD);
    let c_sound = b.check(t.opt_sound, ID_SOUND);
    let c_privacy = b.check(t.opt_privacy, ID_PRIVACY);
    let c_view_only = b.check(t.opt_view_only, ID_VIEW_ONLY);
    let c_quality_label = b.label(t.quality, Body, Tone::Normal);
    let c_quality = b.dropdown(ID_QUALITY, &t.qualities);
    let c_scale_label = b.label(t.scale, Body, Tone::Normal);
    let c_scale = b.dropdown(ID_SCALE, &t.scales);
    let c_monitor_label = b.label(t.monitor, Body, Tone::Normal);
    let c_monitor = b.dropdown(ID_MONITOR, &t.monitors);

    b.page = Some(Page::Share);
    let s_title = b.label(t.share_title, Title, Tone::Normal);
    let s_sub = b.label(t.share_sub, Body, Tone::Muted);
    b.surface = Surface::Card;
    let s_status = b.label("", Status, Tone::Muted);
    let s_detail = b.para("", Body, Tone::Muted);
    let s_toggle = b.drawn(t.start, ID_SHARE, Bold);
    b.surface = Surface::Page;
    let s_allow = b.label(t.allow, Section, Tone::Normal);
    let s_control = b.check(t.allow_control, ID_ALLOW_CONTROL);
    let s_clipboard = b.check(t.allow_clipboard, ID_ALLOW_CLIPBOARD);
    let s_files = b.check(t.allow_files, ID_ALLOW_FILES);
    let s_sound = b.check(t.allow_sound, ID_ALLOW_SOUND);
    let s_privacy = b.check(t.allow_privacy, ID_ALLOW_PRIVACY);
    let s_activity = b.label(t.activity, Section, Tone::Normal);
    let s_log = b.make(
        w!("EDIT"),
        "",
        WS_TABSTOP | WS_VSCROLL | (ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL) as u32,
        WS_EX_CLIENTEDGE,
        ID_LOG,
        Small,
    );
    let s_svc = b.label(t.svc_title, Section, Tone::Normal);
    let s_svc_status = b.label("", Body, Tone::Muted);
    let s_install = b.button(t.install, ID_INSTALL);
    let s_uninstall = b.button(t.uninstall, ID_UNINSTALL);
    let s_sas = b.check(t.svc_sas, ID_SAS);
    let s_svc_text = b.para(t.svc_text, Small, Tone::Muted);

    b.page = Some(Page::Key);
    let k_title = b.label(t.key_title, Title, Tone::Normal);
    let k_sub = b.para(t.key_sub, Body, Tone::Muted);
    b.surface = Surface::Info;
    let k_banner = b.para("", Body, Tone::Normal);
    b.surface = Surface::Page;
    let k_status = b.para("", Bold, Tone::Muted);
    let k_about = b.para(t.key_about, Body, Tone::Muted);
    let k_create = b.drawn(t.create, ID_CREATE, Bold);
    let k_show = b.button(t.show, ID_SHOW);
    let k_remove = b.button(t.remove, ID_REMOVE);
    let k_import_title = b.label(t.import_title, Section, Tone::Normal);
    let k_import_text = b.edit(ID_IMPORT_TEXT, ES_PASSWORD as u32, t.import_cue, Body);
    let k_import = b.button(t.import, ID_IMPORT);
    b.surface = Surface::Card;
    let k_shown_title = b.label(t.shown_title, Section, Tone::Normal);
    let k_warning = b.para(t.key_warning, Body, Tone::Warn);
    let k_copy = b.button(t.copy, ID_COPY);
    let k_hide = b.button(t.hide, ID_HIDE);
    b.surface = Surface::Page;
    let k_shown = b.edit(ID_KEY_TEXT, ES_READONLY as u32, "", Mono);
    unsafe { SetWindowSubclass(k_shown, Some(key_edit_proc), KEY_EDIT_SUBCLASS, 0) };
    b.surface = Surface::Page;
    let k_msg = b.para("", Body, Tone::Muted);

    unsafe {
        SendMessageW(c_list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER) as LPARAM);
        SetWindowTheme(c_list, w!("Explorer"), null());
        for (i, name) in t.columns.iter().enumerate() {
            let mut text = wide(name);
            let mut col: LVCOLUMNW = std::mem::zeroed();
            col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
            col.cx = 100;
            col.pszText = text.as_mut_ptr();
            col.iSubItem = i as i32;
            SendMessageW(c_list, LVM_INSERTCOLUMNW, i, &col as *const _ as LPARAM);
        }
        let cue = wide(t.host_cue);
        SendMessageW(c_host, CB_SETCUEBANNER, 0, cue.as_ptr() as LPARAM);
        SendMessageW(c_host, CB_LIMITTEXT, 253, 0);
        SendMessageW(k_import_text, EM_SETLIMITTEXT, 200, 0);
        SendMessageW(s_install, BCM_SETSHIELD, 0, 1);
        SendMessageW(s_uninstall, BCM_SETSHIELD, 0, 1);
    }

    let c = Controls {
        brand,
        tagline,
        nav,
        version,
        c_title,
        c_sub,
        c_devices,
        c_refresh,
        c_list,
        c_ts,
        c_host_title,
        c_host,
        c_connect,
        c_msg,
        c_options,
        c_fullscreen,
        c_clipboard,
        c_sound,
        c_privacy,
        c_view_only,
        c_quality_label,
        c_quality,
        c_scale_label,
        c_scale,
        c_monitor_label,
        c_monitor,
        s_title,
        s_sub,
        s_status,
        s_detail,
        s_toggle,
        s_allow,
        s_control,
        s_clipboard,
        s_files,
        s_sound,
        s_privacy,
        s_activity,
        s_log,
        s_svc,
        s_svc_status,
        s_install,
        s_uninstall,
        s_sas,
        s_svc_text,
        k_title,
        k_sub,
        k_banner,
        k_status,
        k_about,
        k_create,
        k_show,
        k_remove,
        k_import_title,
        k_import_text,
        k_import,
        k_shown_title,
        k_shown,
        k_copy,
        k_hide,
        k_warning,
        k_msg,
        pages: b.pages,
        fonts: b.fonts,
        surfaces: b.surfaces,
    };
    (c, b.tones)
}

struct App {
    hwnd: HWND,
    t: &'static Text,
    korean: bool,
    c: Controls,
    dpi: Cell<u32>,
    fonts: RefCell<Fonts>,
    pal: Cell<Palette>,
    brushes: RefCell<Brushes>,
    icons: Cell<[HICON; 2]>,
    tones: RefCell<HashMap<usize, Tone>>,
    /// Card backgrounds of the current page, in client pixels.
    decor: RefCell<Vec<(RECT, Surface)>>,
    page: Cell<Page>,
    /// The share button shows "Stop" (red) while true.
    sharing: Cell<bool>,
    /// Set while the device list is being refilled (ignore its selection notifications).
    filling: Cell<bool>,
    last_focus: Cell<HWND>,
    st: RefCell<State>,
    notifier: Notifier,
    rx: Receiver<Event>,
    job: HANDLE,
}

thread_local! {
    static APP: RefCell<Option<Rc<App>>> = const { RefCell::new(None) };
    /// The owner-drawn button under the mouse.
    static HOT: Cell<usize> = const { Cell::new(0) };
}

fn app() -> Option<Rc<App>> {
    APP.with(|a| a.borrow().clone())
}

// ---------------------------------------------------------------------------------------
// Small Win32 helpers

fn set_text(h: HWND, s: &str) {
    let w = wide(s);
    unsafe { SetWindowTextW(h, w.as_ptr()) };
}

fn get_text(h: HWND) -> String {
    unsafe {
        let n = GetWindowTextLengthW(h).max(0) as usize;
        let mut buf = vec![0u16; n + 1];
        let got = GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32).max(0) as usize;
        String::from_utf16_lossy(&buf[..got.min(n)])
    }
}

fn is_checked(h: HWND) -> bool {
    unsafe { SendMessageW(h, BM_GETCHECK, 0, 0) == BST_CHECKED as LRESULT }
}

fn set_checked(h: HWND, on: bool) {
    unsafe { SendMessageW(h, BM_SETCHECK, if on { BST_CHECKED as usize } else { 0 }, 0) };
}

fn selection(h: HWND) -> usize {
    let r = unsafe { SendMessageW(h, CB_GETCURSEL, 0, 0) };
    r.max(0) as usize
}

fn select(h: HWND, i: usize) {
    unsafe { SendMessageW(h, CB_SETCURSEL, i, 0) };
}

fn enable(h: HWND, on: bool) {
    unsafe { EnableWindow(h, on as i32) };
}

fn show(h: HWND, on: bool) {
    unsafe { ShowWindow(h, if on { SW_SHOWNA } else { SW_HIDE }) };
}

fn client_size(h: HWND) -> (i32, i32) {
    let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    unsafe { GetClientRect(h, &mut r) };
    (r.right - r.left, r.bottom - r.top)
}

fn fill(hdc: HDC, r: &RECT, color: COLORREF) {
    unsafe {
        SetDCBrushColor(hdc, color);
        FillRect(hdc, r, GetStockObject(DC_BRUSH));
    }
}

fn round_rect(hdc: HDC, r: &RECT, fill: COLORREF, border: COLORREF, radius: i32) {
    unsafe {
        let old_brush = SelectObject(hdc, GetStockObject(DC_BRUSH));
        let old_pen = SelectObject(hdc, GetStockObject(DC_PEN));
        SetDCBrushColor(hdc, fill);
        SetDCPenColor(hdc, border);
        RoundRect(hdc, r.left, r.top, r.right, r.bottom, radius * 2, radius * 2);
        SelectObject(hdc, old_pen);
        SelectObject(hdc, old_brush);
    }
}

fn draw_text(hdc: HDC, text: &str, r: &RECT, font: HFONT, color: COLORREF, format: u32) {
    let w: Vec<u16> = text.encode_utf16().collect();
    let mut r = *r;
    unsafe {
        let old = SelectObject(hdc, font);
        SetBkMode(hdc, TRANSPARENT as i32);
        SetTextColor(hdc, color);
        DrawTextW(hdc, w.as_ptr(), w.len() as i32, &mut r, format | DT_NOPREFIX);
        SelectObject(hdc, old);
    }
}

fn message_box(owner: HWND, text: &str, flags: u32) -> i32 {
    let (text, title) = (wide(text), wide("safe-rdp"));
    unsafe { MessageBoxW(owner, text.as_ptr(), title.as_ptr(), flags) }
}

fn confirm(owner: HWND, text: &str) -> bool {
    message_box(owner, text, MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES
}

/// Overwrites an edit control's text before clearing it, so the key does not linger in its buffer.
fn scrub_edit(h: HWND) {
    let n = unsafe { GetWindowTextLengthW(h) }.max(0) as usize;
    if n > 0 {
        set_text(h, &"x".repeat(n));
    }
    set_text(h, "");
}

/// Sets secret text on a control, wiping the temporary UTF-16 copy.
fn set_secret_text(h: HWND, s: &str) {
    let mut w = wide(s);
    unsafe { SetWindowTextW(h, w.as_ptr()) };
    wipe_wide(&mut w);
}

fn load_icon(dpi: u32, metric: SYSTEM_METRICS_INDEX) -> HICON {
    unsafe {
        let size = GetSystemMetricsForDpi(metric, dpi);
        let h = LoadImageW(GetModuleHandleW(null()), ICON_ID as usize as PCWSTR, IMAGE_ICON, size, size, LR_DEFAULTCOLOR);
        h as HICON
    }
}

// ---------------------------------------------------------------------------------------
// Entry point

/// True when this process owns its console, i.e. it was started from Explorer or a shortcut
/// rather than from a terminal (then `safe-rdp` without arguments should open the launcher).
pub fn started_from_explorer() -> bool {
    let mut pids = [0u32; 4];
    unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) == 1 }
}

/// Runs the launcher window until it is closed.
pub fn run() -> crate::util::Result<()> {
    if started_from_explorer() {
        // The console was created just for us; do not leave an empty window around.
        unsafe { FreeConsole() };
    }
    super::init_process();

    let name = wide(INSTANCE_MUTEX);
    let mutex = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
    if !mutex.is_null() && unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        activate_existing();
        unsafe { CloseHandle(mutex) };
        return Ok(());
    }
    let r = run_window();
    if !mutex.is_null() {
        unsafe { CloseHandle(mutex) };
    }
    r
}

/// Brings an already running launcher to the front.
fn activate_existing() {
    let class = wide(CLASS);
    unsafe {
        let h = FindWindowW(class.as_ptr(), null());
        if !h.is_null() {
            if IsIconic(h) != 0 {
                ShowWindow(h, SW_RESTORE);
            }
            SetForegroundWindow(h);
        }
    }
}

fn run_window() -> crate::util::Result<()> {
    unsafe {
        let icc =
            INITCOMMONCONTROLSEX { dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32, dwICC: ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
        InitCommonControlsEx(&icc);
    }
    let korean = use_korean();
    let t: &'static Text = if korean { &KO } else { &EN };
    let hwnd = create_main_window()?;
    let dpi = unsafe { GetDpiForWindow(hwnd) }.max(96);
    place_window(hwnd, dpi);

    let (c, tones) = create_controls(hwnd, t);
    let (tx, rx) = mpsc::channel();
    let pal = Palette::current();
    let app = Rc::new(App {
        hwnd,
        t,
        korean,
        c,
        dpi: Cell::new(dpi),
        fonts: RefCell::new(Fonts::new(dpi, korean)),
        pal: Cell::new(pal),
        brushes: RefCell::new(Brushes::new(&pal)),
        icons: Cell::new([null_mut(); 2]),
        tones: RefCell::new(tones),
        decor: RefCell::new(Vec::new()),
        page: Cell::new(Page::Connect),
        sharing: Cell::new(false),
        filling: Cell::new(false),
        last_focus: Cell::new(null_mut()),
        st: RefCell::new(State {
            banner: None,
            key: KeyState::Missing,
            key_shown: false,
            clip_seq: None,
            devices: Vec::new(),
            me: None,
            ts_busy: false,
            ts_updated: None,
            recent: Vec::new(),
            host: None,
            host_gen: 0,
            host_key: None,
            host_key_fp: None,
            restart_after: None,
            host_error: None,
            listen: None,
            share: Share::Off,
            share_view_only: false,
            log: VecDeque::new(),
            svc: Svc::Checking,
            svc_busy: false,
            svc_key: None,
            key_fp: None,
            key_tone: Tone::Muted,
        }),
        notifier: Notifier { tx, hwnd: hwnd as usize },
        rx,
        job: kill_on_close_job(),
    });
    APP.with(|a| *a.borrow_mut() = Some(app.clone()));
    app.init();
    unsafe {
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if app.pre_translate(&msg) || IsDialogMessageW(hwnd, &msg) != 0 {
                continue;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    APP.with(|a| a.borrow_mut().take());
    for icon in app.icons.get() {
        if !icon.is_null() {
            unsafe { DestroyIcon(icon) };
        }
    }
    if !app.job.is_null() {
        // Kills a host that somehow survived shutdown.
        unsafe { CloseHandle(app.job) };
    }
    Ok(())
}

fn create_main_window() -> crate::util::Result<HWND> {
    let class = wide(CLASS);
    let title = wide("safe-rdp");
    unsafe {
        let hinst = GetModuleHandleW(null());
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinst,
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            lpszClassName: class.as_ptr(),
            ..std::mem::zeroed()
        };
        if RegisterClassExW(&wc) == 0 {
            return Err(crate::util::Error::last_os("RegisterClassExW"));
        }
        let hwnd = CreateWindowExW(
            WS_EX_CONTROLPARENT,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            DEFAULT_SIZE.0,
            DEFAULT_SIZE.1,
            null_mut(),
            null_mut(),
            hinst,
            null(),
        );
        if hwnd.is_null() {
            return Err(crate::util::Error::last_os("CreateWindowExW"));
        }
        Ok(hwnd)
    }
}

/// Sizes the window for its monitor's DPI and centres it in the work area.
fn place_window(hwnd: HWND, dpi: u32) {
    unsafe {
        let mut mi: MONITORINFO = std::mem::zeroed();
        mi.cbSize = size_of::<MONITORINFO>() as u32;
        GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mut mi);
        let work = mi.rcWork;
        let mut r =
            RECT { left: 0, top: 0, right: mul_div(DEFAULT_SIZE.0, dpi as i32, 96), bottom: mul_div(DEFAULT_SIZE.1, dpi as i32, 96) };
        AdjustWindowRectExForDpi(&mut r, WS_OVERLAPPEDWINDOW, 0, WS_EX_CONTROLPARENT, dpi);
        let w = (r.right - r.left).min(work.right - work.left);
        let h = (r.bottom - r.top).min(work.bottom - work.top);
        let x = work.left + (work.right - work.left - w) / 2;
        let y = work.top + (work.bottom - work.top - h) / 2;
        SetWindowPos(hwnd, null_mut(), x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        if msg == WM_GETMINMAXINFO {
            min_size(hwnd, &mut *(lp as *mut MINMAXINFO));
            return 0;
        }
        let Some(app) = app() else { return DefWindowProcW(hwnd, msg, wp, lp) };
        // A panic must not unwind into user32; fall back to default handling instead.
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| app.handle(msg, wp, lp))) {
            Ok(Some(r)) => r,
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

fn min_size(hwnd: HWND, mmi: &mut MINMAXINFO) {
    unsafe {
        let dpi = GetDpiForWindow(hwnd).max(96);
        let mut r = RECT { left: 0, top: 0, right: mul_div(MIN_SIZE.0, dpi as i32, 96), bottom: mul_div(MIN_SIZE.1, dpi as i32, 96) };
        AdjustWindowRectExForDpi(&mut r, WS_OVERLAPPEDWINDOW, 0, WS_EX_CONTROLPARENT, dpi);
        let mut mi: MONITORINFO = std::mem::zeroed();
        mi.cbSize = size_of::<MONITORINFO>() as u32;
        GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mut mi);
        let work = mi.rcWork;
        mmi.ptMinTrackSize.x = (r.right - r.left).min(work.right - work.left);
        mmi.ptMinTrackSize.y = (r.bottom - r.top).min(work.bottom - work.top);
    }
}

unsafe extern "system" fn hover_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM, _id: usize, _data: usize) -> LRESULT {
    unsafe {
        match msg {
            WM_MOUSEMOVE => {
                let old = HOT.with(|h| h.replace(hwnd as usize));
                if old != hwnd as usize {
                    if old != 0 {
                        InvalidateRect(old as HWND, null(), 0);
                    }
                    let mut tme = TRACKMOUSEEVENT {
                        cbSize: size_of::<TRACKMOUSEEVENT>() as u32,
                        dwFlags: TME_LEAVE,
                        hwndTrack: hwnd,
                        dwHoverTime: 0,
                    };
                    TrackMouseEvent(&mut tme);
                    InvalidateRect(hwnd, null(), 0);
                }
            }
            WM_MOUSELEAVE => {
                if HOT.with(|h| h.get()) == hwnd as usize {
                    HOT.with(|h| h.set(0));
                    InvalidateRect(hwnd, null(), 0);
                }
            }
            WM_NCDESTROY => {
                RemoveWindowSubclass(hwnd, Some(hover_proc), 1);
            }
            _ => {}
        }
        DefSubclassProc(hwnd, msg, wp, lp)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum KeyEdit {
    Pass,
    Block,
    Copy,
}

/// What the edit showing the key does with a message. Its own copy (Ctrl+C, Ctrl+Insert, the
/// context menu) would leave the key on the clipboard for good, history and cloud sync
/// included; copying goes through the Copy button instead, which avoids both.
fn key_edit_action(msg: u32, wp: WPARAM, ctrl: bool, shift: bool) -> KeyEdit {
    let key = wp as VIRTUAL_KEY;
    match msg {
        WM_COPY => KeyEdit::Copy,
        WM_CUT | WM_CLEAR | WM_PASTE | WM_CONTEXTMENU => KeyEdit::Block,
        WM_KEYDOWN if ctrl && (key == VK_C || key == VK_INSERT) => KeyEdit::Copy,
        WM_KEYDOWN if (ctrl && key == VK_X) || (shift && key == VK_DELETE) => KeyEdit::Block,
        // Ctrl+C and Ctrl+X as characters.
        WM_CHAR if wp == 0x03 || wp == 0x18 => KeyEdit::Block,
        _ => KeyEdit::Pass,
    }
}

const KEY_EDIT_SUBCLASS: usize = 2;

unsafe extern "system" fn key_edit_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM, _id: usize, _data: usize) -> LRESULT {
    unsafe {
        let ctrl = GetKeyState(VK_CONTROL as i32) < 0;
        let shift = GetKeyState(VK_SHIFT as i32) < 0;
        match key_edit_action(msg, wp, ctrl, shift) {
            KeyEdit::Pass => {
                if msg == WM_NCDESTROY {
                    RemoveWindowSubclass(hwnd, Some(key_edit_proc), KEY_EDIT_SUBCLASS);
                }
                DefSubclassProc(hwnd, msg, wp, lp)
            }
            KeyEdit::Block => 0,
            KeyEdit::Copy => {
                // As if the Copy button was clicked (BN_CLICKED is 0).
                PostMessageW(GetParent(hwnd), WM_COMMAND, ID_COPY as usize, 0);
                0
            }
        }
    }
}

/// `a * b / c` rounded to nearest, like Win32 `MulDiv` (0 when `c` is 0).
fn mul_div(a: i32, b: i32, c: i32) -> i32 {
    if c == 0 {
        return 0;
    }
    let (n, c) = (a as i64 * b as i64, c as i64);
    let q = if (n < 0) == (c < 0) { (n.abs() + c.abs() / 2) / c.abs() } else { -((n.abs() + c.abs() / 2) / c.abs()) };
    q.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

fn loword(v: usize) -> u16 {
    (v & 0xffff) as u16
}

fn hiword(v: usize) -> u16 {
    ((v >> 16) & 0xffff) as u16
}

// ---------------------------------------------------------------------------------------
// The window

impl App {
    fn px(&self, dip: i32) -> i32 {
        mul_div(dip, self.dpi.get() as i32, 96)
    }

    fn handle(&self, msg: u32, wp: WPARAM, lp: LPARAM) -> Option<LRESULT> {
        unsafe {
            match msg {
                WM_ERASEBKGND => {
                    self.paint_background(wp as HDC);
                    Some(1)
                }
                WM_PRINTCLIENT => {
                    self.paint_background(wp as HDC);
                    Some(0)
                }
                WM_PAINT => {
                    let mut ps: PAINTSTRUCT = std::mem::zeroed();
                    BeginPaint(self.hwnd, &mut ps);
                    EndPaint(self.hwnd, &ps);
                    Some(0)
                }
                WM_SIZE => {
                    self.layout();
                    InvalidateRect(self.hwnd, null(), 1);
                    Some(0)
                }
                WM_DPICHANGED => {
                    self.dpi_changed(loword(wp) as u32, &*(lp as *const RECT));
                    Some(0)
                }
                WM_CTLCOLORSTATIC => Some(self.ctl_color(wp as HDC, lp as HWND)),
                WM_CTLCOLORBTN => Some(self.brushes.try_borrow().map(|b| b.get(self.c.surface(lp as HWND)) as LRESULT).unwrap_or(0)),
                WM_DRAWITEM => {
                    let dis = &*(lp as *const DRAWITEMSTRUCT);
                    if dis.CtlType != ODT_BUTTON {
                        return None;
                    }
                    self.draw_button(dis);
                    Some(1)
                }
                WM_COMMAND => {
                    self.command(loword(wp), hiword(wp) as u32);
                    Some(0)
                }
                WM_NOTIFY => self.notify(lp as *mut NMHDR),
                DM_GETDEFID => Some(self.default_id()),
                WM_TIMER => {
                    self.timer(wp);
                    Some(0)
                }
                WM_APP_EVENT => {
                    self.drain_events();
                    Some(0)
                }
                WM_ACTIVATE => {
                    if loword(wp) as u32 == WA_INACTIVE {
                        self.last_focus.set(GetFocus());
                        None
                    } else {
                        let f = self.last_focus.get();
                        if !f.is_null() && IsWindowVisible(f) != 0 && IsWindowEnabled(f) != 0 {
                            SetFocus(f);
                            Some(0)
                        } else {
                            None
                        }
                    }
                }
                WM_SETTINGCHANGE | WM_SYSCOLORCHANGE | WM_THEMECHANGED => {
                    self.refresh_palette();
                    None
                }
                WM_CLOSE => {
                    if self.confirm_close() {
                        DestroyWindow(self.hwnd);
                    }
                    Some(0)
                }
                WM_DESTROY => {
                    self.shutdown();
                    PostQuitMessage(0);
                    Some(0)
                }
                _ => None,
            }
        }
    }

    /// Keyboard shortcuts: Ctrl+Tab / Ctrl+Shift+Tab switch sections, F5 refreshes.
    fn pre_translate(&self, msg: &MSG) -> bool {
        if msg.message != WM_KEYDOWN {
            return false;
        }
        let ctrl = unsafe { GetKeyState(VK_CONTROL as i32) } < 0;
        let shift = unsafe { GetKeyState(VK_SHIFT as i32) } < 0;
        match msg.wParam as u16 {
            VK_TAB if ctrl => {
                let i = PAGES.iter().position(|p| *p == self.page.get()).unwrap_or(0);
                let next = if shift { (i + PAGES.len() - 1) % PAGES.len() } else { (i + 1) % PAGES.len() };
                self.set_page(PAGES[next], true);
                true
            }
            VK_F5 => {
                match self.page.get() {
                    Page::Connect => self.refresh_devices(),
                    Page::Share => self.refresh_service(),
                    Page::Key => {}
                }
                true
            }
            _ => false,
        }
    }

    fn init(&self) {
        let settings = Settings::parse(&read_data_file("launcher.txt"));
        self.apply_settings(&settings);
        let recent = parse_recent(&read_data_file("recent.txt"));
        if let Some(first) = recent.first() {
            set_text(self.c.c_host, first);
        }
        self.st.borrow_mut().recent = recent;
        self.fill_recent();

        let key = key_state();
        {
            let mut st = self.st.borrow_mut();
            st.key = key;
            if key != KeyState::Present {
                st.banner = Some(Banner::Welcome);
            }
        }
        self.set_icons();
        self.apply_fonts();
        self.update_key_ui();
        self.update_share_ui();
        self.update_service_ui();
        self.set_page(if key == KeyState::Present { Page::Connect } else { Page::Key }, true);
        self.refresh_devices();
        self.refresh_service();
        unsafe { SetTimer(self.hwnd, TIMER_DEVICES, DEVICE_REFRESH_MS, None) };
    }

    fn set_icons(&self) {
        let dpi = self.dpi.get();
        let (big, small) = (load_icon(dpi, SM_CXICON), load_icon(dpi, SM_CXSMICON));
        if big.is_null() || small.is_null() {
            return; // no icon resource (e.g. a test build); keep the default
        }
        unsafe {
            SendMessageW(self.hwnd, WM_SETICON, ICON_BIG as usize, big as LPARAM);
            SendMessageW(self.hwnd, WM_SETICON, ICON_SMALL as usize, small as LPARAM);
        }
        for old in self.icons.replace([big, small]) {
            if !old.is_null() {
                unsafe { DestroyIcon(old) };
            }
        }
    }

    fn apply_fonts(&self) {
        let Ok(fonts) = self.fonts.try_borrow() else { return };
        for &(h, kind) in &self.c.fonts {
            unsafe { SendMessageW(h, WM_SETFONT, fonts.get(kind) as WPARAM, 1) };
        }
        drop(fonts);
        let m = self.px(6) as usize;
        for h in [self.c.s_log, self.c.k_import_text, self.c.k_shown] {
            unsafe { SendMessageW(h, EM_SETMARGINS, (EC_LEFTMARGIN | EC_RIGHTMARGIN) as usize, (m | m << 16) as LPARAM) };
        }
    }

    /// Height in DIPs for a single-line edit in `kind` (edits do not centre text vertically).
    fn edit_height(&self, kind: FontKind) -> i32 {
        let Ok(fonts) = self.fonts.try_borrow() else { return 28 };
        unsafe {
            let hdc = GetDC(self.hwnd);
            let old = SelectObject(hdc, fonts.get(kind));
            let mut tm: TEXTMETRICW = std::mem::zeroed();
            GetTextMetricsW(hdc, &mut tm);
            SelectObject(hdc, old);
            ReleaseDC(self.hwnd, hdc);
            mul_div(tm.tmHeight, 96, self.dpi.get() as i32) + 12
        }
    }

    fn dpi_changed(&self, dpi: u32, suggested: &RECT) {
        self.dpi.set(dpi.max(96));
        let old = self.fonts.replace(Fonts::new(self.dpi.get(), self.korean));
        self.apply_fonts();
        drop(old);
        self.set_icons();
        unsafe {
            SetWindowPos(
                self.hwnd,
                null_mut(),
                suggested.left,
                suggested.top,
                suggested.right - suggested.left,
                suggested.bottom - suggested.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
        self.layout();
        unsafe { InvalidateRect(self.hwnd, null(), 1) };
    }

    fn refresh_palette(&self) {
        let pal = Palette::current();
        self.pal.set(pal);
        if let Ok(mut b) = self.brushes.try_borrow_mut() {
            *b = Brushes::new(&pal);
        }
        unsafe { RedrawWindow(self.hwnd, null(), null_mut(), RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN) };
    }

    // ----- pages and layout

    fn set_page(&self, page: Page, focus: bool) {
        let old = self.page.replace(page);
        if old == Page::Key && page != Page::Key && self.st.borrow().key_shown {
            self.hide_key();
        }
        // Batch the repaint (WM_SETREDRAW would also make a still-hidden window visible).
        let visible = unsafe { IsWindowVisible(self.hwnd) } != 0;
        if visible {
            unsafe { SendMessageW(self.hwnd, WM_SETREDRAW, 0, 0) };
        }
        self.apply_visibility();
        self.layout();
        if visible {
            unsafe {
                SendMessageW(self.hwnd, WM_SETREDRAW, 1, 0);
                RedrawWindow(self.hwnd, null(), null_mut(), RDW_ERASE | RDW_FRAME | RDW_INVALIDATE | RDW_ALLCHILDREN);
            }
        }
        if focus {
            let target = match page {
                Page::Connect => self.c.c_host,
                Page::Share => self.c.s_toggle,
                Page::Key if self.st.borrow().key == KeyState::Present => self.c.k_show,
                Page::Key => self.c.k_create,
            };
            unsafe { SetFocus(target) };
        }
        match page {
            Page::Connect => {
                let stale = self.st.borrow().ts_updated.is_none_or(|t| t.elapsed() > Duration::from_secs(10));
                if stale {
                    self.refresh_devices();
                }
            }
            Page::Share => self.refresh_service(),
            Page::Key => {}
        }
    }

    fn apply_visibility(&self) {
        let page = self.page.get();
        let (banner, key_shown) = {
            let st = self.st.borrow();
            (st.banner.is_some(), st.key_shown)
        };
        for &(h, p) in &self.c.pages {
            let mut visible = p.is_none_or(|p| p == page);
            if h == self.c.k_banner {
                visible &= banner;
            } else if self.c.key_display().contains(&h) {
                visible &= key_shown;
            }
            show(h, visible);
        }
        for h in self.c.nav {
            unsafe { InvalidateRect(h, null(), 0) };
        }
    }

    /// Height in DIPs that a wrapping static needs at `width` DIPs.
    fn text_height(&self, h: HWND, width: i32) -> i32 {
        let text: Vec<u16> = get_text(h).encode_utf16().collect();
        if text.is_empty() {
            return 0;
        }
        unsafe {
            let font = SendMessageW(h, WM_GETFONT, 0, 0) as HFONT;
            let hdc = GetDC(h);
            let old = SelectObject(hdc, font);
            let mut r = RECT { left: 0, top: 0, right: self.px(width), bottom: 0 };
            DrawTextW(hdc, text.as_ptr(), text.len() as i32, &mut r, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX | DT_EDITCONTROL);
            SelectObject(hdc, old);
            ReleaseDC(h, hdc);
            mul_div(r.bottom, 96, self.dpi.get() as i32) + 2
        }
    }

    fn layout(&self) {
        let (cw, ch) = client_size(self.hwnd);
        if cw <= 0 || ch <= 0 {
            return;
        }
        let dpi = self.dpi.get() as i32;
        let (w, h) = (mul_div(cw, 96, dpi), mul_div(ch, 96, dpi));
        let (banner, key_shown) = {
            let st = self.st.borrow();
            (st.banner.is_some(), st.key_shown)
        };
        let c = &self.c;
        let page = self.page.get();
        let mut pos: Vec<(HWND, i32, i32, i32, i32)> = Vec::with_capacity(80);
        let mut decor: Vec<(i32, i32, i32, i32, Surface)> = Vec::new();
        let mut put = |h: HWND, x: i32, y: i32, ww: i32, hh: i32| pos.push((h, x, y, ww, hh));

        put(c.brand, 22, 22, SIDEBAR - 40, 30);
        put(c.tagline, 22, 54, SIDEBAR - 30, 20);
        for (i, &n) in c.nav.iter().enumerate() {
            put(n, 8, 98 + 46 * i as i32, SIDEBAR - 16, 42);
        }
        put(c.version, 22, h - 34, SIDEBAR - 40, 20);

        let x = SIDEBAR + MARGIN;
        let cw = (w - x - MARGIN).max(300);

        // Connect
        put(c.c_title, x, 22, cw, 38);
        put(c.c_sub, x, 62, cw, 22);
        put(c.c_devices, x, 100, cw - 130, 24);
        put(c.c_refresh, x + cw - 116, 96, 116, 30);
        let list_top = 130;
        let list_bottom = (h - 20 - 252).max(list_top + 90);
        put(c.c_list, x, list_top, cw, list_bottom - list_top);
        let y = list_bottom;
        put(c.c_ts, x, y + 6, cw, 20);
        put(c.c_host_title, x, y + 36, cw, 24);
        put(c.c_host, x, y + 64, cw - 156, 300);
        put(c.c_connect, x + cw - 144, y + 61, 144, 36);
        put(c.c_msg, x, y + 102, cw, 20);
        put(c.c_options, x, y + 132, cw, 24);
        let col = cw / 3;
        let r0 = y + 160;
        for (i, &hh) in [c.c_fullscreen, c.c_clipboard, c.c_sound].iter().enumerate() {
            put(hh, x, r0 + 30 * i as i32, col - 8, 24);
        }
        for (i, &hh) in [c.c_privacy, c.c_view_only].iter().enumerate() {
            put(hh, x + col, r0 + 30 * i as i32, col - 8, 24);
        }
        let label_w = 76;
        for (i, (&l, &d)) in
            [c.c_quality_label, c.c_scale_label, c.c_monitor_label].iter().zip([c.c_quality, c.c_scale, c.c_monitor].iter()).enumerate()
        {
            let ry = r0 + 30 * i as i32 - 1;
            put(l, x + 2 * col, ry + 3, label_w, 22);
            put(d, x + 2 * col + label_w + 4, ry, cw - 2 * col - label_w - 4, 300);
        }

        // Share
        put(c.s_title, x, 22, cw, 38);
        put(c.s_sub, x, 62, cw, 22);
        let card_top = 100;
        let text_w = cw - 40 - 196;
        let detail_h = self.text_height(c.s_detail, text_w).clamp(20, 64);
        let card_h = (44 + detail_h + 16).max(96);
        if page == Page::Share {
            decor.push((x, card_top, cw, card_h, Surface::Card));
        }
        put(c.s_status, x + 20, card_top + 14, text_w, 28);
        put(c.s_detail, x + 20, card_top + 44, text_w, detail_h);
        put(c.s_toggle, x + cw - 20 - 176, card_top + (card_h - 38) / 2, 176, 38);
        let mut y = card_top + card_h + 18;
        put(c.s_allow, x, y, cw, 24);
        y += 30;
        let col = cw / 2;
        for (i, &hh) in [c.s_control, c.s_clipboard, c.s_files].iter().enumerate() {
            put(hh, x, y + 28 * i as i32, col - 8, 24);
        }
        for (i, &hh) in [c.s_sound, c.s_privacy].iter().enumerate() {
            put(hh, x + col, y + 28 * i as i32, col - 8, 24);
        }
        y += 92;
        put(c.s_activity, x, y, cw, 24);
        let log_top = y + 30;
        let svc_text_h = self.text_height(c.s_svc_text, cw);
        let sy = (h - 20 - svc_text_h - 88).max(log_top + 60);
        put(c.s_log, x, log_top, cw, sy - 18 - log_top);
        put(c.s_svc, x, sy, cw - 290, 24);
        put(c.s_svc_status, x, sy + 28, cw - 290, 22);
        put(c.s_install, x + cw - 282, sy + 8, 138, 34);
        put(c.s_uninstall, x + cw - 136, sy + 8, 136, 34);
        put(c.s_sas, x, sy + 56, cw, 24);
        put(c.s_svc_text, x, sy + 86, cw, svc_text_h);

        // Key
        put(c.k_title, x, 22, cw, 38);
        let sub_h = self.text_height(c.k_sub, cw);
        put(c.k_sub, x, 62, cw, sub_h);
        let mut y = 62 + sub_h + 18;
        if banner {
            let bh = self.text_height(c.k_banner, cw - 36);
            if page == Page::Key {
                decor.push((x, y, cw, bh + 28, Surface::Info));
            }
            put(c.k_banner, x + 18, y + 14, cw - 36, bh);
            y += bh + 28 + 18;
        }
        let status_h = self.text_height(c.k_status, cw).max(22);
        put(c.k_status, x, y, cw, status_h);
        y += status_h + 8;
        let about_h = self.text_height(c.k_about, cw);
        put(c.k_about, x, y, cw, about_h);
        y += about_h + 16;
        put(c.k_create, x, y, 180, 38);
        put(c.k_show, x + 192, y + 2, 136, 34);
        put(c.k_remove, x + 340, y + 2, 136, 34);
        y += 56;
        put(c.k_import_title, x, y, cw, 24);
        y += 30;
        let eh = self.edit_height(FontKind::Body);
        put(c.k_import_text, x, y + (34 - eh) / 2, cw - 148, eh);
        put(c.k_import, x + cw - 136, y, 136, 34);
        y += 52;
        if key_shown {
            let warn_w = cw - 36 - 268;
            let warn_h = self.text_height(c.k_warning, warn_w).max(34);
            let mh = self.edit_height(FontKind::Mono);
            let card_h = 14 + 24 + 10 + mh + 14 + warn_h + 16;
            if page == Page::Key {
                decor.push((x, y, cw, card_h, Surface::Card));
            }
            put(c.k_shown_title, x + 18, y + 14, cw - 36, 24);
            put(c.k_shown, x + 18, y + 48, cw - 36, mh);
            let y2 = y + 48 + mh + 14;
            put(c.k_warning, x + 18, y2, warn_w, warn_h);
            put(c.k_copy, x + cw - 18 - 260, y2, 124, 34);
            put(c.k_hide, x + cw - 18 - 128, y2, 128, 34);
            y += card_h + 14;
        }
        let msg_h = self.text_height(c.k_msg, cw).max(22);
        put(c.k_msg, x, y, cw, msg_h);

        let px = |v: i32| mul_div(v, dpi, 96);
        *self.decor.borrow_mut() = decor
            .into_iter()
            .map(|(x, y, ww, hh, s)| (RECT { left: px(x), top: px(y), right: px(x + ww), bottom: px(y + hh) }, s))
            .collect();
        unsafe {
            let mut hdwp = BeginDeferWindowPos(pos.len() as i32);
            for &(hw, x, y, ww, hh) in &pos {
                if hdwp.is_null() {
                    SetWindowPos(hw, null_mut(), px(x), px(y), px(ww).max(0), px(hh).max(0), SWP_NOZORDER | SWP_NOACTIVATE);
                } else {
                    hdwp = DeferWindowPos(hdwp, hw, null_mut(), px(x), px(y), px(ww).max(0), px(hh).max(0), SWP_NOZORDER | SWP_NOACTIVATE);
                }
            }
            if !hdwp.is_null() {
                EndDeferWindowPos(hdwp);
            }
            // Columns: device, system, address, status.
            let total = px(cw) - GetSystemMetricsForDpi(SM_CXVSCROLL, dpi as u32) - px(6);
            for (i, share) in [38, 17, 25, 20].iter().enumerate() {
                SendMessageW(c.c_list, LVM_SETCOLUMNWIDTH, i, (total * share / 100) as LPARAM);
            }
        }
    }

    // ----- painting

    fn paint_background(&self, hdc: HDC) {
        let pal = self.pal.get();
        let (cw, ch) = client_size(self.hwnd);
        let sb = self.px(SIDEBAR);
        fill(hdc, &RECT { left: sb, top: 0, right: cw, bottom: ch }, pal.page);
        fill(hdc, &RECT { left: 0, top: 0, right: sb, bottom: ch }, pal.sidebar);
        fill(hdc, &RECT { left: sb - self.px(1).max(1), top: 0, right: sb, bottom: ch }, pal.separator);
        if let Ok(decor) = self.decor.try_borrow() {
            for (r, s) in decor.iter() {
                let border = if *s == Surface::Info { pal.info_border } else { pal.card_border };
                round_rect(hdc, r, pal.surface(*s), border, self.px(6));
            }
        }
    }

    fn ctl_color(&self, hdc: HDC, ctl: HWND) -> LRESULT {
        let pal = self.pal.get();
        let surface = self.c.surface(ctl);
        let tone = self.tones.try_borrow().ok().and_then(|t| t.get(&(ctl as usize)).copied()).unwrap_or(Tone::Normal);
        unsafe {
            SetTextColor(hdc, pal.tone(tone));
            SetBkColor(hdc, pal.surface(surface));
        }
        self.brushes.try_borrow().map(|b| b.get(surface) as LRESULT).unwrap_or(0)
    }

    fn draw_button(&self, d: &DRAWITEMSTRUCT) {
        let pal = self.pal.get();
        let Ok(fonts) = self.fonts.try_borrow() else { return };
        let hdc = d.hDC;
        let rc = d.rcItem;
        let id = d.CtlID as u16;
        let hot = HOT.with(|h| h.get()) == d.hwndItem as usize;
        let pressed = d.itemState & ODS_SELECTED != 0;
        let disabled = d.itemState & ODS_DISABLED != 0;
        let focus = d.itemState & ODS_FOCUS != 0 && d.itemState & ODS_NOFOCUSRECT == 0;
        let text = get_text(d.hwndItem);
        let r4 = self.px(4);

        if (ID_NAV..ID_NAV + 3).contains(&id) {
            let index = (id - ID_NAV) as usize;
            let selected = PAGES[index] == self.page.get();
            fill(hdc, &rc, pal.sidebar);
            let inner = RECT { left: rc.left, top: rc.top + self.px(2), right: rc.right, bottom: rc.bottom - self.px(2) };
            if selected || hot {
                let c = if selected { pal.nav_selected } else { pal.nav_hot };
                round_rect(hdc, &inner, c, c, r4);
            }
            if selected {
                let mid = (inner.top + inner.bottom) / 2;
                let pill = RECT { left: inner.left, top: mid - self.px(9), right: inner.left + self.px(3), bottom: mid + self.px(9) };
                round_rect(hdc, &pill, pal.accent, pal.accent, self.px(2));
            }
            let icon = RECT { left: inner.left + self.px(12), top: inner.top, right: inner.left + self.px(40), bottom: inner.bottom };
            let fg = if selected && pal.nav_selected == pal.accent { pal.on_accent } else { pal.text };
            draw_text(hdc, NAV_GLYPHS[index], &icon, fonts.get(FontKind::Icon), fg, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            let label = RECT { left: inner.left + self.px(48), top: inner.top, right: inner.right - self.px(8), bottom: inner.bottom };
            let font = fonts.get(if selected { FontKind::Bold } else { FontKind::Body });
            draw_text(hdc, &text, &label, font, fg, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            if focus {
                let f = RECT { left: inner.left + 2, top: inner.top + 2, right: inner.right - 2, bottom: inner.bottom - 2 };
                unsafe { DrawFocusRect(hdc, &f) };
            }
            return;
        }

        let danger = id == ID_SHARE && self.sharing.get();
        let bg = match (disabled, danger, pressed, hot) {
            (true, ..) => pal.disabled,
            (false, true, true, _) => pal.danger_down,
            (false, true, false, true) => pal.danger_hot,
            (false, true, false, false) => pal.danger,
            (false, false, true, _) => pal.accent_down,
            (false, false, false, true) => pal.accent_hot,
            (false, false, false, false) => pal.accent,
        };
        fill(hdc, &rc, pal.surface(self.c.surface(d.hwndItem)));
        round_rect(hdc, &rc, bg, bg, r4);
        draw_text(hdc, &text, &rc, fonts.get(FontKind::Bold), pal.on_accent, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        if focus {
            let inset = self.px(3);
            let f = RECT { left: rc.left + inset, top: rc.top + inset, right: rc.right - inset, bottom: rc.bottom - inset };
            unsafe {
                SetTextColor(hdc, pal.on_accent);
                SetBkColor(hdc, bg);
                DrawFocusRect(hdc, &f);
            }
        }
    }

    /// Sets a status text and its colour.
    fn say(&self, h: HWND, text: &str, tone: Tone) {
        self.tones.borrow_mut().insert(h as usize, tone);
        set_text(h, text);
        unsafe { InvalidateRect(h, null(), 1) };
    }

    // ----- commands

    fn command(&self, id: u16, code: u32) {
        let clicked = code == BN_CLICKED;
        match id {
            _ if (ID_NAV..ID_NAV + 3).contains(&id) && clicked => self.set_page(PAGES[(id - ID_NAV) as usize], false),
            ID_REFRESH if clicked => self.refresh_devices(),
            ID_CONNECT if clicked => self.connect(),
            ID_SHARE if clicked => self.toggle_sharing(),
            ID_INSTALL if clicked => self.service_op(true),
            ID_UNINSTALL if clicked => self.service_op(false),
            ID_CREATE if clicked => self.create_key(),
            ID_SHOW if clicked => self.show_stored_key(),
            ID_REMOVE if clicked => self.remove_key(),
            ID_IMPORT if clicked => self.import_key(),
            ID_COPY if clicked => self.copy_key(),
            ID_HIDE if clicked => self.hide_key(),
            x if x as i32 == IDCANCEL && self.st.borrow().key_shown => self.hide_key(),
            _ => {}
        }
    }

    /// Enter activates the drawn button that has the focus (unlike plain buttons, they do not
    /// become the default by being focused), else Connect on the Connect page and Import in the
    /// key field.
    fn default_id(&self) -> LRESULT {
        let (c, focus) = (&self.c, unsafe { GetFocus() });
        let drawn = [(c.c_connect, ID_CONNECT), (c.s_toggle, ID_SHARE), (c.k_create, ID_CREATE)];
        let nav = (0..3).map(|i| (c.nav[i], ID_NAV + i as u16));
        let id = match drawn.into_iter().chain(nav).find(|&(h, _)| h == focus) {
            Some((_, id)) => id,
            None => match self.page.get() {
                Page::Connect => ID_CONNECT,
                Page::Key if focus == c.k_import_text => ID_IMPORT,
                _ => return 0,
            },
        };
        (DC_HASDEFID << 16 | id as u32) as LRESULT
    }

    fn notify(&self, nm: *mut NMHDR) -> Option<LRESULT> {
        let hdr = unsafe { &*nm };
        if hdr.hwndFrom != self.c.c_list {
            return None;
        }
        match hdr.code {
            NM_CUSTOMDRAW => Some(self.list_custom_draw(unsafe { &mut *(nm as *mut NMLVCUSTOMDRAW) })),
            LVN_ITEMCHANGED => {
                let lv = unsafe { &*(nm as *const NMLISTVIEW) };
                if !self.filling.get() && lv.uNewState & LVIS_SELECTED != 0 && lv.uOldState & LVIS_SELECTED == 0 {
                    self.device_selected(lv.iItem);
                }
                Some(0)
            }
            NM_DBLCLK => {
                let ia = unsafe { &*(nm as *const NMITEMACTIVATE) };
                if ia.iItem >= 0 {
                    self.device_selected(ia.iItem);
                    self.connect();
                }
                Some(0)
            }
            _ => None,
        }
    }

    fn list_custom_draw(&self, cd: &mut NMLVCUSTOMDRAW) -> LRESULT {
        let stage = cd.nmcd.dwDrawStage;
        if stage == CDDS_PREPAINT {
            return CDRF_NOTIFYITEMDRAW as LRESULT;
        }
        if stage == CDDS_ITEMPREPAINT {
            return CDRF_NOTIFYSUBITEMDRAW as LRESULT;
        }
        if stage == CDDS_ITEMPREPAINT | CDDS_SUBITEM {
            let pal = self.pal.get();
            let online = self.st.try_borrow().ok().and_then(|s| s.devices.get(cd.nmcd.dwItemSpec).map(|d| d.online)).unwrap_or(true);
            cd.clrText = match (cd.iSubItem, online) {
                (_, false) => pal.muted,
                (3, true) => pal.good,
                _ => pal.text,
            };
            return CDRF_NEWFONT as LRESULT;
        }
        CDRF_DODEFAULT as LRESULT
    }

    fn timer(&self, id: usize) {
        match id {
            TIMER_DEVICES => {
                if self.page.get() == Page::Connect && unsafe { IsIconic(self.hwnd) } == 0 {
                    self.refresh_devices();
                }
                // Notices the service being given another key (or installed, or removed) in a
                // terminal, and the key being changed there.
                if self.page.get() == Page::Share && unsafe { IsIconic(self.hwnd) } == 0 {
                    self.refresh_service();
                }
            }
            TIMER_CLIPBOARD => self.clear_clipboard(),
            TIMER_KEY => self.check_key_file(),
            _ => {}
        }
    }

    fn drain_events(&self) {
        let mut log_changed = false;
        while let Ok(e) = self.rx.try_recv() {
            match e {
                Event::Devices(r) => self.on_devices(r),
                Event::HostLine(generation, line) => log_changed |= self.on_host_line(generation, &line),
                Event::HostExit(generation) => self.on_host_exit(generation),
                Event::HostStopped(generation) => self.on_host_stopped(generation),
                Event::Viewer { host, entry, update } => self.on_viewer(&host, &entry, update),
                Event::Service(r) => self.on_service_status(r),
                Event::ServiceDone { op, result } => self.on_service_done(op, result),
            }
        }
        if log_changed {
            self.show_log();
        }
    }

    // ----- Connect

    fn connect_options(&self) -> ConnectOptions {
        let c = &self.c;
        ConnectOptions {
            fullscreen: is_checked(c.c_fullscreen),
            clipboard: is_checked(c.c_clipboard),
            audio: is_checked(c.c_sound),
            privacy: is_checked(c.c_privacy),
            view_only: is_checked(c.c_view_only),
            quality: selection(c.c_quality),
            scale: selection(c.c_scale),
            monitor: selection(c.c_monitor),
        }
    }

    fn share_options(&self) -> ShareOptions {
        let c = &self.c;
        ShareOptions {
            control: is_checked(c.s_control),
            clipboard: is_checked(c.s_clipboard),
            files: is_checked(c.s_files),
            audio: is_checked(c.s_sound),
            privacy: is_checked(c.s_privacy),
        }
    }

    fn apply_settings(&self, s: &Settings) {
        let c = &self.c;
        let o = &s.connect;
        for (h, on) in c.connect_options().iter().zip([o.fullscreen, o.clipboard, o.audio, o.privacy, o.view_only]) {
            set_checked(*h, on);
        }
        select(c.c_quality, o.quality);
        select(c.c_scale, o.scale);
        select(c.c_monitor, o.monitor);
        let o = &s.share;
        for (h, on) in c.share_options().iter().zip([o.control, o.clipboard, o.files, o.audio, o.privacy]) {
            set_checked(*h, on);
        }
        set_checked(c.s_sas, s.sas);
    }

    fn save_settings(&self) {
        let s = Settings { connect: self.connect_options(), share: self.share_options(), sas: is_checked(self.c.s_sas) };
        write_data_file("launcher.txt", &s.format());
    }

    fn fill_recent(&self) {
        let recent = self.st.borrow().recent.clone();
        let typed = get_text(self.c.c_host);
        unsafe {
            SendMessageW(self.c.c_host, CB_RESETCONTENT, 0, 0);
            for h in &recent {
                let w = wide(h);
                SendMessageW(self.c.c_host, CB_ADDSTRING, 0, w.as_ptr() as LPARAM);
            }
        }
        set_text(self.c.c_host, &typed);
    }

    fn refresh_devices(&self) {
        {
            let mut st = self.st.borrow_mut();
            if st.ts_busy {
                return;
            }
            st.ts_busy = true;
        }
        let first = self.st.borrow().ts_updated.is_none();
        if first {
            self.say(self.c.c_ts, self.t.ts_loading, Tone::Muted);
        }
        enable(self.c.c_refresh, false);
        let n = self.notifier.clone();
        if !spawn_thread("tailscale-status", move || n.send(Event::Devices(tailscale::status()))) {
            self.st.borrow_mut().ts_busy = false;
            enable(self.c.c_refresh, true);
        }
    }

    fn on_devices(&self, r: Result<tailscale::Status, Problem>) {
        let t = self.t;
        let (msg, tone) = {
            let mut st = self.st.borrow_mut();
            st.ts_busy = false;
            st.ts_updated = Some(Instant::now());
            match r {
                Ok(status) => {
                    st.me = status.self_device().cloned();
                    st.devices = status.peers().cloned().collect();
                    let (on, all) = (st.devices.iter().filter(|d| d.online).count(), st.devices.len());
                    if !status.running() {
                        ((t.ts_state)(&status.backend_state), Tone::Warn)
                    } else if all == 0 {
                        (t.ts_none.to_string(), Tone::Muted)
                    } else {
                        ((t.ts_count)(on, all), Tone::Muted)
                    }
                }
                Err(p) => {
                    st.me = None;
                    st.devices.clear();
                    match p {
                        Problem::NotInstalled => (t.ts_not_installed.to_string(), Tone::Bad),
                        Problem::NotRunning => (t.ts_not_running.to_string(), Tone::Warn),
                        Problem::Failed(e) => ((t.ts_failed)(&e), Tone::Bad),
                    }
                }
            }
        };
        enable(self.c.c_refresh, true);
        self.fill_devices();
        self.say(self.c.c_ts, &msg, tone);
        self.update_share_ui();
    }

    fn fill_devices(&self) {
        let t = self.t;
        let (rows, selected) = {
            let st = self.st.borrow();
            let typed = get_text(self.c.c_host);
            let rows: Vec<[String; 4]> = st
                .devices
                .iter()
                .map(|d| {
                    [
                        d.name.clone(),
                        d.os_label().to_string(),
                        d.address().map(|a| a.to_string()).unwrap_or_default(),
                        if d.online { t.online } else { t.offline }.to_string(),
                    ]
                })
                .collect();
            (rows, st.devices.iter().position(|d| d.matches(&typed)))
        };
        let list = self.c.c_list;
        self.filling.set(true);
        unsafe {
            SendMessageW(list, WM_SETREDRAW, 0, 0);
            SendMessageW(list, LVM_DELETEALLITEMS, 0, 0);
            for (i, row) in rows.iter().enumerate() {
                for (sub, text) in row.iter().enumerate() {
                    let mut w = wide(text);
                    let mut item: LVITEMW = std::mem::zeroed();
                    item.mask = LVIF_TEXT;
                    item.iItem = i as i32;
                    item.iSubItem = sub as i32;
                    item.pszText = w.as_mut_ptr();
                    if sub == 0 {
                        SendMessageW(list, LVM_INSERTITEMW, 0, &item as *const _ as LPARAM);
                    } else {
                        SendMessageW(list, LVM_SETITEMTEXTW, i, &item as *const _ as LPARAM);
                    }
                }
            }
            if let Some(i) = selected {
                let mut item: LVITEMW = std::mem::zeroed();
                item.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
                item.state = LVIS_SELECTED | LVIS_FOCUSED;
                SendMessageW(list, LVM_SETITEMSTATE, i, &item as *const _ as LPARAM);
                SendMessageW(list, LVM_ENSUREVISIBLE, i, 0);
            }
            SendMessageW(list, WM_SETREDRAW, 1, 0);
            InvalidateRect(list, null(), 1);
        }
        self.filling.set(false);
    }

    fn device_selected(&self, index: i32) {
        let text = {
            let st = self.st.borrow();
            picked_text(&st.devices, st.me.as_ref(), index.max(0) as usize)
        };
        if let Some(text) = text {
            set_text(self.c.c_host, &text);
        }
    }

    fn connect(&self) {
        let t = self.t;
        if !self.require_key() {
            return;
        }
        let typed = get_text(self.c.c_host).trim().to_string();
        if typed.is_empty() {
            self.say(self.c.c_msg, t.need_host, Tone::Warn);
            unsafe { SetFocus(self.c.c_host) };
            return;
        }
        let resolved = {
            let st = self.st.borrow();
            resolve_target(&typed, st.devices.iter().chain(st.me.iter()))
        };
        let Some((target, label)) = resolved else {
            self.say(self.c.c_msg, t.bad_host, Tone::Bad);
            unsafe { SetFocus(self.c.c_host) };
            return;
        };
        let args = viewer_args(&target, &self.connect_options());
        let mut child = match spawn_self(&args, false) {
            Ok(c) => c,
            Err(e) => {
                self.say(self.c.c_msg, &(t.launch_failed)(&e.to_string()), Tone::Bad);
                return;
            }
        };
        let stderr = child.stderr.take();
        let n = self.notifier.clone();
        let (host, entry) = (label.clone(), typed);
        if !spawn_thread("viewer-watch", move || watch_viewer(child, stderr, host, entry, n)) {
            self.say(self.c.c_msg, &(t.launch_failed)("cannot start a thread"), Tone::Bad);
            return;
        }
        self.say(self.c.c_msg, &(t.connecting)(&label), Tone::Accent);
        self.save_settings();
    }

    fn on_viewer(&self, host: &str, entry: &str, update: ViewerUpdate) {
        let t = self.t;
        match update {
            ViewerUpdate::Connected => {
                self.say(self.c.c_msg, &(t.connected)(host), Tone::Good);
                // Only hosts that worked are remembered, so typos do not pile up.
                {
                    let mut st = self.st.borrow_mut();
                    add_recent(&mut st.recent, entry);
                    write_data_file("recent.txt", &(st.recent.join("\n") + "\n"));
                }
                self.fill_recent();
            }
            ViewerUpdate::Exited { error: None, .. } => self.say(self.c.c_msg, &(t.ended)(host), Tone::Muted),
            ViewerUpdate::Exited { connected, error: Some(e) } => {
                let reason = if e.is_empty() { t.viewer_crashed } else { tidy_error(&e) };
                if connected {
                    self.say(self.c.c_msg, &(t.lost)(host, reason), Tone::Warn);
                } else {
                    let text = (t.connect_failed)(host, reason);
                    self.say(self.c.c_msg, &text, Tone::Bad);
                    message_box(self.hwnd, &text, MB_OK | MB_ICONWARNING);
                }
            }
        }
    }

    // ----- Share

    fn toggle_sharing(&self) {
        if self.st.borrow().host.is_some() {
            self.stop_sharing();
        } else {
            self.start_sharing();
        }
    }

    fn start_sharing(&self) {
        if !self.require_key() {
            return;
        }
        // Read before the host reads the key: any change after this is then noticed.
        let key_file = read_key_file().ok();
        let key_fp = keystore::user_key_fingerprint();
        let opts = self.share_options();
        let bind = std::env::var("SAFE_RDP_LAUNCHER_BIND").ok();
        let port = std::env::var("SAFE_RDP_LAUNCHER_PORT").ok();
        let spawned = sharing_overrides(bind.as_deref(), port.as_deref())
            .and_then(|(bind, port)| spawn_self(&host_args(&opts, bind, port), true).map_err(|e| e.to_string()));
        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => {
                self.st.borrow_mut().share = Share::Failed(e);
                self.update_share_ui();
                return;
            }
        };
        let tied = unsafe { AssignProcessToJobObject(self.job, child.as_raw_handle() as HANDLE) } != 0;
        let stderr = child.stderr.take();
        let stdin = child.stdin.take();
        let generation = {
            let mut st = self.st.borrow_mut();
            st.host_gen += 1;
            st.host = Some(HostProc { child, stdin });
            st.host_key = key_file;
            st.host_key_fp = key_fp;
            st.host_error = None;
            st.listen = None;
            st.share = Share::Starting;
            st.share_view_only = !opts.control;
            st.log.clear();
            if !tied {
                st.log.push_back("warning: the host is not tied to this window and may outlive it".into());
            }
            st.host_gen
        };
        let n = self.notifier.clone();
        let read = spawn_thread("host-log", move || {
            if let Some(err) = stderr {
                for_each_line(err, |line| n.send(Event::HostLine(generation, line)));
            }
            n.send(Event::HostExit(generation));
        });
        if !read {
            self.stop_sharing();
        }
        unsafe { SetTimer(self.hwnd, TIMER_KEY, KEY_CHECK_MS, None) };
        self.show_log();
        self.update_share_ui();
        self.save_settings();
    }

    fn stop_sharing(&self) {
        let (proc, generation) = {
            let mut st = self.st.borrow_mut();
            let p = st.host.take();
            if p.is_some() {
                st.share = Share::Stopping;
            }
            (p, st.host_gen)
        };
        let n = self.notifier.clone();
        if let Some(p) = proc
            && !spawn_thread("host-stop", move || {
                stop_host(p, STOP_GRACE);
                n.send(Event::HostStopped(generation));
            })
        {
            // Could not stop it in the background: the job object still ends it with us.
            let mut st = self.st.borrow_mut();
            st.share = Share::Failed("cannot stop the host process".into());
            // Nothing reports when it has exited, so a restart could not wait for its port.
            st.restart_after = None;
        }
        self.update_share_ui();
    }

    /// A host that `stop_sharing` stopped has exited: sharing is off now (whether or not its log
    /// ended first, or was ever read), unless a key change asked for it to start again.
    fn on_host_stopped(&self, generation: u64) {
        let restart = {
            let mut st = self.st.borrow_mut();
            if generation == st.host_gen && st.host.is_none() && st.share == Share::Stopping {
                st.share = Share::Off;
                st.host_error = None;
            }
            let due = st.restart_after == Some(generation);
            if due {
                st.restart_after = None;
            }
            // Unless sharing was started again meanwhile, or no usable key is left.
            due && st.host.is_none() && st.key == KeyState::Present
        };
        if restart {
            // Straight from "Stopping" to "Starting", with no "Off" shown in between.
            self.start_sharing();
            if self.st.borrow().host.is_some() {
                self.log_note("the stored key changed: sharing restarted with the new key");
            }
        } else {
            self.update_share_ui();
        }
    }

    /// The stored key was replaced or removed (`present`: a key is stored now), here or
    /// elsewhere. A host keeps the key it started with, so the one this window runs is stopped,
    /// and started again with the new key once it has exited. True if sharing restarts or stopped.
    fn key_replaced(&self, present: bool) -> bool {
        let (running, restarts) = {
            let mut st = self.st.borrow_mut();
            let running = st.host.is_some().then_some(st.host_gen);
            st.restart_after = restart_after_key_change(present, running, st.restart_after);
            (running.is_some(), st.restart_after.is_some())
        };
        if running {
            if !present {
                self.log_note("the stored key was removed or cannot be read: sharing stopped");
            }
            self.stop_sharing();
        }
        self.update_service_ui();
        self.update_share_ui();
        running || restarts
    }

    /// While a host runs: notices that the stored key changed behind this window's back (for
    /// example `safe-rdp keygen --force` or `key forget` in a terminal) and restarts or stops
    /// sharing, since the host keeps the key it started with.
    fn check_key_file(&self) {
        let changed = {
            let st = self.st.borrow();
            match (&st.host, &st.host_key) {
                (None, _) => None,
                (Some(_), Some(started)) => Some(key_file_changed(started, &read_key_file())),
                (Some(_), None) => Some(false),
            }
        };
        match changed {
            None => unsafe {
                KillTimer(self.hwnd, TIMER_KEY);
            },
            Some(false) => {}
            Some(true) if self.same_key_saved_again() => {}
            Some(true) => {
                // A key on display is no longer the stored one.
                if self.st.borrow().key_shown {
                    self.hide_key();
                }
                let key = key_state();
                self.st.borrow_mut().key = key;
                self.update_key_ui();
                self.key_replaced(key == KeyState::Present);
                // Whether the service has the key stored now.
                self.refresh_service();
            }
        }
    }

    /// The key file differs from the one the running host started with: whether it still holds
    /// that host's key (a key saved again is a fresh DPAPI blob). If so, the file as it is now
    /// is the one compared with from here on.
    fn same_key_saved_again(&self) -> bool {
        // Read before the key: a change in between shows at the next check.
        let file = read_key_file();
        let fp = keystore::user_key_fingerprint();
        let mut st = self.st.borrow_mut();
        let same = fp.is_some() && fp == st.host_key_fp;
        if same
            && let Ok(data) = file
            && !data.is_empty()
        {
            st.host_key = Some(data);
        }
        same
    }

    /// Adds a line of the window's own to the activity log.
    fn log_note(&self, line: &str) {
        {
            let mut st = self.st.borrow_mut();
            st.log.push_back(line.into());
            while st.log.len() > MAX_LOG_LINES {
                st.log.pop_front();
            }
        }
        self.show_log();
    }

    /// Returns true if the log changed.
    fn on_host_line(&self, generation: u64, line: &str) -> bool {
        let mut st = self.st.borrow_mut();
        if generation != st.host_gen {
            return false;
        }
        let (time, msg) = split_log(line);
        let event = host_event(msg);
        // While stopping, keep showing "Stopping" whatever the host still reports.
        let stopping = st.share == Share::Stopping;
        let changed_state = event.is_some() && !stopping;
        match event {
            Some(HostEvent::Error(e)) => st.host_error = Some(e),
            _ if stopping => {}
            Some(HostEvent::Listening(addr)) => {
                st.listen = Some(addr.clone());
                st.share = Share::Ready(addr);
            }
            Some(HostEvent::WaitingForTailscale) => st.share = Share::WaitingForTailscale,
            Some(HostEvent::SessionStarted(peer)) => st.share = Share::Connected(peer),
            Some(HostEvent::SessionEnded) => {
                if let Share::Connected(_) = st.share {
                    st.share = st.listen.clone().map(Share::Ready).unwrap_or(Share::Starting);
                }
            }
            None => {}
        }
        st.log.push_back(if time.is_empty() { msg.to_string() } else { format!("{time}  {msg}") });
        while st.log.len() > MAX_LOG_LINES {
            st.log.pop_front();
        }
        drop(st);
        if changed_state {
            self.update_share_ui();
        }
        true
    }

    fn on_host_exit(&self, generation: u64) {
        let exited = {
            let mut st = self.st.borrow_mut();
            if generation != st.host_gen {
                return;
            }
            st.host.take()
        };
        // The process closed stderr, so it is exiting; collect its status.
        let code = exited.map(|mut p| {
            drop(p.stdin.take());
            match p.child.try_wait() {
                Ok(Some(s)) => s.code(),
                _ => {
                    let _ = p.child.kill();
                    p.child.wait().ok().and_then(|s| s.code())
                }
            }
        });
        {
            let mut st = self.st.borrow_mut();
            // Stopped by `stop_sharing`: `on_host_stopped` ends "Stopping", once it has exited.
            if code.is_none() && st.share == Share::Stopping {
                return;
            }
            st.share = match (code, st.host_error.take()) {
                (None, _) => Share::Off, // stopped by the user
                (Some(_), Some(e)) => Share::Failed(e),
                (Some(Some(0)), None) => Share::Off,
                (Some(c), None) => Share::Failed((self.t.host_exited)(c.unwrap_or(-1))),
            };
        }
        self.update_share_ui();
    }

    fn show_log(&self) {
        let text = self.st.borrow().log.iter().map(String::as_str).collect::<Vec<_>>().join("\r\n");
        set_text(self.c.s_log, &text);
        unsafe { SendMessageW(self.c.s_log, WM_VSCROLL, SB_BOTTOM as usize, 0) };
    }

    fn update_share_ui(&self) {
        let t = self.t;
        let (status, tone, detail, running) = {
            let st = self.st.borrow();
            let me = st.me.as_ref().map(|d| d.name.as_str());
            let running = st.host.is_some();
            let (status, tone, detail): (String, Tone, String) = match &st.share {
                Share::Off if st.svc == Svc::Running => match svc_key(st.svc_key.as_deref(), st.key_fp.as_deref()) {
                    SvcKey::Mine => (t.st_off.into(), Tone::Muted, t.st_service_detail.into()),
                    SvcKey::Other => (t.st_off.into(), Tone::Warn, t.st_service_old_key.into()),
                    SvcKey::Unknown => (t.st_off.into(), Tone::Warn, t.st_service_unknown_key.into()),
                },
                Share::Off => (t.st_off.into(), Tone::Muted, t.st_off_detail.into()),
                Share::Starting => (t.st_starting.into(), Tone::Accent, String::new()),
                Share::WaitingForTailscale => (t.st_wait_ts.into(), Tone::Warn, t.st_wait_ts_detail.into()),
                Share::Ready(addr) => (t.st_ready.into(), Tone::Accent, (t.st_ready_detail)(&listen_label(addr, me))),
                Share::Connected(peer) => (
                    (t.st_connected)(&peer_label(peer, &st.devices)),
                    Tone::Good,
                    if st.share_view_only { t.st_connected_view } else { t.st_connected_control }.into(),
                ),
                Share::Stopping => (t.st_stopping.into(), Tone::Muted, String::new()),
                Share::Failed(e) => (t.st_failed.into(), Tone::Bad, e.clone()),
            };
            (format!("●  {status}"), tone, detail, running)
        };
        self.say(self.c.s_status, &status, tone);
        self.say(self.c.s_detail, &detail, if tone == Tone::Bad { Tone::Bad } else { Tone::Muted });
        set_text(self.c.s_toggle, if running { t.stop } else { t.start });
        self.sharing.set(running);
        unsafe { InvalidateRect(self.c.s_toggle, null(), 0) };
        let stopping = self.st.borrow().share == Share::Stopping;
        enable(self.c.s_toggle, !stopping);
        for h in self.c.share_options() {
            enable(h, !running && !stopping);
        }
        self.layout();
    }

    // ----- Service

    fn refresh_service(&self) {
        if self.st.borrow().svc_busy {
            return;
        }
        let n = self.notifier.clone();
        spawn_thread("service-status", move || n.send(Event::Service(service_info())));
    }

    fn on_service_status(&self, info: ServiceInfo) {
        {
            let mut st = self.st.borrow_mut();
            if st.svc_busy {
                return;
            }
            st.svc = match info.status.as_deref() {
                Ok("not installed") => Svc::NotInstalled,
                Ok("running") => Svc::Running,
                Ok(s) if s.starts_with("stopped") => Svc::Stopped,
                Ok("starting" | "stopping") => Svc::Changing,
                _ => Svc::Unknown,
            };
            st.svc_key = info.key;
            st.key_fp = info.mine;
        }
        let has_key = {
            let st = self.st.borrow();
            !svc_lacks_key(st.svc, svc_key(st.svc_key.as_deref(), st.key_fp.as_deref()))
        };
        // However it got there (Update key, Reinstall, a terminal): the note is out of date.
        if has_key {
            self.set_svc_note(None);
        }
        self.update_service_ui();
        self.update_share_ui();
    }

    /// Whether the background service is installed, asked now rather than taken from the last
    /// refresh, since it keeps the key it was given whatever happens to the stored one; also
    /// reads again which key it has and which one is stored. When that cannot be told, anything
    /// but a known "not installed" counts.
    fn service_installed(&self) -> bool {
        let info = service_info();
        let known = info.status.as_deref().ok().map(|s| s != "not installed");
        self.on_service_status(info);
        let st = self.st.borrow();
        st.svc_busy || known.unwrap_or(st.svc != Svc::NotInstalled)
    }

    /// The installed service has another key than the stored one, so the install button gives it
    /// that key rather than reinstalling. While its key cannot be told it stays a reinstall (see
    /// `svc_key_update`).
    fn key_update_due(&self) -> bool {
        let st = self.st.borrow();
        st.svc.installed() && st.key == KeyState::Present && svc_key(st.svc_key.as_deref(), st.key_fp.as_deref()) == SvcKey::Other
    }

    fn update_service_ui(&self) {
        let t = self.t;
        let (svc, busy, key) = {
            let st = self.st.borrow();
            (st.svc, st.svc_busy, svc_key(st.svc_key.as_deref(), st.key_fp.as_deref()))
        };
        let (index, tone) = match svc {
            Svc::Checking => (0, Tone::Muted),
            Svc::NotInstalled => (1, Tone::Muted),
            Svc::Running => (2, Tone::Good),
            Svc::Stopped => (3, Tone::Warn),
            Svc::Changing => (4, Tone::Accent),
            Svc::Unknown => (5, Tone::Muted),
        };
        let installed = svc.installed();
        let mut status = (t.svc_status)(t.svc_states[index]);
        let tone = match key {
            SvcKey::Other if installed && !busy => {
                status.push_str(t.svc_key_status);
                Tone::Warn
            }
            // It may well accept a previous key.
            SvcKey::Unknown if installed && !busy => {
                status.push_str(t.svc_key_unknown);
                Tone::Warn
            }
            _ => tone,
        };
        self.say(self.c.s_svc_status, &status, tone);
        let install = match installed {
            false => t.install,
            true if self.key_update_due() => t.update_key,
            true => t.reinstall,
        };
        set_text(self.c.s_install, install);
        enable(self.c.s_install, !busy && svc != Svc::Checking);
        enable(self.c.s_uninstall, !busy && installed);
        enable(self.c.s_sas, !busy);
    }

    fn service_op(&self, install: bool) {
        let t = self.t;
        if install && !self.require_key() {
            return;
        }
        // While the service has another key than the stored one, the install button gives it
        // that key alone (see `key_update_due`).
        let op = match install {
            false => SvcOp::Remove,
            true if self.key_update_due() => SvcOp::Rekey,
            true => SvcOp::Install,
        };
        let text = match op {
            SvcOp::Install if self.st.borrow().svc.installed() => t.svc_reinstall_confirm,
            SvcOp::Install => t.svc_install_confirm,
            SvcOp::Rekey => t.svc_rekey_confirm,
            SvcOp::Remove => t.svc_uninstall_confirm,
        };
        if confirm(self.hwnd, text) {
            self.run_service_op(op);
        }
    }

    /// Installs the service (with the options ticked under "While sharing, allow"), gives it the
    /// stored key, or removes it, in an elevated process. False if that could not be started.
    fn run_service_op(&self, op: SvcOp) -> bool {
        let args = match op {
            SvcOp::Remove => vec!["service".into(), "uninstall".into()],
            _ => {
                let Some(key) = keystore::user_key_fingerprint() else {
                    // The key is gone or unreadable since it was last looked at.
                    self.st.borrow_mut().key = key_state();
                    self.update_key_ui();
                    self.require_key();
                    return false;
                };
                if op == SvcOp::Rekey {
                    service_rekey_args(&key)
                } else {
                    service_install_args(&self.share_options(), is_checked(self.c.s_sas), &key)
                }
            }
        };
        self.save_settings();
        {
            let mut st = self.st.borrow_mut();
            st.svc_busy = true;
            st.svc = Svc::Changing;
        }
        self.update_service_ui();
        let (owner, n, params) = (self.hwnd as usize, self.notifier.clone(), args.join(" "));
        if !spawn_thread("service-op", move || n.send(Event::ServiceDone { op, result: run_elevated(owner, &params) })) {
            self.st.borrow_mut().svc_busy = false;
            self.refresh_service();
            return false;
        }
        true
    }

    fn on_service_done(&self, op: SvcOp, result: Result<u32, Elevation>) {
        let t = self.t;
        let done = matches!(result, Ok(0));
        self.st.borrow_mut().svc_busy = false;
        // As the command left it, not as it was before: a failed command may still have given
        // the service the key (and then not started it), or removed it.
        self.on_service_status(service_info());
        let note = {
            let st = self.st.borrow();
            let key = svc_key(st.svc_key.as_deref(), st.key_fp.as_deref());
            svc_lacks_key(st.svc, key).then(|| svc_note(t, st.key == KeyState::Present, key))
        };
        // Giving the service the key, or removing it, did not happen: say so where the key
        // was changed, too. (Once it has the key, `on_service_status` took that note away.)
        if !done && note.is_some() {
            self.set_svc_note(note);
        }
        let not_remove = op != SvcOp::Remove;
        match result {
            Ok(0) | Err(Elevation::Cancelled) => {}
            Ok(code) if code == service::EXIT_OTHER_KEY as u32 && not_remove => {
                message_box(self.hwnd, t.svc_other_key, MB_OK | MB_ICONWARNING);
            }
            Ok(code) if code == service::EXIT_NOT_STOPPED as u32 && not_remove => {
                message_box(self.hwnd, t.svc_not_stopped, MB_OK | MB_ICONWARNING);
            }
            Ok(code) if code == service::EXIT_NOT_STARTED as u32 && not_remove => {
                message_box(self.hwnd, t.svc_not_started, MB_OK | MB_ICONWARNING);
            }
            Ok(code) => {
                message_box(self.hwnd, &(t.svc_failed)(code), MB_OK | MB_ICONWARNING);
            }
            Err(Elevation::Failed(e)) => {
                message_box(self.hwnd, &e, MB_OK | MB_ICONWARNING);
            }
        }
    }

    // ----- Key

    fn require_key(&self) -> bool {
        if self.st.borrow().key == KeyState::Present {
            return true;
        }
        self.st.borrow_mut().banner = Some(Banner::NeedKey);
        self.update_key_ui();
        self.set_page(Page::Key, true);
        false
    }

    fn update_key_ui(&self) {
        let t = self.t;
        let (key, banner) = {
            let mut st = self.st.borrow_mut();
            if st.key == KeyState::Present {
                st.banner = None;
            }
            (st.key, st.banner)
        };
        let (text, tone) = match key {
            KeyState::Present => (t.key_stored, Tone::Good),
            KeyState::Missing => (t.key_missing, Tone::Warn),
            KeyState::Unreadable => (t.key_unreadable, Tone::Bad),
        };
        self.say(self.c.k_status, text, tone);
        set_text(
            self.c.k_banner,
            match banner {
                Some(Banner::NeedKey) => t.key_need,
                _ => t.key_welcome,
            },
        );
        enable(self.c.k_show, key == KeyState::Present);
        enable(self.c.k_remove, key != KeyState::Missing);
        self.apply_visibility();
        self.layout();
        unsafe { InvalidateRect(self.hwnd, null(), 1) };
    }

    fn key_message(&self, text: &str, tone: Tone) {
        self.say(self.c.k_msg, text, tone);
        self.layout();
    }

    /// Ends the Key-tab message with `note` (`svc_note`), in place of the one it may end with,
    /// or takes that one away (`None`), giving what is left its own tone back.
    fn set_svc_note(&self, note: Option<&'static str>) {
        let text = get_text(self.c.k_msg);
        let rest = without_svc_note(self.t, &text);
        match (note, rest) {
            (Some(n), _) => {
                if rest.is_none() {
                    let tone = self.tones.borrow().get(&(self.c.k_msg as usize)).copied();
                    self.st.borrow_mut().key_tone = tone.unwrap_or(Tone::Muted);
                }
                let text = format!("{}{n}", rest.unwrap_or(&text));
                self.key_message(text.trim_start(), Tone::Warn);
            }
            (None, Some(rest)) => {
                let tone = if rest.is_empty() { Tone::Muted } else { self.st.borrow().key_tone };
                self.key_message(rest, tone);
            }
            (None, None) => {}
        }
    }

    /// Asks before the stored key is replaced or removed; `svc`: the service is installed.
    fn confirm_key_change(&self, text: &str, svc: bool) -> bool {
        confirm(self.hwnd, &format!("{text}{}", if svc { self.t.key_svc_confirm } else { "" }))
    }

    /// After this window replaced or removed the stored key: restarts or stops the host it runs
    /// and, when the service is installed without the new key, offers to give it that key or to
    /// remove it, right away. Reports `done` (in `tone`) along with what that changed.
    fn key_changed_here(&self, done: &str, tone: Tone) {
        let t = self.t;
        // The callers checked the service just before the change, so this is the old key's.
        let (present, old) = {
            let st = self.st.borrow();
            (st.key == KeyState::Present, st.key_fp.clone())
        };
        let mut text = done.to_string();
        if self.key_replaced(present) {
            text.push_str(if present { t.sharing_restarts } else { t.sharing_stopped });
        }
        let svc = self.service_installed();
        let needed = {
            let st = self.st.borrow();
            // While a service command runs nothing new can be read, nor offered.
            st.svc_busy || svc_needs_update(st.svc_key.as_deref(), old.as_deref(), st.key_fp.as_deref())
        };
        let declined = svc && needed && !self.offer_service_update(present);
        self.key_message(&text, tone);
        if declined {
            let note = {
                let st = self.st.borrow();
                svc_note(t, present, svc_key(st.svc_key.as_deref(), st.key_fp.as_deref()))
            };
            self.set_svc_note(Some(note));
        }
    }

    /// Offers to give the service the stored key (`present`) or to remove it. True if that is
    /// now under way.
    fn offer_service_update(&self, present: bool) -> bool {
        let t = self.t;
        let op = {
            let st = self.st.borrow();
            if st.svc_busy {
                return false;
            }
            svc_key_update(present, svc_key(st.svc_key.as_deref(), st.key_fp.as_deref()))
        };
        let offer = match op {
            SvcOp::Rekey => t.svc_key_offer,
            SvcOp::Install => t.svc_key_reinstall_offer,
            SvcOp::Remove => t.svc_key_remove_offer,
        };
        if message_box(self.hwnd, offer, MB_YESNO | MB_ICONWARNING) != IDYES {
            return false;
        }
        self.run_service_op(op)
    }

    fn create_key(&self) {
        let t = self.t;
        let svc = self.service_installed();
        if self.st.borrow().key == KeyState::Present && !self.confirm_key_change(t.replace_confirm, svc) {
            return;
        }
        let saved = keys::generate().and_then(|k| keystore::save_user_key(&k).map(|_| k));
        match saved {
            Ok(k) => {
                self.st.borrow_mut().key = KeyState::Present;
                let mut text = keys::format_key(&k);
                self.display_key(&text);
                wipe_string(&mut text);
                self.update_key_ui();
                self.key_changed_here(t.created, Tone::Good);
            }
            Err(e) => self.key_message(&(t.key_failed)(&e.to_string()), Tone::Bad),
        }
    }

    fn show_stored_key(&self) {
        match keystore::load_user_key() {
            Ok(k) => {
                let mut text = keys::format_key(&k);
                self.display_key(&text);
                wipe_string(&mut text);
                self.key_message("", Tone::Muted);
            }
            Err(e) => self.key_message(&(self.t.key_failed)(&e.to_string()), Tone::Bad),
        }
    }

    fn display_key(&self, text: &str) {
        set_secret_text(self.c.k_shown, text);
        self.st.borrow_mut().key_shown = true;
        self.apply_visibility();
        self.layout();
        unsafe {
            InvalidateRect(self.hwnd, null(), 1);
            SetFocus(self.c.k_copy);
        }
    }

    fn hide_key(&self) {
        scrub_edit(self.c.k_shown);
        self.st.borrow_mut().key_shown = false;
        self.apply_visibility();
        self.layout();
        unsafe { InvalidateRect(self.hwnd, null(), 1) };
    }

    fn copy_key(&self) {
        let t = self.t;
        match keystore::load_user_key() {
            Ok(k) => {
                let mut text = keys::format_key(&k);
                let ok = clipboard::write_text(self.hwnd, &text);
                wipe_string(&mut text);
                if ok {
                    self.st.borrow_mut().clip_seq = Some(unsafe { GetClipboardSequenceNumber() });
                    unsafe { SetTimer(self.hwnd, TIMER_CLIPBOARD, CLIPBOARD_CLEAR_MS, None) };
                    self.key_message(t.copied, Tone::Good);
                } else {
                    self.key_message(t.copy_failed, Tone::Bad);
                }
            }
            Err(e) => self.key_message(&(t.key_failed)(&e.to_string()), Tone::Bad),
        }
    }

    /// Empties the clipboard if it still holds the key we put there. While another program has
    /// it open, tries again shortly rather than leaving the key there.
    fn clear_clipboard(&self) {
        unsafe { KillTimer(self.hwnd, TIMER_CLIPBOARD) };
        let Some(seq) = self.st.borrow().clip_seq else { return };
        let ours = || unsafe { GetClipboardSequenceNumber() } == seq;
        if ours() {
            if !clipboard::open(self.hwnd) {
                unsafe { SetTimer(self.hwnd, TIMER_CLIPBOARD, CLIPBOARD_RETRY_MS, None) };
                return;
            }
            unsafe {
                // Asked again while it is open, when nothing else can change it.
                if ours() {
                    EmptyClipboard();
                }
                CloseClipboard();
            }
        }
        self.st.borrow_mut().clip_seq = None;
    }

    fn import_key(&self) {
        let t = self.t;
        let h = self.c.k_import_text;
        let mut buf = vec![0u16; 256];
        let n = unsafe { GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32) }.max(0) as usize;
        let mut text = String::from_utf16_lossy(&buf[..n.min(buf.len())]);
        wipe_wide(&mut buf);
        let parsed = keys::parse_key(&text);
        wipe_string(&mut text);
        if n == 0 {
            self.key_message(t.import_empty, Tone::Warn);
            unsafe { SetFocus(h) };
            return;
        }
        let k = match parsed {
            Ok(k) => k,
            Err(e) => {
                self.key_message(&(t.bad_key)(&e.to_string()), Tone::Bad);
                unsafe { SetFocus(h) };
                return;
            }
        };
        let current = self.st.borrow().key;
        if current == KeyState::Present && keystore::load_user_key().is_ok_and(|old| old.0 == k.0) {
            scrub_edit(h);
            self.key_message(t.same_key, Tone::Muted);
            return;
        }
        let svc = self.service_installed();
        if current == KeyState::Present && !self.confirm_key_change(t.replace_confirm, svc) {
            return;
        }
        match keystore::save_user_key(&k) {
            Ok(_) => {
                scrub_edit(h);
                self.st.borrow_mut().key = KeyState::Present;
                if self.st.borrow().key_shown {
                    self.hide_key();
                }
                self.update_key_ui();
                self.key_changed_here(t.imported, Tone::Good);
            }
            Err(e) => self.key_message(&(t.key_failed)(&e.to_string()), Tone::Bad),
        }
    }

    fn remove_key(&self) {
        let t = self.t;
        let svc = self.service_installed();
        if !self.confirm_key_change(t.remove_confirm, svc) {
            return;
        }
        if self.st.borrow().key_shown {
            self.hide_key();
        }
        match keystore::forget_user_key() {
            Ok(removed) => {
                self.st.borrow_mut().key = key_state();
                self.update_key_ui();
                if removed {
                    self.key_changed_here(t.removed, Tone::Muted);
                } else {
                    self.key_message(t.nothing_removed, Tone::Muted);
                }
            }
            Err(e) => self.key_message(&(t.key_failed)(&e.to_string()), Tone::Bad),
        }
    }

    // ----- closing

    fn confirm_close(&self) -> bool {
        self.st.borrow().host.is_none() || confirm(self.hwnd, self.t.close_sharing)
    }

    fn shutdown(&self) {
        unsafe {
            KillTimer(self.hwnd, TIMER_DEVICES);
        }
        self.save_settings();
        let host = self.st.borrow_mut().host.take();
        if let Some(p) = host {
            stop_host(p, Duration::from_millis(800));
        }
        self.clear_clipboard();
        if self.st.borrow().key_shown {
            scrub_edit(self.c.k_shown);
        }
        scrub_edit(self.c.k_import_text);
    }
}

/// Follows one viewer process: reports when it connects and how it ended.
fn watch_viewer(mut child: Child, stderr: Option<std::process::ChildStderr>, host: String, entry: String, n: Notifier) {
    let mut connected = false;
    let mut error = None;
    if let Some(err) = stderr {
        for_each_line(err, |line| match viewer_line(split_log(&line).1) {
            Some(ViewerLine::Connected) if !connected => {
                connected = true;
                n.send(Event::Viewer { host: host.clone(), entry: entry.clone(), update: ViewerUpdate::Connected });
            }
            Some(ViewerLine::Error(e)) => error = Some(e),
            _ => {}
        });
    }
    // A failing viewer logs "error: ..." last; an empty reason means it died without one.
    let failed = !child.wait().is_ok_and(|s| s.success());
    let error = failed.then(|| error.unwrap_or_default());
    n.send(Event::Viewer { host, entry, update: ViewerUpdate::Exited { connected, error } });
}

/// Drops the "cannot connect to ADDR: " prefix the viewer puts before the OS error.
fn tidy_error(e: &str) -> &str {
    e.strip_prefix("cannot connect to ").and_then(|rest| rest.split_once(": ")).map(|(_, reason)| reason).unwrap_or(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(name: &str, ip: &str) -> Device {
        Device {
            name: name.into(),
            dns_name: format!("{name}.example.ts.net"),
            ips: vec![ip.parse().unwrap()],
            os: "windows".into(),
            online: true,
            is_self: false,
        }
    }

    #[test]
    fn settings_roundtrip_and_defaults() {
        let d = Settings::default();
        assert_eq!(Settings::parse(""), d);
        assert_eq!(Settings::parse(&d.format()), d);
        let mut s = d.clone();
        s.connect.fullscreen = true;
        s.connect.quality = 2;
        s.connect.scale = 3;
        s.connect.monitor = 5;
        s.share.control = false;
        s.share.files = true;
        s.sas = true;
        let text = s.format();
        assert!(text.contains("quality=2\n") && text.contains("share_control=0\n"));
        assert_eq!(Settings::parse(&text), s);
        // What the user ticks is kept.
        s.connect.clipboard = true;
        s.connect.audio = true;
        assert_eq!(Settings::parse(&s.format()), s);
    }

    #[test]
    fn settings_ignore_garbage() {
        let s = Settings::parse(
            "version=2\nquality=9\nscale=-1\nmonitor=x\nfullscreen=yes\nunknown=1\nno equals sign\n clipboard = 1 \r\n",
        );
        let mut want = Settings::default();
        want.connect.clipboard = true;
        assert_eq!(s, want);
    }

    #[test]
    fn viewer_clipboard_and_sound_are_opt_in() {
        let d = Settings::default();
        assert!(!d.connect.clipboard && !d.connect.audio);
        assert_eq!(viewer_args("100.64.0.2", &d.connect), ["connect", "100.64.0.2"]);
        // Earlier launchers ticked both by default and saved them after every connection: such
        // a file turns them off again, and keeps everything else.
        let old = "fullscreen=1\nclipboard=1\nsound=1\nprivacy=1\nquality=1\nshare_clipboard=1\n";
        let s = Settings::parse(old);
        assert!(!s.connect.clipboard && !s.connect.audio);
        assert!(s.connect.fullscreen && s.connect.privacy && s.share.clipboard);
        assert_eq!(s.connect.quality, 1);
        assert_eq!(Settings::parse(&format!("version=1\n{old}")), s);
        // Saved since: kept, in any order.
        let s = Settings::parse(&format!("{old}version=2\n"));
        assert!(s.connect.clipboard && s.connect.audio);
        assert!(Settings::parse(&format!("version=3\n{old}")).connect.clipboard);
        assert!(d.format().starts_with("version=2\n"));
    }

    #[test]
    fn key_file_changes_are_noticed() {
        use std::io::{Error, ErrorKind};
        let started = b"blob-1".to_vec();
        assert!(!key_file_changed(&started, &Ok(started.clone())));
        assert!(key_file_changed(&started, &Ok(b"blob-2".to_vec())));
        assert!(key_file_changed(&started, &Ok(b"blob-".to_vec())));
        // Removed: the host must stop.
        assert!(key_file_changed(&started, &Err(Error::from(ErrorKind::NotFound))));
        // Caught while it is being rewritten, or locked for a moment: look again later.
        assert!(!key_file_changed(&started, &Ok(Vec::new())));
        assert!(!key_file_changed(&started, &Err(Error::from(ErrorKind::PermissionDenied))));
    }

    #[test]
    fn sharing_restarts_after_the_host_that_had_the_old_key() {
        // Running host 4: restart once it has exited.
        assert_eq!(restart_after_key_change(true, Some(4), None), Some(4));
        // Host 4 is still stopping after an earlier change: it is the one to wait for.
        assert_eq!(restart_after_key_change(true, None, Some(4)), Some(4));
        assert_eq!(restart_after_key_change(true, None, None), None);
        // No key left: nothing restarts, not even a restart that was already waiting.
        assert_eq!(restart_after_key_change(false, Some(5), None), None);
        assert_eq!(restart_after_key_change(false, None, Some(4)), None);
    }

    #[test]
    fn host_validation() {
        for ok in [
            "pc",
            "DESKTOP-EXAMPLE1",
            "build-server.tail0a1b2c.ts.net",
            "100.64.0.1",
            "100.64.0.1:47301",
            "fd7a:115c:a1e0::1",
            "[fd7a::1]:5",
        ] {
            assert!(valid_host(ok), "{ok}");
        }
        for bad in ["", "-x", "--key-file", "a b", "a;b", "pc\n", "名前", &"a".repeat(254)] {
            assert!(!valid_host(bad), "{bad}");
        }
    }

    #[test]
    fn every_listed_device_can_be_connected() {
        // Peers without a MagicDNS name are listed under their OS host name.
        let mut beta = dev("Beta box", "100.64.0.5");
        beta.dns_name.clear();
        beta.ips.insert(0, "fd7a:115c:a1e0::5".parse().unwrap());
        let devices = [dev("desk", "100.64.0.2"), beta, dev("사무실-PC", "100.64.0.6"), dev("-evil", "100.64.0.7")];
        let resolve = |s: &str| resolve_target(s, devices.iter());
        for d in &devices {
            let (target, label) = resolve(&d.name).unwrap_or_else(|| panic!("{}", d.name));
            assert_eq!(target, d.address().unwrap().to_string(), "connects by address");
            assert_eq!(label, d.name);
        }
        assert_eq!(resolve("beta box"), Some(("100.64.0.5".into(), "Beta box".into())));
        assert_eq!(resolve("desk.example.ts.net"), Some(("100.64.0.2".into(), "desk".into())));
        // Anything else must be a host name or address, never an option or free text.
        assert_eq!(resolve("other-pc"), Some(("other-pc".into(), "other-pc".into())));
        for bad in ["--key-file", "-x", "a b", "名前"] {
            assert_eq!(resolve(bad), None, "{bad}");
        }
        // Picking from the list: the name, unless another device shares it.
        let twins = [dev("Beta box", "100.64.0.8"), dev("BETA BOX", "100.64.0.9"), dev("desk", "100.64.0.2")];
        let me = dev("desk", "100.64.0.1");
        for (i, d) in twins.iter().enumerate() {
            let picked = picked_text(&twins, Some(&me), i).unwrap();
            assert_eq!(picked, d.address().unwrap().to_string());
            assert_eq!(resolve_target(&picked, twins.iter()).unwrap().0, picked);
        }
        assert_eq!(picked_text(&devices, None, 1).as_deref(), Some("Beta box"));
        assert_eq!(picked_text(&devices, None, 9), None);
    }

    #[test]
    fn shown_key_is_copied_only_through_the_copy_button() {
        use KeyEdit::*;
        let (c, x, ins, del) = (VK_C as WPARAM, VK_X as WPARAM, VK_INSERT as WPARAM, VK_DELETE as WPARAM);
        assert_eq!(key_edit_action(WM_COPY, 0, false, false), Copy);
        assert_eq!(key_edit_action(WM_KEYDOWN, c, true, false), Copy);
        assert_eq!(key_edit_action(WM_KEYDOWN, ins, true, false), Copy);
        for (msg, wp, ctrl, shift) in [
            (WM_CONTEXTMENU, 0, false, false),
            (WM_CUT, 0, false, false),
            (WM_KEYDOWN, x, true, false),
            (WM_KEYDOWN, del, false, true),
            (WM_CHAR, 0x03, true, false),
            (WM_CHAR, 0x18, true, false),
        ] {
            assert_eq!(key_edit_action(msg, wp, ctrl, shift), Block, "{msg:#x} {wp:#x}");
        }
        // Selecting, scrolling and moving the caret still work.
        for (msg, wp, ctrl, shift) in [
            (WM_KEYDOWN, c, false, false),
            (WM_KEYDOWN, VK_LEFT as WPARAM, false, true),
            (WM_KEYDOWN, b'A' as WPARAM, true, false),
            (WM_CHAR, b'c' as WPARAM, false, false),
            (WM_LBUTTONDOWN, 0, false, false),
        ] {
            assert_eq!(key_edit_action(msg, wp, ctrl, shift), Pass, "{msg:#x} {wp:#x}");
        }
    }

    #[test]
    fn recent_hosts() {
        let mut r = parse_recent("alpha\n\n  beta  \nALPHA\n--bad\nwith space\n");
        assert_eq!(r, ["alpha", "beta"]);
        add_recent(&mut r, "Beta");
        assert_eq!(r, ["Beta", "alpha"]);
        add_recent(&mut r, "-nope");
        assert_eq!(r, ["Beta", "alpha"]);
        for i in 0..20 {
            add_recent(&mut r, &format!("h{i}"));
        }
        assert_eq!(r.len(), MAX_RECENT);
        assert_eq!(r[0], "h19");
        let many: String = (0..30).map(|i| format!("x{i}\n")).collect();
        assert_eq!(parse_recent(&many).len(), MAX_RECENT);
    }

    #[test]
    fn viewer_command_line() {
        let o = ConnectOptions { clipboard: false, audio: false, ..Default::default() };
        assert_eq!(viewer_args("100.64.0.2", &o), ["connect", "100.64.0.2"]);
        let o = ConnectOptions {
            fullscreen: true,
            clipboard: true,
            audio: true,
            privacy: true,
            view_only: true,
            quality: 1,
            scale: 3,
            monitor: 5,
        };
        assert_eq!(
            viewer_args("pc", &o),
            [
                "connect",
                "pc",
                "--fullscreen",
                "--clipboard",
                "--view-only",
                "--audio",
                "--privacy",
                "--quality",
                "lossless",
                "--downscale",
                "4",
                "--monitor",
                "all"
            ]
        );
        let o = ConnectOptions { clipboard: false, audio: false, quality: 2, scale: 1, monitor: 2, ..Default::default() };
        assert_eq!(viewer_args("pc", &o), ["connect", "pc", "--quality", "low", "--downscale", "2", "--monitor", "2"]);
        // The first quality leaves the choice to the host; balanced has to be asked for.
        let o = ConnectOptions { clipboard: false, audio: false, quality: 3, ..Default::default() };
        assert_eq!(viewer_args("pc", &o), ["connect", "pc", "--quality", "balanced"]);
        // Out-of-range indices add nothing.
        let o = ConnectOptions { clipboard: false, audio: false, quality: 7, scale: 9, monitor: 9, ..Default::default() };
        assert_eq!(viewer_args("pc", &o), ["connect", "pc"]);
    }

    #[test]
    fn host_command_lines() {
        let d = ShareOptions::default();
        assert_eq!(host_args(&d, None, None), ["host", "--stop-on-eof"]);
        let all = ShareOptions { control: false, clipboard: true, files: true, audio: true, privacy: true };
        assert_eq!(
            host_args(&all, Some("127.0.0.1".parse().unwrap()), Some(47301)),
            ["host", "--stop-on-eof", "--view-only", "--clipboard", "--files", "--audio", "--privacy", "--bind", "127.0.0.1", "--port", "47301"]
        );
        const FP: &str = "891d3768f5c4f960";
        assert_eq!(service_install_args(&d, false, FP), ["service", "install", "--expect-key", FP]);
        let a = service_install_args(&ShareOptions { clipboard: true, ..d }, true, FP);
        assert_eq!(a, ["service", "install", "--expect-key", FP, "--clipboard", "--enable-sas"]);
        assert!(a.iter().all(|s| !s.contains([' ', '"'])));
        // What the elevated command takes for the key it must find, and for its options.
        let (expect, rest) = service::expected_key(&a[2..]).unwrap();
        assert_eq!((expect.as_deref(), rest), (Some(FP), &a[4..]));
        let a = service_rekey_args(FP);
        assert_eq!(a, ["service", "rekey", "--expect-key", FP]);
        assert_eq!(service::expected_key(&a[2..]).unwrap(), (Some(FP.to_string()), &[][..]));
    }

    #[test]
    fn the_service_key_is_compared_by_fingerprint() {
        let (mine, other) = (Some("891d3768f5c4f960"), Some("0123456789abcdef"));
        assert_eq!(svc_key(mine, mine), SvcKey::Mine);
        assert_eq!(svc_key(other, mine), SvcKey::Other);
        assert_eq!(svc_key(other, None), SvcKey::Other, "no key stored here");
        assert_eq!(svc_key(None, mine), SvcKey::Unknown);
        assert_eq!(svc_key(None, None), SvcKey::Unknown);
        // A new key: offered unless the service has it already (as after importing its key).
        assert!(svc_needs_update(other, other, mine));
        assert!(svc_needs_update(Some("fedcba9876543210"), other, mine));
        assert!(!svc_needs_update(mine, other, mine));
        assert!(svc_needs_update(None, other, mine));
        // A removed key: offered unless the service has some other key.
        assert!(svc_needs_update(other, other, None));
        assert!(!svc_needs_update(mine, other, None));
        assert!(svc_needs_update(mine, None, None), "the removed key could not be read");
        assert!(svc_needs_update(None, other, None));
    }

    #[test]
    fn a_service_of_unknown_key_is_reinstalled() {
        // Another key: given the stored one alone. No recorded key, as from a safe-rdp that
        // predates the fingerprint: reinstalled, which replaces that old program too.
        assert_eq!(svc_key_update(true, SvcKey::Other), SvcOp::Rekey);
        assert_eq!(svc_key_update(true, SvcKey::Unknown), SvcOp::Install);
        for key in [SvcKey::Mine, SvcKey::Other, SvcKey::Unknown] {
            assert_eq!(svc_key_update(false, key), SvcOp::Remove);
        }
        // After a failed command, read again: a service given the key but not started has it.
        assert!(!svc_lacks_key(Svc::Stopped, SvcKey::Mine));
        assert!(svc_lacks_key(Svc::Stopped, SvcKey::Other));
        assert!(svc_lacks_key(Svc::Running, SvcKey::Unknown));
        assert!(svc_lacks_key(Svc::Unknown, SvcKey::Other), "may be installed");
        assert!(!svc_lacks_key(Svc::NotInstalled, SvcKey::Unknown), "removed after all");
    }

    #[test]
    fn the_key_note_names_the_button_and_goes_once_the_service_has_the_key() {
        for t in [&EN, &KO] {
            // Update key only for a service known to have another key than the stored one.
            assert_eq!(svc_note(t, true, SvcKey::Other), t.svc_key_note);
            assert_eq!(svc_note(t, true, SvcKey::Unknown), t.svc_reinstall_note);
            assert_eq!(svc_note(t, false, SvcKey::Other), t.svc_reinstall_note, "no key stored: Reinstall");
            // Either note comes off the end of the message, and nothing else does.
            for note in [t.svc_key_note, t.svc_reinstall_note] {
                assert_eq!(without_svc_note(t, &format!("{}{note}", t.created)), Some(t.created));
                assert_eq!(without_svc_note(t, note.trim_start()), Some(""));
            }
            assert_eq!(without_svc_note(t, t.created), None);
            assert_eq!(without_svc_note(t, ""), None);
        }
    }

    #[test]
    fn overrides() {
        assert_eq!(sharing_overrides(None, None), Ok((None, None)));
        assert_eq!(sharing_overrides(Some(" "), Some("")), Ok((None, None)));
        assert_eq!(sharing_overrides(Some("127.0.0.1"), Some("47301")), Ok((Some("127.0.0.1".parse().unwrap()), Some(47301))));
        assert!(sharing_overrides(Some("localhost"), None).is_err());
        assert!(sharing_overrides(None, Some("0")).is_err());
        assert!(sharing_overrides(None, Some("70000")).is_err());
    }

    #[test]
    fn log_lines() {
        assert_eq!(split_log("2025-01-01 12:00:00 session started: 100.64.0.2:5000"), ("12:00:00", "session started: 100.64.0.2:5000"));
        assert_eq!(split_log("2025-01-01 12:00:00 "), ("12:00:00", ""));
        assert_eq!(split_log("plain text"), ("", "plain text"));
        assert_eq!(split_log("2026-11-20 23:27:5x oops"), ("", "2026-11-20 23:27:5x oops"));
        assert_eq!(split_log("한국어 로그 줄이 길게 이어집니다"), ("", "한국어 로그 줄이 길게 이어집니다"));
        assert_eq!(split_log(""), ("", ""));
    }

    #[test]
    fn host_status_lines() {
        assert_eq!(
            host_event("safe-rdp host listening on 100.64.0.1:47300 (view-only: false, clipboard: true)"),
            Some(HostEvent::Listening("100.64.0.1:47300".into()))
        );
        assert_eq!(host_event("waiting for Tailscale to come up (no 100.64.0.0/10 address yet)..."), Some(HostEvent::WaitingForTailscale));
        assert_eq!(host_event("session started: 100.64.0.2:51000"), Some(HostEvent::SessionStarted("100.64.0.2:51000".into())));
        assert_eq!(host_event("session ended: 100.64.0.2:51000 disconnected"), Some(HostEvent::SessionEnded));
        assert_eq!(
            host_event("error: cannot listen on 100.64.0.1:47300: in use"),
            Some(HostEvent::Error("cannot listen on 100.64.0.1:47300: in use".into()))
        );
        assert_eq!(host_event("authentication failed for 100.64.0.3:1: bad"), None);
        assert_eq!(viewer_line("connected to pc: remote screen 1920x1080"), Some(ViewerLine::Connected));
        assert_eq!(viewer_line("connecting to 100.64.0.2:47300..."), None);
        assert_eq!(viewer_line("error: cannot connect"), Some(ViewerLine::Error("cannot connect".into())));
        assert_eq!(tidy_error("cannot connect to 127.0.0.1:47399: refused (os error 10061)"), "refused (os error 10061)");
        assert_eq!(tidy_error("cannot connect to [fd7a::1]:47300: timed out"), "timed out");
        assert_eq!(tidy_error("cannot resolve pc: no such host"), "cannot resolve pc: no such host");
        assert_eq!(tidy_error("cannot connect to x"), "cannot connect to x");
    }

    #[test]
    fn labels() {
        assert_eq!(listen_label("100.64.0.1:47300", Some("workstation")), "workstation (100.64.0.1)");
        assert_eq!(listen_label("100.64.0.1:47301", Some("workstation")), "workstation (100.64.0.1:47301)");
        assert_eq!(listen_label("100.64.0.1:47300", None), "100.64.0.1");
        assert_eq!(listen_label("127.0.0.1:47300", Some("workstation")), "127.0.0.1");
        assert_eq!(listen_label("[fd7a::1]:5", None), "[fd7a::1]:5");
        assert_eq!(listen_label("garbage", None), "garbage");
        let devs = [dev("laptop", "100.64.0.2")];
        assert_eq!(peer_label("100.64.0.2:5000", &devs), "laptop");
        assert_eq!(peer_label("[::ffff:100.64.0.2]:5000", &devs), "laptop");
        assert_eq!(peer_label("100.64.0.9:5000", &devs), "100.64.0.9");
        assert_eq!(peer_label("weird", &devs), "weird");
    }

    #[test]
    fn line_reader_bounds_and_lossy() {
        let mut data = b"one\r\ntwo\n".to_vec();
        data.extend(std::iter::repeat_n(b'x', 10_000));
        data.extend(b"\n\xff\xfe end");
        let mut lines = Vec::new();
        for_each_line(&data[..], |l| lines.push(l));
        assert_eq!(lines[0], "one");
        assert_eq!(lines[1], "two");
        assert!(lines.iter().all(|l| l.len() <= MAX_LINE as usize));
        assert_eq!(lines.iter().filter(|l| l.starts_with('x')).map(|l| l.len()).sum::<usize>(), 10_000);
        assert!(lines.last().unwrap().ends_with(" end"));
    }

    #[test]
    fn mul_div_rounds_like_win32() {
        assert_eq!(mul_div(100, 144, 96), 150);
        assert_eq!(mul_div(1, 3, 2), 2);
        assert_eq!(mul_div(-1, 3, 2), -2);
        assert_eq!(mul_div(10, -3, 4), -8);
        assert_eq!(mul_div(5, 5, 0), 0);
        assert_eq!(mul_div(i32::MAX, 2, 1), i32::MAX);
        assert_eq!(-mul_div(100, 144, 720), -20);
    }

    #[test]
    fn both_languages_are_complete() {
        for t in [&EN, &KO] {
            for s in [t.connect, t.start, t.stop, t.create, t.import, t.key_warning, t.svc_text, t.st_service_old_key, t.svc_key_offer] {
                assert!(!s.is_empty());
            }
            for s in [t.update_key, t.svc_other_key, t.svc_not_stopped, t.svc_not_started, t.st_service_unknown_key] {
                assert!(!s.is_empty());
            }
            // Added to other text.
            for s in [t.svc_key_status, t.svc_key_unknown, t.svc_key_note, t.svc_reinstall_note, t.sharing_restarts, t.sharing_stopped] {
                assert!(s.starts_with(' ') && s.len() > 1, "{s}");
            }
            assert!(t.key_svc_confirm.starts_with("\n\n") && t.svc_key_remove_offer.contains("\n\n"));
            for s in [t.svc_install_confirm, t.svc_reinstall_confirm, t.svc_rekey_confirm, t.svc_key_offer, t.svc_key_reinstall_offer] {
                assert!(s.contains("\n\n"), "{s}");
            }
            // Wrapped source lines leave no runs of spaces behind.
            for s in [
                t.replace_confirm,
                t.remove_confirm,
                t.key_svc_confirm,
                t.svc_key_offer,
                t.svc_key_reinstall_offer,
                t.svc_key_remove_offer,
                t.svc_text,
                t.st_service_old_key,
                t.st_service_unknown_key,
                t.svc_not_stopped,
                t.svc_not_started,
                t.svc_install_confirm,
                t.svc_reinstall_confirm,
                t.svc_rekey_confirm,
                t.svc_other_key,
            ] {
                assert!(!s.contains("  "), "{s}");
            }
            assert!((t.ts_count)(1, 3).contains('1') && (t.ts_count)(1, 3).contains('3'));
            assert!((t.connect_failed)("pc", "boom").contains("pc") && (t.connect_failed)("pc", "boom").contains("boom"));
        }
    }

    #[test]
    #[ignore = "opens the launcher window; close it to finish"]
    fn launcher_window() {
        run().unwrap();
    }
}
