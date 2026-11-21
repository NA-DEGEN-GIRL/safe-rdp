//! Headless X server for hosts without a desktop (servers, containers): starts Xvfb on a free
//! display with a private random cookie, optionally runs a session command inside it, and
//! stops both when dropped.
//!
//! /tmp/.X11-unix is shared by every local user, so a display is only used once it is proven
//! to be ours: the directory must be one no other user controls, Xvfb reports through
//! `-displayfd` when it accepts clients, and both socket names of the display must then belong
//! to the Xvfb process we started. A host serving the display talks to that process only.
//!
//! The cookie Xvfb and the host use lives in a file without a name, which Xvfb inherits as a
//! descriptor: nothing done to a path (a tmp cleaner ageing it out, another user re-creating
//! it) can lock the host out or slip Xvfb another cookie. Programs in the session get a copy in
//! a private directory, kept from tmp cleaners for as long as the display runs.

use super::x11::{self, AuthEntry, COOKIE_NAME, Conn, FAMILY_WILD, Target, encode_auth_entry};
use crate::util::{Error, Result, wipe};
use crate::{bail, log};
use std::ffi::{c_char, c_int, c_uint};
use std::fs::{File, FileTimes};
use std::io::{ErrorKind, PipeReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

unsafe extern "C" {
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn prctl(option: c_int, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn waitid(idtype: c_int, id: u32, info: *mut SigInfo, options: c_int) -> c_int;
    fn geteuid() -> u32;
    fn memfd_create(name: *const c_char, flags: c_uint) -> c_int;
}

const PR_SET_PDEATHSIG: c_int = 1;
const F_SETFD: c_int = 2;
const MFD_CLOEXEC: c_uint = 1;
const O_DIRECTORY: c_int = 0o200000;
const O_NOFOLLOW: c_int = 0o400000;
const P_PID: c_int = 1;
const WNOHANG: c_int = 1;
const WEXITED: c_int = 4;
const WNOWAIT: c_int = 0x0100_0000;
const CLD_EXITED: i32 = 1;
const CLD_DUMPED: i32 = 3;

/// `siginfo_t` as `waitid` fills it in for a child (x86_64 layout).
#[repr(C, align(8))]
struct SigInfo {
    signo: i32,
    errno: i32,
    code: i32,
    _pad: i32,
    pid: i32,
    uid: u32,
    status: i32,
    _rest: [i32; 25],
}

const _: () = assert!(std::mem::size_of::<SigInfo>() == 128);

/// How `child` ended, if it has, seen without reaping it (an error once it is reaped): until
/// `stop_group` reaps it, the zombie keeps its pid and process group id from being reused.
fn peek_exit(child: &Child) -> std::io::Result<Option<ExitStatus>> {
    let mut info = SigInfo { signo: 0, errno: 0, code: 0, _pad: 0, pid: 0, uid: 0, status: 0, _rest: [0; 25] };
    if unsafe { waitid(P_PID, child.id(), &mut info, WEXITED | WNOHANG | WNOWAIT) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // As a wait status: the exit code in the second byte, else the signal (0x80: core dumped).
    Ok((info.pid != 0).then(|| {
        ExitStatus::from_raw(match info.code {
            CLD_EXITED => (info.status & 0xff) << 8,
            CLD_DUMPED => (info.status & 0x7f) | 0x80,
            _ => info.status & 0x7f,
        })
    }))
}

/// How `child` ended, if it has, without reaping it.
fn exit_status(child: &mut Child) -> Option<ExitStatus> {
    // Reaped already: std keeps the status it got.
    peek_exit(child).unwrap_or_else(|_| child.try_wait().ok().flatten())
}

/// Backstop for a host killed without a chance to clean up: the child gets SIGTERM when the
/// thread that started it ends (the main thread, for the host).
fn die_with_parent(c: &mut Command) -> &mut Command {
    unsafe {
        c.pre_exec(|| {
            prctl(PR_SET_PDEATHSIG, SIGTERM as u64, 0, 0, 0);
            Ok(())
        })
    }
}

const SIGTERM: c_int = 15;
const SIGKILL: c_int = 9;

/// Display numbers tried when none is given. Starting at 20 keeps clear of real desktops
/// (:0, :1, ...) and SSH X forwarding (:10 upwards).
pub const FIRST_DISPLAY: u32 = 20;
/// A session that works on a stock Ubuntu server: a terminal with its own D-Bus session bus
/// (so it does not attach to a desktop session elsewhere), ending when the terminal closes.
pub const DEFAULT_SESSION: &str = "exec dbus-run-session -- gnome-terminal --wait";

/// `DEFAULT_SESSION` with a terminal sized to fill a `width` x `height` display: there is no
/// window manager to maximise it (about 10 x 22 pixels per cell with the stock font).
pub fn default_session(width: u32, height: u32) -> String {
    let cols = (width.saturating_sub(20) / 10).max(20);
    let rows = (height.saturating_sub(30) / 22).max(5);
    format!("{DEFAULT_SESSION} --geometry={cols}x{rows}+0+0")
}
const LAST_DISPLAY: u32 = 99;
const START_TIMEOUT: Duration = Duration::from_secs(15);
/// How often `watch` checks on Xvfb and the session.
const WATCH_INTERVAL: Duration = Duration::from_millis(500);
/// How often `watch` marks the private directory and its files as used (tmp cleaners go by
/// days).
const REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

/// Xvfb and the session command, each leading its own process group. Only `stop_group` reaps
/// them.
struct Procs {
    xvfb: Child,
    session: Option<Child>,
    /// Set while dropping: the exits that follow are expected.
    closing: bool,
}

impl Procs {
    /// Why the display is no longer usable, once Xvfb or the session command has exited.
    fn ended(&mut self, dir: &Path) -> Option<String> {
        if let Some(status) = exit_status(&mut self.xvfb) {
            return Some(format!("Xvfb exited ({status}): {}", log_tail(&dir.join("xvfb.log"))));
        }
        let status = self.session.as_mut().and_then(exit_status)?;
        Some(if status.success() {
            "the session ended".to_string()
        } else {
            format!("the session ended ({status}): {}", log_tail(&dir.join("session.log")))
        })
    }
}

/// A running Xvfb (plus optional session). Dropping it stops everything and deletes the cookie.
pub struct VirtualDisplay {
    number: u32,
    dir: PathBuf,
    /// The session's copy of the cookie, in `dir`.
    auth: PathBuf,
    /// The cookie Xvfb and this process read (see `cookie_file`).
    cookie: File,
    kept: Kept,
    /// Shared with the `watch` thread, which only holds a weak reference.
    procs: Arc<Mutex<Procs>>,
}

/// The private directory and the files in it, held open while the display runs. The directory
/// is locked, which keeps systemd-tmpfiles away from it and everything in it; `watch` also
/// renews their timestamps for cleaners that only go by age (tmpwatch, tmpreaper). At the end
/// only a directory that still is this one is deleted, and the cookie is wiped through `auth`.
struct Kept {
    dir: File,
    /// The session's copy of the cookie.
    auth: File,
    logs: Vec<File>,
}

impl Kept {
    fn try_clone(&self) -> std::io::Result<Kept> {
        let logs = self.logs.iter().map(File::try_clone).collect::<std::io::Result<_>>()?;
        Ok(Kept { dir: self.dir.try_clone()?, auth: self.auth.try_clone()?, logs })
    }

    /// Marks the directory and its files as just used.
    fn touch(&self) {
        let now = SystemTime::now();
        let times = FileTimes::new().set_accessed(now).set_modified(now);
        for f in [&self.dir, &self.auth].into_iter().chain(&self.logs) {
            let _ = f.set_times(times);
        }
    }

    /// Whether `dir` and `auth` still name the directory and the cookie file held.
    fn in_place(&self, dir: &Path, auth: &Path) -> bool {
        names(dir, &self.dir) && names(auth, &self.auth)
    }
}

fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// Whether `path` itself (not a link there) is the file `f` is open on.
fn names(path: &Path, f: &File) -> bool {
    match (std::fs::symlink_metadata(path), f.metadata()) {
        (Ok(a), Ok(b)) => same_file(&a, &b),
        _ => false,
    }
}

/// Whether opening `path` (following links) reaches the file `f` is open on.
fn leads_to(path: &Path, f: &File) -> bool {
    match (std::fs::metadata(path), f.metadata()) {
        (Ok(a), Ok(b)) => same_file(&a, &b),
        _ => false,
    }
}

/// The name in /proc of descriptor `fd` of process `pid` (or "self").
fn fd_path(pid: &str, fd: c_int) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/fd/{fd}"))
}

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b)
}

/// Whether `dir` can hold our private directory: a directory of this user that nobody else may
/// enter, as a runtime directory must be.
fn is_private_dir(dir: &Path, euid: u32) -> bool {
    std::fs::metadata(dir).is_ok_and(|m| m.is_dir() && m.uid() == euid && m.mode() & 0o077 == 0)
}

/// Where the private directory goes: the per-user runtime directory, else (a host started
/// outside a login, where `/run/user/<uid>` may come and go with other sessions of the user)
/// the temporary directory, which `Kept` protects from tmp cleaners.
fn private_base() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|d| is_private_dir(d, unsafe { geteuid() }))
        .unwrap_or_else(std::env::temp_dir)
}

/// A new 0700 directory for the session's cookie and the logs.
fn private_dir(tag: &str) -> Result<PathBuf> {
    let dir = private_base().join(format!("safe-rdp-{tag}-{}", crate::util::hex_encode(&random_bytes(6)?)));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir)
}

/// Opens directory `dir` (not through a link) and locks it for as long as it stays open:
/// systemd-tmpfiles skips a directory it cannot lock, and everything in it.
fn hold_dir(dir: &Path) -> Result<File> {
    let f = std::fs::OpenOptions::new().read(true).custom_flags(O_DIRECTORY | O_NOFOLLOW).open(dir)?;
    f.lock_shared()?;
    Ok(f)
}

/// One Xauthority entry with the cookie for display `number`, for any address.
fn auth_bytes(number: u32, cookie: &[u8]) -> Vec<u8> {
    let entry = AuthEntry {
        family: FAMILY_WILD,
        address: Vec::new(),
        number: number.to_string().into_bytes(),
        name: COOKIE_NAME.to_vec(),
        data: cookie.to_vec(),
    };
    encode_auth_entry(&entry)
}

/// Writes an Xauthority file holding one wildcard-address cookie for display `number`.
fn write_auth(path: &Path, number: u32, cookie: &[u8]) -> Result<File> {
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    let mut bytes = auth_bytes(number, cookie);
    let r = f.write_all(&bytes).and_then(|_| f.sync_all());
    wipe(&mut bytes);
    r?;
    Ok(f)
}

/// The cookie as Xvfb and this process read it: an Xauthority file without a name (a memfd),
/// reached through descriptors only. Not inherited by the programs this process starts.
fn cookie_file(number: u32, cookie: &[u8]) -> Result<File> {
    let fd = unsafe { memfd_create(c"safe-rdp-xauthority".as_ptr(), MFD_CLOEXEC) };
    if fd < 0 {
        bail!("cannot create the cookie file: {}", std::io::Error::last_os_error());
    }
    // SAFETY: a new descriptor that nothing else owns.
    let mut f = unsafe { File::from_raw_fd(fd) };
    f.set_permissions(std::fs::Permissions::from_mode(0o400))?;
    let mut bytes = auth_bytes(number, cookie);
    let r = f.write_all(&bytes);
    wipe(&mut bytes);
    r?;
    Ok(f)
}

/// True if display `n` is in use or being set up: its socket, its lock file, or the temporary
/// lock file an X server creates first exists (in any form, dangling links included).
fn socket_taken(n: u32) -> bool {
    [x11::local_socket_path(n), format!("/tmp/.X{n}-lock"), format!("/tmp/.tX{n}-lock")]
        .iter()
        .any(|p| std::fs::symlink_metadata(p).is_ok())
}

fn log_tail(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(3)..].join(" / ")
}

/// Stops a process group: SIGTERM, a grace period, then SIGKILL for whatever is left. The
/// leader is reaped last, so the group id cannot pass to another process while it is signalled.
fn stop_group(child: &mut Child) {
    if peek_exit(child).is_err() {
        return; // reaped already: its group id may be someone else's by now
    }
    let pid = child.id() as c_int;
    unsafe { kill(-pid, SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(3);
    while exit_status(child).is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    unsafe { kill(-pid, SIGKILL) };
    let _ = child.wait();
}

/// Refuses a socket directory that another user controls: its owner can swap our display's
/// socket for theirs, which the sticky bit does not prevent.
fn check_socket_dir(dir: &Path, euid: u32) -> Result<()> {
    let m = std::fs::symlink_metadata(dir).map_err(|e| format!("cannot check {}: {e}", dir.display()))?;
    let writable_by_others = m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0;
    if !m.file_type().is_dir() || (m.uid() != 0 && m.uid() != euid) || writable_by_others {
        bail!(
            "refusing to start a virtual display: {} must be a directory owned by root or by this user, \
             sticky if others can write to it",
            dir.display()
        );
    }
    Ok(())
}

/// Reads the display number Xvfb writes to its `-displayfd` pipe once it accepts clients.
fn read_display_number(ready: &mut PipeReader, xvfb: &Mutex<Procs>, n: u32, log_path: &Path) -> Result<u32> {
    let deadline = Instant::now() + START_TIMEOUT;
    let mut got = Vec::new();
    let mut open = true;
    loop {
        if let Some(status) = exit_status(&mut xvfb.lock().unwrap_or_else(|e| e.into_inner()).xvfb) {
            bail!("Xvfb on :{n} exited ({status}): {}", log_tail(log_path));
        }
        if Instant::now() > deadline {
            bail!("Xvfb on :{n} did not come up: {}", log_tail(log_path));
        }
        // Signals (EINTR) only make this report nothing ready.
        if !open || !x11::wait_readable(&[ready.as_raw_fd()], 100)?[0] {
            if !open {
                std::thread::sleep(Duration::from_millis(25));
            }
            continue;
        }
        let mut b = [0u8; 16];
        match ready.read(&mut b) {
            // Closed without a number: Xvfb is exiting.
            Ok(0) => open = false,
            Ok(k) => got.extend_from_slice(&b[..k]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
        if let Some(end) = got.iter().position(|&c| c == b'\n') {
            let shown = std::str::from_utf8(&got[..end]).ok().and_then(|s| s.parse().ok());
            return shown.ok_or_else(|| Error::msg("Xvfb reported a malformed display number"));
        }
        if got.len() > 16 {
            bail!("Xvfb reported a malformed display number");
        }
    }
}

impl VirtualDisplay {
    /// Starts a virtual display on the first free number from 20, points `DISPLAY` and
    /// `XAUTHORITY` of this process at it (the latter at the cookie file without a name), and
    /// runs `session` (a shell command) inside it.
    ///
    /// Call during start-up, before other threads are running: it changes the environment.
    /// Signals arriving meanwhile (a stop request) do not disturb it.
    pub fn start(width: u32, height: u32, session: Option<&str>) -> Result<VirtualDisplay> {
        let vd = VirtualDisplay::spawn(None, width, height, session)?;
        // Should Xvfb die, a server another user starts on its socket names gets nothing from us.
        x11::pin_server(vd.procs().xvfb.id())?;
        // SAFETY: documented to be called before other threads exist.
        unsafe {
            std::env::set_var("DISPLAY", vd.display_name());
            std::env::set_var("XAUTHORITY", vd.cookie_path());
        }
        log!("virtual display {} ({width}x{height}) started", vd.display_name());
        Ok(vd)
    }

    /// Starts Xvfb on `number` (or the first free one from 20) without touching this
    /// process's environment.
    pub fn spawn(number: Option<u32>, width: u32, height: u32, session: Option<&str>) -> Result<VirtualDisplay> {
        if !(64..=16384).contains(&width) || !(64..=16384).contains(&height) {
            bail!("virtual display size {width}x{height} is out of range (64..16384)");
        }
        let candidates: Vec<u32> = match number {
            Some(n) => vec![n],
            None => (FIRST_DISPLAY..=LAST_DISPLAY).filter(|&n| !socket_taken(n)).take(5).collect(),
        };
        if candidates.is_empty() {
            bail!("no free X display number between {FIRST_DISPLAY} and {LAST_DISPLAY}");
        }
        // Checked again once Xvfb has made sure it exists.
        let dir = Path::new(x11::SOCKET_DIR);
        if std::fs::symlink_metadata(dir).is_ok() {
            check_socket_dir(dir, unsafe { geteuid() })?;
        }
        let mut last = Error::msg("no display tried");
        for n in candidates {
            match VirtualDisplay::try_start(n, width, height) {
                Ok(mut vd) => {
                    if let Some(cmd) = session {
                        let (child, log) = vd.run_session(cmd)?;
                        vd.procs().session = Some(child);
                        vd.kept.logs.push(log);
                    }
                    return Ok(vd);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn try_start(n: u32, width: u32, height: u32) -> Result<VirtualDisplay> {
        let dir = private_dir(&format!("x{n}"))?;
        let auth = dir.join("Xauthority");
        let log_path = dir.join("xvfb.log");
        let started = (|| -> Result<(Child, PipeReader, File, Kept)> {
            let held = hold_dir(&dir)?;
            let mut secret = random_bytes(16)?;
            let files = write_auth(&auth, n, &secret).and_then(|copy| Ok((copy, cookie_file(n, &secret)?)));
            wipe(&mut secret);
            let (copy, cookie) = files?;
            // Xvfb opens the cookie by its descriptor's name, which must lead to it.
            let cookie_fd = cookie.as_raw_fd();
            let cookie_name = fd_path("self", cookie_fd);
            if !leads_to(&cookie_name, &cookie) {
                bail!("cannot hand Xvfb its cookie: {} does not lead to it (is /proc mounted?)", cookie_name.display());
            }
            let log = File::create(&log_path)?;
            let kept = Kept { dir: held, auth: copy, logs: vec![log.try_clone()?] };
            // Xvfb writes the display number here once clients can connect.
            let (ready, ready_tx) = std::io::pipe()?;
            let fd = ready_tx.as_raw_fd();
            let mut cmd = Command::new("Xvfb");
            die_with_parent(&mut cmd)
                .arg(format!(":{n}"))
                .args(["-displayfd", &fd.to_string()])
                .args(["-screen", "0", &format!("{width}x{height}x24"), "-nolisten", "tcp", "-noreset", "-auth"])
                .arg(&cookie_name)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(log)
                .process_group(0);
            // Like every descriptor std creates, the pipe is close-on-exec, and so is the
            // cookie; Xvfb must keep both.
            unsafe {
                cmd.pre_exec(move || {
                    for fd in [fd, cookie_fd] {
                        if fcntl(fd, F_SETFD, 0 as c_int) == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
            let child = cmd.spawn().map_err(|e| Error::msg(format!("cannot start Xvfb (is it installed?): {e}")))?;
            drop(ready_tx);
            Ok((child, ready, cookie, kept))
        })();
        let (xvfb, mut ready, cookie, kept) = match started {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e);
            }
        };
        let pid = xvfb.id();
        let procs = Arc::new(Mutex::new(Procs { xvfb, session: None, closing: false }));
        let vd = VirtualDisplay { number: n, dir, auth, cookie, kept, procs };
        let shown = read_display_number(&mut ready, &vd.procs, n, &log_path)?;
        if shown != n {
            bail!("Xvfb started display :{shown} instead of :{n}");
        }
        check_socket_dir(Path::new(x11::SOCKET_DIR), unsafe { geteuid() })?;
        // Proves the listener is our Xvfb before the cookie goes anywhere.
        Conn::connect_to_server(&vd.target(), pid).map_err(|e| format!("cannot use display :{n}: {e}"))?;
        // An X server that could not read its cookie lets every local user in.
        let anonymous = Target { display: vd.display_name(), xauthority: Some(PathBuf::from("/dev/null")) };
        if Conn::connect_to_server(&anonymous, pid).is_ok() {
            bail!("Xvfb on :{n} lets clients in without the cookie: {}", log_tail(&log_path));
        }
        Ok(vd)
    }

    /// Starts the session command; also returns its log, to be kept with the directory.
    fn run_session(&self, cmd: &str) -> Result<(Child, File)> {
        let log = File::create(self.dir.join("session.log"))?;
        let kept = log.try_clone()?;
        let child = die_with_parent(&mut Command::new("sh"))
            .arg("-c")
            .arg(cmd)
            .env("DISPLAY", self.display_name())
            .env("XAUTHORITY", &self.auth)
            .env("XDG_SESSION_TYPE", "x11")
            .env("GDK_BACKEND", "x11")
            .env("QT_QPA_PLATFORM", "xcb")
            .env_remove("WAYLAND_DISPLAY")
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .process_group(0)
            .spawn()
            .map_err(|e| format!("cannot start session '{cmd}': {e}"))?;
        Ok((child, kept))
    }

    fn procs(&self) -> MutexGuard<'_, Procs> {
        self.procs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Watches Xvfb and the session command from a background thread. When either exits, it
    /// logs why and sets `stop`, so a host serving this display shuts down (dropping it)
    /// instead of serving a dead or empty screen; a session command must therefore run for as
    /// long as the session lasts. The thread ends with the display, and dropping the display
    /// does not set `stop`. It also keeps the private directory looking in use to tmp cleaners
    /// (a host may sit without viewers for weeks), and says so if it is gone anyway.
    pub fn watch(&self, stop: &'static AtomicBool) -> Result<()> {
        let procs = Arc::downgrade(&self.procs);
        let (dir, auth, name) = (self.dir.clone(), self.auth.clone(), self.display_name());
        let kept = self.kept.try_clone()?;
        std::thread::Builder::new().name("virtual-display".into()).spawn(move || {
            let mut refreshed = Instant::now();
            let mut warned = false;
            loop {
                std::thread::sleep(WATCH_INTERVAL);
                let Some(procs) = procs.upgrade() else { return };
                let mut p = procs.lock().unwrap_or_else(|e| e.into_inner());
                if p.closing {
                    return;
                }
                if let Some(why) = p.ended(&dir) {
                    log!("virtual display {name}: {why}; stopping");
                    stop.store(true, Ordering::SeqCst);
                    return;
                }
                // Under the lock, which a display being dropped (its directory deleted) holds.
                if refreshed.elapsed() >= REFRESH_INTERVAL {
                    refreshed = Instant::now();
                    kept.touch();
                    // The host and Xvfb do not need the copy, only programs the session starts.
                    if !warned && !kept.in_place(&dir, &auth) {
                        warned = true;
                        log!(
                            "virtual display {name}: {} was deleted or replaced; programs started in the session \
                             from now on cannot open windows",
                            auth.display()
                        );
                    }
                }
            }
        })?;
        Ok(())
    }

    /// `:N`
    pub fn display_name(&self) -> String {
        format!(":{}", self.number)
    }

    /// For connections of this process.
    pub fn target(&self) -> Target {
        Target { display: self.display_name(), xauthority: Some(self.cookie_path()) }
    }

    /// The cookie file's name in /proc, under this process's id rather than "self", so a
    /// program that inherits `XAUTHORITY` never reads a descriptor of its own instead. Other
    /// users cannot open it, nor can such programs once this process is not dumpable.
    fn cookie_path(&self) -> PathBuf {
        fd_path(&std::process::id().to_string(), self.cookie.as_raw_fd())
    }
}

/// For tests; the host learns about exits through `watch`.
#[cfg(test)]
impl VirtualDisplay {
    /// The private Xauthority file holding this display's cookie, for programs started in it.
    pub fn xauthority(&self) -> &Path {
        &self.auth
    }

    /// False once the session command has exited (always true without a session).
    pub fn session_running(&self) -> bool {
        match &self.procs().session {
            Some(c) => matches!(peek_exit(c), Ok(None)),
            None => true,
        }
    }

    /// The last lines the session wrote, for error messages.
    pub fn session_log_tail(&self) -> String {
        log_tail(&self.dir.join("session.log"))
    }

    /// False once Xvfb has exited.
    pub fn running(&self) -> bool {
        matches!(peek_exit(&self.procs().xvfb), Ok(None))
    }
}

impl Drop for VirtualDisplay {
    fn drop(&mut self) {
        let mut p = self.procs();
        p.closing = true;
        x11::retire_server(p.xvfb.id());
        if let Some(s) = &mut p.session {
            stop_group(s);
        }
        stop_group(&mut p.xvfb);
        drop(p);
        // Overwrite both cookies before they go, through the descriptors held: never whatever
        // a path leads to by now.
        for f in [&self.cookie, &self.kept.auth] {
            if let Ok(len) = f.metadata().map(|m| m.len() as usize) {
                let _ = f.write_all_at(&vec![0u8; len], 0);
            }
        }
        // Only the directory made for this display, should another have taken its name.
        if names(&self.dir, &self.kept.dir) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::x11::{find_cookie, parse_xauthority};

    #[test]
    fn auth_file_is_private_and_matches_any_address() {
        let dir = private_dir("test").unwrap();
        let path = dir.join("Xauthority");
        write_auth(&path, 42, &[7; 16]).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        let entries = parse_xauthority(&std::fs::read(&path).unwrap());
        assert_eq!(find_cookie(&entries, 256, b"somehost", 42).map(|c| c.0.clone()), Some(vec![7; 16]));
        assert!(find_cookie(&entries, 256, b"somehost", 43).is_none());
        assert!(write_auth(&path, 42, &[1; 16]).is_err(), "never overwrites");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_cookie_file_has_no_name() {
        const F_GETFD: c_int = 1;
        const FD_CLOEXEC: c_int = 1;
        let f = cookie_file(42, &[7; 16]).unwrap();
        assert_eq!(f.metadata().unwrap().permissions().mode() & 0o777, 0o400);
        // Read the way Xvfb ("self") and this process (its id) do.
        for pid in ["self".to_string(), std::process::id().to_string()] {
            let path = fd_path(&pid, f.as_raw_fd());
            assert!(leads_to(&path, &f), "{}", path.display());
            let entries = parse_xauthority(&std::fs::read(&path).unwrap());
            assert_eq!(find_cookie(&entries, 256, b"somehost", 42).map(|c| c.0.clone()), Some(vec![7; 16]));
        }
        // Only Xvfb is handed it.
        assert_eq!(unsafe { fcntl(f.as_raw_fd(), F_GETFD) } & FD_CLOEXEC, FD_CLOEXEC);
    }

    #[test]
    fn runtime_dirs_must_be_private() {
        let euid = unsafe { geteuid() };
        let dir = private_dir("base").unwrap();
        assert!(is_private_dir(&dir, euid));
        let set = |mode| std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        for mode in [0o750, 0o705, 0o1777] {
            set(mode);
            assert!(!is_private_dir(&dir, euid), "mode {mode:o}");
        }
        set(0o700);
        assert!(!is_private_dir(&dir, euid.wrapping_add(1)), "another user's");
        assert!(!is_private_dir(&dir.join("missing"), euid));
        let file = dir.join("file");
        std::fs::write(&file, b"").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!is_private_dir(&file, euid), "not a directory");
        std::fs::remove_dir_all(&dir).unwrap();
        let base = private_base();
        assert!(is_private_dir(&base, euid) || base == std::env::temp_dir(), "{}", base.display());
    }

    /// Files are told by what is open, not by name: a replacement, a link or a renamed original
    /// is not the file held.
    #[test]
    fn held_files_are_told_from_replacements() {
        let dir = private_dir("held").unwrap();
        let held = hold_dir(&dir).unwrap();
        let path = dir.join("Xauthority");
        let f = write_auth(&path, 1, &[1; 16]).unwrap();
        assert!(names(&dir, &held) && names(&path, &f));
        std::fs::rename(&path, dir.join("moved")).unwrap();
        assert!(!names(&path, &f), "gone");
        std::fs::write(&path, b"").unwrap();
        assert!(!names(&path, &f), "replaced");
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(dir.join("moved"), &path).unwrap();
        assert!(!names(&path, &f), "a link to it");
        assert!(leads_to(&path, &f));
        let moved = dir.with_extension("moved");
        std::fs::rename(&dir, &moved).unwrap();
        std::fs::create_dir(&dir).unwrap();
        assert!(!names(&dir, &held), "another directory of the same name");
        std::fs::remove_dir(&dir).unwrap();
        std::fs::remove_dir_all(&moved).unwrap();
    }

    /// What tmp cleaners look at: timestamps (renewed), and for systemd-tmpfiles whether it can
    /// lock the directory (not while the display runs).
    #[test]
    fn kept_files_look_in_use() {
        let dir = private_dir("kept").unwrap();
        let auth = dir.join("Xauthority");
        let log = dir.join("xvfb.log");
        let kept = Kept { dir: hold_dir(&dir).unwrap(), auth: write_auth(&auth, 1, &[1; 16]).unwrap(), logs: vec![File::create(&log).unwrap()] };
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        for f in [&kept.dir, &kept.auth, &kept.logs[0]] {
            f.set_times(FileTimes::new().set_accessed(old).set_modified(old)).unwrap();
        }
        let clone = kept.try_clone().unwrap();
        clone.touch();
        let recent = SystemTime::now() - Duration::from_secs(600);
        for p in [&dir, &auth, &log] {
            let m = std::fs::metadata(p).unwrap();
            assert!(m.modified().unwrap() > recent && m.accessed().unwrap() > recent, "{}", p.display());
        }
        assert!(kept.in_place(&dir, &auth));
        // systemd-tmpfiles asks for this lock (non-blocking) before it cleans a directory.
        let cleaner = File::open(&dir).unwrap();
        assert!(cleaner.try_lock().is_err(), "the directory is not locked");
        drop((kept, clone));
        assert!(cleaner.try_lock().is_ok(), "still locked once nothing holds it");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn socket_dir_must_be_ours() {
        use std::os::unix::fs::PermissionsExt;
        let euid = unsafe { geteuid() };
        let dir = private_dir("sockets").unwrap();
        let set = |mode| std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        for (mode, safe) in [(0o700, true), (0o755, true), (0o1777, true), (0o1775, true), (0o777, false), (0o775, false)] {
            set(mode);
            assert_eq!(check_socket_dir(&dir, euid).is_ok(), safe, "mode {mode:o}");
        }
        set(0o755);
        if euid != 0 {
            assert!(check_socket_dir(&dir, euid + 1).is_err(), "another user's directory");
        }
        let link = dir.with_extension("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let err = check_socket_dir(&link, euid).err().expect("followed a link");
        assert!(err.to_string().contains("refusing"), "{err}");
        std::fs::remove_file(&link).unwrap();
        assert!(check_socket_dir(&dir.join("missing"), euid).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An ended process stays a zombie, holding its pid and process group id, until
    /// `stop_group` is done signalling its group.
    #[test]
    fn exits_are_seen_without_reaping() {
        let spawn = |script: &str| Command::new("sh").args(["-c", script]).process_group(0).spawn().unwrap();
        let mut p = Procs { xvfb: spawn("sleep 30"), session: Some(spawn("exit 3")), closing: false };
        let deadline = Instant::now() + Duration::from_secs(5);
        let why = loop {
            if let Some(why) = p.ended(Path::new("/nonexistent")) {
                break why;
            }
            assert!(Instant::now() < deadline, "the exit was not seen");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(why.contains("exit status: 3"), "{why}");
        let session = p.session.as_mut().unwrap();
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", session.id())).expect("the session was reaped");
        assert!(stat.contains(") Z "), "{stat}");
        assert_eq!(exit_status(session).map(|s| s.code()), Some(Some(3)), "seen again");
        stop_group(session);
        assert!(peek_exit(session).is_err(), "not reaped");
        assert!(exit_status(&mut p.xvfb).is_none());
        stop_group(&mut p.xvfb);
        assert_eq!(exit_status(&mut p.xvfb).and_then(|s| s.signal()), Some(SIGTERM));
    }

    #[test]
    fn rejects_silly_sizes() {
        assert!(VirtualDisplay::spawn(Some(79), 10, 10, None).is_err());
        assert!(VirtualDisplay::spawn(Some(79), 1024, 100_000, None).is_err());
    }

    #[test]
    fn lock_files_mark_a_display_taken() {
        // A number far outside the X range, so no real display is affected.
        let n = 3_000_000_000 + std::process::id();
        assert!(!socket_taken(n));
        for path in [format!("/tmp/.tX{n}-lock"), format!("/tmp/.X{n}-lock")] {
            std::fs::write(&path, b"").unwrap();
            assert!(socket_taken(n), "{path}");
            std::fs::remove_file(&path).unwrap();
        }
        let link = format!("/tmp/.tX{n}-lock");
        std::os::unix::fs::symlink("/nonexistent/safe-rdp", &link).unwrap();
        assert!(socket_taken(n), "dangling link");
        std::fs::remove_file(&link).unwrap();
        assert!(!socket_taken(n));
    }

    /// Top-level windows of at least 200x100 on the display.
    fn big_windows(c: &mut Conn) -> usize {
        let root = c.root();
        let seq = c.send(crate::platform::linux::x11::Req::new(15, 0).u32(root)).unwrap(); // QueryTree
        let r = c.reply(seq).unwrap();
        let n = u16::from_le_bytes([r[16], r[17]]) as usize;
        let children: Vec<u32> = r[32..32 + 4 * n].chunks_exact(4).map(|w| u32::from_le_bytes(w.try_into().unwrap())).collect();
        children.into_iter().filter(|&w| c.get_geometry(w).is_ok_and(|g| g.width >= 200 && g.height >= 100)).count()
    }

    #[test]
    #[ignore = "needs Xvfb, dbus-run-session and gnome-terminal; SRDP_TEST_SESSION overrides the command"]
    fn runs_a_session() {
        let cmd = std::env::var("SRDP_TEST_SESSION").unwrap_or_else(|_| DEFAULT_SESSION.into());
        let vd = VirtualDisplay::spawn(Some(78), 1024, 768, Some(&cmd)).unwrap();
        let mut c = Conn::connect(&vd.target()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while big_windows(&mut c) == 0 {
            assert!(vd.session_running(), "session exited: {}", vd.session_log_tail());
            assert!(Instant::now() < deadline, "no window appeared: {}", vd.session_log_tail());
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(vd.session_running());
        let started = Instant::now();
        drop(c);
        drop(vd);
        eprintln!("session stopped in {:?}", started.elapsed());
    }

    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn starts_and_stops() {
        let n = 71;
        let auth;
        {
            let vd = VirtualDisplay::spawn(Some(n), 320, 200, Some("sleep 30")).unwrap();
            assert_eq!(vd.display_name(), ":71");
            assert!(vd.running() && vd.session_running());
            let mut c = Conn::connect(&vd.target()).unwrap();
            let g = c.get_geometry(c.root()).unwrap();
            assert_eq!((g.width, g.height, g.depth), (320, 200, 24));
            // Without the cookie the server refuses us.
            let anon = Target { display: vd.display_name(), xauthority: Some(PathBuf::from("/nonexistent")) };
            let err = Conn::connect(&anon).err().expect("connected without a cookie");
            assert!(err.to_string().contains("refused"), "{err}");
            // Both socket names belong to our Xvfb, and to nobody else.
            let pid = vd.procs().xvfb.id();
            assert!(Conn::connect_to_server(&vd.target(), pid).is_ok());
            let err = Conn::connect_to_server(&vd.target(), std::process::id()).err().expect("accepted the wrong server");
            assert!(err.to_string().contains("another process"), "{err}");
            auth = vd.xauthority().to_path_buf();
        }
        assert!(!auth.exists(), "cookie left behind");
        let deadline = Instant::now() + Duration::from_secs(5);
        while socket_taken(n) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!socket_taken(n), "Xvfb still running");
    }

    /// Xvfb and the host read the cookie from the file without a name. The session's copy on
    /// disk can go (aged out by a tmp cleaner) or be replaced (by another user once its
    /// directory is gone) without locking the host out or letting anyone else in.
    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn the_cookie_on_disk_is_only_for_the_session() {
        let vd = VirtualDisplay::spawn(Some(85), 64, 64, None).unwrap();
        let cmdline = std::fs::read(format!("/proc/{}/cmdline", vd.procs().xvfb.id())).unwrap();
        assert!(!String::from_utf8_lossy(&cmdline).contains(&*vd.dir.to_string_lossy()), "Xvfb was given a path");
        let at = |path: &Path| Target { display: vd.display_name(), xauthority: Some(path.to_path_buf()) };
        // Programs in the session use the copy.
        drop(Conn::connect(&at(vd.xauthority())).unwrap());
        // Gone: the host still gets in.
        std::fs::remove_file(vd.xauthority()).unwrap();
        drop(Conn::connect(&vd.target()).unwrap());
        // Replaced by one with another cookie, then by one with none (to an X server reading it,
        // "no access control"): nobody without the cookie gets in either way.
        let foreign = vd.dir.join("foreign");
        write_auth(&foreign, 85, &[9; 16]).unwrap();
        for content in [std::fs::read(&foreign).unwrap(), Vec::new()] {
            std::fs::write(vd.xauthority(), &content).unwrap();
            // A newer modification time, which is what makes an X server read its file again.
            std::thread::sleep(Duration::from_millis(1100));
            match Conn::connect(&at(Path::new("/dev/null"))) {
                Ok(_) => panic!("let in without a cookie"),
                Err(e) => assert!(e.to_string().contains("refused"), "{e}"),
            }
            assert!(Conn::connect(&at(&foreign)).is_err(), "let in with another cookie");
            drop(Conn::connect(&vd.target()).unwrap());
        }
    }

    /// Another process holding the display's abstract socket name (which X clients try first)
    /// keeps us off that display.
    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn refuses_a_display_another_process_serves() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixListener};
        let n = 70;
        let addr = SocketAddr::from_abstract_name(x11::local_socket_path(n).as_bytes()).unwrap();
        let fake = UnixListener::bind_addr(&addr).unwrap();
        fake.set_nonblocking(true).unwrap();
        let err = VirtualDisplay::spawn(Some(n), 64, 64, Some("sleep 30")).err().expect("used a display held by another process");
        eprintln!("refused: {err}");
        // Nothing reached the fake server: no connection carrying the cookie.
        let mut sent = 0;
        while let Ok((mut s, _)) = fake.accept() {
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
            let mut b = [0u8; 64];
            sent += s.read(&mut b).unwrap_or(0);
        }
        assert_eq!(sent, 0, "bytes were sent to the fake server");
        drop(fake);
        assert!(!socket_taken(n), "a socket file was left behind");
    }

    /// A stop request during start-up arrives as a signal handled like the host's handlers do
    /// (SA_RESTART); the system calls it interrupts are retried and start-up completes.
    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn starts_despite_signals() {
        use std::os::unix::thread::{JoinHandleExt, RawPthread};
        unsafe extern "C" {
            fn signal(sig: c_int, handler: extern "C" fn(c_int)) -> usize;
            fn pthread_kill(thread: RawPthread, sig: c_int) -> c_int;
        }
        extern "C" fn ignore(_: c_int) {}
        const SIGUSR1: c_int = 10;
        unsafe { signal(SIGUSR1, ignore) };
        let t = std::thread::spawn(|| {
            let vd = VirtualDisplay::spawn(Some(82), 64, 64, Some("sleep 30"))?;
            Conn::connect(&vd.target())?;
            Ok::<bool, Error>(vd.running() && vd.session_running())
        });
        let (thread, mut sent) = (t.as_pthread_t(), 0);
        while !t.is_finished() {
            unsafe { pthread_kill(thread, SIGUSR1) };
            sent += 1;
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(t.join().unwrap().unwrap());
        assert!(sent > 10, "only {sent} signals sent");
    }

    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn watch_stops_when_the_session_or_xvfb_ends() {
        let n = 80;
        let wait_for = |flag: &AtomicBool| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !flag.load(Ordering::SeqCst) {
                assert!(Instant::now() < deadline, "stop was not requested");
                std::thread::sleep(Duration::from_millis(50));
            }
        };

        let stop: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
        let vd = VirtualDisplay::spawn(Some(n), 64, 64, Some("sleep 1")).unwrap();
        vd.watch(stop).unwrap();
        wait_for(stop);
        assert!(!vd.session_running() && vd.running());
        drop(vd);

        let stop: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
        let vd = VirtualDisplay::spawn(Some(n), 64, 64, None).unwrap();
        vd.watch(stop).unwrap();
        unsafe { kill(vd.procs().xvfb.id() as c_int, SIGKILL) };
        wait_for(stop);
        drop(vd);

        // Dropping a watched display is not a reason to stop.
        let stop: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
        let vd = VirtualDisplay::spawn(Some(n), 64, 64, Some("sleep 30")).unwrap();
        vd.watch(stop).unwrap();
        std::thread::sleep(WATCH_INTERVAL);
        drop(vd);
        std::thread::sleep(WATCH_INTERVAL * 2);
        assert!(!stop.load(Ordering::SeqCst));
    }
}
