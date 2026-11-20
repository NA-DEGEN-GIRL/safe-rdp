//! Headless X server for hosts without a desktop (servers, containers): starts Xvfb on a free
//! display with a private random cookie, optionally runs a session command inside it, and
//! stops both when dropped.
//!
//! /tmp/.X11-unix is shared by every local user, so a display is only used once it is proven
//! to be ours: Xvfb reports through `-displayfd` when it accepts clients, and both socket
//! names of the display must then belong to the Xvfb process we started.

use super::x11::{self, AuthEntry, COOKIE_NAME, Conn, FAMILY_WILD, Target, encode_auth_entry};
use crate::util::{Error, Result, wipe};
use crate::{bail, log};
use std::ffi::c_int;
use std::fs::File;
use std::io::{ErrorKind, PipeReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn prctl(option: c_int, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
}

const PR_SET_PDEATHSIG: c_int = 1;
const F_SETFD: c_int = 2;

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

/// Xvfb and the session command, each leading its own process group.
struct Procs {
    xvfb: Child,
    session: Option<Child>,
    /// Set while dropping: the exits that follow are expected.
    closing: bool,
}

impl Procs {
    /// Why the display is no longer usable, once Xvfb or the session command has exited.
    fn ended(&mut self, dir: &Path) -> Option<String> {
        if let Ok(Some(status)) = self.xvfb.try_wait() {
            return Some(format!("Xvfb exited ({status}): {}", log_tail(&dir.join("xvfb.log"))));
        }
        let status = self.session.as_mut().and_then(|s| s.try_wait().ok().flatten())?;
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
    auth: PathBuf,
    /// Shared with the `watch` thread, which only holds a weak reference.
    procs: Arc<Mutex<Procs>>,
}

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b)
}

/// A new 0700 directory for the cookie and logs, preferably on the per-user runtime tmpfs.
fn private_dir(tag: &str) -> Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("safe-rdp-{tag}-{}", crate::util::hex_encode(&random_bytes(6)?)));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir)
}

/// Writes an Xauthority file holding one wildcard-address cookie for display `number`.
fn write_auth(path: &Path, number: u32, cookie: &[u8]) -> Result<()> {
    let entry = AuthEntry {
        family: FAMILY_WILD,
        address: Vec::new(),
        number: number.to_string().into_bytes(),
        name: COOKIE_NAME.to_vec(),
        data: cookie.to_vec(),
    };
    let mut bytes = encode_auth_entry(&entry);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    let r = f.write_all(&bytes).and_then(|_| f.sync_all());
    wipe(&mut bytes);
    Ok(r?)
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

/// Stops a process group: SIGTERM, a grace period, then SIGKILL.
fn stop_group(child: &mut Child) {
    let pid = child.id() as c_int;
    unsafe { kill(-pid, SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            // The leader is gone; make sure nothing it started lingers.
            unsafe { kill(-pid, SIGKILL) };
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    unsafe { kill(-pid, SIGKILL) };
    let _ = child.wait();
}

/// Reads the display number Xvfb writes to its `-displayfd` pipe once it accepts clients.
fn read_display_number(ready: &mut PipeReader, xvfb: &Mutex<Procs>, n: u32, log_path: &Path) -> Result<u32> {
    let deadline = Instant::now() + START_TIMEOUT;
    let mut got = Vec::new();
    let mut open = true;
    loop {
        if let Ok(Some(status)) = xvfb.lock().unwrap_or_else(|e| e.into_inner()).xvfb.try_wait() {
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
    /// `XAUTHORITY` of this process at it, and runs `session` (a shell command) inside it.
    ///
    /// Call during start-up, before other threads are running: it changes the environment.
    /// Signals arriving meanwhile (a stop request) do not disturb it.
    pub fn start(width: u32, height: u32, session: Option<&str>) -> Result<VirtualDisplay> {
        let vd = VirtualDisplay::spawn(None, width, height, session)?;
        // SAFETY: documented to be called before other threads exist.
        unsafe {
            std::env::set_var("DISPLAY", vd.display_name());
            std::env::set_var("XAUTHORITY", &vd.auth);
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
        let mut last = Error::msg("no display tried");
        for n in candidates {
            match VirtualDisplay::try_start(n, width, height) {
                Ok(vd) => {
                    if let Some(cmd) = session {
                        let child = vd.run_session(cmd)?;
                        vd.procs().session = Some(child);
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
        let started = (|| -> Result<(Child, PipeReader)> {
            let mut cookie = random_bytes(16)?;
            let r = write_auth(&auth, n, &cookie);
            wipe(&mut cookie);
            r?;
            let log = File::create(&log_path)?;
            // Xvfb writes the display number here once clients can connect.
            let (ready, ready_tx) = std::io::pipe()?;
            let fd = ready_tx.as_raw_fd();
            let mut cmd = Command::new("Xvfb");
            die_with_parent(&mut cmd)
                .arg(format!(":{n}"))
                .args(["-displayfd", &fd.to_string()])
                .args(["-screen", "0", &format!("{width}x{height}x24"), "-nolisten", "tcp", "-noreset", "-auth"])
                .arg(&auth)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(log)
                .process_group(0);
            // Like every descriptor std creates, the pipe is close-on-exec; Xvfb must keep it.
            unsafe {
                cmd.pre_exec(move || match fcntl(fd, F_SETFD, 0 as c_int) {
                    -1 => Err(std::io::Error::last_os_error()),
                    _ => Ok(()),
                });
            }
            let child = cmd.spawn().map_err(|e| Error::msg(format!("cannot start Xvfb (is it installed?): {e}")))?;
            drop(ready_tx);
            Ok((child, ready))
        })();
        let (xvfb, mut ready) = match started {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e);
            }
        };
        let pid = xvfb.id();
        let vd = VirtualDisplay { number: n, dir, auth, procs: Arc::new(Mutex::new(Procs { xvfb, session: None, closing: false })) };
        let shown = read_display_number(&mut ready, &vd.procs, n, &log_path)?;
        if shown != n {
            bail!("Xvfb started display :{shown} instead of :{n}");
        }
        // Proves the listener is our Xvfb before the cookie goes anywhere.
        Conn::connect_to_server(&vd.target(), pid).map_err(|e| format!("cannot use display :{n}: {e}"))?;
        Ok(vd)
    }

    fn run_session(&self, cmd: &str) -> Result<Child> {
        let log = File::create(self.dir.join("session.log"))?;
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
        Ok(child)
    }

    fn procs(&self) -> MutexGuard<'_, Procs> {
        self.procs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Watches Xvfb and the session command from a background thread. When either exits, it
    /// logs why and sets `stop`, so a host serving this display shuts down (dropping it)
    /// instead of serving a dead or empty screen; a session command must therefore run for as
    /// long as the session lasts. The thread ends with the display, and dropping the display
    /// does not set `stop`.
    pub fn watch(&self, stop: &'static AtomicBool) -> Result<()> {
        let procs = Arc::downgrade(&self.procs);
        let (dir, name) = (self.dir.clone(), self.display_name());
        std::thread::Builder::new().name("virtual-display".into()).spawn(move || {
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
            }
        })?;
        Ok(())
    }

    /// `:N`
    pub fn display_name(&self) -> String {
        format!(":{}", self.number)
    }

    pub fn number(&self) -> u32 {
        self.number
    }

    /// The private Xauthority file holding this display's cookie.
    pub fn xauthority(&self) -> &Path {
        &self.auth
    }

    pub fn target(&self) -> Target {
        Target { display: self.display_name(), xauthority: Some(self.auth.clone()) }
    }

    /// False once the session command has exited (always true without a session).
    pub fn session_running(&self) -> bool {
        match &mut self.procs().session {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => true,
        }
    }

    /// The last lines the session wrote, for error messages.
    pub fn session_log_tail(&self) -> String {
        log_tail(&self.dir.join("session.log"))
    }

    /// False once Xvfb has exited.
    pub fn running(&self) -> bool {
        matches!(self.procs().xvfb.try_wait(), Ok(None))
    }
}

impl Drop for VirtualDisplay {
    fn drop(&mut self) {
        let mut p = self.procs();
        p.closing = true;
        if let Some(s) = &mut p.session {
            stop_group(s);
        }
        stop_group(&mut p.xvfb);
        drop(p);
        // Overwrite the cookie before deleting it.
        if let Ok(len) = std::fs::metadata(&self.auth).map(|m| m.len() as usize) {
            let _ = std::fs::write(&self.auth, vec![0u8; len]);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
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
