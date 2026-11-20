//! Headless X server for hosts without a desktop (servers, containers): starts Xvfb on a free
//! display with a private random cookie, optionally runs a session command inside it, and
//! stops both when dropped.

use super::x11::{AuthEntry, COOKIE_NAME, Conn, FAMILY_WILD, Target, encode_auth_entry};
use crate::util::{Error, Result, wipe};
use crate::{bail, log};
use std::ffi::c_int;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn kill(pid: c_int, sig: c_int) -> c_int;
}

const SIGTERM: c_int = 15;
const SIGKILL: c_int = 9;

/// Display numbers tried when none is given. Starting at 20 keeps clear of real desktops
/// (:0, :1, ...) and SSH X forwarding (:10 upwards).
pub const FIRST_DISPLAY: u32 = 20;
/// A session that works on a stock Ubuntu server: a terminal with its own D-Bus session bus
/// (so it does not attach to a desktop session elsewhere), ending when the terminal closes.
pub const DEFAULT_SESSION: &str = "exec dbus-run-session -- gnome-terminal --wait";
const LAST_DISPLAY: u32 = 99;
const START_TIMEOUT: Duration = Duration::from_secs(15);

/// A running Xvfb (plus optional session). Dropping it stops everything and deletes the cookie.
pub struct VirtualDisplay {
    number: u32,
    dir: PathBuf,
    auth: PathBuf,
    xvfb: Child,
    session: Option<Child>,
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

fn socket_taken(n: u32) -> bool {
    Path::new(&format!("/tmp/.X11-unix/X{n}")).exists() || Path::new(&format!("/tmp/.X{n}-lock")).exists()
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

impl VirtualDisplay {
    /// Starts a virtual display on the first free number from 20, points `DISPLAY` and
    /// `XAUTHORITY` of this process at it, and runs `session` (a shell command) inside it.
    ///
    /// Call during start-up, before other threads are running: it changes the environment.
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
                Ok(mut vd) => {
                    if let Some(cmd) = session {
                        vd.session = Some(vd.run_session(cmd)?);
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
        let started = (|| {
            let mut cookie = random_bytes(16)?;
            let r = write_auth(&auth, n, &cookie);
            wipe(&mut cookie);
            r?;
            let log = File::create(&log_path)?;
            Command::new("Xvfb")
                .arg(format!(":{n}"))
                .args(["-screen", "0", &format!("{width}x{height}x24"), "-nolisten", "tcp", "-noreset", "-auth"])
                .arg(&auth)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(log)
                .process_group(0)
                .spawn()
                .map_err(|e| Error::msg(format!("cannot start Xvfb (is it installed?): {e}")))
        })();
        let xvfb = match started {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e);
            }
        };
        let mut vd = VirtualDisplay { number: n, dir, auth, xvfb, session: None };
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if let Ok(Some(status)) = vd.xvfb.try_wait() {
                bail!("Xvfb on :{n} exited ({status}): {}", log_tail(&log_path));
            }
            if Path::new(&format!("/tmp/.X11-unix/X{n}")).exists() && Conn::connect(&vd.target()).is_ok() {
                return Ok(vd);
            }
            if Instant::now() > deadline {
                bail!("Xvfb on :{n} did not come up: {}", log_tail(&log_path));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn run_session(&self, cmd: &str) -> Result<Child> {
        let log = File::create(self.dir.join("session.log"))?;
        let child = Command::new("sh")
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
    pub fn session_running(&mut self) -> bool {
        match &mut self.session {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => true,
        }
    }

    /// The last lines the session wrote, for error messages.
    pub fn session_log_tail(&self) -> String {
        log_tail(&self.dir.join("session.log"))
    }

    /// False once Xvfb has exited.
    pub fn running(&mut self) -> bool {
        matches!(self.xvfb.try_wait(), Ok(None))
    }
}

impl Drop for VirtualDisplay {
    fn drop(&mut self) {
        if let Some(s) = &mut self.session {
            stop_group(s);
        }
        stop_group(&mut self.xvfb);
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
        let mut vd = VirtualDisplay::spawn(Some(78), 1024, 768, Some(&cmd)).unwrap();
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
            let mut vd = VirtualDisplay::spawn(Some(n), 320, 200, Some("sleep 30")).unwrap();
            assert_eq!(vd.display_name(), ":71");
            assert!(vd.running() && vd.session_running());
            let mut c = Conn::connect(&vd.target()).unwrap();
            let g = c.get_geometry(c.root()).unwrap();
            assert_eq!((g.width, g.height, g.depth), (320, 200, 24));
            // Without the cookie the server refuses us.
            let anon = Target { display: vd.display_name(), xauthority: Some(PathBuf::from("/nonexistent")) };
            let err = Conn::connect(&anon).err().expect("connected without a cookie");
            assert!(err.to_string().contains("refused"), "{err}");
            auth = vd.xauthority().to_path_buf();
        }
        assert!(!auth.exists(), "cookie left behind");
        let deadline = Instant::now() + Duration::from_secs(5);
        while socket_taken(n) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!socket_taken(n), "Xvfb still running");
    }
}
