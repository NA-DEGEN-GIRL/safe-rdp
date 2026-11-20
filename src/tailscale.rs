//! Tailscale device discovery (portable): runs `tailscale status --json` and lists the
//! devices of the tailnet, so people can pick a PC instead of typing an address.
//!
//! The CLI is looked up only in its standard install locations (directories only
//! administrators can write to), never on `PATH`, where another local user may have planted
//! one. Names coming from the tailnet are shown to the user, so control and bidi-formatting
//! characters are removed.

use crate::json::{self, Value};
use crate::util::Result;
use std::fmt;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// `tailscale status --json` is a few KiB per device; anything near this is not Tailscale.
const MAX_OUTPUT: usize = 8 << 20;
const MAX_STDERR: usize = 64 << 10;
const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_NAME: usize = 63;
const MAX_DNS_NAME: usize = 253;

#[derive(Clone, Debug, PartialEq)]
pub struct Device {
    /// Short MagicDNS name (first label of `dns_name`), or the OS host name.
    pub name: String,
    /// Full MagicDNS name without the trailing dot ("" if unknown).
    pub dns_name: String,
    pub ips: Vec<IpAddr>,
    /// As reported by Tailscale: "windows", "linux", "macOS", "iOS", "android", ...
    pub os: String,
    pub online: bool,
    pub is_self: bool,
}

impl Device {
    /// Address to connect to: the first IPv4 address, else the first address.
    pub fn address(&self) -> Option<IpAddr> {
        self.ips.iter().find(|ip| ip.is_ipv4()).or(self.ips.first()).copied()
    }

    #[cfg_attr(not(windows), allow(dead_code))] // used by the Windows UI
    /// Whether `s` refers to this device: its short name, MagicDNS name or one of its addresses.
    pub fn matches(&self, s: &str) -> bool {
        let s = s.trim().trim_end_matches('.');
        if s.is_empty() {
            return false;
        }
        self.name.eq_ignore_ascii_case(s)
            || (!self.dns_name.is_empty() && self.dns_name.eq_ignore_ascii_case(s))
            || s.parse::<IpAddr>().is_ok_and(|ip| self.ips.contains(&ip))
    }

    /// Operating system name for display.
    pub fn os_label(&self) -> &str {
        match self.os.to_ascii_lowercase().as_str() {
            "windows" => "Windows",
            "linux" => "Linux",
            "macos" => "macOS",
            "ios" => "iOS",
            "android" => "Android",
            "freebsd" => "FreeBSD",
            "openbsd" => "OpenBSD",
            _ => &self.os,
        }
    }
}

/// What `tailscale status` reported.
#[derive(Clone, Debug, PartialEq)]
pub struct Status {
    /// "Running" when connected; otherwise e.g. "NeedsLogin", "Stopped", "Starting".
    pub backend_state: String,
    /// This device first (if known), then the peers: online before offline, then by name.
    pub devices: Vec<Device>,
}

impl Status {
    pub fn running(&self) -> bool {
        self.backend_state == "Running"
    }

    #[cfg_attr(not(windows), allow(dead_code))] // used by the Windows UI
    pub fn self_device(&self) -> Option<&Device> {
        self.devices.iter().find(|d| d.is_self)
    }

    pub fn peers(&self) -> impl Iterator<Item = &Device> {
        self.devices.iter().filter(|d| !d.is_self)
    }
}

/// The peers as an aligned plain-text table (for a `safe-rdp devices` command).
pub fn devices_table(st: &Status) -> String {
    let mut out = String::new();
    if !st.running() {
        out.push_str(&format!(
            "Tailscale is not connected (state: {})\n",
            if st.backend_state.is_empty() { "unknown" } else { &st.backend_state }
        ));
    }
    let mut rows = vec![["DEVICE".to_string(), "SYSTEM".into(), "ADDRESS".into(), "STATUS".into()]];
    rows.extend(st.peers().map(|d| {
        let addr = d.address().map(|a| a.to_string()).unwrap_or_default();
        [d.name.clone(), d.os_label().to_string(), addr, if d.online { "online" } else { "offline" }.to_string()]
    }));
    if rows.len() == 1 {
        out.push_str("No other devices in this tailnet.\n");
        return out;
    }
    let width = |i: usize| rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0);
    let widths = [width(0), width(1), width(2)];
    for r in &rows {
        let mut line = String::new();
        for (i, w) in widths.iter().enumerate() {
            line.push_str(&r[i]);
            line.push_str(&" ".repeat(w - r[i].chars().count() + 2));
        }
        line.push_str(&r[3]);
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// Why the device list is unavailable.
#[derive(Clone, Debug, PartialEq)]
pub enum Problem {
    /// No `tailscale` command was found.
    NotInstalled,
    /// The CLI exists but the Tailscale service/daemon is not reachable.
    NotRunning,
    Failed(String),
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::NotInstalled => f.write_str("Tailscale is not installed (no `tailscale` command found)"),
            Problem::NotRunning => f.write_str("the Tailscale service is not running"),
            Problem::Failed(e) => f.write_str(e),
        }
    }
}

/// System directories the Tailscale packages install the CLI into.
#[cfg(not(windows))]
/// Directories only root can write to; the last three are snap (Ubuntu, then Fedora/Arch) and NixOS.
const CLI_DIRS: [&str; 10] = [
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
    "/opt/tailscale",
    "/snap/bin",
    "/var/lib/snapd/snap/bin",
    "/run/current-system/sw/bin",
];

/// Where the CLI may be: the standard install locations only, never `PATH`.
fn cli_candidates() -> Vec<PathBuf> {
    #[cfg(windows)]
    let candidates = ["ProgramFiles", "ProgramW6432"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(|dir| Path::new(&dir).join("Tailscale").join("tailscale.exe"))
        .filter(|p| p.is_absolute())
        .collect();
    #[cfg(not(windows))]
    let candidates = CLI_DIRS.iter().map(|d| Path::new(d).join("tailscale")).collect();
    candidates
}

/// Locates the Tailscale CLI.
pub fn cli_path() -> Option<PathBuf> {
    cli_candidates().into_iter().find(|p| p.is_file())
}

/// Asks the local Tailscale client for this device and its peers.
pub fn status() -> std::result::Result<Status, Problem> {
    let cli = cli_path().ok_or(Problem::NotInstalled)?;
    let out = run_cli(&cli, &["status", "--json"])?;
    parse_status(&out).map_err(|e| Problem::Failed(format!("unexpected output from tailscale: {e}")))
}

/// Reads at most `cap` bytes, then drains the rest so the writer never blocks on a full pipe.
fn read_capped(mut r: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let _ = (&mut r).take(cap as u64 + 1).read_to_end(&mut buf);
    let overflow = buf.len() > cap;
    if overflow {
        buf.truncate(cap);
        let _ = std::io::copy(&mut r, &mut std::io::sink());
    }
    (buf, overflow)
}

fn run_cli(cli: &Path, args: &[&str]) -> std::result::Result<Vec<u8>, Problem> {
    let mut cmd = Command::new(cli);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    }
    let mut child = cmd.spawn().map_err(|e| Problem::Failed(format!("cannot run {}: {e}", cli.display())))?;
    let out = child.stdout.take().map(|s| std::thread::spawn(move || read_capped(s, MAX_OUTPUT)));
    let err = child.stderr.take().map(|s| std::thread::spawn(move || read_capped(s, MAX_STDERR)));
    let started = Instant::now();
    let exit = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if started.elapsed() < TIMEOUT => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Problem::Failed(format!("tailscale did not answer within {} seconds", TIMEOUT.as_secs())));
            }
            Err(e) => return Err(Problem::Failed(format!("waiting for tailscale: {e}"))),
        }
    };
    let (stdout, overflow) = out.and_then(|t| t.join().ok()).unwrap_or_default();
    let (stderr, _) = err.and_then(|t| t.join().ok()).unwrap_or_default();
    if !exit.success() {
        let msg = String::from_utf8_lossy(&stderr);
        return Err(classify_failure(&msg));
    }
    if overflow {
        return Err(Problem::Failed("tailscale printed an unexpectedly large status".into()));
    }
    Ok(stdout)
}

/// Maps the CLI's error output to a problem; the daemon being down is the common case.
fn classify_failure(stderr: &str) -> Problem {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("failed to connect to local tailscale")
        || lower.contains("is tailscale running")
        || lower.contains("doesn't appear to be running")
    {
        return Problem::NotRunning;
    }
    let line = stderr.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with("Warning:")).unwrap_or("no details");
    Problem::Failed(format!("tailscale status failed: {}", clean(line, 200)))
}

/// Parses `tailscale status --json` output.
pub fn parse_status(text: &[u8]) -> Result<Status> {
    let v = json::parse(text)?;
    if v.as_object().is_none() {
        crate::bail!("status is not a JSON object");
    }
    let backend_state = clean(v.get("BackendState").and_then(Value::as_str).unwrap_or(""), 32);
    let mut devices: Vec<Device> = v.get("Self").and_then(|s| device(s, true)).into_iter().collect();
    let mut peers: Vec<Device> = match v.get("Peer") {
        Some(Value::Object(m)) => m.iter().filter_map(|(_, p)| device(p, false)).collect(),
        Some(Value::Null) | None => Vec::new(),
        Some(_) => crate::bail!("\"Peer\" is not an object"),
    };
    sort_devices(&mut peers);
    devices.extend(peers);
    Ok(Status { backend_state, devices })
}

/// Online devices first, then by name (case-insensitive).
pub fn sort_devices(devices: &mut [Device]) {
    devices.sort_by(|a, b| {
        b.online.cmp(&a.online).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())).then_with(|| a.dns_name.cmp(&b.dns_name))
    });
}

fn device(v: &Value, is_self: bool) -> Option<Device> {
    v.as_object()?;
    let str_field = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("");
    let dns_name = clean(str_field("DNSName").trim_end_matches('.'), MAX_DNS_NAME);
    // Mullvad exit nodes appear as peers but are not the user's machines.
    if dns_name.to_ascii_lowercase().ends_with(".mullvad.ts.net") {
        return None;
    }
    let ips: Vec<IpAddr> =
        v.get("TailscaleIPs").and_then(Value::as_array).unwrap_or(&[]).iter().filter_map(|ip| ip.as_str()?.parse().ok()).collect();
    let first = *ips.first()?;
    let short = dns_name.split('.').next().unwrap_or("");
    let name = match (short, clean(str_field("HostName"), MAX_NAME)) {
        (s, _) if !s.is_empty() => clean(s, MAX_NAME),
        (_, h) if !h.is_empty() => h,
        _ => first.to_string(),
    };
    Some(Device {
        name,
        dns_name,
        ips,
        os: clean(str_field("OS"), 32),
        online: v.get("Online").and_then(Value::as_bool).unwrap_or(false),
        is_self,
    })
}

/// Drops control and bidirectional-formatting characters (and the BOM) and limits the length.
fn clean(s: &str, max_chars: usize) -> String {
    let bidi =
        |c: char| matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}');
    s.chars().filter(|&c| !c.is_control() && !bidi(c)).take(max_chars).collect::<String>().trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/tailscale-status.json");

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn peer<'a>(st: &'a Status, s: &str) -> Option<&'a Device> {
        st.peers().find(|d| d.matches(s))
    }

    #[test]
    fn parses_captured_status() {
        let st = parse_status(FIXTURE).unwrap();
        assert!(st.running());
        let me = st.self_device().unwrap();
        assert_eq!(me.name, "workstation");
        assert_eq!(me.dns_name, "workstation.tail0a1b2c.ts.net");
        assert_eq!(me.ips, [ip("100.64.10.1"), ip("fd7a:115c:a1e0::a01")]);
        assert_eq!(me.os_label(), "Windows");
        assert!(me.online && me.is_self);
        assert_eq!(st.devices[0], *me);

        let names: Vec<&str> = st.peers().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["build-server", "desktop-example1", "mediabox", "phone"]);
        assert!(st.peers().all(|d| d.online && !d.is_self));
        let phone = peer(&st, "phone").unwrap();
        assert_eq!(phone.os_label(), "Android");
        assert_eq!(phone.address(), Some(ip("100.64.10.5")));
        let desktop = peer(&st, "DESKTOP-EXAMPLE1").unwrap();
        assert_eq!(desktop.os_label(), "Windows");
        assert_eq!(desktop.dns_name, "desktop-example1.tail0a1b2c.ts.net");
        assert!(peer(&st, "workstation").is_none(), "self is not a peer");
    }

    #[test]
    fn matching() {
        let st = parse_status(FIXTURE).unwrap();
        let d = peer(&st, "mediabox").unwrap();
        assert!(d.matches("MEDIABOX"));
        assert!(d.matches("mediabox.tail0a1b2c.ts.net."));
        assert!(d.matches(" 100.64.10.3 "));
        assert!(d.matches("fd7a:115c:a1e0::a03"));
        assert!(!d.matches("media"));
        assert!(!d.matches(""));
        assert!(!d.matches("100.64.10.4"));
        assert_eq!(peer(&st, "100.64.10.4").unwrap().name, "build-server");
    }

    #[test]
    fn offline_sorting_and_fallback_names() {
        let doc = r#"{
            "BackendState": "Running",
            "Self": {"HostName": "me", "DNSName": "", "OS": "linux", "TailscaleIPs": ["100.64.0.1"], "Online": true},
            "Peer": {
                "a": {"HostName": "Zeta", "DNSName": "zeta.example.ts.net.", "OS": "macOS", "TailscaleIPs": ["100.64.0.2"]},
                "b": {"HostName": "alpha", "DNSName": "alpha.example.ts.net.", "OS": "iOS", "TailscaleIPs": ["100.64.0.3"]},
                "c": {"HostName": "Beta box", "OS": "windows", "TailscaleIPs": ["fd7a:115c:a1e0::5", "100.64.0.5"], "Online": true},
                "d": {"HostName": "", "DNSName": "", "OS": "plan9", "TailscaleIPs": ["100.64.0.6"]},
                "e": {"HostName": "no-ip", "DNSName": "no-ip.example.ts.net.", "TailscaleIPs": []},
                "f": {"HostName": "se-sto", "DNSName": "se-sto-wg-001.mullvad.ts.net.", "TailscaleIPs": ["100.64.0.7"], "Online": true},
                "g": {"HostName": "bad", "TailscaleIPs": ["not an ip", 5]},
                "h": "not an object"
            }
        }"#;
        let st = parse_status(doc.as_bytes()).unwrap();
        assert_eq!(st.self_device().unwrap().name, "me");
        let peers: Vec<(&str, bool)> = st.peers().map(|d| (d.name.as_str(), d.online)).collect();
        assert_eq!(peers, [("Beta box", true), ("100.64.0.6", false), ("alpha", false), ("zeta", false)]);
        let beta = peer(&st, "beta box").unwrap();
        assert_eq!(beta.address(), Some(ip("100.64.0.5")), "IPv4 preferred");
        assert_eq!(peer(&st, "100.64.0.6").unwrap().os_label(), "plan9");
        assert_eq!(peer(&st, "zeta").unwrap().os_label(), "macOS");
    }

    #[test]
    fn logged_out_and_stopped() {
        let st = parse_status(br#"{"BackendState":"NeedsLogin","Self":{"HostName":"me","TailscaleIPs":null},"Peer":null}"#).unwrap();
        assert!(!st.running());
        assert_eq!(st.backend_state, "NeedsLogin");
        assert!(st.devices.is_empty());
        let st = parse_status(br#"{"BackendState":"Stopped"}"#).unwrap();
        assert!(!st.running() && st.devices.is_empty());
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse_status(b"").is_err());
        assert!(parse_status(b"[]").is_err());
        assert!(parse_status(br#"{"Peer": []}"#).is_err());
        assert!(parse_status(&FIXTURE[..FIXTURE.len() / 2]).is_err());
    }

    #[test]
    fn names_are_sanitised() {
        let doc = "{\"Peer\":{\"x\":{\"HostName\":\"evil\\u202egnp.exe\\u0007\",\"TailscaleIPs\":[\"100.64.0.9\"]}}}";
        let st = parse_status(doc.as_bytes()).unwrap();
        assert_eq!(st.devices[0].name, "evilgnp.exe");
        assert_eq!(clean("\u{feff}a\u{061c}b\u{2067}c\u{2069}", 10), "abc");
        let long = format!("{{\"Peer\":{{\"x\":{{\"HostName\":\"{}\",\"TailscaleIPs\":[\"100.64.0.9\"]}}}}}}", "a".repeat(500));
        assert_eq!(parse_status(long.as_bytes()).unwrap().devices[0].name.len(), MAX_NAME);
    }

    #[test]
    fn failure_classification() {
        assert_eq!(
            classify_failure(
                "failed to connect to local tailscaled; it doesn't appear to be running (sudo systemctl start tailscaled ?)\n"
            ),
            Problem::NotRunning
        );
        assert_eq!(classify_failure("failed to connect to local Tailscale service; is Tailscale running?"), Problem::NotRunning);
        assert_eq!(
            classify_failure("Warning: client version \"1\" != tailscaled server version \"2\"\nsomething else broke\n"),
            Problem::Failed("tailscale status failed: something else broke".into())
        );
        assert_eq!(classify_failure(""), Problem::Failed("tailscale status failed: no details".into()));
    }

    #[test]
    fn table() {
        let st = parse_status(FIXTURE).unwrap();
        let t = devices_table(&st);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines.len(), 5);
        assert!(lines[0].starts_with("DEVICE") && lines[0].ends_with("STATUS"));
        assert!(lines[1].starts_with("build-server") && lines[1].contains("Linux") && lines[1].contains("100.64.10.4"));
        // Columns line up.
        let col = lines[0].find("SYSTEM").unwrap();
        assert!(lines.iter().skip(1).all(|l| l.char_indices().nth(col).is_some_and(|(_, c)| c != ' ')));
        assert!(!t.contains("workstation"), "this device is not listed");
        let stopped = parse_status(br#"{"BackendState":"Stopped"}"#).unwrap();
        assert_eq!(devices_table(&stopped), "Tailscale is not connected (state: Stopped)\nNo other devices in this tailnet.\n");
    }

    #[test]
    fn capped_reads() {
        let (b, over) = read_capped(&b"0123456789"[..], 4);
        assert_eq!((b.as_slice(), over), (&b"0123"[..], true));
        let (b, over) = read_capped(&b"0123"[..], 4);
        assert_eq!((b.as_slice(), over), (&b"0123"[..], false));
    }

    #[test]
    fn cli_is_looked_up_in_fixed_places_only() {
        // Never on PATH, whose directories other users may be able to write to.
        let c = cli_candidates();
        assert!(c.iter().all(|p| p.is_absolute()));
        #[cfg(windows)]
        {
            let pf = std::env::var_os("ProgramFiles").expect("ProgramFiles");
            assert!((1..=2).contains(&c.len()));
            assert_eq!(c[0], Path::new(&pf).join("Tailscale\\tailscale.exe"));
            assert!(c.iter().all(|p| p.ends_with("Tailscale\\tailscale.exe")));
        }
        #[cfg(not(windows))]
        {
            let expected: Vec<PathBuf> = CLI_DIRS.iter().map(|d| Path::new(d).join("tailscale")).collect();
            assert_eq!(c, expected);
            assert_eq!(c[0], Path::new("/usr/bin/tailscale"));
        }
    }

    #[test]
    #[ignore = "needs a local Tailscale client"]
    fn live_status() {
        let st = status().expect("tailscale status");
        println!("this device: {:?}", st.self_device().map(|d| &d.name));
        print!("{}", devices_table(&st));
        assert!(st.self_device().is_some());
    }
}
