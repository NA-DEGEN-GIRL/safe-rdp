//! safe-rdp: a small, auditable remote desktop for Windows and Linux, meant to run over Tailscale.

mod audio;
mod channel;
mod codec;
mod crypto;
mod files;
mod host;
mod json;
mod keys;
mod net;
mod platform;
mod probe;
mod proto;
mod screen;
mod tailscale;
mod util;
mod viewer;

use platform::{capture, keystore};
use screen::MonitorSel;
use net::PeerPolicy;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use util::{Error, Result, Secret};

const USAGE: &str = "\
safe-rdp - remote desktop for Windows and Linux over Tailscale

USAGE:
  safe-rdp gui                       (Windows) Open the launcher window; also what a
                                     double-click on safe-rdp.exe does
  safe-rdp keygen [--force]          Create a new key, store it for this user, print it once
  safe-rdp key import                Store a key (paste it at the prompt) for this user
  safe-rdp key show                  Print the stored key (to set up the other machine)
  safe-rdp key forget                Delete the stored key

  safe-rdp host [HOST OPTIONS]       Share this screen (runs in the current session)
  safe-rdp connect <host[:port]> [VIEWER OPTIONS]
  safe-rdp devices                   List the devices on your tailnet

  safe-rdp service install [HOST OPTIONS] [--enable-sas]   (Windows, elevated) run as a
                                     SYSTEM service: works on the lock/sign-in screen and UAC
  safe-rdp service rekey             (Windows, elevated) give the installed service this
                                     account's key, keeping its options; restarts it
  safe-rdp service uninstall | status
                                     install and rekey take --expect-key <fingerprint> first:
                                     refuse unless this account's key has it (see `status`)

  safe-rdp monitors                  List monitors
  safe-rdp bench [--monitor N]       Measure capture/encode speed on this machine
  safe-rdp probe <host> [--seconds N] [--type TEXT] [--move X,Y] [--click X,Y] [--set K=V]
                [--upload FILE] [--pull] [--expect-change] [--snapshot FILE.ppm]
                                     Headless test client (measures and drives a session)

HOST OPTIONS:
  --bind <ip>              Address to listen on (default: this machine's Tailscale IPv4)
  --port <n>               TCP port (default 47300)
  --allow <ip>[,<ip>...]   Only accept these peer addresses (default: any Tailscale peer)
  --allow-non-tailscale    Permit binding/peers outside Tailscale ranges (not recommended)
  --monitor <n|all>        Monitor shown first, 1 = primary (default), or 'all'; viewers can
                           switch to any monitor of this machine
  --fps <n>                Frame rate cap (default 30)
  --quality <q>            Picture quality for viewers that do not ask: lossless | balanced | low
  --clipboard              Allow text clipboard sharing (viewer must opt in too)
  --files                  Allow file transfer (uploads to Downloads/safe-rdp, pulling copied files)
  --transfer-dir <path>    Save uploads here instead (service: a full path; uploads are saved
                           there as the user signed in on the console)
  --audio                  Allow viewers to listen to this machine's sound
  --privacy                Allow viewers to blank this screen and lock local input while connected
  --view-only              Ignore keyboard and mouse from viewers
  --virtual <WxH>          (Linux) Run in a new headless X display (Xvfb) of this size
  --session <cmd>          (Linux, with --virtual) Program to run in it (default: a terminal);
                           the host stops when it exits, so do not start it in the background
  --key-file <path>        Read the key from a text file instead of the user key store

VIEWER OPTIONS:
  --fullscreen             Start in full screen (toggle: Ctrl+Alt+Enter)
  --clipboard              Share text clipboard (host must allow it)
  --view-only              Do not send keyboard or mouse input
  --allow-capture          (Windows) Let local screenshot/recording tools capture the viewer
                           window; on Linux (X11) they always can
  --downscale <2|3|4>      Ask the host for 1/N resolution (e.g. 4K host on a laptop or slow link)
  --quality <q>            lossless | balanced | low (default: the host's --quality, else balanced)
  --monitor <n|all>        Which host monitor to show (1 = primary)
  --audio                  Play the host's sound
  --privacy                Blank the host's screen and block its local input while connected
  --key-file <path>        Read the key from a text file

In the viewer: the connection bar (top edge in full screen) switches monitor, quality, scale,
sound, clipboard and privacy; drop files on the window to send them; received files go to
Downloads/safe-rdp. Hotkeys: Ctrl+Alt+Enter full screen, Ctrl+Alt+End sends Ctrl+Alt+Del.
";

/// Set when the host should stop (launcher closed our stdin).
static STOP: AtomicBool = AtomicBool::new(false);

fn main() {
    // DLLs loaded from here on (by us or by Windows on our behalf) come from System32 only,
    // never from this executable's folder, where anyone may have left a file; the imports
    // themselves are covered by /DEPENDENTLOADFLAG (build.rs).
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories};
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = dispatch(&args) {
        log!("error: {e}");
        std::process::exit(1);
    }
}

fn dispatch(args: &[String]) -> Result<()> {
    let Some(cmd) = args.first() else {
        #[cfg(windows)]
        if platform::launcher::started_from_explorer() {
            return platform::launcher::run();
        }
        print!("{USAGE}");
        return Ok(());
    };
    let rest = &args[1..];
    match cmd.as_str() {
        #[cfg(windows)]
        "gui" => platform::launcher::run(),
        "devices" => {
            let st = tailscale::status().map_err(|p| Error::msg(p.to_string()))?;
            print!("{}", tailscale::devices_table(&st));
            Ok(())
        }
        "keygen" => keygen(rest),
        "key" => key_cmd(rest),
        "host" => host_cmd(rest),
        #[cfg(windows)]
        "agent" => {
            // Started by the service as SYSTEM inside the console session. The service
            // directory must already exist and be the administrators' alone: never create it,
            // and check it before logging there or reading the key.
            let (stop_event, rest) = platform::service::agent_stop_event(rest);
            let dir = keystore::check_service_dir()?;
            util::set_log_file(&dir.join("host.log"))?;
            let mut cli = parse_host(rest, true)?;
            if cli.opts.files && cli.opts.transfer_dir.is_none() {
                // SYSTEM's own Downloads folder is no place for uploads: keep them in the
                // service's admin-only directory unless --transfer-dir says otherwise (that
                // folder is then written as the user signed in on the console).
                let dir = dir.join("incoming");
                std::fs::create_dir_all(&dir)?;
                cli.opts.transfer_dir = Some(dir);
                cli.opts.own_transfer_dir = true;
            }
            let key = keystore::load_service_key()?;
            platform::init_process();
            // The service signals this event to stop us: end the session cleanly (release held
            // keys and buttons, end privacy mode) instead of being killed. Without it the
            // service can only terminate us, which is no reason not to run.
            match stop_event.map(|name| platform::service::watch_stop_event(name, &STOP)) {
                Some(Ok(())) => {}
                Some(Err(e)) => log!("cannot watch for the service's stop request ({e}); stopping will end this agent abruptly"),
                None => log!("started without a stop event; stopping will end this agent abruptly"),
            }
            let listener = host::bind(&cli.opts, &STOP)?;
            host::serve(listener, cli.opts, key, &STOP)
        }
        "connect" => connect(rest),
        "probe" => probe_cmd(rest),
        #[cfg(windows)]
        "service" => match rest.first().map(String::as_str) {
            Some("install") => {
                let (expect, args) = platform::service::expected_key(&rest[1..])?;
                let cli = parse_host(args, true)?;
                if cli.key_file.is_some() {
                    bail!("--key-file is not supported for the service; it uses this user's stored key");
                }
                // The agent runs in System32: a relative folder would end up there.
                if cli.opts.transfer_dir.as_deref().is_some_and(|d| !d.is_absolute()) {
                    bail!("--transfer-dir needs a full path (such as D:\\Uploads) for the service");
                }
                platform::service::install(args, cli.opts.port, cli.opts.sas, expect.as_deref())
            }
            Some("rekey") => {
                let (expect, args) = platform::service::expected_key(&rest[1..])?;
                if let Some(a) = args.first() {
                    bail!("unknown option '{a}' (usage: safe-rdp service rekey [--expect-key <fingerprint>])");
                }
                platform::service::rekey(expect.as_deref())
            }
            Some("uninstall") => platform::service::uninstall(),
            Some("status") => {
                let status = platform::service::status()?;
                println!("{status}");
                if status != "not installed" {
                    let recorded = platform::service::key_fingerprint().map_err(|e| e.to_string());
                    println!("{}", service_key_line(recorded, keystore::user_key_fingerprint().as_deref()));
                }
                Ok(())
            }
            Some("run") => platform::service::run_dispatcher(rest[1..].to_vec()),
            _ => bail!("usage: safe-rdp service install|rekey|uninstall|status"),
        },
        "monitors" => {
            platform::init_process();
            for (i, m) in capture::monitors().iter().enumerate() {
                println!("{}: {}x{} at ({}, {}){}", i + 1, m.width, m.height, m.left, m.top, if i == 0 { " primary" } else { "" });
            }
            if let Some(v) = capture::resolve(MonitorSel::All) {
                println!("all: {}x{} at ({}, {})", v.width, v.height, v.left, v.top);
            }
            Ok(())
        }
        "bench" => bench(rest),
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            Ok(())
        }
        "version" | "--version" | "-V" => {
            println!("safe-rdp {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => bail!("unknown command '{other}' (see `safe-rdp help`)"),
    }
}

fn next<'a>(it: &mut impl Iterator<Item = &'a String>, opt: &str) -> Result<&'a str> {
    it.next().map(String::as_str).ok_or_else(|| Error::msg(format!("{opt} needs a value")))
}

fn parse_monitor(s: &str) -> Result<MonitorSel> {
    Ok(match s {
        "all" => MonitorSel::All,
        "primary" | "1" => MonitorSel::Primary,
        n => match n.parse::<usize>() {
            Ok(i) if i >= 1 => MonitorSel::Index(i - 1),
            _ => bail!("--monitor expects a number from `safe-rdp monitors` or 'all'"),
        },
    })
}

struct HostCli {
    opts: host::HostOptions,
    key_file: Option<String>,
    /// Stop cleanly when stdin reaches end of file (used by the launcher).
    stop_on_eof: bool,
    virtual_size: Option<(u32, u32)>,
    session: Option<String>,
}

fn host_cmd(args: &[String]) -> Result<()> {
    let cli = parse_host(args, false)?;
    let key = load_key(cli.key_file.as_deref())?;
    // From here on Ctrl+C / SIGTERM only request a stop, so everything below unwinds normally
    // (the virtual display included).
    platform::stop_on_signals(&STOP);
    // Must come before any thread starts: it sets DISPLAY/XAUTHORITY for this process.
    #[cfg(target_os = "linux")]
    let _display = match cli.virtual_size {
        Some((w, h)) => {
            let s = cli.session.clone().unwrap_or_else(|| platform::xvfb::default_session(w, h));
            let d = platform::xvfb::VirtualDisplay::start(w, h, (!s.is_empty()).then_some(s.as_str()))?;
            // Stop when Xvfb or the session program ends instead of serving a dead screen.
            d.watch(&STOP)?;
            Some(d)
        }
        None => None,
    };
    #[cfg(not(target_os = "linux"))]
    if cli.virtual_size.is_some() || cli.session.is_some() {
        bail!("--virtual and --session are only available on Linux");
    }
    platform::init_process();
    if cli.stop_on_eof {
        std::thread::spawn(|| {
            use std::io::Read;
            let mut buf = [0u8; 64];
            let mut stdin = std::io::stdin();
            while matches!(stdin.read(&mut buf), Ok(n) if n > 0) {}
            STOP.store(true, Ordering::SeqCst);
        });
    }
    let listener = host::bind(&cli.opts, &STOP)?;
    host::serve(listener, cli.opts, key, &STOP)
}

fn parse_size(s: &str) -> Result<(u32, u32)> {
    let (w, h) = s.split_once(['x', 'X']).ok_or("--virtual expects WIDTHxHEIGHT, e.g. 1920x1080")?;
    match (w.parse(), h.parse()) {
        (Ok(w), Ok(h)) => Ok((w, h)),
        _ => bail!("--virtual expects WIDTHxHEIGHT, e.g. 1920x1080"),
    }
}

fn parse_host(args: &[String], service: bool) -> Result<HostCli> {
    let mut o = host::HostOptions {
        bind: None,
        port: proto::DEFAULT_PORT,
        policy: PeerPolicy { allow: vec![], allow_non_tailscale: false, loopback_ok: false },
        monitor: MonitorSel::Primary,
        max_fps: 30,
        clipboard: false,
        view_only: false,
        sas: false,
        // Everything beyond screen, keyboard and mouse is opt-in.
        files: false,
        audio: false,
        privacy: false,
        ..host::HostOptions::default()
    };
    let mut cli = HostCli { opts: host::HostOptions::default(), key_file: None, stop_on_eof: false, virtual_size: None, session: None };
    let mut key_file = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--bind" => o.bind = Some(next(&mut it, a)?.parse().map_err(|_| "--bind expects an IP address")?),
            "--port" => o.port = next(&mut it, a)?.parse().map_err(|_| "--port expects a number")?,
            "--allow" => {
                for p in next(&mut it, a)?.split(',').filter(|p| !p.is_empty()) {
                    let ip: IpAddr = p.trim().parse().map_err(|_| format!("--allow: '{p}' is not an IP address"))?;
                    o.policy.allow.push(ip);
                }
            }
            "--allow-non-tailscale" => o.policy.allow_non_tailscale = true,
            "--monitor" => o.monitor = parse_monitor(next(&mut it, a)?)?,
            "--fps" => o.max_fps = next(&mut it, a)?.parse().ok().filter(|f| (1..=120).contains(f)).ok_or("--fps expects 1-120")?,
            "--quality" => o.default_quality = parse_quality(next(&mut it, a)?)? as u32,
            "--clipboard" => o.clipboard = true,
            "--files" => o.files = true,
            "--transfer-dir" => o.transfer_dir = Some(next(&mut it, a)?.into()),
            "--audio" => o.audio = true,
            "--privacy" => o.privacy = true,
            "--view-only" => o.view_only = true,
            "--enable-sas" if service => o.sas = true,
            "--key-file" => key_file = Some(next(&mut it, a)?.to_string()),
            "--stop-on-eof" if !service => cli.stop_on_eof = true,
            "--virtual" if !service => cli.virtual_size = Some(parse_size(next(&mut it, a)?)?),
            "--session" if !service => cli.session = Some(next(&mut it, a)?.to_string()),
            other => bail!("unknown host option '{other}'"),
        }
    }
    if cli.session.is_some() && cli.virtual_size.is_none() {
        bail!("--session needs --virtual");
    }
    if let Some(ip) = o.bind {
        o.policy.loopback_ok = ip.is_loopback();
    }
    if let Some(ip) = o.policy.allow.iter().find(|ip| !net::is_tailscale(**ip) && !ip.is_loopback()) {
        if !o.policy.allow_non_tailscale {
            bail!("--allow {ip} is outside Tailscale; add --allow-non-tailscale if you really mean it");
        }
    }
    cli.opts = o;
    cli.key_file = key_file;
    Ok(cli)
}

fn load_key(key_file: Option<&str>) -> Result<Secret<32>> {
    match key_file {
        Some(p) => keys::load_key_file(p),
        None => keystore::load_user_key(),
    }
}

fn parse_quality(s: &str) -> Result<u8> {
    Ok(match s {
        "lossless" => proto::QUALITY_LOSSLESS,
        "balanced" => proto::QUALITY_BALANCED,
        "low" => proto::QUALITY_LOW,
        _ => bail!("--quality expects lossless, balanced or low"),
    } as u8)
}

fn parse_viewer_monitor(s: &str) -> Result<u8> {
    match s {
        "all" => Ok(proto::MONITOR_ALL),
        n => match n.parse::<u8>() {
            Ok(i) if (1..=200).contains(&i) => Ok(i - 1),
            _ => bail!("--monitor expects a monitor number (1 = primary) or 'all'"),
        },
    }
}

/// Parses one viewer option; returns false if `a` is not a viewer option.
fn viewer_option<'a>(o: &mut viewer::ViewerOptions, a: &str, it: &mut impl Iterator<Item = &'a String>) -> Result<bool> {
    match a {
        "--fullscreen" => o.fullscreen = true,
        "--clipboard" => o.clipboard = true,
        "--view-only" => o.view_only = true,
        "--allow-capture" => o.allow_capture = true,
        "--downscale" => o.downscale = next(it, a)?.parse().ok().filter(|d| (1..=4).contains(d)).ok_or("--downscale expects 1-4")?,
        "--quality" => o.quality = parse_quality(next(it, a)?)?,
        "--monitor" => o.monitor = parse_viewer_monitor(next(it, a)?)?,
        "--audio" => o.audio = true,
        "--privacy" => o.privacy = true,
        _ => return Ok(false),
    }
    Ok(true)
}

fn connect(args: &[String]) -> Result<()> {
    let mut target = None;
    let mut key_file = None;
    let mut o = viewer::ViewerOptions::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if viewer_option(&mut o, a, &mut it)? {
            continue;
        }
        match a.as_str() {
            "--key-file" => key_file = Some(next(&mut it, a)?.to_string()),
            s if s.starts_with("--") => bail!("unknown viewer option '{s}'"),
            s if target.is_none() => target = Some(s.to_string()),
            s => bail!("unexpected argument '{s}'"),
        }
    }
    let target = target.ok_or("usage: safe-rdp connect <host[:port]>")?;
    let key = load_key(key_file.as_deref())?;
    platform::init_process();
    platform::viewer::run(&target, o, key)
}

fn parse_xy(s: &str, opt: &str) -> Result<(u16, u16)> {
    let (x, y) = s.split_once(',').ok_or_else(|| Error::msg(format!("{opt} expects X,Y")))?;
    Ok((x.trim().parse().map_err(|_| format!("{opt}: bad X"))?, y.trim().parse().map_err(|_| format!("{opt}: bad Y"))?))
}

fn probe_cmd(args: &[String]) -> Result<()> {
    let mut target = None;
    let mut key_file = None;
    let mut o = probe::ProbeOptions::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if viewer_option(&mut o.viewer, a, &mut it)? {
            continue;
        }
        match a.as_str() {
            "--seconds" => o.seconds = next(&mut it, a)?.parse().ok().filter(|s: &f64| *s > 0.0).ok_or("--seconds expects a positive number")?,
            "--type" => o.type_text = Some(next(&mut it, a)?.to_string()),
            "--move" => o.moves.push(parse_xy(next(&mut it, a)?, a)?),
            "--click" => o.clicks.push(parse_xy(next(&mut it, a)?, a)?),
            "--set" => {
                let v = next(&mut it, a)?;
                let (k, val) = v.split_once('=').ok_or("--set expects KEY=VALUE")?;
                let key = probe::set_key(k).ok_or_else(|| Error::msg(format!("--set: unknown setting '{k}'")))?;
                let value = match (key, val) {
                    (proto::SET_QUALITY, q) => parse_quality(q)? as u32,
                    (proto::SET_MONITOR, m) => parse_viewer_monitor(m)? as u32,
                    (_, "on") => 1,
                    (_, "off") => 0,
                    (_, n) => n.parse().map_err(|_| format!("--set: bad value '{n}'"))?,
                };
                o.sets.push((key, value));
            }
            "--upload" => o.uploads.push(next(&mut it, a)?.to_string()),
            "--pull" => o.pull = true,
            "--expect-change" => o.expect_change = true,
            "--snapshot" => o.snapshot = Some(next(&mut it, a)?.to_string()),
            "--key-file" => key_file = Some(next(&mut it, a)?.to_string()),
            s if s.starts_with("--") => bail!("unknown probe option '{s}'"),
            s if target.is_none() => target = Some(s.to_string()),
            s => bail!("unexpected argument '{s}'"),
        }
    }
    let target = target.ok_or("usage: safe-rdp probe <host[:port]> [options]")?;
    let key = load_key(key_file.as_deref())?;
    probe::run(&target, o, key)
}

fn keygen(args: &[String]) -> Result<()> {
    let force = args.iter().any(|a| a == "--force");
    if let Some(a) = args.iter().find(|a| *a != "--force") {
        bail!("unknown option '{a}'");
    }
    let replaced = keystore::user_key_path()?.exists();
    if replaced && !force {
        bail!("a key is already stored; use `safe-rdp key show`, or `keygen --force` to replace it");
    }
    #[cfg(windows)]
    let old = keystore::user_key_fingerprint();
    let k = keys::generate()?;
    let path = keystore::save_user_key(&k)?;
    println!("{}", keys::format_key(&k));
    eprintln!();
    eprintln!("Stored for this user in {}", path.display());
    eprintln!("On the other machine run `safe-rdp key import` and paste the line above.");
    eprintln!("Treat it like a password: anyone with this key and tailnet access can control the host.");
    warn_old_key_in_use(replaced, false);
    #[cfg(windows)]
    report_service_key(old.as_deref(), Some(&keys::fingerprint(&k)));
    Ok(())
}

/// After the stored key was replaced or removed: what started with the old key keeps it.
/// `had_key`: a key was stored before; `removed`: there is none now.
fn warn_old_key_in_use(had_key: bool, removed: bool) {
    if had_key {
        let launcher = match (cfg!(windows), removed) {
            (false, _) => "",
            (true, false) => " (sharing from the launcher restarts with the new key by itself)",
            (true, true) => " (sharing from the launcher stops by itself)",
        };
        eprintln!("note: a `safe-rdp host` that is already running keeps the old key until it is restarted{launcher}.");
    }
}

/// After the stored key changed: whether the background service has the key stored now, from
/// the fingerprint it recorded. `old`, `new`: fingerprints of the key stored before and now
/// (None: none, or unreadable).
#[cfg(windows)]
fn report_service_key(old: Option<&str>, new: Option<&str>) {
    let status = platform::service::status();
    let recorded = platform::service::key_fingerprint().map_err(|e| e.to_string());
    if let Some(w) = service_key_warning(status.as_deref().map_err(|e| e.to_string()), recorded, old, new) {
        eprintln!("{w}");
    }
}

/// The service keeps the key it was given: what to tell after the stored key changed, given
/// `service status` (or why it failed), the fingerprint the service recorded for its key (None:
/// it recorded none, as an earlier safe-rdp did not) and those of the key stored before and
/// now (`old`, `new`; None: none, or unreadable). Nothing when the service is not installed.
#[cfg(windows)]
fn service_key_warning(
    status: std::result::Result<&str, String>,
    recorded: std::result::Result<Option<String>, String>,
    old: Option<&str>,
    new: Option<&str>,
) -> Option<String> {
    let was = if new.is_some() { "old" } else { "removed" };
    let fix = match new {
        Some(n) => format!("to give it this key, run `safe-rdp service rekey --expect-key {n}` from an elevated terminal (or `service uninstall`)"),
        None => "run `safe-rdp service uninstall` from an elevated terminal to remove it".to_string(),
    };
    match status {
        Ok("not installed") => return None,
        Ok(_) => {}
        Err(e) => {
            return Some(format!(
                "warning: cannot check the background service ({e}); if it is installed, it keeps the key it was given;\n{fix}"
            ));
        }
    }
    Some(match recorded {
        Ok(Some(r)) if new == Some(r.as_str()) => format!("note: the background service already has this key (fingerprint {r})."),
        Ok(Some(r)) if old == Some(r.as_str()) => format!("warning: the background service still has the {was} key (fingerprint {r}) and accepts it;\n{fix}"),
        Ok(Some(r)) if new.is_some() => format!("warning: the background service has another key (fingerprint {r}), not this one;\n{fix}"),
        Ok(Some(r)) if old.is_some() => format!("note: the background service has another key (fingerprint {r}), not the removed one."),
        Ok(Some(r)) => format!("warning: the background service has the key with fingerprint {r}, which may be the removed one;\n{fix}"),
        Ok(None) => format!(
            "warning: cannot tell which key the background service has (it recorded none, as an earlier safe-rdp did not),\n\
             so it may still accept the {was} key; {fix}"
        ),
        Err(e) => format!("warning: cannot tell which key the background service has ({e}),\nso it may still accept the {was} key; {fix}"),
    })
}

/// `service status`'s line on the service's key: the fingerprint it recorded (None: none, as an
/// earlier safe-rdp did not record it), compared with that of the key stored for this user.
#[cfg(windows)]
fn service_key_line(recorded: std::result::Result<Option<String>, String>, mine: Option<&str>) -> String {
    let fix = |m: &str| format!("`safe-rdp service rekey --expect-key {m}` from an elevated terminal gives it yours");
    match (recorded, mine) {
        (Ok(Some(r)), Some(m)) if r == m => format!("key: {r}, the key stored for this user"),
        (Ok(Some(r)), Some(m)) => format!("key: {r}, not the key stored for this user ({m});\n{}", fix(m)),
        (Ok(Some(r)), None) => format!("key: {r} (no readable key is stored for this user)"),
        (Ok(None), Some(m)) => format!("key: not recorded (as by an earlier safe-rdp);\n{}", fix(m)),
        (Ok(None), None) => "key: not recorded (as by an earlier safe-rdp)".to_string(),
        (Err(e), _) => format!("key: cannot tell ({e})"),
    }
}

fn key_cmd(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("import") => {
            if args.len() > 1 {
                bail!("pass the key on stdin or at the prompt, not as an argument (it would end up in shell history)");
            }
            let mut line = platform::read_secret("Paste key (input hidden): ")?;
            let k = keys::parse_key(&line);
            unsafe { util::wipe(line.as_bytes_mut()) };
            let k = k?;
            let had_key = keystore::user_key_path()?.exists();
            #[cfg(windows)]
            let old = keystore::user_key_fingerprint();
            let path = keystore::save_user_key(&k)?;
            eprintln!("Key stored in {}", path.display());
            warn_old_key_in_use(had_key, false);
            #[cfg(windows)]
            report_service_key(old.as_deref(), Some(&keys::fingerprint(&k)));
            Ok(())
        }
        Some("show") => {
            println!("{}", keys::format_key(&keystore::load_user_key()?));
            Ok(())
        }
        Some("forget") => {
            #[cfg(windows)]
            let old = keystore::user_key_fingerprint();
            if keystore::forget_user_key()? {
                eprintln!("Stored key deleted.");
                warn_old_key_in_use(true, true);
                #[cfg(windows)]
                report_service_key(old.as_deref(), None);
            } else {
                eprintln!("No key was stored.");
            }
            Ok(())
        }
        _ => bail!("usage: safe-rdp key import|show|forget"),
    }
}

fn bench(args: &[String]) -> Result<()> {
    use std::time::Instant;
    let mut monitor = MonitorSel::Primary;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--monitor" => monitor = parse_monitor(next(&mut it, a)?)?,
            other => bail!("unknown option '{other}'"),
        }
    }
    platform::init_process();
    let area = capture::resolve(monitor).ok_or("monitor not found")?;
    let (w, h) = (area.width as usize, area.height as usize);
    println!("screen {w}x{h}, {} encoder threads", std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));

    let t = Instant::now();
    let mut cap = capture::Capturer::open(monitor, area)?;
    let name = cap.backend();
    while !cap.next_frame(500)? {
        if t.elapsed().as_secs() > 3 {
            bail!("{name}: no frame within 3 s");
        }
    }
    let first = t.elapsed().as_secs_f64() * 1000.0;
    let t = Instant::now();
    let mut frames = 0;
    while t.elapsed().as_millis() < 1000 {
        if cap.next_frame(50)? {
            frames += 1;
        }
        if !cap.waits_for_changes() {
            std::thread::sleep(std::time::Duration::from_millis(30));
        }
    }
    println!("capture:       {name}, open + first frame {first:.1} ms, {frames} frames delivered in 1 s");
    let mut frame = cap.pixels().to_vec();
    drop(cap);
    let mut fb = vec![0u8; w * h * 4];
    for (q, label) in [(proto::QUALITY_LOSSLESS, "lossless"), (proto::QUALITY_BALANCED, "balanced"), (proto::QUALITY_LOW, "low")] {
        let mut enc = codec::Encoder::new()?;
        enc.set_quality(q);
        let mut dec = codec::Decoder::new()?;
        let t = Instant::now();
        let rects = enc.encode(&frame, w, h);
        let enc_ms = t.elapsed().as_secs_f64() * 1000.0;
        let msgs = codec::pack(1, w, h, &rects);
        let bytes: usize = msgs.iter().map(Vec::len).sum();
        let t = Instant::now();
        for m in &msgs {
            dec.apply(&m[1..], &mut fb, w, h)?;
        }
        let dec_ms = t.elapsed().as_secs_f64() * 1000.0;
        println!(
            "{label:<9} encode {enc_ms:.1} ms, decode {dec_ms:.1} ms, {:.0} KiB ({:.1}x smaller than 24-bit raw)",
            bytes as f64 / 1024.0,
            (w * h * 3) as f64 / bytes.max(1) as f64
        );
    }
    let mut enc = codec::Encoder::new()?;
    enc.encode(&frame, w, h);
    let t = Instant::now();
    for _ in 0..10 {
        enc.encode(&frame, w, h);
    }
    println!("unchanged:     diff {:.1} ms/frame", t.elapsed().as_secs_f64() * 100.0);
    util::wipe(&mut frame);
    util::wipe(&mut fb);
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    const OLD: &str = "0123456789abcdef";
    const NEW: &str = "891d3768f5c4f960";
    const OTHER: &str = "fedcba9876543210";

    fn warning(recorded: std::result::Result<Option<&str>, &str>, old: Option<&str>, new: Option<&str>) -> String {
        let recorded = recorded.map(|r| r.map(String::from)).map_err(String::from);
        service_key_warning(Ok("running"), recorded, old, new).unwrap()
    }

    #[test]
    fn key_changes_say_which_key_the_service_has() {
        for new in [Some(NEW), None] {
            assert_eq!(service_key_warning(Ok("not installed"), Ok(Some(OLD.into())), Some(OLD), new), None);
            assert_eq!(service_key_warning(Ok("not installed"), Ok(None), None, new), None);
        }
        // Replaced: the service has the new key already, the old one, or yet another.
        let w = warning(Ok(Some(NEW)), Some(OLD), Some(NEW));
        assert!(w.starts_with("note:") && w.contains("already has this key"), "{w}");
        let w = warning(Ok(Some(OLD)), Some(OLD), Some(NEW));
        assert!(w.starts_with("warning:") && w.contains("still has the old key") && w.contains(&format!("rekey --expect-key {NEW}")), "{w}");
        let w = warning(Ok(Some(OTHER)), Some(OLD), Some(NEW));
        assert!(w.contains("another key") && w.contains(OTHER) && w.contains(&format!("rekey --expect-key {NEW}")), "{w}");
        // Removed: the service has the removed key, another one, or nobody can tell.
        let w = warning(Ok(Some(OLD)), Some(OLD), None);
        assert!(w.contains("still has the removed key") && w.contains("service uninstall") && !w.contains("rekey"), "{w}");
        let w = warning(Ok(Some(OTHER)), Some(OLD), None);
        assert!(w.starts_with("note:") && w.contains("not the removed one"), "{w}");
        let w = warning(Ok(Some(OTHER)), None, None);
        assert!(w.starts_with("warning:") && w.contains("may be the removed one"), "{w}");
        // Not knowing is no reason to stay quiet.
        for new in [Some(NEW), None] {
            for w in [warning(Ok(None), Some(OLD), new), warning(Err("access denied"), Some(OLD), new)] {
                assert!(w.starts_with("warning:") && w.contains("cannot tell") && w.contains("may still accept"), "{w}");
            }
        }
        assert!(warning(Err("access denied"), None, Some(NEW)).contains("access denied"));
        let w = service_key_warning(Err("access denied".into()), Ok(None), Some(OLD), Some(NEW)).unwrap();
        assert!(w.contains("access denied") && w.contains(&format!("rekey --expect-key {NEW}")), "{w}");
        let w = service_key_warning(Err("access denied".into()), Ok(None), Some(OLD), None).unwrap();
        assert!(w.contains("access denied") && w.contains("service uninstall"), "{w}");
    }

    #[test]
    fn service_status_compares_the_keys() {
        let line = |r: std::result::Result<Option<&str>, &str>, mine| service_key_line(r.map(|r| r.map(String::from)).map_err(String::from), mine);
        assert_eq!(line(Ok(Some(NEW)), Some(NEW)), format!("key: {NEW}, the key stored for this user"));
        let l = line(Ok(Some(OLD)), Some(NEW));
        assert!(l.contains(&format!("{OLD}, not the key stored")) && l.contains(&format!("rekey --expect-key {NEW}")), "{l}");
        assert!(line(Ok(Some(OLD)), None).contains("no readable key"));
        assert!(line(Ok(None), Some(NEW)).contains("not recorded") && line(Ok(None), Some(NEW)).contains(NEW));
        assert!(line(Err("access denied"), Some(NEW)).contains("cannot tell (access denied)"));
    }
}
