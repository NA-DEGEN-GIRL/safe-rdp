//! safe-rdp: a small, auditable remote desktop for Windows, meant to run over Tailscale.

mod capture;
mod channel;
mod client;
mod clipboard;
mod codec;
mod crypto;
mod desktop;
mod dxgi;
mod input;
mod keystore;
mod mem;
mod net;
mod proto;
mod server;
mod service;
mod util;

use capture::MonitorSel;
use net::PeerPolicy;
use std::net::IpAddr;
use util::{Error, Result, Secret};

const USAGE: &str = "\
safe-rdp - remote desktop for Windows over Tailscale

USAGE:
  safe-rdp keygen [--force]          Create a new key, store it for this user, print it once
  safe-rdp key import                Store a key (paste it at the prompt) for this user
  safe-rdp key show                  Print the stored key (to set up the other machine)
  safe-rdp key forget                Delete the stored key

  safe-rdp host [HOST OPTIONS]       Share this screen (runs in the current session)
  safe-rdp connect <host[:port]> [VIEWER OPTIONS]

  safe-rdp service install [HOST OPTIONS] [--enable-sas]   (elevated) run as a SYSTEM
                                     service: works on the lock/sign-in screen and UAC
  safe-rdp service uninstall | status

  safe-rdp monitors                  List monitors
  safe-rdp bench [--monitor N]       Measure capture/encode speed on this machine

HOST OPTIONS:
  --bind <ip>              Address to listen on (default: this machine's Tailscale IPv4)
  --port <n>               TCP port (default 47300)
  --allow <ip>[,<ip>...]   Only accept these peer addresses (default: any Tailscale peer)
  --allow-non-tailscale    Permit binding/peers outside Tailscale ranges (not recommended)
  --monitor <n|all>        Monitor to share, 1 = primary (default), or 'all'
  --fps <n>                Frame rate cap (default 30)
  --clipboard              Allow text clipboard sharing (viewer must opt in too)
  --view-only              Ignore keyboard and mouse from viewers
  --key-file <path>        Read the key from a text file instead of the user key store

VIEWER OPTIONS:
  --fullscreen             Start in full screen (toggle: Ctrl+Alt+Enter)
  --clipboard              Share text clipboard (host must allow it)
  --view-only              Do not send keyboard or mouse input
  --allow-capture          Let local screenshot/recording tools capture the viewer window
  --key-file <path>        Read the key from a text file

Hotkeys in the viewer: Ctrl+Alt+Enter full screen, Ctrl+Alt+End sends Ctrl+Alt+Del.
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = dispatch(&args) {
        log!("error: {e}");
        std::process::exit(1);
    }
}

fn dpi_aware() {
    use windows_sys::Win32::UI::HiDpi::{DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext};
    unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
}

fn dispatch(args: &[String]) -> Result<()> {
    let Some(cmd) = args.first() else {
        print!("{USAGE}");
        return Ok(());
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "keygen" => keygen(rest),
        "key" => key_cmd(rest),
        "host" => {
            let (opts, key_file) = parse_host(rest, false)?;
            let key = load_key(key_file.as_deref())?;
            dpi_aware();
            server::run(opts, key)
        }
        "agent" => {
            // Started by the service as SYSTEM inside the console session.
            util::set_log_file(&keystore::service_dir().join("host.log"))?;
            let (opts, _) = parse_host(rest, true)?;
            let key = keystore::load_service_key()?;
            dpi_aware();
            server::run(opts, key)
        }
        "connect" => connect(rest),
        "service" => match rest.first().map(String::as_str) {
            Some("install") => {
                let (opts, key_file) = parse_host(&rest[1..], true)?;
                if key_file.is_some() {
                    bail!("--key-file is not supported for the service; it uses this user's stored key");
                }
                service::install(&rest[1..], opts.port, opts.sas)
            }
            Some("uninstall") => service::uninstall(),
            Some("status") => {
                println!("{}", service::status()?);
                Ok(())
            }
            Some("run") => service::run_dispatcher(rest[1..].to_vec()),
            _ => bail!("usage: safe-rdp service install|uninstall|status"),
        },
        "monitors" => {
            dpi_aware();
            for (i, m) in capture::monitors().iter().enumerate() {
                println!("{}: {}x{} at ({}, {}){}", i + 1, m.width, m.height, m.left, m.top, if i == 0 { " primary" } else { "" });
            }
            let v = capture::virtual_screen();
            println!("all: {}x{} at ({}, {})", v.width, v.height, v.left, v.top);
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

fn parse_host(args: &[String], service: bool) -> Result<(server::HostOptions, Option<String>)> {
    let mut o = server::HostOptions {
        bind: None,
        port: proto::DEFAULT_PORT,
        policy: PeerPolicy { allow: vec![], allow_non_tailscale: false, loopback_ok: false },
        monitor: MonitorSel::Primary,
        max_fps: 30,
        clipboard: false,
        view_only: false,
        sas: false,
    };
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
            "--clipboard" => o.clipboard = true,
            "--view-only" => o.view_only = true,
            "--enable-sas" if service => o.sas = true,
            "--key-file" => key_file = Some(next(&mut it, a)?.to_string()),
            other => bail!("unknown host option '{other}'"),
        }
    }
    if let Some(ip) = o.bind {
        o.policy.loopback_ok = ip.is_loopback();
    }
    if let Some(ip) = o.policy.allow.iter().find(|ip| !net::is_tailscale(**ip) && !ip.is_loopback()) {
        if !o.policy.allow_non_tailscale {
            bail!("--allow {ip} is outside Tailscale; add --allow-non-tailscale if you really mean it");
        }
    }
    Ok((o, key_file))
}

fn load_key(key_file: Option<&str>) -> Result<Secret<32>> {
    match key_file {
        Some(p) => keystore::load_key_file(p),
        None => keystore::load_user_key(),
    }
}

fn connect(args: &[String]) -> Result<()> {
    let mut target = None;
    let mut key_file = None;
    let mut o = client::ViewerOptions { fullscreen: false, clipboard: false, view_only: false, allow_capture: false };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--fullscreen" => o.fullscreen = true,
            "--clipboard" => o.clipboard = true,
            "--view-only" => o.view_only = true,
            "--allow-capture" => o.allow_capture = true,
            "--key-file" => key_file = Some(next(&mut it, a)?.to_string()),
            s if s.starts_with("--") => bail!("unknown viewer option '{s}'"),
            s if target.is_none() => target = Some(s.to_string()),
            s => bail!("unexpected argument '{s}'"),
        }
    }
    let target = target.ok_or("usage: safe-rdp connect <host[:port]>")?;
    let key = load_key(key_file.as_deref())?;
    dpi_aware();
    client::run(&target, o, key)
}

fn read_secret(prompt: &str) -> Result<String> {
    use windows_sys::Win32::System::Console::*;
    eprint!("{prompt}");
    let mut line = String::new();
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0;
        let console = GetConsoleMode(h, &mut mode) != 0;
        if console {
            SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
        }
        let r = std::io::stdin().read_line(&mut line);
        if console {
            SetConsoleMode(h, mode);
            eprintln!();
        }
        r?;
    }
    Ok(line)
}

fn keygen(args: &[String]) -> Result<()> {
    let force = args.iter().any(|a| a == "--force");
    if let Some(a) = args.iter().find(|a| *a != "--force") {
        bail!("unknown option '{a}'");
    }
    if keystore::user_key_path()?.exists() && !force {
        bail!("a key is already stored; use `safe-rdp key show`, or `keygen --force` to replace it");
    }
    let k = keystore::generate()?;
    let path = keystore::save_user_key(&k)?;
    println!("{}", keystore::format_key(&k));
    eprintln!();
    eprintln!("Stored (DPAPI-encrypted for this Windows user) in {}", path.display());
    eprintln!("On the other machine run `safe-rdp key import` and paste the line above.");
    eprintln!("Treat it like a password: anyone with this key and tailnet access can control the host.");
    Ok(())
}

fn key_cmd(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("import") => {
            let mut line = match args.get(1) {
                Some(k) => k.clone(),
                None => read_secret("Paste key (input hidden): ")?,
            };
            let k = keystore::parse_key(&line);
            unsafe { util::wipe(line.as_bytes_mut()) };
            let path = keystore::save_user_key(&k?)?;
            eprintln!("Key stored in {}", path.display());
            Ok(())
        }
        Some("show") => {
            println!("{}", keystore::format_key(&keystore::load_user_key()?));
            Ok(())
        }
        Some("forget") => {
            if keystore::forget_user_key()? {
                eprintln!("Stored key deleted.");
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
    dpi_aware();
    let area = capture::resolve(monitor).ok_or("monitor not found")?;
    let (w, h) = (area.width as usize, area.height as usize);
    println!("screen {w}x{h}, {} encoder threads", std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));

    let mut frame = Vec::new();
    for (name, cap) in [("DXGI", capture::Capturer::new(area)), ("GDI", capture::Capturer::gdi(area))] {
        let mut cap = cap?;
        if name == "DXGI" && !cap.waits_for_changes() {
            println!("DXGI:          unavailable");
            continue;
        }
        let t = Instant::now();
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
        }
        println!("{name:<5}          first frame {first:.1} ms; {frames} frames delivered in 1 s");
        frame = cap.pixels().to_vec();
    }

    let mut enc = codec::Encoder::new()?;
    let mut dec = codec::Decoder::new()?;
    let t = Instant::now();
    let rects = enc.encode(&frame, w, h);
    let enc_ms = t.elapsed().as_secs_f64() * 1000.0;
    let msgs = codec::pack(1, w, h, &rects);
    let bytes: usize = msgs.iter().map(Vec::len).sum();
    let mut fb = vec![0u8; w * h * 4];
    let t = Instant::now();
    for m in &msgs {
        dec.apply(&m[1..], &mut fb, w, h)?;
    }
    let dec_ms = t.elapsed().as_secs_f64() * 1000.0;
    println!(
        "full frame:    encode {enc_ms:.1} ms, decode {dec_ms:.1} ms, {:.0} KiB ({:.1}x smaller than 24-bit raw)",
        bytes as f64 / 1024.0,
        (w * h * 3) as f64 / bytes as f64
    );
    let t = Instant::now();
    for _ in 0..10 {
        enc.encode(&frame, w, h);
    }
    println!("unchanged:     diff {:.1} ms/frame", t.elapsed().as_secs_f64() * 100.0);
    util::wipe(&mut frame);    util::wipe(&mut fb);
    Ok(())
}
