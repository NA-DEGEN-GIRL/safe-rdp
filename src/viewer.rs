//! Portable viewer plumbing: resolving the host, connecting, authenticating and the hello
//! exchange. Used by the platform viewers and by `probe`.

use crate::channel::{self, RecordReader, RecordWriter};
use crate::proto::*;
use crate::util::{Error, Result, Secret};
use crate::{bail, log};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

pub struct ViewerOptions {
    pub fullscreen: bool,
    pub clipboard: bool,
    pub view_only: bool,
    /// Allow local screenshot/recording tools to capture the viewer window.
    pub allow_capture: bool,
    /// Ask the host for 1/N resolution (1 = full).
    pub downscale: u8,
}

/// An authenticated session, after the hello exchange.
pub struct Connection {
    pub addr: SocketAddr,
    pub stream: TcpStream,
    pub reader: RecordReader<TcpStream>,
    pub writer: RecordWriter<TcpStream>,
    pub width: usize,
    pub height: usize,
    pub flags: u32,
}

/// Resolves `host`, `host:port`, an IP literal or a MagicDNS name; prefers Tailscale addresses.
pub fn resolve(target: &str) -> Result<SocketAddr> {
    let with_port = if target.parse::<SocketAddr>().is_ok()
        || target.rsplit_once(':').is_some_and(|(h, p)| !h.contains(':') && p.parse::<u16>().is_ok())
    {
        target.to_string()
    } else if target.contains(':') {
        format!("[{target}]:{DEFAULT_PORT}")
    } else {
        format!("{target}:{DEFAULT_PORT}")
    };
    let addrs: Vec<SocketAddr> = with_port.to_socket_addrs().map_err(|e| format!("cannot resolve {target}: {e}"))?.collect();
    addrs
        .iter()
        .find(|a| crate::net::is_tailscale(a.ip()))
        .or(addrs.first())
        .copied()
        .ok_or_else(|| Error::msg(format!("{target} has no addresses")))
}

pub fn connect(target: &str, downscale: u8, psk: &Secret<32>) -> Result<Connection> {
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
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut reader = RecordReader::new(stream.try_clone()?, keys.recv);
    let mut writer = RecordWriter::new(stream.try_clone()?, keys.send);
    let mut hello = Vec::new();
    ClientMsg::Hello { downscale }.encode(&mut hello);
    writer.send(&hello)?;
    let (width, height, flags) = match ServerMsg::decode(reader.recv()?)? {
        ServerMsg::Hello { width, height, flags } => (width as usize, height as usize, flags),
        _ => bail!("unexpected first message from host"),
    };
    if width == 0 || height == 0 {
        bail!("host reported an empty screen");
    }
    log!("connected: remote screen {width}x{height}");
    Ok(Connection { addr, stream, reader, writer, width, height, flags })
}
