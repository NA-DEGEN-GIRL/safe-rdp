//! Application messages carried inside encrypted records.

use crate::bail;
use crate::util::Result;

pub const DEFAULT_PORT: u16 = 47300;
pub const MAX_CLIPBOARD: usize = 1 << 20;

// Server -> client
pub const S_HELLO: u8 = 0x01;
pub const S_TILES: u8 = 0x02;
pub const S_CURSOR: u8 = 0x03;
pub const S_CLIPBOARD: u8 = 0x04;
pub const S_PING: u8 = 0x05;
pub const S_NOTICE: u8 = 0x06;

// Client -> server
pub const C_ACK: u8 = 0x81;
pub const C_MOUSE_MOVE: u8 = 0x82;
pub const C_MOUSE_BUTTON: u8 = 0x83;
pub const C_WHEEL: u8 = 0x84;
pub const C_KEY: u8 = 0x85;
pub const C_RELEASE_ALL: u8 = 0x86;
pub const C_CLIPBOARD: u8 = 0x87;
pub const C_REFRESH: u8 = 0x88;
pub const C_SAS: u8 = 0x89;
pub const C_PING: u8 = 0x8a;

// Hello feature flags
pub const F_CLIPBOARD: u32 = 1;
pub const F_VIEW_ONLY: u32 = 2;
pub const F_SAS: u32 = 4;

// Key flags
pub const KEY_EXTENDED: u8 = 1;
pub const KEY_UP: u8 = 2;

pub const BTN_LEFT: u8 = 0;
pub const BTN_RIGHT: u8 = 1;
pub const BTN_MIDDLE: u8 = 2;
pub const BTN_X1: u8 = 3;
pub const BTN_X2: u8 = 4;

/// Cursor shapes mirrored to the viewer (the viewer draws its own local cursor).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cursor {
    Hidden = 0,
    Arrow,
    IBeam,
    Wait,
    Cross,
    UpArrow,
    SizeNwse,
    SizeNesw,
    SizeWe,
    SizeNs,
    SizeAll,
    No,
    Hand,
    AppStarting,
    Help,
}

impl Cursor {
    pub const ALL: [Cursor; 15] = [
        Cursor::Hidden,
        Cursor::Arrow,
        Cursor::IBeam,
        Cursor::Wait,
        Cursor::Cross,
        Cursor::UpArrow,
        Cursor::SizeNwse,
        Cursor::SizeNesw,
        Cursor::SizeWe,
        Cursor::SizeNs,
        Cursor::SizeAll,
        Cursor::No,
        Cursor::Hand,
        Cursor::AppStarting,
        Cursor::Help,
    ];

    pub fn from_u8(v: u8) -> Cursor {
        Cursor::ALL.get(v as usize).copied().unwrap_or(Cursor::Arrow)
    }
}

#[derive(Debug, PartialEq)]
pub enum ClientMsg {
    Ack(u32),
    MouseMove { x: u16, y: u16 },
    MouseButton { button: u8, down: bool },
    Wheel { delta: i16, horizontal: bool },
    Key { vk: u16, scan: u16, flags: u8 },
    ReleaseAll,
    Clipboard(String),
    Refresh,
    Sas,
    Ping,
}

#[derive(Debug, PartialEq)]
pub enum ServerMsg<'a> {
    Hello { width: u16, height: u16, flags: u32 },
    /// Opaque payload parsed by `codec::Decoder`.
    Tiles(&'a [u8]),
    Cursor(Cursor),
    Clipboard(String),
    Ping,
    Notice(String),
}

/// Little-endian cursor over a byte slice.
pub struct Rd<'a>(pub &'a [u8]);

impl<'a> Rd<'a> {
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            bail!("truncated message");
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }
    pub fn end(&self) -> Result<()> {
        if !self.0.is_empty() {
            bail!("trailing bytes in message");
        }
        Ok(())
    }
}

fn text(b: &[u8]) -> Result<String> {
    if b.len() > MAX_CLIPBOARD {
        bail!("text too large");
    }
    String::from_utf8(b.to_vec()).map_err(|_| "invalid UTF-8".into())
}

impl ClientMsg {
    pub fn encode(&self, o: &mut Vec<u8>) {
        match self {
            ClientMsg::Ack(id) => {
                o.push(C_ACK);
                o.extend_from_slice(&id.to_le_bytes());
            }
            ClientMsg::MouseMove { x, y } => {
                o.push(C_MOUSE_MOVE);
                o.extend_from_slice(&x.to_le_bytes());
                o.extend_from_slice(&y.to_le_bytes());
            }
            ClientMsg::MouseButton { button, down } => o.extend_from_slice(&[C_MOUSE_BUTTON, *button, *down as u8]),
            ClientMsg::Wheel { delta, horizontal } => {
                o.push(C_WHEEL);
                o.extend_from_slice(&delta.to_le_bytes());
                o.push(*horizontal as u8);
            }
            ClientMsg::Key { vk, scan, flags } => {
                o.push(C_KEY);
                o.extend_from_slice(&vk.to_le_bytes());
                o.extend_from_slice(&scan.to_le_bytes());
                o.push(*flags);
            }
            ClientMsg::ReleaseAll => o.push(C_RELEASE_ALL),
            ClientMsg::Clipboard(s) => {
                o.push(C_CLIPBOARD);
                o.extend_from_slice(s.as_bytes());
            }
            ClientMsg::Refresh => o.push(C_REFRESH),
            ClientMsg::Sas => o.push(C_SAS),
            ClientMsg::Ping => o.push(C_PING),
        }
    }

    pub fn decode(b: &[u8]) -> Result<ClientMsg> {
        let mut r = Rd(b);
        let m = match r.u8()? {
            C_ACK => ClientMsg::Ack(r.u32()?),
            C_MOUSE_MOVE => ClientMsg::MouseMove { x: r.u16()?, y: r.u16()? },
            C_MOUSE_BUTTON => ClientMsg::MouseButton { button: r.u8()?, down: r.u8()? != 0 },
            C_WHEEL => ClientMsg::Wheel { delta: r.u16()? as i16, horizontal: r.u8()? != 0 },
            C_KEY => ClientMsg::Key { vk: r.u16()?, scan: r.u16()?, flags: r.u8()? },
            C_RELEASE_ALL => ClientMsg::ReleaseAll,
            C_CLIPBOARD => return Ok(ClientMsg::Clipboard(text(r.0)?)),
            C_REFRESH => ClientMsg::Refresh,
            C_SAS => ClientMsg::Sas,
            C_PING => ClientMsg::Ping,
            t => bail!("unknown client message {t:#x}"),
        };
        r.end()?;
        Ok(m)
    }
}

impl<'a> ServerMsg<'a> {
    pub fn encode(&self, o: &mut Vec<u8>) {
        match self {
            ServerMsg::Hello { width, height, flags } => {
                o.push(S_HELLO);
                o.extend_from_slice(&width.to_le_bytes());
                o.extend_from_slice(&height.to_le_bytes());
                o.extend_from_slice(&flags.to_le_bytes());
            }
            ServerMsg::Tiles(p) => {
                o.push(S_TILES);
                o.extend_from_slice(p);
            }
            ServerMsg::Cursor(c) => o.extend_from_slice(&[S_CURSOR, *c as u8]),
            ServerMsg::Clipboard(s) => {
                o.push(S_CLIPBOARD);
                o.extend_from_slice(s.as_bytes());
            }
            ServerMsg::Ping => o.push(S_PING),
            ServerMsg::Notice(s) => {
                o.push(S_NOTICE);
                o.extend_from_slice(s.as_bytes());
            }
        }
    }

    pub fn decode(b: &'a [u8]) -> Result<ServerMsg<'a>> {
        let mut r = Rd(b);
        let m = match r.u8()? {
            S_HELLO => ServerMsg::Hello { width: r.u16()?, height: r.u16()?, flags: r.u32()? },
            S_TILES => return Ok(ServerMsg::Tiles(r.0)),
            S_CURSOR => ServerMsg::Cursor(Cursor::from_u8(r.u8()?)),
            S_CLIPBOARD => return Ok(ServerMsg::Clipboard(text(r.0)?)),
            S_PING => ServerMsg::Ping,
            S_NOTICE => return Ok(ServerMsg::Notice(text(r.0)?)),
            t => bail!("unknown server message {t:#x}"),
        };
        r.end()?;
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_roundtrip() {
        let msgs = [
            ClientMsg::Ack(7),
            ClientMsg::MouseMove { x: 1919, y: 1079 },
            ClientMsg::MouseButton { button: BTN_X2, down: true },
            ClientMsg::Wheel { delta: -120, horizontal: true },
            ClientMsg::Key { vk: 0x15, scan: 0x72, flags: KEY_UP | KEY_EXTENDED },
            ClientMsg::ReleaseAll,
            ClientMsg::Clipboard("안녕 clipboard".into()),
            ClientMsg::Refresh,
            ClientMsg::Sas,
            ClientMsg::Ping,
        ];
        for m in msgs {
            let mut b = Vec::new();
            m.encode(&mut b);
            assert_eq!(ClientMsg::decode(&b).unwrap(), m);
        }
    }

    #[test]
    fn server_roundtrip() {
        let msgs = [
            ServerMsg::Hello { width: 2560, height: 1440, flags: F_CLIPBOARD },
            ServerMsg::Tiles(&[1, 2, 3]),
            ServerMsg::Cursor(Cursor::IBeam),
            ServerMsg::Clipboard("x".into()),
            ServerMsg::Ping,
            ServerMsg::Notice("bye".into()),
        ];
        for m in msgs {
            let mut b = Vec::new();
            m.encode(&mut b);
            assert_eq!(ServerMsg::decode(&b).unwrap(), m);
        }
    }

    #[test]
    fn rejects_malformed() {
        assert!(ClientMsg::decode(&[]).is_err());
        assert!(ClientMsg::decode(&[C_ACK, 1, 2]).is_err());
        assert!(ClientMsg::decode(&[C_REFRESH, 0]).is_err());
        assert!(ClientMsg::decode(&[0x7f]).is_err());
        assert!(ClientMsg::decode(&[C_CLIPBOARD, 0xff, 0xfe]).is_err());
        assert!(ServerMsg::decode(&[S_HELLO, 1]).is_err());
    }
}
