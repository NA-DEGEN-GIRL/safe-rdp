//! Application messages carried inside encrypted records (protocol version 2).
//!
//! Every record holds exactly one message: a type byte followed by little-endian fields.
//! Decoders reject unknown types, truncated fields and trailing bytes.

use crate::bail;
use crate::util::Result;

pub const DEFAULT_PORT: u16 = 47300;
pub const MAX_CLIPBOARD: usize = 1 << 20;
/// Upper bound for one file-transfer data chunk.
pub const MAX_FILE_CHUNK: usize = 1 << 20;
/// Upper bound for a transferred file name (bytes of UTF-8, no directories).
pub const MAX_FILE_NAME: usize = 255;
/// Upper bound for one transferred file.
pub const MAX_FILE_SIZE: u64 = 64 << 30;

// Server -> client
pub const S_HELLO: u8 = 0x01;
pub const S_TILES: u8 = 0x02;
pub const S_CURSOR: u8 = 0x03;
pub const S_CLIPBOARD: u8 = 0x04;
pub const S_PING: u8 = 0x05;
pub const S_NOTICE: u8 = 0x06;
pub const S_PONG: u8 = 0x07;
pub const S_AUDIO: u8 = 0x08;
pub const S_FILE_BEGIN: u8 = 0x09;
pub const S_FILE_DATA: u8 = 0x0a;
pub const S_FILE_END: u8 = 0x0b;
pub const S_FILE_RESULT: u8 = 0x0c;
pub const S_STATE: u8 = 0x0d;

// Client -> server
pub const C_HELLO: u8 = 0x80;
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
pub const C_SET: u8 = 0x8b;
pub const C_FILE_BEGIN: u8 = 0x8c;
pub const C_FILE_DATA: u8 = 0x8d;
pub const C_FILE_END: u8 = 0x8e;
pub const C_FILE_PULL: u8 = 0x8f;

// Host capability flags in `ServerMsg::Hello`
pub const F_CLIPBOARD: u32 = 1;
pub const F_VIEW_ONLY: u32 = 2;
pub const F_SAS: u32 = 4;
pub const F_AUDIO: u32 = 8;
pub const F_FILES: u32 = 16;
pub const F_PRIVACY: u32 = 32;

// Viewer wishes in `ClientMsg::Hello::flags`
pub const HELLO_AUDIO: u8 = 1;
pub const HELLO_PRIVACY: u8 = 2;

/// Settings the viewer can change during a session (`ClientMsg::Set`); the host confirms
/// the value actually in effect with `ServerMsg::State` using the same key.
pub const SET_QUALITY: u8 = 1;
pub const SET_DOWNSCALE: u8 = 2;
pub const SET_MONITOR: u8 = 3;
pub const SET_AUDIO: u8 = 4;
pub const SET_PRIVACY: u8 = 5;

/// `SET_QUALITY` values.
pub const QUALITY_LOSSLESS: u32 = 0;
/// Lossy for busy regions, lossless refinement once they settle (default).
pub const QUALITY_BALANCED: u32 = 1;
/// Stronger lossy compression for slow links, refinement only after a longer pause.
pub const QUALITY_LOW: u32 = 2;

/// `SET_MONITOR` / hello monitor values besides a zero-based index.
pub const MONITOR_ALL: u8 = 0xff;
pub const MONITOR_DEFAULT: u8 = 0xfe;

/// `ServerMsg::State` value meaning "this feature is unavailable on the host".
pub const STATE_UNAVAILABLE: u32 = u32::MAX;

// Key flags
pub const KEY_EXTENDED: u8 = 1;
pub const KEY_UP: u8 = 2;

pub const BTN_LEFT: u8 = 0;
pub const BTN_RIGHT: u8 = 1;
pub const BTN_MIDDLE: u8 = 2;
pub const BTN_X1: u8 = 3;
pub const BTN_X2: u8 = 4;

// Audio codecs in `ServerMsg::Audio`
pub const AUDIO_PCM16: u8 = 0;
pub const AUDIO_IMA_ADPCM: u8 = 1;

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

/// A monitor as advertised to the viewer.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct MonitorInfo {
    pub left: i32,
    pub top: i32,
    pub width: u16,
    pub height: u16,
}

#[derive(Debug, PartialEq)]
pub enum ClientMsg {
    /// First message of a session.
    Hello { downscale: u8, quality: u8, monitor: u8, flags: u8 },
    Ack(u32),
    MouseMove { x: u16, y: u16 },
    MouseButton { button: u8, down: bool },
    Wheel { delta: i16, horizontal: bool },
    Key { vk: u16, scan: u16, flags: u8 },
    ReleaseAll,
    Clipboard(String),
    Refresh,
    Sas,
    /// Round-trip probe; the host echoes `t` in `ServerMsg::Pong`.
    Ping(u64),
    Set { key: u8, value: u32 },
    /// Upload to the host: header, chunks, then the SHA-256 of the whole file.
    FileBegin { id: u32, size: u64, name: String },
    FileData { id: u32, data: Vec<u8> },
    FileEnd { id: u32, sha256: [u8; 32] },
    /// Ask the host to send the files currently copied to its clipboard.
    FilePull,
}

#[derive(Debug, PartialEq)]
pub enum ServerMsg<'a> {
    Hello { width: u16, height: u16, flags: u32, monitor: u8, monitors: Vec<MonitorInfo>, name: String },
    /// Opaque payload parsed by `codec::Decoder`.
    Tiles(&'a [u8]),
    Cursor(Cursor),
    Clipboard(String),
    Ping,
    Notice(String),
    Pong(u64),
    Audio { seq: u32, rate: u32, channels: u8, codec: u8, data: &'a [u8] },
    FileBegin { id: u32, size: u64, name: String },
    FileData { id: u32, data: &'a [u8] },
    FileEnd { id: u32, sha256: [u8; 32] },
    /// Outcome of an upload: `ok` plus a human-readable detail (saved path or error).
    FileResult { id: u32, ok: bool, message: String },
    State { key: u8, value: u32 },
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
    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }
    pub fn arr32(&mut self) -> Result<[u8; 32]> {
        Ok(self.bytes(32)?.try_into().unwrap())
    }
    /// The rest of the message.
    pub fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }
    pub fn end(&self) -> Result<()> {
        if !self.0.is_empty() {
            bail!("trailing bytes in message");
        }
        Ok(())
    }
}

fn text(b: &[u8], max: usize) -> Result<String> {
    if b.len() > max {
        bail!("text too large");
    }
    String::from_utf8(b.to_vec()).map_err(|_| "invalid UTF-8".into())
}

/// Control characters, and invisible format characters that reorder text (bidi overrides,
/// marks and isolates), break lines or hide text, so `a\u{202E}gpj.exe` cannot pose as `aexe.jpg`.
fn deceptive(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

/// Windows device names (`CON`, `nul.txt`, `COM1.tar.gz`, ...), which open a device instead of a file.
fn windows_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or_default().trim_end_matches(' ').to_ascii_uppercase();
    let port = stem.strip_prefix("COM").or_else(|| stem.strip_prefix("LPT"));
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || port.is_some_and(|d| matches!(d, "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"))
}

/// A transferred file name must be a single, plain path component that every supported OS stores
/// under exactly that name: no trailing `.` or space (Windows drops them, which would move the
/// Mark of the Web onto a different file), no device names, no control or bidi characters.
pub fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_FILE_NAME
        && !name.ends_with(['.', ' '])
        && !name.chars().any(|c| matches!(c, '/' | '\\' | ':') || deceptive(c))
        && !windows_device_name(name)
}

/// Peer-supplied `s` made safe to log or print: control and deceptive format characters become
/// `?` (no terminal escapes, forged lines or reordered text), and it is cut to 512 characters.
pub fn printable(s: &str) -> String {
    const MAX: usize = 512;
    let mut out: String = s.chars().take(MAX).map(|c| if deceptive(c) { '?' } else { c }).collect();
    if s.chars().nth(MAX).is_some() {
        out.push('…');
    }
    out
}

fn file_name(b: &[u8]) -> Result<String> {
    let name = text(b, MAX_FILE_NAME)?;
    if !valid_file_name(&name) {
        bail!("invalid file name");
    }
    Ok(name)
}

fn chunk(b: &[u8]) -> Result<&[u8]> {
    if b.is_empty() || b.len() > MAX_FILE_CHUNK {
        bail!("bad file chunk size");
    }
    Ok(b)
}

fn file_size(v: u64) -> Result<u64> {
    if v > MAX_FILE_SIZE {
        bail!("file too large");
    }
    Ok(v)
}

impl ClientMsg {
    pub fn encode(&self, o: &mut Vec<u8>) {
        match self {
            ClientMsg::Hello { downscale, quality, monitor, flags } => o.extend_from_slice(&[C_HELLO, *downscale, *quality, *monitor, *flags]),
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
            ClientMsg::Ping(t) => {
                o.push(C_PING);
                o.extend_from_slice(&t.to_le_bytes());
            }
            ClientMsg::Set { key, value } => {
                o.extend_from_slice(&[C_SET, *key]);
                o.extend_from_slice(&value.to_le_bytes());
            }
            ClientMsg::FileBegin { id, size, name } => {
                o.push(C_FILE_BEGIN);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(&size.to_le_bytes());
                o.extend_from_slice(name.as_bytes());
            }
            ClientMsg::FileData { id, data } => {
                o.push(C_FILE_DATA);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(data);
            }
            ClientMsg::FileEnd { id, sha256 } => {
                o.push(C_FILE_END);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(sha256);
            }
            ClientMsg::FilePull => o.push(C_FILE_PULL),
        }
    }

    pub fn decode(b: &[u8]) -> Result<ClientMsg> {
        let mut r = Rd(b);
        let m = match r.u8()? {
            C_HELLO => ClientMsg::Hello { downscale: r.u8()?, quality: r.u8()?, monitor: r.u8()?, flags: r.u8()? },
            C_ACK => ClientMsg::Ack(r.u32()?),
            C_MOUSE_MOVE => ClientMsg::MouseMove { x: r.u16()?, y: r.u16()? },
            C_MOUSE_BUTTON => ClientMsg::MouseButton { button: r.u8()?, down: r.u8()? != 0 },
            C_WHEEL => ClientMsg::Wheel { delta: r.u16()? as i16, horizontal: r.u8()? != 0 },
            C_KEY => ClientMsg::Key { vk: r.u16()?, scan: r.u16()?, flags: r.u8()? },
            C_RELEASE_ALL => ClientMsg::ReleaseAll,
            C_CLIPBOARD => ClientMsg::Clipboard(text(r.rest(), MAX_CLIPBOARD)?),
            C_REFRESH => ClientMsg::Refresh,
            C_SAS => ClientMsg::Sas,
            C_PING => ClientMsg::Ping(r.u64()?),
            C_SET => ClientMsg::Set { key: r.u8()?, value: r.u32()? },
            C_FILE_BEGIN => ClientMsg::FileBegin { id: r.u32()?, size: file_size(r.u64()?)?, name: file_name(r.rest())? },
            C_FILE_DATA => ClientMsg::FileData { id: r.u32()?, data: chunk(r.rest())?.to_vec() },
            C_FILE_END => ClientMsg::FileEnd { id: r.u32()?, sha256: r.arr32()? },
            C_FILE_PULL => ClientMsg::FilePull,
            t => bail!("unknown client message {t:#x}"),
        };
        r.end()?;
        Ok(m)
    }
}

impl<'a> ServerMsg<'a> {
    pub fn encode(&self, o: &mut Vec<u8>) {
        match self {
            ServerMsg::Hello { width, height, flags, monitor, monitors, name } => {
                o.push(S_HELLO);
                o.extend_from_slice(&width.to_le_bytes());
                o.extend_from_slice(&height.to_le_bytes());
                o.extend_from_slice(&flags.to_le_bytes());
                o.push(*monitor);
                o.push(monitors.len().min(255) as u8);
                for m in monitors.iter().take(255) {
                    o.extend_from_slice(&m.left.to_le_bytes());
                    o.extend_from_slice(&m.top.to_le_bytes());
                    o.extend_from_slice(&m.width.to_le_bytes());
                    o.extend_from_slice(&m.height.to_le_bytes());
                }
                let n = name.floor_char_boundary(255);
                o.push(n as u8);
                o.extend_from_slice(&name.as_bytes()[..n]);
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
            ServerMsg::Pong(t) => {
                o.push(S_PONG);
                o.extend_from_slice(&t.to_le_bytes());
            }
            ServerMsg::Audio { seq, rate, channels, codec, data } => {
                o.push(S_AUDIO);
                o.extend_from_slice(&seq.to_le_bytes());
                o.extend_from_slice(&rate.to_le_bytes());
                o.extend_from_slice(&[*channels, *codec]);
                o.extend_from_slice(data);
            }
            ServerMsg::FileBegin { id, size, name } => {
                o.push(S_FILE_BEGIN);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(&size.to_le_bytes());
                o.extend_from_slice(name.as_bytes());
            }
            ServerMsg::FileData { id, data } => {
                o.push(S_FILE_DATA);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(data);
            }
            ServerMsg::FileEnd { id, sha256 } => {
                o.push(S_FILE_END);
                o.extend_from_slice(&id.to_le_bytes());
                o.extend_from_slice(sha256);
            }
            ServerMsg::FileResult { id, ok, message } => {
                o.push(S_FILE_RESULT);
                o.extend_from_slice(&id.to_le_bytes());
                o.push(*ok as u8);
                o.extend_from_slice(message.as_bytes());
            }
            ServerMsg::State { key, value } => {
                o.extend_from_slice(&[S_STATE, *key]);
                o.extend_from_slice(&value.to_le_bytes());
            }
        }
    }

    pub fn decode(b: &'a [u8]) -> Result<ServerMsg<'a>> {
        let mut r = Rd(b);
        let m = match r.u8()? {
            S_HELLO => {
                let (width, height, flags, monitor) = (r.u16()?, r.u16()?, r.u32()?, r.u8()?);
                let n = r.u8()? as usize;
                let mut monitors = Vec::with_capacity(n);
                for _ in 0..n {
                    monitors.push(MonitorInfo { left: r.i32()?, top: r.i32()?, width: r.u16()?, height: r.u16()? });
                }
                let len = r.u8()? as usize;
                let name = text(r.bytes(len)?, 255)?;
                ServerMsg::Hello { width, height, flags, monitor, monitors, name }
            }
            S_TILES => ServerMsg::Tiles(r.rest()),
            S_CURSOR => ServerMsg::Cursor(Cursor::from_u8(r.u8()?)),
            S_CLIPBOARD => ServerMsg::Clipboard(text(r.rest(), MAX_CLIPBOARD)?),
            S_PING => ServerMsg::Ping,
            S_NOTICE => ServerMsg::Notice(text(r.rest(), 4096)?),
            S_PONG => ServerMsg::Pong(r.u64()?),
            S_AUDIO => ServerMsg::Audio { seq: r.u32()?, rate: r.u32()?, channels: r.u8()?, codec: r.u8()?, data: r.rest() },
            S_FILE_BEGIN => ServerMsg::FileBegin { id: r.u32()?, size: file_size(r.u64()?)?, name: file_name(r.rest())? },
            S_FILE_DATA => ServerMsg::FileData { id: r.u32()?, data: chunk(r.rest())? },
            S_FILE_END => ServerMsg::FileEnd { id: r.u32()?, sha256: r.arr32()? },
            S_FILE_RESULT => ServerMsg::FileResult { id: r.u32()?, ok: r.u8()? != 0, message: text(r.rest(), 4096)? },
            S_STATE => ServerMsg::State { key: r.u8()?, value: r.u32()? },
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
            ClientMsg::Hello { downscale: 2, quality: QUALITY_BALANCED as u8, monitor: MONITOR_DEFAULT, flags: HELLO_AUDIO },
            ClientMsg::Ack(7),
            ClientMsg::MouseMove { x: 1919, y: 1079 },
            ClientMsg::MouseButton { button: BTN_X2, down: true },
            ClientMsg::Wheel { delta: -120, horizontal: true },
            ClientMsg::Key { vk: 0x15, scan: 0x72, flags: KEY_UP | KEY_EXTENDED },
            ClientMsg::ReleaseAll,
            ClientMsg::Clipboard("안녕 clipboard".into()),
            ClientMsg::Refresh,
            ClientMsg::Sas,
            ClientMsg::Ping(0x1122334455667788),
            ClientMsg::Set { key: SET_MONITOR, value: 1 },
            ClientMsg::FileBegin { id: 3, size: 1 << 33, name: "보고서 v2.pdf".into() },
            ClientMsg::FileData { id: 3, data: vec![1, 2, 3] },
            ClientMsg::FileEnd { id: 3, sha256: [9; 32] },
            ClientMsg::FilePull,
        ];
        for m in msgs {
            let mut b = Vec::new();
            m.encode(&mut b);
            assert_eq!(ClientMsg::decode(&b).unwrap(), m);
        }
    }

    #[test]
    fn server_roundtrip() {
        let mons = vec![MonitorInfo { left: 0, top: 0, width: 3840, height: 2160 }, MonitorInfo { left: -1920, top: 100, width: 1920, height: 1080 }];
        let msgs = [
            ServerMsg::Hello { width: 2560, height: 1440, flags: F_CLIPBOARD | F_FILES, monitor: 0, monitors: mons, name: "desk".into() },
            ServerMsg::Tiles(&[1, 2, 3]),
            ServerMsg::Cursor(Cursor::IBeam),
            ServerMsg::Clipboard("x".into()),
            ServerMsg::Ping,
            ServerMsg::Notice("bye".into()),
            ServerMsg::Pong(42),
            ServerMsg::Audio { seq: 1, rate: 48000, channels: 2, codec: AUDIO_IMA_ADPCM, data: &[5, 6] },
            ServerMsg::FileBegin { id: 1, size: 10, name: "a.txt".into() },
            ServerMsg::FileData { id: 1, data: &[0; 10] },
            ServerMsg::FileEnd { id: 1, sha256: [1; 32] },
            ServerMsg::FileResult { id: 1, ok: false, message: "disk full".into() },
            ServerMsg::State { key: SET_PRIVACY, value: STATE_UNAVAILABLE },
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
        // Monitor count larger than the payload.
        assert!(ServerMsg::decode(&[S_HELLO, 0, 1, 0, 1, 0, 0, 0, 0, 0, 3]).is_err());
    }

    #[test]
    fn file_names_are_single_components() {
        for bad in ["", ".", "..", "a/b", "a\\b", "C:x", "x\0y", "tab\there", &"x".repeat(256)] {
            assert!(!valid_file_name(bad), "{bad:?} accepted");
            let mut b = Vec::new();
            ClientMsg::FileBegin { id: 1, size: 1, name: bad.to_string() }.encode(&mut b);
            assert!(ClientMsg::decode(&b).is_err());
        }
        assert!(valid_file_name("ok name (1).tar.gz"));
        // Names Windows would store under another name, device names, and spoofing characters.
        let spoofed = [
            "setup.exe.",
            "doc.docm ",
            "evil.exe. . ",
            "CON",
            "nul.txt",
            "Aux.tar.gz",
            "com1",
            "LPT9.log",
            "COM¹.txt",
            "con .txt",
            "CONOUT$",
            "holiday\u{202E}gpj.exe",
            "a\u{2066}b.txt",
            "a\u{200F}.txt",
            "a\u{061C}.txt",
            "\u{FEFF}a.txt",
            "line\u{2028}break.txt",
            "hidden\u{E0041}.txt",
        ];
        for bad in spoofed {
            assert!(!valid_file_name(bad), "{bad:?} accepted");
            let mut b = Vec::new();
            ServerMsg::FileBegin { id: 1, size: 1, name: bad.to_string() }.encode(&mut b);
            assert!(ServerMsg::decode(&b).is_err());
        }
        let persian = "می\u{200C}خواهم.txt";
        for good in [".bashrc", "console.log", "com10.txt", "lpt.txt", "nul_", "x.conf", persian, "a\u{200D}b.png", "보고서 v2.pdf"] {
            assert!(valid_file_name(good), "{good:?} rejected");
        }
        let mut b = Vec::new();
        ClientMsg::FileBegin { id: 1, size: MAX_FILE_SIZE + 1, name: "big".into() }.encode(&mut b);
        assert!(ClientMsg::decode(&b).is_err());
        let mut b = Vec::new();
        ClientMsg::FileData { id: 1, data: vec![] }.encode(&mut b);
        assert!(ClientMsg::decode(&b).is_err());
    }

    #[test]
    fn printable_neutralises_peer_text() {
        assert_eq!(printable("office-pc 보고서"), "office-pc 보고서");
        assert_eq!(printable("\x1b]52;c;aGk=\x07\rconnected to x\nerror: y"), "?]52;c;aGk=??connected to x?error: y");
        assert_eq!(printable("a\u{202E}gpj.exe\u{2028}"), "a?gpj.exe?");
        assert_eq!(printable(&"x".repeat(512)), "x".repeat(512));
        assert_eq!(printable(&"가".repeat(600)), "가".repeat(512) + "…");
    }
}
