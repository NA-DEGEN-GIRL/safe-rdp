//! Minimal X11 client that speaks the wire protocol directly over the display socket.
//!
//! No libX11/xcb: connection setup with MIT-MAGIC-COOKIE-1 from the Xauthority file, the core
//! requests safe-rdp needs, and the BIG-REQUESTS, MIT-SHM, XTEST, RANDR, XINERAMA, XFIXES and
//! XKB extensions. Requests are written straight to the socket; a request with a reply waits
//! for it and queues the events that arrive first. Everything the server sends is
//! length-checked before use.

use crate::proto::Rd;
use crate::util::{Error, Result, SecureVec, wipe};
use crate::{bail, log};
use std::collections::{HashMap, VecDeque};
use std::ffi::{c_int, c_void};
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

// Core requests
const CREATE_WINDOW: u8 = 1;
const CHANGE_WINDOW_ATTRIBUTES: u8 = 2;
const DESTROY_WINDOW: u8 = 4;
const MAP_WINDOW: u8 = 8;
const CONFIGURE_WINDOW: u8 = 12;
const GET_GEOMETRY: u8 = 14;
const INTERN_ATOM: u8 = 16;
const GET_ATOM_NAME: u8 = 17;
const CHANGE_PROPERTY: u8 = 18;
const GET_PROPERTY: u8 = 20;
const SET_SELECTION_OWNER: u8 = 22;
const GET_SELECTION_OWNER: u8 = 23;
const CONVERT_SELECTION: u8 = 24;
const SEND_EVENT: u8 = 25;
const GRAB_KEYBOARD: u8 = 31;
const UNGRAB_KEYBOARD: u8 = 32;
#[cfg(test)]
const QUERY_POINTER: u8 = 38;
#[cfg(test)]
const SET_INPUT_FOCUS: u8 = 42;
const GET_INPUT_FOCUS: u8 = 43;
const OPEN_FONT: u8 = 45;
const CREATE_PIXMAP: u8 = 53;
const FREE_PIXMAP: u8 = 54;
const CREATE_GC: u8 = 55;
const FREE_GC: u8 = 60;
const CLEAR_AREA: u8 = 61;
const POLY_FILL_RECTANGLE: u8 = 70;
const PUT_IMAGE: u8 = 72;
const GET_IMAGE: u8 = 73;
const CREATE_CURSOR: u8 = 93;
const CREATE_GLYPH_CURSOR: u8 = 94;
const QUERY_EXTENSION: u8 = 98;
const GET_KEYBOARD_MAPPING: u8 = 101;

/// Image format for PutImage/GetImage.
pub const Z_PIXMAP: u8 = 2;

// Events
pub const KEY_PRESS: u8 = 2;
pub const KEY_RELEASE: u8 = 3;
pub const BUTTON_PRESS: u8 = 4;
pub const BUTTON_RELEASE: u8 = 5;
pub const MOTION_NOTIFY: u8 = 6;
const FOCUS_IN: u8 = 9;
const FOCUS_OUT: u8 = 10;
const EXPOSE: u8 = 12;
const MAP_NOTIFY: u8 = 19;
const CONFIGURE_NOTIFY: u8 = 22;
const PROPERTY_NOTIFY: u8 = 28;
const SELECTION_CLEAR: u8 = 29;
const SELECTION_REQUEST: u8 = 30;
const SELECTION_NOTIFY: u8 = 31;
const CLIENT_MESSAGE: u8 = 33;
const MAPPING_NOTIFY: u8 = 34;
const GENERIC_EVENT: u8 = 35;

// Event masks
pub const KEY_PRESS_MASK: u32 = 1 << 0;
pub const KEY_RELEASE_MASK: u32 = 1 << 1;
pub const BUTTON_PRESS_MASK: u32 = 1 << 2;
pub const BUTTON_RELEASE_MASK: u32 = 1 << 3;
pub const POINTER_MOTION_MASK: u32 = 1 << 6;
pub const EXPOSURE_MASK: u32 = 1 << 15;
pub const STRUCTURE_NOTIFY_MASK: u32 = 1 << 17;
pub const SUBSTRUCTURE_NOTIFY_MASK: u32 = 1 << 19;
pub const SUBSTRUCTURE_REDIRECT_MASK: u32 = 1 << 20;
pub const FOCUS_CHANGE_MASK: u32 = 1 << 21;
pub const PROPERTY_CHANGE_MASK: u32 = 1 << 22;

// Window attribute value-mask bits (CreateWindow / ChangeWindowAttributes)
pub const CW_BACK_PIXEL: u32 = 1 << 1;
pub const CW_EVENT_MASK: u32 = 1 << 11;
pub const CW_CURSOR: u32 = 1 << 14;

// ConfigureWindow value-mask bits
pub const CONFIG_X: u16 = 1 << 0;
pub const CONFIG_Y: u16 = 1 << 1;
pub const CONFIG_WIDTH: u16 = 1 << 2;
pub const CONFIG_HEIGHT: u16 = 1 << 3;
pub const CONFIG_STACK_MODE: u16 = 1 << 6;

// Predefined atoms
pub const ATOM_ATOM: u32 = 4;
pub const ATOM_STRING: u32 = 31;
pub const ATOM_WINDOW: u32 = 33;
pub const ATOM_WM_NAME: u32 = 39;
pub const ATOM_WM_CLASS: u32 = 67;

pub const CURRENT_TIME: u32 = 0;
pub const NONE: u32 = 0;
/// `GetProperty` type wildcard.
pub const ANY_PROPERTY_TYPE: u32 = 0;
/// `FocusIn`/`FocusOut` modes and details.
pub const NOTIFY_UNGRAB: u8 = 2;
pub const NOTIFY_INFERIOR: u8 = 2;
pub const NOTIFY_POINTER: u8 = 5;

// Xauthority families
pub const FAMILY_INTERNET: u16 = 0;
pub const FAMILY_INTERNET6: u16 = 6;
pub const FAMILY_LOCAL: u16 = 256;
pub const FAMILY_WILD: u16 = 0xffff;
pub const COOKIE_NAME: &[u8] = b"MIT-MAGIC-COOKIE-1";

const IO_TIMEOUT: Duration = Duration::from_secs(15);
/// Upper bound for a reply read into the internal buffer (images are read straight into the
/// caller's buffer instead).
const MAX_REPLY: usize = 64 << 20;

// ---------------------------------------------------------------------------------------------
// Display names and Xauthority

/// A parsed `$DISPLAY`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayName {
    /// Empty for the local socket, else a TCP host name or address.
    pub host: String,
    pub number: u32,
    pub screen: u32,
}

/// Parses `:N`, `:N.S`, `unix:N`, `host:N[.S]`, `[v6addr]:N` and the `tcp/` / `unix/` prefixes.
pub fn parse_display(s: &str) -> Result<DisplayName> {
    let bad = || Error::msg(format!("unsupported DISPLAY value '{s}'"));
    let (proto, rest) = match s.split_once('/') {
        Some((p @ ("tcp" | "unix" | "inet" | "inet6"), r)) => (p, r),
        _ => ("", s),
    };
    let (host, disp) = rest.rsplit_once(':').ok_or_else(bad)?;
    if host.ends_with(':') && !host.starts_with('[') {
        return Err(bad()); // DECnet "host::N"
    }
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    let (num, screen) = disp.split_once('.').unwrap_or((disp, "0"));
    let digits = |t: &str| !t.is_empty() && t.len() <= 5 && t.bytes().all(|c| c.is_ascii_digit());
    if !digits(num) || !digits(screen) {
        return Err(bad());
    }
    let (number, screen): (u32, u32) = (num.parse().map_err(|_| bad())?, screen.parse().map_err(|_| bad())?);
    let host = match (proto, host) {
        ("unix", _) | (_, "unix") | ("", "") => String::new(),
        (_, "") => "localhost".to_string(),
        (_, h) => h.to_string(),
    };
    if !host.is_empty() && number > 65535 - 6000 {
        return Err(bad());
    }
    Ok(DisplayName { host, number, screen })
}

/// One entry of an Xauthority file.
pub struct AuthEntry {
    pub family: u16,
    pub address: Vec<u8>,
    pub number: Vec<u8>,
    pub name: Vec<u8>,
    pub data: Vec<u8>,
}

impl Drop for AuthEntry {
    fn drop(&mut self) {
        wipe(&mut self.data);
    }
}

/// Parses an Xauthority file (big-endian, length-prefixed fields); stops at a truncated entry.
pub fn parse_xauthority(b: &[u8]) -> Vec<AuthEntry> {
    fn field(b: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
        let len = u16::from_be_bytes(b.get(*pos..*pos + 2)?.try_into().ok()?) as usize;
        let v = b.get(*pos + 2..*pos + 2 + len)?.to_vec();
        *pos += 2 + len;
        Some(v)
    }
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < b.len() {
        let entry = (|| {
            let family = u16::from_be_bytes(b.get(pos..pos + 2)?.try_into().ok()?);
            let mut p = pos + 2;
            let address = field(b, &mut p)?;
            let number = field(b, &mut p)?;
            let name = field(b, &mut p)?;
            let data = field(b, &mut p)?;
            Some((AuthEntry { family, address, number, name, data }, p))
        })();
        match entry {
            Some((e, next)) => {
                out.push(e);
                pos = next;
            }
            None => break,
        }
    }
    out
}

/// Serialises one Xauthority entry (fields longer than 65535 bytes are truncated).
pub fn encode_auth_entry(e: &AuthEntry) -> Vec<u8> {
    let mut o = e.family.to_be_bytes().to_vec();
    for f in [&e.address, &e.number, &e.name, &e.data] {
        let n = f.len().min(0xffff);
        o.extend_from_slice(&(n as u16).to_be_bytes());
        o.extend_from_slice(&f[..n]);
    }
    o
}

/// The MIT-MAGIC-COOKIE-1 for display `number` reached as `family`/`address`, by libXau's
/// rules: a wildcard family or an exact address match, and an empty or equal display number.
pub fn find_cookie(entries: &[AuthEntry], family: u16, address: &[u8], number: u32) -> Option<SecureVec> {
    let num = number.to_string();
    entries
        .iter()
        .find(|e| {
            (e.family == FAMILY_WILD || (e.family == family && e.address == address))
                && (e.number.is_empty() || e.number == num.as_bytes())
                && e.name == COOKIE_NAME
        })
        .map(|e| SecureVec(e.data.clone()))
}

/// Which display to talk to and where its cookie lives.
#[derive(Clone, Debug)]
pub struct Target {
    pub display: String,
    /// Xauthority file; `None` means `$XAUTHORITY`, then `~/.Xauthority`.
    pub xauthority: Option<PathBuf>,
}

impl Target {
    /// The display of this process (`$DISPLAY`, `$XAUTHORITY`).
    pub fn from_env() -> Result<Target> {
        let display = std::env::var("DISPLAY")
            .ok()
            .filter(|d| !d.is_empty())
            .ok_or("DISPLAY is not set: run inside an X11 session or start a virtual display")?;
        let xauthority = std::env::var_os("XAUTHORITY").filter(|v| !v.is_empty()).map(PathBuf::from);
        Ok(Target { display, xauthority })
    }

    fn auth_file(&self) -> Option<PathBuf> {
        self.xauthority
            .clone()
            .or_else(|| std::env::var_os("XAUTHORITY").filter(|v| !v.is_empty()).map(PathBuf::from))
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".Xauthority")))
    }
}

// ---------------------------------------------------------------------------------------------
// Connection setup

/// How pixels of one depth are laid out in images.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PixelFormat {
    pub depth: u8,
    pub bpp: u8,
    /// Scanline padding in bits.
    pub pad: u8,
    pub msb_first: bool,
    /// Red, green and blue masks of the visual.
    pub masks: [u32; 3],
}

impl PixelFormat {
    /// True if images are already BGRA/BGRX bytes, the common little-endian TrueColor case.
    pub fn is_bgrx(&self) -> bool {
        self.bpp == 32 && !self.msb_first && self.masks == [0xff0000, 0xff00, 0xff]
    }

    /// Bytes per scanline of a `width`-pixel image.
    pub fn row_bytes(&self, width: usize) -> usize {
        let pad = (self.pad as usize).max(8);
        (width * self.bpp as usize).div_ceil(pad) * pad / 8
    }

    fn supported(&self) -> bool {
        matches!(self.bpp, 16 | 24 | 32) && self.masks.iter().all(|&m| m != 0)
    }

    fn read_pixel(&self, b: &[u8]) -> u32 {
        match (self.bpp, self.msb_first) {
            (32, false) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            (32, true) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            (24, false) => u32::from_le_bytes([b[0], b[1], b[2], 0]),
            (24, true) => u32::from_be_bytes([0, b[0], b[1], b[2]]),
            (_, false) => u16::from_le_bytes([b[0], b[1]]) as u32,
            (_, true) => u16::from_be_bytes([b[0], b[1]]) as u32,
        }
    }

    fn write_pixel(&self, v: u32, b: &mut [u8]) {
        match (self.bpp, self.msb_first) {
            (32, false) => b[..4].copy_from_slice(&v.to_le_bytes()),
            (32, true) => b[..4].copy_from_slice(&v.to_be_bytes()),
            (24, false) => b[..3].copy_from_slice(&v.to_le_bytes()[..3]),
            (24, true) => b[..3].copy_from_slice(&v.to_be_bytes()[1..]),
            (_, false) => b[..2].copy_from_slice(&(v as u16).to_le_bytes()),
            (_, true) => b[..2].copy_from_slice(&(v as u16).to_be_bytes()),
        }
    }

    /// Converts a ZPixmap image (`row_bytes(w)` per row) into BGRA, `w*h*4` bytes.
    pub fn to_bgra(&self, src: &[u8], w: usize, h: usize, dst: &mut [u8]) {
        let (stride, step) = (self.row_bytes(w), self.bpp as usize / 8);
        let ch = self.masks.map(Channel::new);
        for y in 0..h {
            let row = &src[y * stride..y * stride + w * step];
            let out = &mut dst[y * w * 4..(y + 1) * w * 4];
            for (px, o) in row.chunks_exact(step).zip(out.chunks_exact_mut(4)) {
                let v = self.read_pixel(px);
                o.copy_from_slice(&[ch[2].get(v), ch[1].get(v), ch[0].get(v), 255]);
            }
        }
    }

    /// Converts `w` BGRA pixels into one ZPixmap row of this format.
    pub fn from_bgra_row(&self, src: &[u8], dst: &mut [u8]) {
        let step = self.bpp as usize / 8;
        let ch = self.masks.map(Channel::new);
        for (px, o) in src.chunks_exact(4).zip(dst.chunks_exact_mut(step)) {
            let v = ch[0].put(px[2]) | ch[1].put(px[1]) | ch[2].put(px[0]);
            self.write_pixel(v, o);
        }
    }
}

/// One colour channel of a TrueColor visual: where its bits sit and how many there are.
#[derive(Clone, Copy)]
struct Channel {
    shift: u32,
    bits: u32,
}

impl Channel {
    fn new(mask: u32) -> Channel {
        let shift = mask.trailing_zeros().min(31);
        Channel { shift, bits: (mask >> shift).count_ones().clamp(1, 16) }
    }

    fn get(&self, v: u32) -> u8 {
        let x = (v >> self.shift) & ((1u32 << self.bits) - 1);
        if self.bits >= 8 {
            (x >> (self.bits - 8)) as u8
        } else {
            // Replicate the high bits so that full intensity maps to 255.
            let mut out = 0u32;
            let mut have = 0;
            while have < 8 {
                out = (out << self.bits) | x;
                have += self.bits;
            }
            (out >> (have - 8)) as u8
        }
    }

    fn put(&self, c: u8) -> u32 {
        let x = if self.bits >= 8 { (c as u32) << (self.bits - 8) } else { c as u32 >> (8 - self.bits) };
        x << self.shift
    }
}

/// The parts of the connection setup reply safe-rdp uses (for the chosen screen).
#[derive(Clone, Debug)]
pub struct Setup {
    pub id_base: u32,
    pub id_mask: u32,
    /// In 4-byte units.
    pub max_request: u16,
    pub min_keycode: u8,
    pub max_keycode: u8,
    pub root: u32,
    pub black: u32,
    pub format: PixelFormat,
}

/// Parses a successful setup reply (the whole message, header included).
pub fn parse_setup(b: &[u8], screen: u32) -> Result<Setup> {
    let mut r = Rd(b);
    r.bytes(8)?; // status, unused, protocol version, length
    let _release = r.u32()?;
    let id_base = r.u32()?;
    let id_mask = r.u32()?;
    let _motion = r.u32()?;
    let vendor_len = r.u16()? as usize;
    let max_request = r.u16()?;
    let nscreens = r.u8()? as u32;
    let nformats = r.u8()? as usize;
    let image_order = r.u8()?;
    r.bytes(3)?; // bitmap bit order, scanline unit, scanline pad
    let min_keycode = r.u8()?;
    let max_keycode = r.u8()?;
    r.bytes(4)?;
    r.bytes(vendor_len.div_ceil(4) * 4)?;
    let mut formats = Vec::with_capacity(nformats);
    for _ in 0..nformats {
        let f = r.bytes(8)?;
        formats.push((f[0], f[1], f[2]));
    }
    if id_mask == 0 {
        bail!("X server sent an empty resource id mask");
    }
    if screen >= nscreens {
        bail!("X screen {screen} does not exist");
    }
    for i in 0..nscreens {
        let root = r.u32()?;
        let _colormap = r.u32()?;
        let _white = r.u32()?;
        let black = r.u32()?;
        let _input_masks = r.u32()?;
        r.bytes(4)?; // width, height in pixels
        r.bytes(8)?; // size in mm, installed maps
        let root_visual = r.u32()?;
        r.bytes(2)?; // backing stores, save-unders
        let root_depth = r.u8()?;
        let ndepths = r.u8()?;
        let mut masks = None;
        for _ in 0..ndepths {
            let depth = r.u8()?;
            r.u8()?;
            let nvisuals = r.u16()?;
            r.bytes(4)?;
            for _ in 0..nvisuals {
                let id = r.u32()?;
                let class = r.u8()?;
                r.bytes(3)?; // bits per rgb, colormap entries
                let m = [r.u32()?, r.u32()?, r.u32()?];
                r.bytes(4)?;
                // TrueColor (4) or DirectColor (5) at the root depth.
                if id == root_visual && depth == root_depth && (class == 4 || class == 5) {
                    masks = Some(m);
                }
            }
        }
        if i != screen {
            continue;
        }
        let masks = masks.ok_or("the X screen does not use a TrueColor visual")?;
        let &(_, bpp, pad) = formats.iter().find(|f| f.0 == root_depth).ok_or("no pixmap format for the root depth")?;
        let format = PixelFormat { depth: root_depth, bpp, pad, msb_first: image_order == 1, masks };
        if !format.supported() {
            bail!("unsupported X pixel format ({root_depth}-bit depth, {bpp} bits per pixel)");
        }
        return Ok(Setup { id_base, id_mask, max_request, min_keycode, max_keycode, root, black, format });
    }
    unreachable!("screen index checked above")
}

// ---------------------------------------------------------------------------------------------
// Requests, replies, events and errors

/// A request under construction: opcode, data byte, length placeholder, then the fields.
pub struct Req(Vec<u8>);

impl Req {
    pub fn new(opcode: u8, data: u8) -> Req {
        Req(vec![opcode, data, 0, 0])
    }
    pub fn u8(mut self, v: u8) -> Req {
        self.0.push(v);
        self
    }
    pub fn u16(mut self, v: u16) -> Req {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn i16(self, v: i16) -> Req {
        self.u16(v as u16)
    }
    pub fn u32(mut self, v: u32) -> Req {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn pad(mut self, n: usize) -> Req {
        self.0.resize(self.0.len() + n, 0);
        self
    }
    /// Appends bytes and pads to a 4-byte boundary.
    pub fn bytes(mut self, b: &[u8]) -> Req {
        self.0.extend_from_slice(b);
        self.0.resize(self.0.len().div_ceil(4) * 4, 0);
        self
    }

    /// Final wire bytes for a request whose total size (with `body` bytes appended after
    /// these, padded) is `len` units: plain 16-bit length or the BIG-REQUESTS form.
    fn finish(mut self, body: usize, big: bool) -> Result<Vec<u8>> {
        debug_assert!(self.0.len() % 4 == 0, "request header must be 4-byte aligned");
        let units = (self.0.len() + body.div_ceil(4) * 4) / 4;
        if units <= 0xffff {
            self.0[2..4].copy_from_slice(&(units as u16).to_le_bytes());
        } else if big {
            let total = u32::try_from(units + 1).map_err(|_| "X request too large")?;
            self.0.splice(4..4, total.to_le_bytes());
        } else {
            bail!("X request too large");
        }
        Ok(self.0)
    }
}

/// An X protocol error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XError {
    pub code: u8,
    pub seq: u64,
    pub value: u32,
    pub major: u8,
    pub minor: u16,
}

impl fmt::Display for XError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [&str; 18] = [
            "", "Request", "Value", "Window", "Pixmap", "Atom", "Cursor", "Font", "Match", "Drawable", "Access", "Alloc", "Colormap",
            "GContext", "IDChoice", "Name", "Length", "Implementation",
        ];
        let name = NAMES.get(self.code as usize).copied().filter(|n| !n.is_empty()).unwrap_or("extension");
        write!(f, "X error {name} ({}) in request {}.{}", self.code, self.major, self.minor)
    }
}

impl From<XError> for Error {
    fn from(e: XError) -> Self {
        Error::msg(e.to_string())
    }
}

/// The events safe-rdp handles; anything else (extension events included) is `Other`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Event {
    Key { press: bool, keycode: u8, time: u32, state: u16 },
    Button { press: bool, button: u8, x: i16, y: i16 },
    Motion { x: i16, y: i16 },
    Focus { focus_in: bool, detail: u8, mode: u8 },
    Expose { x: u16, y: u16, width: u16, height: u16, count: u16 },
    Configure { window: u32, width: u16, height: u16 },
    Map { window: u32 },
    Property { window: u32, atom: u32, time: u32, deleted: bool },
    SelectionClear { selection: u32, time: u32 },
    SelectionRequest { time: u32, requestor: u32, selection: u32, target: u32, property: u32 },
    SelectionNotify { time: u32, requestor: u32, selection: u32, target: u32, property: u32 },
    ClientMessage { window: u32, kind: u32, format: u8, data: [u8; 20] },
    Mapping { request: u8, first: u8, count: u8 },
    Other([u8; 32]),
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

impl Event {
    pub fn parse(b: &[u8; 32]) -> Event {
        let (u16_, u32_) = (|o| le16(b, o), |o| le32(b, o));
        match b[0] & 0x7f {
            c @ (KEY_PRESS | KEY_RELEASE) => Event::Key { press: c == KEY_PRESS, keycode: b[1], time: u32_(4), state: u16_(28) },
            c @ (BUTTON_PRESS | BUTTON_RELEASE) => {
                Event::Button { press: c == BUTTON_PRESS, button: b[1], x: u16_(24) as i16, y: u16_(26) as i16 }
            }
            MOTION_NOTIFY => Event::Motion { x: u16_(24) as i16, y: u16_(26) as i16 },
            c @ (FOCUS_IN | FOCUS_OUT) => Event::Focus { focus_in: c == FOCUS_IN, detail: b[1], mode: b[8] },
            EXPOSE => Event::Expose { x: u16_(8), y: u16_(10), width: u16_(12), height: u16_(14), count: u16_(16) },
            CONFIGURE_NOTIFY => Event::Configure { window: u32_(8), width: u16_(20), height: u16_(22) },
            MAP_NOTIFY => Event::Map { window: u32_(8) },
            PROPERTY_NOTIFY => Event::Property { window: u32_(4), atom: u32_(8), time: u32_(12), deleted: b[16] == 1 },
            SELECTION_CLEAR => Event::SelectionClear { time: u32_(4), selection: u32_(12) },
            SELECTION_REQUEST => Event::SelectionRequest {
                time: u32_(4),
                requestor: u32_(12),
                selection: u32_(16),
                target: u32_(20),
                property: u32_(24),
            },
            SELECTION_NOTIFY => Event::SelectionNotify {
                time: u32_(4),
                requestor: u32_(8),
                selection: u32_(12),
                target: u32_(16),
                property: u32_(20),
            },
            CLIENT_MESSAGE => {
                Event::ClientMessage { window: u32_(4), kind: u32_(8), format: b[1], data: b[12..32].try_into().unwrap() }
            }
            MAPPING_NOTIFY => Event::Mapping { request: b[4], first: b[5], count: b[6] },
            _ => Event::Other(*b),
        }
    }
}

enum Packet {
    Reply(u64, Vec<u8>),
    Error(XError),
    Event([u8; 32]),
}

/// Size of the complete packet at the start of `b`, once its header has arrived.
fn packet_len(b: &[u8]) -> Option<usize> {
    if b.len() < 32 {
        return None;
    }
    Some(match b[0] {
        1 | GENERIC_EVENT => 32 + 4 * le32(b, 4) as usize,
        _ => 32,
    })
}

/// A negotiated extension.
#[derive(Clone, Copy, Debug)]
pub struct Ext {
    pub opcode: u8,
    pub first_event: u8,
}

enum Sock {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Sock {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Sock::Unix(s) => s.read(b),
            Sock::Tcp(s) => s.read(b),
        }
    }

    fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
        match self {
            Sock::Unix(s) => s.write_all(b),
            Sock::Tcp(s) => s.write_all(b),
        }
    }

    fn fd(&self) -> RawFd {
        match self {
            Sock::Unix(s) => s.as_raw_fd(),
            Sock::Tcp(s) => s.as_raw_fd(),
        }
    }

    fn set_timeouts(&self, t: Option<Duration>) -> std::io::Result<()> {
        match self {
            Sock::Unix(s) => s.set_read_timeout(t).and_then(|_| s.set_write_timeout(t)),
            Sock::Tcp(s) => s.set_read_timeout(t).and_then(|_| s.set_write_timeout(t)),
        }
    }
}

/// Geometry of a drawable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub root: u32,
    pub depth: u8,
    pub x: i16,
    pub y: i16,
    pub width: u16,
    pub height: u16,
}

/// Pointer position from `QueryPointer`.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pointer {
    pub root_x: i16,
    pub root_y: i16,
    pub win_x: i16,
    pub win_y: i16,
    pub mask: u16,
}

/// A property value from `GetProperty`.
pub struct Property {
    pub kind: u32,
    pub bytes_after: u32,
    pub value: Vec<u8>,
}

/// One monitor from RANDR or XINERAMA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Monitor {
    pub x: i16,
    pub y: i16,
    pub width: u16,
    pub height: u16,
    pub primary: bool,
}

/// A connection to an X server.
pub struct Conn {
    sock: Sock,
    local: bool,
    pub setup: Setup,
    /// Sequence number of the last request written (full width; the wire carries 16 bits).
    seq: u64,
    rbuf: Vec<u8>,
    rpos: usize,
    events: VecDeque<[u8; 32]>,
    errors: Vec<XError>,
    /// Largest request in bytes.
    max_request: usize,
    big: bool,
    next_id: u32,
    /// Extensions looked up so far (`None`: absent or too old).
    exts: HashMap<&'static str, Option<Ext>>,
    atoms: HashMap<String, u32>,
}

fn io_error(e: std::io::Error) -> Error {
    match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => Error::msg("X server is not responding"),
        _ => Error::msg(format!("X connection failed: {e}")),
    }
}

/// Where local displays keep their socket files.
pub const SOCKET_DIR: &str = "/tmp/.X11-unix";

/// The socket file of local display `number`. Servers also listen on the same name in the
/// abstract namespace, which libxcb clients try first.
pub fn local_socket_path(number: u32) -> String {
    format!("{SOCKET_DIR}/X{number}")
}

/// Process id of the only X server this process may talk to (0: any server run by root or by
/// this user). Set for a virtual display, so a server another local user starts on its socket
/// names after it dies never sees our cookie, keystrokes or screen requests.
static PINNED_SERVER: AtomicU32 = AtomicU32::new(0);
/// `PINNED_SERVER` once the pinned server is being stopped: no server is trusted any more.
const RETIRED: u32 = u32::MAX;

/// From now on every connection of this process must reach X server process `pid`, whichever
/// socket name it goes through. Set once; it never reverts to trusting other servers.
pub fn pin_server(pid: u32) -> Result<()> {
    match PINNED_SERVER.compare_exchange(0, pid, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => Ok(()),
        Err(_) => bail!("this process already uses another X server"),
    }
}

/// Called before pinned server `pid` is stopped (and its pid can be reused): later connections
/// fail instead of reaching whoever gets that pid next.
pub fn retire_server(pid: u32) {
    let _ = PINNED_SERVER.compare_exchange(pid, RETIRED, Ordering::SeqCst, Ordering::SeqCst);
}

fn pinned_server() -> Option<u32> {
    Some(PINNED_SERVER.load(Ordering::SeqCst)).filter(|&p| p != 0)
}

const SOL_SOCKET: c_int = 1;
const SO_PEERCRED: c_int = 17;

#[repr(C)]
#[derive(Clone, Copy)]
struct Ucred {
    pid: i32,
    uid: u32,
    gid: u32,
}

/// Who is at the other end of a connected Unix socket (for a server, the process that called
/// `listen`).
fn peer_cred(s: &UnixStream) -> Result<Ucred> {
    let mut cred = Ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<Ucred>() as u32;
    let r = unsafe { getsockopt(s.as_raw_fd(), SOL_SOCKET, SO_PEERCRED, (&mut cred as *mut Ucred).cast(), &mut len) };
    if r != 0 || len as usize != std::mem::size_of::<Ucred>() || cred.pid <= 0 {
        bail!("cannot tell which process serves an X socket: {}", std::io::Error::last_os_error());
    }
    Ok(cred)
}

fn connect_unix(addr: &std::os::unix::net::SocketAddr) -> std::io::Result<UnixStream> {
    loop {
        match UnixStream::connect_addr(addr) {
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            r => return r,
        }
    }
}

/// Connects to `addr` and checks that process `pid` is the one listening there. Nothing is sent.
fn connect_checked(addr: &std::os::unix::net::SocketAddr, pid: u32, what: &str) -> Result<UnixStream> {
    let s = connect_unix(addr).map_err(|e| format!("cannot connect to {what}: {e}"))?;
    let peer = peer_cred(&s)?.pid;
    if peer as u32 != pid {
        bail!("{what} is served by another process (pid {peer})");
    }
    Ok(s)
}

/// Connects to local display `number` through its socket file, else its abstract name, and
/// checks who serves it before anything is sent: X server process `pinned` when given, else a
/// server run by root or by `euid`. A server failing the check is never passed over for the
/// other name.
fn connect_local(number: u32, pinned: Option<u32>, euid: u32) -> Result<UnixStream> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr;
    if pinned == Some(RETIRED) {
        bail!("the virtual display has stopped");
    }
    let path = local_socket_path(number);
    let mut failed = None;
    for addr in [SocketAddr::from_pathname(&path)?, SocketAddr::from_abstract_name(path.as_bytes())?] {
        let s = match connect_unix(&addr) {
            Ok(s) => s,
            Err(e) => {
                failed.get_or_insert(e);
                continue;
            }
        };
        let peer = peer_cred(&s)?;
        match pinned {
            Some(pid) if peer.pid as u32 != pid => {
                bail!("X display :{number} is served by another process (pid {}) than its virtual display", peer.pid)
            }
            None if peer.uid != 0 && peer.uid != euid => bail!("X display :{number} is served by another user (uid {})", peer.uid),
            _ => return Ok(s),
        }
    }
    let why = failed.map(|e| e.to_string()).unwrap_or_default();
    bail!("cannot connect to X display :{number}: {why}")
}

fn connect_socket(name: &DisplayName, pinned: Option<u32>) -> Result<(Sock, u16, Vec<u8>)> {
    if name.host.is_empty() {
        let sock = connect_local(name.number, pinned, unsafe { geteuid() })?;
        return Ok((Sock::Unix(sock), FAMILY_LOCAL, super::hostname().into_bytes()));
    }
    if pinned.is_some() {
        bail!("only the virtual display can be used, not {}:{}", name.host, name.number);
    }
    let port = 6000 + name.number as u16;
    let addrs: Vec<_> = (name.host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve X server {}: {e}", name.host))?
        .collect();
    let mut last = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, Duration::from_secs(5)) {
            Ok(s) => {
                s.set_nodelay(true)?;
                let ip = a.ip();
                if ip.is_loopback() {
                    return Ok((Sock::Tcp(s), FAMILY_LOCAL, super::hostname().into_bytes()));
                }
                log!("warning: X11 traffic to {} is not encrypted", name.host);
                let (family, address) = match ip {
                    std::net::IpAddr::V4(v4) => (FAMILY_INTERNET, v4.octets().to_vec()),
                    std::net::IpAddr::V6(v6) => (FAMILY_INTERNET6, v6.octets().to_vec()),
                };
                return Ok((Sock::Tcp(s), family, address));
            }
            Err(e) => last = Some(e),
        }
    }
    let why = last.map(|e| e.to_string()).unwrap_or_else(|| "no address".into());
    bail!("cannot connect to X server {}:{}: {why}", name.host, name.number)
}

impl Conn {
    /// Connects to `target`, authenticating with its MIT-MAGIC-COOKIE-1 when there is one.
    pub fn connect(target: &Target) -> Result<Conn> {
        let name = parse_display(&target.display)?;
        let (sock, family, address) = connect_socket(&name, pinned_server())?;
        Conn::handshake(sock, family, &address, &name, target)
    }

    /// Like `connect`, for a local display that process `pid` must be serving: both of its
    /// socket names (the file and the abstract twin) must belong to `pid`, or nothing, the
    /// cookie included, is sent. The file is used, never the abstract name as a fallback.
    pub fn connect_to_server(target: &Target, pid: u32) -> Result<Conn> {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::SocketAddr;
        let name = parse_display(&target.display)?;
        if !name.host.is_empty() {
            bail!("{} is not a local display", target.display);
        }
        let path = local_socket_path(name.number);
        let n = name.number;
        drop(connect_checked(&SocketAddr::from_abstract_name(path.as_bytes())?, pid, &format!("the abstract socket of display :{n}"))?);
        let sock = connect_checked(&SocketAddr::from_pathname(&path)?, pid, &format!("the socket file of display :{n}"))?;
        Conn::handshake(Sock::Unix(sock), FAMILY_LOCAL, super::hostname().as_bytes(), &name, target)
    }

    fn handshake(mut sock: Sock, family: u16, address: &[u8], name: &DisplayName, target: &Target) -> Result<Conn> {
        sock.set_timeouts(Some(IO_TIMEOUT))?;
        let cookie = target.auth_file().and_then(|p| std::fs::read(p).ok()).and_then(|mut raw| {
            let entries = parse_xauthority(&raw);
            wipe(&mut raw);
            find_cookie(&entries, family, address, name.number)
        });

        let (auth_name, auth_data): (&[u8], &[u8]) = match &cookie {
            Some(c) => (COOKIE_NAME, &c.0),
            None => (b"", b""),
        };
        let mut hello = vec![b'l', 0];
        hello.extend_from_slice(&11u16.to_le_bytes());
        hello.extend_from_slice(&0u16.to_le_bytes());
        hello.extend_from_slice(&(auth_name.len() as u16).to_le_bytes());
        hello.extend_from_slice(&(auth_data.len() as u16).to_le_bytes());
        hello.extend_from_slice(&[0, 0]);
        for part in [auth_name, auth_data] {
            hello.extend_from_slice(part);
            hello.resize(hello.len().div_ceil(4) * 4, 0);
        }
        let sent = sock.write_all(&hello).map_err(io_error);
        wipe(&mut hello);
        drop(cookie);
        sent?;

        let mut head = [0u8; 8];
        read_exact(&mut sock, &mut head)?;
        let extra = le16(&head, 6) as usize * 4;
        let mut reply = head.to_vec();
        reply.resize(8 + extra, 0);
        read_exact(&mut sock, &mut reply[8..])?;
        match head[0] {
            1 => {}
            0 => {
                let n = (head[1] as usize).min(extra);
                bail!("X server refused the connection: {}", String::from_utf8_lossy(&reply[8..8 + n]).trim());
            }
            _ => bail!("X server requires further authentication: {}", String::from_utf8_lossy(&reply[8..]).trim_end_matches('\0').trim()),
        }
        let setup = parse_setup(&reply, name.screen)?;
        let mut c = Conn {
            local: matches!(sock, Sock::Unix(_)),
            sock,
            max_request: setup.max_request as usize * 4,
            setup,
            seq: 0,
            rbuf: Vec::new(),
            rpos: 0,
            events: VecDeque::new(),
            errors: Vec::new(),
            big: false,
            next_id: 0,
            exts: HashMap::new(),
            atoms: HashMap::new(),
        };
        c.enable_big_requests()?;
        Ok(c)
    }

    /// The socket, for `poll`.
    pub fn fd(&self) -> RawFd {
        self.sock.fd()
    }

    pub fn root(&self) -> u32 {
        self.setup.root
    }

    /// Largest request the server accepts, in bytes.
    pub fn max_request_bytes(&self) -> usize {
        self.max_request
    }

    /// A fresh resource id.
    pub fn new_id(&mut self) -> Result<u32> {
        let shift = self.setup.id_mask.trailing_zeros();
        if self.next_id >= self.setup.id_mask >> shift {
            bail!("out of X resource ids");
        }
        self.next_id += 1;
        Ok(self.setup.id_base | (self.next_id << shift))
    }

    // --- writing

    /// Sends a request; returns its sequence number.
    pub fn send(&mut self, req: Req) -> Result<u64> {
        self.send_with(req, &[])
    }

    /// Sends a request followed by `body` (padded to 4 bytes) without copying the body.
    pub fn send_with(&mut self, req: Req, body: &[u8]) -> Result<u64> {
        let mut head = req.finish(body.len(), self.big)?;
        let total = head.len() + body.len().div_ceil(4) * 4;
        if total > self.max_request {
            bail!("X request of {total} bytes exceeds the server limit");
        }
        if body.is_empty() {
            self.sock.write_all(&head).map_err(io_error)?;
        } else if body.len() <= 4096 {
            head.extend_from_slice(body);
            head.resize(total, 0);
            let r = self.sock.write_all(&head);
            wipe(&mut head);
            r.map_err(io_error)?;
        } else {
            self.sock.write_all(&head).map_err(io_error)?;
            self.sock.write_all(body).map_err(io_error)?;
            let pad = total - head.len() - body.len();
            if pad > 0 {
                self.sock.write_all(&[0u8; 3][..pad]).map_err(io_error)?;
            }
        }
        self.seq += 1;
        Ok(self.seq)
    }

    // --- reading

    fn avail(&self) -> &[u8] {
        &self.rbuf[self.rpos..]
    }

    fn consume(&mut self, n: usize) {
        self.rpos += n;
        if self.rpos == self.rbuf.len() {
            self.rbuf.clear();
            self.rpos = 0;
        }
    }

    /// Reads more from the socket (blocking up to the I/O timeout).
    fn fill(&mut self) -> Result<()> {
        if self.rpos > 0 {
            self.rbuf.drain(..self.rpos);
            self.rpos = 0;
        }
        let old = self.rbuf.len();
        self.rbuf.resize(old + 65536, 0);
        let n = match self.sock.read(&mut self.rbuf[old..]) {
            Ok(0) => {
                self.rbuf.truncate(old);
                bail!("the X server closed the connection");
            }
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => 0,
            Err(e) => {
                self.rbuf.truncate(old);
                return Err(io_error(e));
            }
        };
        self.rbuf.truncate(old + n);
        Ok(())
    }

    /// Widens a 16-bit sequence number from the server to the full counter.
    fn widen(&self, s: u16) -> u64 {
        self.seq.saturating_sub((self.seq as u16).wrapping_sub(s) as u64)
    }

    fn next_packet(&mut self, block: bool) -> Result<Option<Packet>> {
        loop {
            if let Some(n) = packet_len(self.avail()) {
                if n > MAX_REPLY {
                    bail!("X server sent an oversized reply");
                }
                if self.avail().len() >= n {
                    let b = &self.rbuf[self.rpos..self.rpos + n];
                    let p = match b[0] {
                        0 => Some(Packet::Error(XError {
                            code: b[1],
                            seq: self.widen(le16(b, 2)),
                            value: le32(b, 4),
                            minor: le16(b, 8),
                            major: b[10],
                        })),
                        1 => Some(Packet::Reply(self.widen(le16(b, 2)), b.to_vec())),
                        GENERIC_EVENT => None, // never selected
                        _ => Some(Packet::Event(b[..32].try_into().unwrap())),
                    };
                    if matches!(p, Some(Packet::Reply(..))) {
                        // Replies may carry clipboard text; do not leave copies behind.
                        wipe(&mut self.rbuf[self.rpos..self.rpos + n]);
                    }
                    self.consume(n);
                    match p {
                        Some(p) => return Ok(Some(p)),
                        None => continue,
                    }
                }
            }
            if !block {
                return Ok(None);
            }
            self.fill()?;
        }
    }

    /// Queues an event or remembers an error for a request whose reply nobody waits for.
    fn stash(&mut self, p: Packet) {
        match p {
            Packet::Event(e) => self.events.push_back(e),
            Packet::Error(e) => {
                if self.errors.len() >= 32 {
                    self.errors.remove(0);
                }
                self.errors.push(e);
            }
            Packet::Reply(..) => {} // late reply to an abandoned request
        }
    }

    /// Waits for the reply to request `seq`.
    pub fn reply(&mut self, seq: u64) -> Result<Vec<u8>> {
        loop {
            match self.next_packet(true)? {
                Some(Packet::Reply(s, b)) if s == seq => return Ok(b),
                Some(Packet::Error(e)) if e.seq == seq => return Err(e.into()),
                Some(p) => self.stash(p),
                None => {}
            }
        }
    }

    /// Waits for the reply to `seq` and reads its body (after the 32-byte header) straight into
    /// `sink`, which must be at least as large. Returns the header and the body length.
    pub fn reply_into(&mut self, seq: u64, sink: &mut [u8]) -> Result<([u8; 32], usize)> {
        loop {
            while self.avail().len() < 32 {
                self.fill()?;
            }
            let head: [u8; 32] = self.avail()[..32].try_into().unwrap();
            if head[0] == 1 && self.widen(le16(&head, 2)) == seq {
                let body = 4 * le32(&head, 4) as usize;
                self.consume(32);
                if body > sink.len() {
                    self.skip(body)?;
                    bail!("X reply larger than expected");
                }
                self.read_into(&mut sink[..body])?;
                return Ok((head, body));
            }
            match self.next_packet(true)? {
                Some(Packet::Error(e)) if e.seq == seq => return Err(e.into()),
                Some(p) => self.stash(p),
                None => {}
            }
        }
    }

    /// Reads exactly `out.len()` bytes: buffered ones first (wiped from the buffer), then the socket.
    fn read_into(&mut self, out: &mut [u8]) -> Result<()> {
        let n = self.avail().len().min(out.len());
        out[..n].copy_from_slice(&self.rbuf[self.rpos..self.rpos + n]);
        wipe(&mut self.rbuf[self.rpos..self.rpos + n]);
        self.consume(n);
        read_exact(&mut self.sock, &mut out[n..])
    }

    fn skip(&mut self, mut n: usize) -> Result<()> {
        let mut scratch = vec![0u8; 65536];
        while n > 0 {
            let k = n.min(scratch.len());
            self.read_into(&mut scratch[..k])?;
            n -= k;
        }
        wipe(&mut scratch);
        Ok(())
    }

    /// A round trip: afterwards every earlier request has been processed. Fails with the first
    /// error caused by a request sent at or after `since`.
    pub fn sync_since(&mut self, since: u64) -> Result<()> {
        let seq = self.send(Req::new(GET_INPUT_FOCUS, 0))?;
        self.reply(seq)?;
        let first = self.errors.iter().find(|e| e.seq >= since && e.seq <= seq).copied();
        self.errors.retain(|e| e.seq > seq);
        match first {
            Some(e) => Err(e.into()),
            None => Ok(()),
        }
    }

    /// A round trip, ignoring errors from earlier requests.
    pub fn sync(&mut self) -> Result<()> {
        self.sync_since(u64::MAX).map(|_| ())
    }

    /// The next event already received, without blocking.
    pub fn poll_event(&mut self) -> Result<Option<Event>> {
        loop {
            if let Some(e) = self.events.pop_front() {
                return Ok(Some(Event::parse(&e)));
            }
            match self.next_packet(false)? {
                Some(p) => self.stash(p),
                None => return Ok(None),
            }
        }
    }

    /// True if an event is queued or already in the read buffer.
    pub fn has_buffered_event(&self) -> bool {
        !self.events.is_empty() || packet_len(self.avail()).is_some_and(|n| self.avail().len() >= n)
    }

    /// Reads whatever the server has sent; call when `poll` reports the socket readable.
    pub fn read_input(&mut self) -> Result<()> {
        self.fill()
    }

    /// Reads input that is already waiting on the socket, without blocking.
    pub fn read_pending(&mut self) -> Result<()> {
        if wait_readable(&[self.fd()], 0)?[0] {
            self.fill()?;
        }
        Ok(())
    }

    /// Waits up to `timeout` for the next event.
    #[cfg(test)]
    pub fn wait_event(&mut self, timeout: Duration) -> Result<Option<Event>> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(e) = self.poll_event()? {
                return Ok(Some(e));
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            if wait_readable(&[self.fd()], left.as_millis().min(i32::MAX as u128) as i32)?[0] {
                self.fill()?;
            }
        }
    }

    // --- core requests

    pub fn intern_atom(&mut self, name: &str, only_if_exists: bool) -> Result<u32> {
        if let Some(&a) = self.atoms.get(name) {
            return Ok(a);
        }
        let seq = self.send(Req::new(INTERN_ATOM, only_if_exists as u8).u16(name.len() as u16).pad(2).bytes(name.as_bytes()))?;
        let r = self.reply(seq)?;
        let a = le32(&r, 8);
        if a != NONE {
            self.atoms.insert(name.to_string(), a);
        }
        Ok(a)
    }

    /// `intern_atom` that creates the atom if needed.
    pub fn atom(&mut self, name: &str) -> Result<u32> {
        self.intern_atom(name, false)
    }

    pub fn atom_name(&mut self, atom: u32) -> Result<String> {
        let seq = self.send(Req::new(GET_ATOM_NAME, 0).u32(atom))?;
        let r = self.reply(seq)?;
        let n = le16(&r, 8) as usize;
        let name = r.get(32..32 + n).ok_or("truncated GetAtomName reply")?;
        Ok(String::from_utf8_lossy(name).into_owned())
    }

    /// Looks an extension up (cached; `None` if the server lacks it).
    fn query_extension(&mut self, name: &str) -> Result<Option<Ext>> {
        let seq = self.send(Req::new(QUERY_EXTENSION, 0).u16(name.len() as u16).pad(2).bytes(name.as_bytes()))?;
        let r = self.reply(seq)?;
        Ok((r[8] != 0).then(|| Ext { opcode: r[9], first_event: r[10] }))
    }

    fn enable_big_requests(&mut self) -> Result<()> {
        if let Some(ext) = self.query_extension("BIG-REQUESTS")? {
            let seq = self.send(Req::new(ext.opcode, 0))?;
            let r = self.reply(seq)?;
            let max = le32(&r, 8) as usize;
            if max > self.max_request / 4 {
                self.max_request = max.saturating_mul(4).min(1 << 30);
                self.big = true;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_window(&mut self, parent: u32, x: i16, y: i16, w: u16, h: u16, class: u16, mask: u32, values: &[u32]) -> Result<u32> {
        let id = self.new_id()?;
        // Depth and visual copied from the parent, no border.
        let mut req = Req::new(CREATE_WINDOW, 0).u32(id).u32(parent).i16(x).i16(y).u16(w.max(1)).u16(h.max(1));
        req = req.u16(0).u16(class).u32(0).u32(mask);
        for &v in values {
            req = req.u32(v);
        }
        self.send(req)?;
        Ok(id)
    }

    pub fn change_window_attributes(&mut self, window: u32, mask: u32, values: &[u32]) -> Result<()> {
        let mut req = Req::new(CHANGE_WINDOW_ATTRIBUTES, 0).u32(window).u32(mask);
        for &v in values {
            req = req.u32(v);
        }
        self.send(req).map(|_| ())
    }

    pub fn destroy_window(&mut self, window: u32) -> Result<()> {
        self.send(Req::new(DESTROY_WINDOW, 0).u32(window)).map(|_| ())
    }

    pub fn map_window(&mut self, window: u32) -> Result<()> {
        self.send(Req::new(MAP_WINDOW, 0).u32(window)).map(|_| ())
    }

    /// `values` in mask-bit order, each sent as 32 bits.
    pub fn configure_window(&mut self, window: u32, mask: u16, values: &[u32]) -> Result<()> {
        let mut req = Req::new(CONFIGURE_WINDOW, 0).u32(window).u16(mask).pad(2);
        for &v in values {
            req = req.u32(v);
        }
        self.send(req).map(|_| ())
    }

    pub fn get_geometry(&mut self, drawable: u32) -> Result<Geometry> {
        let seq = self.send(Req::new(GET_GEOMETRY, 0).u32(drawable))?;
        let r = self.reply(seq)?;
        Ok(Geometry {
            depth: r[1],
            root: le32(&r, 8),
            x: le16(&r, 12) as i16,
            y: le16(&r, 14) as i16,
            width: le16(&r, 16),
            height: le16(&r, 18),
        })
    }

    pub fn change_property(&mut self, window: u32, property: u32, kind: u32, format: u8, data: &[u8]) -> Result<()> {
        let unit = (format / 8).max(1) as usize;
        let req = Req::new(CHANGE_PROPERTY, 0).u32(window).u32(property).u32(kind).u8(format).pad(3).u32((data.len() / unit) as u32);
        self.send_with(req, data).map(|_| ())
    }

    /// Reads up to `max_bytes` of a property (rounded up to 4 bytes).
    pub fn get_property(&mut self, window: u32, property: u32, kind: u32, max_bytes: usize, delete: bool) -> Result<Property> {
        let units = max_bytes.div_ceil(4).min(u32::MAX as usize) as u32;
        let seq = self.send(Req::new(GET_PROPERTY, delete as u8).u32(window).u32(property).u32(kind).u32(0).u32(units))?;
        let r = self.reply(seq)?;
        let format = r[1];
        let n = le32(&r, 16) as usize * (format / 8).max(1) as usize;
        let value = r.get(32..32 + n).ok_or("truncated GetProperty reply")?.to_vec();
        Ok(Property { kind: le32(&r, 8), bytes_after: le32(&r, 12), value })
    }

    pub fn set_selection_owner(&mut self, owner: u32, selection: u32, time: u32) -> Result<()> {
        self.send(Req::new(SET_SELECTION_OWNER, 0).u32(owner).u32(selection).u32(time)).map(|_| ())
    }

    pub fn get_selection_owner(&mut self, selection: u32) -> Result<u32> {
        let seq = self.send(Req::new(GET_SELECTION_OWNER, 0).u32(selection))?;
        Ok(le32(&self.reply(seq)?, 8))
    }

    pub fn convert_selection(&mut self, requestor: u32, selection: u32, target: u32, property: u32, time: u32) -> Result<()> {
        self.send(Req::new(CONVERT_SELECTION, 0).u32(requestor).u32(selection).u32(target).u32(property).u32(time)).map(|_| ())
    }

    pub fn send_event(&mut self, destination: u32, mask: u32, event: &[u8; 32]) -> Result<()> {
        self.send(Req::new(SEND_EVENT, 0).u32(destination).u32(mask).bytes(event)).map(|_| ())
    }

    /// Returns true if the grab succeeded.
    pub fn grab_keyboard(&mut self, window: u32) -> Result<bool> {
        // owner_events false, asynchronous pointer and keyboard.
        let seq = self.send(Req::new(GRAB_KEYBOARD, 0).u32(window).u32(CURRENT_TIME).u8(1).u8(1).pad(2))?;
        Ok(self.reply(seq)?[1] == 0)
    }

    pub fn ungrab_keyboard(&mut self) -> Result<()> {
        self.send(Req::new(UNGRAB_KEYBOARD, 0).u32(CURRENT_TIME)).map(|_| ())
    }

    #[cfg(test)]
    pub fn query_pointer(&mut self, window: u32) -> Result<Pointer> {
        let seq = self.send(Req::new(QUERY_POINTER, 0).u32(window))?;
        let r = self.reply(seq)?;
        Ok(Pointer {
            root_x: le16(&r, 16) as i16,
            root_y: le16(&r, 18) as i16,
            win_x: le16(&r, 20) as i16,
            win_y: le16(&r, 22) as i16,
            mask: le16(&r, 24),
        })
    }

    #[cfg(test)]
    pub fn set_input_focus(&mut self, window: u32) -> Result<()> {
        // revert-to Parent
        self.send(Req::new(SET_INPUT_FOCUS, 2).u32(window).u32(CURRENT_TIME)).map(|_| ())
    }

    pub fn open_font(&mut self, name: &str) -> Result<u32> {
        let id = self.new_id()?;
        self.send(Req::new(OPEN_FONT, 0).u32(id).u16(name.len() as u16).pad(2).bytes(name.as_bytes()))?;
        Ok(id)
    }

    /// A cursor from the standard cursor font (`glyph` and its mask `glyph + 1`), black on white.
    pub fn create_glyph_cursor(&mut self, font: u32, glyph: u16) -> Result<u32> {
        let id = self.new_id()?;
        let req = Req::new(CREATE_GLYPH_CURSOR, 0).u32(id).u32(font).u32(font).u16(glyph).u16(glyph + 1);
        self.send(req.u16(0).u16(0).u16(0).u16(0xffff).u16(0xffff).u16(0xffff))?;
        Ok(id)
    }

    /// An invisible 1x1 cursor (a cleared one-bit pixmap as both source and mask).
    pub fn create_blank_cursor(&mut self, drawable: u32) -> Result<u32> {
        let pixmap = self.new_id()?;
        self.send(Req::new(CREATE_PIXMAP, 1).u32(pixmap).u32(drawable).u16(1).u16(1))?;
        let gc = self.create_gc(pixmap, 0)?;
        self.send(Req::new(POLY_FILL_RECTANGLE, 0).u32(pixmap).u32(gc).i16(0).i16(0).u16(1).u16(1))?;
        self.free_gc(gc)?;
        let id = self.new_id()?;
        self.send(Req::new(CREATE_CURSOR, 0).u32(id).u32(pixmap).u32(pixmap).pad(12).u16(0).u16(0))?;
        self.send(Req::new(FREE_PIXMAP, 0).u32(pixmap))?;
        Ok(id)
    }

    /// A graphics context without graphics exposures.
    pub fn create_gc(&mut self, drawable: u32, foreground: u32) -> Result<u32> {
        let id = self.new_id()?;
        // GCForeground | GCGraphicsExposures
        self.send(Req::new(CREATE_GC, 0).u32(id).u32(drawable).u32(1 << 2 | 1 << 16).u32(foreground).u32(0))?;
        Ok(id)
    }

    pub fn free_gc(&mut self, gc: u32) -> Result<()> {
        self.send(Req::new(FREE_GC, 0).u32(gc)).map(|_| ())
    }

    /// Clears a window area to its background (no-op for an empty rectangle).
    pub fn clear_area(&mut self, window: u32, x: i16, y: i16, w: u16, h: u16) -> Result<()> {
        if w == 0 || h == 0 {
            return Ok(()); // zero would mean "to the edge"
        }
        self.send(Req::new(CLEAR_AREA, 0).u32(window).i16(x).i16(y).u16(w).u16(h)).map(|_| ())
    }

    /// Uploads a ZPixmap image at the root depth (`row_bytes(w)` per row, already in the
    /// server's pixel format), split into as many requests as the size limit needs.
    #[allow(clippy::too_many_arguments)]
    pub fn put_image(&mut self, drawable: u32, gc: u32, w: u16, h: u16, x: i16, y: i16, data: &[u8]) -> Result<()> {
        let stride = self.setup.format.row_bytes(w as usize);
        if w == 0 || h == 0 {
            return Ok(());
        }
        if data.len() < stride * h as usize {
            bail!("image data too short");
        }
        let rows_per = (self.max_request.saturating_sub(28) / stride).min(h as usize);
        if rows_per == 0 {
            bail!("image row too large for an X request");
        }
        let depth = self.setup.format.depth;
        let mut row = 0;
        while row < h as usize {
            let n = rows_per.min(h as usize - row);
            let top = y.saturating_add(row as i16);
            let req = Req::new(PUT_IMAGE, Z_PIXMAP).u32(drawable).u32(gc).u16(w).u16(n as u16).i16(x).i16(top).u8(0).u8(depth).pad(2);
            self.send_with(req, &data[row * stride..(row + n) * stride])?;
            row += n;
        }
        Ok(())
    }

    /// Reads a ZPixmap image of `drawable` into `out` (which must hold `h * row_bytes(w)`).
    pub fn get_image(&mut self, drawable: u32, x: i16, y: i16, w: u16, h: u16, out: &mut [u8]) -> Result<()> {
        let seq = self.send(Req::new(GET_IMAGE, Z_PIXMAP).u32(drawable).i16(x).i16(y).u16(w).u16(h).u32(u32::MAX))?;
        let want = self.setup.format.row_bytes(w as usize) * h as usize;
        let (head, n) = self.reply_into(seq, out)?;
        if head[1] != self.setup.format.depth || n < want {
            bail!("unexpected GetImage reply ({n} bytes at depth {})", head[1]);
        }
        Ok(())
    }

    /// `(keysyms_per_keycode, keysyms)` for `count` keycodes starting at `first`.
    pub fn keyboard_mapping(&mut self, first: u8, count: u8) -> Result<(usize, Vec<u32>)> {
        let seq = self.send(Req::new(GET_KEYBOARD_MAPPING, 0).u8(first).u8(count).pad(2))?;
        let r = self.reply(seq)?;
        let per = r[1] as usize;
        let syms = r.get(32..).unwrap_or_default().chunks_exact(4).map(|c| le32(c, 0)).collect();
        Ok((per, syms))
    }

    // --- extensions

    /// Looks an extension up once and negotiates its version with `init` (false: unusable).
    fn ext(&mut self, name: &'static str, init: fn(&mut Conn, Ext) -> Result<bool>) -> Result<Option<Ext>> {
        if let Some(&e) = self.exts.get(name) {
            return Ok(e);
        }
        let e = match self.query_extension(name)? {
            Some(e) if init(self, e)? => Some(e),
            _ => None,
        };
        self.exts.insert(name, e);
        Ok(e)
    }

    /// MIT-SHM, only over a local socket.
    pub fn shm(&mut self) -> Result<Option<Ext>> {
        if !self.local {
            return Ok(None);
        }
        self.ext("MIT-SHM", |c, e| {
            let seq = c.send(Req::new(e.opcode, 0))?;
            c.reply(seq)?;
            Ok(true)
        })
    }

    pub fn xtest(&mut self) -> Result<Option<Ext>> {
        self.ext("XTEST", |c, e| {
            let seq = c.send(Req::new(e.opcode, 0).u8(2).u8(0).u16(2))?; // GetVersion 2.2
            Ok(c.reply(seq)?[1] >= 2)
        })
    }

    /// RANDR with monitor support (1.5).
    pub fn randr(&mut self) -> Result<Option<Ext>> {
        self.ext("RANDR", |c, e| {
            let seq = c.send(Req::new(e.opcode, 0).u32(1).u32(5))?;
            let r = c.reply(seq)?;
            Ok((le32(&r, 8), le32(&r, 12)) >= (1, 5))
        })
    }

    pub fn xinerama(&mut self) -> Result<Option<Ext>> {
        self.ext("XINERAMA", |c, e| {
            let seq = c.send(Req::new(e.opcode, 4))?; // IsActive
            Ok(le32(&c.reply(seq)?, 8) != 0)
        })
    }

    /// XFIXES 2 or later (cursor names, selection notifications).
    pub fn xfixes(&mut self) -> Result<Option<Ext>> {
        self.ext("XFIXES", |c, e| {
            let seq = c.send(Req::new(e.opcode, 0).u32(5).u32(0))?;
            Ok(le32(&c.reply(seq)?, 8) >= 2)
        })
    }

    pub fn xkb(&mut self) -> Result<Option<Ext>> {
        self.ext("XKEYBOARD", |c, e| {
            let seq = c.send(Req::new(e.opcode, 0).u16(1).u16(0))?; // UseExtension 1.0
            Ok(c.reply(seq)?[1] != 0)
        })
    }

    /// MIT-SHM GetImage into an attached segment; true if the reply's depth matched.
    #[allow(clippy::too_many_arguments)]
    pub fn shm_get_image(&mut self, shm: Ext, drawable: u32, x: i16, y: i16, w: u16, h: u16, seg: u32) -> Result<()> {
        let req = Req::new(shm.opcode, 4).u32(drawable).i16(x).i16(y).u16(w).u16(h).u32(u32::MAX).u8(Z_PIXMAP).pad(3).u32(seg).u32(0);
        let seq = self.send(req)?;
        let r = self.reply(seq)?;
        if r[1] != self.setup.format.depth {
            bail!("unexpected ShmGetImage depth {}", r[1]);
        }
        Ok(())
    }

    /// MIT-SHM PutImage of the `src` rectangle of a `total`-sized image in segment `seg`.
    #[allow(clippy::too_many_arguments)]
    pub fn shm_put_image(
        &mut self,
        shm: Ext,
        drawable: u32,
        gc: u32,
        total: (u16, u16),
        src: (u16, u16, u16, u16),
        dst: (i16, i16),
        seg: u32,
    ) -> Result<()> {
        let req = Req::new(shm.opcode, 3).u32(drawable).u32(gc).u16(total.0).u16(total.1).u16(src.0).u16(src.1).u16(src.2).u16(src.3);
        let depth = self.setup.format.depth;
        self.send(req.i16(dst.0).i16(dst.1).u8(depth).u8(Z_PIXMAP).u8(0).u8(0).u32(seg).u32(0)).map(|_| ())
    }

    /// XTEST FakeInput: `kind` is KeyPress..MotionNotify; motion is absolute on the root window.
    pub fn fake_input(&mut self, xtest: Ext, kind: u8, detail: u8, x: i16, y: i16) -> Result<()> {
        let root = self.setup.root;
        let req = Req::new(xtest.opcode, 2).u8(kind).u8(detail).pad(2).u32(CURRENT_TIME).u32(root).pad(8).i16(x).i16(y).pad(8);
        self.send(req).map(|_| ())
    }

    /// Monitors from RANDR 1.5 or XINERAMA (empty if neither knows any).
    pub fn monitors(&mut self) -> Result<Vec<Monitor>> {
        let root = self.setup.root;
        if let Some(randr) = self.randr()? {
            let seq = self.send(Req::new(randr.opcode, 42).u32(root).u8(1).pad(3))?;
            let r = self.reply(seq)?;
            let n = le32(&r, 12) as usize;
            let mut out = Vec::new();
            let mut pos = 32;
            for _ in 0..n.min(64) {
                let Some(m) = r.get(pos..pos + 24) else { break };
                let outputs = le16(m, 6) as usize;
                let (x, y) = (le16(m, 8) as i16, le16(m, 10) as i16);
                out.push(Monitor { primary: m[4] != 0, x, y, width: le16(m, 12), height: le16(m, 14) });
                pos += 24 + 4 * outputs;
            }
            if !out.is_empty() {
                return Ok(out);
            }
        }
        if let Some(xin) = self.xinerama()? {
            let seq = self.send(Req::new(xin.opcode, 5))?;
            let r = self.reply(seq)?;
            let n = le32(&r, 8) as usize;
            let list = r.get(32..).unwrap_or_default();
            return Ok(list
                .chunks_exact(8)
                .take(n.min(64))
                .enumerate()
                .map(|(i, m)| {
                    let (x, y) = (le16(m, 0) as i16, le16(m, 2) as i16);
                    Monitor { x, y, width: le16(m, 4), height: le16(m, 6), primary: i == 0 }
                })
                .collect());
        }
        Ok(Vec::new())
    }

    /// Asks for XFIXES cursor-change events on the root window.
    pub fn select_cursor_input(&mut self, xfixes: Ext) -> Result<()> {
        let root = self.setup.root;
        self.send(Req::new(xfixes.opcode, 3).u32(root).u32(1)).map(|_| ())
    }

    /// The name atom of the current cursor (0 if unnamed), via GetCursorImageAndName.
    pub fn cursor_name(&mut self, xfixes: Ext) -> Result<u32> {
        let seq = self.send(Req::new(xfixes.opcode, 25))?;
        let r = self.reply(seq)?;
        Ok(le32(&r, 24))
    }

    /// Asks for XFIXES notifications when `selection` changes owner, including when its owner
    /// goes away (window destroyed or client gone; these report owner `NONE`).
    pub fn select_selection_input(&mut self, xfixes: Ext, window: u32, selection: u32) -> Result<()> {
        // SetSelectionOwner | SelectionWindowDestroy | SelectionClientClose
        self.send(Req::new(xfixes.opcode, 2).u32(window).u32(selection).u32(7)).map(|_| ())
    }

    /// Stops key auto-repeat from producing release/press pairs (XKB detectable auto-repeat).
    pub fn detectable_autorepeat(&mut self) -> Result<bool> {
        let Some(xkb) = self.xkb()? else { return Ok(false) };
        let req = Req::new(xkb.opcode, 21).u16(0x100).pad(2).u32(1).u32(1).u32(0).u32(0).u32(0);
        let seq = self.send(req)?;
        let r = self.reply(seq)?;
        Ok(le32(&r, 12) & 1 != 0)
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        wipe(&mut self.rbuf);
    }
}

fn read_exact(sock: &mut Sock, out: &mut [u8]) -> Result<()> {
    let mut done = 0;
    while done < out.len() {
        match sock.read(&mut out[done..]) {
            Ok(0) => bail!("the X server closed the connection"),
            Ok(n) => done += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(io_error(e)),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// poll(2), wake-up pipe and SysV shared memory

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

const POLLIN: i16 = 1;
const IPC_PRIVATE: c_int = 0;
const IPC_CREAT: c_int = 0o1000;
const IPC_RMID: c_int = 0;
const MADV_DONTDUMP: c_int = 16;

unsafe extern "C" {
    fn poll(fds: *mut PollFd, n: u64, timeout: c_int) -> c_int;
    fn shmget(key: c_int, size: usize, flags: c_int) -> c_int;
    fn shmat(id: c_int, addr: *const c_void, flags: c_int) -> *mut c_void;
    fn shmdt(addr: *const c_void) -> c_int;
    fn shmctl(id: c_int, cmd: c_int, buf: *mut c_void) -> c_int;
    fn madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int;
    fn getsockopt(fd: c_int, level: c_int, name: c_int, value: *mut c_void, len: *mut u32) -> c_int;
    fn geteuid() -> u32;
}

/// Waits until one of `fds` is readable (or hung up); `timeout_ms < 0` waits forever.
/// Returns readiness per descriptor (all false on timeout or EINTR).
pub fn wait_readable(fds: &[RawFd], timeout_ms: i32) -> Result<Vec<bool>> {
    let mut p: Vec<PollFd> = fds.iter().map(|&fd| PollFd { fd, events: POLLIN, revents: 0 }).collect();
    let n = unsafe { poll(p.as_mut_ptr(), p.len() as u64, timeout_ms) };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() != ErrorKind::Interrupted {
            return Err(Error::msg(format!("poll failed: {e}")));
        }
    }
    Ok(p.iter().map(|f| n > 0 && f.revents != 0).collect())
}

/// Self-pipe that lets other threads wake a thread blocked in `wait_readable`.
pub struct Wake {
    rx: UnixStream,
    tx: UnixStream,
}

impl Wake {
    pub fn new() -> Result<Wake> {
        let (rx, tx) = UnixStream::pair()?;
        rx.set_nonblocking(true)?;
        tx.set_nonblocking(true)?;
        Ok(Wake { rx, tx })
    }

    /// A handle other threads use to wake the owner.
    pub fn waker(&self) -> Result<Waker> {
        Ok(Waker(self.tx.try_clone()?))
    }

    pub fn fd(&self) -> RawFd {
        self.rx.as_raw_fd()
    }

    /// Empties the pipe.
    pub fn drain(&self) {
        let mut b = [0u8; 64];
        while matches!((&self.rx).read(&mut b), Ok(n) if n > 0) {}
    }
}

#[derive(Debug)]
pub struct Waker(UnixStream);

impl Waker {
    pub fn wake(&self) {
        // A full pipe already guarantees a wake-up.
        let _ = (&self.0).write(&[1]);
    }
}

/// A SysV shared-memory segment attached to us and to the X server (MIT-SHM). The memory is
/// private to this user (0600), excluded from core dumps, locked when allowed, and wiped
/// before it is released.
pub struct ShmSegment {
    pub seg: u32,
    ptr: *mut u8,
    len: usize,
}

unsafe impl Send for ShmSegment {}

impl ShmSegment {
    pub fn new(conn: &mut Conn, shm: Ext, len: usize) -> Result<ShmSegment> {
        let id = unsafe { shmget(IPC_PRIVATE, len.max(1), IPC_CREAT | 0o600) };
        if id < 0 {
            return Err(Error::last_os("shmget"));
        }
        let p = unsafe { shmat(id, std::ptr::null(), 0) };
        if p as isize == -1 {
            let e = Error::last_os("shmat");
            unsafe { shmctl(id, IPC_RMID, std::ptr::null_mut()) };
            return Err(e);
        }
        let mut s = ShmSegment { seg: 0, ptr: p as *mut u8, len };
        let attached = (|| {
            let seg = conn.new_id()?;
            let seq = conn.send(Req::new(shm.opcode, 1).u32(seg).u32(id as u32).u8(0).pad(3))?;
            conn.sync_since(seq)?;
            Ok::<u32, Error>(seg)
        })();
        // Both sides are attached (or the server refused): the id is no longer needed, and the
        // segment disappears once the last mapping goes.
        unsafe { shmctl(id, IPC_RMID, std::ptr::null_mut()) };
        s.seg = attached?;
        unsafe { madvise(p, len, MADV_DONTDUMP) };
        super::mem::lock_pages(s.ptr, len);
        Ok(s)
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Tells the server to let go of the segment (it also does so when the connection closes).
    pub fn detach(&self, conn: &mut Conn, shm: Ext) {
        if self.seg != 0 {
            let _ = conn.send(Req::new(shm.opcode, 2).u32(self.seg));
        }
    }
}

impl Drop for ShmSegment {
    fn drop(&mut self) {
        wipe(self.as_mut_slice());
        unsafe { shmdt(self.ptr as *const c_void) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error `f` returns once a closed listener is gone. A child another test is starting
    /// holds a copy of every descriptor until it runs its program, keeping the listener alive.
    fn when_closed<T>(mut f: impl FnMut() -> Result<T>) -> Error {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match f() {
                Err(e) => return e,
                Ok(_) => assert!(std::time::Instant::now() < deadline, "the listener is still there"),
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn checks_who_serves_a_socket() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixListener};
        let me = std::process::id();
        let abs = SocketAddr::from_abstract_name(format!("safe-rdp-test-peer-{me}").as_bytes()).unwrap();
        let listener = UnixListener::bind_addr(&abs).unwrap();
        // This process listens, so any other pid is turned away before anything is sent.
        let err = connect_checked(&abs, me + 1, "the test socket").err().expect("accepted another process");
        assert!(err.to_string().contains("another process"), "{err}");
        let (mut peer, _) = listener.accept().unwrap();
        let mut b = [0u8; 8];
        assert_eq!(peer.read(&mut b).unwrap(), 0, "bytes were sent");
        assert!(connect_checked(&abs, me, "the test socket").is_ok());
        drop(listener);
        when_closed(|| connect_checked(&abs, me, "the test socket"));

        let dir = std::env::temp_dir().join(format!("safe-rdp-peer-{me}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("X0");
        let _listener = UnixListener::bind(&path).unwrap();
        let file = SocketAddr::from_pathname(&path).unwrap();
        assert!(connect_checked(&file, me + 1, "the test socket").is_err());
        assert!(connect_checked(&file, me, "the test socket").is_ok());
        std::fs::remove_dir_all(&dir).unwrap();

        let tcp = Target { display: "localhost:1".into(), xauthority: None };
        assert!(Conn::connect_to_server(&tcp, me).err().expect("TCP display").to_string().contains("not a local display"));
    }

    /// Every local connection checks who serves the display before sending anything, also
    /// when only the abstract name is left (as after the server we trusted died).
    #[test]
    fn local_connections_check_the_server() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixListener};
        let me = std::process::id();
        let euid = unsafe { geteuid() };
        // A number far outside the X range, served on its abstract name only.
        let n = 3_000_000_000 + me;
        let abs = SocketAddr::from_abstract_name(local_socket_path(n).as_bytes()).unwrap();
        let listener = UnixListener::bind_addr(&abs).unwrap();
        listener.set_nonblocking(true).unwrap();
        let err = connect_local(n, Some(me + 1), euid).err().expect("accepted a server other than the pinned one");
        assert!(err.to_string().contains("another process"), "{err}");
        if euid != 0 {
            let err = connect_local(n, None, euid + 1).err().expect("accepted another user's server");
            assert!(err.to_string().contains("another user"), "{err}");
        }
        assert!(connect_local(n, Some(RETIRED), euid).is_err());
        let mut sent = 0;
        while let Ok((mut s, _)) = listener.accept() {
            s.set_nonblocking(false).unwrap();
            let mut b = [0u8; 8];
            sent += s.read(&mut b).unwrap();
        }
        assert_eq!(sent, 0, "bytes were sent");
        assert!(connect_local(n, Some(me), euid).is_ok());
        assert!(connect_local(n, None, euid).is_ok());
        drop(listener);
        let err = when_closed(|| connect_local(n, Some(me), euid));
        assert!(err.to_string().contains("cannot connect"), "{err}");

        let tcp = parse_display("localhost:1").unwrap();
        let err = connect_socket(&tcp, Some(me)).err().expect("left the pinned server");
        assert!(err.to_string().contains("only the virtual display"), "{err}");
    }

    #[test]
    fn display_names() {
        let d = |h: &str, n, s| DisplayName { host: h.into(), number: n, screen: s };
        assert_eq!(parse_display(":0").unwrap(), d("", 0, 0));
        assert_eq!(parse_display(":71.1").unwrap(), d("", 71, 1));
        assert_eq!(parse_display("unix:3").unwrap(), d("", 3, 0));
        assert_eq!(parse_display("localhost:10.0").unwrap(), d("localhost", 10, 0));
        assert_eq!(parse_display("10.1.2.3:2").unwrap(), d("10.1.2.3", 2, 0));
        assert_eq!(parse_display("[::1]:4").unwrap(), d("::1", 4, 0));
        assert_eq!(parse_display("tcp/box:1").unwrap(), d("box", 1, 0));
        assert_eq!(parse_display("tcp/:1").unwrap(), d("localhost", 1, 0));
        assert_eq!(parse_display("unix/:5").unwrap(), d("", 5, 0));
        for bad in ["", "0", ":", ":x", ":-1", ":1.", ":1.x", "host::0", ":123456", "h:60000", "wayland-0"] {
            assert!(parse_display(bad).is_err(), "{bad:?} accepted");
        }
    }

    fn entry(family: u16, address: &[u8], number: &str, data: &[u8]) -> AuthEntry {
        AuthEntry { family, address: address.to_vec(), number: number.as_bytes().to_vec(), name: COOKIE_NAME.to_vec(), data: data.to_vec() }
    }

    #[test]
    fn xauthority_roundtrip_and_matching() {
        let entries = [
            entry(FAMILY_LOCAL, b"otherhost", "0", &[1; 16]),
            entry(FAMILY_LOCAL, b"me", "1", &[2; 16]),
            entry(FAMILY_INTERNET, &[10, 0, 0, 5], "", &[3; 16]),
            entry(FAMILY_WILD, b"", "7", &[4; 16]),
        ];
        let mut file = Vec::new();
        for e in &entries {
            file.extend(encode_auth_entry(e));
        }
        // A truncated trailing entry is ignored.
        file.extend_from_slice(&[0x01, 0x00, 0x00, 0x05, b'x']);
        let parsed = parse_xauthority(&file);
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[1].address, b"me");
        assert_eq!(parsed[2].family, FAMILY_INTERNET);

        let cookie = |f, a: &[u8], n| find_cookie(&parsed, f, a, n).map(|c| c.0.clone());
        assert_eq!(cookie(FAMILY_LOCAL, b"me", 1), Some(vec![2; 16]));
        assert_eq!(cookie(FAMILY_LOCAL, b"me", 0), None);
        assert_eq!(cookie(FAMILY_INTERNET, &[10, 0, 0, 5], 42), Some(vec![3; 16]), "empty number matches any display");
        assert_eq!(cookie(FAMILY_LOCAL, b"anything", 7), Some(vec![4; 16]), "wildcard family");

        let mut other = entry(FAMILY_LOCAL, b"me", "2", &[5; 16]);
        other.name = b"XDM-AUTHORIZATION-1".to_vec();
        assert!(find_cookie(&[other], FAMILY_LOCAL, b"me", 2).is_none());
        assert!(parse_xauthority(&[0x01]).is_empty());
    }

    /// A setup reply with one screen, one depth-24 TrueColor visual and the given format.
    pub(super) fn fake_setup(bpp: u8, order: u8, masks: [u32; 3]) -> Vec<u8> {
        let vendor = b"Test";
        let mut b = vec![1, 0, 11, 0, 0, 0, 0, 0];
        b.extend_from_slice(&1u32.to_le_bytes()); // release
        b.extend_from_slice(&0x0040_0000u32.to_le_bytes());
        b.extend_from_slice(&0x001f_ffffu32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&(vendor.len() as u16).to_le_bytes());
        b.extend_from_slice(&0xffffu16.to_le_bytes());
        b.extend_from_slice(&[1, 2, order, 0, 32, 32, 8, 255, 0, 0, 0, 0]);
        b.extend_from_slice(vendor);
        b.extend_from_slice(&[1, 1, 32, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&[24, bpp, 32, 0, 0, 0, 0, 0]);
        // Screen
        for v in [0x100u32, 0x20, 0xffffff, 0, 0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        for v in [1920u16, 1080, 500, 280, 1, 1] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&0x21u32.to_le_bytes());
        b.extend_from_slice(&[0, 0, 24, 1]);
        b.extend_from_slice(&[24, 0, 1, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&0x21u32.to_le_bytes());
        b.extend_from_slice(&[4, 8, 0, 1]);
        for m in masks {
            b.extend_from_slice(&m.to_le_bytes());
        }
        b.extend_from_slice(&[0; 4]);
        let extra = ((b.len() - 8) / 4) as u16;
        b[6..8].copy_from_slice(&extra.to_le_bytes());
        b
    }

    #[test]
    fn parses_setup_reply() {
        let b = fake_setup(32, 0, [0xff0000, 0xff00, 0xff]);
        let s = parse_setup(&b, 0).unwrap();
        assert_eq!((s.root, s.black, s.max_request), (0x100, 0, 0xffff));
        assert_eq!((s.min_keycode, s.max_keycode, s.id_base, s.id_mask), (8, 255, 0x0040_0000, 0x001f_ffff));
        assert!(s.format.is_bgrx());
        assert_eq!(s.format.row_bytes(3), 12);
        assert!(parse_setup(&b, 1).is_err());
        // Every truncation fails cleanly.
        for n in 0..b.len() {
            assert!(parse_setup(&b[..n], 0).is_err(), "truncated at {n}");
        }
        assert!(parse_setup(&fake_setup(8, 0, [0xff0000, 0xff00, 0xff]), 0).is_err());
    }

    #[test]
    fn pixel_conversion() {
        let px = [(0x12u8, 0x34u8, 0x56u8), (0xff, 0x00, 0x80), (0, 0, 0), (255, 255, 255)];
        for fmt in [
            PixelFormat { depth: 24, bpp: 32, pad: 32, msb_first: false, masks: [0xff0000, 0xff00, 0xff] },
            PixelFormat { depth: 24, bpp: 32, pad: 32, msb_first: true, masks: [0xff0000, 0xff00, 0xff] },
            PixelFormat { depth: 24, bpp: 32, pad: 32, msb_first: false, masks: [0xff, 0xff00, 0xff0000] },
            PixelFormat { depth: 24, bpp: 24, pad: 32, msb_first: false, masks: [0xff0000, 0xff00, 0xff] },
        ] {
            let bgra: Vec<u8> = px.iter().flat_map(|&(r, g, b)| [b, g, r, 255]).collect();
            let mut wire = vec![0u8; fmt.row_bytes(4)];
            fmt.from_bgra_row(&bgra, &mut wire);
            let mut back = vec![0u8; 16];
            fmt.to_bgra(&wire, 4, 1, &mut back);
            assert_eq!(back, bgra, "{fmt:?}");
        }
        // 16-bit 565: full intensity stays full, black stays black.
        let f565 = PixelFormat { depth: 16, bpp: 16, pad: 32, msb_first: false, masks: [0xf800, 0x07e0, 0x001f] };
        assert_eq!(f565.row_bytes(3), 8);
        let mut back = [0u8; 8];
        f565.to_bgra(&[0xff, 0xff, 0x00, 0x00], 2, 1, &mut back);
        assert_eq!(back, [255, 255, 255, 255, 0, 0, 0, 255]);
        let mut wire = [0u8; 2];
        f565.from_bgra_row(&[0, 0, 255, 255], &mut wire);
        assert_eq!(u16::from_le_bytes(wire), 0xf800);
    }

    #[test]
    fn request_encoding() {
        let r = Req::new(INTERN_ATOM, 1).u16(5).pad(2).bytes(b"HELLO").finish(0, false).unwrap();
        assert_eq!(r, [16, 1, 4, 0, 5, 0, 0, 0, b'H', b'E', b'L', b'L', b'O', 0, 0, 0]);
        // Body bytes count towards the length, padded.
        let r = Req::new(PUT_IMAGE, Z_PIXMAP).pad(20).finish(6, false).unwrap();
        assert_eq!(le16(&r, 2), 8);
        // Too long for 16 bits: BIG-REQUESTS form, length includes the extra word.
        let r = Req::new(PUT_IMAGE, Z_PIXMAP).pad(20).finish(0x40000, true).unwrap();
        assert_eq!((le16(&r, 2), le32(&r, 4), r.len()), (0, 6 + 0x10000 + 1, 28));
        assert!(Req::new(PUT_IMAGE, 0).pad(20).finish(0x40000, false).is_err());
    }

    #[test]
    fn packets_and_events() {
        assert_eq!(packet_len(&[0; 31]), None);
        let mut reply = [0u8; 32];
        reply[0] = 1;
        reply[4..8].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(packet_len(&reply), Some(44));
        let mut ev = [0u8; 32];
        ev[0] = KEY_PRESS | 0x80; // sent with SendEvent
        ev[1] = 38;
        ev[28] = 4;
        assert_eq!(Event::parse(&ev), Event::Key { press: true, keycode: 38, time: 0, state: 4 });
        ev[0] = CLIENT_MESSAGE;
        ev[1] = 32;
        ev[8..12].copy_from_slice(&77u32.to_le_bytes());
        ev[12] = 9;
        assert!(matches!(Event::parse(&ev), Event::ClientMessage { kind: 77, format: 32, data, .. } if data[0] == 9));
        ev[0] = 90;
        assert!(matches!(Event::parse(&ev), Event::Other(_)));
    }
}
