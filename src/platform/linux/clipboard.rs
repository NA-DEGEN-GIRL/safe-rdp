//! Text clipboard bridge for the X11 CLIPBOARD selection.
//!
//! Runs its own X connection and thread with a hidden window. XFIXES reports when another
//! application takes the selection; its text is then fetched as UTF8_STRING (or STRING), also
//! through the INCR protocol for large selections. Text from the remote side is offered to
//! local applications by owning the selection until someone else takes it.

use super::x11::{self, ANY_PROPERTY_TYPE, ATOM_ATOM, ATOM_STRING, CURRENT_TIME, Conn, Event, Ext, NONE, Target, Wake, Waker};
use crate::log;
use crate::proto::MAX_CLIPBOARD;
use crate::util::{Error, Result, wipe};
use std::sync::mpsc;

/// The bridge, as seen from the session: remote text goes in with `set`, local changes come
/// out through the callback given to `spawn`.
pub struct Clipboard {
    tx: Option<mpsc::Sender<String>>,
    waker: Waker,
}

impl Clipboard {
    /// Starts watching the clipboard of this process's display; `on_change` runs on the
    /// bridge thread.
    pub fn spawn(on_change: impl Fn(String) + Send + 'static) -> Result<Clipboard> {
        Clipboard::spawn_on(Target::from_env()?, on_change)
    }

    pub fn spawn_on(target: Target, on_change: impl Fn(String) + Send + 'static) -> Result<Clipboard> {
        let (tx, rx) = mpsc::channel::<String>();
        let wake = Wake::new()?;
        let waker = wake.waker()?;
        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();
        std::thread::Builder::new().name("clipboard".into()).spawn(move || match Bridge::open(&target) {
            Ok(mut b) => {
                let _ = ready_tx.send(Ok(()));
                if let Err(e) = b.run(&wake, &rx, &on_change) {
                    log!("clipboard sharing stopped: {e}");
                }
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e));
            }
        })?;
        ready_rx.recv().map_err(|_| Error::msg("clipboard thread died"))??;
        Ok(Clipboard { tx: Some(tx), waker })
    }

    /// Replaces the local clipboard text (asynchronously, on the bridge thread).
    pub fn set(&self, text: String) {
        if let Some(tx) = &self.tx {
            if tx.send(text).is_ok() {
                self.waker.wake();
            }
        }
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        // Close the channel first so the woken thread sees it disconnected.
        self.tx = None;
        self.waker.wake();
    }
}

/// Files currently copied on this machine (none: X11 file clipboards are not supported).
pub fn copied_files() -> Vec<std::path::PathBuf> {
    Vec::new()
}

/// ISO 8859-1 bytes (the STRING type) to text.
fn from_latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// Text to ISO 8859-1; characters outside it become '?'.
fn to_latin1(s: &str) -> Vec<u8> {
    s.chars().map(|c| if (c as u32) < 256 { c as u8 } else { b'?' }).collect()
}

/// Text from a selection value: UTF-8 for UTF8_STRING and the like, Latin-1 for STRING.
fn decode_text(kind: u32, string: u32, value: &[u8]) -> String {
    let s = if kind == string { from_latin1(value) } else { String::from_utf8_lossy(value).into_owned() };
    // Many applications NUL-terminate their selections.
    s.trim_end_matches('\0').to_string()
}

struct Atoms {
    clipboard: u32,
    utf8: u32,
    targets: u32,
    text: u32,
    text_plain: u32,
    incr: u32,
    property: u32,
}

/// A selection transfer in progress.
enum Fetch {
    /// Waiting for SelectionNotify for this target.
    Converting(u32),
    /// INCR chunks arriving; `None` once the text grew too large (the rest is drained).
    Incremental(u32, Option<Vec<u8>>),
}

struct Bridge {
    conn: Conn,
    win: u32,
    xfixes: Ext,
    atoms: Atoms,
    /// Text we serve while we own the selection.
    owned: Option<String>,
    /// The clipboard text as last seen or set, so unchanged text is not echoed back.
    last: Option<String>,
    fetch: Option<Fetch>,
}

fn wipe_string(s: &mut Option<String>) {
    if let Some(mut t) = s.take() {
        unsafe { wipe(t.as_bytes_mut()) };
    }
}

impl Bridge {
    fn open(target: &Target) -> Result<Bridge> {
        let mut conn = Conn::connect(target)?;
        let xfixes = conn.xfixes()?.ok_or("the X server lacks XFIXES")?;
        let root = conn.root();
        // An unmapped window: requestor for conversions and owner for our selections.
        let win = conn.create_window(root, -10, -10, 1, 1, 2, x11::CW_EVENT_MASK, &[x11::PROPERTY_CHANGE_MASK])?;
        let atoms = Atoms {
            clipboard: conn.atom("CLIPBOARD")?,
            utf8: conn.atom("UTF8_STRING")?,
            targets: conn.atom("TARGETS")?,
            text: conn.atom("TEXT")?,
            text_plain: conn.atom("text/plain;charset=utf-8")?,
            incr: conn.atom("INCR")?,
            property: conn.atom("SAFE_RDP_SELECTION")?,
        };
        conn.select_selection_input(xfixes, win, atoms.clipboard)?;
        conn.sync()?;
        Ok(Bridge { conn, win, xfixes, atoms, owned: None, last: None, fetch: None })
    }

    fn run(&mut self, wake: &Wake, rx: &mpsc::Receiver<String>, on_change: &dyn Fn(String)) -> Result<()> {
        let r = self.serve(wake, rx, on_change);
        wipe_string(&mut self.owned);
        wipe_string(&mut self.last);
        r
    }

    fn serve(&mut self, wake: &Wake, rx: &mpsc::Receiver<String>, on_change: &dyn Fn(String)) -> Result<()> {
        loop {
            let mut latest = None;
            loop {
                match rx.try_recv() {
                    Ok(t) => latest = Some(t),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
                }
            }
            if let Some(t) = latest {
                self.take_ownership(t)?;
            }
            while let Some(ev) = self.conn.poll_event()? {
                self.on_event(ev, on_change)?;
            }
            if self.conn.has_buffered_event() {
                continue;
            }
            let ready = x11::wait_readable(&[self.conn.fd(), wake.fd()], -1)?;
            if ready[1] {
                wake.drain();
            }
            if ready[0] {
                self.conn.read_input()?;
            }
        }
    }

    fn take_ownership(&mut self, text: String) -> Result<()> {
        if self.last.as_deref() == Some(text.as_str()) && self.owned.is_none() {
            return Ok(()); // the local clipboard already holds this text
        }
        self.conn.set_selection_owner(self.win, self.atoms.clipboard, CURRENT_TIME)?;
        if self.conn.get_selection_owner(self.atoms.clipboard)? != self.win {
            log!("could not take the X clipboard");
            return Ok(());
        }
        wipe_string(&mut self.owned);
        self.last = Some(text.clone());
        self.owned = Some(text);
        Ok(())
    }

    fn on_event(&mut self, ev: Event, on_change: &dyn Fn(String)) -> Result<()> {
        match ev {
            Event::Other(raw) if raw[0] & 0x7f == self.xfixes.first_event => {
                // XFixesSelectionNotify: window, owner, selection, ...
                let owner = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
                let selection = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
                if selection == self.atoms.clipboard && owner != self.win {
                    wipe_string(&mut self.owned);
                    self.fetch = None;
                    if owner != NONE {
                        self.request(self.atoms.utf8)?;
                    }
                }
            }
            Event::SelectionNotify { requestor, selection, target, property, .. }
                if requestor == self.win && selection == self.atoms.clipboard =>
            {
                if !matches!(self.fetch, Some(Fetch::Converting(t)) if t == target) {
                    return Ok(());
                }
                self.fetch = None;
                if property == NONE {
                    // The owner cannot give UTF-8; try Latin-1 before giving up.
                    if target == self.atoms.utf8 {
                        self.request(ATOM_STRING)?;
                    }
                    return Ok(());
                }
                let p = self.conn.get_property(self.win, property, ANY_PROPERTY_TYPE, MAX_CLIPBOARD + 4, true)?;
                if p.kind == self.atoms.incr {
                    // Deleting the property (done above) starts the transfer.
                    self.fetch = Some(Fetch::Incremental(target, Some(Vec::new())));
                } else if p.bytes_after > 0 || p.value.len() > MAX_CLIPBOARD {
                    log!("local clipboard text is too large to share");
                } else {
                    self.report(decode_text(p.kind, ATOM_STRING, &p.value), on_change);
                }
                let mut v = p.value;
                wipe(&mut v);
            }
            Event::Property { window, atom, deleted: false, .. } if window == self.win && atom == self.atoms.property => {
                let Some(Fetch::Incremental(target, buf)) = &mut self.fetch else { return Ok(()) };
                let target = *target;
                let mut p = self.conn.get_property(self.win, atom, ANY_PROPERTY_TYPE, MAX_CLIPBOARD + 4, true)?;
                if p.value.is_empty() {
                    let done = buf.take();
                    self.fetch = None;
                    match done {
                        Some(mut all) => {
                            let kind = if target == ATOM_STRING { ATOM_STRING } else { self.atoms.utf8 };
                            self.report(decode_text(kind, ATOM_STRING, &all), on_change);
                            wipe(&mut all);
                        }
                        None => log!("local clipboard text is too large to share"),
                    }
                } else if let Some(b) = buf {
                    if b.len() + p.value.len() > MAX_CLIPBOARD {
                        wipe(b);
                        *buf = None;
                    } else {
                        b.extend_from_slice(&p.value);
                    }
                }
                wipe(&mut p.value);
            }
            Event::SelectionRequest { time, requestor, selection, target, property } => {
                self.answer(time, requestor, selection, target, property)?;
            }
            Event::SelectionClear { selection, .. } if selection == self.atoms.clipboard => wipe_string(&mut self.owned),
            _ => {}
        }
        Ok(())
    }

    fn request(&mut self, target: u32) -> Result<()> {
        self.fetch = Some(Fetch::Converting(target));
        self.conn.convert_selection(self.win, self.atoms.clipboard, target, self.atoms.property, CURRENT_TIME)
    }

    fn report(&mut self, text: String, on_change: &dyn Fn(String)) {
        if text.is_empty() || self.last.as_deref() == Some(text.as_str()) {
            return;
        }
        wipe_string(&mut self.last);
        self.last = Some(text.clone());
        on_change(text);
    }

    /// Serves a local application's request for our selection.
    fn answer(&mut self, time: u32, requestor: u32, selection: u32, target: u32, property: u32) -> Result<()> {
        // Obsolete clients leave the property out; ICCCM says to use the target then.
        let property = if property == NONE { target } else { property };
        let a = &self.atoms;
        let served = match (&self.owned, selection == a.clipboard) {
            (Some(text), true) => {
                let reply: Option<(u32, u8, Vec<u8>)> = if target == a.targets {
                    let list = [a.targets, a.utf8, a.text_plain, a.text, ATOM_STRING];
                    Some((ATOM_ATOM, 32, list.iter().flat_map(|t| t.to_le_bytes()).collect()))
                } else if target == a.utf8 || target == a.text || target == a.text_plain {
                    Some((a.utf8, 8, text.as_bytes().to_vec()))
                } else if target == ATOM_STRING {
                    Some((ATOM_STRING, 8, to_latin1(text)))
                } else {
                    None
                };
                match reply {
                    Some((kind, format, mut data)) if data.len() + 64 <= self.conn.max_request_bytes() => {
                        let r = self.conn.change_property(requestor, property, kind, format, &data);
                        wipe(&mut data);
                        r?;
                        true
                    }
                    _ => false,
                }
            }
            _ => false,
        };
        let mut ev = [0u8; 32];
        ev[0] = 31; // SelectionNotify
        for (i, v) in [time, requestor, selection, target, if served { property } else { NONE }].iter().enumerate() {
            ev[4 + 4 * i..8 + 4 * i].copy_from_slice(&v.to_le_bytes());
        }
        self.conn.send_event(requestor, 0, &ev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::xvfb::VirtualDisplay;
    use std::time::{Duration, Instant};

    #[test]
    fn text_encodings() {
        assert_eq!(to_latin1("café 안녕"), b"caf\xe9 ??");
        assert_eq!(from_latin1(b"caf\xe9"), "café");
        assert_eq!(decode_text(31, 31, b"caf\xe9\0"), "café");
        assert_eq!(decode_text(99, 31, "안녕\0".as_bytes()), "안녕");
        assert_eq!(decode_text(99, 31, b"bad \xff utf8"), "bad \u{fffd} utf8");
    }

    fn wait_for(rx: &mpsc::Receiver<String>) -> String {
        rx.recv_timeout(Duration::from_secs(5)).expect("no clipboard change reported")
    }

    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn bridges_between_clients() {
        let vd = VirtualDisplay::spawn(Some(77), 200, 200, None).unwrap();
        let t = vd.target();
        let (atx, arx) = mpsc::channel();
        let (btx, brx) = mpsc::channel();
        let a = Clipboard::spawn_on(t.clone(), move |s| atx.send(s).unwrap()).unwrap();
        let b = Clipboard::spawn_on(t.clone(), move |s| btx.send(s).unwrap()).unwrap();

        a.set("안녕 clipboard".into());
        assert_eq!(wait_for(&brx), "안녕 clipboard");
        b.set("from b".into());
        assert_eq!(wait_for(&arx), "from b");
        // Large text goes through as one property.
        let big = "x".repeat(600 * 1024);
        a.set(big.clone());
        assert_eq!(wait_for(&brx), big);
        assert!(arx.try_recv().is_err(), "a reported its own text");

        // A plain client asking for TARGETS and STRING.
        let mut c = Conn::connect(&t).unwrap();
        let root = c.root();
        let win = c.create_window(root, 0, 0, 1, 1, 2, 0, &[]).unwrap();
        let (clipboard, targets, prop) = (c.atom("CLIPBOARD").unwrap(), c.atom("TARGETS").unwrap(), c.atom("P").unwrap());
        a.set("Grüße 안녕".into());
        let deadline = Instant::now() + Duration::from_secs(5);
        let fetch = |c: &mut Conn, target: u32| {
            c.convert_selection(win, clipboard, target, prop, CURRENT_TIME).unwrap();
            loop {
                assert!(Instant::now() < deadline);
                if let Some(Event::SelectionNotify { property, .. }) = c.wait_event(Duration::from_secs(1)).unwrap() {
                    assert_eq!(property, prop);
                    return c.get_property(win, prop, ANY_PROPERTY_TYPE, 1 << 16, true).unwrap();
                }
            }
        };
        // Wait until a owns the selection with the new text.
        while fetch(&mut c, ATOM_STRING).value != b"Gr\xfc\xdfe ??" {
            std::thread::sleep(Duration::from_millis(20));
        }
        let p = fetch(&mut c, targets);
        assert_eq!(p.kind, ATOM_ATOM);
        let utf8 = c.atom("UTF8_STRING").unwrap();
        assert!(p.value.chunks_exact(4).any(|v| u32::from_le_bytes(v.try_into().unwrap()) == utf8));
        assert_eq!(fetch(&mut c, utf8).value, "Grüße 안녕".as_bytes());
        drop(a);
        drop(b);
    }
}
