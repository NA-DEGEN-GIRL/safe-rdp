//! Text clipboard bridge for the X11 CLIPBOARD selection.
//!
//! Runs its own X connection and thread with a hidden window. XFIXES reports when another
//! application takes the selection; its text is then fetched as UTF8_STRING (or STRING), also
//! through the INCR protocol for large selections. Text from the remote side is offered to
//! local applications by owning the selection until someone else takes it.

use super::x11::{self, ANY_PROPERTY_TYPE, ATOM_ATOM, ATOM_STRING, CURRENT_TIME, Conn, Event, Ext, NONE, Target, Wake, Waker};
use crate::log;
use crate::platform::handover::Handover;
use crate::proto::MAX_CLIPBOARD;
use crate::util::{Error, Result, wipe};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

/// How long after we take the selection a local offer of the same text counts as its echo
/// (a clipboard manager copies it within milliseconds; a person copying it again takes longer).
const ECHO_WINDOW: Duration = Duration::from_secs(2);

/// The bridge, as seen from the session: remote text goes in with `set`, local changes come
/// out through the callback given to `spawn`.
pub struct Clipboard {
    /// Remote text for the bridge thread: only the newest waits, however busy the thread is.
    pending: Arc<Handover>,
    waker: Waker,
}

impl Clipboard {
    /// Starts watching the clipboard of this process's display; `on_change` runs on the
    /// bridge thread.
    pub fn spawn(on_change: impl Fn(String) + Send + 'static) -> Result<Clipboard> {
        Clipboard::spawn_on(Target::from_env()?, on_change)
    }

    pub fn spawn_on(target: Target, on_change: impl Fn(String) + Send + 'static) -> Result<Clipboard> {
        let pending = Arc::new(Handover::default());
        let wake = Wake::new()?;
        let waker = wake.waker()?;
        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();
        let taken = pending.clone();
        std::thread::Builder::new().name("clipboard".into()).spawn(move || match Bridge::open(&target) {
            Ok(mut b) => {
                let _ = ready_tx.send(Ok(()));
                if let Err(e) = b.run(&wake, &taken, &on_change) {
                    log!("clipboard sharing stopped: {e}");
                }
                // Text sent from now on has nowhere to go.
                taken.close();
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e));
            }
        })?;
        ready_rx.recv().map_err(|_| Error::msg("clipboard thread died"))??;
        Ok(Clipboard { pending, waker })
    }

    /// Replaces the local clipboard text (asynchronously, on the bridge thread).
    pub fn set(&self, text: String) {
        if self.pending.put(text) {
            self.waker.wake();
        }
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        // Close first so the woken thread sees it closed.
        self.pending.close();
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

/// Cuts `text` to at most `MAX_CLIPBOARD` bytes (at a character boundary), the most the peer
/// accepts; decoding can make text longer than the selection bytes it came from. True if cut.
fn limit(text: &mut String) -> bool {
    if text.len() <= MAX_CLIPBOARD {
        return false;
    }
    let mut cut = MAX_CLIPBOARD;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    // NUL bytes keep the string valid UTF-8 until it is truncated.
    unsafe { wipe(&mut text.as_bytes_mut()[cut..]) };
    text.truncate(cut);
    true
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
    /// The text the local clipboard holds as far as we know (`None`: unknown, empty or not
    /// text), so text it already holds is not taken over again.
    last: Option<String>,
    /// When `last` came from the remote side, until a local application offers text. The first
    /// such offer of the same text within `ECHO_WINDOW` (typically a clipboard manager copying
    /// it from us) is not sent back.
    echo: Option<Instant>,
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
        Ok(Bridge { conn, win, xfixes, atoms, owned: None, last: None, echo: None, fetch: None })
    }

    fn run(&mut self, wake: &Wake, pending: &Handover, on_change: &dyn Fn(String)) -> Result<()> {
        let r = self.serve(wake, pending, on_change);
        wipe_string(&mut self.owned);
        wipe_string(&mut self.last);
        r
    }

    fn serve(&mut self, wake: &Wake, pending: &Handover, on_change: &dyn Fn(String)) -> Result<()> {
        loop {
            // Taken only after the wake-up pipe is drained (below), so text put meanwhile
            // without a wake-up of its own is not left behind.
            if pending.is_closed() {
                return Ok(());
            }
            if let Some(t) = pending.take() {
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
            wipe_string(&mut Some(text));
            return Ok(()); // a local application already offers this text
        }
        self.conn.set_selection_owner(self.win, self.atoms.clipboard, CURRENT_TIME)?;
        if self.conn.get_selection_owner(self.atoms.clipboard)? != self.win {
            log!("could not take the X clipboard");
            wipe_string(&mut Some(text));
            return Ok(());
        }
        wipe_string(&mut self.owned);
        wipe_string(&mut self.last);
        self.last = Some(text.clone());
        self.owned = Some(text);
        self.echo = Some(Instant::now());
        Ok(())
    }

    /// The local clipboard no longer holds text we know of.
    fn forget(&mut self) {
        wipe_string(&mut self.last);
        self.echo = None;
    }

    fn on_event(&mut self, ev: Event, on_change: &dyn Fn(String)) -> Result<()> {
        match ev {
            // From the server only: any client can send events to our window (bit 0x80 set).
            Event::Other(raw) if raw[0] == self.xfixes.first_event => {
                // XFixesSelectionNotify: window, owner, selection, ...
                let owner = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
                let selection = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
                if selection == self.atoms.clipboard && owner != self.win {
                    wipe_string(&mut self.owned);
                    self.fetch = None;
                    if owner != NONE {
                        self.request(self.atoms.utf8)?;
                    } else {
                        // Released, or its owner went away: the clipboard is empty now.
                        self.forget();
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
                    } else {
                        self.forget(); // not text
                    }
                    return Ok(());
                }
                if property != self.atoms.property {
                    // Not where we asked for it (an owner gone wrong, or a forged event).
                    self.forget();
                    return Ok(());
                }
                let p = self.conn.get_property(self.win, property, ANY_PROPERTY_TYPE, MAX_CLIPBOARD + 4, true)?;
                if p.kind == self.atoms.incr {
                    // Deleting the property (done above) starts the transfer.
                    self.fetch = Some(Fetch::Incremental(target, Some(Vec::new())));
                } else if p.bytes_after > 0 || p.value.len() > MAX_CLIPBOARD {
                    log!("local clipboard text is too large to share");
                    // Not read whole, so not deleted with the read.
                    self.conn.delete_property(self.win, property)?;
                    self.forget();
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
                if p.bytes_after > 0 {
                    // A chunk too large to read whole: deleted by hand, so the owner goes on to
                    // the next (drained, like the rest).
                    self.conn.delete_property(self.win, atom)?;
                    if let Some(b) = buf {
                        wipe(b);
                        *buf = None;
                    }
                } else if p.value.is_empty() {
                    let done = buf.take();
                    self.fetch = None;
                    match done {
                        Some(mut all) => {
                            let kind = if target == ATOM_STRING { ATOM_STRING } else { self.atoms.utf8 };
                            self.report(decode_text(kind, ATOM_STRING, &all), on_change);
                            wipe(&mut all);
                        }
                        None => {
                            log!("local clipboard text is too large to share");
                            self.forget();
                        }
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
        // Whatever an earlier transfer left there goes first.
        self.conn.delete_property(self.win, self.atoms.property)?;
        self.conn.convert_selection(self.win, self.atoms.clipboard, target, self.atoms.property, CURRENT_TIME)
    }

    /// Passes on text a local application now offers. Text the remote side just sent is not
    /// echoed back; text copied again locally is sent again (the remote clipboard may have
    /// changed to something that is not text in the meantime).
    fn report(&mut self, mut text: String, on_change: &dyn Fn(String)) {
        let echo = self.echo.take().is_some_and(|at| at.elapsed() < ECHO_WINDOW);
        if text.is_empty() {
            self.forget();
            return;
        }
        if limit(&mut text) {
            log!("local clipboard text is too large to share whole; only its first {} KiB are sent", MAX_CLIPBOARD / 1024);
        }
        if echo && self.last.as_deref() == Some(text.as_str()) {
            wipe_string(&mut Some(text));
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

    #[test]
    fn text_encodings() {
        assert_eq!(to_latin1("café 안녕"), b"caf\xe9 ??");
        assert_eq!(from_latin1(b"caf\xe9"), "café");
        assert_eq!(decode_text(31, 31, b"caf\xe9\0"), "café");
        assert_eq!(decode_text(99, 31, "안녕\0".as_bytes()), "안녕");
        assert_eq!(decode_text(99, 31, b"bad \xff utf8"), "bad \u{fffd} utf8");
    }

    #[test]
    fn shared_text_never_exceeds_the_limit() {
        // Latin-1 grows when decoded: within the limit as selection bytes, beyond it as text.
        let mut t = decode_text(31, 31, &vec![0xe9; MAX_CLIPBOARD * 3 / 4]);
        assert!(t.len() > MAX_CLIPBOARD);
        assert!(limit(&mut t));
        assert_eq!(t.len(), MAX_CLIPBOARD);
        assert!(t.chars().all(|c| c == 'é'));
        // Each invalid UTF-8 byte becomes U+FFFD (3 bytes); the cut lands between characters.
        let mut t = decode_text(99, 31, &vec![0xff; MAX_CLIPBOARD / 2]);
        assert!(limit(&mut t));
        assert_eq!(t.len(), MAX_CLIPBOARD / 3 * 3);
        assert!(t.chars().all(|c| c == '\u{fffd}'));
        let mut t = "a".repeat(MAX_CLIPBOARD);
        assert!(!limit(&mut t));
        assert_eq!(t.len(), MAX_CLIPBOARD);
    }

    /// Makes window `win` of `c` the CLIPBOARD owner and turns down the next `n` conversions
    /// asked of it, like an application holding an image.
    fn refuse_conversions(c: &mut Conn, win: u32, clipboard: u32, n: usize) {
        c.set_selection_owner(win, clipboard, CURRENT_TIME).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut refused = 0;
        while refused < n {
            assert!(Instant::now() < deadline, "no conversion was asked for");
            let ev = c.wait_event(Duration::from_millis(50)).unwrap();
            if let Some(Event::SelectionRequest { time, requestor, selection, target, .. }) = ev {
                let mut ev = [0u8; 32];
                ev[0] = 31; // SelectionNotify
                for (i, v) in [time, requestor, selection, target, NONE].iter().enumerate() {
                    ev[4 + 4 * i..8 + 4 * i].copy_from_slice(&v.to_le_bytes());
                }
                c.send_event(requestor, 0, &ev).unwrap();
                refused += 1;
            }
        }
    }

    /// The same text sent or copied again after the clipboard changed in ways that are not
    /// shared (its owner left, or it held something that is not text) gets through.
    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn same_text_again_after_unshared_changes() {
        let vd = VirtualDisplay::spawn(Some(81), 200, 200, None).unwrap();
        let t = vd.target();
        let (atx, arx) = mpsc::channel();
        let a = Clipboard::spawn_on(t.clone(), move |s| atx.send(s).unwrap()).unwrap();
        let mut c = Conn::connect(&t).unwrap();
        let clipboard = c.atom("CLIPBOARD").unwrap();
        let root = c.root();
        let win = c.create_window(root, 0, 0, 1, 1, 2, 0, &[]).unwrap();
        let wait_owner = |c: &mut Conn, want: &dyn Fn(u32) -> bool| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !want(c.get_selection_owner(clipboard).unwrap()) {
                assert!(Instant::now() < deadline, "clipboard owner did not change");
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        let text = "make deploy";

        // A local application copies the text and exits: nobody owns the clipboard.
        let app = Clipboard::spawn_on(t.clone(), |_| {}).unwrap();
        app.set(text.into());
        assert_eq!(wait_for(&arx), text);
        drop(app);
        wait_owner(&mut c, &|o| o == NONE);
        std::thread::sleep(Duration::from_millis(300));
        // The remote side sends the same text again: it is offered locally.
        a.set(text.into());
        wait_owner(&mut c, &|o| o != NONE);
        let a_win = c.get_selection_owner(clipboard).unwrap();

        // An application that offers no text (UTF8_STRING, then STRING refused) takes the
        // clipboard, and the remote side sends the same text again.
        refuse_conversions(&mut c, win, clipboard, 2);
        std::thread::sleep(Duration::from_millis(300));
        assert!(arx.try_recv().is_err());
        a.set(text.into());
        wait_owner(&mut c, &|o| o == a_win);

        // The first local offer of text the remote side sent is its echo; a second is a copy.
        let app = Clipboard::spawn_on(t.clone(), |_| {}).unwrap();
        app.set(text.into());
        assert!(arx.recv_timeout(Duration::from_millis(700)).is_err(), "echoed the remote text");
        app.set(text.into());
        assert_eq!(wait_for(&arx), text);

        drop(app);
        wait_owner(&mut c, &|o| o == NONE);
        std::thread::sleep(Duration::from_millis(300));

        // Long after the remote side sent text, a local copy of the same text is no echo (with
        // no clipboard manager, no echo ever came).
        let text = "make test";
        a.set(text.into());
        wait_owner(&mut c, &|o| o == a_win);
        std::thread::sleep(ECHO_WINDOW + Duration::from_millis(300));
        let app = Clipboard::spawn_on(t.clone(), |_| {}).unwrap();
        app.set(text.into());
        assert_eq!(wait_for(&arx), text);
        drop(app);
        drop(a);
    }

    /// Waits for the next conversion asked of `c`'s selection and answers it with `property`,
    /// after `prepare` (given the requestor and its property) has run.
    fn answer_next(c: &mut Conn, property: u32, prepare: impl FnOnce(&mut Conn, u32, u32)) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(Instant::now() < deadline, "no conversion was asked for");
            if let Some(Event::SelectionRequest { time, requestor, selection, target, property: asked }) =
                c.wait_event(Duration::from_millis(50)).unwrap()
            {
                prepare(c, requestor, asked);
                let mut ev = [0u8; 32];
                ev[0] = 31; // SelectionNotify
                for (i, v) in [time, requestor, selection, target, property].iter().enumerate() {
                    ev[4 + 4 * i..8 + 4 * i].copy_from_slice(&v.to_le_bytes());
                }
                c.send_event(requestor, 0, &ev).unwrap();
                c.sync().unwrap();
                return;
            }
        }
    }

    /// Other local clients can send the bridge any event and answer its conversions with
    /// anything: none of that stops clipboard sharing, nor leaves text the bridge refused
    /// behind on its window.
    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn survives_forged_events_and_bad_answers() {
        let vd = VirtualDisplay::spawn(Some(95), 200, 200, None).unwrap();
        let t = vd.target();
        let (atx, arx) = mpsc::channel();
        let a = Clipboard::spawn_on(t.clone(), move |s| atx.send(s).unwrap()).unwrap();
        let mut c = Conn::connect(&t).unwrap();
        let (clipboard, utf8) = (c.atom("CLIPBOARD").unwrap(), c.atom("UTF8_STRING").unwrap());
        let (theirs, prop) = (c.atom("SAFE_RDP_SELECTION").unwrap(), c.atom("P").unwrap());
        let root = c.root();
        let win = c.create_window(root, 0, 0, 1, 1, 2, 0, &[]).unwrap();
        let fetch = |c: &mut Conn| {
            c.convert_selection(win, clipboard, utf8, prop, CURRENT_TIME).unwrap();
            loop {
                if let Some(Event::SelectionNotify { property, .. }) = c.wait_event(Duration::from_secs(5)).unwrap() {
                    return (property != NONE).then(|| c.get_property(win, prop, ANY_PROPERTY_TYPE, 1 << 16, true).unwrap().value);
                }
            }
        };

        // A forged XFixesSelectionNotify (sent, so with bit 0x80) saying someone else took the
        // clipboard: the bridge keeps offering the remote text.
        a.set("remote text".into());
        let deadline = Instant::now() + Duration::from_secs(5);
        while fetch(&mut c).as_deref() != Some(b"remote text".as_slice()) {
            assert!(Instant::now() < deadline, "the remote text was not offered");
            std::thread::sleep(Duration::from_millis(20));
        }
        let bridge = c.get_selection_owner(clipboard).unwrap();
        let xfixes = c.xfixes().unwrap().unwrap();
        let mut ev = [0u8; 32];
        ev[0] = xfixes.first_event | 0x80;
        for (at, v) in [(4, bridge), (8, win), (12, clipboard)] {
            ev[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        c.send_event(bridge, 0, &ev).unwrap();
        c.sync().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(fetch(&mut c).as_deref(), Some(b"remote text".as_slice()), "a forged event took the text away");

        // An owner naming a property the bridge did not ask for (an atom that does not even
        // exist): the bridge goes on.
        c.set_selection_owner(win, clipboard, CURRENT_TIME).unwrap();
        answer_next(&mut c, 0x0fff_ffff, |_, _, _| {});
        // An owner putting more text than may be shared in one property: refused, and deleted.
        c.set_selection_owner(win, clipboard, CURRENT_TIME).unwrap();
        let too_much = vec![b'x'; MAX_CLIPBOARD + 100];
        answer_next(&mut c, theirs, |c, requestor, asked| {
            assert_eq!(asked, theirs);
            c.change_property(requestor, asked, utf8, 8, &too_much).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while c.get_property(bridge, theirs, ANY_PROPERTY_TYPE, 4, false).unwrap().kind != NONE {
            assert!(Instant::now() < deadline, "the refused text was left on the bridge's window");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(arx.try_recv().is_err());

        // Still sharing: a local copy reaches the remote side.
        let app = Clipboard::spawn_on(t.clone(), |_| {}).unwrap();
        app.set("copied here".into());
        assert_eq!(wait_for(&arx), "copied here");
        drop(app);
        drop(a);
    }

    fn wait_for(rx: &mpsc::Receiver<String>) -> String {
        rx.recv_timeout(Duration::from_secs(5)).expect("no clipboard change reported")
    }

    /// Remote texts sent while the bridge thread is busy passing a local change on (to a
    /// stalled viewer, on a host) do not pile up; once it is free, the newest is offered.
    #[test]
    #[ignore = "needs Xvfb; run on the Linux test host with --ignored"]
    fn a_busy_bridge_offers_the_newest_text() {
        let vd = VirtualDisplay::spawn(Some(84), 200, 200, None).unwrap();
        let t = vd.target();
        let (busy_tx, busy_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let a = Clipboard::spawn_on(t.clone(), move |_| {
            let _ = busy_tx.send(());
            let _ = release_rx.recv();
        })
        .unwrap();
        let app = Clipboard::spawn_on(t.clone(), |_| {}).unwrap();
        app.set("copied here".into());
        busy_rx.recv_timeout(Duration::from_secs(5)).expect("the local copy was not reported");
        for i in 0..1000 {
            a.set(format!("{i:04} {}", "x".repeat(1024)));
        }
        drop(release_tx);

        let mut c = Conn::connect(&t).unwrap();
        let root = c.root();
        let win = c.create_window(root, 0, 0, 1, 1, 2, 0, &[]).unwrap();
        let (clipboard, utf8, prop) = (c.atom("CLIPBOARD").unwrap(), c.atom("UTF8_STRING").unwrap(), c.atom("P").unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(Instant::now() < deadline, "the newest text was not offered");
            c.convert_selection(win, clipboard, utf8, prop, CURRENT_TIME).unwrap();
            let answered = c.wait_event(Duration::from_secs(1)).unwrap();
            if matches!(answered, Some(Event::SelectionNotify { property, .. }) if property == prop)
                && c.get_property(win, prop, ANY_PROPERTY_TYPE, 1 << 16, true).unwrap().value.starts_with(b"0999 ")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(app);
        drop(a);
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
