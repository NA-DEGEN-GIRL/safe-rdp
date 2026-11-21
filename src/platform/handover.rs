//! Hand-over of remote clipboard text to a clipboard bridge thread, shared by both platforms'
//! `clipboard::Clipboard`.
//!
//! Only the newest text matters, so one the bridge thread has not taken yet is replaced (and
//! wiped), never queued behind: on a host that thread also passes local changes on to the
//! viewer, which keeps it busy for as long as the viewer stalls its side of the connection,
//! while the same viewer can send texts of up to `MAX_CLIPBOARD` bytes as fast as it likes. At
//! most one text waits here.

use crate::util::wipe;
use std::sync::{Mutex, MutexGuard};

#[derive(Default)]
pub struct Handover(Mutex<Slot>);

#[derive(Default)]
struct Slot {
    text: Option<String>,
    /// Nothing takes text any more (the session dropped its `Clipboard`, or the bridge ended).
    closed: bool,
}

fn wipe_text(text: Option<String>) {
    if let Some(mut t) = text {
        // NUL bytes keep the string valid UTF-8.
        unsafe { wipe(t.as_bytes_mut()) };
    }
}

impl Handover {
    fn slot(&self) -> MutexGuard<'_, Slot> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Leaves `text` for the bridge thread in place of any it has not taken yet. True when
    /// nothing was waiting, so the thread must be woken (otherwise a wake-up is already due);
    /// false, with `text` wiped, once closed.
    pub fn put(&self, text: String) -> bool {
        let mut s = self.slot();
        if s.closed {
            drop(s);
            wipe_text(Some(text));
            return false;
        }
        let old = s.text.replace(text);
        drop(s);
        let wake = old.is_none();
        wipe_text(old);
        wake
    }

    /// The newest text left, if any.
    pub fn take(&self) -> Option<String> {
        self.slot().text.take()
    }

    /// Wipes the text left, if any: one nothing is going to take.
    #[cfg_attr(not(windows), allow(dead_code))] // the Windows bridge
    pub fn discard(&self) {
        wipe_text(self.take());
    }

    /// Wipes the text left, and every text put from now on.
    pub fn close(&self) {
        let mut s = self.slot();
        s.closed = true;
        let old = s.text.take();
        drop(s);
        wipe_text(old);
    }

    #[cfg_attr(windows, allow(dead_code))] // the Linux bridge
    pub fn is_closed(&self) -> bool {
        self.slot().closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn only_the_newest_text_waits() {
        let h = Handover::default();
        assert_eq!(h.take(), None);
        assert!(h.put("a".into()), "the first text wakes the thread");
        assert!(!h.put("b".into()), "a wake-up is already due");
        assert!(!h.put("c".into()));
        assert_eq!(h.take().as_deref(), Some("c"));
        assert_eq!(h.take(), None);
        assert!(h.put("d".into()), "taken: the next text wakes it again");
        h.discard();
        assert_eq!(h.take(), None);
        assert!(h.put("e".into()));
        assert!(!h.is_closed());
        h.close();
        assert!(h.is_closed());
        assert_eq!(h.take(), None, "closing wipes what was left");
        assert!(!h.put("f".into()));
        assert_eq!(h.take(), None, "nothing is kept once closed");
    }

    /// A producer far faster than a busy taker: the taker sees ever newer texts, never an
    /// older one after a newer, and always the last one in the end.
    #[test]
    fn a_slow_taker_gets_the_latest() {
        let h = Arc::new(Handover::default());
        let p = h.clone();
        let producer = std::thread::spawn(move || {
            for i in 1..=20_000u32 {
                p.put(i.to_string());
            }
        });
        let mut last = 0;
        loop {
            let done = producer.is_finished();
            match h.take() {
                Some(t) => {
                    let i: u32 = t.parse().unwrap();
                    assert!(i > last, "{i} after {last}");
                    last = i;
                }
                None if done => break,
                None => {}
            }
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        producer.join().unwrap();
        assert_eq!(last, 20_000);
    }
}
