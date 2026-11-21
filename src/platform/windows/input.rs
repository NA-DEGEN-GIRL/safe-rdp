//! Input injection on the host via SendInput.

use super::capture::virtual_screen;
use super::desktop::DesktopFollower;
use crate::screen::Area;
use crate::proto::*;
use std::collections::{HashSet, VecDeque};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{XBUTTON1, XBUTTON2};

/// Tags kept for events the privacy hooks have not seen yet; the oldest make room.
const MAX_PENDING: usize = 4096;
/// How long the keys Windows adds to an event of ours may still pass the privacy hooks after the
/// SendInput call with that event has returned. The hooks run within the call; this is only a
/// margin, should one of them get to see the event late.
const ADDED_GRACE: Duration = Duration::from_millis(250);
/// How often releases that Windows refused are sent again (see `Injector::retry_owed`), and for
/// how long after their session ended (see `Leftovers`).
const RETRY_EVERY: Duration = Duration::from_millis(500);
const RETRY_FOR: Duration = Duration::from_secs(600);

/// A key that Windows adds of its own, untagged, to an event we inject. The privacy hooks let
/// one through for each event of ours that brings it, while that event is on its way.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Added {
    /// The Left Ctrl in front of every Right Alt press and release while the layout has AltGr.
    AltGrCtrl,
    /// With Num Lock on, a Shift held down is let go before a numpad key and pressed again after
    /// it (Shift+Numpad7 is a plain Home); Left (false) or Right (true) Shift.
    NumpadShift(bool),
}

/// An `Added` key that may pass for the event tagged `tag`.
struct Allowance {
    tag: usize,
    key: Added,
    /// When it stops counting; `None` while the SendInput call with the event runs.
    until: Option<Instant>,
}

/// Tags of the events we injected that no privacy hook has passed yet, oldest first. Tags are
/// recorded only while privacy mode is on ("armed"): an event sent while it is off reaches
/// other programs' hooks and windows with its tag unused, so that tag must never open the
/// privacy hooks later.
struct Pending {
    armed: bool,
    tags: VecDeque<usize>,
    /// The keys Windows may add to the events of ours on their way, oldest first.
    added: VecDeque<Allowance>,
}

impl Pending {
    const fn new() -> Pending {
        Pending { armed: false, tags: VecDeque::new(), added: VecDeque::new() }
    }

    fn arm(&mut self, on: bool) {
        self.armed = on;
        self.tags.clear();
        self.added.clear();
    }

    fn add(&mut self, tag: usize) {
        if !self.armed {
            return;
        }
        if self.tags.len() >= MAX_PENDING {
            self.tags.pop_front();
        }
        self.tags.push_back(tag);
    }

    /// Removes `tag`; false if it is not (or no longer) there. The newest come first: with the
    /// hooks running, the event they are looking at was sent moments ago.
    fn take(&mut self, tag: usize) -> bool {
        match self.tags.iter().rposition(|&t| t == tag) {
            Some(i) => {
                self.tags.remove(i);
                // AltGr's Left Ctrl comes in front of its Right Alt, never after it.
                self.added.retain(|a| a.tag != tag || a.key != Added::AltGrCtrl);
                true
            }
            None => false,
        }
    }

    /// Lets `key` pass for the event tagged `tag`, which is about to be sent.
    fn allow(&mut self, tag: usize, key: Added) {
        if !self.armed {
            return;
        }
        if self.added.len() >= MAX_PENDING {
            self.added.pop_front();
        }
        self.added.push_back(Allowance { tag, key, until: None });
    }

    /// The SendInput call with the event tagged `tag` has returned, having sent it or not. A
    /// sent event's allowances run out shortly; a refused one reached nobody, and its tag and
    /// allowances are withdrawn.
    fn sent(&mut self, tag: usize, sent: bool, now: Instant) {
        if sent {
            for a in self.added.iter_mut().filter(|a| a.tag == tag && a.until.is_none()) {
                a.until = Some(now + ADDED_GRACE);
            }
        } else {
            self.take(tag);
            self.added.retain(|a| a.tag != tag);
        }
    }

    /// Uses up the newest allowance for `key` that still counts.
    fn take_added(&mut self, key: Added, now: Instant) -> bool {
        self.added.retain(|a| a.until.is_none_or(|t| now < t));
        match self.added.iter().rposition(|a| a.key == key) {
            Some(i) => {
                self.added.remove(i);
                true
            }
            None => false,
        }
    }
}

static PENDING: Mutex<Pending> = Mutex::new(Pending::new());

/// Called by privacy mode once its hooks are in place (`true`) and after they are gone
/// (`false`). Either way every tag issued so far stops counting.
pub fn arm(on: bool) {
    PENDING.lock().unwrap_or_else(PoisonError::into_inner).arm(on);
}

/// A fresh random marker for the `dwExtraInfo` of one event we inject, recorded (while privacy
/// mode is on) for the privacy hooks, which let an injected event through only with a tag they
/// have not seen before.
pub fn new_tag() -> usize {
    let mut b = [0u8; size_of::<usize>()];
    if crate::crypto::random(&mut b).is_err() {
        // CNG does not fail in practice; std's hash keys come from the OS generator too.
        use std::hash::{BuildHasher, RandomState};
        b = (RandomState::new().hash_one(std::process::id()) as usize).to_ne_bytes();
    }
    // Never 0 (what other programs send) nor the pen/touch signature 0xFF5157xx.
    let tag = (usize::from_ne_bytes(b) & !0x8000_0000) | 1;
    PENDING.lock().unwrap_or_else(PoisonError::into_inner).add(tag);
    tag
}

/// Called by the privacy hooks: whether `tag` is that of an event we injected, which it then
/// stops being. Each tag lets one event through.
pub fn take_tag(tag: usize) -> bool {
    PENDING.lock().unwrap_or_else(PoisonError::into_inner).take(tag)
}

/// Called by the privacy hooks for the Left Ctrl that Windows adds, untagged, in front of every
/// Right Alt press and release while the layout has AltGr: whether a Right Alt of ours is on
/// its way (in our SendInput call, and not seen by the hooks yet) that has not had its Left
/// Ctrl. One each.
pub fn take_altgr_ctrl() -> bool {
    PENDING.lock().unwrap_or_else(PoisonError::into_inner).take_added(Added::AltGrCtrl, Instant::now())
}

/// Called by the privacy hooks for the Shift, Left or Right (`right`), that Windows lets go of
/// and presses again, untagged, around a numpad key while Num Lock is on: whether a numpad key
/// of ours is on its way (in our SendInput call) while we hold that Shift. One each.
pub fn take_numpad_shift(right: bool) -> bool {
    PENDING.lock().unwrap_or_else(PoisonError::into_inner).take_added(Added::NumpadShift(right), Instant::now())
}

/// A tag for a Right Alt event on its way, for the privacy hooks' tests.
#[cfg(test)]
pub fn new_right_alt_tag() -> usize {
    let tag = new_tag();
    PENDING.lock().unwrap_or_else(PoisonError::into_inner).allow(tag, Added::AltGrCtrl);
    tag
}

/// A tag for a numpad key on its way while we hold the Left or Right (`right`) Shift, for the
/// privacy hooks' tests.
#[cfg(test)]
pub fn new_numpad_tag(right: bool) -> usize {
    let tag = new_tag();
    PENDING.lock().unwrap_or_else(PoisonError::into_inner).allow(tag, Added::NumpadShift(right));
    tag
}

/// The tagged event's SendInput call has returned this long ago, for the privacy hooks' tests.
#[cfg(test)]
pub fn sent_for_test(tag: usize, ago: Duration) {
    PENDING.lock().unwrap_or_else(PoisonError::into_inner).sent(tag, true, Instant::now() - ago);
}

/// Tests that use the process-wide tags hold this, with privacy mode's arming simulated.
#[cfg(test)]
pub fn armed_for_test() -> impl Drop {
    static LOCK: Mutex<()> = Mutex::new(());
    struct Armed(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
    impl Drop for Armed {
        fn drop(&mut self) {
            arm(false);
        }
    }
    let guard = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    arm(true);
    Armed(guard)
}

/// A key as we inject it. Only valid keys are made (`from_wire`), which bounds how many
/// different ones a viewer can hold down to a few thousand.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct HeldKey {
    /// 0 for keys injected by scancode, where the host's layout supplies the virtual key.
    vk: u16,
    /// A set-1 scancode without its E0 prefix, which is `extended`.
    scan: u16,
    extended: bool,
}

impl HeldKey {
    /// The key a `Key` message names, or `None` if it names none.
    fn from_wire(vk: u16, scan: u16, flags: u8) -> Option<HeldKey> {
        // Some senders fold the E0 prefix into the scancode.
        let (scan, mut extended) = if scan >> 8 == 0xe0 { (scan & 0xff, true) } else { (scan, flags & KEY_EXTENDED != 0) };
        // Unicode input on the viewer comes as VK_PACKET with a UTF-16 code unit where the
        // scancode goes; pressed as a scancode that would be some unrelated key. Anything else
        // above 0xff is not a scancode either (AltGr's simulated Left Ctrl is 0x21D).
        if vk == VK_PACKET || scan > 0xff {
            return None;
        }
        if inject_by_vk(vk, scan) {
            // Virtual keys run from 1 to 254.
            return (1..=0xfe).contains(&vk).then_some(HeldKey { vk, scan, extended });
        }
        // Windows reports Right Shift and Num Lock as extended although neither scancode has
        // an E0 form; sent with the prefix they would be no key at all.
        if matches!(scan, 0x36 | 0x45) {
            extended = false;
        }
        Some(HeldKey { vk: 0, scan, extended })
    }

    /// The key that a keyboard event of ours (made by `key`) presses or releases.
    fn of(ki: &KEYBDINPUT) -> HeldKey {
        let vk = if ki.dwFlags & KEYEVENTF_SCANCODE != 0 { 0 } else { ki.wVk };
        HeldKey { vk, scan: ki.wScan, extended: ki.dwFlags & KEYEVENTF_EXTENDEDKEY != 0 }
    }

    /// Right Alt, which is AltGr on layouts that have one.
    fn is_right_alt(self) -> bool {
        if inject_by_vk(self.vk, self.scan) {
            self.vk == VK_RMENU || (self.vk == VK_MENU && self.extended)
        } else {
            self.scan == 0x38 && self.extended
        }
    }

    /// A numpad key that Num Lock turns into a digit (KBDNUMPAD in kbd.h): 7 8 9, 4 5 6,
    /// 1 2 3, 0 and the decimal point.
    fn is_numpad(self) -> bool {
        !inject_by_vk(self.vk, self.scan) && !self.extended && matches!(self.scan, 0x47..=0x49 | 0x4b..=0x4d | 0x4f..=0x53)
    }

    /// Left (false) or Right (true) Shift, if this is one.
    fn shift(self) -> Option<bool> {
        if inject_by_vk(self.vk, self.scan) {
            match self.vk {
                VK_LSHIFT => Some(false),
                VK_RSHIFT => Some(true),
                _ => None,
            }
        } else {
            match (self.scan, self.extended) {
                (0x2a, false) => Some(false),
                (0x36, false) => Some(true),
                _ => None,
            }
        }
    }
}

/// A key or mouse button the remote user can hold down.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Held {
    Key(HeldKey),
    /// An index into `BUTTON_FLAGS`.
    Button(usize),
}

impl Held {
    fn release(self) -> INPUT {
        match self {
            Held::Key(k) => key(k, true),
            Held::Button(i) => {
                let (_, uf, data) = BUTTON_FLAGS[i];
                mouse(0, 0, data, uf)
            }
        }
    }
}

/// Injects the remote user's input. Like the `DesktopFollower` it holds, it must be used and
/// dropped on the thread that created it.
pub struct Injector {
    area: Area,
    /// Keys and buttons the remote user holds down.
    keys: HashSet<HeldKey>,
    buttons: [bool; 5],
    /// Releases Windows refused, sent again ahead of the next event, by `retry_owed` and by
    /// `release_all`: a lost release would leave the key held down on the host. Those still
    /// owed when the injector is dropped become `Leftovers`.
    owed: Vec<Held>,
    /// When `retry_owed` may try them again.
    retry_at: Instant,
    /// The host follows the input desktop now and then; this follows it the moment Windows
    /// refuses an event, so that the event goes to the new desktop instead of nowhere.
    desktop: DesktopFollower,
}

impl Default for Injector {
    fn default() -> Injector {
        // Releases an earlier session could not send go out ahead of this one's first event,
        // or by `retry_owed` once the input desktop is back, whichever comes first.
        let owed = leftovers(|l| std::mem::take(&mut l.held));
        let desktop = DesktopFollower::new();
        Injector { area: Area::default(), keys: HashSet::new(), buttons: [false; 5], owed, retry_at: Instant::now(), desktop }
    }
}

/// Hands `inputs` to Windows and returns how many it took, which are the first ones: it takes
/// none while this thread is not on the input desktop. The tags of the rest never reached
/// anyone and are withdrawn. The keys Windows adds of its own to these events, given the
/// Shift keys (left, right) we hold, may pass the privacy hooks only while this call runs
/// (the hooks run within it) and for `ADDED_GRACE` after.
fn send(inputs: &[INPUT], shifts: [bool; 2]) -> usize {
    {
        let mut p = PENDING.lock().unwrap_or_else(PoisonError::into_inner);
        for i in inputs {
            for key in added(i, shifts).into_iter().flatten() {
                p.allow(extra_info(i), key);
            }
        }
    }
    let n = (send_input(inputs) as usize).min(inputs.len());
    let now = Instant::now();
    let mut p = PENDING.lock().unwrap_or_else(PoisonError::into_inner);
    for (k, i) in inputs.iter().enumerate() {
        p.sent(extra_info(i), k < n, now);
    }
    n
}

/// The keys Windows may add of its own to `i`, an event of ours, while we hold `shifts`.
fn added(i: &INPUT, shifts: [bool; 2]) -> [Option<Added>; 2] {
    if i.r#type != INPUT_KEYBOARD {
        return [None; 2];
    }
    let k = HeldKey::of(unsafe { &i.Anonymous.ki });
    if k.is_right_alt() {
        [Some(Added::AltGrCtrl), None]
    } else if k.is_numpad() {
        // Only a Shift of ours: one the person at the machine holds down stays theirs.
        [shifts[0].then_some(Added::NumpadShift(false)), shifts[1].then_some(Added::NumpadShift(true))]
    } else {
        [None; 2]
    }
}

fn send_input(inputs: &[INPUT]) -> u32 {
    #[cfg(test)]
    {
        if let Some(n) = tests::fake_send(inputs) {
            return n;
        }
    }
    unsafe { SendInput(inputs.len() as u32, inputs.as_ptr(), size_of::<INPUT>() as i32) }
}

fn extra_info(i: &INPUT) -> usize {
    unsafe { if i.r#type == INPUT_KEYBOARD { i.Anonymous.ki.dwExtraInfo } else { i.Anonymous.mi.dwExtraInfo } }
}

fn mouse(dx: i32, dy: i32, data: i32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT { dx, dy, mouseData: data as u32, dwFlags: flags, time: 0, dwExtraInfo: new_tag() },
        },
    }
}

/// Keys whose scancodes are ambiguous or layout-specific are injected by virtual-key code.
fn inject_by_vk(vk: u16, scan: u16) -> bool {
    scan == 0 || matches!(vk, VK_PAUSE | VK_HANGUL | VK_HANJA | VK_IME_ON | VK_IME_OFF)
}

fn key(k: HeldKey, up: bool) -> INPUT {
    let mut flags = if up { KEYEVENTF_KEYUP } else { 0 };
    if k.extended {
        flags |= KEYEVENTF_EXTENDEDKEY;
    }
    let vk = if inject_by_vk(k.vk, k.scan) {
        k.vk
    } else {
        flags |= KEYEVENTF_SCANCODE;
        0
    };
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT { wVk: vk, wScan: k.scan, dwFlags: flags, time: 0, dwExtraInfo: new_tag() },
        },
    }
}

const BUTTON_FLAGS: [(MOUSE_EVENT_FLAGS, MOUSE_EVENT_FLAGS, i32); 5] = [
    (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, 0),
    (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, 0),
    (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, 0),
    (MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, XBUTTON1 as i32),
    (MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, XBUTTON2 as i32),
];

impl Injector {
    pub fn set_area(&mut self, a: Area) {
        self.area = a;
    }

    pub fn handle(&mut self, m: &ClientMsg) {
        match *m {
            ClientMsg::MouseMove { x, y } => {
                let a = self.area;
                let v = virtual_screen();
                if a.width <= 0 || v.width <= 0 || v.height <= 0 {
                    return;
                }
                let px = (a.left + (x as i32).min(a.width - 1)) - v.left;
                let py = (a.top + (y as i32).min(a.height - 1)) - v.top;
                // Round up so that Windows' (n * size) >> 16 maps back to exactly this pixel.
                let nx = ((px as i64 * 65536 + v.width as i64 - 1) / v.width as i64) as i32;
                let ny = ((py as i64 * 65536 + v.height as i64 - 1) / v.height as i64) as i32;
                self.deliver(Some(&|| mouse(nx, ny, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK)));
            }
            ClientMsg::MouseButton { button, down } => {
                let Some(&(df, uf, data)) = BUTTON_FLAGS.get(button as usize) else { return };
                self.press(Held::Button(button as usize), down, &|| mouse(0, 0, data, if down { df } else { uf }));
            }
            ClientMsg::Wheel { delta, horizontal } => {
                self.deliver(Some(&|| mouse(0, 0, delta as i32, if horizontal { MOUSEEVENTF_HWHEEL } else { MOUSEEVENTF_WHEEL })));
            }
            ClientMsg::Key { vk, scan, flags } => {
                let Some(k) = HeldKey::from_wire(vk, scan, flags) else { return };
                let up = flags & KEY_UP != 0;
                self.press(Held::Key(k), !up, &|| key(k, up));
            }
            ClientMsg::ReleaseAll => self.release_all(),
            _ => {}
        }
    }

    /// Records `h` as held (`down`) or not and sends `event`, its press or release.
    fn press(&mut self, h: Held, down: bool, event: &dyn Fn() -> INPUT) {
        let was_held = match h {
            Held::Key(k) if down => !self.keys.insert(k),
            Held::Key(k) => self.keys.remove(&k),
            Held::Button(i) => std::mem::replace(&mut self.buttons[i], down),
        };
        if down {
            // Held again: the release still owed would now let go of it.
            self.owed.retain(|&o| o != h);
            self.deliver(Some(event));
        } else if !self.deliver(Some(event)) && was_held {
            self.owe(h);
        }
    }

    fn owe(&mut self, h: Held) {
        owe(&mut self.owed, h);
    }

    /// Sends `event`, if any, behind the releases still owed (see `send_behind`).
    fn deliver(&mut self, event: Option<&dyn Fn() -> INPUT>) -> bool {
        let shifts = self.shifts();
        let desktop = &mut self.desktop;
        send_behind(&mut self.owed, event, shifts, &mut || follow(desktop))
    }

    /// The Shift keys (left, right) the remote user holds down.
    fn shifts(&self) -> [bool; 2] {
        let mut held = [false; 2];
        for right in self.keys.iter().filter_map(|k| k.shift()) {
            held[right as usize] = true;
        }
        held
    }

    /// Releases every key and button the remote user still holds down, and whatever release
    /// Windows refused before.
    pub fn release_all(&mut self) {
        let keys: Vec<HeldKey> = self.keys.drain().collect();
        for k in keys {
            self.owe(Held::Key(k));
        }
        for i in 0..self.buttons.len() {
            if std::mem::take(&mut self.buttons[i]) {
                self.owe(Held::Button(i));
            }
        }
        self.deliver(None);
    }

    /// Tries again, at most every `RETRY_EVERY`, to send the releases still owed, those taken
    /// over from an earlier session included. The input thread calls this between messages, so
    /// that they go out soon after the input desktop is back even when the viewer sends no
    /// input (view-only, the probe, or left alone): until then the keys stay held on the host.
    pub fn retry_owed(&mut self) {
        let now = Instant::now();
        if self.owed.is_empty() || now < self.retry_at {
            return;
        }
        self.retry_at = now + RETRY_EVERY;
        self.deliver(None);
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        self.release_all();
        if !self.owed.is_empty() {
            crate::log!("{} held keys or buttons could not be released yet: the input desktop is out of reach", self.owed.len());
            leave_over(std::mem::take(&mut self.owed));
        }
    }
}

fn owe(owed: &mut Vec<Held>, h: Held) {
    if !owed.contains(&h) {
        owed.push(h);
    }
}

/// Sends `event`, if any, behind the releases still `owed`, given the Shift keys we hold
/// (`send`). When Windows takes none of it, this thread is usually no longer on the input
/// desktop (Ctrl+Alt+Del, a UAC prompt, the lock screen): `follow` it there and try once more.
/// Returns whether `event` went out.
fn send_behind(owed: &mut Vec<Held>, event: Option<&dyn Fn() -> INPUT>, shifts: [bool; 2], follow: &mut dyn FnMut() -> bool) -> bool {
    for retry in [false, true] {
        if retry && !follow() {
            break;
        }
        // Fresh events (and tags) each time: `send` withdrew those of a refused attempt.
        let mut inputs: Vec<INPUT> = owed.iter().map(|h| h.release()).collect();
        inputs.extend(event.map(|e| e()));
        if inputs.is_empty() {
            return true;
        }
        let sent = send(&inputs, shifts);
        owed.drain(..sent.min(owed.len()));
        if sent == inputs.len() {
            return true;
        }
    }
    false
}

/// Moves this thread to the input desktop if it is elsewhere; true if it moved.
fn follow(desktop: &mut DesktopFollower) -> bool {
    #[cfg(test)]
    {
        if let Some(moved) = tests::fake_follow() {
            return moved;
        }
    }
    desktop.sync()
}

/// Releases still owed when their injector was dropped: its session ended while the input
/// desktop was out of reach (the lock screen or a UAC prompt, for a host that is not a
/// service), and the viewer that could have sent more input is gone. The next injector takes
/// them over, sends them ahead of anything else and keeps trying them (`retry_owed`); until
/// then a thread of their own tries every `RETRY_EVERY`, for `RETRY_FOR`, so that the keys are
/// let go of soon after the desktop comes back.
struct Leftovers {
    held: Vec<Held>,
    /// That thread is running.
    retrying: bool,
}

impl Leftovers {
    const fn new() -> Leftovers {
        Leftovers { held: Vec::new(), retrying: false }
    }
}

#[cfg(not(test))]
static LEFTOVERS: Mutex<Leftovers> = Mutex::new(Leftovers::new());

/// Runs `f` on this process's leftovers (in tests, on the test thread's own).
#[cfg(not(test))]
fn leftovers<T>(f: impl FnOnce(&mut Leftovers) -> T) -> T {
    f(&mut LEFTOVERS.lock().unwrap_or_else(PoisonError::into_inner))
}

#[cfg(test)]
use tests::leftovers;

/// Keeps `owed` for the next injector, and has a thread try them until then.
fn leave_over(owed: Vec<Held>) {
    leftovers(|l| {
        for h in owed {
            owe(&mut l.held, h);
        }
        if !l.retrying {
            l.retrying = spawn_retry();
        }
    });
}

/// Starts the thread that tries the leftovers again; false if it could not be started (the
/// next injector still sends them).
fn spawn_retry() -> bool {
    #[cfg(test)]
    {
        if let Some(started) = tests::fake_spawn() {
            return started;
        }
    }
    std::thread::Builder::new().name("releases".into()).spawn(retry_leftovers).is_ok()
}

/// Body of that thread.
fn retry_leftovers() {
    let mut desktop = DesktopFollower::new();
    let end = Instant::now() + RETRY_FOR;
    loop {
        std::thread::sleep(RETRY_EVERY);
        if !retry_once(&mut desktop, Instant::now() >= end) {
            break;
        }
    }
}

/// Tries once to send the leftovers. False when the thread is done: nothing is left (the next
/// injector may have taken them, and tries them from then on) or this was its `last` try.
fn retry_once(desktop: &mut DesktopFollower, last: bool) -> bool {
    leftovers(|l| {
        if !l.held.is_empty() {
            // Nothing is held down any more, so no Shift of ours either.
            send_behind(&mut l.held, None, [false; 2], &mut || follow(desktop));
            if l.held.is_empty() {
                crate::log!("held keys and buttons left over from an earlier session released");
            }
        }
        if l.held.is_empty() || last {
            if !l.held.is_empty() {
                crate::log!("{} held keys or buttons are still out of reach: the next session releases them first", l.held.len());
            }
            l.retrying = false;
            return false;
        }
        true
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetCursorPos, SetCursorPos};

    /// What an injector under test talks to instead of Windows: whether its thread is on the
    /// input desktop, whether it could get there, and what Windows took.
    #[derive(Default)]
    struct World {
        off_desktop: bool,
        /// The input desktop is out of reach (the lock screen, for a host that is not a service).
        unreachable: bool,
        taken: Vec<Ev>,
        taken_tags: Vec<usize>,
        refused_tags: Vec<usize>,
        /// Play the privacy hooks for the keys Windows adds: for each event taken, whether
        /// AltGr's Left Ctrl, a Left Shift and a Right Shift around a numpad key would pass.
        hook: bool,
        added: Vec<[bool; 3]>,
        /// Threads started to retry leftover releases (none really are).
        retry_threads: usize,
    }

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Ev {
        Key { vk: u16, scan: u16, flags: KEYBD_EVENT_FLAGS },
        Mouse { flags: MOUSE_EVENT_FLAGS, data: u32 },
    }

    fn ev(i: &INPUT) -> Ev {
        unsafe {
            if i.r#type == INPUT_KEYBOARD {
                let k = i.Anonymous.ki;
                Ev::Key { vk: k.wVk, scan: k.wScan, flags: k.dwFlags }
            } else {
                let m = i.Anonymous.mi;
                Ev::Mouse { flags: m.dwFlags, data: m.mouseData }
            }
        }
    }

    thread_local! {
        static WORLD: RefCell<World> = RefCell::new(World::default());
        /// Set by the one test that moves the real mouse; no other test injects anything.
        static REAL: Cell<bool> = const { Cell::new(false) };
        /// The leftovers of the sessions on this test thread.
        static LEFTOVERS: RefCell<Leftovers> = const { RefCell::new(Leftovers::new()) };
    }

    fn world<T>(f: impl FnOnce(&mut World) -> T) -> T {
        WORLD.with_borrow_mut(f)
    }

    pub(super) fn leftovers<T>(f: impl FnOnce(&mut Leftovers) -> T) -> T {
        LEFTOVERS.with_borrow_mut(f)
    }

    /// SendInput for the injector under test; `None` lets the real one run.
    pub(super) fn fake_send(inputs: &[INPUT]) -> Option<u32> {
        if REAL.get() {
            return None;
        }
        Some(world(|w| {
            if w.off_desktop {
                w.refused_tags.extend(inputs.iter().map(extra_info));
                return 0;
            }
            if w.hook {
                w.added.extend(inputs.iter().map(|_| [take_altgr_ctrl(), take_numpad_shift(false), take_numpad_shift(true)]));
            }
            w.taken.extend(inputs.iter().map(ev));
            w.taken_tags.extend(inputs.iter().map(extra_info));
            inputs.len() as u32
        }))
    }

    /// Starting the thread that retries leftover releases: counted, not done.
    pub(super) fn fake_spawn() -> Option<bool> {
        if REAL.get() {
            return None;
        }
        Some(world(|w| {
            w.retry_threads += 1;
            true
        }))
    }

    pub(super) fn fake_follow() -> Option<bool> {
        if REAL.get() {
            return None;
        }
        Some(world(|w| {
            let moved = w.off_desktop && !w.unreachable;
            w.off_desktop &= !moved;
            moved
        }))
    }

    const LCTRL: (u16, u16) = (0xa2, 0x1d);
    const LALT: (u16, u16) = (0xa4, 0x38);
    const LSHIFT: (u16, u16) = (0xa0, 0x2a);
    const A: (u16, u16) = (0x41, 0x1e);
    /// Numpad 7, which is Home while Num Lock is off.
    const NUM7: (u16, u16) = (0x24, 0x47);

    fn key_msg((vk, scan): (u16, u16), up: bool) -> ClientMsg {
        ClientMsg::Key { vk, scan, flags: if up { KEY_UP } else { 0 } }
    }

    fn held((vk, scan): (u16, u16)) -> Held {
        Held::Key(HeldKey::from_wire(vk, scan, 0).unwrap())
    }

    /// A key event sent by scancode.
    fn sc(scan: u16, up: bool) -> Ev {
        Ev::Key { vk: 0, scan, flags: KEYEVENTF_SCANCODE | if up { KEYEVENTF_KEYUP } else { 0 } }
    }

    #[test]
    fn a_refused_event_follows_the_input_desktop_and_goes_again() {
        let _armed = armed_for_test();
        let mut inj = Injector::default();
        inj.handle(&key_msg(LCTRL, false));
        // Ctrl+Alt+Del or a UAC prompt has switched the input desktop.
        world(|w| w.off_desktop = true);
        inj.handle(&key_msg(LCTRL, true));
        assert!(inj.owed.is_empty() && inj.keys.is_empty());
        assert_eq!(world(|w| std::mem::take(&mut w.taken)), [sc(0x1d, false), sc(0x1d, true)]);
        // The refused attempt's tag reached nobody and opens nothing; the second has its own.
        let (taken, refused) = world(|w| (w.taken_tags.clone(), w.refused_tags.clone()));
        assert_eq!((taken.len(), refused.len()), (2, 1));
        assert!(!taken.contains(&refused[0]));
        assert!(!take_tag(refused[0]), "a refused event's tag stayed pending");
        assert!(take_tag(taken[1]));
    }

    #[test]
    fn releases_windows_refused_go_out_ahead_of_the_next_event() {
        let _armed = armed_for_test();
        let mut inj = Injector::default();
        inj.handle(&key_msg(LCTRL, false));
        inj.handle(&ClientMsg::MouseButton { button: 0, down: true });
        world(|w| w.taken.clear());
        // The lock screen, which a host that is not a service cannot follow.
        world(|w| (w.off_desktop, w.unreachable) = (true, true));
        inj.handle(&key_msg(LCTRL, true));
        inj.handle(&ClientMsg::MouseButton { button: 0, down: false });
        inj.handle(&key_msg(A, false)); // lost, like anything typed at nowhere
        inj.handle(&ClientMsg::ReleaseAll);
        assert_eq!(inj.owed, [held(LCTRL), Held::Button(0), held(A)]);
        assert!(world(|w| w.taken.is_empty()));
        // Back on the input desktop: the releases first, then what comes next, all at once.
        world(|w| w.off_desktop = false);
        inj.handle(&ClientMsg::Wheel { delta: 120, horizontal: false });
        let left_up = Ev::Mouse { flags: MOUSEEVENTF_LEFTUP, data: 0 };
        let wheel = Ev::Mouse { flags: MOUSEEVENTF_WHEEL, data: 120 };
        assert_eq!(world(|w| std::mem::take(&mut w.taken)), [sc(0x1d, true), left_up, sc(0x1e, true), wheel]);
        assert!(inj.owed.is_empty());
        drop(inj);
        assert!(world(|w| w.taken.is_empty()), "released twice");
    }

    #[test]
    fn pressing_a_key_again_cancels_its_owed_release() {
        let _armed = armed_for_test();
        let mut inj = Injector::default();
        inj.handle(&key_msg(LALT, false));
        world(|w| (w.off_desktop, w.unreachable) = (true, true));
        inj.handle(&key_msg(LALT, true));
        assert_eq!(inj.owed, [held(LALT)]);
        inj.handle(&key_msg(LALT, false));
        assert!(inj.owed.is_empty());
        world(|w| (w.off_desktop, w.unreachable, w.taken) = (false, false, Vec::new()));
        inj.handle(&key_msg(LALT, false)); // auto-repeat
        inj.handle(&key_msg(LALT, true));
        assert_eq!(world(|w| std::mem::take(&mut w.taken)), [sc(0x38, false), sc(0x38, true)]);
        drop(inj);
        assert!(world(|w| w.taken.is_empty()));
    }

    #[test]
    fn release_all_follows_the_input_desktop_too() {
        let _armed = armed_for_test();
        let mut inj = Injector::default();
        inj.handle(&key_msg(LCTRL, false));
        inj.handle(&key_msg(LALT, false));
        inj.handle(&ClientMsg::MouseButton { button: 3, down: true });
        world(|w| w.taken.clear());
        world(|w| w.off_desktop = true);
        // The session ends at the Ctrl+Alt+Del screen.
        drop(inj);
        let mut taken = world(|w| std::mem::take(&mut w.taken));
        let x1_up = Ev::Mouse { flags: MOUSEEVENTF_XUP, data: XBUTTON1 as u32 };
        assert_eq!(taken.pop(), Some(x1_up));
        taken.sort_by_key(|e| format!("{e:?}"));
        assert_eq!(taken, [sc(0x1d, true), sc(0x38, true)]);
        assert!(leftovers(|l| l.held.is_empty()) && world(|w| w.retry_threads) == 0);
    }

    #[test]
    fn releases_a_session_could_not_send_go_out_once_the_desktop_is_back() {
        let _armed = armed_for_test();
        let mut inj = Injector::default();
        inj.handle(&key_msg(LCTRL, false));
        inj.handle(&ClientMsg::MouseButton { button: 0, down: true });
        world(|w| w.taken.clear());
        // A UAC prompt comes up, which a host that is not a service cannot follow, and the
        // viewer that sees only a frozen screen leaves.
        world(|w| (w.off_desktop, w.unreachable) = (true, true));
        inj.handle(&key_msg(LCTRL, true));
        drop(inj);
        assert_eq!(leftovers(|l| l.held.clone()), [held(LCTRL), Held::Button(0)]);
        assert_eq!(world(|w| w.retry_threads), 1);
        // The thread keeps trying while the prompt is up...
        let mut desktop = DesktopFollower::new();
        assert!(retry_once(&mut desktop, false));
        assert!(retry_once(&mut desktop, false));
        assert!(world(|w| w.taken.is_empty()));
        // ...and lets go of the keys once it is gone.
        world(|w| w.off_desktop = false);
        assert!(!retry_once(&mut desktop, false), "kept trying");
        let left_up = Ev::Mouse { flags: MOUSEEVENTF_LEFTUP, data: 0 };
        assert_eq!(world(|w| std::mem::take(&mut w.taken)), [sc(0x1d, true), left_up]);
        assert!(leftovers(|l| l.held.is_empty() && !l.retrying));
        // The next session ending out of reach starts it again; one at a time.
        for _ in 0..2 {
            let mut inj = Injector::default();
            inj.handle(&key_msg(LALT, false));
            world(|w| (w.off_desktop, w.unreachable) = (true, true));
            drop(inj);
            world(|w| (w.off_desktop, w.unreachable) = (false, false));
        }
        assert_eq!(world(|w| w.retry_threads), 2);
        assert_eq!(leftovers(|l| l.held.clone()), [held(LALT)]);
    }

    #[test]
    fn the_next_session_sends_the_releases_left_over_first() {
        let _armed = armed_for_test();
        let mut inj = Injector::default();
        inj.handle(&key_msg(LCTRL, false));
        inj.handle(&key_msg(LALT, false));
        world(|w| w.taken.clear());
        // The lock screen, and the viewer leaves.
        world(|w| (w.off_desktop, w.unreachable) = (true, true));
        drop(inj);
        // The thread has given up by the time anyone unlocks.
        let mut desktop = DesktopFollower::new();
        assert!(!retry_once(&mut desktop, true));
        assert_eq!(leftovers(|l| (l.held.len(), l.retrying)), (2, false));
        world(|w| w.off_desktop = false);
        let mut inj = Injector::default();
        assert!(leftovers(|l| l.held.is_empty()), "the next session did not take them over");
        // A key pressed again is no longer released under the new session.
        inj.handle(&key_msg(LALT, false));
        inj.handle(&ClientMsg::Wheel { delta: 120, horizontal: false });
        let wheel = Ev::Mouse { flags: MOUSEEVENTF_WHEEL, data: 120 };
        assert_eq!(world(|w| std::mem::take(&mut w.taken)), [sc(0x1d, true), sc(0x38, false), wheel]);
        drop(inj);
        assert_eq!(world(|w| std::mem::take(&mut w.taken)), [sc(0x38, true)]);
        // Nothing left for the thread, should it still run.
        assert!(!retry_once(&mut desktop, false));
        assert!(world(|w| w.taken.is_empty()));
    }

    #[test]
    fn owed_releases_go_out_without_further_input() {
        let _armed = armed_for_test();
        let mut inj = Injector::default();
        inj.handle(&key_msg(LCTRL, false));
        inj.handle(&ClientMsg::MouseButton { button: 0, down: true });
        world(|w| w.taken.clear());
        // A UAC prompt comes up, which a host that is not a service cannot follow, and the
        // viewer leaves.
        world(|w| (w.off_desktop, w.unreachable) = (true, true));
        drop(inj);
        assert_eq!(world(|w| w.retry_threads), 1);
        // A viewer that sends no input (view-only, or left alone) connects while the prompt is
        // up and takes the releases over, and the thread that tried them stops.
        let mut inj = Injector::default();
        let mut desktop = DesktopFollower::new();
        assert!(!retry_once(&mut desktop, false));
        let before = Instant::now();
        inj.retry_owed();
        assert_eq!(inj.owed, [held(LCTRL), Held::Button(0)]);
        assert!(inj.retry_at >= before + RETRY_EVERY);
        // The prompt is answered: they go out at the session's next try, not before (however
        // long this thread waited for its turn in between).
        world(|w| (w.off_desktop, w.unreachable) = (false, false));
        inj.retry_at = Instant::now() + Duration::from_secs(3600);
        inj.retry_owed();
        assert!(world(|w| w.taken.is_empty()), "tried again within RETRY_EVERY");
        inj.retry_at = Instant::now();
        inj.retry_owed();
        let left_up = Ev::Mouse { flags: MOUSEEVENTF_LEFTUP, data: 0 };
        assert_eq!(world(|w| std::mem::take(&mut w.taken)), [sc(0x1d, true), left_up]);
        assert!(inj.owed.is_empty());
        // The session's own refused releases are tried again just the same.
        inj.handle(&key_msg(LALT, false));
        world(|w| (w.off_desktop, w.unreachable, w.taken) = (true, true, Vec::new()));
        inj.handle(&key_msg(LALT, true));
        inj.retry_at = Instant::now();
        inj.retry_owed();
        assert_eq!(inj.owed, [held(LALT)]);
        world(|w| (w.off_desktop, w.unreachable) = (false, false));
        inj.retry_at = Instant::now();
        inj.retry_owed();
        assert_eq!(world(|w| std::mem::take(&mut w.taken)), [sc(0x38, true)]);
        // Nothing owed, nothing sent; and nothing is left over.
        inj.retry_at = Instant::now();
        inj.retry_owed();
        drop(inj);
        assert!(world(|w| w.taken.is_empty()) && leftovers(|l| l.held.is_empty()));
        assert_eq!(world(|w| w.retry_threads), 1);
    }

    #[test]
    fn what_is_not_a_key_is_not_pressed() {
        let _armed = armed_for_test();
        let mut inj = Injector::default();
        let junk = [
            (VK_PACKET, 0x53, 0),     // 'S' typed by a Unicode-injecting tool on the viewer
            (VK_PACKET, 0xd55c, 0),   // a Hangul syllable, likewise
            (VK_PACKET, 0, 0),
            (VK_LCONTROL, 0x21d, 0),  // AltGr's simulated Left Ctrl, from older viewers
            (0x41, 0x11e, 0),
            (0x41, 0xe11d, 0),
            (0, 0, KEY_EXTENDED),
            (0xff, 0, 0),
            (0x141, 0, 0),
        ];
        for (vk, scan, flags) in junk {
            inj.handle(&ClientMsg::Key { vk, scan, flags });
            inj.handle(&ClientMsg::Key { vk, scan, flags: flags | KEY_UP });
        }
        assert!(world(|w| w.taken.is_empty()) && inj.keys.is_empty());
        // The E0 prefix folded into the scancode is the extended flag.
        assert_eq!(HeldKey::from_wire(VK_DELETE, 0xe053, 0), HeldKey::from_wire(VK_DELETE, 0x53, KEY_EXTENDED));
        // By scancode the virtual key plays no part: a press and a release still pair up when
        // the viewer's layout changed in between.
        assert_eq!(HeldKey::from_wire(0x41, 0x1e, 0), HeldKey::from_wire(0x51, 0x1e, KEY_UP));
        assert_eq!(HeldKey::from_wire(VK_PAUSE, 0x45, 0), Some(HeldKey { vk: VK_PAUSE, scan: 0x45, extended: false }));
        assert_eq!(HeldKey::from_wire(VK_VOLUME_UP, 0, KEY_EXTENDED), Some(HeldKey { vk: VK_VOLUME_UP, scan: 0, extended: true }));
    }

    #[test]
    fn a_viewer_can_hold_down_only_so_many_keys() {
        // Every virtual key and scancode form there is, and some junk beyond.
        let scans: Vec<u16> = (0..=0x1ff).chain(0xe000..=0xe0ff).chain([0xe11d, 0xd55c, 0xffff]).collect();
        let mut keys = HashSet::new();
        for vk in (0..=0x1ffu16).chain([0x7fff, 0xffff]) {
            for &scan in &scans {
                for flags in [0, KEY_EXTENDED] {
                    keys.extend(HeldKey::from_wire(vk, scan, flags));
                }
            }
        }
        assert!(keys.len() < 4096, "{} different keys", keys.len());
    }

    #[test]
    fn right_shift_and_num_lock_are_sent_without_the_e0_prefix() {
        // Lookups in this thread's keyboard layout; nothing is typed.
        let vsc_to_vk = |code: u32| unsafe { MapVirtualKeyW(code, MAPVK_VSC_TO_VK_EX) };
        // Windows reports both keys as extended (the Linux keymap's ALIASES), and the X11
        // viewer sends Num Lock so.
        for (vk, scan) in [(VK_RSHIFT, 0x36u16), (VK_NUMLOCK, 0x45)] {
            for flags in [0, KEY_EXTENDED] {
                let k = HeldKey::from_wire(vk, scan, flags).unwrap();
                assert_eq!(k, HeldKey { vk: 0, scan, extended: false });
                assert_eq!(ev(&key(k, false)), sc(scan, false));
            }
            assert_eq!(vsc_to_vk(scan as u32), vk as u32);
            assert_eq!(vsc_to_vk(0xe000 | scan as u32), 0, "{scan:#x} has an E0 form after all");
        }
        // Keys that do have an E0 form keep it.
        for (vk, scan) in [(VK_DIVIDE, 0x35u16), (VK_HOME, 0x47), (VK_DELETE, 0x53)] {
            assert!(HeldKey::from_wire(vk, scan, KEY_EXTENDED).unwrap().extended);
            assert_eq!(vsc_to_vk(0xe000 | scan as u32), vk as u32);
        }
        // The keymap's other aliases need no help here: Alt+Print Screen and Ctrl+Pause.
        assert_eq!(vsc_to_vk(0x54), VK_SNAPSHOT as u32);
        assert_eq!(vsc_to_vk(0xe046), VK_CANCEL as u32);
    }

    #[test]
    fn what_windows_adds_to_a_key_is_told_from_the_key() {
        let _armed = armed_for_test();
        let ralt = HeldKey::from_wire(VK_RMENU, 0x38, KEY_EXTENDED).unwrap();
        let lalt = HeldKey::from_wire(VK_LMENU, 0x38, 0).unwrap();
        assert!(ralt.is_right_alt() && !lalt.is_right_alt());
        assert!(HeldKey::from_wire(VK_RMENU, 0, 0).unwrap().is_right_alt());
        assert!(HeldKey::from_wire(VK_MENU, 0, KEY_EXTENDED).unwrap().is_right_alt());
        assert!(!HeldKey::from_wire(VK_MENU, 0, 0).unwrap().is_right_alt());
        // Korean layouts' Right Alt goes as Han/Eng by virtual key.
        assert!(!HeldKey::from_wire(VK_HANGUL, 0x38, KEY_EXTENDED).unwrap().is_right_alt());
        // The numpad's digit keys, not the grey keys beside them nor its - and +.
        let numpad = |vk, scan, flags| HeldKey::from_wire(vk, scan, flags).unwrap().is_numpad();
        for (vk, scan) in [(VK_HOME, 0x47), (VK_NUMPAD8, 0x48), (VK_CLEAR, 0x4c), (VK_NUMPAD0, 0x52), (VK_DECIMAL, 0x53)] {
            assert!(numpad(vk, scan, 0), "{scan:#x}");
            assert!(!numpad(vk, scan, KEY_EXTENDED), "{scan:#x} extended");
        }
        assert!(!numpad(VK_SUBTRACT, 0x4a, 0) && !numpad(VK_ADD, 0x4e, 0) && !numpad(VK_DIVIDE, 0x35, KEY_EXTENDED));
        assert!(!numpad(VK_NUMPAD7, 0, 0), "by virtual key Windows makes no Home of it");
        let shift = |vk, scan, flags| HeldKey::from_wire(vk, scan, flags).unwrap().shift();
        assert_eq!(shift(VK_LSHIFT, 0x2a, 0), Some(false));
        assert_eq!(shift(VK_RSHIFT, 0x36, KEY_EXTENDED), Some(true));
        assert_eq!(shift(VK_RSHIFT, 0, 0), Some(true));
        assert_eq!(shift(VK_LSHIFT, 0x2a, KEY_EXTENDED), None, "E0 2A is no key");
        assert_eq!(shift(VK_LCONTROL, 0x1d, 0), None);
        // An event of ours tells which key it is for.
        let keys = [ralt, lalt, HeldKey::from_wire(VK_PAUSE, 0x45, 0).unwrap(), HeldKey::from_wire(VK_VOLUME_UP, 0, KEY_EXTENDED).unwrap()];
        for k in keys {
            for up in [false, true] {
                let i = key(k, up);
                assert_eq!(HeldKey::of(unsafe { &i.Anonymous.ki }), k);
                take_tag(extra_info(&i));
            }
        }
    }

    #[test]
    fn keys_windows_adds_pass_only_with_our_events_on_their_way() {
        let _armed = armed_for_test();
        let mut inj = Injector::default();
        world(|w| w.hook = true);
        let ext = |(vk, scan), up| ClientMsg::Key { vk, scan, flags: KEY_EXTENDED | if up { KEY_UP } else { 0 } };
        let (ralt, rshift) = ((VK_RMENU, 0x38), (VK_RSHIFT, 0x36));
        let (n, ctrl, l, r, lr) = ([false; 3], [true, false, false], [false, true, false], [false, false, true], [false, true, true]);
        let steps = [
            (ext(ralt, false), ctrl),
            (key_msg(A, false), n),
            (key_msg(A, true), n),
            (ext(ralt, true), ctrl),
            (key_msg(NUM7, false), n), // no Shift held: Windows adds none
            (key_msg(NUM7, true), n),
            (key_msg(LSHIFT, false), n),
            (key_msg(NUM7, false), l),
            (ext(NUM7, false), n), // the grey Home
            (ext(NUM7, true), n),
            (ext(rshift, false), n),
            (key_msg(NUM7, true), lr),
            (key_msg(LSHIFT, true), n),
            (key_msg(NUM7, false), r),
            (ext(rshift, true), n),
            (key_msg(NUM7, true), n),
        ];
        for (i, (m, want)) in steps.iter().enumerate() {
            inj.handle(m);
            assert_eq!(world(|w| std::mem::take(&mut w.added)), [*want], "step {i}");
        }
        assert!(PENDING.lock().unwrap().added.is_empty());
        // The hooks never see the Right Alt (an elevated window has the focus): its Left Ctrl
        // may pass only briefly after the call.
        world(|w| w.hook = false);
        let before = Instant::now();
        inj.handle(&ext(ralt, false));
        let until: Vec<_> = PENDING.lock().unwrap().added.iter().map(|a| a.until).collect();
        assert!(matches!(until[..], [Some(t)] if t >= before + ADDED_GRACE && t <= Instant::now() + ADDED_GRACE), "{until:?}");
        // A refused event's allowance goes with its tag.
        world(|w| (w.off_desktop, w.unreachable) = (true, true));
        inj.handle(&ext(ralt, true));
        assert_eq!(PENDING.lock().unwrap().added.len(), 1);
        world(|w| (w.off_desktop, w.unreachable) = (false, false));
        drop(inj);
    }

    #[test]
    fn allowances_end_with_their_sendinput_call() {
        use Added::*;
        let t = Instant::now();
        let mut p = Pending::new();
        p.add(1);
        p.allow(1, AltGrCtrl); // privacy mode is off
        p.arm(true);
        assert!(!p.take_added(AltGrCtrl, t));
        p.add(2);
        p.allow(2, AltGrCtrl);
        p.add(3);
        assert!(p.take_added(AltGrCtrl, t));
        assert!(!p.take_added(AltGrCtrl, t), "two for one Right Alt");
        assert!(p.take(2), "the Right Alt itself still passes");
        // Ctrl was already down, so Windows added none: the allowance ends with its Right Alt.
        p.add(4);
        p.allow(4, AltGrCtrl);
        assert!(p.take(4));
        assert!(!p.take_added(AltGrCtrl, t), "outlived its Right Alt");
        // While the call runs it counts, however long the hooks take.
        p.add(5);
        p.allow(5, AltGrCtrl);
        assert!(p.take_added(AltGrCtrl, t + Duration::from_secs(60)));
        // Once it has returned, only briefly.
        for tag in [6, 7] {
            p.add(tag);
            p.allow(tag, AltGrCtrl);
            p.sent(tag, true, t);
        }
        assert!(p.take_added(AltGrCtrl, t + ADDED_GRACE / 2));
        assert!(!p.take_added(AltGrCtrl, t + ADDED_GRACE), "outlived its SendInput call");
        assert!(p.added.is_empty());
        assert!(p.take(6) && p.take(7), "the tags themselves are as before");
        // Windows presses a Shift again after the numpad key itself.
        p.add(8);
        p.allow(8, NumpadShift(true));
        assert!(p.take(8));
        assert!(!p.take_added(NumpadShift(false), t), "not the Shift we hold");
        assert!(p.take_added(NumpadShift(true), t));
        assert!(!p.take_added(NumpadShift(true), t), "two for one numpad key");
        // A refused event reached nobody, and neither did anything Windows would add to it.
        p.add(9);
        p.allow(9, NumpadShift(false));
        p.sent(9, false, t);
        assert!(!p.take(9) && !p.take_added(NumpadShift(false), t));
        p.add(10);
        p.allow(10, AltGrCtrl);
        p.arm(false);
        p.arm(true);
        assert!(!p.take_added(AltGrCtrl, t), "survived the end of privacy mode");
        for tag in 1..=MAX_PENDING + 10 {
            p.allow(tag, NumpadShift(false));
        }
        assert_eq!(p.added.len(), MAX_PENDING);
    }

    #[test]
    fn every_event_gets_a_fresh_tag_that_passes_once() {
        let _armed = armed_for_test();
        let a = |up| key(HeldKey { vk: 0x41, scan: 0x1e, extended: false }, up);
        let inputs = [a(false), mouse(0, 0, 0, MOUSEEVENTF_MOVE), a(true), mouse(0, 0, 0, MOUSEEVENTF_MOVE)];
        let extra = |i: INPUT| unsafe { if i.r#type == INPUT_KEYBOARD { i.Anonymous.ki.dwExtraInfo } else { i.Anonymous.mi.dwExtraInfo } };
        let tags = inputs.map(extra);
        for (i, &t) in tags.iter().enumerate() {
            assert!(!tags[..i].contains(&t), "tag reused: {tags:x?}");
            assert_ne!(t, 0);
            assert_ne!(t, 0x5344_5250, "the old fixed tag");
            assert_ne!(t & 0xFFFF_FF00, 0xFF51_5700);
        }
        // In any order, but each only once; anything else never.
        for &t in tags.iter().rev() {
            assert!(take_tag(t));
            assert!(!take_tag(t), "a tag passed twice");
        }
        assert!(!take_tag(0));
        assert!(!take_tag(new_tag() ^ 0x5a5a));
    }

    #[test]
    fn tags_count_only_while_privacy_mode_is_on() {
        let mut p = Pending::new();
        p.add(7); // sent while privacy mode was off: others may have seen it
        p.arm(true);
        assert!(!p.take(7), "a tag from before privacy mode passed");
        p.add(8);
        p.add(9);
        assert!(p.take(8));
        p.arm(false);
        assert!(!p.take(9), "a tag survived the end of privacy mode");
        p.add(10);
        p.arm(true);
        assert!(!p.take(10));
    }

    #[test]
    fn pending_tags_are_bounded_and_the_oldest_go() {
        let mut p = Pending::new();
        p.arm(true);
        for t in 1..=MAX_PENDING + 10 {
            p.add(t);
        }
        assert_eq!(p.tags.len(), MAX_PENDING);
        assert!(!p.take(10) && p.take(11) && p.take(MAX_PENDING + 10) && p.take(MAX_PENDING));
        assert!(!p.take(11));
        assert_eq!(p.tags.len(), MAX_PENDING - 3);
    }

    #[test]
    #[ignore = "moves the real mouse cursor; run with --ignored"]
    fn absolute_moves_land_on_exact_pixels() {
        REAL.set(true);
        unsafe {
            windows_sys::Win32::UI::HiDpi::SetProcessDpiAwarenessContext(windows_sys::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
        };
        let mut orig = POINT { x: 0, y: 0 };
        unsafe { GetCursorPos(&mut orig) };
        let area = crate::platform::capture::resolve(crate::screen::MonitorSel::Primary).unwrap();
        let mut inj = Injector::default();
        inj.set_area(area);
        let mut seen = Vec::new();
        for (x, y) in [(0, 0), (1, 1), (123, 457), (area.width - 1, area.height - 1), (area.width / 2 + 1, area.height / 3)] {
            inj.handle(&ClientMsg::MouseMove { x: x as u16, y: y as u16 });
            std::thread::sleep(std::time::Duration::from_millis(40));
            let mut p = POINT { x: 0, y: 0 };
            unsafe { GetCursorPos(&mut p) };
            seen.push(((area.left + x, area.top + y), (p.x, p.y)));
        }
        unsafe { SetCursorPos(orig.x, orig.y) };
        for (want, got) in seen {
            assert_eq!(want, got);
        }
    }
}