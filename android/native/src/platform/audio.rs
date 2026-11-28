//! Playback of the host's sound through AAudio (the NDK's audio API): a stream whose callback
//! pulls from the shared jitter buffer. A stream that dies (headphones unplugged, another app
//! taking the output) is reopened by a later `push`, at most every `REOPEN_EVERY`.

use super::jitter::JitterBuffer;
use crate::util::{Error, Result};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const START_MS: u32 = 60;
const MAX_MS: u32 = 300;
/// How often a lost output is tried again (sound arrives every 20 ms; a call can hold the
/// output for minutes).
const REOPEN_EVERY: Duration = Duration::from_secs(3);

type Builder = c_void;
type Stream = c_void;
type DataCallback = extern "C" fn(*mut Stream, *mut c_void, *mut c_void, i32) -> i32;
type ErrorCallback = extern "C" fn(*mut Stream, *mut c_void, i32);

const AAUDIO_OK: i32 = 0;
const AAUDIO_FORMAT_PCM_I16: i32 = 1;
const AAUDIO_PERFORMANCE_MODE_LOW_LATENCY: i32 = 12;
const AAUDIO_USAGE_MEDIA: i32 = 1;
const AAUDIO_CONTENT_TYPE_MUSIC: i32 = 2;
const AAUDIO_CALLBACK_RESULT_CONTINUE: i32 = 0;
const AAUDIO_CALLBACK_RESULT_STOP: i32 = 1;

#[link(name = "aaudio")]
unsafe extern "C" {
    fn AAudio_createStreamBuilder(b: *mut *mut Builder) -> i32;
    fn AAudioStreamBuilder_setSampleRate(b: *mut Builder, rate: i32);
    fn AAudioStreamBuilder_setChannelCount(b: *mut Builder, n: i32);
    fn AAudioStreamBuilder_setFormat(b: *mut Builder, f: i32);
    fn AAudioStreamBuilder_setPerformanceMode(b: *mut Builder, m: i32);
    fn AAudioStreamBuilder_setUsage(b: *mut Builder, u: i32);
    fn AAudioStreamBuilder_setContentType(b: *mut Builder, c: i32);
    fn AAudioStreamBuilder_setDataCallback(b: *mut Builder, cb: DataCallback, user: *mut c_void);
    fn AAudioStreamBuilder_setErrorCallback(b: *mut Builder, cb: ErrorCallback, user: *mut c_void);
    fn AAudioStreamBuilder_openStream(b: *mut Builder, s: *mut *mut Stream) -> i32;
    fn AAudioStreamBuilder_delete(b: *mut Builder) -> i32;
    fn AAudioStream_requestStart(s: *mut Stream) -> i32;
    fn AAudioStream_requestStop(s: *mut Stream) -> i32;
    fn AAudioStream_close(s: *mut Stream) -> i32;
    fn AAudio_convertResultToText(r: i32) -> *const std::ffi::c_char;
}

fn text(r: i32) -> String {
    let p = unsafe { AAudio_convertResultToText(r) };
    if p.is_null() { format!("AAudio error {r}") } else { unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned() }
}

/// What the data callback reads. `AAudioStream_close` returns only once no data callback runs,
/// so it outlives every call made with it.
struct Shared {
    buf: Mutex<JitterBuffer>,
    channels: usize,
}

/// The data callback's context: the buffer and the stream's own `dead` flag.
struct Context {
    shared: Arc<Shared>,
    dead: &'static AtomicBool,
}

extern "C" fn on_data(_s: *mut Stream, user: *mut c_void, data: *mut c_void, frames: i32) -> i32 {
    let r = std::panic::catch_unwind(|| {
        if user.is_null() {
            return AAUDIO_CALLBACK_RESULT_STOP;
        }
        let ctx = unsafe { &*(user as *const Context) };
        if data.is_null() || frames <= 0 || !(data as usize).is_multiple_of(align_of::<i16>()) {
            return AAUDIO_CALLBACK_RESULT_CONTINUE;
        }
        let out = unsafe { std::slice::from_raw_parts_mut(data as *mut i16, frames as usize * ctx.shared.channels) };
        if ctx.dead.load(Ordering::Acquire) {
            out.fill(0);
            return AAUDIO_CALLBACK_RESULT_STOP;
        }
        match ctx.shared.buf.try_lock() {
            // Never wait in the audio callback; a busy buffer plays a moment of silence.
            Ok(mut b) => {
                b.pull(out);
            }
            Err(_) => out.fill(0),
        }
        AAUDIO_CALLBACK_RESULT_CONTINUE
    });
    r.unwrap_or(AAUDIO_CALLBACK_RESULT_STOP)
}

/// Called on a thread of AAudio's own, which may still run after the stream was closed on some
/// devices: its context is a flag that is never freed (one byte per stream opened).
extern "C" fn on_error(_s: *mut Stream, user: *mut c_void, _error: i32) {
    // Closing a stream from its own error callback is not allowed: the next push reopens it.
    if !user.is_null() {
        let dead = user as usize;
        let _ = std::panic::catch_unwind(|| unsafe { &*(dead as *const AtomicBool) }.store(true, Ordering::Release));
    }
}

/// An open stream and what its callbacks use.
struct Open {
    stream: *mut Stream,
    /// Freed after the stream is closed (`Drop`).
    context: *mut Context,
    dead: &'static AtomicBool,
    opened_at: Instant,
}

impl Drop for Open {
    fn drop(&mut self) {
        unsafe {
            AAudioStream_requestStop(self.stream);
            // Waits for a running data callback; after it none comes.
            AAudioStream_close(self.stream);
            drop(Box::from_raw(self.context));
        }
    }
}

pub struct AudioPlayer {
    open: Option<Open>,
    shared: Arc<Shared>,
    rate: u32,
    /// When a lost output may be reopened; whether that failing was reported.
    retry_at: Option<Instant>,
    warned: bool,
}

unsafe impl Send for AudioPlayer {}

impl AudioPlayer {
    pub fn new(rate: u32, channels: u8) -> Result<AudioPlayer> {
        if !(8_000..=192_000).contains(&rate) || !(1..=2).contains(&channels) {
            return Err(Error::msg(format!("unsupported playback format: {rate} Hz, {channels} channels")));
        }
        let shared = Arc::new(Shared { buf: Mutex::new(JitterBuffer::new(rate, channels, START_MS, MAX_MS)), channels: channels as usize });
        let open = open(rate, &shared)?;
        Ok(AudioPlayer { open: Some(open), shared, rate, retry_at: None, warned: false })
    }

    pub fn push(&mut self, pcm: &[i16]) {
        if self.open.as_ref().is_some_and(|o| o.dead.load(Ordering::Acquire))
            && let Some(o) = self.open.take()
        {
            // A stream that played a while (headphones pulled out) is reopened at once; one that
            // died right after opening (the output taken by a call) is tried again at the pace
            // of failed opens, not with every packet.
            self.retry_at = Some(o.opened_at + REOPEN_EVERY);
        }
        if self.open.is_none() {
            if self.retry_at.is_some_and(|t| Instant::now() < t) {
                return;
            }
            match open(self.rate, &self.shared) {
                Ok(o) => {
                    self.open = Some(o);
                    self.retry_at = None;
                    self.warned = false;
                }
                Err(e) => {
                    if !std::mem::replace(&mut self.warned, true) {
                        crate::log!("sound output lost: {e}");
                    }
                    self.retry_at = Some(Instant::now() + REOPEN_EVERY);
                    return;
                }
            }
        }
        self.shared.buf.lock().unwrap_or_else(|e| e.into_inner()).push(pcm);
    }
}

fn open(rate: u32, shared: &Arc<Shared>) -> Result<Open> {
    let dead: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let context = Box::into_raw(Box::new(Context { shared: shared.clone(), dead }));
    let fail = |what: &str, r: i32| -> Result<Open> {
        drop(unsafe { Box::from_raw(context) });
        Err(Error::msg(format!("{what}: {}", text(r))))
    };
    unsafe {
        let mut b: *mut Builder = std::ptr::null_mut();
        let r = AAudio_createStreamBuilder(&mut b);
        if r != AAUDIO_OK {
            return fail("cannot open sound output", r);
        }
        AAudioStreamBuilder_setSampleRate(b, rate as i32);
        AAudioStreamBuilder_setChannelCount(b, shared.channels as i32);
        AAudioStreamBuilder_setFormat(b, AAUDIO_FORMAT_PCM_I16);
        AAudioStreamBuilder_setPerformanceMode(b, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
        AAudioStreamBuilder_setUsage(b, AAUDIO_USAGE_MEDIA);
        AAudioStreamBuilder_setContentType(b, AAUDIO_CONTENT_TYPE_MUSIC);
        AAudioStreamBuilder_setDataCallback(b, on_data, context.cast());
        AAudioStreamBuilder_setErrorCallback(b, on_error, (dead as *const AtomicBool).cast_mut().cast());
        let mut s: *mut Stream = std::ptr::null_mut();
        let r = AAudioStreamBuilder_openStream(b, &mut s);
        AAudioStreamBuilder_delete(b);
        if r != AAUDIO_OK {
            return fail("cannot open sound output", r);
        }
        let r = AAudioStream_requestStart(s);
        if r != AAUDIO_OK {
            AAudioStream_close(s);
            return fail("cannot start sound output", r);
        }
        Ok(Open { stream: s, context, dead, opened_at: Instant::now() })
    }
}
