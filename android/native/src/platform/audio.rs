//! Playback of the host's sound through AAudio (the NDK's audio API): a stream whose callback
//! pulls from the shared jitter buffer. A stream that dies (headphones unplugged, another app
//! taking the output) is reopened by the next `push`.

use super::jitter::JitterBuffer;
use crate::util::{Error, Result};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const START_MS: u32 = 60;
const MAX_MS: u32 = 300;

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

/// What the callbacks see; boxed so its address stays put while the stream lives.
struct Shared {
    buf: Mutex<JitterBuffer>,
    channels: usize,
    dead: AtomicBool,
}

extern "C" fn on_data(_s: *mut Stream, user: *mut c_void, data: *mut c_void, frames: i32) -> i32 {
    let shared = unsafe { &*(user as *const Shared) };
    let out = unsafe { std::slice::from_raw_parts_mut(data as *mut i16, frames.max(0) as usize * shared.channels) };
    match shared.buf.try_lock() {
        // Never wait in the audio callback; a busy buffer plays a moment of silence.
        Ok(mut b) => {
            b.pull(out);
        }
        Err(_) => out.fill(0),
    }
    AAUDIO_CALLBACK_RESULT_CONTINUE
}

extern "C" fn on_error(_s: *mut Stream, user: *mut c_void, _error: i32) {
    // Closing a stream from its own error callback is not allowed: the next push reopens it.
    unsafe { &*(user as *const Shared) }.dead.store(true, Ordering::SeqCst);
}

pub struct AudioPlayer {
    stream: *mut Stream,
    shared: Arc<Shared>,
    rate: u32,
}

unsafe impl Send for AudioPlayer {}

impl AudioPlayer {
    pub fn new(rate: u32, channels: u8) -> Result<AudioPlayer> {
        if !(8_000..=192_000).contains(&rate) || !(1..=2).contains(&channels) {
            return Err(Error::msg(format!("unsupported playback format: {rate} Hz, {channels} channels")));
        }
        let shared = Arc::new(Shared {
            buf: Mutex::new(JitterBuffer::new(rate, channels, START_MS, MAX_MS)),
            channels: channels as usize,
            dead: AtomicBool::new(false),
        });
        let stream = open(rate, channels, &shared)?;
        Ok(AudioPlayer { stream, shared, rate })
    }

    pub fn push(&mut self, pcm: &[i16]) {
        if self.shared.dead.load(Ordering::SeqCst) {
            close(self.stream);
            self.stream = std::ptr::null_mut();
            self.shared.dead.store(false, Ordering::SeqCst);
            match open(self.rate, self.shared.channels as u8, &self.shared) {
                Ok(s) => self.stream = s,
                Err(e) => {
                    crate::log!("sound output lost: {e}");
                    self.shared.dead.store(true, Ordering::SeqCst);
                    return;
                }
            }
        }
        self.shared.buf.lock().unwrap_or_else(|e| e.into_inner()).push(pcm);
    }
}

fn open(rate: u32, channels: u8, shared: &Arc<Shared>) -> Result<*mut Stream> {
    unsafe {
        let mut b: *mut Builder = std::ptr::null_mut();
        let r = AAudio_createStreamBuilder(&mut b);
        if r != AAUDIO_OK {
            return Err(Error::msg(format!("cannot open sound output: {}", text(r))));
        }
        AAudioStreamBuilder_setSampleRate(b, rate as i32);
        AAudioStreamBuilder_setChannelCount(b, channels as i32);
        AAudioStreamBuilder_setFormat(b, AAUDIO_FORMAT_PCM_I16);
        AAudioStreamBuilder_setPerformanceMode(b, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
        AAudioStreamBuilder_setUsage(b, AAUDIO_USAGE_MEDIA);
        AAudioStreamBuilder_setContentType(b, AAUDIO_CONTENT_TYPE_MUSIC);
        let user = Arc::as_ptr(shared) as *mut c_void;
        AAudioStreamBuilder_setDataCallback(b, on_data, user);
        AAudioStreamBuilder_setErrorCallback(b, on_error, user);
        let mut s: *mut Stream = std::ptr::null_mut();
        let r = AAudioStreamBuilder_openStream(b, &mut s);
        AAudioStreamBuilder_delete(b);
        if r != AAUDIO_OK {
            return Err(Error::msg(format!("cannot open sound output: {}", text(r))));
        }
        let r = AAudioStream_requestStart(s);
        if r != AAUDIO_OK {
            AAudioStream_close(s);
            return Err(Error::msg(format!("cannot start sound output: {}", text(r))));
        }
        Ok(s)
    }
}

fn close(s: *mut Stream) {
    if !s.is_null() {
        unsafe {
            AAudioStream_requestStop(s);
            AAudioStream_close(s);
        }
    }
}

impl Drop for AudioPlayer {
    fn drop(&mut self) {
        // AAudioStream_close waits for a running callback, after which `shared` may go.
        close(self.stream);
    }
}
