//! Audio via WASAPI: loopback capture of the default output device (host) and shared-mode
//! playback with a jitter buffer (viewer).
//!
//! windows-sys has no COM interface bindings, so the handful of vtable slots used here are
//! declared by hand. Slot numbers were taken from the Windows SDK headers (mmdeviceapi.h,
//! Audioclient.h, C interface section).

// host.rs / viewer.rs do not call this module yet.
#![allow(dead_code)]

use crate::log;
use crate::platform::jitter::JitterBuffer;
use crate::util::{Error, Result, wide};
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Media::Audio::{
    AUDCLNT_BUFFERFLAGS_SILENT, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM, AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
    AUDCLNT_STREAMFLAGS_LOOPBACK, AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY, MMDeviceEnumerator, WAVEFORMATEX, eConsole, eRender,
};
use windows_sys::Win32::System::Com::{CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize};
use windows_sys::Win32::System::Threading::{AvRevertMmThreadCharacteristics, AvSetMmThreadCharacteristicsW, CreateEventW, WaitForSingleObject};
use windows_sys::core::GUID;

type HRESULT = i32;

const IID_IMMDEVICEENUMERATOR: GUID = GUID::from_u128(0xa95664d2_9614_4f35_a746_de8db63617e6);
const IID_IAUDIOCLIENT: GUID = GUID::from_u128(0x1cb9ad4c_dbfa_4c32_b178_c2f568a703b2);
const IID_IAUDIOCAPTURECLIENT: GUID = GUID::from_u128(0xc8adbd64_e71e_48a0_a4de_185c395cd317);
const IID_IAUDIORENDERCLIENT: GUID = GUID::from_u128(0xf294acfc_3146_4483_a7bf_addca7c260e2);
const KSDATAFORMAT_SUBTYPE_PCM: GUID = GUID::from_u128(0x00000001_0000_0010_8000_00aa00389b71);
const KSDATAFORMAT_SUBTYPE_IEEE_FLOAT: GUID = GUID::from_u128(0x00000003_0000_0010_8000_00aa00389b71);

const WAVE_FORMAT_PCM: u16 = 1;
const WAVE_FORMAT_IEEE_FLOAT: u16 = 3;
const WAVE_FORMAT_EXTENSIBLE: u16 = 0xfffe;
const E_NOTFOUND: HRESULT = 0x80070490u32 as i32;

/// 100-ns units per millisecond (REFERENCE_TIME).
const HNS_PER_MS: i64 = 10_000;
/// Loopback engine buffer: room for a slow `on_pcm` without losing audio.
const CAPTURE_BUFFER_MS: i64 = 200;
/// How often the capture/render threads wake when the engine sends no event.
const POLL_MS: u32 = 20;
/// Render engine buffer requested, and how much of it is kept filled.
const RENDER_BUFFER_MS: i64 = 50;
const DEVICE_FILL_MS: u32 = 30;
/// Jitter buffer: start playing at 60 ms queued, never hold more than 300 ms.
const START_MS: u32 = 60;
const MAX_MS: u32 = 300;
/// Following the default device: how often it is checked and how long to back off after errors.
const DEVICE_CHECK: Duration = Duration::from_secs(1);
const RETRY: Duration = Duration::from_millis(500);
/// A stream that ran this long before failing is reported again (others stay quiet).
const HEALTHY: Duration = Duration::from_secs(1);

fn hr(h: HRESULT, what: &str) -> Result<()> {
    if h < 0 {
        return Err(Error::msg(format!("{what} failed (HRESULT {:#010x})", h as u32)));
    }
    Ok(())
}

/// Owned COM pointer.
struct Com(*mut c_void);

impl Com {
    /// Function pointer from vtable slot `i`.
    unsafe fn slot<F: Copy>(&self, i: usize) -> F {
        unsafe {
            let vtbl = *(self.0 as *const *const usize);
            std::mem::transmute_copy(&*vtbl.add(i))
        }
    }

    /// Calls a method that takes no arguments besides `this` (IAudioClient::Start/Stop).
    fn call(&self, slot: usize, what: &str) -> Result<()> {
        let f: unsafe extern "system" fn(*mut c_void) -> HRESULT = unsafe { self.slot(slot) };
        hr(unsafe { f(self.0) }, what)
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let release: unsafe extern "system" fn(*mut c_void) -> u32 = unsafe { self.slot(2) };
            unsafe { release(self.0) };
        }
    }
}

/// COM for the current thread; balanced only when this call initialised it.
struct Apartment(bool);

impl Apartment {
    fn enter() -> Apartment {
        // RPC_E_CHANGED_MODE (an STA thread) still leaves COM usable: these objects are free-threaded.
        Apartment(unsafe { CoInitializeEx(null(), COINIT_MULTITHREADED as u32) } >= 0)
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}

/// Registers the thread with MMCSS ("Audio") so heavy encode/decode work does not starve it.
struct Mmcss(HANDLE);

impl Mmcss {
    fn audio() -> Mmcss {
        let mut index = 0u32;
        Mmcss(unsafe { AvSetMmThreadCharacteristicsW(wide("Audio").as_ptr(), &mut index) })
    }
}

impl Drop for Mmcss {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { AvRevertMmThreadCharacteristics(self.0) };
        }
    }
}

/// Auto-reset event the audio engine signals when it has data or needs more.
struct Event(HANDLE);

impl Event {
    fn new() -> Result<Event> {
        let h = unsafe { CreateEventW(null(), 0, 0, null()) };
        if h.is_null() {
            return Err(Error::last_os("CreateEvent"));
        }
        Ok(Event(h))
    }

    fn wait(&self, ms: u32) {
        unsafe { WaitForSingleObject(self.0, ms) };
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// IMMDeviceEnumerator.
struct Devices(Com);

impl Devices {
    fn new() -> Result<Devices> {
        let mut p = null_mut();
        hr(unsafe { CoCreateInstance(&MMDeviceEnumerator, null_mut(), CLSCTX_ALL, &IID_IMMDEVICEENUMERATOR, &mut p) }, "creating MMDeviceEnumerator")?;
        Ok(Devices(Com(p)))
    }

    /// The default output device (eRender, eConsole) and its endpoint ID.
    fn default_output(&self) -> Result<(Com, Vec<u16>)> {
        unsafe {
            // IMMDeviceEnumerator::GetDefaultAudioEndpoint
            let get: unsafe extern "system" fn(*mut c_void, i32, i32, *mut *mut c_void) -> HRESULT = self.0.slot(4);
            let mut d = null_mut();
            let r = get(self.0.0, eRender, eConsole, &mut d);
            if r == E_NOTFOUND {
                return Err("no audio output device".into());
            }
            hr(r, "GetDefaultAudioEndpoint")?;
            let device = Com(d);
            // IMMDevice::GetId
            let get_id: unsafe extern "system" fn(*mut c_void, *mut *mut u16) -> HRESULT = device.slot(5);
            let mut s = null_mut();
            hr(get_id(device.0, &mut s), "IMMDevice::GetId")?;
            if s.is_null() {
                return Err("IMMDevice::GetId returned no ID".into());
            }
            let mut n = 0;
            while *s.add(n) != 0 {
                n += 1;
            }
            let id = std::slice::from_raw_parts(s, n).to_vec();
            CoTaskMemFree(s as *const c_void);
            Ok((device, id))
        }
    }

    /// True when the default output device is no longer `id`.
    fn default_changed(&self, id: &[u16]) -> Result<bool> {
        Ok(self.default_output()?.1 != id)
    }
}

/// IAudioClient on one endpoint.
struct Client(Com);

impl Client {
    fn activate(device: &Com) -> Result<Client> {
        unsafe {
            // IMMDevice::Activate
            let activate: unsafe extern "system" fn(*mut c_void, *const GUID, u32, *const c_void, *mut *mut c_void) -> HRESULT = device.slot(3);
            let mut p = null_mut();
            hr(activate(device.0, &IID_IAUDIOCLIENT, CLSCTX_ALL, null(), &mut p), "IMMDevice::Activate")?;
            Ok(Client(Com(p)))
        }
    }

    /// The engine's shared-mode format as raw WAVEFORMATEX(+extension) bytes.
    fn mix_format(&self) -> Result<Vec<u8>> {
        unsafe {
            let get: unsafe extern "system" fn(*mut c_void, *mut *mut WAVEFORMATEX) -> HRESULT = self.0.slot(8);
            let mut p = null_mut();
            hr(get(self.0.0, &mut p), "IAudioClient::GetMixFormat")?;
            if p.is_null() {
                return Err("GetMixFormat returned no format".into());
            }
            let base = std::slice::from_raw_parts(p as *const u8, 18);
            let extra = (u16::from_le_bytes([base[16], base[17]]) as usize).min(256);
            let raw = std::slice::from_raw_parts(p as *const u8, 18 + extra).to_vec();
            CoTaskMemFree(p as *const c_void);
            Ok(raw)
        }
    }

    fn initialize(&self, flags: u32, buffer_ms: i64, format: *const WAVEFORMATEX) -> Result<()> {
        unsafe {
            let init: unsafe extern "system" fn(*mut c_void, i32, u32, i64, i64, *const WAVEFORMATEX, *const GUID) -> HRESULT = self.0.slot(3);
            hr(init(self.0.0, AUDCLNT_SHAREMODE_SHARED, flags, buffer_ms * HNS_PER_MS, 0, format, null()), "IAudioClient::Initialize")
        }
    }

    fn buffer_frames(&self) -> Result<u32> {
        let get: unsafe extern "system" fn(*mut c_void, *mut u32) -> HRESULT = unsafe { self.0.slot(4) };
        let mut n = 0;
        hr(unsafe { get(self.0.0, &mut n) }, "IAudioClient::GetBufferSize")?;
        Ok(n)
    }

    fn padding(&self) -> Result<u32> {
        let get: unsafe extern "system" fn(*mut c_void, *mut u32) -> HRESULT = unsafe { self.0.slot(6) };
        let mut n = 0;
        hr(unsafe { get(self.0.0, &mut n) }, "IAudioClient::GetCurrentPadding")?;
        Ok(n)
    }

    fn set_event(&self, event: &Event) -> Result<()> {
        let set: unsafe extern "system" fn(*mut c_void, HANDLE) -> HRESULT = unsafe { self.0.slot(13) };
        hr(unsafe { set(self.0.0, event.0) }, "IAudioClient::SetEventHandle")
    }

    fn service(&self, iid: &GUID) -> Result<Com> {
        let get: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT = unsafe { self.0.slot(14) };
        let mut p = null_mut();
        hr(unsafe { get(self.0.0, iid, &mut p) }, "IAudioClient::GetService")?;
        Ok(Com(p))
    }

    fn start(&self) -> Result<()> {
        self.0.call(10, "IAudioClient::Start")
    }

    fn stop(&self) {
        let _ = self.0.call(11, "IAudioClient::Stop");
    }
}

/// Sample encodings the loopback converter reads.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Sample {
    U8,
    I16,
    I24,
    I32,
    F32,
    F64,
}

impl Sample {
    fn bytes(self) -> usize {
        match self {
            Sample::U8 => 1,
            Sample::I16 => 2,
            Sample::I24 => 3,
            Sample::I32 | Sample::F32 => 4,
            Sample::F64 => 8,
        }
    }

    /// Reads one little-endian sample (`b` holds exactly `bytes()`) as -1.0..1.0 (float mixes
    /// may exceed that; NaN and infinities read as silence so they cannot spread in a downmix).
    #[inline]
    fn read(self, b: &[u8]) -> f32 {
        let v = match self {
            Sample::U8 => return (b[0] as f32 - 128.0) / 128.0,
            Sample::I16 => return i16::from_le_bytes([b[0], b[1]]) as f32 / 32768.0,
            Sample::I24 => return i32::from_le_bytes([0, b[0], b[1], b[2]]) as f32 / 2_147_483_648.0,
            Sample::I32 => return i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f32 / 2_147_483_648.0,
            Sample::F32 => f32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            Sample::F64 => f64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) as f32,
        };
        if v.is_finite() { v } else { 0.0 }
    }
}

#[derive(Debug, PartialEq)]
struct MixFormat {
    rate: u32,
    channels: usize,
    sample: Sample,
    /// WAVEFORMATEXTENSIBLE speaker mask (0 when absent).
    mask: u32,
}

fn guid_eq(a: &GUID, b: &GUID) -> bool {
    (a.data1, a.data2, a.data3, a.data4) == (b.data1, b.data2, b.data3, b.data4)
}

/// Parses WAVEFORMATEX / WAVEFORMATEXTENSIBLE bytes (packed, little-endian).
fn parse_format(raw: &[u8]) -> Result<MixFormat> {
    let u16_at = |o: usize| raw.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or("truncated audio format");
    let u32_at = |o: usize| raw.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or("truncated audio format");
    let (tag, channels, rate, block, bits) = (u16_at(0)?, u16_at(2)? as usize, u32_at(4)?, u16_at(12)? as usize, u16_at(14)? as usize);
    let (float, mask) = match tag {
        WAVE_FORMAT_PCM => (false, 0),
        WAVE_FORMAT_IEEE_FLOAT => (true, 0),
        WAVE_FORMAT_EXTENSIBLE => {
            if u16_at(16)? < 22 {
                return Err("truncated WAVEFORMATEXTENSIBLE".into());
            }
            let sub = GUID { data1: u32_at(24)?, data2: u16_at(28)?, data3: u16_at(30)?, data4: raw.get(32..40).ok_or("truncated audio format")?.try_into().unwrap() };
            let float = if guid_eq(&sub, &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT) {
                true
            } else if guid_eq(&sub, &KSDATAFORMAT_SUBTYPE_PCM) {
                false
            } else {
                return Err("unsupported audio sub-format".into());
            };
            (float, u32_at(20)?)
        }
        t => return Err(Error::msg(format!("unsupported audio format tag {t:#x}"))),
    };
    let sample = match (float, bits) {
        (false, 8) => Sample::U8,
        (false, 16) => Sample::I16,
        (false, 24) => Sample::I24,
        (false, 32) => Sample::I32,
        (true, 32) => Sample::F32,
        (true, 64) => Sample::F64,
        _ => return Err(Error::msg(format!("unsupported {bits}-bit {} samples", if float { "float" } else { "integer" }))),
    };
    if !(1..=32).contains(&channels) || block != channels * sample.bytes() || rate == 0 {
        return Err("inconsistent audio format".into());
    }
    Ok(MixFormat { rate, channels, sample, mask })
}

/// Stereo gains per speaker position (bit index of the WAVEFORMATEXTENSIBLE channel mask):
/// fronts stay on their side, centres split at -3 dB, LFE is dropped, rears fold in at -3 dB.
const SPEAKER_GAINS: [[f32; 2]; 18] = [
    [1.0, 0.0],       // front left
    [0.0, 1.0],       // front right
    [0.707, 0.707],   // front centre
    [0.0, 0.0],       // LFE
    [0.707, 0.0],     // back left
    [0.0, 0.707],     // back right
    [0.924, 0.383],   // front left of centre
    [0.383, 0.924],   // front right of centre
    [0.5, 0.5],       // back centre
    [0.707, 0.0],     // side left
    [0.0, 0.707],     // side right
    [0.5, 0.5],       // top centre
    [0.707, 0.0],     // top front left
    [0.5, 0.5],       // top front centre
    [0.0, 0.707],     // top front right
    [0.5, 0.0],       // top back left
    [0.354, 0.354],   // top back centre
    [0.0, 0.5],       // top back right
];

/// Stereo gains for each of `channels` source channels. Channels map to the set bits of
/// `mask` in order; without a mask the standard order (FL, FR, FC, LFE, BL, BR, ...) applies;
/// channels beyond the mask have no speaker and are left out.
fn downmix_gains(channels: usize, mask: u32) -> Vec<[f32; 2]> {
    let mask = if mask == 0 { u32::MAX } else { mask };
    let mut positions = (0..32).filter(|b| mask & (1 << b) != 0);
    (0..channels).map(|_| positions.next().and_then(|b| SPEAKER_GAINS.get(b).copied()).unwrap_or([0.0, 0.0])).collect()
}

/// Turns engine frames into interleaved i16: mono stays mono, stereo passes through and
/// anything wider is folded down to stereo; integer multiples of 48 / 44.1 kHz are
/// decimated to those rates.
struct Converter {
    sample: Sample,
    channels: usize,
    out_channels: usize,
    gains: Vec<[f32; 2]>,
    rate: u32,
    decim: usize,
    acc: [f32; 2],
    acc_n: usize,
}

impl Converter {
    fn new(fmt: &MixFormat) -> Converter {
        let out_channels = if fmt.channels == 1 { 1 } else { 2 };
        let gains = if fmt.channels > 2 { downmix_gains(fmt.channels, fmt.mask) } else { Vec::new() };
        let decim = [48_000, 44_100].iter().find(|&&base| fmt.rate > base && fmt.rate.is_multiple_of(base)).map_or(1, |&base| (fmt.rate / base) as usize);
        Converter { sample: fmt.sample, channels: fmt.channels, out_channels, gains, rate: fmt.rate / decim as u32, decim, acc: [0.0; 2], acc_n: 0 }
    }

    fn frame_bytes(&self) -> usize {
        self.channels * self.sample.bytes()
    }

    /// Converts the whole frames in `src`.
    fn push(&mut self, src: &[u8], out: &mut Vec<i16>) {
        let size = self.sample.bytes();
        for frame in src.chunks_exact(self.frame_bytes()) {
            let mut lr = [0.0f32; 2];
            if self.channels <= 2 {
                for (v, s) in lr.iter_mut().zip(frame.chunks_exact(size)) {
                    *v = self.sample.read(s);
                }
            } else {
                for (s, g) in frame.chunks_exact(size).zip(&self.gains) {
                    let v = self.sample.read(s);
                    lr[0] += v * g[0];
                    lr[1] += v * g[1];
                }
            }
            self.accumulate(lr, out);
        }
    }

    fn push_silence(&mut self, frames: usize, out: &mut Vec<i16>) {
        for _ in 0..frames {
            self.accumulate([0.0; 2], out);
        }
    }

    #[inline]
    fn accumulate(&mut self, lr: [f32; 2], out: &mut Vec<i16>) {
        self.acc[0] += lr[0];
        self.acc[1] += lr[1];
        self.acc_n += 1;
        if self.acc_n == self.decim {
            let scale = 32768.0 / self.decim as f32;
            for v in &self.acc[..self.out_channels] {
                // NaN turns into 0 in the saturating cast.
                out.push((v * scale).round().clamp(-32768.0, 32767.0) as i16);
            }
            self.acc = [0.0; 2];
            self.acc_n = 0;
        }
    }
}

type OnPcm = Box<dyn FnMut(&[i16], u32, u8) + Send>;

/// Loopback capture of the current default output device.
struct Loopback {
    devices: Devices,
    device_id: Vec<u16>,
    client: Client,
    capture: Com,
    event: Event,
    conv: Converter,
}

impl Loopback {
    fn open() -> Result<Loopback> {
        let devices = Devices::new()?;
        let (device, device_id) = devices.default_output()?;
        let mut client = Client::activate(&device)?;
        let raw = client.mix_format()?;
        let fmt = parse_format(&raw)?;
        let event = Event::new()?;
        let format = raw.as_ptr() as *const WAVEFORMATEX;
        let flags = AUDCLNT_STREAMFLAGS_LOOPBACK | AUDCLNT_STREAMFLAGS_EVENTCALLBACK;
        if client.initialize(flags, CAPTURE_BUFFER_MS, format).is_ok() {
            client.set_event(&event)?;
        } else {
            // Event-driven loopback needs Windows 10; older systems are polled every POLL_MS.
            client = Client::activate(&device)?;
            client.initialize(AUDCLNT_STREAMFLAGS_LOOPBACK, CAPTURE_BUFFER_MS, format)?;
        }
        let capture = client.service(&IID_IAUDIOCAPTURECLIENT)?;
        client.start()?;
        Ok(Loopback { devices, device_id, client, capture, event, conv: Converter::new(&fmt) })
    }

    /// Delivers audio until `stop` is set (Ok), the default device changes (Ok) or the
    /// device fails (Err).
    fn run(&mut self, on_pcm: &mut OnPcm, stop: &AtomicBool) -> Result<()> {
        let (rate, channels) = (self.conv.rate, self.conv.out_channels as u8);
        let frame_bytes = self.conv.frame_bytes();
        // IAudioCaptureClient::GetBuffer, ReleaseBuffer, GetNextPacketSize
        let get: unsafe extern "system" fn(*mut c_void, *mut *mut u8, *mut u32, *mut u32, *mut u64, *mut u64) -> HRESULT = unsafe { self.capture.slot(3) };
        let release: unsafe extern "system" fn(*mut c_void, u32) -> HRESULT = unsafe { self.capture.slot(4) };
        let next: unsafe extern "system" fn(*mut c_void, *mut u32) -> HRESULT = unsafe { self.capture.slot(5) };
        let mut pcm = Vec::new();
        let mut last_check = Instant::now();
        while !stop.load(Ordering::SeqCst) {
            self.event.wait(POLL_MS);
            loop {
                let mut pending = 0;
                hr(unsafe { next(self.capture.0, &mut pending) }, "GetNextPacketSize")?;
                if pending == 0 {
                    break;
                }
                let (mut data, mut frames, mut flags) = (null_mut(), 0u32, 0u32);
                hr(unsafe { get(self.capture.0, &mut data, &mut frames, &mut flags, null_mut(), null_mut()) }, "IAudioCaptureClient::GetBuffer")?;
                if frames == 0 {
                    break; // AUDCLNT_S_BUFFER_EMPTY
                }
                if flags & AUDCLNT_BUFFERFLAGS_SILENT as u32 != 0 || data.is_null() {
                    self.conv.push_silence(frames as usize, &mut pcm);
                } else {
                    let src = unsafe { std::slice::from_raw_parts(data, frames as usize * frame_bytes) };
                    self.conv.push(src, &mut pcm);
                }
                hr(unsafe { release(self.capture.0, frames) }, "IAudioCaptureClient::ReleaseBuffer")?;
            }
            if !pcm.is_empty() {
                on_pcm(&pcm, rate, channels);
                pcm.clear();
            }
            if last_check.elapsed() >= DEVICE_CHECK {
                last_check = Instant::now();
                if self.devices.default_changed(&self.device_id)? {
                    log!("audio: default output device changed, following it");
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        self.client.stop();
    }
}

/// Sleeps up to `d`, waking early when `stop` is set.
fn nap(d: Duration, stop: &AtomicBool) {
    let end = Instant::now() + d;
    while !stop.load(Ordering::SeqCst) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Captures what the host is playing. Dropping it stops capture.
pub struct AudioCapture {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl AudioCapture {
    /// True when there is a default output device to record from.
    pub fn available() -> bool {
        let _com = Apartment::enter();
        Devices::new().and_then(|d| d.default_output()).is_ok()
    }

    /// `on_pcm(samples, rate, channels)` receives interleaved 16-bit PCM (1 or 2 channels) from
    /// a capture thread, about every 10-20 ms while something plays. Fails when the default
    /// output device cannot be recorded; later device changes and failures are retried.
    pub fn start(on_pcm: Box<dyn FnMut(&[i16], u32, u8) + Send>) -> Result<AudioCapture> {
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::sync_channel(1);
        let s = stop.clone();
        let thread = std::thread::Builder::new().name("audio-capture".into()).spawn(move || capture_thread(on_pcm, &s, tx))?;
        match rx.recv() {
            Ok(Ok(())) => Ok(AudioCapture { stop, thread: Some(thread) }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err("audio capture thread exited".into())
            }
        }
    }
}

impl Drop for AudioCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn capture_thread(mut on_pcm: OnPcm, stop: &AtomicBool, ready: mpsc::SyncSender<Result<()>>) {
    let _com = Apartment::enter();
    let _mmcss = Mmcss::audio();
    let mut ready = Some(ready);
    let mut reported = false;
    while !stop.load(Ordering::SeqCst) {
        let opened = Instant::now();
        let r = match Loopback::open() {
            Ok(mut lb) => {
                if let Some(tx) = ready.take() {
                    let _ = tx.send(Ok(()));
                }
                lb.run(&mut on_pcm, stop)
            }
            Err(e) => match ready.take() {
                Some(tx) => {
                    let _ = tx.send(Err(e));
                    return;
                }
                None => Err(e),
            },
        };
        if opened.elapsed() >= HEALTHY {
            reported = false;
        }
        if let Err(e) = r {
            if !reported {
                log!("audio capture interrupted ({e}); retrying");
                reported = true;
            }
            nap(RETRY, stop);
        }
    }
}

/// Shared-mode render stream on the default output device.
struct Render {
    devices: Devices,
    device_id: Vec<u16>,
    client: Client,
    render: Com,
    event: Event,
    channels: usize,
    /// Frames kept queued in the engine buffer.
    fill: u32,
    scratch: Vec<i16>,
}

impl Render {
    fn open(rate: u32, channels: u8, buf: &Mutex<JitterBuffer>) -> Result<Render> {
        let devices = Devices::new()?;
        let (device, device_id) = devices.default_output()?;
        let client = Client::activate(&device)?;
        let block = channels as u16 * 2;
        let format = WAVEFORMATEX {
            wFormatTag: WAVE_FORMAT_PCM,
            nChannels: channels as u16,
            nSamplesPerSec: rate,
            nAvgBytesPerSec: rate * block as u32,
            nBlockAlign: block,
            wBitsPerSample: 16,
            cbSize: 0,
        };
        // The engine converts rate and channel count to its mix format.
        let flags = AUDCLNT_STREAMFLAGS_EVENTCALLBACK | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY;
        client.initialize(flags, RENDER_BUFFER_MS, &format)?;
        let event = Event::new()?;
        client.set_event(&event)?;
        let render = client.service(&IID_IAUDIORENDERCLIENT)?;
        let fill = client.buffer_frames()?.min((rate as u64 * DEVICE_FILL_MS as u64 / 1000) as u32).max(1);
        let mut r = Render { devices, device_id, client, render, event, channels: channels as usize, fill, scratch: Vec::new() };
        r.top_up(buf)?; // start with a full buffer rather than an immediate underrun
        r.client.start()?;
        Ok(r)
    }

    /// Keeps `fill` frames queued in the engine, from the jitter buffer or as silence.
    fn top_up(&mut self, buf: &Mutex<JitterBuffer>) -> Result<()> {
        let padding = self.client.padding()?;
        if padding >= self.fill {
            return Ok(());
        }
        let frames = self.fill - padding;
        self.scratch.resize(frames as usize * self.channels, 0);
        let audible = buf.lock().unwrap_or_else(|e| e.into_inner()).pull(&mut self.scratch);
        unsafe {
            // IAudioRenderClient::GetBuffer, ReleaseBuffer
            let get: unsafe extern "system" fn(*mut c_void, u32, *mut *mut u8) -> HRESULT = self.render.slot(3);
            let release: unsafe extern "system" fn(*mut c_void, u32, u32) -> HRESULT = self.render.slot(4);
            let mut p = null_mut();
            hr(get(self.render.0, frames, &mut p), "IAudioRenderClient::GetBuffer")?;
            if audible && !p.is_null() {
                std::ptr::copy_nonoverlapping(self.scratch.as_ptr() as *const u8, p, self.scratch.len() * 2);
            }
            let flags = if audible { 0 } else { AUDCLNT_BUFFERFLAGS_SILENT as u32 };
            hr(release(self.render.0, frames, flags), "IAudioRenderClient::ReleaseBuffer")
        }
    }

    fn run(&mut self, buf: &Mutex<JitterBuffer>, stop: &AtomicBool) -> Result<()> {
        let mut last_check = Instant::now();
        while !stop.load(Ordering::SeqCst) {
            self.event.wait(POLL_MS);
            self.top_up(buf)?;
            if last_check.elapsed() >= DEVICE_CHECK {
                last_check = Instant::now();
                if self.devices.default_changed(&self.device_id)? {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

impl Drop for Render {
    fn drop(&mut self) {
        self.client.stop();
    }
}

/// Plays a PCM stream with a small jitter buffer. Dropping it stops playback.
pub struct AudioPlayer {
    buf: Arc<Mutex<JitterBuffer>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl AudioPlayer {
    /// Opens the default output device for `rate` Hz, 1 or 2 channel 16-bit PCM.
    pub fn new(rate: u32, channels: u8) -> Result<AudioPlayer> {
        if !(8_000..=384_000).contains(&rate) || !(1..=2).contains(&channels) {
            return Err(Error::msg(format!("unsupported playback format: {rate} Hz, {channels} channels")));
        }
        let buf = Arc::new(Mutex::new(JitterBuffer::new(rate, channels, START_MS, MAX_MS)));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::sync_channel(1);
        let (b, s) = (buf.clone(), stop.clone());
        let thread = std::thread::Builder::new().name("audio-render".into()).spawn(move || render_thread(rate, channels, &b, &s, tx))?;
        match rx.recv() {
            Ok(Ok(())) => Ok(AudioPlayer { buf, stop, thread: Some(thread) }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err("audio playback thread exited".into())
            }
        }
    }

    /// Queues interleaved 16-bit PCM.
    pub fn push(&mut self, pcm: &[i16]) {
        self.buf.lock().unwrap_or_else(|e| e.into_inner()).push(pcm);
    }
}

impl Drop for AudioPlayer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn render_thread(rate: u32, channels: u8, buf: &Mutex<JitterBuffer>, stop: &AtomicBool, ready: mpsc::SyncSender<Result<()>>) {
    let _com = Apartment::enter();
    let _mmcss = Mmcss::audio();
    let mut ready = Some(ready);
    let mut reported = false;
    while !stop.load(Ordering::SeqCst) {
        let opened = Instant::now();
        let r = match Render::open(rate, channels, buf) {
            Ok(mut out) => {
                if let Some(tx) = ready.take() {
                    let _ = tx.send(Ok(()));
                }
                out.run(buf, stop)
            }
            Err(e) => match ready.take() {
                Some(tx) => {
                    let _ = tx.send(Err(e));
                    return;
                }
                None => Err(e),
            },
        };
        if opened.elapsed() >= HEALTHY {
            reported = false;
        }
        if let Err(e) = r {
            if !reported {
                log!("audio playback interrupted ({e}); retrying");
                reported = true;
            }
            nap(RETRY, stop);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WAVEFORMATEXTENSIBLE bytes as the engine reports them.
    fn extensible(channels: u16, rate: u32, bits: u16, mask: u32, sub: &GUID) -> Vec<u8> {
        let block = channels * bits / 8;
        let mut b = Vec::new();
        b.extend_from_slice(&WAVE_FORMAT_EXTENSIBLE.to_le_bytes());
        b.extend_from_slice(&channels.to_le_bytes());
        b.extend_from_slice(&rate.to_le_bytes());
        b.extend_from_slice(&(rate * block as u32).to_le_bytes());
        b.extend_from_slice(&block.to_le_bytes());
        b.extend_from_slice(&bits.to_le_bytes());
        b.extend_from_slice(&22u16.to_le_bytes());
        b.extend_from_slice(&bits.to_le_bytes()); // valid bits
        b.extend_from_slice(&mask.to_le_bytes());
        b.extend_from_slice(&sub.data1.to_le_bytes());
        b.extend_from_slice(&sub.data2.to_le_bytes());
        b.extend_from_slice(&sub.data3.to_le_bytes());
        b.extend_from_slice(&sub.data4);
        assert_eq!(b.len(), 40);
        b
    }

    fn plain(tag: u16, channels: u16, rate: u32, bits: u16) -> Vec<u8> {
        let mut b = extensible(channels, rate, bits, 0, &KSDATAFORMAT_SUBTYPE_PCM);
        b[..2].copy_from_slice(&tag.to_le_bytes());
        b[16..18].copy_from_slice(&0u16.to_le_bytes());
        b.truncate(18);
        b
    }

    fn f32s(v: &[f32]) -> Vec<u8> {
        v.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    #[test]
    fn parses_engine_formats() {
        let f = parse_format(&extensible(2, 48_000, 32, 3, &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT)).unwrap();
        assert_eq!(f, MixFormat { rate: 48_000, channels: 2, sample: Sample::F32, mask: 3 });
        let f = parse_format(&extensible(6, 44_100, 24, 0x3f, &KSDATAFORMAT_SUBTYPE_PCM)).unwrap();
        assert_eq!((f.sample, f.channels, f.mask), (Sample::I24, 6, 0x3f));
        assert_eq!(parse_format(&plain(WAVE_FORMAT_PCM, 1, 16_000, 16)).unwrap().sample, Sample::I16);
        assert_eq!(parse_format(&plain(WAVE_FORMAT_IEEE_FLOAT, 2, 96_000, 64)).unwrap().sample, Sample::F64);

        let mut bad_block = plain(WAVE_FORMAT_PCM, 2, 48_000, 16);
        bad_block[12] = 3;
        let mut short_ext = extensible(2, 48_000, 32, 3, &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT);
        short_ext.truncate(30);
        let mut small_cb = extensible(2, 48_000, 32, 3, &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT);
        small_cb[16] = 0;
        for raw in [
            vec![0u8; 10],
            plain(0x55, 2, 48_000, 16),                                        // MP3
            plain(WAVE_FORMAT_PCM, 2, 48_000, 12),                             // odd bit depth
            plain(WAVE_FORMAT_IEEE_FLOAT, 2, 48_000, 16),                      // half floats
            plain(WAVE_FORMAT_PCM, 0, 48_000, 16),
            plain(WAVE_FORMAT_PCM, 2, 0, 16),
            extensible(2, 48_000, 32, 3, &GUID::from_u128(0x00000092_0000_0010_8000_00aa00389b71)), // AC-3 passthrough
            bad_block,
            short_ext,
            small_cb,
        ] {
            assert!(parse_format(&raw).is_err(), "{raw:?} accepted");
        }
    }

    #[test]
    fn converts_samples_to_i16() {
        let fmt = |sample, channels| MixFormat { rate: 48_000, channels, sample, mask: 0 };
        let mut out = Vec::new();
        Converter::new(&fmt(Sample::F32, 2)).push(&f32s(&[0.5, -0.5, 1.5, f32::NAN, -1.0, f32::INFINITY]), &mut out);
        assert_eq!(out, [16384, -16384, 32767, 0, -32768, 0]);

        out.clear();
        let i16s: Vec<u8> = [1i16, -2, i16::MAX, i16::MIN].iter().flat_map(|x| x.to_le_bytes()).collect();
        Converter::new(&fmt(Sample::I16, 2)).push(&i16s, &mut out);
        assert_eq!(out, [1, -2, i16::MAX, i16::MIN]);

        out.clear();
        Converter::new(&fmt(Sample::I24, 1)).push(&[0x00, 0x00, 0x40, 0xff, 0xff, 0xff, 0x00, 0x00, 0x80], &mut out);
        assert_eq!(out, [16384, 0, -32768]);

        out.clear();
        let i32s: Vec<u8> = [0x4000_0000i32, i32::MIN].iter().flat_map(|x| x.to_le_bytes()).collect();
        Converter::new(&fmt(Sample::I32, 1)).push(&i32s, &mut out);
        assert_eq!(out, [16384, -32768]);

        out.clear();
        Converter::new(&fmt(Sample::U8, 1)).push(&[128, 192, 0], &mut out);
        assert_eq!(out, [0, 16384, -32768]);

        // A trailing partial frame is ignored; silence keeps the channel layout.
        out.clear();
        let mut c = Converter::new(&fmt(Sample::F32, 2));
        c.push(&f32s(&[0.25, 0.25, 0.25]), &mut out);
        c.push_silence(2, &mut out);
        assert_eq!(out, [8192, 8192, 0, 0, 0, 0]);
    }

    #[test]
    fn folds_surround_into_stereo() {
        // 5.1 (FL FR FC LFE BL BR): centre splits, LFE is dropped, rears fold into their side.
        let fmt = MixFormat { rate: 48_000, channels: 6, sample: Sample::F32, mask: 0x3f };
        let c = Converter::new(&fmt);
        assert_eq!(c.out_channels, 2);
        let mut out = Vec::new();
        let mut conv = c;
        conv.push(&f32s(&[0.1, 0.2, 0.4, 0.9, 0.2, 0.0]), &mut out);
        let expect_l = (0.1 + 0.707 * 0.4 + 0.707 * 0.2) * 32768.0;
        let expect_r = (0.2 + 0.707 * 0.4) * 32768.0;
        assert!((out[0] as f32 - expect_l).abs() <= 1.0 && (out[1] as f32 - expect_r).abs() <= 1.0, "{out:?}");

        // Side-surround 5.1 (mask 0x60f) maps by mask bit, not by position in the buffer.
        assert_eq!(downmix_gains(6, 0x60f)[4], [0.707, 0.0]);
        assert_eq!(downmix_gains(6, 0x60f)[5], [0.0, 0.707]);
        // No mask: standard order. More channels than mask bits: extras are silent.
        assert_eq!(downmix_gains(3, 0)[2], [0.707, 0.707]);
        assert_eq!(downmix_gains(4, 0x3)[3], [0.0, 0.0]);
        // Hot surround content clips instead of wrapping; a NaN channel does not spread.
        out.clear();
        conv.push(&f32s(&[1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.5, 0.5, f32::NAN, 0.0, 0.0, 0.0]), &mut out);
        assert_eq!(out, [32767, 32767, 16384, 16384]);
    }

    #[test]
    fn decimates_high_rates() {
        let mut c = Converter::new(&MixFormat { rate: 96_000, channels: 1, sample: Sample::I16, mask: 0 });
        assert_eq!(c.rate, 48_000);
        let src: Vec<u8> = [100i16, 300, -50, -150, 7].iter().flat_map(|x| x.to_le_bytes()).collect();
        let mut out = Vec::new();
        c.push(&src, &mut out);
        assert_eq!(out, [200, -100]); // the odd frame waits for its partner
        assert_eq!(Converter::new(&MixFormat { rate: 176_400, channels: 2, sample: Sample::F32, mask: 3 }).rate, 44_100);
        assert_eq!(Converter::new(&MixFormat { rate: 48_000, channels: 2, sample: Sample::F32, mask: 3 }).decim, 1);
        assert_eq!(Converter::new(&MixFormat { rate: 88_200, channels: 2, sample: Sample::F32, mask: 3 }).rate, 44_100);
        assert_eq!(Converter::new(&MixFormat { rate: 50_000, channels: 2, sample: Sample::F32, mask: 3 }).rate, 50_000);
    }

    #[test]
    fn rejects_unsupported_playback_formats() {
        assert!(AudioPlayer::new(1_000, 2).is_err());
        assert!(AudioPlayer::new(48_000, 0).is_err());
        assert!(AudioPlayer::new(48_000, 6).is_err());
    }

    /// Opens the real devices. Plays silence only: a silent render stream keeps the engine
    /// running so loopback has packets to deliver even when nothing else is playing.
    #[test]
    #[ignore = "uses the default audio device (silent)"]
    fn smoke_loopback_and_silent_playback() {
        assert!(AudioCapture::available(), "no default output device");
        let mut player = AudioPlayer::new(48_000, 2).unwrap();
        player.push(&vec![0i16; 2 * 9600]); // 200 ms of silence
        let seen = Arc::new(Mutex::new((0usize, 0usize, 0u32, 0u8)));
        let s = seen.clone();
        let cap = AudioCapture::start(Box::new(move |pcm, rate, channels| {
            let mut s = s.lock().unwrap();
            s.0 += 1;
            s.1 += pcm.len();
            (s.2, s.3) = (rate, channels);
        }))
        .unwrap();
        let t = Instant::now();
        std::thread::sleep(Duration::from_millis(300));
        drop(cap);
        let stopped_in = t.elapsed();
        let left = player.buf.lock().unwrap().queued_frames();
        drop(player);
        let (calls, samples, rate, channels) = *seen.lock().unwrap();
        eprintln!("loopback: {calls} callbacks, {samples} samples, {rate} Hz x{channels}, stopped after {stopped_in:?}; {left} frames unplayed");
        assert_eq!(left, 0, "the render thread did not drain the jitter buffer");
        assert!(calls > 0, "loopback delivered nothing while a stream was playing");
        assert!((8_000..=192_000).contains(&rate) && (1..=2).contains(&channels));
        let frames_per_call = samples / channels as usize / calls;
        assert!(frames_per_call <= rate as usize / 20, "chunks of {frames_per_call} frames");
        assert!(stopped_in < Duration::from_millis(500));
    }
}
