//! Audio forwarding: the IMA ADPCM codec carried in `ServerMsg::Audio`, the host-side
//! packetizer that turns captured PCM into messages and the viewer-side receiver that
//! decodes them into the platform player.
//!
//! ADPCM packet layout (`proto::AUDIO_IMA_ADPCM`): for every channel a little-endian `i16`
//! predictor and a `u8` step index (0..=88), then one 4-bit code per sample in interleaved
//! order, two codes per byte, low nibble first. Bit 7 of the first channel's step index
//! byte is set when the last byte carries a single code. Every packet starts from the codec
//! state stored in its own header, so packets decode independently and a lost or skipped
//! packet never corrupts the ones after it.

use crate::bail;
#[cfg(not(test))]
use crate::platform::audio::AudioPlayer;
// Tests never open a sound device: the receiver gets a player that only records what it was asked.
#[cfg(test)]
use tests::FakePlayer as AudioPlayer;
use crate::proto::{AUDIO_IMA_ADPCM, AUDIO_PCM16, ServerMsg};
use crate::util::Result;
use std::time::{Duration, Instant};

/// Channel counts the codec and the stream accept.
pub const MAX_CHANNELS: u8 = 2;
/// Sample rates accepted from the network.
pub const MIN_RATE: u32 = 8_000;
pub const MAX_RATE: u32 = 192_000;
/// Largest packet the decoders accept, in frames (one second at 48 kHz).
pub const MAX_PACKET_FRAMES: usize = 48_000;
/// Audio carried by one packet from the host.
pub const PACKET_MS: u32 = 20;

/// Header bytes per channel: predictor `i16` + step index `u8`.
const HEADER: usize = 3;
/// Flag in the first step index byte: the final payload byte holds one code.
const ODD: u8 = 0x80;
const MAX_INDEX: u8 = 88;

const STEPS: [i32; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143,
    157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552,
    1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487,
    12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];
const INDEX_ADJUST: [i32; 8] = [-1, -1, -1, -1, 2, 4, 6, 8];

/// Codec state of one channel; identical on both ends while they stay in sync.
#[derive(Clone, Copy, Default)]
struct Channel {
    pred: i32,
    index: i32,
}

impl Channel {
    /// The sample `code` reconstructs from the current state (without changing it).
    #[inline]
    fn reconstruct(&self, code: u8) -> i32 {
        let step = STEPS[self.index as usize];
        let mut diff = step >> 3;
        if code & 4 != 0 {
            diff += step;
        }
        if code & 2 != 0 {
            diff += step >> 1;
        }
        if code & 1 != 0 {
            diff += step >> 2;
        }
        let p = if code & 8 != 0 { self.pred - diff } else { self.pred + diff };
        p.clamp(i16::MIN as i32, i16::MAX as i32)
    }

    #[inline]
    fn decode(&mut self, code: u8) -> i16 {
        self.pred = self.reconstruct(code);
        self.index = (self.index + INDEX_ADJUST[(code & 7) as usize]).clamp(0, MAX_INDEX as i32);
        self.pred as i16
    }

    /// Emits the code whose reconstruction lands closest to `sample` (smaller steps win ties)
    /// and advances the state exactly as the decoder will.
    #[inline]
    fn encode(&mut self, sample: i16) -> u8 {
        let target = sample as i32;
        let mut best = (u32::MAX, 0u8);
        for magnitude in 0..8u8 {
            for code in [magnitude, magnitude | 8] {
                let err = (self.reconstruct(code) - target).unsigned_abs();
                if err < best.0 {
                    best = (err, code);
                }
            }
        }
        self.decode(best.1);
        best.1
    }
}

/// IMA ADPCM encoder for interleaved 16-bit PCM (4 bits per sample).
pub struct AdpcmEncoder {
    channels: usize,
    state: [Channel; MAX_CHANNELS as usize],
}

impl AdpcmEncoder {
    /// `channels` must be 1 or 2.
    pub fn new(channels: u8) -> AdpcmEncoder {
        assert!((1..=MAX_CHANNELS).contains(&channels), "ADPCM supports 1 or 2 channels, not {channels}");
        AdpcmEncoder { channels: channels as usize, state: [Channel::default(); MAX_CHANNELS as usize] }
    }

    /// Appends one self-contained packet holding the whole frames of `pcm` (at most
    /// `MAX_PACKET_FRAMES`) to `out` and returns the number of samples consumed.
    /// Nothing is appended when `pcm` holds no whole frame.
    pub fn encode(&mut self, pcm: &[i16], out: &mut Vec<u8>) -> usize {
        let c = self.channels;
        let n = (pcm.len() / c).min(MAX_PACKET_FRAMES) * c;
        if n == 0 {
            return 0;
        }
        out.reserve(HEADER * c + n.div_ceil(2));
        for (i, ch) in self.state[..c].iter().enumerate() {
            out.extend_from_slice(&(ch.pred as i16).to_le_bytes());
            out.push(ch.index as u8 | if i == 0 && !n.is_multiple_of(2) { ODD } else { 0 });
        }
        let (pairs, rest) = pcm[..n].as_chunks::<2>();
        let mut k = 0;
        for &[a, b] in pairs {
            let lo = self.state[k % c].encode(a);
            let hi = self.state[(k + 1) % c].encode(b);
            out.push(lo | hi << 4);
            k += 2;
        }
        if let [last] = rest {
            out.push(self.state[k % c].encode(*last));
        }
        n
    }
}

/// IMA ADPCM decoder. Packets carry their own state, so one decoder serves a whole stream
/// regardless of loss.
#[derive(Default)]
pub struct AdpcmDecoder;

impl AdpcmDecoder {
    /// Decodes one packet and appends its interleaved samples to `out`. Malformed packets
    /// (bad header, length or padding) are rejected without touching `out`.
    pub fn decode(&mut self, data: &[u8], channels: u8, out: &mut Vec<i16>) -> Result<()> {
        if !(1..=MAX_CHANNELS).contains(&channels) {
            bail!("unsupported audio channel count {channels}");
        }
        let c = channels as usize;
        let Some((header, payload)) = data.split_at_checked(HEADER * c) else { bail!("truncated audio packet") };
        let mut state = [Channel::default(); MAX_CHANNELS as usize];
        let mut odd = false;
        for (i, (h, ch)) in header.as_chunks::<HEADER>().0.iter().zip(state.iter_mut()).enumerate() {
            let flag = h[2] & ODD != 0;
            let index = h[2] & !ODD;
            if index > MAX_INDEX || (flag && i != 0) {
                bail!("bad ADPCM header");
            }
            odd |= flag;
            *ch = Channel { pred: i16::from_le_bytes([h[0], h[1]]) as i32, index: index as i32 };
        }
        let nibbles = (payload.len() * 2).checked_sub(odd as usize).ok_or("bad ADPCM packet length")?;
        if !nibbles.is_multiple_of(c) || nibbles / c > MAX_PACKET_FRAMES {
            bail!("bad ADPCM packet length");
        }
        if odd && payload.last().is_some_and(|b| b >> 4 != 0) {
            bail!("bad ADPCM padding");
        }
        out.reserve(nibbles);
        for k in 0..nibbles {
            let b = payload[k / 2];
            let code = if k % 2 == 0 { b & 15 } else { b >> 4 };
            out.push(state[k % c].decode(code));
        }
        Ok(())
    }
}

/// Appends little-endian 16-bit PCM (`proto::AUDIO_PCM16`) to `out`.
fn decode_pcm16(data: &[u8], channels: u8, out: &mut Vec<i16>) -> Result<()> {
    let frame = 2 * channels as usize;
    if frame == 0 || !data.len().is_multiple_of(frame) || data.len() / frame > MAX_PACKET_FRAMES {
        bail!("bad PCM packet length");
    }
    out.extend(data.as_chunks::<2>().0.iter().map(|b| i16::from_le_bytes(*b)));
    Ok(())
}

/// Sample rates and channel counts the stream carries.
pub fn valid_format(rate: u32, channels: u8) -> bool {
    (MIN_RATE..=MAX_RATE).contains(&rate) && (1..=MAX_CHANNELS).contains(&channels)
}

/// Host side: frames the PCM from `platform::audio::AudioCapture` into `PACKET_MS` ADPCM
/// messages. Digital silence is not sent; the viewer plays silence when its buffer runs dry.
pub struct AudioSender {
    enc: AdpcmEncoder,
    rate: u32,
    channels: u8,
    pending: Vec<i16>,
    packet: Vec<u8>,
    seq: u32,
}

impl Default for AudioSender {
    fn default() -> Self {
        AudioSender::new()
    }
}

impl AudioSender {
    pub fn new() -> AudioSender {
        AudioSender { enc: AdpcmEncoder::new(1), rate: 0, channels: 0, pending: Vec::new(), packet: Vec::new(), seq: 0 }
    }

    /// Takes one capture callback's worth of PCM and hands each completed message to `send`.
    /// Input in a format the stream cannot carry is dropped.
    pub fn push(&mut self, pcm: &[i16], rate: u32, channels: u8, mut send: impl FnMut(ServerMsg<'_>)) {
        if !valid_format(rate, channels) {
            return;
        }
        if (rate, channels) != (self.rate, self.channels) {
            (self.rate, self.channels) = (rate, channels);
            self.enc = AdpcmEncoder::new(channels);
            self.pending.clear();
        }
        self.pending.extend_from_slice(pcm);
        let per_packet = (rate * PACKET_MS / 1000) as usize * channels as usize;
        let mut done = 0;
        while self.pending.len() - done >= per_packet {
            let chunk = &self.pending[done..done + per_packet];
            done += per_packet;
            if chunk.iter().all(|&s| s == 0) {
                // Restart from rest so the first packet after the gap matches its content.
                self.enc = AdpcmEncoder::new(channels);
                continue;
            }
            self.packet.clear();
            self.enc.encode(chunk, &mut self.packet);
            self.seq = self.seq.wrapping_add(1);
            send(ServerMsg::Audio { seq: self.seq, rate, channels, codec: AUDIO_IMA_ADPCM, data: &self.packet });
        }
        self.pending.drain(..done);
    }
}

/// How long the receiver waits before trying to open an audio device again.
const PLAYER_RETRY: Duration = Duration::from_secs(5);
/// However often the host changes the stream format, a new player (on Linux a `pw-play` process)
/// is opened at most this often; packets in another format are dropped meanwhile.
const FORMAT_HOLD: Duration = Duration::from_secs(2);

/// Viewer side: decodes `ServerMsg::Audio` and queues it on the platform player, which is
/// (re)opened when the stream format changes.
#[derive(Default)]
pub struct AudioReceiver {
    dec: AdpcmDecoder,
    pcm: Vec<i16>,
    player: Option<AudioPlayer>,
    format: (u32, u8),
    retry_at: Option<Instant>,
    /// When a player was last opened (or tried).
    opened_at: Option<Instant>,
}

impl AudioReceiver {
    /// Decodes one message's payload into interleaved PCM.
    pub fn decode(&mut self, rate: u32, channels: u8, codec: u8, data: &[u8]) -> Result<&[i16]> {
        if !valid_format(rate, channels) {
            bail!("unsupported audio format: {rate} Hz, {channels} channels");
        }
        self.pcm.clear();
        match codec {
            AUDIO_IMA_ADPCM => self.dec.decode(data, channels, &mut self.pcm)?,
            AUDIO_PCM16 => decode_pcm16(data, channels, &mut self.pcm)?,
            c => bail!("unknown audio codec {c}"),
        }
        Ok(&self.pcm)
    }

    /// Decodes and plays one message. Errors report a malformed message or a missing audio
    /// device (once per failure streak); the session can carry on after either.
    pub fn play(&mut self, rate: u32, channels: u8, codec: u8, data: &[u8]) -> Result<()> {
        self.play_at(Instant::now(), rate, channels, codec, data)
    }

    fn play_at(&mut self, now: Instant, rate: u32, channels: u8, codec: u8, data: &[u8]) -> Result<()> {
        self.decode(rate, channels, codec, data)?;
        if self.format != (rate, channels) {
            if self.opened_at.is_some_and(|t| now.duration_since(t) < FORMAT_HOLD) {
                return Ok(());
            }
            self.player = None;
            self.format = (rate, channels);
            self.retry_at = None;
        }
        if self.player.is_none() {
            if self.retry_at.is_some_and(|t| now < t) {
                return Ok(());
            }
            self.opened_at = Some(now);
            match AudioPlayer::new(rate, channels) {
                Ok(p) => {
                    self.player = Some(p);
                    self.retry_at = None;
                }
                Err(e) => {
                    let first = self.retry_at.is_none();
                    self.retry_at = Some(now + PLAYER_RETRY);
                    return if first { Err(e) } else { Ok(()) };
                }
            }
        }
        if let Some(p) = self.player.as_mut() {
            p.push(&self.pcm);
        }
        Ok(())
    }

    /// Whether the audio device could not be opened when last tried: an error from `play` then
    /// is about the device rather than the message.
    #[cfg_attr(not(windows), allow(dead_code))] // only the Windows viewer switches sound off and on
    pub fn device_failed(&self) -> bool {
        self.retry_at.is_some()
    }

    /// Stops playback when the user switches sound off; the next message reopens the device at
    /// once (the format hold and retry delay only pace what the host sends).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn stop(&mut self) {
        self.player = None;
        self.format = (0, 0);
        self.retry_at = None;
        self.opened_at = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::S_AUDIO;
    use std::cell::{Cell, RefCell};

    thread_local! {
        /// Formats `AudioPlayer::new` was called with on this thread, and whether it fails.
        static OPENED: RefCell<Vec<(u32, u8)>> = const { RefCell::new(Vec::new()) };
        static NO_DEVICE: Cell<bool> = const { Cell::new(false) };
    }

    pub struct FakePlayer;

    impl FakePlayer {
        pub fn new(rate: u32, channels: u8) -> Result<FakePlayer> {
            OPENED.with_borrow_mut(|o| o.push((rate, channels)));
            if NO_DEVICE.get() {
                bail!("no audio device");
            }
            Ok(FakePlayer)
        }

        pub fn push(&mut self, _pcm: &[i16]) {}
    }

    #[test]
    fn format_flapping_cannot_respawn_the_player() {
        let packet = |ch: u8| vec![1u8; 2 * 960 * ch as usize];
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        for no_device in [false, true] {
            NO_DEVICE.set(no_device);
            let mut r = AudioReceiver::default();
            // A host alternating mono and stereo in every 20 ms packet for 10 s: a player every 2 s.
            for i in 0..500 {
                let ch = 1 + (i % 2) as u8;
                let _ = r.play_at(at(20 * i), 48_000, ch, AUDIO_PCM16, &packet(ch));
            }
            let opened = OPENED.take();
            assert_eq!(opened.len(), 5);
            assert!(opened.windows(2).all(|w| w[0] != w[1]), "{opened:?}");
        }
        NO_DEVICE.set(false);
        // A format that settles is followed at once, then kept.
        let mut r = AudioReceiver::default();
        r.play_at(at(0), 48_000, 2, AUDIO_PCM16, &packet(2)).unwrap();
        for i in 0..100 {
            r.play_at(at(5000 + 20 * i), 44_100, 1, AUDIO_PCM16, &packet(1)).unwrap();
        }
        assert_eq!(OPENED.take(), [(48_000, 2), (44_100, 1)]);
    }

    #[test]
    fn receiver_checks_packets_before_playing() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let mut r = AudioReceiver::default();
        // Longer than a packet may be, or not whole frames: refused before any player is involved.
        assert!(r.play_at(at(0), 48_000, 2, AUDIO_PCM16, &vec![0; 4 * (MAX_PACKET_FRAMES + 1)]).is_err());
        assert!(r.play_at(at(0), 48_000, 2, AUDIO_PCM16, &[0; 6]).is_err());
        assert!(!r.device_failed());
        assert!(OPENED.take().is_empty());
        // A missing device is told apart from a bad message, and reported once per streak.
        NO_DEVICE.set(true);
        assert!(r.play_at(at(0), 48_000, 2, AUDIO_PCM16, &[0; 8]).is_err());
        assert!(r.device_failed());
        assert!(r.play_at(at(20), 48_000, 2, AUDIO_PCM16, &[0; 8]).is_ok());
        // Sound switched off and on again: the device is tried again at once.
        r.stop();
        assert!(!r.device_failed());
        NO_DEVICE.set(false);
        r.play_at(at(40), 48_000, 2, AUDIO_PCM16, &[0; 8]).unwrap();
        assert_eq!(OPENED.take(), [(48_000, 2), (48_000, 2)]);
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn sample(&mut self, amp: f64) -> i16 {
            (((self.next() % 65536) as f64 - 32768.0) * amp) as i16
        }
    }

    fn sine(rate: f64, freq: f64, amp: f64, frames: usize, phase: f64) -> Vec<i16> {
        (0..frames).map(|i| (amp * 32767.0 * (2.0 * std::f64::consts::PI * freq * i as f64 / rate + phase).sin()).round() as i16).collect()
    }

    fn interleave(l: &[i16], r: &[i16]) -> Vec<i16> {
        l.iter().zip(r).flat_map(|(&a, &b)| [a, b]).collect()
    }

    fn snr_db(reference: &[i16], decoded: &[i16]) -> f64 {
        assert_eq!(reference.len(), decoded.len());
        let signal: f64 = reference.iter().map(|&s| (s as f64).powi(2)).sum();
        let noise: f64 = reference.iter().zip(decoded).map(|(&a, &b)| (a as f64 - b as f64).powi(2)).sum();
        10.0 * (signal / noise.max(1e-9)).log10()
    }

    /// Encodes in `PACKET_MS` packets and decodes each one separately, like the stream does.
    fn roundtrip(pcm: &[i16], channels: u8, packet_frames: usize) -> (Vec<i16>, usize) {
        let mut enc = AdpcmEncoder::new(channels);
        let mut dec = AdpcmDecoder;
        let (mut out, mut bytes) = (Vec::new(), 0);
        for chunk in pcm.chunks(packet_frames * channels as usize) {
            let mut packet = Vec::new();
            assert_eq!(enc.encode(chunk, &mut packet), chunk.len());
            bytes += packet.len();
            dec.decode(&packet, channels, &mut out).unwrap();
        }
        (out, bytes)
    }

    #[test]
    fn sines_survive_with_good_snr() {
        // 4-bit IMA ADPCM is slew-rate limited: SNR falls about 6 dB per octave, so the
        // 25 dB bar covers the band where music carries its energy and treble gets a lower one.
        for rate in [44_100.0, 48_000.0] {
            for (freq, min_db) in [(60.0, 25.0), (440.0, 25.0), (1000.0, 25.0), (2500.0, 25.0), (6000.0, 19.0), (10_000.0, 16.0)] {
                for amp in [0.01, 0.05, 0.3, 0.9] {
                    let pcm = sine(rate, freq, amp, rate as usize / 2, 0.3);
                    let (out, _) = roundtrip(&pcm, 1, 960);
                    let snr = snr_db(&pcm, &out);
                    assert!(snr >= min_db, "{freq} Hz at {amp} ({rate} Hz): SNR {snr:.1} dB");
                }
            }
        }
    }

    #[test]
    fn stereo_channels_stay_independent() {
        let l = sine(48_000.0, 440.0, 0.5, 4800, 0.0);
        let r = sine(48_000.0, 2500.0, 0.2, 4800, 1.0);
        let pcm = interleave(&l, &r);
        let (out, bytes) = roundtrip(&pcm, 2, 960);
        let (dl, dr): (Vec<i16>, Vec<i16>) = out.as_chunks::<2>().0.iter().map(|&[a, b]| (a, b)).unzip();
        assert!(snr_db(&l, &dl) >= 25.0, "left {:.1} dB", snr_db(&l, &dl));
        assert!(snr_db(&r, &dr) >= 25.0, "right {:.1} dB", snr_db(&r, &dr));
        // 4 bits per sample plus a 6-byte header per 20 ms packet.
        assert_eq!(bytes, 5 * (6 + 960));
    }

    #[test]
    fn noise_and_extremes_roundtrip() {
        let mut rng = Rng(0x9e3779b97f4a7c15);
        let noise: Vec<i16> = (0..9600).map(|_| rng.sample(0.25)).collect();
        let (out, _) = roundtrip(&noise, 2, 960);
        let snr = snr_db(&noise, &out);
        assert!(snr >= 6.0, "white noise SNR {snr:.1} dB");

        // Full-scale square wave and constant rails: the predictor clamps instead of wrapping.
        let square: Vec<i16> = (0..4800).map(|i| if (i / 24) % 2 == 0 { i16::MAX } else { i16::MIN }).collect();
        let (out, _) = roundtrip(&square, 1, 960);
        assert!(snr_db(&square, &out) >= 5.0, "square SNR {:.1} dB", snr_db(&square, &out));
        for rail in [i16::MIN, i16::MAX] {
            let flat = vec![rail; 2000];
            let (out, _) = roundtrip(&flat, 1, 960);
            assert!(out[100..].iter().all(|&s| (s as i32 - rail as i32).abs() < 16));
        }

        let (out, _) = roundtrip(&[0; 1920], 2, 960);
        assert!(out.iter().all(|&s| s.abs() <= 1));
    }

    #[test]
    fn odd_sample_counts() {
        for len in [1usize, 2, 3, 5, 961, 1001] {
            let pcm = sine(48_000.0, 700.0, 0.4, len, 0.0);
            let mut packet = Vec::new();
            assert_eq!(AdpcmEncoder::new(1).encode(&pcm, &mut packet), len);
            assert_eq!(packet.len(), 3 + len.div_ceil(2));
            let mut out = Vec::new();
            AdpcmDecoder.decode(&packet, 1, &mut out).unwrap();
            assert_eq!(out.len(), len);
        }
        // A trailing partial stereo frame is left for the caller.
        let mut packet = Vec::new();
        assert_eq!(AdpcmEncoder::new(2).encode(&[100, -100, 200], &mut packet), 2);
        let mut out = Vec::new();
        AdpcmDecoder.decode(&packet, 2, &mut out).unwrap();
        assert_eq!(out.len(), 2);
        // No whole frame: no packet at all.
        packet.clear();
        assert_eq!(AdpcmEncoder::new(2).encode(&[1], &mut packet), 0);
        assert!(packet.is_empty());
        // Oversized input is capped at one packet's worth.
        let big = vec![5i16; (MAX_PACKET_FRAMES + 10) * 2];
        assert_eq!(AdpcmEncoder::new(2).encode(&big, &mut packet), MAX_PACKET_FRAMES * 2);
        out.clear();
        AdpcmDecoder.decode(&packet, 2, &mut out).unwrap();
        assert_eq!(out.len(), MAX_PACKET_FRAMES * 2);
    }

    #[test]
    fn packets_decode_independently() {
        let pcm = sine(48_000.0, 1234.0, 0.6, 4800, 0.0);
        let mut enc = AdpcmEncoder::new(1);
        let packets: Vec<Vec<u8>> = pcm
            .chunks(960)
            .map(|c| {
                let mut p = Vec::new();
                enc.encode(c, &mut p);
                p
            })
            .collect();
        let mut whole = Vec::new();
        for p in &packets {
            AdpcmDecoder.decode(p, 1, &mut whole).unwrap();
        }
        // Losing packet 2 leaves every other packet's output unchanged.
        let mut lossy = Vec::new();
        for (i, p) in packets.iter().enumerate().filter(|(i, _)| *i != 2) {
            let start = lossy.len();
            AdpcmDecoder.decode(p, 1, &mut lossy).unwrap();
            assert_eq!(&lossy[start..], &whole[i * 960..(i + 1) * 960]);
        }
    }

    #[test]
    fn rejects_hostile_packets() {
        let mut d = AdpcmDecoder;
        let mut out = vec![7i16];
        let bad: &[(&[u8], u8)] = &[
            (&[], 1),
            (&[0, 0], 1),
            (&[0, 0, 0, 0, 0], 2),
            (&[0, 0, 89], 1),
            (&[0, 0, 0xff, 0x12], 1),
            (&[0, 0, ODD], 1),                     // odd flag without payload
            (&[0, 0, ODD, 0x21], 1),               // padding nibble not zero
            (&[0, 0, ODD, 0, 0, 0, 0x11], 2),      // odd code count for stereo
            (&[0, 0, 0, 0, 0, ODD, 0x11], 2),      // flag on the second channel
            (&[0, 0, 0, 0x11], 0),
            (&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11], 3),
        ];
        for (data, ch) in bad {
            assert!(d.decode(data, *ch, &mut out).is_err(), "{data:?} x{ch} accepted");
        }
        let mut huge = vec![0u8; 3 + MAX_PACKET_FRAMES / 2 + 1];
        huge[2] = 0;
        assert!(d.decode(&huge, 1, &mut out).is_err());
        assert_eq!(out, [7], "rejected packets must not emit samples");

        // Header-only packets are valid and empty.
        d.decode(&[1, 2, 88], 1, &mut out).unwrap();
        assert_eq!(out, [7]);

        // Random garbage: never panics, and accepted packets emit exactly their code count.
        let mut rng = Rng(12345);
        for _ in 0..20_000 {
            let len = (rng.next() % 64) as usize;
            let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let ch = (rng.next() % 4) as u8;
            out.clear();
            if d.decode(&data, ch, &mut out).is_ok() {
                assert!(out.len() <= 2 * len);
            }
        }
    }

    #[test]
    fn pcm16_payloads() {
        let mut r = AudioReceiver::default();
        assert_eq!(r.decode(48_000, 2, AUDIO_PCM16, &[1, 0, 0xff, 0xff]).unwrap(), [1, -1]);
        assert!(r.decode(48_000, 2, AUDIO_PCM16, &[1, 0, 0xff]).is_err());
        assert!(r.decode(48_000, 2, 7, &[1, 0, 0xff, 0xff]).is_err());
        assert!(r.decode(4_000, 2, AUDIO_PCM16, &[1, 0, 0xff, 0xff]).is_err());
        assert!(r.decode(48_000, 3, AUDIO_PCM16, &[1, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn sender_frames_packets_and_skips_silence() {
        let mut s = AudioSender::new();
        let mut r = AudioReceiver::default();
        let tone = interleave(&sine(48_000.0, 440.0, 0.5, 2400, 0.0), &sine(48_000.0, 440.0, 0.5, 2400, 0.0));
        let mut msgs = Vec::new();
        let mut decoded = Vec::new();
        // Uneven callback sizes, as capture delivers them.
        for chunk in tone.chunks(2 * 441) {
            s.push(chunk, 48_000, 2, |m| {
                let mut b = Vec::new();
                m.encode(&mut b);
                assert_eq!(b[0], S_AUDIO);
                if let ServerMsg::Audio { seq, rate, channels, codec, data } = ServerMsg::decode(&b).unwrap() {
                    decoded.extend_from_slice(r.decode(rate, channels, codec, data).unwrap());
                    msgs.push((seq, data.len()));
                }
            });
        }
        // 2400 frames = two full 960-frame packets; the rest waits for more input.
        assert_eq!(msgs, [(1, 6 + 960), (2, 6 + 960)]);
        assert!(snr_db(&tone[..decoded.len()], &decoded) >= 25.0);

        // Digital silence produces nothing; the sequence continues afterwards.
        let mut n = 0;
        s.push(&vec![0; 2 * 960 * 3], 48_000, 2, |_| n += 1);
        assert_eq!(n, 1, "only the packet that still held tone is sent");
        let mut seqs = Vec::new();
        s.push(&tone[..2 * 960], 48_000, 2, |m| {
            if let ServerMsg::Audio { seq, .. } = m {
                seqs.push(seq);
            }
        });
        assert_eq!(seqs, [4]);

        // A format change restarts framing; unusable formats are ignored.
        let mut fmts = Vec::new();
        s.push(&vec![100; 882], 44_100, 1, |m| {
            if let ServerMsg::Audio { rate, channels, data, .. } = m {
                fmts.push((rate, channels, data.len()));
            }
        });
        assert_eq!(fmts, [(44_100, 1, 3 + 441)]);
        s.push(&[1; 6000], 48_000, 6, |_| panic!("6 channels cannot be sent"));
        s.push(&[1; 6000], 1_000, 1, |_| panic!("1 kHz cannot be sent"));
    }

    #[test]
    fn sender_restarts_the_encoder_after_silence_and_format_changes() {
        /// The codec state (header) each message sent for `pcm` starts from.
        fn headers(s: &mut AudioSender, pcm: &[i16], rate: u32) -> Vec<Vec<u8>> {
            let mut h = Vec::new();
            s.push(pcm, rate, 1, |m| {
                if let ServerMsg::Audio { data, .. } = m {
                    h.push(data[..HEADER].to_vec());
                }
            });
            h
        }
        let loud: Vec<i16> = (0..960).map(|i| if i % 2 == 0 { 30_000 } else { -30_000 }).collect();
        let mut s = AudioSender::new();
        assert_eq!(headers(&mut s, &loud, 48_000), [[0u8, 0, 0]]);
        // Straight after loud audio, quiet audio starts from the loud audio's state...
        assert_ne!(headers(&mut s, &[1; 960], 48_000), [[0u8, 0, 0]]);
        // ...but after silence from rest, as if the silence had been sent, and so after a new rate.
        headers(&mut s, &loud, 48_000);
        assert!(headers(&mut s, &[0; 960], 48_000).is_empty());
        assert_eq!(headers(&mut s, &[1; 960], 48_000), [[0u8, 0, 0]]);
        headers(&mut s, &loud, 48_000);
        assert_eq!(headers(&mut s, &[1; 882], 44_100), [[0u8, 0, 0]]);
    }
}
