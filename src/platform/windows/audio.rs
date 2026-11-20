//! Audio capture (host, system loopback) and playback (viewer) (placeholder until implemented).

use crate::bail;
use crate::util::Result;

/// Captures what the host is playing. Dropping it stops capture.
pub struct AudioCapture;

impl AudioCapture {
    pub fn available() -> bool {
        false
    }

    /// `on_pcm(samples, rate, channels)` receives interleaved 16-bit PCM from a capture thread.
    pub fn start(_on_pcm: Box<dyn FnMut(&[i16], u32, u8) + Send>) -> Result<AudioCapture> {
        bail!("audio capture is not available on this host")
    }
}

/// Plays a PCM stream with a small jitter buffer. Dropping it stops playback.
pub struct AudioPlayer;

impl AudioPlayer {
    pub fn new(_rate: u32, _channels: u8) -> Result<AudioPlayer> {
        bail!("audio playback is not available here")
    }

    /// Queues interleaved 16-bit PCM.
    pub fn push(&mut self, _pcm: &[i16]) {}
}
