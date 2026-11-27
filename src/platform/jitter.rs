//! Playback jitter buffer shared by the platform audio players.
//!
//! Sits between the network and the audio device: playback starts, and restarts after an
//! underrun, only once `start` worth of audio is queued; underruns play silence with short
//! fades so gaps do not click; latency stays bounded by dropping the oldest audio when the
//! queue passes `max`, or when it has stayed well above `start` for a while (bursts after a
//! network stall, clock drift between host and viewer).

use std::collections::VecDeque;

/// Queue level above `start` that counts as excess latency.
const SLACK_MS: usize = 80;
/// How long excess latency is tolerated before it is dropped.
const TRIM_AFTER_MS: usize = 2000;
/// Fade applied when audio stops or resumes around an underrun.
const FADE_MS: usize = 2;
/// Typical size of one push, used to size the queue up front.
const PUSH_HINT_MS: usize = 20;

pub struct JitterBuffer {
    channels: usize,
    queue: VecDeque<i16>,
    /// All levels are in samples (frames * channels).
    start: usize,
    max: usize,
    high: usize,
    trim_after: usize,
    /// Samples pulled while the queue stayed above `high`.
    over: usize,
    buffering: bool,
    fade_frames: usize,
    /// Frames of fade-in still to apply after playback resumed.
    fade_in: usize,
}

impl JitterBuffer {
    /// `channels` >= 1; `start_ms` <= `max_ms`.
    pub fn new(rate: u32, channels: u8, start_ms: u32, max_ms: u32) -> JitterBuffer {
        let ch = channels.max(1) as usize;
        let frames = |ms: usize| rate as usize * ms / 1000;
        let start = frames(start_ms as usize) * ch;
        let max = (frames(max_ms as usize) * ch).max(start);
        JitterBuffer {
            channels: ch,
            queue: VecDeque::with_capacity(max + frames(PUSH_HINT_MS) * ch),
            start,
            max,
            high: (start + frames(SLACK_MS) * ch).min(max),
            trim_after: frames(TRIM_AFTER_MS) * ch,
            over: 0,
            buffering: true,
            fade_frames: frames(FADE_MS).max(1),
            fade_in: 0,
        }
    }

    /// Frames waiting to be played.
    #[cfg(test)]
    pub fn queued_frames(&self) -> usize {
        self.queue.len() / self.channels
    }

    /// Queues interleaved PCM (a trailing partial frame is ignored).
    pub fn push(&mut self, pcm: &[i16]) {
        let mut pcm = &pcm[..pcm.len() - pcm.len() % self.channels];
        if pcm.len() > self.max {
            // All but its last `start` would be dropped at once: never grow the queue for it.
            self.queue.clear();
            self.over = 0;
            pcm = &pcm[pcm.len() - self.start..];
        }
        self.queue.extend(pcm);
        if self.queue.len() > self.max {
            self.drop_to_start();
        }
    }

    /// Fills `out` (whole frames) with queued audio, or silence while buffering. Returns
    /// whether any queued audio went out.
    pub fn pull(&mut self, out: &mut [i16]) -> bool {
        let len = out.len() - out.len() % self.channels;
        let (out, tail) = out.split_at_mut(len);
        tail.fill(0);
        if self.buffering {
            if self.queue.len() < self.start.max(self.channels) {
                out.fill(0);
                return false;
            }
            self.buffering = false;
            self.fade_in = self.fade_frames;
        }
        let n = len.min(self.queue.len());
        for (o, s) in out[..n].iter_mut().zip(self.queue.drain(..n)) {
            *o = s;
        }
        out[n..].fill(0);
        let frames = n / self.channels;
        if self.fade_in > 0 {
            let done = self.fade_frames - self.fade_in;
            let k = self.fade_in.min(frames);
            for f in 0..k {
                self.scale(&mut out[f * self.channels..(f + 1) * self.channels], done + f + 1, self.fade_frames + 1);
            }
            self.fade_in -= k;
        }
        if n < len {
            // Underrun: fade out what we had and wait for `start` worth of audio again.
            let k = self.fade_frames.min(frames);
            for j in 0..k {
                let f = frames - k + j;
                self.scale(&mut out[f * self.channels..(f + 1) * self.channels], k - j, k + 1);
            }
            self.buffering = true;
            self.over = 0;
        } else if self.queue.len() > self.high {
            self.over += len;
            if self.over >= self.trim_after {
                self.drop_to_start();
            }
        } else {
            self.over = 0;
        }
        n > 0
    }

    fn scale(&self, frame: &mut [i16], num: usize, den: usize) {
        for s in frame {
            *s = (*s as i32 * num as i32 / den as i32) as i16;
        }
    }

    fn drop_to_start(&mut self) {
        let excess = self.queue.len().saturating_sub(self.start);
        self.queue.drain(..excess);
        self.over = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: u32 = 1000; // one frame per millisecond keeps the arithmetic readable

    fn ramp(frames: usize, ch: usize, v: i16) -> Vec<i16> {
        vec![v; frames * ch]
    }

    #[test]
    fn waits_for_start_level_then_plays() {
        let mut j = JitterBuffer::new(RATE, 2, 60, 300);
        let mut out = vec![1i16; 20];
        j.push(&ramp(50, 2, 1000));
        assert!(!j.pull(&mut out));
        assert!(out.iter().all(|&s| s == 0));
        assert_eq!(j.queued_frames(), 50);
        j.push(&ramp(10, 2, 1000));
        assert!(j.pull(&mut out));
        // Fade-in over the first 2 frames, then the signal itself.
        assert_eq!(&out[..4], &[333, 333, 666, 666]);
        assert!(out[4..].iter().all(|&s| s == 1000));
        assert_eq!(j.queued_frames(), 50);
    }

    #[test]
    fn underrun_fades_out_plays_silence_and_rebuffers() {
        let mut j = JitterBuffer::new(RATE, 1, 10, 300);
        j.push(&ramp(14, 1, 900));
        let mut out = vec![0i16; 10];
        assert!(j.pull(&mut out));
        assert!(j.pull(&mut out)); // only 4 frames left: underrun inside this pull
        assert_eq!(&out[..4], &[900, 900, 600, 300]);
        assert!(out[4..].iter().all(|&s| s == 0));
        // Below the start level again: silence until 10 frames are queued.
        j.push(&ramp(9, 1, 900));
        assert!(!j.pull(&mut out));
        assert!(out.iter().all(|&s| s == 0));
        j.push(&ramp(1, 1, 900));
        assert!(j.pull(&mut out));
    }

    #[test]
    fn caps_latency() {
        let mut j = JitterBuffer::new(RATE, 2, 60, 300);
        j.push(&ramp(301, 2, 5));
        assert_eq!(j.queued_frames(), 60, "past the ceiling the oldest audio is dropped");
        // A push larger than the ceiling keeps only its newest audio, without growing the queue.
        let cap = j.queue.capacity();
        let mut big = ramp(5000, 2, 1);
        big.extend(ramp(60, 2, 7));
        j.push(&big);
        assert_eq!(j.queued_frames(), 60);
        assert!(j.queue.iter().all(|&s| s == 7));
        assert_eq!(j.queue.capacity(), cap);

        // Sitting above start + slack for two seconds drops the excess too.
        let mut j = JitterBuffer::new(RATE, 1, 60, 300);
        j.push(&ramp(200, 1, 5));
        let mut out = vec![0i16; 10];
        let mut pulled = 0;
        while j.queued_frames() > 60 && pulled < 3000 {
            j.push(&ramp(10, 1, 5));
            j.pull(&mut out);
            pulled += 10;
        }
        assert_eq!(j.queued_frames(), 60);
        assert!((2000..=2010).contains(&pulled), "trimmed after {pulled} ms");
    }

    #[test]
    fn partial_frames_are_ignored() {
        let mut j = JitterBuffer::new(RATE, 2, 1, 300);
        j.push(&[1, 2, 3]);
        assert_eq!(j.queued_frames(), 1);
        let mut out = [9i16; 3];
        assert!(j.pull(&mut out));
        assert_eq!(out[2], 0);
        assert_eq!(JitterBuffer::new(RATE, 0, 10, 5).channels, 1);
    }
}
