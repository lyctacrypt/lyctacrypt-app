use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{anyhow, bail, Result};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use eframe::egui;

pub const VOICE_RATE: u32 = 16_000;

pub const VOICE_MAX_SECS: f32 = 30.0;

const PREVIEW_MAX: u32 = 640;

pub fn decode_preview(data: &[u8]) -> Option<egui::ColorImage> {
    let mut reader = image::ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(96 * 1024 * 1024);
    reader.limits(limits);
    let img = reader.decode().ok()?;
    let img = img.thumbnail(PREVIEW_MAX, PREVIEW_MAX).to_rgba8();
    let size = [img.width() as usize, img.height() as usize];
    Some(egui::ColorImage::from_rgba_unmultiplied(size, img.as_raw()))
}

pub fn is_wav(data: &[u8]) -> bool {
    data.len() > 44 && &data[..4] == b"RIFF" && &data[8..12] == b"WAVE"
}

#[cfg(test)]
fn wav_seconds(data: &[u8]) -> Option<f32> {
    use rodio::Source;
    let d = rodio::Decoder::new_wav(Cursor::new(data.to_vec())).ok()?;
    d.total_duration().map(|d| d.as_secs_f32())
}

pub struct Recorder {
    stream: cpal::Stream,
    samples: Arc<Mutex<Vec<i16>>>,
    started: Instant,
}

impl Recorder {
    pub fn start() -> Result<Self> {
        let device = cpal::default_host()
            .default_input_device()
            .ok_or_else(|| anyhow!("no microphone found"))?;
        let config = device.default_input_config()?;
        let channels = config.channels() as usize;
        let step = config.sample_rate().0 as f64 / VOICE_RATE as f64;
        let max = (VOICE_RATE as f32 * VOICE_MAX_SECS) as usize;
        let samples = Arc::new(Mutex::new(Vec::<i16>::with_capacity(max)));
        let sink = Arc::clone(&samples);

        let mut phase = 0.0_f64;
        let (mut sum, mut count) = (0.0_f32, 0_u32);
        let mut push = move |frame_mono: f32| {
            sum += frame_mono;
            count += 1;
            phase += 1.0;
            if phase >= step {
                phase -= step;
                let v = (sum / count as f32).clamp(-1.0, 1.0);
                (sum, count) = (0.0, 0);
                if let Ok(mut s) = sink.lock() {
                    if s.len() < max {
                        s.push((v * i16::MAX as f32) as i16);
                    }
                }
            }
        };
        let err = |_e: cpal::StreamError| {};
        let cfg: cpal::StreamConfig = config.clone().into();
        let stream = match config.sample_format() {
            cpal::SampleFormat::F32 => device.build_input_stream(
                &cfg,
                move |data: &[f32], _: &_| {
                    for f in data.chunks(channels) {
                        push(f.iter().sum::<f32>() / channels as f32);
                    }
                },
                err,
                None,
            )?,
            cpal::SampleFormat::I16 => device.build_input_stream(
                &cfg,
                move |data: &[i16], _: &_| {
                    for f in data.chunks(channels) {
                        let s: f32 = f.iter().map(|&x| x as f32 / 32768.0).sum();
                        push(s / channels as f32);
                    }
                },
                err,
                None,
            )?,
            cpal::SampleFormat::U16 => device.build_input_stream(
                &cfg,
                move |data: &[u16], _: &_| {
                    for f in data.chunks(channels) {
                        let s: f32 = f.iter().map(|&x| (x as f32 - 32768.0) / 32768.0).sum();
                        push(s / channels as f32);
                    }
                },
                err,
                None,
            )?,
            other => bail!("unsupported microphone format: {other:?}"),
        };
        stream.play()?;
        Ok(Self {
            stream,
            samples,
            started: Instant::now(),
        })
    }

    pub fn seconds(&self) -> f32 {
        self.started.elapsed().as_secs_f32().min(VOICE_MAX_SECS)
    }

    pub fn full(&self) -> bool {
        self.started.elapsed().as_secs_f32() >= VOICE_MAX_SECS
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        drop(self.stream);
        let samples = self
            .samples
            .lock()
            .map_err(|_| anyhow!("recording failed"))?;
        if samples.len() < VOICE_RATE as usize / 4 {
            bail!("recording too short");
        }
        Ok(encode_wav(&samples))
    }
}

pub fn encode_wav(samples: &[i16]) -> Vec<u8> {
    let data_len = (samples.len() * 2) as u32;
    let mut out = Vec::with_capacity(44 + data_len as usize);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data_len).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&VOICE_RATE.to_le_bytes());
    out.extend_from_slice(&(VOICE_RATE * 2).to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_len.to_le_bytes());
    for s in samples {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out
}

pub struct Player {
    _stream: rodio::OutputStream,
    sink: rodio::Sink,
    pub file: u32,
}

impl Player {
    pub fn play(file: u32, data: Vec<u8>) -> Result<Self> {
        if !is_wav(&data) {
            bail!("only WAV voice notes can be played here; save the file instead");
        }
        let (stream, handle) = rodio::OutputStream::try_default()?;
        let sink = rodio::Sink::try_new(&handle)?;
        sink.append(rodio::Decoder::new_wav(Cursor::new(data))?);
        Ok(Self {
            _stream: stream,
            sink,
            file,
        })
    }

    pub fn finished(&self) -> bool {
        self.sink.empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wav_roundtrip() {
        let samples: Vec<i16> = (0..VOICE_RATE).map(|i| (i % 100) as i16 * 100).collect();
        let wav = encode_wav(&samples);
        assert!(is_wav(&wav));
        let secs = wav_seconds(&wav).unwrap();
        assert!((secs - 1.0).abs() < 0.01);
    }

    #[test]
    fn garbage_is_not_an_image() {
        assert!(decode_preview(b"not an image").is_none());
        assert!(decode_preview(&[]).is_none());
    }
}
