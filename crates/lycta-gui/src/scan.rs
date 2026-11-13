use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use eframe::egui;

pub fn decode_luma(w: usize, h: usize, luma: &[u8]) -> Option<String> {
    if w == 0 || h == 0 || luma.len() < w * h {
        return None;
    }
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| luma[y * w + x]);
    img.detect_grids()
        .into_iter()
        .find_map(|g| g.decode().ok().map(|(_, content)| content))
}

pub fn decode_file(path: &std::path::Path) -> Result<String> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > 32 * 1024 * 1024 {
        return Err(anyhow!("image too large"));
    }
    let img = image::ImageReader::open(path)?
        .with_guessed_format()?
        .decode()?
        .thumbnail(1600, 1600)
        .to_luma8();
    decode_luma(img.width() as usize, img.height() as usize, img.as_raw())
        .ok_or_else(|| anyhow!("no QR code found in this image"))
}

#[derive(Default)]
struct Shared {
    frame: Option<(usize, usize, Vec<u8>)>,
    found: Option<String>,
    error: Option<String>,
}

pub struct Scanner {
    stop: Arc<AtomicBool>,
    shared: Arc<Mutex<Shared>>,
}

impl Scanner {
    pub fn start(ctx: egui::Context) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Mutex::new(Shared::default()));
        let (stop2, shared2) = (Arc::clone(&stop), Arc::clone(&shared));
        std::thread::spawn(move || {
            if let Err(e) = capture_loop(&stop2, &shared2, &ctx) {
                if let Ok(mut s) = shared2.lock() {
                    s.error = Some(e.to_string());
                }
                ctx.request_repaint();
            }
        });
        Self { stop, shared }
    }

    pub fn take_frame(&self) -> Option<egui::ColorImage> {
        let (w, h, rgb) = self.shared.lock().ok()?.frame.take()?;
        Some(egui::ColorImage::from_rgb([w, h], &rgb))
    }

    pub fn found(&self) -> Option<String> {
        self.shared.lock().ok()?.found.clone()
    }

    pub fn error(&self) -> Option<String> {
        self.shared.lock().ok()?.error.clone()
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn capture_loop(stop: &AtomicBool, shared: &Mutex<Shared>, ctx: &egui::Context) -> Result<()> {
    use nokhwa::pixel_format::RgbFormat;
    use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};

    let format = RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
    let mut cam = nokhwa::Camera::new(CameraIndex::Index(0), format)
        .map_err(|e| anyhow!("no camera available ({e})"))?;
    cam.open_stream()
        .map_err(|e| anyhow!("camera could not start ({e})"))?;
    while !stop.load(Ordering::Relaxed) {
        let frame = cam.frame().map_err(|e| anyhow!("camera error ({e})"))?;
        let img = frame
            .decode_image::<RgbFormat>()
            .map_err(|e| anyhow!("camera error ({e})"))?;
        let (w, h) = (img.width() as usize, img.height() as usize);
        let rgb = img.into_raw();
        let luma: Vec<u8> = rgb
            .chunks_exact(3)
            .map(|p| ((p[0] as u32 * 299 + p[1] as u32 * 587 + p[2] as u32 * 114) / 1000) as u8)
            .collect();
        let found = decode_luma(w, h, &luma);
        let done = found.is_some();
        if let Ok(mut s) = shared.lock() {
            s.frame = Some((w, h, rgb));
            if done {
                s.found = found;
            }
        }
        ctx.request_repaint();
        if done {
            break;
        }
    }
    let _ = cam.stop_stream();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_back_a_generated_qr() {
        let text = "lycta:test-invite-0123456789";
        let (n, cells) = lycta_node::qr::matrix(text).expect("qr");

        let (scale, quiet) = (6, 4);
        let side = (n + 2 * quiet) * scale;
        let mut luma = vec![255u8; side * side];
        for y in 0..n {
            for x in 0..n {
                if cells[y * n + x] {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let px = (x + quiet) * scale + dx;
                            let py = (y + quiet) * scale + dy;
                            luma[py * side + px] = 0;
                        }
                    }
                }
            }
        }

        assert_eq!(decode_luma(side, side, &luma), Some(text.to_uppercase()));
        assert_eq!(decode_luma(side, side, &vec![255u8; side * side]), None);
    }
}
