use anyhow::{anyhow, Result};
use qrcode::render::unicode::Dense1x2;
use qrcode::{Color, EcLevel, QrCode};

fn code(data: &str) -> Result<QrCode> {
    QrCode::with_error_correction_level(data.to_uppercase().as_bytes(), EcLevel::M)
        .map_err(|e| anyhow!("QR code : {e}"))
}

pub fn to_terminal(data: &str) -> Result<String> {
    Ok(code(data)?
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

pub fn matrix(data: &str) -> Result<(usize, Vec<bool>)> {
    let c = code(data)?;
    let w = c.width();
    Ok((
        w,
        c.to_colors()
            .into_iter()
            .map(|x| x == Color::Dark)
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn renders() {
        let s = super::to_terminal("lycta:abc").unwrap();
        assert!(s.lines().count() > 5);
        let (w, m) = super::matrix("lycta:abc").unwrap();
        assert_eq!(m.len(), w * w);
    }
}
