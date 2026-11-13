use eframe::egui::{
    self, Align, Color32, CornerRadius, FontId, Frame, Layout, Margin, Response, RichText, Sense,
    Stroke, TextStyle, Ui, Vec2,
};
use lycta_sha3::{Digest, Sha3_256};

const LOGO_PNG: &[u8] = include_bytes!("../assets/logo.png");

pub struct Palette;

impl Palette {
    pub const SKY_DEEP: Color32 = Color32::from_rgb(0x20, 0x93, 0xDA);
    pub const SKY: Color32 = Color32::from_rgb(0x43, 0xC7, 0xFA);
    pub const SKY_LIGHT: Color32 = Color32::from_rgb(0x8E, 0xE2, 0xFF);

    pub const BG: Color32 = Color32::from_rgb(0xF2, 0xFA, 0xFF);
    pub const CARD: Color32 = Color32::WHITE;
    pub const HOVER: Color32 = Color32::from_rgb(0xE3, 0xF3, 0xFC);
    pub const BORDER: Color32 = Color32::from_rgb(0xCF, 0xE7, 0xF5);
    pub const BORDER_STRONG: Color32 = Color32::from_rgb(0x9C, 0xCB, 0xE8);
    pub const INPUT: Color32 = Color32::WHITE;
    pub const BUTTON: Color32 = Color32::WHITE;

    pub const TEXT: Color32 = Color32::from_rgb(0x04, 0x22, 0x3D);
    pub const MUTED: Color32 = Color32::from_rgb(0x4E, 0x6B, 0x85);

    pub const INK: Color32 = Color32::from_rgb(0x04, 0x22, 0x3D);
    pub const ACCENT: Color32 = Color32::from_rgb(0x1A, 0x8F, 0xDB);
    pub const ACCENT_DIM: Color32 = Color32::from_rgb(0xD3, 0xEE, 0xFD);
    pub const OUT_BUBBLE: Color32 = Color32::from_rgb(0x1A, 0x8F, 0xDB);
    pub const IN_BUBBLE: Color32 = Color32::WHITE;
    pub const OK: Color32 = Color32::from_rgb(0x12, 0xA5, 0x77);
    pub const WARN: Color32 = Color32::from_rgb(0xD9, 0x8A, 0x0B);
    pub const DANGER: Color32 = Color32::from_rgb(0xE0, 0x4A, 0x4A);
}

pub fn install(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (TextStyle::Heading, FontId::proportional(22.0)),
        (TextStyle::Body, FontId::proportional(15.0)),
        (TextStyle::Button, FontId::proportional(14.5)),
        (TextStyle::Small, FontId::proportional(12.0)),
        (TextStyle::Monospace, FontId::monospace(13.5)),
    ]
    .into();
    style.spacing.item_spacing = Vec2::new(8.0, 7.0);
    style.spacing.button_padding = Vec2::new(12.0, 6.0);
    style.spacing.interact_size.y = 30.0;

    let v = &mut style.visuals;
    *v = egui::Visuals::light();

    v.panel_fill = Color32::TRANSPARENT;
    v.window_fill = Palette::CARD;
    v.extreme_bg_color = Palette::INPUT;
    v.faint_bg_color = Palette::BG;
    v.override_text_color = Some(Palette::TEXT);
    v.hyperlink_color = Palette::ACCENT;
    v.selection.bg_fill = Palette::ACCENT_DIM;
    v.selection.stroke = Stroke::new(1.0_f32, Palette::ACCENT);
    v.window_corner_radius = CornerRadius::same(14);
    v.window_stroke = Stroke::new(1.0_f32, Palette::BORDER);
    v.menu_corner_radius = CornerRadius::same(10);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = CornerRadius::same(5);
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, Palette::BORDER);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, Palette::TEXT);
    v.widgets.inactive.weak_bg_fill = Palette::BUTTON;

    v.widgets.inactive.bg_fill = Palette::HOVER;
    v.slider_trailing_fill = true;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, Palette::BORDER_STRONG);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, Palette::TEXT);
    v.widgets.hovered.weak_bg_fill = Palette::HOVER;
    v.widgets.hovered.bg_fill = Palette::HOVER;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, Palette::ACCENT);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, Palette::TEXT);
    v.widgets.active.weak_bg_fill = Palette::ACCENT_DIM;
    v.widgets.active.bg_stroke = Stroke::new(1.0_f32, Palette::ACCENT);
    v.widgets.open.weak_bg_fill = Palette::ACCENT_DIM;
    v.text_cursor.stroke = Stroke::new(2.0_f32, Palette::ACCENT);
    v.popup_shadow = egui::epaint::Shadow {
        offset: [0, 6],
        blur: 20,
        spread: 0,
        color: Color32::from_rgba_premultiplied(4, 34, 61, 40),
    };
    ctx.set_style(style);
}

pub fn logo_rgba() -> Option<(Vec<u8>, u32, u32)> {
    let img = image::load_from_memory_with_format(LOGO_PNG, image::ImageFormat::Png)
        .ok()?
        .to_rgba8();
    let (w, h) = img.dimensions();
    Some((img.into_raw(), w, h))
}

pub fn window_icon() -> Option<egui::IconData> {
    let (rgba, width, height) = logo_rgba()?;
    Some(egui::IconData {
        rgba,
        width,
        height,
    })
}

fn logo_texture(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let id = egui::Id::new("lycta_logo_texture");
    if let Some(t) = ctx.data(|d| d.get_temp::<egui::TextureHandle>(id)) {
        return Some(t);
    }
    let (rgba, w, h) = logo_rgba()?;
    let image = egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
    let tex = ctx.load_texture("lycta_logo", image, egui::TextureOptions::LINEAR);
    ctx.data_mut(|d| d.insert_temp(id, tex.clone()));
    Some(tex)
}

fn paint_logo(painter: &egui::Painter, rect: egui::Rect) {
    if let Some(tex) = logo_texture(painter.ctx()) {
        painter.image(
            tex.id(),
            rect,
            egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
            Color32::WHITE,
        );
    }
}

pub fn logo(ui: &mut Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    paint_logo(ui.painter(), rect);
}

pub fn paint_background(ctx: &egui::Context) {
    let rect = ctx.screen_rect();
    let painter = ctx.layer_painter(egui::LayerId::background());
    let stops: [(f32, Color32); 6] = [
        (0.0, Palette::SKY_DEEP),
        (0.24, Palette::SKY),
        (0.42, Palette::SKY_LIGHT),
        (0.62, Palette::SKY_LIGHT),
        (0.84, Palette::SKY),
        (1.0, Palette::SKY_DEEP),
    ];
    let mut mesh = egui::Mesh::default();
    for (i, &(t, color)) in stops.iter().enumerate() {
        let x = rect.left() + rect.width() * t;
        mesh.colored_vertex(egui::pos2(x, rect.top()), color);
        mesh.colored_vertex(egui::pos2(x, rect.bottom()), color);
        if i > 0 {
            let b = (i as u32) * 2;
            mesh.add_triangle(b - 2, b - 1, b);
            mesh.add_triangle(b - 1, b + 1, b);
        }
    }
    painter.add(egui::Shape::mesh(mesh));

    let c = egui::pos2(rect.center().x, rect.top() + rect.height() * 0.25);
    let rx = rect.width() * 0.42;
    let ry = rect.height() * 0.5;
    let center_color = Color32::from_rgba_unmultiplied(214, 247, 255, 235);
    let mid_color = Color32::from_rgba_unmultiplied(214, 247, 255, 110);
    let edge_color = Color32::from_rgba_unmultiplied(214, 247, 255, 0);
    let mut glow = egui::Mesh::default();
    glow.colored_vertex(c, center_color);
    let segments = 72u32;
    for k in 0..=segments {
        let a = std::f32::consts::TAU * k as f32 / segments as f32;
        let (s, co) = a.sin_cos();
        glow.colored_vertex(c + Vec2::new(co * rx * 0.5, s * ry * 0.5), mid_color);
        glow.colored_vertex(c + Vec2::new(co * rx, s * ry), edge_color);
    }
    for k in 0..segments {
        let inner = 1 + 2 * k;
        let outer = inner + 1;
        let next_inner = inner + 2;
        let next_outer = outer + 2;
        glow.add_triangle(0, inner, next_inner);
        glow.add_triangle(inner, outer, next_outer);
        glow.add_triangle(inner, next_outer, next_inner);
    }
    painter.add(egui::Shape::mesh(glow));
}

pub const TITLE_BAR_HEIGHT: f32 = 38.0;
const CHROME_BUTTON_WIDTH: f32 = 46.0;
const RESIZE_MARGIN: f32 = 6.0;

pub fn title_bar(ctx: &egui::Context) -> bool {
    let maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
    let mut close_clicked = false;
    egui::TopBottomPanel::top("title_bar")
        .exact_height(TITLE_BAR_HEIGHT)
        .frame(Frame::new())
        .show_separator_line(false)
        .show(ctx, |ui| {
            let bar = ui.max_rect();

            let drag = ui.interact(bar, egui::Id::new("title_drag"), Sense::click_and_drag());
            if drag.drag_started_by(egui::PointerButton::Primary) {
                ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }
            if drag.double_clicked() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
            }

            let painter = ui.painter_at(bar);
            let icon_rect = egui::Rect::from_center_size(
                egui::pos2(bar.left() + 24.0, bar.center().y),
                Vec2::splat(26.0),
            );
            paint_logo(&painter, icon_rect);
            painter.text(
                egui::pos2(bar.left() + 44.0, bar.center().y),
                egui::Align2::LEFT_CENTER,
                "LyctaCrypt",
                FontId::proportional(14.0),
                Color32::WHITE,
            );

            let mut x = bar.right();
            for kind in [Chrome::Close, Chrome::Maximize, Chrome::Minimize] {
                x -= CHROME_BUTTON_WIDTH;
                let rect = egui::Rect::from_min_size(
                    egui::pos2(x, bar.top()),
                    Vec2::new(CHROME_BUTTON_WIDTH, TITLE_BAR_HEIGHT),
                );
                if chrome_button(ui, rect, kind, maximized).clicked() {
                    match kind {
                        Chrome::Close => close_clicked = true,
                        Chrome::Maximize => {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized))
                        }
                        Chrome::Minimize => {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true))
                        }
                    }
                }
            }
        });
    close_clicked
}

#[derive(Clone, Copy, PartialEq)]
enum Chrome {
    Minimize,
    Maximize,
    Close,
}

fn chrome_button(ui: &mut Ui, rect: egui::Rect, kind: Chrome, maximized: bool) -> Response {
    let id = egui::Id::new(match kind {
        Chrome::Minimize => "chrome_min",
        Chrome::Maximize => "chrome_max",
        Chrome::Close => "chrome_close",
    });
    let resp = ui.interact(rect, id, Sense::click());
    let painter = ui.painter_at(rect);
    let hovered = resp.hovered();
    let pressed = resp.is_pointer_button_down_on();
    let bg = match (kind, hovered, pressed) {
        (Chrome::Close, true, true) => Palette::DANGER.gamma_multiply(0.85),
        (Chrome::Close, true, false) => Palette::DANGER,
        (_, true, true) => Color32::from_white_alpha(70),
        (_, true, false) => Color32::from_white_alpha(45),
        _ => Color32::TRANSPARENT,
    };
    let fg = Color32::WHITE;
    painter.rect_filled(rect, 0.0, bg);
    let c = rect.center();
    let s = 5.0;
    let stroke = Stroke::new(1.3_f32, fg);
    match kind {
        Chrome::Minimize => {
            painter.line_segment([c + Vec2::new(-s, 0.0), c + Vec2::new(s, 0.0)], stroke);
        }
        Chrome::Maximize if maximized => {
            let back =
                egui::Rect::from_center_size(c + Vec2::new(1.5, -1.5), Vec2::splat(2.0 * s - 2.0));
            let front =
                egui::Rect::from_center_size(c + Vec2::new(-1.5, 1.5), Vec2::splat(2.0 * s - 2.0));
            painter.rect_stroke(back, 1.5, stroke, egui::StrokeKind::Middle);
            painter.rect_stroke(front, 1.5, stroke, egui::StrokeKind::Middle);
        }
        Chrome::Maximize => {
            let r = egui::Rect::from_center_size(c, Vec2::splat(2.0 * s));
            painter.rect_stroke(r, 1.5, stroke, egui::StrokeKind::Middle);
        }
        Chrome::Close => {
            painter.line_segment([c + Vec2::new(-s, -s), c + Vec2::new(s, s)], stroke);
            painter.line_segment([c + Vec2::new(-s, s), c + Vec2::new(s, -s)], stroke);
        }
    }
    resp.on_hover_cursor(egui::CursorIcon::Default)
}

pub fn window_frame(ctx: &egui::Context) {
    let maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
    let screen = ctx.screen_rect();
    if maximized {
        return;
    }
    ctx.layer_painter(egui::LayerId::new(
        egui::Order::Foreground,
        egui::Id::new("window_border"),
    ))
    .rect_stroke(
        screen.shrink(0.5),
        0.0,
        Stroke::new(1.0_f32, Palette::SKY_DEEP),
        egui::StrokeKind::Inside,
    );
    let Some(pos) = ctx.input(|i| i.pointer.hover_pos()) else {
        return;
    };
    use egui::viewport::ResizeDirection as D;
    let m = RESIZE_MARGIN;
    let left = pos.x <= screen.left() + m;
    let right = pos.x >= screen.right() - m;
    let top = pos.y <= screen.top() + m;
    let bottom = pos.y >= screen.bottom() - m;
    let dir = match (left, right, top, bottom) {
        (true, _, true, _) => Some(D::NorthWest),
        (_, true, true, _) => Some(D::NorthEast),
        (true, _, _, true) => Some(D::SouthWest),
        (_, true, _, true) => Some(D::SouthEast),
        (true, ..) => Some(D::West),
        (_, true, ..) => Some(D::East),
        (_, _, true, _) => Some(D::North),
        (.., true) => Some(D::South),
        _ => None,
    };
    let Some(dir) = dir else { return };
    let cursor = match dir {
        D::North | D::South => egui::CursorIcon::ResizeVertical,
        D::East | D::West => egui::CursorIcon::ResizeHorizontal,
        D::NorthWest | D::SouthEast => egui::CursorIcon::ResizeNwSe,
        D::NorthEast | D::SouthWest => egui::CursorIcon::ResizeNeSw,
    };
    ctx.set_cursor_icon(cursor);
    if ctx.input(|i| i.pointer.primary_pressed()) {
        ctx.send_viewport_cmd(egui::ViewportCommand::BeginResize(dir));
    }
}

fn soft_shadow() -> egui::epaint::Shadow {
    egui::epaint::Shadow {
        offset: [0, 6],
        blur: 24,
        spread: 0,
        color: Color32::from_rgba_premultiplied(4, 34, 61, 38),
    }
}

pub fn sidebar_frame() -> Frame {
    Frame::new()
        .fill(Color32::from_rgba_unmultiplied(255, 255, 255, 150))
        .inner_margin(Margin::same(14))
        .outer_margin(Margin {
            left: 10,
            right: 0,
            top: 0,
            bottom: 10,
        })
        .corner_radius(CornerRadius::same(16))
        .stroke(Stroke::new(
            1.0_f32,
            Color32::from_rgba_unmultiplied(255, 255, 255, 200),
        ))
}

pub fn central_frame() -> Frame {
    Frame::new()
        .fill(Color32::from_rgba_unmultiplied(246, 252, 255, 238))
        .inner_margin(Margin::symmetric(18, 12))
        .outer_margin(Margin {
            left: 10,
            right: 10,
            top: 0,
            bottom: 10,
        })
        .corner_radius(CornerRadius::same(16))
        .stroke(Stroke::new(
            1.0_f32,
            Color32::from_rgba_unmultiplied(255, 255, 255, 220),
        ))
        .shadow(soft_shadow())
}

pub fn composer_frame() -> Frame {
    Frame::new()
        .fill(Palette::CARD)
        .corner_radius(CornerRadius::same(14))
        .inner_margin(Margin::symmetric(10, 8))
        .stroke(Stroke::new(1.0_f32, Palette::BORDER))
}

pub fn toast_frame(accent: Color32) -> Frame {
    Frame::new()
        .fill(Palette::CARD)
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(14, 10))
        .stroke(Stroke::new(1.5_f32, accent))
        .shadow(soft_shadow())
}

pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::new()
        .fill(Color32::from_rgba_unmultiplied(255, 255, 255, 215))
        .corner_radius(CornerRadius::same(18))
        .inner_margin(Margin::same(20))
        .stroke(Stroke::new(
            1.0_f32,
            Color32::from_rgba_unmultiplied(255, 255, 255, 240),
        ))
        .shadow(soft_shadow())
        .show(ui, add)
        .inner
}

pub fn header(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    ui.horizontal(|ui| {
        ui.set_min_height(48.0);
        add(ui);
    });
    ui.add_space(4.0);
    let rect = ui.available_rect_before_wrap();
    ui.painter().hline(
        rect.x_range(),
        rect.top(),
        Stroke::new(1.0_f32, Palette::BORDER),
    );
    ui.add_space(4.0);
}

pub fn banner(ui: &mut Ui, color: Color32, add: impl FnOnce(&mut Ui)) {
    Frame::new()
        .fill(color.gamma_multiply(0.12))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(12, 10))
        .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.5)))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.vertical(add);
        });
    ui.add_space(4.0);
}

pub fn modal<'a>(title: &'a str, open: &'a mut bool) -> egui::Window<'a> {
    egui::Window::new(RichText::new(title).strong())
        .open(open)
        .collapsible(false)
        .resizable(false)
        .vscroll(true)
        .max_height(760.0)
        .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
        .frame(
            Frame::new()
                .fill(Palette::CARD)
                .corner_radius(CornerRadius::same(18))
                .inner_margin(Margin::same(20))
                .stroke(Stroke::new(1.0_f32, Palette::BORDER))
                .shadow(egui::epaint::Shadow {
                    offset: [0, 12],
                    blur: 40,
                    spread: 0,
                    color: Color32::from_rgba_premultiplied(4, 34, 61, 70),
                }),
        )
}

pub fn section_resp(ui: &mut Ui, title: &str) -> Response {
    ui.add_space(4.0);
    ui.label(RichText::new(title).small().strong().color(Palette::MUTED))
}

pub fn section(ui: &mut Ui, title: &str) {
    ui.add_space(4.0);
    ui.label(RichText::new(title).small().strong().color(Palette::MUTED));
}

pub fn primary_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(Color32::WHITE).strong())
            .fill(Palette::INK)
            .stroke(Stroke::NONE)
            .corner_radius(CornerRadius::same(10)),
    )
}

pub fn icon_button(icon: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(icon).size(17.0).color(Palette::TEXT))
        .frame(false)
        .min_size(Vec2::splat(30.0))
}

pub fn list_row(
    ui: &mut Ui,
    selected: bool,
    avatar: impl FnOnce(&mut Ui) -> Response,
    title: &str,
    subtitle: &str,
    unread: usize,
) -> Response {
    let fill = if selected {
        Color32::WHITE
    } else {
        Color32::TRANSPARENT
    };
    let stroke = if selected {
        Stroke::new(1.0_f32, Palette::BORDER)
    } else {
        Stroke::NONE
    };
    let r = Frame::new()
        .fill(fill)
        .stroke(stroke)
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(8, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                avatar(ui);
                ui.vertical(|ui| {
                    ui.set_width((ui.available_width() - 34.0).max(40.0));
                    ui.label(RichText::new(title).strong());
                    let sub: String = subtitle.chars().take(48).collect();
                    let sub = if subtitle.chars().count() > 48 {
                        format!("{sub}…")
                    } else {
                        sub
                    };
                    ui.add(
                        egui::Label::new(RichText::new(sub).small().color(Palette::MUTED))
                            .truncate(),
                    );
                });
                if unread > 0 {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        count_badge(ui, unread);
                    });
                }
            });
        })
        .response;
    let r = r.interact(Sense::click());
    if r.hovered() && !selected {
        ui.painter().rect_filled(
            r.rect,
            12.0,
            Color32::from_rgba_unmultiplied(255, 255, 255, 90),
        );
    }
    r.on_hover_cursor(egui::CursorIcon::PointingHand)
}

pub fn image_preview(ui: &mut Ui, out: bool, tex: &egui::TextureHandle) {
    let full = ui.available_width();
    let max = Vec2::new((full * 0.6).min(300.0), 240.0);
    let ts = tex.size_vec2();
    let scale = (max.x / ts.x).min(max.y / ts.y).min(1.0);
    let size = ts * scale;
    let (row, _) = ui.allocate_exact_size(Vec2::new(full, size.y), Sense::hover());
    let x = if out {
        row.right() - size.x
    } else {
        row.left()
    };
    let rect = egui::Rect::from_min_size(egui::pos2(x, row.top()), size);
    egui::Image::new(tex).corner_radius(12).paint_at(ui, rect);
    ui.painter().rect_stroke(
        rect,
        12.0,
        Stroke::new(1.0_f32, Palette::BORDER),
        egui::StrokeKind::Inside,
    );
    ui.add_space(3.0);
}

pub fn voice_note(ui: &mut Ui, out: bool, playing: bool) -> bool {
    let full = ui.available_width();
    let size = Vec2::new(150.0, 34.0);
    let (row, _) = ui.allocate_exact_size(Vec2::new(full, size.y), Sense::hover());
    let x = if out {
        row.right() - size.x
    } else {
        row.left()
    };
    let rect = egui::Rect::from_min_size(egui::pos2(x, row.top()), size);
    let resp = ui
        .interact(
            rect,
            ui.id().with(("voice", row.top() as i32)),
            Sense::click(),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    let p = ui.painter();
    p.rect(
        rect,
        17.0,
        if resp.hovered() {
            Palette::ACCENT.gamma_multiply(0.14)
        } else {
            Color32::WHITE
        },
        Stroke::new(1.0_f32, Palette::ACCENT),
        egui::StrokeKind::Inside,
    );

    let c = egui::pos2(rect.left() + 17.0, rect.center().y);
    p.circle_filled(c, 11.0, Palette::ACCENT);
    if playing {
        p.rect_filled(
            egui::Rect::from_center_size(c, Vec2::splat(8.0)),
            1.0,
            Color32::WHITE,
        );
    } else {
        p.add(egui::Shape::convex_polygon(
            vec![
                c + Vec2::new(-3.5, -5.5),
                c + Vec2::new(5.5, 0.0),
                c + Vec2::new(-3.5, 5.5),
            ],
            Color32::WHITE,
            Stroke::NONE,
        ));
    }

    let bars = [
        5.0, 9.0, 13.0, 7.0, 11.0, 15.0, 8.0, 12.0, 6.0, 10.0, 14.0, 7.0, 9.0, 5.0,
    ];
    for (k, h) in bars.iter().enumerate() {
        let bx = rect.left() + 38.0 + k as f32 * 7.5;
        p.rect_filled(
            egui::Rect::from_center_size(egui::pos2(bx, rect.center().y), Vec2::new(3.0, *h)),
            1.5,
            if playing {
                Palette::ACCENT
            } else {
                Palette::MUTED
            },
        );
    }
    ui.add_space(3.0);
    resp.clicked()
}

pub struct BubbleView<'a> {
    pub id: egui::Id,
    pub out: bool,
    pub text: &'a str,

    pub status: Option<bool>,

    pub quote: Option<&'a str>,

    pub reactions: &'a [(String, usize, bool)],
    pub edited: bool,
    pub deleted: bool,

    pub selected: bool,
}

pub fn message_bubble(ui: &mut Ui, v: &BubbleView) -> Response {
    use egui::text::{LayoutJob, TextWrapping};
    let pad = Vec2::new(13.0, 9.0);
    let full = ui.available_width();
    let max_text = (full * 0.72).max(160.0) - 2.0 * pad.x;
    let body = TextStyle::Body.resolve(ui.style());
    let small = TextStyle::Small.resolve(ui.style());
    let text_color = if v.out { Color32::WHITE } else { Palette::TEXT };
    let soft = if v.out {
        Color32::from_white_alpha(190)
    } else {
        Palette::MUTED
    };

    let galley = if v.deleted {
        let mut job = LayoutJob::single_section(
            "Message deleted".into(),
            egui::TextFormat {
                font_id: body.clone(),
                color: soft,
                italics: true,
                ..Default::default()
            },
        );
        job.wrap = TextWrapping::wrap_at_width(max_text);
        ui.painter().layout_job(job)
    } else {
        ui.painter()
            .layout(v.text.to_owned(), body, text_color, max_text)
    };
    let quote_galley = v.quote.filter(|_| !v.deleted).map(|q| {
        let mut job = LayoutJob::single_section(
            q.replace('\n', " "),
            egui::TextFormat::simple(small.clone(), soft),
        );
        job.wrap = TextWrapping::truncate_at_width(max_text - 14.0);
        ui.painter().layout_job(job)
    });
    let mut footer = String::new();
    if v.edited && !v.deleted {
        footer.push_str("edited");
    }
    if let Some(delivered) = v.status {
        if !footer.is_empty() {
            footer.push_str("  ");
        }
        footer.push_str(if delivered { "✔" } else { "🕓" });
    }
    let footer_galley =
        (!footer.is_empty()).then(|| ui.painter().layout_no_wrap(footer, small.clone(), soft));

    let text_size = galley.size();
    let quote_size = quote_galley
        .as_ref()
        .map(|g| g.size() + Vec2::new(14.0, 8.0))
        .unwrap_or(Vec2::ZERO);
    let footer_size = footer_galley
        .as_ref()
        .map(|g| g.size())
        .unwrap_or(Vec2::ZERO);
    let gap = 4.0;
    let inner = Vec2::new(
        text_size.x.max(quote_size.x).max(footer_size.x),
        text_size.y
            + if quote_galley.is_some() {
                quote_size.y + gap
            } else {
                0.0
            }
            + if footer_galley.is_some() {
                footer_size.y + 2.0
            } else {
                0.0
            },
    );
    let size = inner + 2.0 * pad;
    let chips_h = if v.reactions.is_empty() { 0.0 } else { 26.0 };
    let (row, _) = ui.allocate_exact_size(Vec2::new(full, size.y + chips_h), Sense::hover());
    let x = if v.out {
        row.right() - size.x
    } else {
        row.left()
    };
    let rect = egui::Rect::from_min_size(egui::pos2(x, row.top()), size);
    let resp = ui.interact(rect, v.id, Sense::click());
    let radius = if v.out {
        CornerRadius {
            nw: 16,
            ne: 5,
            sw: 16,
            se: 16,
        }
    } else {
        CornerRadius {
            nw: 5,
            ne: 16,
            sw: 16,
            se: 16,
        }
    };
    let painter = ui.painter();
    let hovered = resp.hovered() || v.selected;
    if v.out {
        let fill = if hovered {
            Palette::OUT_BUBBLE.gamma_multiply(0.9)
        } else {
            Palette::OUT_BUBBLE
        };
        painter.rect_filled(rect, radius, fill);
    } else {
        painter.rect(
            rect,
            radius,
            Palette::IN_BUBBLE,
            Stroke::new(
                1.0_f32,
                if hovered {
                    Palette::ACCENT
                } else {
                    Palette::BORDER
                },
            ),
            egui::StrokeKind::Inside,
        );
    }
    if v.selected {
        painter.rect_stroke(
            rect.expand(2.0),
            radius,
            Stroke::new(2.0_f32, Palette::ACCENT),
            egui::StrokeKind::Outside,
        );
    }
    let mut y = rect.top() + pad.y;
    if let Some(q) = quote_galley {
        let qrect = egui::Rect::from_min_size(egui::pos2(rect.left() + pad.x, y), quote_size);
        let qfill = if v.out {
            Color32::from_white_alpha(38)
        } else {
            Palette::ACCENT.gamma_multiply(0.10)
        };
        painter.rect_filled(qrect, 6.0, qfill);
        painter.rect_filled(
            egui::Rect::from_min_size(qrect.min, Vec2::new(3.0, qrect.height())),
            CornerRadius {
                nw: 6,
                sw: 6,
                ne: 0,
                se: 0,
            },
            if v.out {
                Color32::WHITE
            } else {
                Palette::ACCENT
            },
        );
        painter.galley(qrect.min + Vec2::new(9.0, 4.0), q, soft);
        y += quote_size.y + gap;
    }
    painter.galley(egui::pos2(rect.left() + pad.x, y), galley, text_color);
    y += text_size.y + 2.0;
    if let Some(g) = footer_galley {
        painter.galley(egui::pos2(rect.right() - pad.x - footer_size.x, y), g, soft);
    }
    if !v.reactions.is_empty() {
        let font = FontId::proportional(15.0);
        let mut cx = if v.out {
            rect.right()
        } else {
            rect.left() + 6.0
        };
        let cy = rect.bottom() - 4.0;

        let chips: Vec<_> = v
            .reactions
            .iter()
            .map(|(e, n, mine)| {
                let label = if *n > 1 {
                    format!("{e} {n}")
                } else {
                    e.clone()
                };
                (
                    painter.layout_no_wrap(label, font.clone(), Palette::TEXT),
                    *mine,
                )
            })
            .collect();
        if v.out {
            cx -= chips.iter().map(|(g, _)| g.size().x + 18.0).sum::<f32>() + 6.0;
        }
        for (g, mine) in chips {
            let w = g.size().x + 14.0;
            let chip = egui::Rect::from_min_size(egui::pos2(cx, cy), Vec2::new(w, 24.0));
            painter.rect(
                chip,
                12.0,
                if mine {
                    Palette::ACCENT.gamma_multiply(0.16)
                } else {
                    Color32::WHITE
                },
                Stroke::new(
                    1.0_f32,
                    if mine {
                        Palette::ACCENT
                    } else {
                        Palette::BORDER
                    },
                ),
                egui::StrokeKind::Inside,
            );
            painter.galley(chip.center() - g.size() / 2.0, g, Palette::TEXT);
            cx += w + 4.0;
        }
    }
    ui.add_space(5.0);
    resp
}

pub fn bubble(ui: &mut Ui, out: bool, text: &str, status: Option<bool>) {
    let pad = Vec2::new(13.0, 9.0);
    let full = ui.available_width();
    let max_text = (full * 0.72).max(160.0) - 2.0 * pad.x;
    let body = TextStyle::Body.resolve(ui.style());
    let small = TextStyle::Small.resolve(ui.style());
    let text_color = if out { Color32::WHITE } else { Palette::TEXT };
    let status_color = if out {
        Color32::from_white_alpha(190)
    } else {
        Palette::MUTED
    };
    let galley = ui
        .painter()
        .layout(text.to_owned(), body, text_color, max_text);
    let status_galley = status.map(|delivered| {
        ui.painter().layout_no_wrap(
            if delivered {
                "✔".into()
            } else {
                "🕓".into()
            },
            small,
            status_color,
        )
    });
    let text_size = galley.size();
    let status_size = status_galley
        .as_ref()
        .map(|g| g.size())
        .unwrap_or(Vec2::ZERO);
    let inner = Vec2::new(
        text_size.x.max(status_size.x),
        text_size.y
            + if status.is_some() {
                status_size.y + 2.0
            } else {
                0.0
            },
    );
    let size = inner + 2.0 * pad;
    let (row, _) = ui.allocate_exact_size(Vec2::new(full, size.y), Sense::hover());
    let x = if out {
        row.right() - size.x
    } else {
        row.left()
    };
    let rect = egui::Rect::from_min_size(egui::pos2(x, row.top()), size);
    let radius = if out {
        CornerRadius {
            nw: 16,
            ne: 5,
            sw: 16,
            se: 16,
        }
    } else {
        CornerRadius {
            nw: 5,
            ne: 16,
            sw: 16,
            se: 16,
        }
    };
    let painter = ui.painter();
    if out {
        painter.rect_filled(rect, radius, Palette::OUT_BUBBLE);
    } else {
        painter.rect(
            rect,
            radius,
            Palette::IN_BUBBLE,
            Stroke::new(1.0_f32, Palette::BORDER),
            egui::StrokeKind::Inside,
        );
    }
    painter.galley(rect.min + pad, galley, text_color);
    if let Some(g) = status_galley {
        let pos = egui::pos2(
            rect.right() - pad.x - status_size.x,
            rect.top() + pad.y + text_size.y + 2.0,
        );
        painter.galley(pos, g, status_color);
    }
    ui.add_space(5.0);
}

fn count_badge(ui: &mut Ui, n: usize) {
    let text = if n > 99 {
        "99+".to_string()
    } else {
        n.to_string()
    };
    let font = FontId::proportional(11.5);
    let g = ui.painter().layout_no_wrap(text, font, Color32::WHITE);
    let w = (g.size().x + 12.0).max(20.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(w, 20.0), Sense::hover());
    ui.painter().rect_filled(rect, 10.0, Palette::ACCENT);
    ui.painter()
        .galley(rect.center() - g.size() / 2.0, g, Color32::WHITE);
}

pub fn avatar(ui: &mut Ui, fp: &[u8; 32], size: f32) -> Response {
    let h: [u8; 32] = Sha3_256::digest([b"LyctaCrypt/avatar".as_slice(), fp].concat()).into();
    let hue = h[0] as f32 / 255.0;
    let fg: Color32 = egui::ecolor::Hsva::new(hue, 0.65, 0.72, 1.0).into();
    let bg: Color32 = egui::ecolor::Hsva::new(hue, 0.18, 0.98, 1.0).into();
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, size * 0.3, bg);
    let pad = size * 0.18;
    let cell = (size - 2.0 * pad) / 5.0;
    for y in 0..5 {
        for x in 0..3 {
            if (h[1 + y * 3 + x] & 1) == 1 {
                for xx in [x, 4 - x] {
                    let min = rect.min + Vec2::new(pad + xx as f32 * cell, pad + y as f32 * cell);
                    p.rect_filled(
                        egui::Rect::from_min_size(min, Vec2::splat(cell)),
                        cell * 0.2,
                        fg,
                    );
                }
            }
        }
    }
    resp
}

pub fn group_badge(ui: &mut Ui, size: f32) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, size * 0.3, Palette::ACCENT_DIM);
    p.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        "👥",
        FontId::proportional(size * 0.5),
        Palette::ACCENT,
    );
    resp
}
