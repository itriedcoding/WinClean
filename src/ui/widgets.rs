//! Reusable interface pieces: cards, badges, buttons, progress, switches,
//! dialogs and table helpers. Everything is painted with the active palette.

use crate::theme::{self, Palette};
use crate::ui::icons::{self, Icon};
use eframe::egui::{
    self, Align, Align2, Color32, FontId, Id, Layout, Margin, Rect, Response, RichText, Rounding,
    Sense, Stroke, Ui, Vec2,
};

pub fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    Color32::from_rgb(
        (a.r() as f32 + (b.r() as f32 - a.r() as f32) * t) as u8,
        (a.g() as f32 + (b.g() as f32 - a.g() as f32) * t) as u8,
        (a.b() as f32 + (b.b() as f32 - a.b() as f32) * t) as u8,
    )
}

pub fn card(palette: &Palette) -> egui::Frame {
    egui::Frame::none()
        .fill(palette.card)
        .stroke(Stroke::new(1.0_f32, palette.border))
        .rounding(Rounding::same(14.0))
        .inner_margin(Margin::same(18.0))
}

pub fn section(ui: &mut Ui, palette: &Palette, title: &str) {
    ui.label(
        RichText::new(title)
            .font(FontId::new(16.5, theme::heading()))
            .color(palette.text_strong),
    );
}

pub fn stat_card(
    ui: &mut Ui,
    palette: &Palette,
    width: f32,
    label: &str,
    value: &str,
    hint: &str,
    accent: Color32,
) {
    let frame = card(palette).inner_margin(Margin::same(14.0));
    frame.show(ui, |ui| {
        ui.set_width((width - 28.0).max(40.0));
        ui.horizontal(|ui| {
            ui.label(RichText::new(label).size(11.5).color(palette.muted));
            let _ = accent;
        });
        ui.add_space(2.0);
        ui.label(
            RichText::new(value)
                .font(FontId::new(22.0, theme::heading()))
                .color(palette.text_strong),
        );
        ui.label(RichText::new(hint).size(11.0).color(accent));
    });
}

pub fn badge(ui: &mut Ui, palette: &Palette, text: &str, color: Color32) -> Response {
    let frame = egui::Frame::none()
        .fill(palette.alpha(color, if palette.dark { 32 } else { 24 }))
        .rounding(Rounding::same(20.0))
        .inner_margin(Margin {
            left: 8.0,
            right: 8.0,
            top: 2.0,
            bottom: 2.0,
        });
    frame
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.0).color(color));
        })
        .response
}

pub fn primary_button(ui: &mut Ui, palette: &Palette, text: &str) -> Response {
    let button = egui::Button::new(
        RichText::new(text)
            .size(13.5)
            .color(palette.on_accent)
            .strong(),
    )
    .fill(palette.accent)
    .stroke(Stroke::NONE)
    .rounding(Rounding::same(8.0))
    .min_size(Vec2::new(0.0, 34.0));
    let response = ui.add(button);
    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    response
}

pub fn ghost_button(ui: &mut Ui, palette: &Palette, text: &str) -> Response {
    let button = egui::Button::new(RichText::new(text).size(13.5).color(palette.text))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0_f32, palette.border))
        .rounding(Rounding::same(8.0))
        .min_size(Vec2::new(0.0, 34.0));
    let response = ui.add(button);
    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    response
}

pub fn danger_button(ui: &mut Ui, palette: &Palette, text: &str) -> Response {
    let button = egui::Button::new(
        RichText::new(text)
            .size(13.5)
            .color(palette.on_accent)
            .strong(),
    )
    .fill(palette.danger)
    .stroke(Stroke::NONE)
    .rounding(Rounding::same(8.0))
    .min_size(Vec2::new(0.0, 34.0));
    let response = ui.add(button);
    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    response
}

pub fn icon_button(ui: &mut Ui, palette: &Palette, icon: Icon, tooltip: &str) -> Response {
    let size = Vec2::new(32.0, 32.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    let background = if response.hovered() {
        palette.elevated
    } else {
        Color32::TRANSPARENT
    };
    ui.painter()
        .rect_filled(rect, Rounding::same(8.0), background);
    let icon_rect = Rect::from_center_size(rect.center(), Vec2::splat(16.0));
    icons::paint(
        ui.painter(),
        icon_rect,
        icon,
        if response.hovered() {
            palette.text_strong
        } else {
            palette.muted
        },
    );
    if !tooltip.is_empty() {
        response.clone().on_hover_text(tooltip)
    } else {
        response
    }
}

pub fn toggle_switch(
    ui: &mut Ui,
    palette: &Palette,
    id: impl std::hash::Hash,
    value: &mut bool,
) -> Response {
    let (rect, mut response) = ui.allocate_exact_size(Vec2::new(40.0, 22.0), Sense::click());
    if response.clicked() {
        *value = !*value;
        response.mark_changed();
    }
    let progress = ui
        .ctx()
        .animate_bool_with_time(Id::new(("toggle", id)), *value, 0.14);
    let track = mix(palette.track, palette.accent, progress);
    ui.painter().rect_filled(rect, Rounding::same(11.0), track);
    let knob_x = rect.left() + 11.0 + (rect.width() - 22.0) * progress;
    ui.painter()
        .circle_filled(egui::pos2(knob_x, rect.center().y), 8.5, Color32::WHITE);
    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    response
}

pub fn checkbox(ui: &mut Ui, palette: &Palette, value: &mut bool, label: &str) -> Response {
    let response = ui
        .horizontal(|ui| {
            let size = Vec2::splat(18.0);
            let (rect, response) = ui.allocate_exact_size(size, Sense::click());
            let fill = if *value {
                palette.accent
            } else {
                Color32::TRANSPARENT
            };
            ui.painter().rect_filled(rect, Rounding::same(5.0), fill);
            ui.painter().rect_stroke(
                rect,
                Rounding::same(5.0),
                Stroke::new(
                    1.0_f32,
                    if *value {
                        palette.accent
                    } else {
                        palette.border_strong
                    },
                ),
            );
            if *value {
                let check = Rect::from_center_size(rect.center(), Vec2::splat(11.0));
                icons::paint_sized(ui.painter(), check, Icon::Check, palette.on_accent, 1.8);
            }
            let text = ui.add(
                egui::Label::new(RichText::new(label).size(12.5).color(palette.text))
                    .truncate()
                    .sense(Sense::click()),
            );
            if response.clicked() || text.clicked() {
                *value = !*value;
            }
            if response.hovered() || text.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
            response | text
        })
        .inner;
    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    response
}

pub fn progress_bar(ui: &mut Ui, palette: &Palette, fraction: f32, height: f32, color: Color32) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, height), Sense::hover());
    ui.painter()
        .rect_filled(rect, Rounding::same(height * 0.5), palette.track);
    let filled_width = rect.width() * fraction.clamp(0.0, 1.0);
    if filled_width > 0.5 {
        let filled = Rect::from_min_size(rect.min, Vec2::new(filled_width, height));
        ui.painter()
            .rect_filled(filled, Rounding::same(height * 0.5), color);
    }
}

/// Indeterminate bar used while the exact percentage is unknown.
pub fn indeterminate_bar(ui: &mut Ui, palette: &Palette, height: f32) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, height), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, Rounding::same(height * 0.5), palette.track);
    let time = ui.input(|input| input.time) as f32;
    let segment = (rect.width() * 0.28).max(40.0);
    let travel = rect.width() + segment;
    let offset = (time * 220.0) % travel;
    let start = rect.left() - segment + offset;
    let visible_left = start.max(rect.left());
    let visible_right = (start + segment).min(rect.right());
    if visible_right > visible_left {
        let bar = Rect::from_min_max(
            egui::pos2(visible_left, rect.top()),
            egui::pos2(visible_right, rect.bottom()),
        );
        painter.rect_filled(bar, Rounding::same(height * 0.5), palette.accent);
    }
}

pub fn ring(
    ui: &mut Ui,
    palette: &Palette,
    fraction: f32,
    size: f32,
    color: Color32,
    centre_text: &str,
    caption: &str,
) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let centre = rect.center();
    let radius = size * 0.5 - 8.0;
    let painter = ui.painter();
    painter.circle_stroke(centre, radius, Stroke::new(9.0_f32, palette.track));

    let steps = 64;
    let sweep = std::f32::consts::TAU * fraction.clamp(0.0, 1.0);
    let start = -std::f32::consts::FRAC_PI_2;
    let mut previous = None;
    for step in 0..=steps {
        let angle = start + sweep * step as f32 / steps as f32;
        let point = centre + Vec2::new(angle.cos(), angle.sin()) * radius;
        if let Some(last) = previous {
            painter.line_segment([last, point], Stroke::new(9.0_f32, color));
        }
        previous = Some(point);
    }
    painter.text(
        centre - Vec2::new(0.0, 8.0),
        Align2::CENTER_CENTER,
        centre_text,
        FontId::new(size * 0.26, theme::heading()),
        palette.text_strong,
    );
    painter.text(
        centre + Vec2::new(0.0, size * 0.17),
        Align2::CENTER_CENTER,
        caption,
        FontId::new(10.5, egui::FontFamily::Proportional),
        palette.muted,
    );
}

pub fn thin_separator(ui: &mut Ui, palette: &Palette) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::hover());
    ui.painter()
        .rect_filled(rect, Rounding::ZERO, palette.border);
}

pub fn empty_state(ui: &mut Ui, palette: &Palette, icon: Icon, title: &str, detail: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(26.0);
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(46.0), Sense::hover());
        icons::paint_sized(ui.painter(), rect, icon, palette.muted, 1.5);
        ui.add_space(8.0);
        ui.label(
            RichText::new(title)
                .font(FontId::new(15.0, theme::heading()))
                .color(palette.text),
        );
        ui.label(RichText::new(detail).size(12.0).color(palette.muted));
        ui.add_space(20.0);
    });
}

pub fn alert_banner(
    ui: &mut Ui,
    palette: &Palette,
    color: Color32,
    icon: Icon,
    title: &str,
    body: &str,
) -> Response {
    let frame = egui::Frame::none()
        .fill(palette.alpha(color, if palette.dark { 26 } else { 18 }))
        .stroke(Stroke::new(1.0_f32, palette.alpha(color, 90)))
        .rounding(Rounding::same(12.0))
        .inner_margin(Margin::same(16.0));
    frame
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
                icons::paint_sized(ui.painter(), rect, icon, color, 1.6);
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(title)
                            .font(FontId::new(14.0, theme::heading()))
                            .color(palette.text_strong),
                    );
                    ui.label(RichText::new(body).size(12.0).color(palette.muted));
                });
            });
        })
        .response
}

/// Centered dialog with a dimmed backdrop.
pub fn modal(
    ctx: &egui::Context,
    palette: &Palette,
    id: &str,
    width: f32,
    title: &str,
    subtitle: Option<&str>,
    add_contents: impl FnOnce(&mut Ui),
) {
    let screen = ctx.screen_rect();
    egui::Area::new(Id::new(format!("{id}-backdrop")))
        .order(egui::Order::Foreground)
        .fixed_pos(screen.min)
        .show(ctx, |ui| {
            ui.painter().rect_filled(
                screen,
                Rounding::ZERO,
                Color32::from_black_alpha(if palette.dark { 170 } else { 90 }),
            );
            let _ = ui.allocate_exact_size(screen.size(), Sense::click());
        });

    egui::Area::new(Id::new(id))
        .order(egui::Order::Tooltip)
        .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
        .show(ctx, |ui| {
            egui::Frame::none()
                .fill(palette.panel)
                .stroke(Stroke::new(1.0_f32, palette.border_strong))
                .rounding(Rounding::same(14.0))
                .inner_margin(Margin::same(22.0))
                .show(ui, |ui| {
                    ui.set_width(width);
                    ui.label(
                        RichText::new(title)
                            .font(FontId::new(17.0, theme::heading()))
                            .color(palette.text_strong),
                    );
                    if let Some(subtitle) = subtitle {
                        ui.label(RichText::new(subtitle).size(12.0).color(palette.muted));
                    }
                    ui.add_space(6.0);
                    add_contents(ui);
                });
        });
}

pub fn key_value(ui: &mut Ui, palette: &Palette, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(key).size(12.0).color(palette.muted));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(value).size(12.5).color(palette.text));
        });
    });
}

/// Clickable table header cell that reports sort direction changes.
pub fn sort_header(
    ui: &mut Ui,
    palette: &Palette,
    label: &str,
    width: f32,
    active: bool,
    descending: bool,
) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 22.0), Sense::click());
    let color = if active {
        palette.text_strong
    } else {
        palette.muted
    };
    ui.painter().text(
        rect.left_center() + Vec2::new(2.0, 0.0),
        Align2::LEFT_CENTER,
        label,
        FontId::new(11.5, egui::FontFamily::Proportional),
        color,
    );
    if active {
        let centre = egui::pos2(rect.left() + width - 12.0, rect.center().y);
        let stroke = Stroke::new(1.4_f32, palette.accent);
        if descending {
            ui.painter().line_segment(
                [centre + Vec2::new(-4.0, -2.0), centre + Vec2::new(0.0, 2.5)],
                stroke,
            );
            ui.painter().line_segment(
                [centre + Vec2::new(0.0, 2.5), centre + Vec2::new(4.0, -2.0)],
                stroke,
            );
        } else {
            ui.painter().line_segment(
                [centre + Vec2::new(-4.0, 2.0), centre + Vec2::new(0.0, -2.5)],
                stroke,
            );
            ui.painter().line_segment(
                [centre + Vec2::new(0.0, -2.5), centre + Vec2::new(4.0, 2.0)],
                stroke,
            );
        }
    }
    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    response
}

/// Right-aligned muted label used for secondary table columns.
pub fn muted_cell(ui: &mut Ui, palette: &Palette, text: &str, width: f32) {
    ui.allocate_ui_with_layout(
        Vec2::new(width, 20.0),
        Layout::right_to_left(Align::Center),
        |ui| {
            ui.add(
                egui::Label::new(RichText::new(text).size(12.0).color(palette.muted))
                    .truncate()
                    .selectable(false),
            );
        },
    );
}

pub fn text_cell(
    ui: &mut Ui,
    _palette: &Palette,
    text: &str,
    width: f32,
    color: Color32,
    size: f32,
) {
    ui.allocate_ui_with_layout(
        Vec2::new(width, 20.0),
        Layout::left_to_right(Align::Center),
        |ui| {
            ui.add(
                egui::Label::new(RichText::new(text).size(size).color(color))
                    .truncate()
                    .selectable(false),
            );
        },
    );
}

/// Small spinner arc for "working" feedback.
pub fn spinner(ui: &mut Ui, palette: &Palette, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let centre = rect.center();
    let radius = size * 0.36;
    let time = ui.input(|input| input.time) as f32 * 3.0;
    let steps = 18;
    let mut previous = None;
    for step in 0..=steps {
        let angle = time + std::f32::consts::TAU * step as f32 / steps as f32;
        let point = centre + Vec2::new(angle.cos(), angle.sin()) * radius;
        if let Some(last) = previous {
            ui.painter()
                .line_segment([last, point], Stroke::new(2.0_f32, palette.accent));
        }
        previous = Some(point);
    }
}
