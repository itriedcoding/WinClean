//! Visual language: palettes for both themes and the typography setup.

use crate::model::{HealthState, Risk, ThreatSeverity};
use crate::settings::ThemeMode;
use eframe::egui::{
    self, Color32, FontData, FontDefinitions, FontFamily, FontId, Stroke, TextStyle,
};

#[derive(Clone, Copy, Debug)]
pub struct Palette {
    pub dark: bool,
    pub bg: Color32,
    pub sidebar: Color32,
    pub panel: Color32,
    pub card: Color32,
    pub card_hover: Color32,
    pub elevated: Color32,
    pub border: Color32,
    pub border_strong: Color32,
    pub text: Color32,
    pub text_strong: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub accent_hover: Color32,
    pub accent_soft: Color32,
    pub on_accent: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub danger: Color32,
    pub track: Color32,
    pub shadow: Color32,
}

fn rgb(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

impl Palette {
    pub fn dark() -> Self {
        Self {
            dark: true,
            bg: rgb(0x0B0E14),
            sidebar: rgb(0x0D1118),
            panel: rgb(0x10151D),
            card: rgb(0x151A24),
            card_hover: rgb(0x1A202B),
            elevated: rgb(0x1E2532),
            border: rgb(0x232B39),
            border_strong: rgb(0x2F3A4C),
            text: rgb(0xDCE2EC),
            text_strong: rgb(0xF2F5FA),
            muted: rgb(0x8892A4),
            accent: rgb(0x3B82F6),
            accent_hover: rgb(0x60A5FA),
            accent_soft: rgb(0x1D3357),
            on_accent: rgb(0xFFFFFF),
            success: rgb(0x34D399),
            warning: rgb(0xFBBF24),
            danger: rgb(0xF87171),
            track: rgb(0x1C2330),
            shadow: Color32::from_rgba_unmultiplied(0, 0, 0, 70),
        }
    }

    pub fn light() -> Self {
        Self {
            dark: false,
            bg: rgb(0xF3F5F9),
            sidebar: rgb(0xFFFFFF),
            panel: rgb(0xFFFFFF),
            card: rgb(0xFFFFFF),
            card_hover: rgb(0xF5F7FB),
            elevated: rgb(0xEEF2F8),
            border: rgb(0xE1E7F0),
            border_strong: rgb(0xCFD8E6),
            text: rgb(0x2A3444),
            text_strong: rgb(0x0F172A),
            muted: rgb(0x67748A),
            accent: rgb(0x2563EB),
            accent_hover: rgb(0x1D4ED8),
            accent_soft: rgb(0xE3ECFD),
            on_accent: rgb(0xFFFFFF),
            success: rgb(0x059669),
            warning: rgb(0xB45309),
            danger: rgb(0xDC2626),
            track: rgb(0xE8EDF5),
            shadow: Color32::from_rgba_unmultiplied(15, 23, 42, 18),
        }
    }

    pub fn for_mode(mode: ThemeMode) -> Self {
        match mode {
            ThemeMode::Dark => Self::dark(),
            ThemeMode::Light => Self::light(),
        }
    }

    pub fn risk_color(&self, risk: Risk) -> Color32 {
        match risk {
            Risk::Safe => self.success,
            Risk::Caution => self.warning,
            Risk::Review => self.accent,
        }
    }

    pub fn severity_color(&self, severity: ThreatSeverity) -> Color32 {
        match severity {
            ThreatSeverity::Low => self.muted,
            ThreatSeverity::Medium => self.warning,
            ThreatSeverity::High => self.danger,
            ThreatSeverity::Severe => Color32::from_rgb(0xFF, 0x4D, 0x6D),
        }
    }

    pub fn health_color(&self, state: HealthState) -> Color32 {
        match state {
            HealthState::Good => self.success,
            HealthState::Warning => self.warning,
            HealthState::Critical => self.danger,
        }
    }

    pub fn alpha(&self, color: Color32, alpha: u8) -> Color32 {
        Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), alpha)
    }
}

/// Loads Segoe UI from the system when available so the app looks native.
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let regular = std::fs::read(r"C:\Windows\Fonts\segoeui.ttf").ok();
    let semibold = std::fs::read(r"C:\Windows\Fonts\seguisb.ttf")
        .or_else(|_| std::fs::read(r"C:\Windows\Fonts\segoeuib.ttf"))
        .ok();
    if let Some(bytes) = regular {
        fonts
            .font_data
            .insert("segoe".to_string(), FontData::from_owned(bytes));
        fonts
            .families
            .entry(FontFamily::Proportional)
            .or_default()
            .insert(0, "segoe".to_string());
    }
    if let Some(bytes) = semibold {
        fonts
            .font_data
            .insert("segoe-semibold".to_string(), FontData::from_owned(bytes));
        fonts.families.insert(
            FontFamily::Name("semibold".into()),
            vec!["segoe-semibold".to_string(), "segoe".to_string()],
        );
        fonts.families.insert(
            FontFamily::Name("bold".into()),
            vec!["segoe-semibold".to_string(), "segoe".to_string()],
        );
    }
    ctx.set_fonts(fonts);
}

pub fn heading() -> FontFamily {
    FontFamily::Name("semibold".into())
}

pub fn apply(ctx: &egui::Context, palette: &Palette) {
    let mut style = (*ctx.style()).clone();
    let mut visuals = if palette.dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    visuals.override_text_color = Some(palette.text);
    visuals.panel_fill = palette.bg;
    visuals.window_fill = palette.panel;
    visuals.extreme_bg_color = palette.card;
    visuals.faint_bg_color = palette.card_hover;
    visuals.hyperlink_color = palette.accent;
    visuals.window_rounding = egui::Rounding::same(14.0);
    visuals.menu_rounding = egui::Rounding::same(10.0);
    visuals.selection.bg_fill = palette.accent_soft;
    visuals.selection.stroke = Stroke::new(1.0_f32, palette.accent);
    visuals.widgets.noninteractive.bg_fill = palette.card;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, palette.border);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, palette.text);
    visuals.widgets.inactive.bg_fill = palette.card_hover;
    visuals.widgets.inactive.weak_bg_fill = palette.card_hover;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, palette.border);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, palette.text);
    visuals.widgets.inactive.rounding = egui::Rounding::same(8.0);
    visuals.widgets.hovered.bg_fill = palette.elevated;
    visuals.widgets.hovered.weak_bg_fill = palette.elevated;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, palette.border_strong);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, palette.text_strong);
    visuals.widgets.hovered.rounding = egui::Rounding::same(8.0);
    visuals.widgets.active.bg_fill = palette.accent_soft;
    visuals.widgets.active.weak_bg_fill = palette.accent_soft;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, palette.accent);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, palette.text_strong);
    visuals.widgets.active.rounding = egui::Rounding::same(8.0);
    visuals.widgets.open.bg_fill = palette.card;
    visuals.widgets.open.bg_stroke = Stroke::new(1.0_f32, palette.border_strong);
    visuals.popup_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 6.0),
        blur: 18.0,
        spread: 2.0,
        color: palette.shadow,
    };
    style.visuals = visuals;

    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.interact_size.y = 32.0;
    style.spacing.scroll.bar_width = 8.0;
    style.spacing.menu_margin = egui::Margin::same(8.0);
    style.text_styles = [
        (TextStyle::Heading, FontId::new(25.0, heading())),
        (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
        (
            TextStyle::Monospace,
            FontId::new(12.5, FontFamily::Monospace),
        ),
        (
            TextStyle::Button,
            FontId::new(14.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Small,
            FontId::new(11.5, FontFamily::Proportional),
        ),
    ]
    .into();
    ctx.set_style(style);
}

/// Smoothly moves `current` towards `target` using frame delta time.
pub fn approach(current: &mut f32, target: f32, dt: f32, speed: f32) {
    let factor = (dt * speed).clamp(0.0, 1.0);
    *current += (target - *current) * factor;
    if (*current - target).abs() < 0.001 {
        *current = target;
    }
}
