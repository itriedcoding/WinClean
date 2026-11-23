//! Crisp vector icons drawn with the egui painter. No image assets, no font
//! glyph fallbacks, and they follow the active theme colour.

use eframe::egui::{Color32, Pos2, Rect, Rounding, Shape, Stroke, Vec2};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    Grid,
    Broom,
    Layers,
    File,
    Shield,
    Chart,
    Rocket,
    Activity,
    Gear,
    Search,
    Check,
    Alert,
    Close,
    ChevronRight,
    Trash,
    Folder,
    Refresh,
    Play,
    Stop,
    Clock,
    Disk,
    Download,
    Info,
    Sparkle,
    Memory,
    Cpu,
    External,
    Plus,
    Minus,
    Lock,
}

impl Icon {
    /// Maps a category icon name used by the scan model.
    pub fn from_category(name: &str) -> Icon {
        match name {
            "temp" => Icon::Broom,
            "browser" => Icon::Grid,
            "image" => Icon::File,
            "crash" => Icon::Alert,
            "log" => Icon::File,
            "alert" => Icon::Alert,
            "update" => Icon::Download,
            "clock" => Icon::Clock,
            "trash" => Icon::Trash,
            "file" => Icon::File,
            "copy" => Icon::Layers,
            _ => Icon::File,
        }
    }
}

pub fn paint(painter: &eframe::egui::Painter, rect: Rect, icon: Icon, color: Color32) {
    paint_sized(painter, rect, icon, color, 1.6);
}

pub fn paint_sized(
    painter: &eframe::egui::Painter,
    rect: Rect,
    icon: Icon,
    color: Color32,
    width: f32,
) {
    let stroke = Stroke::new(width, color);
    let point = |x: f32, y: f32| {
        Pos2::new(
            rect.min.x + rect.width() * x,
            rect.min.y + rect.height() * y,
        )
    };
    let line = |a: (f32, f32), b: (f32, f32)| {
        painter.line_segment([point(a.0, a.1), point(b.0, b.1)], stroke);
    };
    let soft = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 38);

    match icon {
        Icon::Grid => {
            let cell = rect.width() * 0.34;
            let gap = rect.width() * 0.12;
            for (index, (x, y)) in [(0.1, 0.1), (0.56, 0.1), (0.1, 0.56), (0.56, 0.56)]
                .into_iter()
                .enumerate()
            {
                let _ = index;
                painter.rect_stroke(
                    Rect::from_min_size(point(x, y), Vec2::splat(cell)),
                    Rounding::same(2.0),
                    stroke,
                );
                let _ = gap;
            }
        }
        Icon::Broom => {
            line((0.2, 0.78), (0.66, 0.28));
            line((0.64, 0.22), (0.8, 0.38));
            line((0.2, 0.78), (0.1, 0.92));
            line((0.32, 0.7), (0.22, 0.86));
            line((0.44, 0.6), (0.34, 0.78));
            painter.circle_filled(point(0.86, 0.14), rect.width() * 0.05, color);
            painter.circle_filled(point(0.12, 0.28), rect.width() * 0.03, color);
        }
        Icon::Layers => {
            let mid = 0.5;
            painter.add(Shape::convex_polygon(
                vec![
                    point(0.5, 0.12),
                    point(0.9, 0.34),
                    point(0.5, 0.56),
                    point(0.1, 0.34),
                ],
                soft,
                stroke,
            ));
            line((0.14, 0.54), (0.5, 0.74));
            line((0.5, 0.74), (0.86, 0.54));
            line((0.14, 0.72), (0.5, 0.92));
            line((0.5, 0.92), (0.86, 0.72));
            let _ = mid;
        }
        Icon::File => {
            painter.rect_stroke(
                Rect::from_min_max(point(0.2, 0.08), point(0.8, 0.92)),
                Rounding::same(2.0),
                stroke,
            );
            line((0.34, 0.36), (0.66, 0.36));
            line((0.34, 0.54), (0.66, 0.54));
            line((0.34, 0.72), (0.56, 0.72));
        }
        Icon::Shield => {
            let points = vec![
                point(0.5, 0.06),
                point(0.88, 0.22),
                point(0.82, 0.62),
                point(0.5, 0.94),
                point(0.18, 0.62),
                point(0.12, 0.22),
            ];
            painter.add(Shape::convex_polygon(points, soft, stroke));
            line((0.34, 0.48), (0.46, 0.62));
            line((0.46, 0.62), (0.68, 0.36));
        }
        Icon::Chart => {
            line((0.08, 0.92), (0.94, 0.92));
            painter.rect_filled(
                Rect::from_min_max(point(0.18, 0.56), point(0.36, 0.9)),
                Rounding::same(2.0),
                color,
            );
            painter.rect_filled(
                Rect::from_min_max(point(0.42, 0.34), point(0.6, 0.9)),
                Rounding::same(2.0),
                color,
            );
            painter.rect_filled(
                Rect::from_min_max(point(0.66, 0.14), point(0.84, 0.9)),
                Rounding::same(2.0),
                color,
            );
        }
        Icon::Rocket => {
            painter.add(Shape::convex_polygon(
                vec![
                    point(0.5, 0.05),
                    point(0.72, 0.42),
                    point(0.5, 0.78),
                    point(0.28, 0.42),
                ],
                soft,
                stroke,
            ));
            painter.circle_stroke(point(0.5, 0.36), rect.width() * 0.09, stroke);
            line((0.28, 0.5), (0.12, 0.72));
            line((0.72, 0.5), (0.88, 0.72));
            line((0.5, 0.8), (0.5, 0.96));
        }
        Icon::Activity => {
            let points = vec![
                point(0.06, 0.55),
                point(0.28, 0.55),
                point(0.4, 0.2),
                point(0.56, 0.82),
                point(0.68, 0.55),
                point(0.94, 0.55),
            ];
            painter.add(Shape::line(points, stroke));
        }
        Icon::Gear => {
            painter.circle_stroke(point(0.5, 0.5), rect.width() * 0.22, stroke);
            painter.circle_filled(point(0.5, 0.5), rect.width() * 0.07, color);
            for step in 0..6 {
                let angle = std::f32::consts::TAU * step as f32 / 6.0;
                let inner = Vec2::new(angle.cos(), angle.sin()) * rect.width() * 0.28;
                let outer = Vec2::new(angle.cos(), angle.sin()) * rect.width() * 0.4;
                painter.line_segment([point(0.5, 0.5) + inner, point(0.5, 0.5) + outer], stroke);
            }
        }
        Icon::Search => {
            painter.circle_stroke(point(0.42, 0.42), rect.width() * 0.26, stroke);
            line((0.62, 0.62), (0.9, 0.9));
        }
        Icon::Check => {
            line((0.14, 0.52), (0.4, 0.78));
            line((0.4, 0.78), (0.86, 0.22));
        }
        Icon::Alert => {
            painter.add(Shape::convex_polygon(
                vec![point(0.5, 0.06), point(0.96, 0.9), point(0.04, 0.9)],
                soft,
                stroke,
            ));
            line((0.5, 0.36), (0.5, 0.62));
            painter.circle_filled(point(0.5, 0.76), rect.width() * 0.035, color);
        }
        Icon::Close => {
            line((0.2, 0.2), (0.8, 0.8));
            line((0.8, 0.2), (0.2, 0.8));
        }
        Icon::ChevronRight => {
            line((0.36, 0.18), (0.68, 0.5));
            line((0.68, 0.5), (0.36, 0.82));
        }
        Icon::Trash => {
            line((0.16, 0.24), (0.84, 0.24));
            line((0.38, 0.24), (0.4, 0.1));
            line((0.62, 0.24), (0.6, 0.1));
            line((0.4, 0.1), (0.6, 0.1));
            painter.rect_stroke(
                Rect::from_min_max(point(0.24, 0.28), point(0.76, 0.92)),
                Rounding::same(2.0),
                stroke,
            );
            line((0.44, 0.42), (0.44, 0.78));
            line((0.56, 0.42), (0.56, 0.78));
        }
        Icon::Folder => {
            painter.rect_stroke(
                Rect::from_min_max(point(0.08, 0.24), point(0.92, 0.84)),
                Rounding::same(3.0),
                stroke,
            );
            line((0.08, 0.34), (0.4, 0.34));
            line((0.4, 0.34), (0.5, 0.24));
            line((0.5, 0.24), (0.08, 0.24));
        }
        Icon::Refresh => {
            let radius = rect.width() * 0.3;
            let center = point(0.5, 0.5);
            let steps = 18;
            let mut previous = None;
            for step in 0..=steps {
                let angle = -std::f32::consts::FRAC_PI_2
                    + std::f32::consts::TAU * 0.82 * step as f32 / steps as f32;
                let position = center + Vec2::new(angle.cos(), angle.sin()) * radius;
                if let Some(last) = previous {
                    painter.line_segment([last, position], stroke);
                }
                previous = Some(position);
            }
            line((0.78, 0.12), (0.72, 0.42));
            line((0.78, 0.12), (0.5, 0.2));
        }
        Icon::Play => {
            painter.add(Shape::convex_polygon(
                vec![point(0.28, 0.14), point(0.86, 0.5), point(0.28, 0.86)],
                color,
                Stroke::NONE,
            ));
        }
        Icon::Stop => {
            painter.rect_filled(
                Rect::from_min_max(point(0.24, 0.24), point(0.76, 0.76)),
                Rounding::same(2.0),
                color,
            );
        }
        Icon::Clock => {
            painter.circle_stroke(point(0.5, 0.5), rect.width() * 0.4, stroke);
            line((0.5, 0.5), (0.5, 0.26));
            line((0.5, 0.5), (0.68, 0.6));
        }
        Icon::Disk => {
            painter.rect_stroke(
                Rect::from_min_max(point(0.1, 0.18), point(0.9, 0.82)),
                Rounding::same(3.0),
                stroke,
            );
            line((0.1, 0.42), (0.9, 0.42));
            painter.circle_stroke(point(0.68, 0.64), rect.width() * 0.06, stroke);
        }
        Icon::Download => {
            line((0.5, 0.1), (0.5, 0.62));
            line((0.3, 0.44), (0.5, 0.64));
            line((0.7, 0.44), (0.5, 0.64));
            line((0.16, 0.82), (0.84, 0.82));
            line((0.16, 0.66), (0.16, 0.82));
            line((0.84, 0.66), (0.84, 0.82));
        }
        Icon::Info => {
            painter.circle_stroke(point(0.5, 0.5), rect.width() * 0.4, stroke);
            painter.circle_filled(point(0.5, 0.3), rect.width() * 0.035, color);
            line((0.5, 0.44), (0.5, 0.72));
        }
        Icon::Sparkle => {
            painter.add(Shape::convex_polygon(
                vec![
                    point(0.5, 0.04),
                    point(0.6, 0.4),
                    point(0.96, 0.5),
                    point(0.6, 0.6),
                    point(0.5, 0.96),
                    point(0.4, 0.6),
                    point(0.04, 0.5),
                    point(0.4, 0.4),
                ],
                color,
                Stroke::NONE,
            ));
        }
        Icon::Memory => {
            painter.rect_stroke(
                Rect::from_min_max(point(0.16, 0.24), point(0.84, 0.76)),
                Rounding::same(2.0),
                stroke,
            );
            for step in 0..4 {
                let x = 0.26 + step as f32 * 0.16;
                line((x, 0.1), (x, 0.24));
                line((x, 0.76), (x, 0.9));
            }
        }
        Icon::Cpu => {
            painter.rect_stroke(
                Rect::from_min_max(point(0.18, 0.18), point(0.82, 0.82)),
                Rounding::same(3.0),
                stroke,
            );
            painter.rect_filled(
                Rect::from_min_max(point(0.36, 0.36), point(0.64, 0.64)),
                Rounding::same(2.0),
                color,
            );
        }
        Icon::External => {
            painter.rect_stroke(
                Rect::from_min_max(point(0.1, 0.3), point(0.7, 0.9)),
                Rounding::same(2.0),
                stroke,
            );
            line((0.5, 0.5), (0.9, 0.1));
            line((0.62, 0.1), (0.9, 0.1));
            line((0.9, 0.1), (0.9, 0.38));
        }
        Icon::Plus => {
            line((0.5, 0.16), (0.5, 0.84));
            line((0.16, 0.5), (0.84, 0.5));
        }
        Icon::Minus => {
            line((0.16, 0.5), (0.84, 0.5));
        }
        Icon::Lock => {
            painter.rect_stroke(
                Rect::from_min_max(point(0.18, 0.46), point(0.82, 0.9)),
                Rounding::same(3.0),
                stroke,
            );
            let radius = rect.width() * 0.2;
            let mut previous = None;
            for step in 0..=10 {
                let angle = std::f32::consts::PI + std::f32::consts::PI * step as f32 / 10.0;
                let position = point(0.5, 0.46) + Vec2::new(angle.cos(), angle.sin()) * radius;
                if let Some(last) = previous {
                    painter.line_segment([last, position], stroke);
                }
                previous = Some(position);
            }
            painter.circle_filled(point(0.5, 0.64), rect.width() * 0.045, color);
        }
    }
}
