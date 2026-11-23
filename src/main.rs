//! WinClean — a lightweight Windows PC cleaner and security utility.
//!
//! Two entry points share the same engine:
//! * the native desktop interface (default), and
//! * `winclean.exe --maintenance`, a headless safe cleanup used by the weekly
//!   scheduled task. It only removes files the normal Quick Clean would preselect,
//!   never personal files, and logs everything.

#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

mod app;
mod core;
mod format;
mod model;
mod platform;
mod settings;
mod theme;
mod ui;

use app::WinCleanApp;
use core::clean::CleanOptions;
use model::{Category, Finding};
use settings::{AppState, Settings};
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |flag: &str| args.iter().any(|arg| arg == flag);

    if has("--version") || has("-V") {
        println!("WinClean {}", app::VERSION);
        return;
    }
    if has("--help") || has("-h") {
        print_help();
        return;
    }

    install_panic_hook();

    if has("--maintenance") {
        let code = run_maintenance();
        std::process::exit(code);
    }

    if let Err(error) = run_gui() {
        core::logbook::sink().error("app", format!("The interface could not start: {error}"));
        eprintln!("WinClean could not start: {error}");
    }
}

fn print_help() {
    println!(
        "WinClean {}\n\
         \n\
         Usage: winclean [options]\n\
         \n\
         Options:\n\
           --maintenance   Run a headless safe cleanup and exit\n\
           --version, -V   Print the version\n\
           --help, -h      Show this help\n\
         \n\
         The graphical interface starts when no option is given.",
        app::VERSION
    );
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let message = format!("Panic: {info}");
        core::logbook::sink().error("panic", &message);
        eprintln!("{message}");
    }));
}

fn run_gui() -> Result<(), String> {
    let state = AppState::load();
    let width = state.window_width.unwrap_or(1240.0).clamp(1_040.0, 3_840.0);
    let height = state.window_height.unwrap_or(830.0).clamp(680.0, 2_160.0);

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("WinClean — PC Cleaner & Security")
            .with_inner_size([width, height])
            .with_min_inner_size([1_040.0, 680.0])
            .with_icon(std::sync::Arc::new(icon_data())),
        vsync: true,
        ..Default::default()
    };

    eframe::run_native(
        "WinClean",
        options,
        Box::new(|cc| {
            let application: Box<dyn eframe::App> = Box::new(WinCleanApp::new(cc));
            Ok(application)
        }),
    )
    .map_err(|error| error.to_string())
}

/// Headless cleanup used by the weekly scheduled task.
fn run_maintenance() -> i32 {
    let sink = core::logbook::sink();
    sink.info("maintenance", "Scheduled maintenance started");
    let settings = Settings::load();
    let (findings, summary) = app::maintenance_scan();
    let candidates: Vec<Finding> = findings
        .into_iter()
        .filter(is_safe_for_unattended_cleanup)
        .collect();
    if candidates.is_empty() {
        sink.info(
            "maintenance",
            format!(
                "Nothing safe to remove (scanned {} items, {} recoverable)",
                summary.items_found,
                format::bytes(summary.bytes_found)
            ),
        );
        return 0;
    }
    let options = CleanOptions {
        allowed_roots: core::clean::cleanup_allowed_roots(&settings),
        exclusions: settings.exclusions(),
        approve_personal: false,
    };
    let expected: u64 = candidates.iter().map(|finding| finding.size).sum();
    let mut session = ui::jobs::CleanSession::start(candidates, options);
    let deadline = std::time::Instant::now() + Duration::from_secs(600);
    while std::time::Instant::now() < deadline {
        let tick = session.poll();
        if let Some(report) = tick.done {
            sink.info(
                "maintenance",
                format!(
                    "Maintenance removed {} of {} item(s), freed {} ({} failed, {} skipped)",
                    report.removed,
                    report.removed + report.failed + report.skipped,
                    format::bytes(report.bytes_freed),
                    report.failed,
                    report.skipped
                ),
            );
            for (path, error) in report.errors.iter().take(10) {
                sink.warn("maintenance", format!("{}: {error}", path.display()));
            }
            return if report.failed > 0 { 1 } else { 0 };
        }
        std::thread::sleep(Duration::from_millis(80));
    }
    sink.warn(
        "maintenance",
        format!(
            "Maintenance timed out with about {} still queued",
            format::bytes(expected)
        ),
    );
    1
}

/// Unattended cleanup is deliberately narrower than an interactive Deep Clean:
/// only default-selected cleanup categories, never personal folders, never the
/// recycle bin, large files or duplicates.
fn is_safe_for_unattended_cleanup(finding: &Finding) -> bool {
    !finding.special
        && finding.category.default_selected()
        && !matches!(
            finding.category,
            Category::LargeFile | Category::Duplicate | Category::RecycleBin
        )
        && !core::guard::is_personal(&finding.path)
}

/// Generates the window and taskbar icon at runtime, so the binary stays a single
/// self-contained file with no external assets.
fn icon_data() -> eframe::egui::IconData {
    const SIZE: usize = 64;
    let mut rgba = vec![0u8; SIZE * SIZE * 4];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let px = x as f32 + 0.5;
            let py = y as f32 + 0.5;
            if !inside_rounded(px, py, 2.0, 2.0, 60.0, 60.0, 15.0) {
                continue;
            }
            let t = (py / SIZE as f32).clamp(0.0, 1.0);
            let base = (
                36.0 + (52.0 - 36.0) * t,
                92.0 + (126.0 - 92.0) * t,
                238.0 + (247.0 - 238.0) * t,
            );
            let on_check = near_segment(px, py, 17.0, 33.5, 28.0, 44.5, 3.2)
                || near_segment(px, py, 28.0, 44.5, 47.0, 21.0, 3.2);
            let offset = (y * SIZE + x) * 4;
            if on_check {
                rgba[offset] = 255;
                rgba[offset + 1] = 255;
                rgba[offset + 2] = 255;
            } else {
                rgba[offset] = base.0 as u8;
                rgba[offset + 1] = base.1 as u8;
                rgba[offset + 2] = base.2 as u8;
            }
            rgba[offset + 3] = 255;
        }
    }
    eframe::egui::IconData {
        rgba,
        width: SIZE as u32,
        height: SIZE as u32,
    }
}

fn inside_rounded(px: f32, py: f32, x: f32, y: f32, w: f32, h: f32, radius: f32) -> bool {
    let cx = px.clamp(x + radius, x + w - radius);
    let cy = py.clamp(y + radius, y + h - radius);
    let dx = px - cx;
    let dy = py - cy;
    if px < x || py < y || px > x + w || py > y + h {
        return false;
    }
    dx * dx + dy * dy <= radius * radius
}

fn near_segment(px: f32, py: f32, ax: f32, ay: f32, bx: f32, by: f32, width: f32) -> bool {
    let vx = bx - ax;
    let vy = by - ay;
    let length_sq = vx * vx + vy * vy;
    if length_sq <= f32::EPSILON {
        return (px - ax).hypot(py - ay) <= width;
    }
    let t = (((px - ax) * vx + (py - ay) * vy) / length_sq).clamp(0.0, 1.0);
    let nx = ax + vx * t;
    let ny = ay + vy * t;
    (px - nx).hypot(py - ny) <= width
}
