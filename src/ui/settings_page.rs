//! Settings: appearance, cleaning behaviour, exclusions, Windows integration and
//! the operation log.

use crate::app::{ToastKind, WinCleanApp};
use crate::core::logbook::{self, Level};
use crate::platform;
use crate::settings::ThemeMode;
use crate::ui::icons::{self, Icon};
use crate::ui::widgets;
use eframe::egui::{self, Align, Layout, RichText, Sense, Stroke, Ui, Vec2};

#[derive(Default)]
pub struct SettingsPageState {
    pub exclusion_input: String,
    pub show_all_logs: bool,
}

enum SettingsAction {
    Theme(ThemeMode),
    Autostart(bool),
    Maintenance(bool),
    Elevate,
    OpenLogFolder,
    OpenAppData,
    ClearLogView,
}

pub fn show(ui: &mut Ui, app: &mut WinCleanApp) {
    let palette = app.palette;
    let elevated = app.elevated;
    let os_version = app.os_version.clone();
    let host_label = app.host_label.clone();
    let autostart_active = platform::autostart_enabled();
    let maintenance_active = platform::maintenance_task_installed();

    let mut settings = app.settings.clone();
    let mut exclusion_input = app.settings_page.exclusion_input.clone();
    let mut show_all_logs = app.settings_page.show_all_logs;
    let mut changed = false;
    let mut action: Option<SettingsAction> = None;
    let mut message: Option<(ToastKind, String)> = None;

    widgets::card(&palette).show(ui, |ui| {
        widgets::section(ui, &palette, "Appearance");
        ui.label(
            RichText::new("Both themes use the same layout and contrast; pick what feels right.")
                .size(11.0)
                .color(palette.muted),
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Theme").size(12.0).color(palette.text));
            for (mode, label) in [(ThemeMode::Dark, "Dark"), (ThemeMode::Light, "Light")] {
                let selected = settings.theme == mode;
                let button =
                    egui::Button::new(RichText::new(label).size(12.0).color(if selected {
                        palette.on_accent
                    } else {
                        palette.text
                    }))
                    .fill(if selected {
                        palette.accent
                    } else {
                        palette.card_hover
                    })
                    .stroke(Stroke::new(
                        1.0_f32,
                        if selected {
                            palette.accent
                        } else {
                            palette.border
                        },
                    ))
                    .rounding(egui::Rounding::same(7.0))
                    .min_size(Vec2::new(74.0, 30.0));
                if ui.add(button).clicked() && !selected {
                    action = Some(SettingsAction::Theme(mode));
                }
            }
            ui.add_space(10.0);
            if widgets::toggle_switch(ui, &palette, "reduce-motion", &mut settings.reduce_motion)
                .changed()
            {
                changed = true;
            }
            ui.label(
                RichText::new("Reduce motion")
                    .size(12.0)
                    .color(palette.text),
            );
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Monitor refresh")
                    .size(12.0)
                    .color(palette.text),
            );
            let slider = egui::Slider::new(&mut settings.monitor_interval_ms, 500..=3_000)
                .suffix(" ms")
                .step_by(100.0);
            if ui.add(slider).changed() {
                changed = true;
            }
            ui.label(
                RichText::new("Lower values update the process list more often.")
                    .size(10.5)
                    .color(palette.muted),
            );
        });
    });

    ui.add_space(12.0);
    widgets::card(&palette).show(ui, |ui| {
        widgets::section(ui, &palette, "Cleaning & storage");
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Large file threshold").size(12.0).color(palette.text));
            if ui
                .add(egui::Slider::new(
                    &mut settings.large_file_threshold_gb,
                    1..=50,
                ).suffix(" GB"))
                .changed()
            {
                changed = true;
            }
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new("Duplicate minimum size").size(12.0).color(palette.text));
            if ui
                .add(egui::Slider::new(
                    &mut settings.duplicate_min_size_mb,
                    1..=200,
                ).suffix(" MB"))
                .changed()
            {
                changed = true;
            }
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new("Low storage warning").size(12.0).color(palette.text));
            if ui
                .add(egui::Slider::new(
                    &mut settings.low_storage_threshold_gb,
                    10..=200,
                ).suffix(" GB free"))
                .changed()
            {
                changed = true;
            }
        });
        ui.add_space(6.0);
        widgets::thin_separator(ui, &palette);
        ui.add_space(6.0);
        if widgets::checkbox(
            ui,
            &palette,
            &mut settings.include_prefetch,
            "Offer Prefetch data for cleanup (not recommended — launch traces help startup speed)",
        )
        .changed()
        {
            changed = true;
        }
        if widgets::checkbox(
            ui,
            &palette,
            &mut settings.scan_system_folders,
            "Include Windows and Program Files in large file scans",
        )
        .changed()
        {
            changed = true;
        }
        ui.label(
            RichText::new(
                "Large files are never deleted automatically, even above the threshold. Personal folders always require explicit approval.",
            )
            .size(10.5)
            .color(palette.muted),
        );
    });

    ui.add_space(12.0);
    widgets::card(&palette).show(ui, |ui| {
        widgets::section(ui, &palette, "Safety & exclusions");
        ui.add_space(4.0);
        for line in [
            "Windows system folders (System32, WinSxS, WindowsApps, Recovery) are always protected.",
            "Deleting always requires confirmation; personal folders need a second approval.",
            "Locked files are skipped instead of forced, so nothing half-deleted is left behind.",
            "Every cleanup and security action is written to the log.",
        ] {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(13.0), Sense::hover());
                icons::paint_sized(ui.painter(), rect, Icon::Check, palette.success, 1.5);
                ui.label(RichText::new(line).size(11.0).color(palette.muted));
            });
        }
        ui.add_space(8.0);
        ui.label(
            RichText::new("Never clean these paths")
                .size(12.5)
                .color(palette.text_strong),
        );
        ui.label(
            RichText::new(
                r"Prefixes or wildcards. Environment variables such as %USERPROFILE% and ? / * are supported.",
            )
            .size(10.5)
            .color(palette.muted),
        );
        ui.add_space(4.0);
        let mut add_clicked = false;
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut exclusion_input)
                    .hint_text(r"C:\Projects or *\important.log")
                    .desired_width(340.0),
            );
            add_clicked = widgets::primary_button(ui, &palette, "Add").clicked();
        });
        if add_clicked {
            if settings.add_exclusion(&exclusion_input) {
                exclusion_input.clear();
                changed = true;
                message = Some((ToastKind::Success, "Exclusion added".to_string()));
            } else {
                message = Some((
                    ToastKind::Error,
                    "That exclusion is empty or already exists".to_string(),
                ));
            }
        }
        ui.add_space(6.0);
        if settings.exclusions.is_empty() {
            ui.label(
                RichText::new(
                    "No exclusions yet — everything inside the scanned cleanup locations is eligible.",
                )
                .size(11.0)
                .color(palette.muted),
            );
        } else {
            let mut remove: Option<usize> = None;
            for (index, rule) in settings.exclusions.iter().enumerate() {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(12.0), Sense::hover());
                    icons::paint_sized(ui.painter(), rect, Icon::Lock, palette.muted, 1.4);
                    ui.label(RichText::new(rule).size(11.5).color(palette.text));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::icon_button(ui, &palette, Icon::Close, "Remove").clicked() {
                            remove = Some(index);
                        }
                    });
                });
            }
            if let Some(index) = remove {
                settings.remove_exclusion(index);
                changed = true;
            }
        }
    });

    ui.add_space(12.0);
    widgets::card(&palette).show(ui, |ui| {
        widgets::section(ui, &palette, "Windows integration");
        ui.add_space(6.0);
        if widgets::toggle_switch(ui, &palette, "autostart", &mut settings.start_with_windows).changed()
        {
            action = Some(SettingsAction::Autostart(settings.start_with_windows));
        }
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new("Start WinClean with Windows").size(12.0).color(palette.text));
                ui.label(
                    RichText::new(if autostart_active {
                        "Registered in your user Run key"
                    } else {
                        "Not registered"
                    })
                    .size(10.5)
                    .color(palette.muted),
                );
            });
        });
        ui.add_space(6.0);
        if widgets::toggle_switch(
            ui,
            &palette,
            "maintenance",
            &mut settings.weekly_maintenance,
        )
        .changed()
        {
            action = Some(SettingsAction::Maintenance(settings.weekly_maintenance));
        }
        ui.vertical(|ui| {
            ui.label(RichText::new("Weekly maintenance").size(12.0).color(palette.text));
            ui.label(
                RichText::new(if maintenance_active {
                    "Scheduled task installed · Sundays 03:00 · headless safe cleanup"
                } else {
                    "Schedules a headless safe cleanup every Sunday at 03:00"
                })
                .size(10.5)
                .color(palette.muted),
            );
        });
        ui.add_space(6.0);
        widgets::thin_separator(ui, &palette);
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(if elevated {
                        "Running as administrator"
                    } else {
                        "Running as a standard user"
                    })
                    .size(12.0)
                    .color(palette.text),
                );
                ui.label(
                    RichText::new(
                        "Elevation is requested only for Windows-protected folders and Defender actions.",
                    )
                    .size(10.5)
                    .color(palette.muted),
                );
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if !elevated && widgets::ghost_button(ui, &palette, "Restart elevated").clicked() {
                    action = Some(SettingsAction::Elevate);
                }
                if widgets::ghost_button(ui, &palette, "Open log folder").clicked() {
                    action = Some(SettingsAction::OpenLogFolder);
                }
            });
        });
    });

    ui.add_space(12.0);
    widgets::card(&palette).show(ui, |ui| {
        ui.horizontal(|ui| {
            widgets::section(ui, &palette, "Activity log");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::ghost_button(ui, &palette, "Open folder").clicked() {
                    action = Some(SettingsAction::OpenAppData);
                }
                if widgets::ghost_button(ui, &palette, "Clear view").clicked() {
                    action = Some(SettingsAction::ClearLogView);
                }
                widgets::checkbox(ui, &palette, &mut show_all_logs, "Show all");
            });
        });
        ui.label(
            RichText::new(format!("Stored at {}", logbook::sink().path().display()))
                .size(10.5)
                .color(palette.muted),
        );
        ui.add_space(4.0);
        let limit = if show_all_logs { 400 } else { 60 };
        let entries = logbook::sink().recent(limit);
        if entries.is_empty() {
            ui.label(
                RichText::new("No operations logged yet.")
                    .size(11.0)
                    .color(palette.muted),
            );
        } else {
            egui::ScrollArea::vertical()
                .id_salt("activity-log")
                .max_height(260.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for entry in entries.iter().rev() {
                        let color = match entry.level {
                            Level::Success => palette.success,
                            Level::Warn => palette.warning,
                            Level::Error => palette.danger,
                            Level::Info => palette.muted,
                        };
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(crate::format::date_time(
                                    entry.time,
                                    platform::local_offset_seconds(),
                                ))
                                .size(10.0)
                                .color(palette.muted),
                            );
                            widgets::badge(ui, &palette, entry.level.label(), color);
                            ui.label(
                                RichText::new(crate::format::ellipsize(&entry.message, 96))
                                    .size(10.5)
                                    .color(palette.text),
                            );
                        });
                    }
                });
        }
    });

    ui.add_space(12.0);
    widgets::card(&palette).show(ui, |ui| {
        widgets::section(ui, &palette, "About");
        ui.add_space(4.0);
        widgets::key_value(ui, &palette, "WinClean", crate::app::VERSION);
        widgets::key_value(ui, &palette, "Windows", &os_version);
        widgets::key_value(ui, &palette, "Computer", &host_label);
        widgets::key_value(
            ui,
            &palette,
            "Build",
            if cfg!(debug_assertions) {
                "development"
            } else {
                "release (optimised)"
            },
        );
        ui.label(
            RichText::new(
                "WinClean never disables Microsoft Defender, the Windows firewall or any security feature, and never uploads file contents. Scans and detections happen locally or inside Microsoft Defender.",
            )
            .size(10.5)
            .color(palette.muted),
        );
    });

    let theme_changed = action
        .as_ref()
        .map(|action| matches!(action, SettingsAction::Theme(_)))
        .unwrap_or(false);
    if changed && !theme_changed {
        app.settings = settings.clone();
        app.persist_settings();
    }
    app.settings_page.exclusion_input = exclusion_input;
    app.settings_page.show_all_logs = show_all_logs;
    if let Some((kind, text)) = message {
        app.toast(kind, text);
    }

    match action {
        Some(SettingsAction::Theme(mode)) => {
            app.settings = settings;
            app.set_theme(ui.ctx(), mode);
        }
        Some(SettingsAction::Autostart(enabled)) => {
            app.settings = settings;
            match platform::set_autostart(enabled) {
                Ok(()) => {
                    app.persist_settings();
                    app.toast(
                        ToastKind::Success,
                        if enabled {
                            "WinClean will start with Windows"
                        } else {
                            "Autostart disabled"
                        },
                    );
                }
                Err(err) => {
                    app.settings.start_with_windows = !enabled;
                    app.persist_settings();
                    app.toast(ToastKind::Error, err);
                }
            }
        }
        Some(SettingsAction::Maintenance(enabled)) => {
            app.settings = settings;
            app.toggle_maintenance(enabled);
        }
        Some(SettingsAction::Elevate) => app.request_elevation(),
        Some(SettingsAction::OpenLogFolder) => {
            if let Err(err) = platform::open_folder(&crate::core::paths::log_dir()) {
                app.toast(ToastKind::Error, err);
            }
        }
        Some(SettingsAction::OpenAppData) => {
            if let Err(err) = platform::open_folder(&crate::core::paths::app_data_dir()) {
                app.toast(ToastKind::Error, err);
            }
        }
        Some(SettingsAction::ClearLogView) => {
            logbook::sink().clear_view();
            app.toast(
                ToastKind::Info,
                "Log view cleared (the file on disk is kept)",
            );
        }
        None => {}
    }
}
