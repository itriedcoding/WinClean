//! Dashboard: health score, storage snapshot, protection state and quick actions.

use crate::app::{Page, ToastKind, WinCleanApp};
use crate::core::logbook::{self, Level};
use crate::core::storage::{self, HealthInput};
use crate::model::{DefenderScanKind, Volume};
use crate::platform;
use crate::theme::{self, Palette};
use crate::ui::icons::{self, Icon};
use crate::ui::widgets::{self, mix};
use eframe::egui::{
    self, Align, Color32, FontId, Layout, Rect, RichText, Rounding, Sense, Ui, Vec2,
};

enum DashAction {
    Navigate(Page),
    QuickScan,
    DefenderScan,
    OpenSecurity,
    Elevate,
    UpdateSignatures,
}

pub fn show(ui: &mut Ui, app: &mut WinCleanApp) {
    let palette = app.palette;
    let volumes = app.volumes.clone();
    let defender = app.defender.clone();
    let insights = app.insights.clone();
    let threshold = app.settings.low_storage_threshold_bytes();
    let startup_enabled = app
        .startup_entries
        .iter()
        .filter(|entry| entry.enabled)
        .count();
    let startup_suspicious = app
        .startup_entries
        .iter()
        .filter(|entry| entry.suspicious)
        .count();
    let threats = app.threat_count();
    let defender_threats = app.security.threats.len();
    let scan_running = app.security.scanning;
    let stats = app.sample.stats.clone();
    let last_clean = app.state.last_quick_clean;
    let bytes_freed_total = app.state.bytes_freed_total;
    let reduced_motion = app.settings.reduce_motion;
    let mut action: Option<DashAction> = None;

    let checks = storage::health_checks(&HealthInput {
        volumes: &volumes,
        threshold_bytes: threshold,
        cleanup_bytes: insights.cleanup_bytes,
        recycle_bytes: insights.recycle_bytes,
        startup_enabled,
        defender: defender.as_ref(),
    });
    let score = storage::score(&checks);
    let score_color = if score >= 80 {
        palette.success
    } else if score >= 55 {
        palette.warning
    } else {
        palette.danger
    };

    if let Some(volume) = storage::lowest_free_volume(&volumes) {
        if storage::is_low_storage(volume, threshold) {
            widgets::card(&palette).show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::hover());
                    ui.painter().circle_filled(
                        rect.center(),
                        15.0,
                        palette.alpha(palette.warning, 30),
                    );
                    icons::paint_sized(ui.painter(), rect.shrink(6.0), Icon::Disk, palette.warning, 1.7);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "Only {} free on {}",
                                crate::format::bytes(volume.free),
                                volume.mount.trim_end_matches('\\')
                            ))
                            .font(FontId::new(16.0, theme::heading()))
                            .color(palette.text_strong),
                        );
                        ui.label(
                            RichText::new(
                                "Windows needs free space for updates and temporary files. Recovering a few gigabytes keeps the PC fast.",
                            )
                            .size(12.0)
                            .color(palette.muted),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::primary_button(ui, &palette, "Guided cleanup").clicked() {
                            action = Some(DashAction::Navigate(Page::Storage));
                        }
                        if widgets::ghost_button(ui, &palette, "Quick Clean").clicked() {
                            action = Some(DashAction::Navigate(Page::QuickClean));
                        }
                    });
                });
            });
            ui.add_space(14.0);
        }
    }

    ui.columns(4, |columns| {
        let width = columns[0].available_width();
        widgets::stat_card(
            &mut columns[0],
            &palette,
            width,
            "System health",
            &format!("{score} / 100"),
            &match score {
                80..=100 => "Everything looks healthy",
                55..=79 => "Some attention recommended",
                _ => "Action recommended",
            },
            score_color,
        );
        widgets::stat_card(
            &mut columns[1],
            &palette,
            width,
            "Recoverable now",
            &crate::format::bytes(insights.cleanup_bytes + insights.recycle_bytes),
            if insights.cleanup_bytes > 0 {
                "From the last cleanup scan"
            } else {
                "Run Quick Clean to measure"
            },
            palette.success,
        );
        let free = storage::lowest_free_volume(&volumes)
            .map(|volume| volume.free)
            .unwrap_or(0);
        widgets::stat_card(
            &mut columns[2],
            &palette,
            width,
            "Free storage",
            &crate::format::bytes(free),
            &storage::lowest_free_volume(&volumes)
                .map(|volume| format!("on {}", volume.mount.trim_end_matches('\\')))
                .unwrap_or_else(|| "No fixed drive".to_string()),
            if free < threshold {
                palette.warning
            } else {
                palette.accent
            },
        );
        widgets::stat_card(
            &mut columns[3],
            &palette,
            width,
            "Security",
            &if threats == 0 {
                "Clear".to_string()
            } else {
                format!("{threats} finding(s)")
            },
            if threats == 0 {
                "Microsoft Defender active"
            } else {
                "Review the Malware Scanner"
            },
            if threats == 0 {
                palette.success
            } else {
                palette.danger
            },
        );
    });

    ui.add_space(14.0);
    ui.columns(2, |columns| {
        health_card(&mut columns[0], &palette, score, score_color, &checks);
        storage_card(&mut columns[1], &palette, &volumes, threshold, &insights);
    });

    ui.add_space(14.0);
    ui.columns(3, |columns| {
        let width = columns[0].available_width();
        action_card(
            &mut columns[0],
            &palette,
            width,
            Icon::Broom,
            "Clean up junk",
            if insights.cleanup_bytes > 0 {
                format!(
                    "{} across temp files, caches and logs",
                    crate::format::bytes(insights.cleanup_bytes)
                )
            } else {
                "Scan for temporary files, caches and crash reports".to_string()
            },
            "Review & clean",
            || action = Some(DashAction::Navigate(Page::QuickClean)),
        );
        let defender_label = defender
            .as_ref()
            .map(|status| {
                if status.available && status.antivirus_enabled {
                    if status.realtime_enabled {
                        "Real-time protection is on".to_string()
                    } else {
                        "Real-time protection is off".to_string()
                    }
                } else {
                    "Defender status unavailable".to_string()
                }
            })
            .unwrap_or_else(|| "Checking Microsoft Defender…".to_string());
        action_card(
            &mut columns[1],
            &palette,
            width,
            Icon::Shield,
            "Security check",
            defender_label,
            if scan_running {
                "Scan running…"
            } else {
                "Run quick scan"
            },
            || {
                if scan_running {
                    action = Some(DashAction::Navigate(Page::Malware));
                } else {
                    action = Some(DashAction::DefenderScan);
                }
            },
        );
        action_card(
            &mut columns[2],
            &palette,
            width,
            Icon::Rocket,
            "Startup impact",
            if startup_suspicious > 0 {
                format!("{startup_suspicious} suspicious startup entries need a look")
            } else {
                format!("{startup_enabled} apps launch when you sign in")
            },
            "Manage startup",
            || action = Some(DashAction::Navigate(Page::Startup)),
        );
    });

    ui.add_space(14.0);
    ui.columns(2, |columns| {
        protection_card(
            &mut columns[0],
            &palette,
            defender.as_ref(),
            defender_threats,
            scan_running,
            &mut action,
            reduced_motion,
        );
        activity_card(
            &mut columns[1],
            &palette,
            last_clean,
            bytes_freed_total,
            &stats,
            &mut action,
        );
    });

    match action {
        Some(DashAction::Navigate(page)) => app.navigate(page),
        Some(DashAction::QuickScan) => app.navigate(Page::QuickClean),
        Some(DashAction::DefenderScan) => {
            app.navigate(Page::Malware);
            app.defender_scan(DefenderScanKind::Quick);
            app.toast(ToastKind::Info, "Microsoft Defender quick scan started");
        }
        Some(DashAction::OpenSecurity) => {
            if let Err(err) = platform::open_windows_security() {
                app.toast(ToastKind::Error, err);
            }
        }
        Some(DashAction::Elevate) => app.request_elevation(),
        Some(DashAction::UpdateSignatures) => {
            app.security.busy = Some("Updating Microsoft Defender signatures…".to_string());
            let result = platform::update_defender_signatures();
            app.security.busy = None;
            match result {
                Ok(message) => {
                    logbook::sink().success("security", format!("Defender signatures: {message}"));
                    app.toast(ToastKind::Success, message);
                }
                Err(err) => app.toast(ToastKind::Error, err),
            }
        }
        None => {}
    }
}

fn health_card(
    ui: &mut Ui,
    palette: &Palette,
    score: u32,
    score_color: Color32,
    checks: &[crate::model::HealthCheck],
) {
    widgets::card(palette).show(ui, |ui| {
        ui.set_width(ui.available_width());
        widgets::section(ui, palette, "System health");
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            widgets::ring(
                ui,
                palette,
                score as f32 / 100.0,
                128.0,
                score_color,
                &format!("{score}"),
                "health score",
            );
            ui.add_space(10.0);
            ui.vertical(|ui| {
                for check in checks.iter().take(4) {
                    let color = palette.health_color(check.state);
                    ui.horizontal(|ui| {
                        let (rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
                        ui.painter().circle_filled(rect.center(), 3.5, color);
                        ui.label(
                            RichText::new(&check.title)
                                .size(12.0)
                                .color(palette.text_strong),
                        );
                    });
                    ui.label(RichText::new(&check.detail).size(10.5).color(palette.muted));
                    ui.add_space(3.0);
                }
            });
        });
    });
}

fn storage_card(
    ui: &mut Ui,
    palette: &Palette,
    volumes: &[Volume],
    threshold: u64,
    insights: &storage::StorageInsight,
) {
    widgets::card(palette).show(ui, |ui| {
        ui.set_width(ui.available_width());
        widgets::section(ui, palette, "Storage");
        ui.add_space(6.0);
        if volumes.is_empty() {
            widgets::empty_state(
                ui,
                palette,
                Icon::Disk,
                "No drive detected",
                "WinClean could not read drive information on this system.",
            );
            return;
        }
        for volume in volumes.iter().take(3) {
            let low = storage::is_low_storage(volume, threshold);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{} · {}",
                        volume.mount.trim_end_matches('\\'),
                        volume.label
                    ))
                    .size(12.0)
                    .color(palette.text_strong),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} free of {}",
                            crate::format::bytes(volume.free),
                            crate::format::bytes(volume.total)
                        ))
                        .size(11.0)
                        .color(if low {
                            palette.warning
                        } else {
                            palette.muted
                        }),
                    );
                });
            });
            ui.add_space(3.0);
            let segments = storage::stacked_segments(volume, insights.cleanup_bytes);
            let (rect, _) =
                ui.allocate_exact_size(Vec2::new(ui.available_width(), 10.0), Sense::hover());
            ui.painter()
                .rect_filled(rect, Rounding::same(5.0), palette.track);
            let mut x = rect.left();
            let total = volume.total.max(1) as f32;
            for (label, bytes) in segments {
                let width = rect.width() * (bytes as f32 / total);
                let color = match label {
                    "Reclaimable" => palette.accent,
                    "In use" => mix(
                        palette.track,
                        palette.muted,
                        if palette.dark { 0.45 } else { 0.35 },
                    ),
                    _ => Color32::TRANSPARENT,
                };
                if width > 0.4 {
                    let segment = Rect::from_min_size(
                        egui::pos2(x, rect.top()),
                        Vec2::new(width, rect.height()),
                    );
                    ui.painter()
                        .rect_filled(segment, Rounding::same(2.0), color);
                }
                x += width;
            }
            ui.add_space(8.0);
        }
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(9.0), Sense::hover());
            ui.painter()
                .circle_filled(rect.center(), 4.0, palette.accent);
            ui.label(RichText::new("Reclaimable").size(10.0).color(palette.muted));
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(9.0), Sense::hover());
            ui.painter()
                .circle_filled(rect.center(), 4.0, mix(palette.track, palette.muted, 0.45));
            ui.label(RichText::new("In use").size(10.0).color(palette.muted));
        });
    });
}

fn action_card(
    ui: &mut Ui,
    palette: &Palette,
    width: f32,
    icon: Icon,
    title: &str,
    body: String,
    button: &str,
    mut on_click: impl FnMut(),
) {
    widgets::card(palette).show(ui, |ui| {
        ui.set_width((width - 36.0).max(120.0));
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::hover());
        ui.painter()
            .rect_filled(rect, Rounding::same(8.0), palette.alpha(palette.accent, 28));
        icons::paint_sized(ui.painter(), rect.shrink(7.0), icon, palette.accent, 1.7);
        ui.add_space(6.0);
        ui.label(
            RichText::new(title)
                .font(FontId::new(14.5, theme::heading()))
                .color(palette.text_strong),
        );
        ui.label(RichText::new(body).size(11.5).color(palette.muted));
        ui.add_space(8.0);
        if widgets::ghost_button(ui, palette, button).clicked() {
            on_click();
        }
    });
}

fn protection_card(
    ui: &mut Ui,
    palette: &Palette,
    defender: Option<&crate::model::DefenderStatus>,
    detections: usize,
    scanning: bool,
    action: &mut Option<DashAction>,
    reduced_motion: bool,
) {
    widgets::card(palette).show(ui, |ui| {
        ui.set_width(ui.available_width());
        widgets::section(ui, palette, "Protection");
        ui.add_space(4.0);
        match defender {
            None => {
                ui.horizontal(|ui| {
                    widgets::spinner(ui, palette, 16.0);
                    ui.label(
                        RichText::new("Reading Microsoft Defender status…")
                            .size(12.0)
                            .color(palette.muted),
                    );
                });
            }
            Some(status) if !status.available => {
                widgets::alert_banner(
                    ui,
                    palette,
                    palette.warning,
                    Icon::Alert,
                    "Defender status unavailable",
                    status
                        .error
                        .as_deref()
                        .unwrap_or("Windows Security could not be queried."),
                );
                ui.add_space(6.0);
                if widgets::ghost_button(ui, palette, "Open Windows Security").clicked() {
                    *action = Some(DashAction::OpenSecurity);
                }
            }
            Some(status) => {
                let healthy = status.antivirus_enabled && status.realtime_enabled;
                let color = if healthy { palette.success } else { palette.danger };
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
                    icons::paint_sized(
                        ui.painter(),
                        rect,
                        if healthy { Icon::Shield } else { Icon::Alert },
                        color,
                        1.7,
                    );
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(if healthy {
                                "Microsoft Defender is protecting this PC"
                            } else {
                                "Protection needs attention"
                            })
                            .size(13.0)
                            .color(palette.text_strong),
                        );
                        ui.label(
                            RichText::new(format!(
                                "Signatures {} · {}",
                                if status.signature_version.is_empty() {
                                    "unknown".to_string()
                                } else {
                                    status.signature_version.clone()
                                },
                                match status.signature_age_days {
                                    Some(0) => "updated today".to_string(),
                                    Some(days) => format!("{days} day(s) old"),
                                    None => "age unknown".to_string(),
                                }
                            ))
                            .size(11.0)
                            .color(palette.muted),
                        );
                    });
                });
                if detections > 0 {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!(
                            "{detections} detection(s) recorded — review them in the Malware Scanner"
                        ))
                        .size(11.5)
                        .color(palette.warning),
                    );
                }
                ui.add_space(8.0);
                let mut buttons = Vec::new();
                ui.horizontal(|ui| {
                    buttons.push(("Open Windows Security", widgets::ghost_button(ui, palette, "Windows Security").clicked()));
                    buttons.push(("Update signatures", widgets::ghost_button(ui, palette, "Update signatures").clicked()));
                });
                for (kind, clicked) in buttons {
                    if !clicked {
                        continue;
                    }
                    if kind == "Update signatures" {
                        *action = Some(DashAction::UpdateSignatures);
                    } else {
                        *action = Some(DashAction::OpenSecurity);
                    }
                }
                if !scanning {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(
                            "WinClean never disables Defender, the firewall or Windows security features.",
                        )
                        .size(10.0)
                        .color(palette.muted),
                    );
                }
                let _ = reduced_motion;
            }
        }
    });
}

fn activity_card(
    ui: &mut Ui,
    palette: &Palette,
    last_clean: Option<u64>,
    total_freed: u64,
    stats: &crate::model::SystemStats,
    action: &mut Option<DashAction>,
) {
    widgets::card(palette).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            widgets::section(ui, palette, "Activity");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::ghost_button(ui, palette, "Open log").clicked() {
                    *action = Some(DashAction::Navigate(Page::Settings));
                }
            });
        });
        ui.add_space(4.0);
        let entries = logbook::sink().recent(4);
        if entries.is_empty() {
            ui.label(
                RichText::new("No operations yet. Everything you do is logged here and on disk.")
                    .size(11.5)
                    .color(palette.muted),
            );
        } else {
            for entry in entries.iter().rev() {
                let color = match entry.level {
                    Level::Success => palette.success,
                    Level::Warn => palette.warning,
                    Level::Error => palette.danger,
                    Level::Info => palette.muted,
                };
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(7.0), Sense::hover());
                    ui.painter().circle_filled(rect.center(), 3.0, color);
                    ui.label(
                        RichText::new(crate::format::ellipsize(&entry.message, 58))
                            .size(11.0)
                            .color(palette.text),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(crate::format::relative(entry.time))
                                .size(10.0)
                                .color(palette.muted),
                        );
                    });
                });
            }
        }
        ui.add_space(10.0);
        widgets::thin_separator(ui, palette);
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("Freed all time")
                        .size(10.5)
                        .color(palette.muted),
                );
                ui.label(
                    RichText::new(crate::format::bytes(total_freed))
                        .font(FontId::new(15.0, theme::heading()))
                        .color(palette.success),
                );
            });
            ui.add_space(18.0);
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("Last cleanup")
                        .size(10.5)
                        .color(palette.muted),
                );
                let text = last_clean
                    .map(|secs| {
                        crate::format::relative(
                            std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs),
                        )
                    })
                    .unwrap_or_else(|| "never".to_string());
                ui.label(
                    RichText::new(text)
                        .font(FontId::new(13.0, theme::heading()))
                        .color(palette.text),
                );
            });
            ui.add_space(18.0);
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("Memory in use")
                        .size(10.5)
                        .color(palette.muted),
                );
                ui.label(
                    RichText::new(format!(
                        "{} · {:.0}%",
                        crate::format::bytes(stats.mem_used),
                        stats.mem_percent()
                    ))
                    .font(FontId::new(13.0, theme::heading()))
                    .color(palette.text),
                );
            });
        });
    });
}
