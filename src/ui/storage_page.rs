//! Storage analyzer: volume usage, quantified recommendations, folder breakdown
//! and installed application sizes.

use crate::app::{Page, ToastKind, WinCleanApp};
use crate::core::storage::{self, StorageInsight};
use crate::model::{InstalledApp, RecommendationAction, Volume};
use crate::platform;
use crate::theme::{self, Palette};
use crate::ui::icons::{self, Icon};
use crate::ui::jobs::FolderScanJob;
use crate::ui::widgets::{self, mix};
use eframe::egui::{
    self, Align, Align2, FontId, Layout, RichText, Rounding, Sense, Stroke, Ui, Vec2,
};
use std::path::{Path, PathBuf};

pub struct StorageState {
    pub scan: Option<FolderScanJob>,
    pub folders: Vec<(PathBuf, u64)>,
    pub loading: bool,
    pub root: String,
    pub confirm_empty_bin: bool,
}

impl Default for StorageState {
    fn default() -> Self {
        let root = platform::volumes()
            .into_iter()
            .find(|volume| volume.fixed)
            .map(|volume| volume.mount)
            .unwrap_or_else(|| r"C:\".to_string());
        Self {
            scan: None,
            folders: Vec::new(),
            loading: false,
            root,
            confirm_empty_bin: false,
        }
    }
}

enum StorageAction {
    Navigate(Page),
    AskEmptyBin,
    EmptyBin,
    Analyze(PathBuf),
    Reveal(PathBuf),
    OpenAppsSettings,
    RefreshApps,
    StartQuickScan,
    DismissBinDialog,
}

pub fn show(ui: &mut Ui, app: &mut WinCleanApp) {
    let palette = app.palette;
    let volumes = app.volumes.clone();
    let threshold = app.settings.low_storage_threshold_bytes();
    let insights = app.insights.clone();
    let apps = app.apps.clone();
    let apps_loading = app.apps_job.is_some();
    let mut action: Option<StorageAction> = None;

    let low_volume = storage::lowest_free_volume(&volumes)
        .filter(|volume| storage::is_low_storage(volume, threshold))
        .cloned();

    if let Some(volume) = &low_volume {
        low_storage_banner(ui, &palette, volume, &mut action);
        ui.add_space(14.0);
        guided_steps(ui, &palette, &insights, &mut action);
        ui.add_space(14.0);
    }

    volume_cards(ui, &palette, &volumes, threshold, &insights);
    ui.add_space(14.0);

    recommendations(ui, &palette, &insights, threshold, &mut action);
    ui.add_space(14.0);

    folder_breakdown(ui, &palette, app, &mut action);
    ui.add_space(14.0);

    applications(ui, &palette, &apps, apps_loading, &mut action);
    ui.add_space(8.0);

    confirm_empty_bin(ui.ctx(), &palette, app, &mut action);

    match action {
        Some(StorageAction::Navigate(page)) => app.navigate(page),
        Some(StorageAction::StartQuickScan) => {
            let settings = app.settings.clone();
            app.quick.start_scan(&settings);
            app.navigate(Page::QuickClean);
            app.toast(ToastKind::Info, "Quick Clean scan started");
        }
        Some(StorageAction::AskEmptyBin) => app.storage.confirm_empty_bin = true,
        Some(StorageAction::EmptyBin) => match platform::empty_recycle_bin() {
            Ok(freed) => {
                crate::core::logbook::sink().success(
                    "clean",
                    format!("Recycle Bin emptied, freed {}", crate::format::bytes(freed)),
                );
                app.quick.remove_path(Path::new("shell:RecycleBin"));
                app.deep.remove_path(Path::new("shell:RecycleBin"));
                app.insights.recycle_bytes = 0;
                app.refresh_volumes();
                app.toast(
                    ToastKind::Success,
                    format!(
                        "Recycle Bin emptied · {} freed",
                        crate::format::bytes(freed)
                    ),
                );
            }
            Err(err) => app.toast(ToastKind::Error, err),
        },
        Some(StorageAction::Analyze(root)) => app.start_storage_scan(root),
        Some(StorageAction::Reveal(path)) => {
            if let Err(err) = platform::reveal_in_explorer(&path) {
                app.toast(ToastKind::Error, err);
            }
        }
        Some(StorageAction::OpenAppsSettings) => {
            if let Err(err) = platform::open_url("ms-settings:appsfeatures") {
                app.toast(ToastKind::Error, err);
            }
        }
        Some(StorageAction::RefreshApps) => {
            app.apps_job = None;
            app.load_apps();
        }
        Some(StorageAction::DismissBinDialog) => {
            app.storage.confirm_empty_bin = false;
        }
        None => {}
    }
}

fn low_storage_banner(
    ui: &mut Ui,
    palette: &Palette,
    volume: &Volume,
    action: &mut Option<StorageAction>,
) {
    egui::Frame::none()
        .fill(palette.alpha(palette.warning, if palette.dark { 30 } else { 18 }))
        .stroke(Stroke::new(1.0_f32, palette.alpha(palette.warning, 110)))
        .rounding(Rounding::same(14.0))
        .inner_margin(egui::Margin::same(20.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(46.0), Sense::hover());
                ui.painter().circle_filled(
                    rect.center(),
                    23.0,
                    palette.alpha(palette.warning, 40),
                );
                icons::paint_sized(ui.painter(), rect.shrink(11.0), Icon::Alert, palette.warning, 1.9);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "Low storage: {} free on {}",
                            crate::format::bytes(volume.free),
                            volume.mount.trim_end_matches('\\')
                        ))
                        .font(FontId::new(19.0, theme::heading()))
                        .color(palette.text_strong),
                    );
                    ui.label(
                        RichText::new(format!(
                            "Windows slows down and updates fail below {}. Follow the guided steps to recover space safely.",
                            crate::format::bytes(100 * 1024 * 1024 * 1024)
                        ))
                        .size(12.0)
                        .color(palette.muted),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::primary_button(ui, palette, "Guided cleanup").clicked() {
                        // The steps are already visible; start with the safest action.
                        *action = Some(StorageAction::StartQuickScan);
                    }
                });
            });
        });
}

fn guided_steps(
    ui: &mut Ui,
    palette: &Palette,
    insights: &StorageInsight,
    action: &mut Option<StorageAction>,
) {
    widgets::card(palette).show(ui, |ui| {
        widgets::section(ui, palette, "Guided cleanup");
        ui.label(
            RichText::new("Four safe steps, in order of impact. Each one shows what it can free before you confirm.")
                .size(11.5)
                .color(palette.muted),
        );
        ui.add_space(8.0);
        let steps = [
            (
                "1",
                "Clean temporary files and caches",
                crate::format::bytes(insights.cleanup_bytes),
                "Open Quick Clean",
                StorageAction::StartQuickScan,
            ),
            (
                "2",
                "Empty the Recycle Bin",
                crate::format::bytes(insights.recycle_bytes),
                "Empty Recycle Bin",
                StorageAction::AskEmptyBin,
            ),
            (
                "3",
                "Review duplicate files",
                crate::format::bytes(insights.duplicate_bytes),
                "Open Deep Clean",
                StorageAction::Navigate(Page::DeepClean),
            ),
            (
                "4",
                "Review large files",
                crate::format::bytes(insights.large_file_bytes),
                "Open Large Files",
                StorageAction::Navigate(Page::LargeFiles),
            ),
        ];
        for (number, title, amount, button, click_action) in steps {
            let enabled = amount != "0 B";
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(24.0), Sense::hover());
                ui.painter().circle_filled(
                    rect.center(),
                    12.0,
                    palette.alpha(palette.accent, 34),
                );
                ui.painter().text(
                    rect.center(),
                    Align2::CENTER_CENTER,
                    number,
                    FontId::new(11.0, theme::heading()),
                    palette.accent,
                );
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(title)
                            .size(12.5)
                            .color(palette.text_strong),
                    );
                    ui.label(
                        RichText::new(if enabled {
                            format!("Up to {amount} recoverable")
                        } else {
                            "Run a scan to estimate".to_string()
                        })
                        .size(10.5)
                        .color(if enabled { palette.success } else { palette.muted }),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::ghost_button(ui, palette, button).clicked() {
                        let _ = match click_action {
                            StorageAction::StartQuickScan => {
                                *action = Some(StorageAction::StartQuickScan)
                            }
                            StorageAction::AskEmptyBin => {
                                *action = Some(StorageAction::AskEmptyBin)
                            }
                            StorageAction::Navigate(page) => {
                                *action = Some(StorageAction::Navigate(page))
                            }
                            _ => {}
                        };
                    }
                });
            });
            ui.add_space(5.0);
        }
    });
}

fn volume_cards(
    ui: &mut Ui,
    palette: &Palette,
    volumes: &[Volume],
    threshold: u64,
    insights: &StorageInsight,
) {
    if volumes.is_empty() {
        widgets::card(palette).show(ui, |ui| {
            widgets::empty_state(
                ui,
                palette,
                Icon::Disk,
                "No drives detected",
                "Drive information is unavailable on this system.",
            );
        });
        return;
    }
    ui.columns(volumes.len().min(2), |columns| {
        for (index, volume) in volumes.iter().take(2).enumerate() {
            let ui = &mut columns[index];
            widgets::card(palette).show(ui, |ui| {
                ui.set_width(ui.available_width());
                let low = storage::is_low_storage(volume, threshold);
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(26.0), Sense::hover());
                    icons::paint_sized(ui.painter(), rect, Icon::Disk, palette.accent, 1.6);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "{} · {}",
                                volume.mount.trim_end_matches('\\'),
                                volume.label
                            ))
                            .font(FontId::new(14.0, theme::heading()))
                            .color(palette.text_strong),
                        );
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
                ui.add_space(8.0);
                let segments = storage::stacked_segments(volume, insights.cleanup_bytes);
                let (rect, _) =
                    ui.allocate_exact_size(Vec2::new(ui.available_width(), 14.0), Sense::hover());
                ui.painter()
                    .rect_filled(rect, Rounding::same(7.0), palette.track);
                let mut x = rect.left();
                let total = volume.total.max(1) as f32;
                for (label, bytes) in segments {
                    let width = rect.width() * (bytes as f32 / total);
                    let color = match label {
                        "Reclaimable" => palette.accent,
                        "In use" => mix(palette.track, palette.muted, 0.45),
                        _ => egui::Color32::TRANSPARENT,
                    };
                    if width > 0.4 {
                        ui.painter().rect_filled(
                            egui::Rect::from_min_size(
                                egui::pos2(x, rect.top()),
                                Vec2::new(width, rect.height()),
                            ),
                            Rounding::same(3.0),
                            color,
                        );
                    }
                    x += width;
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    widgets::badge(
                        ui,
                        palette,
                        &format!(
                            "{}% used",
                            (100.0 - storage::free_percent(volume)).round() as u32
                        ),
                        if low { palette.warning } else { palette.accent },
                    );
                    if low {
                        widgets::badge(
                            ui,
                            palette,
                            "Below your free-space threshold",
                            palette.warning,
                        );
                    }
                });
            });
            if index == 1 {
                break;
            }
        }
    });
}

fn recommendations(
    ui: &mut Ui,
    palette: &Palette,
    insights: &StorageInsight,
    threshold: u64,
    action: &mut Option<StorageAction>,
) {
    widgets::card(palette).show(ui, |ui| {
        widgets::section(ui, palette, "Recommended actions");
        ui.label(
            RichText::new("Estimates come from the most recent scan on this PC.")
                .size(11.5)
                .color(palette.muted),
        );
        ui.add_space(8.0);
        let list = storage::recommendations(insights, threshold);
        if list.is_empty() {
            widgets::empty_state(
                ui,
                palette,
                Icon::Check,
                "No recommendations yet",
                "Run Quick Clean or Deep Clean so WinClean can measure what is safe to remove.",
            );
            if widgets::primary_button(ui, palette, "Scan now").clicked() {
                *action = Some(StorageAction::StartQuickScan);
            }
            return;
        }
        for recommendation in list {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::hover());
                ui.painter().rect_filled(
                    rect,
                    Rounding::same(8.0),
                    palette.alpha(palette.accent, 26),
                );
                icons::paint_sized(
                    ui.painter(),
                    rect.shrink(7.0),
                    Icon::Broom,
                    palette.accent,
                    1.6,
                );
                ui.vertical(|ui| {
                    ui.set_max_width(ui.available_width() - 240.0);
                    ui.label(
                        RichText::new(&recommendation.title)
                            .size(12.5)
                            .color(palette.text_strong),
                    );
                    ui.label(
                        RichText::new(&recommendation.detail)
                            .size(10.5)
                            .color(palette.muted),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let label = match recommendation.action {
                        RecommendationAction::OpenQuickClean => "Open Quick Clean",
                        RecommendationAction::OpenDeepClean => "Open Deep Clean",
                        RecommendationAction::OpenLargeFiles => "Open Large Files",
                        RecommendationAction::OpenRecycleBin => "Recycle Bin",
                        RecommendationAction::OpenStorageAnalyzer => "Analyze",
                    };
                    if widgets::ghost_button(ui, palette, label).clicked() {
                        *action = match recommendation.action {
                            RecommendationAction::OpenQuickClean => {
                                Some(StorageAction::StartQuickScan)
                            }
                            RecommendationAction::OpenDeepClean => {
                                Some(StorageAction::Navigate(Page::DeepClean))
                            }
                            RecommendationAction::OpenLargeFiles => {
                                Some(StorageAction::Navigate(Page::LargeFiles))
                            }
                            RecommendationAction::OpenRecycleBin => {
                                Some(StorageAction::AskEmptyBin)
                            }
                            RecommendationAction::OpenStorageAnalyzer => {
                                Some(StorageAction::Navigate(Page::Storage))
                            }
                        };
                    }
                    widgets::badge(
                        ui,
                        palette,
                        &crate::format::bytes(recommendation.bytes),
                        palette.success,
                    );
                });
            });
            ui.add_space(4.0);
        }
    });
}

fn folder_breakdown(
    ui: &mut Ui,
    palette: &Palette,
    app: &mut WinCleanApp,
    action: &mut Option<StorageAction>,
) {
    let volumes = app.volumes.clone();
    let state = &mut app.storage;
    widgets::card(palette).show(ui, |ui| {
        ui.horizontal(|ui| {
            widgets::section(ui, palette, "Disk space analyzer");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if state.loading {
                    widgets::spinner(ui, palette, 14.0);
                    ui.label(
                        RichText::new("Measuring folders…")
                            .size(11.0)
                            .color(palette.muted),
                    );
                } else if widgets::primary_button(ui, palette, "Analyze").clicked() {
                    *action = Some(StorageAction::Analyze(PathBuf::from(state.root.clone())));
                }
                egui::ComboBox::from_id_salt("storage-root")
                    .selected_text(display_path(&state.root))
                    .width(190.0)
                    .show_ui(ui, |ui| {
                        for volume in &volumes {
                            let label = format!(
                                "{} · {}",
                                volume.mount.trim_end_matches('\\'),
                                volume.label
                            );
                            if ui
                                .selectable_label(
                                    display_path(&state.root)
                                        == volume.mount.trim_end_matches('\\'),
                                    label,
                                )
                                .clicked()
                            {
                                state.root = volume.mount.clone();
                            }
                        }
                        let profile = crate::core::paths::user_profile();
                        if ui
                            .selectable_label(
                                state.root == profile.to_string_lossy(),
                                "Your user folder",
                            )
                            .clicked()
                        {
                            state.root = profile.to_string_lossy().to_string();
                        }
                    });
            });
        });
        ui.label(
            RichText::new(
                "Top-level folders by size. Nothing is deleted here — use the cleaners for that.",
            )
            .size(11.0)
            .color(palette.muted),
        );
        ui.add_space(6.0);

        if state.folders.is_empty() && !state.loading {
            widgets::empty_state(
                ui,
                palette,
                Icon::Chart,
                "Analyze a drive or folder",
                "Pick a root above and press Analyze to see which folders take the most space.",
            );
            return;
        }

        let max = state
            .folders
            .iter()
            .map(|(_, bytes)| *bytes)
            .max()
            .unwrap_or(1);
        let total: u64 = state.folders.iter().map(|(_, bytes)| *bytes).sum();
        ui.label(
            RichText::new(format!(
                "Measured {} across {} folder(s)",
                crate::format::bytes(total),
                state.folders.len()
            ))
            .size(11.0)
            .color(palette.muted),
        );
        ui.add_space(4.0);
        for (path, bytes) in state.folders.iter().take(14) {
            ui.horizontal(|ui| {
                widgets::text_cell(
                    ui,
                    palette,
                    &display_path(&path.to_string_lossy()),
                    220.0,
                    palette.text,
                    11.5,
                );
                let fraction = *bytes as f32 / max as f32;
                let (rect, _) = ui.allocate_exact_size(
                    Vec2::new((ui.available_width() - 150.0).max(60.0), 9.0),
                    Sense::hover(),
                );
                ui.painter()
                    .rect_filled(rect, Rounding::same(4.5), palette.track);
                let filled = egui::Rect::from_min_size(
                    rect.min,
                    Vec2::new(rect.width() * fraction, rect.height()),
                );
                ui.painter()
                    .rect_filled(filled, Rounding::same(4.5), palette.accent);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    widgets::muted_cell(ui, palette, &crate::format::bytes(*bytes), 70.0);
                    if widgets::icon_button(ui, palette, Icon::Folder, "Show in Explorer").clicked()
                    {
                        *action = Some(StorageAction::Reveal(path.clone()));
                    }
                });
            });
        }
    });
}

fn applications(
    ui: &mut Ui,
    palette: &Palette,
    apps: &[InstalledApp],
    loading: bool,
    action: &mut Option<StorageAction>,
) {
    widgets::card(palette).show(ui, |ui| {
        ui.horizontal(|ui| {
            widgets::section(ui, palette, "Installed applications");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::ghost_button(ui, palette, "Apps & features").clicked() {
                    *action = Some(StorageAction::OpenAppsSettings);
                }
                if widgets::icon_button(ui, palette, Icon::Refresh, "Reload").clicked() {
                    *action = Some(StorageAction::RefreshApps);
                }
            });
        });
        ui.label(
            RichText::new("Sizes are the estimates Windows records. Uninstall from Apps & features so vendors can clean up properly.")
                .size(11.0)
                .color(palette.muted),
        );
        ui.add_space(6.0);
        if loading && apps.is_empty() {
            ui.horizontal(|ui| {
                widgets::spinner(ui, palette, 15.0);
                ui.label(RichText::new("Reading installed programs…").size(11.5).color(palette.muted));
            });
            return;
        }
        if apps.is_empty() {
            widgets::empty_state(
                ui,
                palette,
                Icon::Layers,
                "No programs listed",
                "Windows did not return any uninstall entries.",
            );
            return;
        }
        let total: u64 = apps.iter().map(|app| app.size).sum();
        ui.label(
            RichText::new(format!(
                "{} programs · {} recorded",
                apps.len(),
                crate::format::bytes(total)
            ))
            .size(11.0)
            .color(palette.muted),
        );
        ui.add_space(3.0);
        for app in apps.iter().take(10) {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
                icons::paint_sized(ui.painter(), rect, Icon::Layers, palette.muted, 1.4);
                ui.vertical(|ui| {
                    ui.set_max_width(ui.available_width() - 170.0);
                    ui.label(RichText::new(&app.name).size(11.5).color(palette.text));
                    ui.label(
                        RichText::new(format!(
                            "{}{}",
                            if app.publisher.is_empty() {
                                "Unknown publisher".to_string()
                            } else {
                                app.publisher.clone()
                            },
                            if app.version.is_empty() {
                                String::new()
                            } else {
                                format!(" · {}", app.version)
                            }
                        ))
                        .size(10.0)
                        .color(palette.muted),
                    );
                });
                let size_text = if app.size > 0 {
                    crate::format::bytes(app.size)
                } else {
                    "—".to_string()
                };
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    widgets::muted_cell(ui, palette, &size_text, 80.0);
                });
            });
            ui.add_space(2.0);
        }
    });
}

fn confirm_empty_bin(
    ctx: &egui::Context,
    palette: &Palette,
    app: &mut WinCleanApp,
    action: &mut Option<StorageAction>,
) {
    if !app.storage.confirm_empty_bin {
        return;
    }
    let bytes = app.insights.recycle_bytes;
    let mut confirm = false;
    let mut close = false;
    widgets::modal(
        ctx,
        palette,
        "empty-recycle-bin",
        430.0,
        "Empty the Recycle Bin?",
        Some("Files you deleted earlier will be permanently removed."),
        |ui| {
            ui.add_space(4.0);
            widgets::key_value(ui, palette, "Space to free", &crate::format::bytes(bytes));
            ui.add_space(8.0);
            widgets::alert_banner(
                ui,
                palette,
                palette.warning,
                Icon::Trash,
                "This cannot be undone",
                "Open the Recycle Bin first if you want to restore anything.",
            );
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if widgets::danger_button(ui, palette, "Empty Recycle Bin").clicked() {
                    confirm = true;
                }
                if widgets::ghost_button(ui, palette, "Cancel").clicked() {
                    close = true;
                }
            });
        },
    );
    app.storage.confirm_empty_bin = false;
    if confirm {
        *action = Some(StorageAction::EmptyBin);
    } else if close {
        *action = Some(StorageAction::DismissBinDialog);
    }
}

fn display_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('\\');
    if trimmed.is_empty() {
        path.to_string()
    } else if trimmed.len() == 2 && trimmed.ends_with(':') {
        format!("{trimmed}\\")
    } else {
        trimmed.to_string()
    }
}
