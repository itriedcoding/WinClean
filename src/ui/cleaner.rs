//! Quick Clean, Deep Clean and Large Files. One reviewed, category based
//! workflow shared by all three pages.

use crate::app::{Page, ToastKind, WinCleanApp};
use crate::core::guard;
use crate::core::scanner::{RecycleBinInfo, ScanSpec};
use crate::core::storage;
use crate::model::{
    Category, CleanProgress, CleanReport, Finding, Risk, ScanProgress, ScanSummary, Volume,
};
use crate::platform;
use crate::settings::Settings;
use crate::theme::{self, Palette};
use crate::ui::icons::{self, Icon};
use crate::ui::jobs::{CleanSession, ScanSession};
use crate::ui::widgets;
use eframe::egui::{
    self, Align, Color32, FontId, Layout, Rect, RichText, Rounding, Sense, Stroke, Ui, Vec2,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CleanerMode {
    Quick,
    Deep,
    LargeFiles,
}

impl CleanerMode {
    pub fn title(self) -> &'static str {
        match self {
            CleanerMode::Quick => "Quick Clean",
            CleanerMode::Deep => "Deep Clean",
            CleanerMode::LargeFiles => "Large Files",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            CleanerMode::Quick => {
                "Sweeps temporary files, browser caches and crash reports that Windows or your apps rebuild automatically. Safe to run any time."
            }
            CleanerMode::Deep => {
                "Everything Quick Clean finds, plus Windows Update leftovers, logs, duplicates and files above your size threshold. Every item is listed for review."
            }
            CleanerMode::LargeFiles => {
                "Finds files larger than your threshold across your drives. These are often personal data — nothing is deleted without your confirmation."
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FindingSort {
    Size,
    Path,
    Modified,
    Category,
}

impl FindingSort {
    fn label(self) -> &'static str {
        match self {
            FindingSort::Size => "Size",
            FindingSort::Path => "Name",
            FindingSort::Modified => "Modified",
            FindingSort::Category => "Category",
        }
    }
}

enum CleanerAction {
    Start,
    Cancel,
    Refresh,
    Clean(Vec<Finding>, bool),
    Reveal(PathBuf),
    Navigate(Page),
}

pub struct CleanerState {
    pub mode: CleanerMode,
    pub scan: Option<ScanSession>,
    pub clean: Option<CleanSession>,
    pub findings: Vec<Finding>,
    pub index: HashMap<String, usize>,
    pub selected: HashSet<String>,
    pub summary: Option<ScanSummary>,
    pub progress: ScanProgress,
    pub stage: String,
    pub error: Option<String>,
    pub clean_progress: CleanProgress,
    pub last_report: Option<CleanReport>,
    pub text_filter: String,
    pub category_filter: Option<Category>,
    pub sort: FindingSort,
    pub sort_desc: bool,
    pub include_large: bool,
    pub include_duplicates: bool,
    pub all_drives: bool,
    pub confirm_open: bool,
    pub confirm_understood: bool,
    pub approve_personal: bool,
    pub scanned_at: Option<String>,
}

impl CleanerState {
    pub fn new(mode: CleanerMode) -> Self {
        Self {
            mode,
            scan: None,
            clean: None,
            findings: Vec::new(),
            index: HashMap::new(),
            selected: HashSet::new(),
            summary: None,
            progress: ScanProgress::default(),
            stage: String::new(),
            error: None,
            clean_progress: CleanProgress::default(),
            last_report: None,
            text_filter: String::new(),
            category_filter: None,
            sort: FindingSort::Size,
            sort_desc: true,
            include_large: mode == CleanerMode::Deep,
            include_duplicates: mode == CleanerMode::Deep,
            all_drives: false,
            confirm_open: false,
            confirm_understood: false,
            approve_personal: false,
            scanned_at: None,
        }
    }

    pub fn busy(&self) -> bool {
        self.scan.is_some() || self.clean.is_some()
    }

    pub fn start_scan(&mut self, settings: &Settings) {
        self.findings.clear();
        self.index.clear();
        self.selected.clear();
        self.summary = None;
        self.last_report = None;
        self.error = None;
        self.category_filter = None;
        self.stage = "Preparing scan…".to_string();
        self.progress = ScanProgress::default();

        let recycle = platform::recycle_bin_info().unwrap_or(RecycleBinInfo::default());
        let mut spec = ScanSpec::new(settings);
        match self.mode {
            CleanerMode::Quick => {
                spec = spec.with_cleanup(settings).with_recycle_bin(recycle);
            }
            CleanerMode::Deep => {
                spec = spec.with_cleanup(settings).with_recycle_bin(recycle);
                if self.include_large {
                    spec = spec.with_large_files(settings);
                }
                if self.include_duplicates {
                    spec = spec.with_duplicates(settings, self.all_drives);
                }
            }
            CleanerMode::LargeFiles => {
                spec = spec.with_large_files(settings);
            }
        }
        self.scan = Some(ScanSession::start(spec));
    }

    pub fn cancel_scan(&mut self) {
        if let Some(scan) = &self.scan {
            scan.cancel();
        }
        if let Some(clean) = &self.clean {
            clean.cancel();
        }
    }

    pub fn poll_scan(&mut self) -> Option<crate::ui::jobs::ScanTick> {
        let scan = self.scan.as_mut()?;
        let tick = scan.poll();
        if scan.finished() {
            return Some(tick);
        }
        if tick.findings.is_empty()
            && tick.done.is_none()
            && tick.failed.is_none()
            && tick.progress.is_none()
            && tick.stage.is_none()
        {
            None
        } else {
            Some(tick)
        }
    }

    pub fn poll_clean(&mut self) -> Option<crate::ui::jobs::CleanTick> {
        let clean = self.clean.as_mut()?;
        let tick = clean.poll();
        if clean.finished() {
            return Some(tick);
        }
        if tick.progress.is_none() && tick.done.is_none() {
            None
        } else {
            Some(tick)
        }
    }

    pub fn insert(&mut self, finding: Finding) {
        let key = finding.key();
        if let Some(&index) = self.index.get(&key) {
            // A cleanup category is more useful to show than a size based hit.
            let existing = &self.findings[index];
            let better = matches!(finding.category, Category::Duplicate)
                && matches!(existing.category, Category::LargeFile);
            if better {
                self.findings[index] = finding;
            }
            return;
        }
        if self.should_preselect(&finding) {
            self.selected.insert(key.clone());
        }
        self.index.insert(key, self.findings.len());
        self.findings.push(finding);
    }

    fn should_preselect(&self, finding: &Finding) -> bool {
        match self.mode {
            CleanerMode::Quick => {
                finding.category.default_selected() && finding.category.risk() == Risk::Safe
            }
            CleanerMode::Deep => {
                finding.category.default_selected() && finding.category.risk() != Risk::Review
            }
            CleanerMode::LargeFiles => false,
        }
    }

    pub fn finish_scan(&mut self, summary: ScanSummary) {
        self.scanned_at = Some(crate::format::date_time(
            std::time::SystemTime::now(),
            platform::local_offset_seconds(),
        ));
        self.summary = Some(summary);
        self.scan = None;
        self.stage = String::new();
    }

    pub fn remove_path(&mut self, path: &Path) {
        let key = guard::normalize(path);
        if let Some(index) = self.index.remove(&key) {
            if index < self.findings.len() {
                self.findings.remove(index);
            }
            self.index.clear();
            for (position, finding) in self.findings.iter().enumerate() {
                self.index.insert(finding.key(), position);
            }
        }
        self.selected.remove(&key);
    }

    pub fn selected_findings(&self) -> Vec<Finding> {
        self.findings
            .iter()
            .filter(|finding| self.selected.contains(&finding.key()))
            .cloned()
            .collect()
    }

    pub fn selected_bytes(&self) -> u64 {
        self.findings
            .iter()
            .filter(|finding| self.selected.contains(&finding.key()))
            .map(|finding| finding.size)
            .sum()
    }

    pub fn total_bytes(&self) -> u64 {
        self.findings.iter().map(|finding| finding.size).sum()
    }

    fn category_totals(&self) -> Vec<(Category, u64, usize)> {
        let mut totals: HashMap<Category, (u64, usize)> = HashMap::new();
        for finding in &self.findings {
            let entry = totals.entry(finding.category).or_insert((0, 0));
            entry.0 += finding.size;
            entry.1 += 1;
        }
        let mut list: Vec<(Category, u64, usize)> = totals
            .into_iter()
            .map(|(category, (bytes, count))| (category, bytes, count))
            .collect();
        list.sort_by(|a, b| b.1.cmp(&a.1));
        list
    }

    fn visible(&self) -> Vec<usize> {
        let query = self.text_filter.trim().to_ascii_lowercase();
        let mut indices: Vec<usize> = self
            .findings
            .iter()
            .enumerate()
            .filter(|(_, finding)| {
                self.category_filter
                    .map(|category| category == finding.category)
                    .unwrap_or(true)
                    && (query.is_empty()
                        || finding
                            .path
                            .to_string_lossy()
                            .to_ascii_lowercase()
                            .contains(&query)
                        || finding.group.to_ascii_lowercase().contains(&query))
            })
            .map(|(index, _)| index)
            .collect();
        match self.sort {
            FindingSort::Size => {
                indices.sort_by(|a, b| self.findings[*a].size.cmp(&self.findings[*b].size))
            }
            FindingSort::Path => indices.sort_by(|a, b| {
                self.findings[*a]
                    .path
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .cmp(
                        &self.findings[*b]
                            .path
                            .to_string_lossy()
                            .to_ascii_lowercase(),
                    )
            }),
            FindingSort::Modified => {
                indices.sort_by(|a, b| self.findings[*a].modified.cmp(&self.findings[*b].modified))
            }
            FindingSort::Category => indices.sort_by(|a, b| {
                self.findings[*a]
                    .category
                    .cmp(&self.findings[*b].category)
                    .then(self.findings[*b].size.cmp(&self.findings[*a].size))
            }),
        }
        if self.sort_desc {
            indices.reverse();
        }
        indices
    }
}

pub fn show(ui: &mut Ui, app: &mut WinCleanApp, mode: CleanerMode) {
    let palette = app.palette;
    let elevated = app.elevated;
    let mut action: Option<CleanerAction> = None;

    let low_threshold = app.settings.low_storage_threshold_bytes();
    let volumes: Vec<Volume> = app.volumes.clone();
    let large_threshold = app.settings.large_file_threshold_bytes();
    let reduce_motion = app.settings.reduce_motion;

    {
        let state = match mode {
            CleanerMode::Quick => &mut app.quick,
            CleanerMode::Deep => &mut app.deep,
            CleanerMode::LargeFiles => &mut app.large,
        };

        header(ui, &palette, state, elevated, large_threshold, &mut action);
        ui.add_space(14.0);

        if let Some(volume) = storage::lowest_free_volume(&volumes) {
            if storage::is_low_storage(volume, low_threshold) {
                widgets::alert_banner(
                    ui,
                    &palette,
                    palette.warning,
                    Icon::Disk,
                    &format!(
                        "Low storage on {} — {} free",
                        volume.mount.trim_end_matches('\\'),
                        crate::format::bytes(volume.free)
                    ),
                    "Cleaning now recovers space. See Storage Analyzer for a guided walkthrough.",
                );
                ui.add_space(10.0);
                if widgets::ghost_button(ui, &palette, "Open Storage Analyzer").clicked() {
                    action = Some(CleanerAction::Navigate(Page::Storage));
                }
                ui.add_space(14.0);
            }
        }

        if state.busy() {
            progress_panel(ui, &palette, state, reduce_motion, &mut action);
            ui.add_space(14.0);
        }

        if let Some(error) = state.error.clone() {
            widgets::alert_banner(
                ui,
                &palette,
                palette.danger,
                Icon::Alert,
                "The operation could not continue",
                &error,
            );
            ui.add_space(12.0);
        }

        if let Some(report) = &state.last_report {
            report_panel(ui, &palette, report);
            ui.add_space(14.0);
        }

        summary_row(ui, &palette, state, mode, large_threshold);
        ui.add_space(14.0);

        results(ui, &palette, state, mode, &mut action);
        ui.add_space(12.0);
    }

    match action {
        Some(CleanerAction::Start) => {
            let settings = app.settings.clone();
            let state = match mode {
                CleanerMode::Quick => &mut app.quick,
                CleanerMode::Deep => &mut app.deep,
                CleanerMode::LargeFiles => &mut app.large,
            };
            if state.busy() {
                state.cancel_scan();
            } else {
                state.start_scan(&settings);
                app.toast(ToastKind::Info, "Scan started");
            }
        }
        Some(CleanerAction::Cancel) => {
            let state = match mode {
                CleanerMode::Quick => &mut app.quick,
                CleanerMode::Deep => &mut app.deep,
                CleanerMode::LargeFiles => &mut app.large,
            };
            state.cancel_scan();
        }
        Some(CleanerAction::Refresh) => {
            let settings = app.settings.clone();
            let state = match mode {
                CleanerMode::Quick => &mut app.quick,
                CleanerMode::Deep => &mut app.deep,
                CleanerMode::LargeFiles => &mut app.large,
            };
            state.start_scan(&settings);
        }
        Some(CleanerAction::Clean(items, approve)) => {
            app.begin_clean_with(mode, items, approve);
        }
        Some(CleanerAction::Reveal(path)) => {
            if let Err(err) = platform::reveal_in_explorer(&path) {
                app.toast(ToastKind::Error, err);
            }
        }
        Some(CleanerAction::Navigate(page)) => app.navigate(page),
        None => {}
    }
}

fn header(
    ui: &mut Ui,
    palette: &Palette,
    state: &mut CleanerState,
    elevated: bool,
    large_threshold: u64,
    action: &mut Option<CleanerAction>,
) {
    widgets::card(palette).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_max_width(ui.available_width() - 210.0);
                ui.label(
                    RichText::new(state.mode.title())
                        .font(FontId::new(19.0, theme::heading()))
                        .color(palette.text_strong),
                );
                ui.label(
                    RichText::new(state.mode.description())
                        .size(12.0)
                        .color(palette.muted),
                );
                if state.mode == CleanerMode::LargeFiles {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!(
                            "Threshold: files larger than {} · change it in Settings",
                            crate::format::bytes(large_threshold)
                        ))
                        .size(11.5)
                        .color(palette.accent),
                    );
                }
                if state.mode != CleanerMode::Quick && !elevated {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(
                            "Some Windows folders need administrator rights (see the Elevate button).",
                        )
                        .size(11.0)
                        .color(palette.warning),
                    );
                }
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if state.busy() {
                    if widgets::ghost_button(ui, palette, "Cancel").clicked() {
                        *action = Some(CleanerAction::Cancel);
                    }
                } else {
                    let label = if state.findings.is_empty() {
                        "Start scan"
                    } else {
                        "Scan again"
                    };
                    if widgets::primary_button(ui, palette, label).clicked() {
                        *action = Some(CleanerAction::Start);
                    }
                }
            });
        });

        if state.mode == CleanerMode::Deep {
            ui.add_space(10.0);
            widgets::thin_separator(ui, palette);
            ui.add_space(10.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Include:").size(11.5).color(palette.muted));
                widgets::checkbox(ui, palette, &mut state.include_large, "Large files");
                widgets::checkbox(ui, palette, &mut state.include_duplicates, "Duplicate files");
                if state.include_duplicates {
                    widgets::checkbox(ui, palette, &mut state.all_drives, "Compare all drives");
                }
                if widgets::badge(ui, palette, "Review required", palette.accent).clicked() {
                    // Badges are informational; nothing to do.
                }
            });
        }
    });
}

fn progress_panel(
    ui: &mut Ui,
    palette: &Palette,
    state: &CleanerState,
    reduce_motion: bool,
    action: &mut Option<CleanerAction>,
) {
    widgets::card(palette).show(ui, |ui| {
        if let Some(clean) = &state.clean {
            let progress = &state.clean_progress;
            let fraction = if progress.total > 0 {
                progress.done as f32 / progress.total as f32
            } else {
                0.0
            };
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Deleting selected items")
                        .font(FontId::new(14.5, theme::heading()))
                        .color(palette.text_strong),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("{} of {}", progress.done, progress.total))
                            .size(11.5)
                            .color(palette.muted),
                    );
                });
            });
            ui.add_space(6.0);
            if reduce_motion {
                widgets::progress_bar(ui, palette, fraction, 6.0, palette.accent);
            } else {
                widgets::progress_bar(ui, palette, fraction, 6.0, palette.accent);
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{} freed so far",
                        crate::format::bytes(progress.bytes_freed)
                    ))
                    .size(11.5)
                    .color(palette.success),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(crate::format::ellipsize(&progress.current, 70))
                            .size(10.5)
                            .color(palette.muted),
                    );
                });
            });
            let _ = clean;
        } else {
            let progress = &state.progress;
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if state.stage.is_empty() {
                        "Scanning"
                    } else {
                        state.stage.as_str()
                    })
                    .font(FontId::new(14.5, theme::heading()))
                    .color(palette.text_strong),
                );
                ui.add_space(6.0);
                widgets::spinner(ui, palette, 14.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} files · {} folders",
                            crate::format::count(progress.files),
                            crate::format::count(progress.dirs)
                        ))
                        .size(11.5)
                        .color(palette.muted),
                    );
                });
            });
            ui.add_space(6.0);
            if let Some(percent) = progress.percent {
                widgets::progress_bar(ui, palette, percent / 100.0, 6.0, palette.accent);
            } else {
                widgets::indeterminate_bar(ui, palette, 6.0);
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{} recoverable so far",
                        crate::format::bytes(progress.bytes_found)
                    ))
                    .size(11.5)
                    .color(palette.success),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(crate::format::ellipsize(&progress.current, 64))
                            .size(10.5)
                            .color(palette.muted),
                    );
                    if widgets::icon_button(ui, palette, Icon::Stop, "Cancel scan").clicked() {
                        *action = Some(CleanerAction::Cancel);
                    }
                });
            });
        }
    });
}

fn report_panel(ui: &mut Ui, palette: &Palette, report: &CleanReport) {
    widgets::card(palette).show(ui, |ui| {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
            icons::paint_sized(
                ui.painter(),
                rect,
                if report.failed == 0 && report.skipped == 0 {
                    Icon::Check
                } else {
                    Icon::Info
                },
                if report.failed == 0 && report.skipped == 0 {
                    palette.success
                } else {
                    palette.warning
                },
                1.7,
            );
            ui.label(
                RichText::new(format!(
                    "Freed {} · {} removed · {} skipped · {} failed",
                    crate::format::bytes(report.bytes_freed),
                    report.removed,
                    report.skipped,
                    report.failed
                ))
                .size(12.5)
                .color(palette.text_strong),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(crate::format::duration(report.elapsed))
                        .size(11.0)
                        .color(palette.muted),
                );
            });
        });
        if !report.errors.is_empty() {
            ui.add_space(4.0);
            for (path, error) in report.errors.iter().take(3) {
                ui.label(
                    RichText::new(format!(
                        "{} — {}",
                        crate::format::ellipsize(&path.to_string_lossy(), 60),
                        error
                    ))
                    .size(11.0)
                    .color(palette.danger),
                );
            }
        }
        if !report.skipped_items.is_empty() {
            ui.label(
                RichText::new(format!(
                    "{} item(s) kept for safety: {}",
                    report.skipped_items.len(),
                    report.skipped_items[0].1
                ))
                .size(11.0)
                .color(palette.muted),
            );
        }
    });
}

fn summary_row(
    ui: &mut Ui,
    palette: &Palette,
    state: &CleanerState,
    mode: CleanerMode,
    large_threshold: u64,
) {
    let columns = match mode {
        CleanerMode::LargeFiles => 3,
        _ => 4,
    };
    ui.columns(columns, |columns| {
        let width = columns[0].available_width();
        let total = state.total_bytes();
        let items = state.findings.len();
        widgets::stat_card(
            &mut columns[0],
            palette,
            width,
            if mode == CleanerMode::LargeFiles {
                "Large files found"
            } else {
                "Recoverable"
            },
            &crate::format::bytes(total),
            &format!("{} item(s) reviewed", crate::format::count(items as u64)),
            palette.success,
        );
        if columns.len() > 1 {
            widgets::stat_card(
                &mut columns[1],
                palette,
                width,
                "Selected",
                &crate::format::bytes(state.selected_bytes()),
                &format!("{} item(s) selected", state.selected.len()),
                palette.accent,
            );
        }
        if columns.len() > 2 {
            let scans = state
                .summary
                .as_ref()
                .map(|summary| {
                    format!(
                        "{} files in {}",
                        crate::format::count(summary.files_scanned),
                        crate::format::duration(summary.elapsed)
                    )
                })
                .unwrap_or_else(|| "No scan yet".to_string());
            widgets::stat_card(
                &mut columns[2],
                palette,
                width,
                "Scan coverage",
                &state
                    .summary
                    .as_ref()
                    .map(|summary| crate::format::count(summary.dirs_scanned))
                    .unwrap_or_else(|| "0".to_string()),
                &scans,
                palette.muted,
            );
        }
        if columns.len() > 3 {
            widgets::stat_card(
                &mut columns[3],
                palette,
                width,
                "Largest category",
                &state
                    .summary
                    .as_ref()
                    .and_then(|summary| summary.categories.first())
                    .map(|total| total.category.short())
                    .unwrap_or(if mode == CleanerMode::LargeFiles {
                        "Large files"
                    } else {
                        "—"
                    }),
                &format!("Threshold {}", crate::format::bytes(large_threshold)),
                palette.warning,
            );
        }
    });
}

fn results(
    ui: &mut Ui,
    palette: &Palette,
    state: &mut CleanerState,
    mode: CleanerMode,
    action: &mut Option<CleanerAction>,
) {
    widgets::card(palette).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Review results")
                    .font(FontId::new(16.0, theme::heading()))
                    .color(palette.text_strong),
            );
            ui.add_space(6.0);
            if !state.findings.is_empty() {
                widgets::badge(
                    ui,
                    palette,
                    &format!("{} items", crate::format::count(state.findings.len() as u64)),
                    palette.muted,
                );
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::icon_button(ui, palette, Icon::Refresh, "Rescan").clicked() {
                    *action = Some(CleanerAction::Refresh);
                }
                if widgets::icon_button(ui, palette, Icon::Folder, "Open Settings").clicked() {
                    *action = Some(CleanerAction::Navigate(Page::Settings));
                }
            });
        });

        if state.findings.is_empty() {
            if state.scan.is_some() {
                widgets::empty_state(
                    ui,
                    palette,
                    Icon::Search,
                    "Scanning your PC…",
                    "Items appear here as soon as they are found.",
                );
            } else if state.summary.is_some() {
                widgets::empty_state(
                    ui,
                    palette,
                    Icon::Check,
                    "Nothing to clean",
                    "No matching files were found. Your storage is already tidy.",
                );
            } else if mode == CleanerMode::LargeFiles {
                widgets::empty_state(
                    ui,
                    palette,
                    Icon::File,
                    "No large files scanned yet",
                    "Start a scan to list every file above your size threshold with its folder and date.",
                );
            } else {
                widgets::empty_state(
                    ui,
                    palette,
                    Icon::Broom,
                    "Ready when you are",
                    "Start a scan to see exactly what can be removed before anything is deleted.",
                );
            }
            return;
        }

        ui.add_space(8.0);
        category_chips(ui, palette, state);
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut state.text_filter)
                    .hint_text("Filter by name or folder")
                    .desired_width(210.0),
            );
            egui::ComboBox::from_id_salt("cleaner-sort")
                .selected_text(format!("Sort: {}", state.sort.label()))
                .width(140.0)
                .show_ui(ui, |ui| {
                    for option in [
                        FindingSort::Size,
                        FindingSort::Path,
                        FindingSort::Modified,
                        FindingSort::Category,
                    ] {
                        if ui
                            .selectable_label(state.sort == option, option.label())
                            .clicked()
                        {
                            state.sort = option;
                        }
                    }
                });
            if widgets::ghost_button(ui, palette, "Direction").clicked() {
                state.sort_desc = !state.sort_desc;
            }
            let visible = state.visible();
            let all_selected = !visible.is_empty()
                && visible
                    .iter()
                    .all(|index| state.selected.contains(&state.findings[*index].key()));
            let mut toggle_all = all_selected;
            if widgets::checkbox(ui, palette, &mut toggle_all, "Select all shown").clicked() {
                for index in &visible {
                    let key = state.findings[*index].key();
                    if toggle_all {
                        state.selected.insert(key);
                    } else {
                        state.selected.remove(&key);
                    }
                }
            }
        });

        ui.add_space(6.0);
        table(ui, palette, state, mode, action);

        ui.add_space(10.0);
        widgets::thin_separator(ui, palette);
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} selected · {}",
                    state.selected.len(),
                    crate::format::bytes(state.selected_bytes())
                ))
                .size(12.5)
                .color(palette.text_strong),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let enabled = !state.selected.is_empty() && state.clean.is_none();
                if enabled {
                    if widgets::danger_button(ui, palette, "Delete selected…").clicked() {
                        state.confirm_open = true;
                        state.confirm_understood = false;
                    }
                } else {
                    ui.add_enabled(false, egui::Button::new("Delete selected…"));
                }
                if !state.selected.is_empty() && widgets::ghost_button(ui, palette, "Clear").clicked()
                {
                    state.selected.clear();
                }
                ui.label(
                    RichText::new("Only checked items are deleted. Personal folders need extra approval.")
                        .size(10.5)
                        .color(palette.muted),
                );
            });
        });
    });

    confirm_dialog(ui.ctx(), palette, state, action);
}

fn category_chips(ui: &mut Ui, palette: &Palette, state: &mut CleanerState) {
    let totals = state.category_totals();
    egui::ScrollArea::horizontal()
        .id_salt("category-chips")
        .max_height(36.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let total: u64 = totals.iter().map(|(_, bytes, _)| *bytes).sum();
                let active = state.category_filter.is_none();
                if chip(ui, palette, "All", Some(total), active) {
                    state.category_filter = None;
                }
                for (category, bytes, _count) in totals {
                    let selected = state.category_filter == Some(category);
                    if chip(ui, palette, category.short(), Some(bytes), selected) {
                        state.category_filter = if selected { None } else { Some(category) };
                    }
                }
            });
        });
}

fn chip(ui: &mut Ui, palette: &Palette, label: &str, bytes: Option<u64>, selected: bool) -> bool {
    let text = match bytes {
        Some(bytes) => format!("{label} · {}", crate::format::bytes_short(bytes)),
        None => label.to_string(),
    };
    let button = egui::Button::new(RichText::new(text).size(11.5).color(if selected {
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
    .rounding(Rounding::same(16.0));
    ui.add(button).clicked()
}

fn table(
    ui: &mut Ui,
    palette: &Palette,
    state: &mut CleanerState,
    mode: CleanerMode,
    action: &mut Option<CleanerAction>,
) {
    let visible = state.visible();
    let available = ui.available_width();
    let checkbox_width = 26.0;
    let category_width = 108.0;
    let size_width = 78.0;
    let modified_width = 104.0;
    let reveal_width = 26.0;
    let name_width = ((available
        - checkbox_width
        - category_width
        - size_width
        - modified_width
        - reveal_width
        - 40.0)
        * 0.42)
        .max(120.0);
    let location_width = (available
        - checkbox_width
        - category_width
        - size_width
        - modified_width
        - reveal_width
        - name_width
        - 40.0)
        .max(90.0);

    ui.horizontal(|ui| {
        ui.add_space(checkbox_width);
        widgets::sort_header(
            ui,
            palette,
            "Name",
            name_width,
            state.sort == FindingSort::Path,
            state.sort_desc,
        );
        widgets::sort_header(
            ui,
            palette,
            "Category",
            category_width,
            state.sort == FindingSort::Category,
            state.sort_desc,
        );
        widgets::sort_header(
            ui,
            palette,
            "Size",
            size_width,
            state.sort == FindingSort::Size,
            state.sort_desc,
        );
        widgets::sort_header(
            ui,
            palette,
            "Modified",
            modified_width,
            state.sort == FindingSort::Modified,
            state.sort_desc,
        );
        widgets::text_cell(ui, palette, "Folder", location_width, palette.muted, 11.0);
        ui.add_space(reveal_width);
    });
    widgets::thin_separator(ui, palette);

    let row_height = 32.0;
    egui::ScrollArea::vertical()
        .id_salt("cleaner-table")
        .max_height(380.0)
        .auto_shrink([false, false])
        .show_rows(ui, row_height, visible.len(), |ui, range| {
            for row in range {
                let index = visible[row];
                let finding = &state.findings[index];
                let key = finding.key();
                let mut checked = state.selected.contains(&key);
                let row_rect = Rect::from_min_size(
                    ui.cursor().min,
                    Vec2::new(ui.available_width(), row_height),
                );
                if checked {
                    ui.painter().rect_filled(
                        row_rect,
                        Rounding::same(5.0),
                        palette.alpha(palette.accent, if palette.dark { 22 } else { 16 }),
                    );
                }
                let mut checkbox_clicked = false;
                let mut reveal = false;
                let inner = ui.horizontal(|ui| {
                    ui.set_height(row_height);
                    let (rect, response) =
                        ui.allocate_exact_size(Vec2::splat(18.0), Sense::click());
                    ui.painter().rect_filled(
                        rect,
                        Rounding::same(5.0),
                        if checked {
                            palette.accent
                        } else {
                            Color32::TRANSPARENT
                        },
                    );
                    ui.painter().rect_stroke(
                        rect,
                        Rounding::same(5.0),
                        Stroke::new(
                            1.0_f32,
                            if checked {
                                palette.accent
                            } else {
                                palette.border_strong
                            },
                        ),
                    );
                    if checked {
                        icons::paint_sized(
                            ui.painter(),
                            Rect::from_center_size(rect.center(), Vec2::splat(11.0)),
                            Icon::Check,
                            palette.on_accent,
                            1.8,
                        );
                    }
                    if response.clicked() {
                        checkbox_clicked = true;
                    }
                    ui.add_space(6.0);

                    let name_color = palette.text_strong;
                    ui.allocate_ui_with_layout(
                        Vec2::new(name_width, row_height),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            let response = ui.add(
                                egui::Label::new(
                                    RichText::new(finding.name()).size(12.0).color(name_color),
                                )
                                .truncate()
                                .selectable(false),
                            );
                            if response.hovered() {
                                response.on_hover_text(finding.path.to_string_lossy().to_string());
                            }
                        },
                    );

                    let risk_color = palette.risk_color(finding.category.risk());
                    ui.allocate_ui_with_layout(
                        Vec2::new(category_width, row_height),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            widgets::badge(ui, palette, finding.category.short(), risk_color);
                        },
                    );

                    widgets::muted_cell(
                        ui,
                        palette,
                        &crate::format::bytes(finding.size),
                        size_width,
                    );
                    let modified = finding
                        .modified
                        .map(|time| {
                            crate::format::date_time(time, platform::local_offset_seconds())
                        })
                        .unwrap_or_else(|| "—".to_string());
                    widgets::muted_cell(ui, palette, &modified, modified_width);
                    widgets::text_cell(
                        ui,
                        palette,
                        &finding.location(),
                        location_width,
                        palette.muted,
                        11.0,
                    );
                    if widgets::icon_button(ui, palette, Icon::Folder, "Show in Explorer").clicked()
                    {
                        reveal = true;
                    }
                });

                let row_response = inner.response.interact(Sense::click());
                if row_response.clicked() && !checkbox_clicked && !reveal {
                    checked = !checked;
                    checkbox_clicked = true;
                }
                if checkbox_clicked {
                    if checked {
                        state.selected.insert(key);
                    } else {
                        state.selected.remove(&key);
                    }
                }
                if reveal {
                    *action = Some(CleanerAction::Reveal(finding.path.clone()));
                }
                if row_response.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
            }
        });

    if visible.is_empty() {
        widgets::empty_state(
            ui,
            palette,
            Icon::Search,
            "No items match the filter",
            "Clear the search box or pick another category.",
        );
    }
    let _ = mode;
}

fn confirm_dialog(
    ctx: &egui::Context,
    palette: &Palette,
    state: &mut CleanerState,
    action: &mut Option<CleanerAction>,
) {
    if !state.confirm_open {
        return;
    }
    let items: Vec<Finding> = state.selected_findings();
    let personal: Vec<&Finding> = items
        .iter()
        .filter(|finding| guard::is_personal(&finding.path))
        .collect();
    let personal_count = personal.len();
    let has_personal = personal_count > 0;
    let total: u64 = items.iter().map(|finding| finding.size).sum();
    let review_each = state.mode == CleanerMode::LargeFiles || state.mode == CleanerMode::Deep;
    let mut close = false;
    let mut confirm = false;
    let mut understood = state.confirm_understood;
    let mut approve = state.approve_personal;

    widgets::modal(
        ctx,
        palette,
        "clean-confirm",
        480.0,
        "Delete the selected items?",
        Some("Files are removed permanently. Review the list before confirming."),
        |ui| {
            ui.add_space(6.0);
            widgets::key_value(ui, palette, "Items", &format!("{}", items.len()));
            widgets::key_value(ui, palette, "Space to free", &crate::format::bytes(total));
            if review_each {
                widgets::key_value(
                    ui,
                    palette,
                    "Largest item",
                    &items
                        .iter()
                        .max_by_key(|finding| finding.size)
                        .map(|finding| {
                            format!(
                                "{} ({})",
                                finding.name(),
                                crate::format::bytes(finding.size)
                            )
                        })
                        .unwrap_or_else(|| "—".to_string()),
                );
            }
            ui.add_space(8.0);

            if has_personal {
                widgets::alert_banner(
                    ui,
                    palette,
                    palette.warning,
                    Icon::Info,
                    &format!("{personal_count} personal file(s) included"),
                    "These items live in Documents, Desktop, Downloads or a similar folder. WinClean keeps them unless you explicitly approve.",
                );
                ui.add_space(6.0);
                widgets::checkbox(
                    ui,
                    palette,
                    &mut approve,
                    "I have reviewed these personal files and want them deleted",
                );
                ui.add_space(4.0);
            }

            widgets::alert_banner(
                ui,
                palette,
                palette.accent,
                Icon::Shield,
                "Safety checks stay on",
                "Windows system files, excluded paths and items outside the scanned locations are never deleted.",
            );
            ui.add_space(8.0);
            widgets::checkbox(
                ui,
                palette,
                &mut understood,
                "I understand these files will be permanently deleted",
            );
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let personal_ok = !has_personal || approve;
                if understood && personal_ok {
                    if widgets::danger_button(ui, palette, "Delete now").clicked() {
                        confirm = true;
                    }
                } else {
                    ui.add_enabled(false, egui::Button::new("Delete now"));
                }
                if widgets::ghost_button(ui, palette, "Keep files").clicked() {
                    close = true;
                }
            });
        },
    );

    state.confirm_understood = understood;
    state.approve_personal = approve;

    if confirm {
        state.confirm_open = false;
        state.confirm_understood = false;
        *action = Some(CleanerAction::Clean(items, approve));
    } else if close {
        state.confirm_open = false;
        state.confirm_understood = false;
    }
}

/// Root folders accepted for cleanup deletions.
pub fn cleanup_roots_for(settings: &Settings) -> Vec<PathBuf> {
    crate::core::clean::cleanup_allowed_roots(settings)
}

pub fn volume_roots() -> Vec<PathBuf> {
    crate::core::clean::volume_roots()
}
