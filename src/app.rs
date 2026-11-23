//! Application shell: state ownership, background job polling and navigation.

use crate::core::scanner::{ScanSpec, ScanSummary};
use crate::core::storage::{self, StorageInsight};
use crate::model::{
    Category, CleanReport, DefenderScanKind, DefenderStatus, Finding, StartupEntry, Volume,
};
use crate::platform::{self, ProcessSample, ProcessSampler};
use crate::settings::{AppState, Settings, ThemeMode};
use crate::theme::{self, Palette};
use crate::ui::cleaner::{CleanerMode, CleanerState};
use crate::ui::dashboard;
use crate::ui::icons::{self, Icon};
use crate::ui::jobs::{
    AppsJob, CleanSession, FolderScanJob, SecurityEvent, SecurityJob, StartupEvent, StartupJob,
    StatusJob,
};
use crate::ui::malware::SecurityState;
use crate::ui::monitor::MonitorState;
use crate::ui::settings_page::SettingsPageState;
use crate::ui::startup::StartupPageState;
use crate::ui::storage_page::StorageState;
use crate::ui::widgets;
use crate::ui::{cleaner, malware, monitor, settings_page, startup, storage_page};
use eframe::egui::{
    self, Align, Align2, Color32, FontId, Layout, Margin, Rect, RichText, Rounding, Sense, Stroke,
    Vec2,
};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const SIDEBAR_WIDTH: f32 = 236.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Page {
    Dashboard,
    QuickClean,
    DeepClean,
    LargeFiles,
    Malware,
    Storage,
    Startup,
    Monitor,
    Settings,
}

impl Page {
    pub const ALL: [Page; 9] = [
        Page::Dashboard,
        Page::QuickClean,
        Page::DeepClean,
        Page::LargeFiles,
        Page::Malware,
        Page::Storage,
        Page::Startup,
        Page::Monitor,
        Page::Settings,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Page::Dashboard => "Dashboard",
            Page::QuickClean => "Quick Clean",
            Page::DeepClean => "Deep Clean",
            Page::LargeFiles => "Large Files",
            Page::Malware => "Malware Scanner",
            Page::Storage => "Storage Analyzer",
            Page::Startup => "Startup Manager",
            Page::Monitor => "System Monitor",
            Page::Settings => "Settings",
        }
    }

    pub fn subtitle(self) -> &'static str {
        match self {
            Page::Dashboard => "System health at a glance",
            Page::QuickClean => "Safe, everyday cleanup",
            Page::DeepClean => "Every recoverable byte, reviewed by you",
            Page::LargeFiles => "Find what is really using your drive",
            Page::Malware => "Microsoft Defender scans and local heuristics",
            Page::Storage => "Where your space goes and how to get it back",
            Page::Startup => "Control what launches with Windows",
            Page::Monitor => "Live processes, CPU and memory",
            Page::Settings => "Preferences, exclusions and activity log",
        }
    }

    pub fn icon(self) -> Icon {
        match self {
            Page::Dashboard => Icon::Grid,
            Page::QuickClean => Icon::Broom,
            Page::DeepClean => Icon::Layers,
            Page::LargeFiles => Icon::File,
            Page::Malware => Icon::Shield,
            Page::Storage => Icon::Chart,
            Page::Startup => Icon::Rocket,
            Page::Monitor => Icon::Activity,
            Page::Settings => Icon::Gear,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Info,
    Success,
    Error,
}

pub struct Toast {
    pub kind: ToastKind,
    pub message: String,
    pub until: Instant,
}

pub struct WinCleanApp {
    pub settings: Settings,
    pub state: AppState,
    pub page: Page,
    pub palette: Palette,
    pub volumes: Vec<Volume>,
    pub defender: Option<DefenderStatus>,
    pub status_job: Option<StatusJob>,
    pub sampler: ProcessSampler,
    pub sample: ProcessSample,
    pub next_sample: Instant,
    pub next_volume_refresh: Instant,
    pub startup_entries: Vec<StartupEntry>,
    pub startup_job: Option<StartupJob>,
    pub startup_error: Option<String>,
    pub apps: Vec<crate::model::InstalledApp>,
    pub apps_job: Option<AppsJob>,
    pub quick: CleanerState,
    pub deep: CleanerState,
    pub large: CleanerState,
    pub security: SecurityState,
    pub storage: StorageState,
    pub monitor: MonitorState,
    pub startup_page: StartupPageState,
    pub settings_page: SettingsPageState,
    pub insights: StorageInsight,
    pub toast: Option<Toast>,
    pub nav_anim: f32,
    pub elevated: bool,
    pub os_version: String,
    pub host_label: String,
    pub last_state_save: Instant,
    pub confirm_elevate: bool,
    pub quit_requested: bool,
}

impl WinCleanApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::install_fonts(&cc.egui_ctx);
        let settings = Settings::load();
        let palette = Palette::for_mode(settings.theme);
        theme::apply(&cc.egui_ctx, &palette);
        let state = AppState::load();
        let mut sampler = ProcessSampler::new();
        let sample = sampler.sample();
        let volumes = platform::volumes();
        let elevated = platform::is_elevated();

        let quick = CleanerState::new(CleanerMode::Quick);
        let deep = CleanerState::new(CleanerMode::Deep);
        let large = CleanerState::new(CleanerMode::LargeFiles);
        let now = Instant::now();

        Self {
            settings,
            state,
            page: Page::Dashboard,
            palette,
            volumes,
            defender: None,
            status_job: Some(StatusJob::start()),
            sampler,
            sample,
            next_sample: now + Duration::from_secs(1),
            next_volume_refresh: now + Duration::from_secs(30),
            startup_entries: Vec::new(),
            startup_job: Some(StartupJob::start()),
            startup_error: None,
            apps: Vec::new(),
            apps_job: Some(AppsJob::start()),
            quick,
            deep,
            large,
            security: SecurityState::default(),
            storage: StorageState::default(),
            monitor: MonitorState::default(),
            startup_page: StartupPageState::default(),
            settings_page: SettingsPageState::default(),
            insights: StorageInsight::default(),
            toast: None,
            nav_anim: 0.0,
            elevated,
            os_version: platform::os_version(),
            host_label: format!("{}@{}", platform::user_name(), platform::computer_name()),
            last_state_save: now,
            confirm_elevate: false,
            quit_requested: false,
        }
    }

    // -----------------------------------------------------------------------
    // Simple state helpers used by every page
    // -----------------------------------------------------------------------

    pub fn navigate(&mut self, page: Page) {
        if self.page != page {
            self.page = page;
        }
    }

    pub fn toast(&mut self, kind: ToastKind, message: impl Into<String>) {
        self.toast = Some(Toast {
            kind,
            message: message.into(),
            until: Instant::now() + Duration::from_secs(7),
        });
    }

    pub fn cycle_theme(&mut self, ctx: &egui::Context) {
        self.settings.theme = match self.settings.theme {
            ThemeMode::Dark => ThemeMode::Light,
            ThemeMode::Light => ThemeMode::Dark,
        };
        self.palette = Palette::for_mode(self.settings.theme);
        theme::apply(ctx, &self.palette);
        self.persist_settings();
    }

    pub fn persist_settings(&mut self) {
        if let Err(err) = self.settings.save() {
            crate::core::logbook::sink()
                .warn("settings", format!("Could not save settings: {err}"));
        }
        self.nav_anim = self.nav_anim.max(0.0);
    }

    pub fn toggle_autostart(&mut self, ctx: &mut eframe::egui::Ui, enabled: bool) {
        match platform::set_autostart(enabled) {
            Ok(()) => {
                self.settings.start_with_windows = enabled;
                self.persist_settings();
                self.toast(
                    ToastKind::Success,
                    if enabled {
                        "WinClean will start with Windows"
                    } else {
                        "Autostart disabled"
                    },
                );
                let _ = ctx;
            }
            Err(err) => self.toast(ToastKind::Error, err),
        }
    }

    pub fn toggle_maintenance(&mut self, enabled: bool) {
        match platform::set_maintenance_task(enabled) {
            Ok(()) => {
                self.settings.weekly_maintenance = enabled;
                self.persist_settings();
                self.toast(
                    ToastKind::Success,
                    if enabled {
                        "Weekly maintenance scheduled for Sundays at 03:00"
                    } else {
                        "Scheduled maintenance removed"
                    },
                );
            }
            Err(err) => self.toast(ToastKind::Error, err),
        }
    }

    pub fn request_elevation(&mut self) {
        self.confirm_elevate = true;
    }

    pub fn perform_elevation(&mut self) {
        self.confirm_elevate = false;
        match platform::relaunch_elevated() {
            Ok(()) => {
                crate::core::logbook::sink().info(
                    "security",
                    "Restarting with administrator privileges at the user's request",
                );
                self.quit_requested = true;
            }
            Err(err) => {
                crate::core::logbook::sink().warn("security", format!("Elevation failed: {err}"));
                self.toast(ToastKind::Error, err);
            }
        }
    }

    pub fn defender_scan(&mut self, kind: DefenderScanKind) {
        self.security.job = Some(SecurityJob::start_scan(kind));
        self.security.scanning = true;
        self.security.progress = 0.0;
        self.security.stage = "Starting Microsoft Defender…".to_string();
        self.security.error = None;
    }

    pub fn refresh_threats(&mut self) {
        // Never replace a running scan job: that would cancel the scan silently.
        if self.security.scanning {
            return;
        }
        self.security.job = Some(SecurityJob::start_refresh());
        self.security.loading = true;
    }

    pub fn remove_threat(&mut self, id: i64) {
        self.security.busy = Some("Asking Microsoft Defender to remove the threat…".to_string());
        let result = platform::remove_threat(id);
        self.security.busy = None;
        match result {
            Ok(()) => {
                crate::core::logbook::sink().success(
                    "security",
                    format!("Microsoft Defender confirmed threat {id} is no longer active"),
                );
                self.toast(
                    ToastKind::Success,
                    "Microsoft Defender confirmed the threat was removed",
                );
                self.refresh_threats();
            }
            Err(err) => {
                crate::core::logbook::sink().warn(
                    "security",
                    format!("Defender did not remove threat {id}: {err}"),
                );
                self.toast(ToastKind::Error, err);
                self.refresh_threats();
            }
        }
    }

    pub fn refresh_volumes(&mut self) {
        self.volumes = platform::volumes();
    }

    pub fn load_startup(&mut self) {
        if self.startup_job.is_none() {
            self.startup_job = Some(StartupJob::start());
            self.startup_error = None;
        }
    }

    pub fn load_apps(&mut self) {
        if self.apps_job.is_none() {
            self.apps_job = Some(AppsJob::start());
        }
    }

    pub fn start_storage_scan(&mut self, root: PathBuf) {
        self.storage.scan = Some(FolderScanJob::start(root, 2));
        self.storage.loading = true;
    }

    /// Aggregates the latest scan totals into the storage insight model.
    pub fn refresh_insights(&mut self) {
        let mut insight = StorageInsight::default();
        // Prefer the deep scan when it exists: it is a superset of the quick scan,
        // so counting both would double count the same files.
        if let Some(summary) = self.deep.summary.as_ref().or(self.quick.summary.as_ref()) {
            for total in &summary.categories {
                match total.category {
                    Category::LargeFile => insight.large_file_bytes += total.bytes,
                    Category::Duplicate => insight.duplicate_bytes += total.bytes,
                    Category::RecycleBin => insight.recycle_bytes += total.bytes,
                    Category::WindowsUpdateCache => insight.update_cache_bytes += total.bytes,
                    Category::BrowserCache => {
                        insight.browser_bytes += total.bytes;
                        insight.cleanup_bytes += total.bytes;
                    }
                    _ => insight.cleanup_bytes += total.bytes,
                }
            }
        }
        self.insights = insight;
    }

    pub fn storage_insight_ready(&self) -> bool {
        self.quick.summary.is_some() || self.deep.summary.is_some()
    }

    pub fn threat_count(&self) -> usize {
        self.security
            .threats
            .iter()
            .filter(|threat| threat.source == crate::model::ThreatSource::Defender)
            .count()
            + self.security.heuristics.len()
    }

    // -----------------------------------------------------------------------
    // Job polling
    // -----------------------------------------------------------------------

    fn tick_jobs(&mut self, ctx: &egui::Context) {
        let status = self.status_job.as_ref().and_then(|job| job.poll());
        if let Some(status) = status {
            self.defender = Some(status);
            self.status_job = None;
        } else if self.status_job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }

        let startup_events = self
            .startup_job
            .as_ref()
            .map(|job| job.poll())
            .unwrap_or_default();
        if !startup_events.is_empty() {
            for event in startup_events {
                match event {
                    StartupEvent::Loaded(entries) => {
                        self.startup_entries = entries;
                        self.startup_page.loaded = true;
                        self.startup_page.loading = false;
                    }
                    StartupEvent::Failed(error) => {
                        self.startup_error = Some(error);
                        self.startup_page.loading = false;
                    }
                }
            }
            self.startup_job = None;
        } else if self.startup_job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }

        let apps = self.apps_job.as_ref().and_then(|job| job.poll());
        if let Some(apps) = apps {
            self.apps = apps;
            self.apps_job = None;
        } else if self.apps_job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }

        // Scan + clean sessions for the three cleaner pages.
        self.tick_cleaner(CleanerMode::Quick, ctx);
        self.tick_cleaner(CleanerMode::Deep, ctx);
        self.tick_cleaner(CleanerMode::LargeFiles, ctx);

        // Storage folder scan.
        let folders = self.storage.scan.as_ref().and_then(|scan| scan.poll());
        if let Some(folders) = folders {
            self.storage.folders = folders;
            self.storage.loading = false;
            self.storage.scan = None;
        } else if self.storage.scan.is_some() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }

        // Malware job events.
        let security_events = self
            .security
            .job
            .as_ref()
            .map(|job| job.poll())
            .unwrap_or_default();
        let mut finish_security_job = false;
        for event in security_events {
            match event {
                SecurityEvent::Progress(percent, stage) => {
                    self.security.progress = percent.unwrap_or(0.0) / 100.0;
                    self.security.has_percent = percent.is_some();
                    self.security.stage = stage;
                }
                SecurityEvent::Threats(result) => {
                    self.security.loading = false;
                    match result {
                        Ok(threats) => {
                            self.security.threats = threats;
                            self.security.threats_error = None;
                        }
                        Err(error) => {
                            self.security.threats_error = Some(error);
                        }
                    }
                    self.security
                        .rebuild_heuristics(&self.startup_entries, &self.sample.processes);
                    if !self.security.scanning {
                        finish_security_job = true;
                    }
                }
                SecurityEvent::ScanFinished(result) => {
                    self.security.scanning = false;
                    self.security.has_percent = false;
                    match result {
                        Ok(cancelled) => {
                            if cancelled {
                                self.security.stage = "Scan cancelled".to_string();
                                self.toast(ToastKind::Info, "Malware scan cancelled");
                            } else {
                                self.security.stage =
                                    "Verified with Microsoft Defender".to_string();
                                self.security.last_scan = Some(Instant::now());
                                self.state.last_defender_scan = Some(crate::format::date_time(
                                    std::time::SystemTime::now(),
                                    platform::local_offset_seconds(),
                                ));
                                self.state.save();
                            }
                        }
                        Err(error) => {
                            self.security.error = Some(error.clone());
                            self.security.stage = "Scan failed".to_string();
                            self.toast(ToastKind::Error, error);
                        }
                    }
                    finish_security_job = true;
                }
            }
        }
        if finish_security_job {
            self.security.job = None;
        } else if self.security.job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(120));
        }

        // Process sampling with page aware cadence.
        let now = Instant::now();
        if now >= self.next_sample {
            let interval = match self.page {
                Page::Monitor => self.settings.monitor_interval_ms.clamp(500, 5_000),
                Page::Dashboard => 1_500,
                _ => 4_000,
            };
            self.sample = self.sampler.sample();
            self.monitor.push(&self.sample);
            self.elevated = self.sample.stats.elevated;
            self.next_sample = now + Duration::from_millis(interval);
            if matches!(self.page, Page::Monitor | Page::Dashboard) {
                ctx.request_repaint_after(Duration::from_millis(interval));
            }
        }

        if now >= self.next_volume_refresh {
            self.refresh_volumes();
            self.next_volume_refresh = now + Duration::from_secs(30);
        }

        if now.duration_since(self.last_state_save) > Duration::from_secs(15) {
            self.last_state_save = now;
            self.state.save();
        }
    }

    fn tick_cleaner(&mut self, mode: CleanerMode, ctx: &egui::Context) {
        let state = match mode {
            CleanerMode::Quick => &mut self.quick,
            CleanerMode::Deep => &mut self.deep,
            CleanerMode::LargeFiles => &mut self.large,
        };
        let scan_tick = state.poll_scan();
        let mut finished_summary: Option<ScanSummary> = None;
        if let Some(tick) = scan_tick {
            for finding in tick.findings {
                state.insert(finding);
            }
            if let Some(progress) = tick.progress {
                state.progress = progress;
            }
            if let Some(stage) = tick.stage {
                state.stage = stage;
            }
            if let Some(summary) = tick.done.clone() {
                state.finish_scan(summary.clone());
                finished_summary = Some(summary);
            }
            if let Some(error) = tick.failed {
                state.error = Some(error);
                state.scan = None;
            }
            ctx.request_repaint_after(Duration::from_millis(90));
        }

        let clean_tick = state.poll_clean();
        let mut finished_report: Option<CleanReport> = None;
        if let Some(tick) = clean_tick {
            if let Some(progress) = tick.progress {
                state.clean_progress = progress;
            }
            if let Some(report) = tick.done.clone() {
                state.last_report = Some(report.clone());
                state.clean = None;
                finished_report = Some(report);
            }
            ctx.request_repaint_after(Duration::from_millis(90));
        }

        if let Some(summary) = finished_summary {
            self.on_scan_finished(mode, summary);
        }
        if let Some(report) = finished_report {
            self.apply_clean_report(mode, report);
        }
    }

    fn on_scan_finished(&mut self, mode: CleanerMode, summary: ScanSummary) {
        crate::core::logbook::sink().info(
            "scan",
            format!(
                "{} scan finished: {} items, {} recoverable in {}",
                match mode {
                    CleanerMode::Quick => "Quick",
                    CleanerMode::Deep => "Deep",
                    CleanerMode::LargeFiles => "Large file",
                },
                summary.items_found,
                crate::format::bytes(summary.bytes_found),
                crate::format::duration(summary.elapsed)
            ),
        );
        if summary.cancelled {
            self.toast(ToastKind::Info, "Scan cancelled");
        } else if summary.items_found == 0 {
            self.toast(ToastKind::Success, "Nothing to clean was found");
        } else {
            self.toast(
                ToastKind::Info,
                format!("{} recoverable", crate::format::bytes(summary.bytes_found)),
            );
        }
        self.refresh_insights();
    }

    fn apply_clean_report(&mut self, mode: CleanerMode, report: CleanReport) {
        let sink = crate::core::logbook::sink();
        sink.info(
            "clean",
            format!(
                "{}: removed {}, failed {}, skipped {}, freed {}",
                match mode {
                    CleanerMode::Quick => "Quick clean",
                    CleanerMode::Deep => "Deep clean",
                    CleanerMode::LargeFiles => "Large file cleanup",
                },
                report.removed,
                report.failed,
                report.skipped,
                crate::format::bytes(report.bytes_freed)
            ),
        );
        self.state.bytes_freed_total = self
            .state
            .bytes_freed_total
            .saturating_add(report.bytes_freed);
        self.state.last_quick_clean = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        self.state.save();
        self.refresh_volumes();
        self.refresh_insights();

        let state = match mode {
            CleanerMode::Quick => &mut self.quick,
            CleanerMode::Deep => &mut self.deep,
            CleanerMode::LargeFiles => &mut self.large,
        };
        for path in &report.removed_items {
            state.remove_path(path);
        }
        state.selected.clear();
        state.summary = None;

        if report.removed == 0 && report.failed == 0 && report.skipped > 0 {
            let reason = report
                .skipped_items
                .first()
                .map(|(_, reason)| reason.clone())
                .unwrap_or_else(|| "WinClean kept them for safety".to_string());
            self.toast(
                ToastKind::Error,
                format!(
                    "Nothing was deleted — {} item(s) kept: {reason}",
                    report.skipped
                ),
            );
        } else if report.removed == 0 && report.failed > 0 {
            let detail = report
                .errors
                .first()
                .map(|(path, error)| format!("{}: {error}", path.display()))
                .unwrap_or_else(|| "The files could not be deleted".to_string());
            let hint = if !self.elevated
                && report
                    .errors
                    .iter()
                    .any(|(_, error)| error.to_ascii_lowercase().contains("access denied"))
            {
                " — restart WinClean as administrator to clean Windows folders"
            } else {
                ""
            };
            self.toast(ToastKind::Error, format!("{detail}{hint}"));
        } else if report.failed > 0 {
            self.toast(
                ToastKind::Info,
                format!(
                    "Freed {} · {} item(s) skipped ({} in use)",
                    crate::format::bytes(report.bytes_freed),
                    report.skipped + report.failed,
                    report.failed
                ),
            );
        } else {
            self.toast(
                ToastKind::Success,
                format!(
                    "Freed {} across {} item(s)",
                    crate::format::bytes(report.bytes_freed),
                    report.removed
                ),
            );
        }
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        let palette = self.palette;
        egui::SidePanel::left("sidebar")
            .exact_width(SIDEBAR_WIDTH)
            .resizable(false)
            .frame(
                egui::Frame::none()
                    .fill(palette.sidebar)
                    .inner_margin(Margin {
                        left: 16.0,
                        right: 14.0,
                        top: 18.0,
                        bottom: 14.0,
                    }),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::hover());
                    ui.painter()
                        .rect_filled(rect, Rounding::same(8.0), palette.accent);
                    icons::paint_sized(
                        ui.painter(),
                        Rect::from_center_size(rect.center(), Vec2::splat(18.0)),
                        Icon::Shield,
                        Color32::WHITE,
                        1.9,
                    );
                    ui.add_space(2.0);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("WinClean")
                                .font(FontId::new(17.0, theme::heading()))
                                .color(palette.text_strong),
                        );
                        ui.label(
                            RichText::new("PC care & security")
                                .size(10.0)
                                .color(palette.muted),
                        );
                    });
                });
                ui.add_space(20.0);
                let selected_index = Page::ALL
                    .iter()
                    .position(|page| *page == self.page)
                    .unwrap_or(0) as f32;
                let target = selected_index * 42.0;
                let dt = ctx.input(|input| input.stable_dt).min(0.05);
                theme::approach(&mut self.nav_anim, target, dt, 14.0);
                if (self.nav_anim - target).abs() > 0.2 && !self.settings.reduce_motion {
                    ctx.request_repaint();
                }

                let list_top = ui.cursor().top();
                let mut clicked: Option<Page> = None;
                for page in Page::ALL {
                    let selected = page == self.page;
                    let (rect, response) = ui
                        .allocate_exact_size(Vec2::new(ui.available_width(), 38.0), Sense::click());
                    let hovered = response.hovered();
                    if selected {
                        ui.painter().rect_filled(
                            rect,
                            Rounding::same(9.0),
                            palette.alpha(palette.accent, 34),
                        );
                    } else if hovered {
                        ui.painter()
                            .rect_filled(rect, Rounding::same(9.0), palette.card_hover);
                    }
                    if selected {
                        let indicator = Rect::from_min_size(
                            egui::pos2(rect.left() - 12.0, rect.center().y - 11.0),
                            Vec2::new(3.0, 22.0),
                        );
                        ui.painter()
                            .rect_filled(indicator, Rounding::same(2.0), palette.accent);
                    }
                    let icon_rect = Rect::from_center_size(
                        egui::pos2(rect.left() + 22.0, rect.center().y),
                        Vec2::splat(17.0),
                    );
                    icons::paint_sized(
                        ui.painter(),
                        icon_rect,
                        page.icon(),
                        if selected {
                            palette.accent
                        } else {
                            palette.muted
                        },
                        1.6,
                    );
                    ui.painter().text(
                        egui::pos2(rect.left() + 42.0, rect.center().y),
                        Align2::LEFT_CENTER,
                        page.label(),
                        FontId::new(13.0, egui::FontFamily::Proportional),
                        if selected {
                            palette.text_strong
                        } else {
                            palette.text
                        },
                    );
                    let count = self.badge_count(page);
                    if count > 0 {
                        let label = count.to_string();
                        let size = Vec2::new(22.0, 18.0);
                        let badge = Rect::from_min_size(
                            egui::pos2(rect.right() - size.x - 6.0, rect.center().y - 9.0),
                            size,
                        );
                        ui.painter().rect_filled(
                            badge,
                            Rounding::same(9.0),
                            palette.alpha(palette.warning, 40),
                        );
                        ui.painter().text(
                            badge.center(),
                            Align2::CENTER_CENTER,
                            label,
                            FontId::new(10.0, egui::FontFamily::Proportional),
                            palette.warning,
                        );
                    }
                    if response.clicked() {
                        clicked = Some(page);
                    }
                    if hovered {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    }
                }
                let _ = list_top;
                if let Some(page) = clicked {
                    self.navigate(page);
                }

                ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!("WinClean {VERSION}"))
                            .size(10.0)
                            .color(palette.muted),
                    );
                    ui.label(
                        RichText::new(&self.host_label)
                            .size(10.0)
                            .color(palette.muted),
                    );
                    ui.add_space(6.0);
                    widgets::thin_separator(ui, &palette);
                    ui.add_space(6.0);
                    if let Some(volume) = storage::lowest_free_volume(&self.volumes) {
                        let fraction = 1.0 - storage::free_percent(volume) / 100.0;
                        ui.label(
                            RichText::new(format!(
                                "{} free on {}",
                                crate::format::bytes(volume.free),
                                volume.mount.trim_end_matches('\\')
                            ))
                            .size(10.5)
                            .color(
                                if volume.free < self.settings.low_storage_threshold_bytes() {
                                    palette.warning
                                } else {
                                    palette.muted
                                },
                            ),
                        );
                        widgets::progress_bar(
                            ui,
                            &palette,
                            fraction,
                            5.0,
                            if fraction > 0.9 {
                                palette.danger
                            } else {
                                palette.accent
                            },
                        );
                    }
                });
            });
    }

    fn badge_count(&self, page: Page) -> usize {
        match page {
            Page::Malware => self.threat_count(),
            Page::Startup => self
                .startup_entries
                .iter()
                .filter(|entry| entry.suspicious)
                .count(),
            _ => 0,
        }
    }

    fn topbar(&mut self, ctx: &egui::Context) {
        let palette = self.palette;
        egui::TopBottomPanel::top("topbar")
            .exact_height(68.0)
            .frame(
                egui::Frame::none()
                    .fill(palette.bg)
                    .inner_margin(Margin {
                        left: 26.0,
                        right: 26.0,
                        top: 16.0,
                        bottom: 8.0,
                    }),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(self.page.label())
                                .font(FontId::new(20.0, theme::heading()))
                                .color(palette.text_strong),
                        );
                        ui.label(
                            RichText::new(self.page.subtitle())
                                .size(11.5)
                                .color(palette.muted),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let theme_icon = if self.palette.dark {
                            Icon::Sparkle
                        } else {
                            Icon::Clock
                        };
                        if widgets::icon_button(ui, &palette, theme_icon, "Switch theme").clicked() {
                            self.cycle_theme(ctx);
                        }
                        if widgets::icon_button(ui, &palette, Icon::Gear, "Settings").clicked() {
                            self.navigate(Page::Settings);
                        }
                        if self.elevated {
                            widgets::badge(ui, &palette, "Administrator", palette.success);
                        } else {
                            let response = ui.add(
                                egui::Button::new(
                                    RichText::new("Elevate")
                                        .size(11.5)
                                        .color(palette.warning)
                                        .strong(),
                                )
                                .fill(palette.alpha(palette.warning, 24))
                                .stroke(Stroke::new(1.0_f32, palette.alpha(palette.warning, 90)))
                                .rounding(Rounding::same(7.0))
                                .min_size(Vec2::new(0.0, 26.0)),
                            );
                            if response
                                .on_hover_text(
                                    "Some Windows folders can only be cleaned with administrator rights",
                                )
                                .clicked()
                            {
                                self.request_elevation();
                            }
                        }
                        if let Some(cleaner) = self.active_scan_summary() {
                            widgets::badge(ui, &palette, &cleaner, palette.accent);
                        }
                    });
                });
            });
    }

    fn active_scan_summary(&self) -> Option<String> {
        for (label, state) in [
            ("Quick Clean", &self.quick),
            ("Deep Clean", &self.deep),
            ("Large Files", &self.large),
        ] {
            if state.scan.is_some() {
                return Some(format!("Scanning · {label}"));
            }
            if state.clean.is_some() {
                return Some(format!("Cleaning · {label}"));
            }
        }
        if self.security.scanning {
            return Some("Defender scan running".to_string());
        }
        None
    }

    fn draw_toast(&mut self, ctx: &egui::Context) {
        let Some(toast) = &self.toast else {
            return;
        };
        if Instant::now() > toast.until {
            self.toast = None;
            return;
        }
        let color = match toast.kind {
            ToastKind::Info => self.palette.accent,
            ToastKind::Success => self.palette.success,
            ToastKind::Error => self.palette.danger,
        };
        let icon = match toast.kind {
            ToastKind::Info => Icon::Info,
            ToastKind::Success => Icon::Check,
            ToastKind::Error => Icon::Alert,
        };
        let message = toast.message.clone();
        egui::Area::new(egui::Id::new("toast"))
            .order(egui::Order::Foreground)
            .anchor(Align2::RIGHT_BOTTOM, Vec2::new(-24.0, -22.0))
            .show(ctx, |ui| {
                egui::Frame::none()
                    .fill(self.palette.elevated)
                    .stroke(Stroke::new(1.0_f32, self.palette.alpha(color, 120)))
                    .rounding(Rounding::same(10.0))
                    .inner_margin(Margin::symmetric(14.0, 10.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let (rect, _) =
                                ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
                            icons::paint_sized(ui.painter(), rect, icon, color, 1.6);
                            ui.label(
                                RichText::new(message)
                                    .size(12.5)
                                    .color(self.palette.text_strong),
                            );
                            if widgets::icon_button(ui, &self.palette, Icon::Close, "").clicked() {
                                self.toast = None;
                            }
                        });
                    });
            });
        ctx.request_repaint_after(Duration::from_millis(400));
    }

    fn draw_elevation_dialog(&mut self, ctx: &egui::Context) {
        if !self.confirm_elevate {
            return;
        }
        let palette = self.palette;
        let mut close = false;
        let mut confirm = false;
        widgets::modal(
            ctx,
            &palette,
            "elevate-modal",
            430.0,
            "Restart with administrator rights?",
            Some("Windows will show a UAC prompt. WinClean only asks when a task needs it."),
            |ui| {
                ui.add_space(4.0);
                for line in [
                    "Cleaning Windows\\Temp, Windows Update cache and Windows logs needs administrator rights.",
                    "WinClean never disables Defender, the firewall or any security feature.",
                    "Everything else, including browser and user caches, works without elevation.",
                ] {
                    ui.horizontal(|ui| {
                        let (rect, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                        icons::paint_sized(ui.painter(), rect, Icon::Check, palette.success, 1.6);
                        ui.label(RichText::new(line).size(12.0).color(palette.text));
                    });
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if widgets::primary_button(ui, &palette, "Restart as administrator").clicked() {
                        confirm = true;
                    }
                    if widgets::ghost_button(ui, &palette, "Not now").clicked() {
                        close = true;
                    }
                });
            },
        );
        if confirm {
            self.perform_elevation();
        } else if close {
            self.confirm_elevate = false;
        }
    }

    pub fn set_theme(&mut self, ctx: &egui::Context, mode: ThemeMode) {
        self.settings.theme = mode;
        self.palette = Palette::for_mode(mode);
        theme::apply(ctx, &self.palette);
        self.persist_settings();
    }

    /// Starts a confirmed cleanup of the reviewed selection.
    pub fn begin_clean_with(
        &mut self,
        mode: CleanerMode,
        items: Vec<Finding>,
        approve_personal: bool,
    ) {
        if items.is_empty() {
            return;
        }
        let (roots, exclusions) = match mode {
            CleanerMode::Quick => (
                cleaner::cleanup_roots_for(&self.settings),
                self.settings.exclusions(),
            ),
            CleanerMode::Deep => {
                let mut roots = cleaner::cleanup_roots_for(&self.settings);
                roots.extend(cleaner::volume_roots());
                (roots, self.settings.exclusions())
            }
            CleanerMode::LargeFiles => (cleaner::volume_roots(), self.settings.exclusions()),
        };
        let options = crate::core::clean::CleanOptions {
            allowed_roots: roots,
            exclusions,
            approve_personal,
        };
        let state = match mode {
            CleanerMode::Quick => &mut self.quick,
            CleanerMode::Deep => &mut self.deep,
            CleanerMode::LargeFiles => &mut self.large,
        };
        state.clean = Some(CleanSession::start(items, options));
        state.clean_progress = crate::model::CleanProgress::default();
        state.last_report = None;
        self.toast(ToastKind::Info, "Cleaning started");
    }
}

impl eframe::App for WinCleanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.tick_jobs(ctx);
        self.sidebar(ctx);
        self.topbar(ctx);

        let palette = self.palette;
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(palette.bg).inner_margin(Margin {
                left: 26.0,
                right: 26.0,
                top: 4.0,
                bottom: 22.0,
            }))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        match self.page {
                            Page::Dashboard => dashboard::show(ui, self),
                            Page::QuickClean => cleaner::show(ui, self, CleanerMode::Quick),
                            Page::DeepClean => cleaner::show(ui, self, CleanerMode::Deep),
                            Page::LargeFiles => cleaner::show(ui, self, CleanerMode::LargeFiles),
                            Page::Malware => malware::show(ui, self),
                            Page::Storage => storage_page::show(ui, self),
                            Page::Startup => startup::show(ui, self),
                            Page::Monitor => monitor::show(ui, self),
                            Page::Settings => settings_page::show(ui, self),
                        }
                        ui.add_space(16.0);
                    });
            });

        self.draw_elevation_dialog(ctx);
        self.draw_toast(ctx);

        if self.quit_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        let size = ctx.screen_rect().size();
        if size.x > 200.0 && size.y > 200.0 {
            self.state.window_width = Some(size.x);
            self.state.window_height = Some(size.y);
        }
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        let color = self.palette.bg;
        [
            color.r() as f32 / 255.0,
            color.g() as f32 / 255.0,
            color.b() as f32 / 255.0,
            1.0,
        ]
    }
}

/// Startup scan used by the command line maintenance mode.
pub fn maintenance_scan() -> (Vec<Finding>, ScanSummary) {
    let settings = Settings::load();
    let spec = ScanSpec::new(&settings).with_cleanup(&settings);
    let handle = crate::core::scanner::spawn_scan(spec);
    let mut findings = Vec::new();
    let mut summary = ScanSummary::default();
    let deadline = Instant::now() + Duration::from_secs(900);
    while Instant::now() < deadline {
        match handle.rx.recv_timeout(Duration::from_millis(250)) {
            Ok(crate::model::ScanEvent::Findings(batch)) => findings.extend(batch),
            Ok(crate::model::ScanEvent::Done(done)) => {
                summary = done;
                break;
            }
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }
    (findings, summary)
}
