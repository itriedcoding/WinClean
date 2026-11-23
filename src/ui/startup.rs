//! Startup manager: Run keys, Startup folder items and scheduled tasks.

use crate::app::{ToastKind, WinCleanApp};
use crate::model::{StartupEntry, StartupKind};
use crate::platform;
use crate::theme::{self};
use crate::ui::icons::{self, Icon};
use crate::ui::widgets;
use eframe::egui::{self, Align, FontId, Layout, RichText, Rounding, Sense, Ui, Vec2};
use std::path::PathBuf;

pub struct StartupPageState {
    pub filter: String,
    pub only_suspicious: bool,
    pub show_tasks: bool,
    pub loaded: bool,
    pub loading: bool,
    pub message: Option<(bool, String)>,
}

impl Default for StartupPageState {
    fn default() -> Self {
        Self {
            filter: String::new(),
            only_suspicious: false,
            show_tasks: true,
            loaded: false,
            loading: false,
            message: None,
        }
    }
}

enum StartupAction {
    Refresh,
    Toggle(StartupEntry, bool),
    Reveal(PathBuf),
    OpenTaskScheduler,
}

pub fn show(ui: &mut Ui, app: &mut WinCleanApp) {
    let palette = app.palette;
    let elevated = app.elevated;
    if !app.startup_page.loaded {
        app.startup_page.loaded = true;
        app.startup_page.loading = true;
        app.load_startup();
    }
    let entries = app.startup_entries.clone();
    let loading = app.startup_job.is_some();
    let mut action: Option<StartupAction> = None;
    let state = &mut app.startup_page;

    let enabled = entries.iter().filter(|entry| entry.enabled).count();
    let suspicious = entries.iter().filter(|entry| entry.suspicious).count();

    widgets::card(&palette).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{enabled} startup item(s) · {suspicious} flagged as suspicious"
                    ))
                    .font(FontId::new(16.0, theme::heading()))
                    .color(palette.text_strong),
                );
                ui.label(
                    RichText::new(
                        "Disabling an entry is reversible: WinClean uses the same StartupApproved registry value Windows itself uses.",
                    )
                    .size(11.5)
                    .color(palette.muted),
                );
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::ghost_button(ui, &palette, "Task Scheduler").clicked() {
                    action = Some(StartupAction::OpenTaskScheduler);
                }
                if widgets::primary_button(ui, &palette, "Refresh").clicked() {
                    action = Some(StartupAction::Refresh);
                }
                if loading {
                    widgets::spinner(ui, &palette, 14.0);
                }
                if !elevated {
                    widgets::badge(ui, &palette, "System items need admin", palette.muted);
                }
            });
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut state.filter)
                    .hint_text("Filter by name or command")
                    .desired_width(250.0),
            );
            widgets::checkbox(ui, &palette, &mut state.only_suspicious, "Only suspicious");
            widgets::checkbox(ui, &palette, &mut state.show_tasks, "Show scheduled tasks");
        });
    });

    ui.add_space(12.0);

    let filter = state.filter.trim().to_ascii_lowercase();
    let filtered: Vec<StartupEntry> = entries
        .into_iter()
        .filter(|entry| state.show_tasks || entry.kind != StartupKind::ScheduledTask)
        .filter(|entry| !state.only_suspicious || entry.suspicious)
        .filter(|entry| {
            filter.is_empty()
                || entry.name.to_ascii_lowercase().contains(&filter)
                || entry.command.to_ascii_lowercase().contains(&filter)
                || entry.scope.to_ascii_lowercase().contains(&filter)
        })
        .collect();

    widgets::card(&palette).show(ui, |ui| {
        if filtered.is_empty() {
            if loading {
                ui.horizontal(|ui| {
                    widgets::spinner(ui, &palette, 16.0);
                    ui.label(
                        RichText::new("Reading startup entries and scheduled tasks…")
                            .size(12.0)
                            .color(palette.muted),
                    );
                });
            } else {
                widgets::empty_state(
                    ui,
                    &palette,
                    Icon::Rocket,
                    "No matching startup items",
                    "Nothing launches with Windows that matches this filter.",
                );
            }
            return;
        }

        let width = ui.available_width();
        ui.horizontal(|ui| {
            ui.add_space(52.0);
            widgets::text_cell(ui, &palette, "Name", width * 0.24, palette.muted, 11.0);
            widgets::text_cell(ui, &palette, "Command", width * 0.34, palette.muted, 11.0);
            widgets::text_cell(ui, &palette, "Scope", 96.0, palette.muted, 11.0);
            widgets::text_cell(ui, &palette, "Source", 92.0, palette.muted, 11.0);
        });
        widgets::thin_separator(ui, &palette);
        ui.add_space(2.0);

        let name_width = width * 0.24;
        let command_width = width * 0.34;
        for entry in &filtered {
            let row_rect = egui::Rect::from_min_size(
                ui.cursor().min,
                Vec2::new(ui.available_width(), 42.0),
            );
            if entry.suspicious {
                ui.painter().rect_filled(
                    row_rect,
                    Rounding::same(6.0),
                    palette.alpha(palette.warning, if palette.dark { 16 } else { 10 }),
                );
            }
            let mut toggle = entry.enabled;
            let mut reveal = false;
            ui.horizontal(|ui| {
                ui.set_height(42.0);
                match entry.kind {
                    StartupKind::ScheduledTask => {
                        let (rect, response) =
                            ui.allocate_exact_size(Vec2::splat(36.0), Sense::hover());
                        icons::paint_sized(
                            ui.painter(),
                            egui::Rect::from_center_size(rect.center(), Vec2::splat(15.0)),
                            Icon::Lock,
                            palette.muted,
                            1.4,
                        );
                        response.on_hover_text(
                            "Scheduled tasks are managed in Task Scheduler and listed for information only.",
                        );
                    }
                    _ => {
                        let response = widgets::toggle_switch(
                            ui,
                            &palette,
                            entry.id.clone(),
                            &mut toggle,
                        );
                        if response.changed() {
                            action = Some(StartupAction::Toggle(entry.clone(), toggle));
                        }
                        if response.hovered() {
                            response.on_hover_text(if entry.enabled {
                                "Disable this startup entry"
                            } else {
                                "Enable this startup entry"
                            });
                        }
                    }
                }
                ui.add_space(6.0);
                ui.vertical(|ui| {
                    ui.set_width(name_width);
                    ui.label(
                        RichText::new(&entry.name)
                            .size(12.0)
                            .color(if entry.enabled {
                                palette.text_strong
                            } else {
                                palette.muted
                            }),
                    );
                    if !entry.reason.is_empty() {
                        ui.label(
                            RichText::new(crate::format::ellipsize(&entry.reason, 60))
                                .size(10.0)
                                .color(palette.warning),
                        );
                    } else {
                        ui.label(
                            RichText::new(if entry.enabled { "Enabled" } else { "Disabled" })
                                .size(10.0)
                                .color(palette.muted),
                        );
                    }
                });
                ui.allocate_ui_with_layout(
                    Vec2::new(command_width, 40.0),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        let response = ui.add(
                            egui::Label::new(
                                RichText::new(&entry.command)
                                    .size(10.5)
                                    .color(palette.muted),
                            )
                            .truncate()
                            .selectable(false),
                        );
                        response.on_hover_text(&entry.command);
                    },
                );
                widgets::text_cell(ui, &palette, &entry.scope, 96.0, palette.text, 10.5);
                widgets::text_cell(
                    ui,
                    &palette,
                    entry.kind.label(),
                    92.0,
                    palette.muted,
                    10.5,
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::icon_button(ui, &palette, Icon::Folder, "Show in Explorer")
                        .clicked()
                    {
                        reveal = true;
                    }
                    if entry.suspicious {
                        widgets::badge(ui, &palette, "Review", palette.warning);
                    }
                });
            });
            if reveal {
                action = Some(StartupAction::Reveal(PathBuf::from(&entry.command)));
            }
            widgets::thin_separator(ui, &palette);
        }
    });

    ui.add_space(12.0);
    widgets::card(&palette).show(ui, |ui| {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
            icons::paint_sized(ui.painter(), rect, Icon::Info, palette.muted, 1.5);
            ui.label(
                RichText::new(
                    "Suspicious is a local heuristic (temporary folder, impersonated Windows binary, encoded command). It is a reason to look closer, not proof of malware — run a Defender scan for a verdict.",
                )
                .size(11.0)
                .color(palette.muted),
            );
        });
        if let Some((_ok, message)) = &app.startup_page.message {
            ui.label(RichText::new(message).size(11.0).color(palette.danger));
        }
    });

    match action {
        Some(StartupAction::Refresh) => {
            app.startup_job = None;
            app.startup_page.loading = true;
            app.load_startup();
        }
        Some(StartupAction::Toggle(entry, enabled)) => {
            match platform::set_startup_enabled(&entry, enabled) {
                Ok(()) => {
                    if let Some(existing) = app
                        .startup_entries
                        .iter_mut()
                        .find(|candidate| candidate.id == entry.id)
                    {
                        existing.enabled = enabled;
                    }
                    crate::core::logbook::sink().info(
                        "startup",
                        format!(
                            "{} startup entry {}",
                            if enabled { "Enabled" } else { "Disabled" },
                            entry.name
                        ),
                    );
                    app.toast(
                        ToastKind::Success,
                        format!(
                            "{} {}",
                            entry.name,
                            if enabled { "enabled" } else { "disabled" }
                        ),
                    );
                    app.startup_page.message = None;
                }
                Err(err) => {
                    crate::core::logbook::sink()
                        .warn("startup", format!("Could not change {}: {err}", entry.name));
                    app.toast(ToastKind::Error, err);
                }
            }
        }
        Some(StartupAction::Reveal(path)) => {
            if let Err(err) = platform::reveal_in_explorer(&path) {
                if let Err(folder_err) = platform::open_folder(&path) {
                    app.toast(ToastKind::Error, format!("{err} · {folder_err}"));
                }
            }
        }
        Some(StartupAction::OpenTaskScheduler) => {
            if let Err(err) = platform::open_url("taskschd.msc") {
                app.toast(ToastKind::Error, err);
            }
        }
        None => {}
    }
}
