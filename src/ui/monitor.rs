//! System monitor: live CPU and memory history plus a process table.

use crate::app::{ToastKind, WinCleanApp};
use crate::platform::{self, ProcessSample};
use crate::theme::{self, Palette};
use crate::ui::icons::{self, Icon};
use crate::ui::widgets::{self};
use eframe::egui::{
    self, Align, Align2, FontId, Layout, RichText, Rounding, Sense, Stroke, Ui, Vec2,
};
use std::collections::VecDeque;
use std::path::PathBuf;

const HISTORY: usize = 90;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProcSort {
    Cpu,
    Memory,
    Name,
}

pub struct MonitorState {
    pub filter: String,
    pub sort: ProcSort,
    pub descending: bool,
    pub confirm_kill: Option<(u32, String)>,
    pub pending_kill: Option<u32>,
    pub history_cpu: VecDeque<f32>,
    pub history_mem: VecDeque<f32>,
}

impl Default for MonitorState {
    fn default() -> Self {
        Self {
            filter: String::new(),
            sort: ProcSort::Cpu,
            descending: true,
            confirm_kill: None,
            pending_kill: None,
            history_cpu: VecDeque::with_capacity(HISTORY),
            history_mem: VecDeque::with_capacity(HISTORY),
        }
    }
}

impl MonitorState {
    pub fn push(&mut self, sample: &ProcessSample) {
        self.history_cpu
            .push_back(sample.stats.cpu.clamp(0.0, 100.0));
        self.history_mem
            .push_back(sample.stats.mem_percent().clamp(0.0, 100.0));
        while self.history_cpu.len() > HISTORY {
            self.history_cpu.pop_front();
        }
        while self.history_mem.len() > HISTORY {
            self.history_mem.pop_front();
        }
    }
}

enum MonitorAction {
    Kill(u32),
    Reveal(PathBuf),
    Sort(ProcSort),
}

pub fn show(ui: &mut Ui, app: &mut WinCleanApp) {
    let palette = app.palette;
    let stats = app.sample.stats.clone();
    let processes = app.sample.processes.clone();
    let elevated = app.elevated;
    let mut action: Option<MonitorAction> = None;
    let state = &mut app.monitor;

    ui.columns(4, |columns| {
        let width = columns[0].available_width();
        widgets::stat_card(
            &mut columns[0],
            &palette,
            width,
            "CPU load",
            &format!("{:.0}%", stats.cpu),
            "All cores, live sample",
            if stats.cpu > 80.0 {
                palette.danger
            } else {
                palette.accent
            },
        );
        widgets::stat_card(
            &mut columns[1],
            &palette,
            width,
            "Memory",
            &format!(
                "{} / {}",
                crate::format::bytes(stats.mem_used),
                crate::format::bytes(stats.mem_total)
            ),
            &format!("{:.0}% in use", stats.mem_percent()),
            if stats.mem_percent() > 85.0 {
                palette.warning
            } else {
                palette.success
            },
        );
        widgets::stat_card(
            &mut columns[2],
            &palette,
            width,
            "Processes",
            &format!("{}", stats.process_count),
            &format!(
                "{} threads",
                crate::format::count(stats.thread_count as u64)
            ),
            palette.muted,
        );
        widgets::stat_card(
            &mut columns[3],
            &palette,
            width,
            "Uptime",
            &uptime(stats.uptime_secs),
            if elevated {
                "Administrator"
            } else {
                "Standard user"
            },
            palette.muted,
        );
    });

    ui.add_space(14.0);
    widgets::card(&palette).show(ui, |ui| {
        ui.horizontal(|ui| {
            widgets::section(ui, &palette, "Resource history");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new("Last 90 samples")
                        .size(10.5)
                        .color(palette.muted),
                );
            });
        });
        ui.add_space(6.0);
        sparkline(ui, &palette, &state.history_cpu, &state.history_mem);
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(9.0), Sense::hover());
            ui.painter()
                .circle_filled(rect.center(), 4.0, palette.accent);
            ui.label(RichText::new("CPU").size(10.5).color(palette.muted));
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(9.0), Sense::hover());
            ui.painter()
                .circle_filled(rect.center(), 4.0, palette.success);
            ui.label(RichText::new("Memory").size(10.5).color(palette.muted));
        });
    });

    ui.add_space(14.0);
    widgets::card(&palette).show(ui, |ui| {
        ui.horizontal(|ui| {
            widgets::section(ui, &palette, "Processes");
            ui.add_space(6.0);
            let suspicious = processes.iter().filter(|process| process.suspicious).count();
            if suspicious > 0 {
                widgets::badge(
                    ui,
                    &palette,
                    &format!("{suspicious} flagged"),
                    palette.warning,
                );
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut state.filter)
                        .hint_text("Filter processes")
                        .desired_width(190.0),
                );
            });
        });
        ui.add_space(6.0);

        let filter = state.filter.trim().to_ascii_lowercase();
        let mut list: Vec<&crate::model::ProcessInfo> = processes
            .iter()
            .filter(|process| {
                filter.is_empty()
                    || process.name.to_ascii_lowercase().contains(&filter)
                    || process
                        .exe
                        .as_ref()
                        .map(|path| path.to_string_lossy().to_ascii_lowercase().contains(&filter))
                        .unwrap_or(false)
                    || process.pid.to_string() == filter
            })
            .collect();
        match state.sort {
            ProcSort::Cpu => list.sort_by(|a, b| {
                b.cpu
                    .partial_cmp(&a.cpu)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(b.memory.cmp(&a.memory))
            }),
            ProcSort::Memory => list.sort_by(|a, b| b.memory.cmp(&a.memory)),
            ProcSort::Name => list.sort_by(|a, b| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            }),
        }
        if !state.descending {
            list.reverse();
        }

        let width = ui.available_width();
        let name_width = width * 0.30;
        let path_width = width * 0.30;
        ui.horizontal(|ui| {
            if widgets::sort_header(
                ui,
                &palette,
                "Name",
                name_width,
                state.sort == ProcSort::Name,
                state.descending,
            )
            .clicked()
            {
                action = Some(MonitorAction::Sort(ProcSort::Name));
            }
            widgets::text_cell(ui, &palette, "PID", 64.0, palette.muted, 11.0);
            if widgets::sort_header(
                ui,
                &palette,
                "CPU",
                66.0,
                state.sort == ProcSort::Cpu,
                state.descending,
            )
            .clicked()
            {
                action = Some(MonitorAction::Sort(ProcSort::Cpu));
            }
            if widgets::sort_header(
                ui,
                &palette,
                "Memory",
                80.0,
                state.sort == ProcSort::Memory,
                state.descending,
            )
            .clicked()
            {
                action = Some(MonitorAction::Sort(ProcSort::Memory));
            }
            widgets::text_cell(ui, &palette, "Image path", path_width, palette.muted, 11.0);
        });
        widgets::thin_separator(ui, &palette);

        egui::ScrollArea::vertical()
            .id_salt("process-table")
            .max_height(420.0)
            .auto_shrink([false, false])
            .show_rows(ui, 30.0, list.len(), |ui, range| {
                for row in range {
                    let process = list[row];
                    ui.horizontal(|ui| {
                        ui.set_height(30.0);
                        ui.allocate_ui_with_layout(
                            Vec2::new(name_width, 28.0),
                            Layout::left_to_right(Align::Center),
                            |ui| {
                                let color = if process.suspicious {
                                    palette.warning
                                } else {
                                    palette.text
                                };
                                let response = ui.add(
                                    egui::Label::new(
                                        RichText::new(&process.name).size(11.5).color(color),
                                    )
                                    .truncate()
                                    .selectable(false),
                                );
                                if process.suspicious {
                                    response.clone().on_hover_text(&process.reason);
                                }
                                if process.suspicious {
                                    let (rect, _) = ui.allocate_exact_size(
                                        Vec2::splat(13.0),
                                        Sense::hover(),
                                    );
                                    icons::paint_sized(
                                        ui.painter(),
                                        rect,
                                        Icon::Alert,
                                        palette.warning,
                                        1.5,
                                    );
                                }
                            },
                        );
                        widgets::muted_cell(ui, &palette, &process.pid.to_string(), 64.0);
                        let cpu_color = if process.cpu > 25.0 {
                            palette.warning
                        } else {
                            palette.text
                        };
                        widgets::text_cell(
                            ui,
                            &palette,
                            &format!("{:.1}%", process.cpu),
                            66.0,
                            cpu_color,
                            11.0,
                        );
                        widgets::text_cell(
                            ui,
                            &palette,
                            &crate::format::bytes(process.memory),
                            80.0,
                            palette.text,
                            11.0,
                        );
                        let path = process
                            .exe
                            .as_ref()
                            .map(|path| path.to_string_lossy().to_string())
                            .unwrap_or_else(|| "—".to_string());
                        ui.allocate_ui_with_layout(
                            Vec2::new(path_width, 28.0),
                            Layout::left_to_right(Align::Center),
                            |ui| {
                                let response = ui.add(
                                    egui::Label::new(
                                        RichText::new(crate::format::ellipsize(&path, 60))
                                            .size(10.0)
                                            .color(palette.muted),
                                    )
                                    .truncate()
                                    .selectable(false),
                                );
                                response.on_hover_text(&path);
                            },
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if widgets::ghost_button(ui, &palette, "End task").clicked() {
                                state.confirm_kill = Some((process.pid, process.name.clone()));
                            }
                            if widgets::icon_button(ui, &palette, Icon::Folder, "Show in Explorer")
                                .clicked()
                            {
                                if let Some(path) = &process.exe {
                                    action = Some(MonitorAction::Reveal(path.clone()));
                                }
                            }
                        });
                    });
                }
            });

        if list.is_empty() {
            widgets::empty_state(
                ui,
                &palette,
                Icon::Activity,
                "No processes match",
                "Clear the filter to see every running process.",
            );
        }

        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "Ending a process can lose unsaved work. System processes need administrator rights and may restart automatically.",
            )
            .size(10.5)
            .color(palette.muted),
        );
    });

    confirm_kill(ui.ctx(), &palette, state);
    if let Some(pid) = state.pending_kill.take() {
        action = Some(MonitorAction::Kill(pid));
    }

    match action {
        Some(MonitorAction::Sort(sort)) => {
            if state.sort == sort {
                state.descending = !state.descending;
            } else {
                state.sort = sort;
                state.descending = true;
            }
        }
        Some(MonitorAction::Kill(pid)) => match platform::kill_process(pid) {
            Ok(()) => {
                crate::core::logbook::sink().info(
                    "monitor",
                    format!("Ended process {pid} at the user's request"),
                );
                app.toast(ToastKind::Success, format!("Process {pid} ended"));
                app.sample = app.sampler.sample();
            }
            Err(err) => {
                crate::core::logbook::sink()
                    .warn("monitor", format!("Could not end process {pid}: {err}"));
                app.toast(ToastKind::Error, err);
            }
        },
        Some(MonitorAction::Reveal(path)) => {
            if let Err(err) = platform::reveal_in_explorer(&path) {
                app.toast(ToastKind::Error, err);
            }
        }
        None => {}
    }
}

fn confirm_kill(ctx: &egui::Context, palette: &Palette, state: &mut MonitorState) {
    let Some((pid, name)) = state.confirm_kill.clone() else {
        return;
    };
    let mut confirm = false;
    let mut close = false;
    widgets::modal(
        ctx,
        palette,
        "kill-process",
        420.0,
        "End this process?",
        Some("Unsaved work in the application will be lost."),
        |ui| {
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("{name} · PID {pid}"))
                    .font(FontId::new(13.5, theme::heading()))
                    .color(palette.text_strong),
            );
            ui.add_space(8.0);
            widgets::alert_banner(
                ui,
                palette,
                palette.warning,
                Icon::Alert,
                "Windows may restart it",
                "Windows services and security processes are protected and usually restart on their own.",
            );
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if widgets::danger_button(ui, palette, "End process").clicked() {
                    confirm = true;
                }
                if widgets::ghost_button(ui, palette, "Cancel").clicked() {
                    close = true;
                }
            });
        },
    );
    if confirm {
        state.confirm_kill = None;
        state.pending_kill = Some(pid);
    } else if close {
        state.confirm_kill = None;
    }
}

fn sparkline(ui: &mut Ui, palette: &Palette, cpu: &VecDeque<f32>, memory: &VecDeque<f32>) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 110.0), Sense::hover());
    ui.painter()
        .rect_filled(rect, Rounding::same(10.0), palette.track);
    for step in 1..4 {
        let y = rect.top() + rect.height() * step as f32 / 4.0;
        ui.painter().line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
            Stroke::new(1.0_f32, palette.alpha(palette.border, 120)),
        );
    }
    let draw = |values: &VecDeque<f32>, color: eframe::egui::Color32| {
        if values.len() < 2 {
            return;
        }
        let count = values.len();
        let mut previous: Option<egui::Pos2> = None;
        for (index, value) in values.iter().enumerate() {
            let x = rect.left() + rect.width() * index as f32 / (HISTORY - 1) as f32;
            let y = rect.bottom() - rect.height() * (value / 100.0).clamp(0.0, 1.0);
            let point = egui::pos2(x, y);
            if let Some(last) = previous {
                ui.painter()
                    .line_segment([last, point], Stroke::new(1.8_f32, color));
            }
            if index == count - 1 {
                ui.painter().circle_filled(point, 3.0, color);
            }
            previous = Some(point);
        }
    };
    draw(cpu, palette.accent);
    draw(memory, palette.success);
    ui.painter().text(
        rect.left_top() + Vec2::new(8.0, 6.0),
        Align2::LEFT_TOP,
        "100%",
        FontId::new(9.5, egui::FontFamily::Proportional),
        palette.muted,
    );
}

fn uptime(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes:02}m")
    } else {
        format!("{minutes}m")
    }
}
