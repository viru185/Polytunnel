//! Activity: a summary of the last attempt with the report for IT and the trace switch, then
//! the log (newest first), filtered to problems if wanted.

use std::time::Instant;

use eframe::egui::{self, Align2, Rect, Sense, Ui, pos2, vec2};
use polytunnel_core::ipc::Status;

use super::body;
use crate::connect;
use crate::gui::icons::{self, Icon};
use crate::gui::widgets::{self, Kind as Button};
use crate::gui::{App, Level, theme};

enum Do {
    Clear,
    Undo,
    Report,
    Trace(bool),
}

impl App {
    pub(in crate::gui) fn activity_page(&mut self, ui: &mut Ui) {
        let mut todo = Vec::new();
        let has_log = !self.log.is_empty();
        if widgets::page_header(ui, "Activity", "", |ui| {
            ui.add_enabled_ui(has_log, |ui| {
                if widgets::icon_button(ui, Icon::Trash, "Clear the list", 36.0, None).clicked() {
                    todo.push(Do::Clear);
                }
            });
        }) {
            self.back();
            return;
        }
        let p = widgets::pal(ui);
        // The summary: the last attempt, else the connection now.
        let (icon, ink, title, time) = match (&self.status, &self.last_attempt) {
            (Some(Err(_)), _) => (
                Icon::Error,
                p.red_text,
                "Service not running".to_string(),
                String::new(),
            ),
            (_, Some(a)) if a.result.is_err() => (
                Icon::Error,
                p.red_text,
                "Last attempt failed".to_string(),
                a.time.clone(),
            ),
            (Some(Ok(Status::Failed { .. })), _) => (
                Icon::Error,
                p.red_text,
                "Last attempt failed".into(),
                String::new(),
            ),
            (
                Some(Ok(Status::Connected {
                    notice: Some(_), ..
                })),
                _,
            ) => (
                Icon::Warning,
                p.amber_text,
                "Connected, limited".into(),
                String::new(),
            ),
            (Some(Ok(Status::Reconnecting { .. })), _) => (
                Icon::Warning,
                p.amber_text,
                "Reconnecting".into(),
                String::new(),
            ),
            (Some(Ok(Status::Connected { .. })), _) => {
                (Icon::Ok, p.green_text, "Connected".into(), String::new())
            }
            (Some(Ok(_)), Some(a)) => (
                Icon::Ok,
                p.green_text,
                "Last attempt connected".into(),
                a.time.clone(),
            ),
            (Some(Ok(_)), None) => (Icon::Dot, p.text3, "No attempts yet".into(), String::new()),
            (None, _) => (Icon::Dot, p.text3, "Checking".into(), String::new()),
        };
        let mut rows: Vec<(String, String)> = Vec::new();
        if let Some(a) = &self.last_attempt {
            rows.push(("Profile".into(), a.profile.clone()));
            if let Err(e) = &a.result {
                rows.push((
                    "Reason".into(),
                    e.split(" (").next().unwrap_or(e).to_string(),
                ));
            }
        }
        let service = match &self.status {
            Some(Ok(_)) => "Running".to_string(),
            Some(Err(e)) => connect::service_problem(e),
            None => "Checking".into(),
        };
        let ks_word = match &self.killswitch {
            Some((_, _, Some(_))) => "problem",
            Some((s, _, _)) if s.mode == polytunnel_core::ipc::KillSwitchMode::Off => "off",
            Some((s, _, _)) if s.mode == polytunnel_core::ipc::KillSwitchMode::Always => "lockdown",
            Some((_, true, _)) => "on",
            Some(_) => "ready",
            None => "unknown",
        };
        rows.push((
            "Service · kill switch".into(),
            format!("{service} · {ks_word}"),
        ));
        let mut trace = self.trace;
        let trace_env = std::env::var_os("POLYTUNNEL_TRACE").is_some();
        let undo = self.cleared.is_some();
        let lines: Vec<(String, Level, String)> = self
            .log
            .iter()
            .rev()
            .filter(|l| !self.problems_only || matches!(l.level, Level::Warning | Level::Problem))
            .map(|l| (l.time.clone(), l.level, l.text.clone()))
            .collect();
        let mut problems_only = self.problems_only;
        body(ui, "activity", |ui| {
            ui.add_space(4.0);
            widgets::card(ui, false, |ui| {
                let (rect, _) = widgets::row_frame(ui, 48.0, true, false, Sense::hover());
                icons::paint(
                    ui.painter(),
                    Rect::from_min_size(
                        pos2(rect.left() + 16.0, rect.center().y - 8.0),
                        vec2(16.0, 16.0),
                    ),
                    icon,
                    ink,
                );
                ui.painter().text(
                    pos2(rect.left() + 40.0, rect.center().y),
                    Align2::LEFT_CENTER,
                    &title,
                    theme::semibold(14.0),
                    p.text,
                );
                if !time.is_empty() {
                    ui.painter().text(
                        pos2(rect.right() - 16.0, rect.center().y),
                        Align2::RIGHT_CENTER,
                        &time,
                        theme::regular(14.0),
                        p.text2,
                    );
                }
                for (k, v) in &rows {
                    widgets::value_row(ui, k, v, None);
                }
                if widgets::toggle_row(
                    ui,
                    "Record a troubleshooting trace",
                    Some(if trace_env {
                        "POLYTUNNEL_TRACE is set, so traces stay on"
                    } else {
                        "Passwords, codes and cookies are removed"
                    }),
                    !trace_env,
                    &mut trace,
                    false,
                    false,
                ) {
                    todo.push(Do::Trace(trace));
                }
                egui::Frame::NONE
                    .inner_margin(egui::Margin::same(16))
                    .show(ui, |ui| {
                        let r = ui.max_rect();
                        ui.painter().hline(
                            (r.left() - 16.0)..=(r.right() + 16.0),
                            r.top() - 16.0 + 0.5,
                            egui::Stroke::new(1.0, p.line),
                        );
                        if widgets::button_block(
                            ui,
                            Button::Secondary,
                            "Save report for IT",
                            Some(Icon::Download),
                        )
                        .clicked()
                        {
                            todo.push(Do::Report);
                        }
                        ui.add_space(4.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new("Saves a text file in Downloads and shows it.")
                                    .size(12.0)
                                    .color(p.text3),
                            );
                        });
                    });
            });
            ui.add_space(16.0);
            widgets::segmented(
                ui,
                &mut problems_only,
                &[(false, "Everything"), (true, "Problems")],
            );
            if undo {
                ui.add_space(8.0);
                widgets::card(ui, false, |ui| {
                    widgets::setting_row(ui, "The list was cleared", None, true, |ui| {
                        if widgets::link(ui, "Undo", true, None).clicked() {
                            todo.push(Do::Undo);
                        }
                    });
                });
            }
            ui.add_space(16.0);
            if lines.is_empty() {
                widgets::help(
                    ui,
                    if problems_only {
                        "No problems."
                    } else {
                        "Nothing yet."
                    },
                );
            } else {
                ui.label(
                    egui::RichText::new("Today")
                        .font(theme::semibold(12.0))
                        .color(p.text3),
                );
                ui.add_space(4.0);
            }
            for (time, level, text) in lines {
                let (icon, ink) = match level {
                    Level::Info => (Icon::Dot, p.text3),
                    Level::Good => (Icon::Ok, p.green_text),
                    Level::Warning => (Icon::Warning, p.amber_text),
                    Level::Problem => (Icon::Error, p.red_text),
                };
                ui.add_space(6.0);
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = 12.0;
                    let (r, _) = ui.allocate_exact_size(vec2(16.0, 20.0), Sense::hover());
                    icons::paint(
                        ui.painter(),
                        Rect::from_min_size(r.min + vec2(0.0, 2.0), vec2(16.0, 16.0)),
                        icon,
                        ink,
                    );
                    let (t, _) = ui.allocate_exact_size(vec2(36.0, 20.0), Sense::hover());
                    ui.painter().text(
                        t.left_center(),
                        Align2::LEFT_CENTER,
                        &time[..time.len().min(5)],
                        theme::regular(12.0),
                        p.text3,
                    );
                    ui.add(
                        egui::Label::new(egui::RichText::new(&text).size(14.0).color(p.text))
                            .wrap(),
                    );
                });
                ui.add_space(6.0);
            }
        });
        self.problems_only = problems_only;
        for action in todo {
            match action {
                Do::Clear => {
                    let old = std::mem::take(&mut self.log);
                    self.cleared = Some((old, Instant::now()));
                }
                Do::Undo => {
                    if let Some((old, _)) = self.cleared.take() {
                        let newer = std::mem::replace(&mut self.log, old);
                        self.log.extend(newer);
                    }
                }
                Do::Report => self.save_report(),
                Do::Trace(on) => {
                    let file = crate::trace::file().display().to_string();
                    match crate::trace::set(on) {
                        Ok(()) => {
                            self.trace = crate::trace::enabled();
                            self.log(if self.trace {
                                format!("Recording connection traces in {file}.")
                            } else {
                                "Connection traces are off.".to_string()
                            });
                        }
                        Err(e) => self.log_at(
                            Level::Problem,
                            format!("Could not change the trace setting: {e}"),
                        ),
                    }
                }
            }
        }
    }
}
