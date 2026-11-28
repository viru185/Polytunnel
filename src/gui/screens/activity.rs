//! Activity: what Polytunnel did, and a short diagnosis.

use eframe::egui::{self, Align, Label, Layout, RichText};
use polytunnel_core::ipc::Status;

use crate::connect;
use crate::gui::icons::Icon;
use crate::gui::widgets;
use crate::gui::{App, Level};

impl App {
    pub(in crate::gui) fn activity_screen(&mut self, ui: &mut egui::Ui) {
        let p = widgets::pal(ui);
        ui.horizontal(|ui| {
            ui.heading("Activity");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::icon_button(ui, Icon::Trash, "Clear the log").clicked() {
                    self.log.clear();
                }
                if widgets::icon_button(ui, Icon::Copy, "Copy the log").clicked() {
                    let text: Vec<String> = self
                        .log
                        .iter()
                        .map(|l| format!("{}  {}", l.time, l.text))
                        .collect();
                    ui.ctx().copy_text(text.join("\n"));
                }
            });
        });
        ui.add_space(4.0);
        widgets::segmented(
            ui,
            &mut self.problems_only,
            &[(false, "Everything"), (true, "Problems")],
        );
        ui.add_space(4.0);
        self.diagnostics(ui);
        ui.add_space(4.0);
        let lines: Vec<(String, Level, String)> = self
            .log
            .iter()
            .filter(|l| !self.problems_only || matches!(l.level, Level::Warning | Level::Problem))
            .map(|l| (l.time.clone(), l.level, l.text.clone()))
            .collect();
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink(false)
            .show(ui, |ui| {
                if lines.is_empty() {
                    ui.label(RichText::new("Nothing yet.").size(12.0).color(p.muted));
                }
                for (time, level, text) in lines {
                    let (dot, ink) = match level {
                        Level::Info => (p.dot_idle, p.text),
                        Level::Good => (p.dot_green, p.green),
                        Level::Warning => (p.dot_amber, p.amber),
                        Level::Problem => (p.dot_red, p.red),
                    };
                    ui.horizontal_top(|ui| {
                        ui.label(RichText::new(time).monospace().size(11.0).color(p.muted));
                        widgets::dot(ui, dot);
                        ui.add(Label::new(RichText::new(text).size(12.0).color(ink)).wrap());
                    });
                }
            });
    }

    fn diagnostics(&mut self, ui: &mut egui::Ui) {
        let p = widgets::pal(ui);
        let (summary, color) = match &self.status {
            Some(Err(_)) => ("Service not running", p.red),
            Some(Ok(Status::Failed { .. })) => ("Last attempt failed", p.red),
            Some(Ok(Status::Connected {
                notice: Some(_), ..
            })) => ("Restricted", p.amber),
            Some(Ok(Status::Reconnecting { .. })) => ("Reconnecting", p.amber),
            Some(Ok(_)) => ("All good", p.green),
            None => ("Checking", p.muted),
        };
        widgets::card(ui, |ui| {
            if !widgets::fold(ui, "diagnostics", "Diagnostics", Some((summary, color))) {
                return;
            }
            let service = match &self.status {
                Some(Ok(_)) => "Running".to_string(),
                Some(Err(e)) => connect::service_problem(e),
                None => "Checking".into(),
            };
            pair(ui, "Service", &service);
            match &self.status {
                Some(Ok(Status::Connected {
                    server,
                    addresses,
                    transport,
                    gateway,
                    notice,
                    ..
                })) => {
                    pair(ui, "Server", server);
                    if let Some(gateway) = gateway {
                        pair(ui, "Gateway address", gateway);
                    }
                    pair(ui, "Your address", &addresses.join(", "));
                    pair(ui, "Tunnel", &connect::transport_name(transport));
                    pair(ui, "Device check", notice.as_deref().unwrap_or("Accepted"));
                }
                Some(Ok(status)) => pair(ui, "Connection", &connect::describe(status)),
                _ => {}
            }
            if let Some((settings, active, problem)) = &self.killswitch {
                pair(
                    ui,
                    "Kill switch",
                    &connect::describe_killswitch(settings, *active, problem.as_deref()),
                );
            }
            pair(ui, "Trace", if self.trace { "On" } else { "Off" });
        });
    }
}

fn pair(ui: &mut egui::Ui, label: &str, value: &str) {
    let p = widgets::pal(ui);
    widgets::divider(ui);
    ui.horizontal_top(|ui| {
        ui.label(RichText::new(label).size(12.0).color(p.muted));
        ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
            ui.add(Label::new(RichText::new(value).size(12.0)).wrap());
        });
    });
}
