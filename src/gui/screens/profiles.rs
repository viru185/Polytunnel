//! Profiles: every profile as a row that opens to its actions and, for GlobalProtect, its
//! gateways.

use eframe::egui::{self, Align, CursorIcon, Label, Layout, Rect, RichText, Sense, vec2};
use polytunnel_core::ipc::Status;
use polytunnel_core::profile::{GlobalProtectProfile, Profile};
use polytunnel_gp::rank::Probe;

use crate::gui::icons::Icon;
use crate::gui::widgets::{self, Tone};
use crate::gui::{App, Kind, Leave, active_profile, save_profiles};

use super::home::profile_line;

/// How a GlobalProtect profile picks its gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayMode {
    /// The fastest that answers, every time.
    Fastest,
    /// A preferred one while it answers, else the fastest.
    Prefer,
    /// Only one.
    Always,
}

pub fn gateway_mode(p: &GlobalProtectProfile) -> GatewayMode {
    match (&p.gateway, &p.preferred_gateway) {
        (Some(_), _) => GatewayMode::Always,
        (None, Some(_)) => GatewayMode::Prefer,
        (None, None) => GatewayMode::Fastest,
    }
}

/// The profile's gateway settings for `mode`, choosing `candidate` (the best measured
/// gateway) when the mode needs one and none is set.
pub fn with_mode(
    p: &GlobalProtectProfile,
    mode: GatewayMode,
    candidate: Option<&str>,
) -> (Option<String>, Option<String>) {
    let current = p.gateway.clone().or_else(|| p.preferred_gateway.clone());
    let chosen = current.or_else(|| candidate.map(str::to_string));
    match mode {
        GatewayMode::Fastest => (None, None),
        GatewayMode::Prefer => (None, chosen),
        GatewayMode::Always => (chosen, None),
    }
}

impl App {
    pub(in crate::gui) fn profiles_screen(&mut self, ui: &mut egui::Ui) {
        let p = widgets::pal(ui);
        ui.horizontal(|ui| {
            ui.heading("Profiles");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_enabled_ui(!self.read_only(), |ui| {
                    let add = widgets::icon_button(ui, Icon::Plus, "Add a profile");
                    egui::Popup::menu(&add).width(210.0).show(|ui| {
                        let mut pick = None;
                        if ui.button("GlobalProtect").clicked() {
                            pick = Some(Kind::GlobalProtect);
                        }
                        if ui.button("Fortinet SSL VPN").clicked() {
                            pick = Some(Kind::FortinetSsl);
                        }
                        if ui.button("Fortinet IPsec").clicked() {
                            pick = Some(Kind::FortinetIpsec);
                        }
                        if cfg!(windows) {
                            ui.separator();
                            if ui.button("Import from FortiClient").clicked() {
                                ui.close();
                                self.import_forticlient();
                            }
                        }
                        if let Some(kind) = pick {
                            ui.close();
                            self.leave_editor(Leave::New(kind));
                        }
                    });
                });
            });
        });
        ui.add_space(4.0);
        if let Some(e) = self.load_error.clone() {
            widgets::banner(
                ui,
                Tone::Error,
                "Your profiles file could not be read",
                &format!(
                    "{e}\nFix or remove it, then reopen Polytunnel. Nothing is changed until then."
                ),
            );
            ui.add_space(6.0);
        }
        if self.profiles.profiles.is_empty() && self.load_error.is_none() {
            widgets::card(ui, |ui| {
                ui.label(RichText::new("No profiles yet").strong());
                ui.label(
                    RichText::new("Press + to add a GlobalProtect or Fortinet profile.")
                        .size(12.0)
                        .color(p.muted),
                );
            });
            return;
        }
        let names: Vec<String> = self.profiles.profiles.keys().cloned().collect();
        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 6.0;
                for name in names {
                    self.profile_card(ui, &name);
                }
            });
    }

    fn profile_card(&mut self, ui: &mut egui::Ui, name: &str) {
        let p = widgets::pal(ui);
        let Some(profile) = self.profiles.get(name).cloned() else {
            return;
        };
        let active = active_profile(&self.status).map(str::to_string);
        let this_active = active.as_deref() == Some(name);
        let open = self.expanded.as_deref() == Some(name);
        let (dot, ink, _) = crate::gui::theme::status_colors(p, self.status.as_ref());
        let kind = match &profile {
            Profile::GlobalProtect(_) => "GP",
            Profile::FortinetSsl(_) => "SSL",
            Profile::FortinetIpsec(_) => "IPsec",
        };
        let mut toggle = false;
        widgets::card(ui, |ui| {
            let header = ui.horizontal(|ui| {
                widgets::dot(ui, if this_active { dot } else { p.dot_idle });
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.label(RichText::new(name).strong());
                    let mut line = profile_line(&profile);
                    if this_active {
                        line = match &self.status {
                            Some(Ok(Status::Connected { .. })) => "Connected".into(),
                            Some(Ok(Status::Reconnecting { .. })) => "Reconnecting".into(),
                            _ => "Connecting".into(),
                        };
                    }
                    ui.add(
                        Label::new(RichText::new(line).size(11.0).color(if this_active {
                            ink
                        } else {
                            p.muted
                        }))
                        .truncate(),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    widgets::pill(ui, kind, p.muted, p.sunken);
                });
            });
            let click = ui
                .interact(
                    header.response.rect,
                    egui::Id::unique(("profile-row", name)),
                    Sense::click(),
                )
                .on_hover_cursor(CursorIcon::PointingHand);
            if click.clicked() {
                toggle = true;
            }
            if open {
                ui.add_space(4.0);
                widgets::divider(ui);
                ui.add_space(4.0);
                self.profile_actions(ui, name, &profile, active.as_deref());
                if let Profile::GlobalProtect(gp) = &profile {
                    ui.add_space(6.0);
                    self.gateway_section(ui, name, gp);
                } else {
                    let servers = match &profile {
                        Profile::FortinetSsl(f) => f.servers(),
                        Profile::FortinetIpsec(f) => f.servers(),
                        Profile::GlobalProtect(_) => Vec::new(),
                    };
                    if servers.len() > 1 {
                        ui.add_space(4.0);
                        widgets::section(ui, "Gateways, in order");
                        for (i, server) in servers.iter().enumerate() {
                            ui.label(RichText::new(format!("{}. {server}", i + 1)).size(12.0));
                        }
                    }
                }
            }
        });
        if toggle {
            self.expanded = if open { None } else { Some(name.to_string()) };
        }
    }

    fn profile_actions(
        &mut self,
        ui: &mut egui::Ui,
        name: &str,
        profile: &Profile,
        active: Option<&str>,
    ) {
        let this_active = active == Some(name);
        let setting_up = matches!(
            &self.status,
            Some(Ok(Status::Connecting { .. } | Status::NeedsInput { .. }))
        );
        ui.horizontal(|ui| {
            if this_active {
                let label = if setting_up || self.busy() {
                    "Cancel"
                } else {
                    "Disconnect"
                };
                if ui
                    .add_enabled(!self.running.disconnect, widgets::primary(ui, label))
                    .clicked()
                {
                    self.disconnect(ui.ctx());
                }
            } else {
                let label = match active {
                    Some(_) => format!("Switch to {name}"),
                    None => "Connect".into(),
                };
                if ui
                    .add_enabled(!self.busy(), widgets::primary(ui, &label))
                    .on_disabled_hover_text("Wait until the current attempt finishes.")
                    .clicked()
                {
                    self.selected = Some(name.to_string());
                    self.connect(ui.ctx(), name.to_string());
                }
            }
            if ui
                .add_enabled(
                    !this_active && !self.busy() && !self.read_only(),
                    widgets::secondary(ui, "Edit"),
                )
                .on_disabled_hover_text("Disconnect first to change this profile.")
                .clicked()
            {
                self.open_editor(crate::gui::Editor::from_profile(name, profile));
            }
        });
    }

    /// A GlobalProtect profile's gateway choice and the measured gateways.
    fn gateway_section(&mut self, ui: &mut egui::Ui, name: &str, gp: &GlobalProtectProfile) {
        let p = widgets::pal(ui);
        widgets::section(ui, "Gateway");
        let mut mode = gateway_mode(gp);
        let before = mode;
        widgets::segmented(
            ui,
            &mut mode,
            &[
                (GatewayMode::Fastest, "Fastest"),
                (GatewayMode::Prefer, "Prefer one"),
                (GatewayMode::Always, "Always one"),
            ],
        );
        let shown = self.gateways.as_ref().is_some_and(|g| g.profile == name);
        let best = self
            .gateways
            .as_ref()
            .filter(|g| g.profile == name)
            .and_then(|g| g.ranking.as_ref())
            .and_then(|r| r.chosen.and_then(|i| r.gateways.get(i)))
            .map(|r| r.gateway.label().to_string());
        if mode != before {
            let (gateway, preferred) = with_mode(gp, mode, best.as_deref());
            self.set_gateway_choice(name, gateway, preferred);
        }
        let help = match mode {
            GatewayMode::Fastest => "Every connect measures the gateways and uses the quickest.",
            GatewayMode::Prefer => "Your choice while it answers, else the fastest other.",
            GatewayMode::Always => "Only your choice. If it does not answer, connecting fails.",
        };
        ui.label(RichText::new(help).size(11.0).color(p.muted));

        let measuring = self.gateways.as_ref().is_some_and(|g| g.pending.is_some());
        let mut action = None;
        if let Some(view) = self.gateways.as_ref().filter(|g| g.profile == name) {
            if let Some(ranking) = &view.ranking {
                let slowest = ranking
                    .gateways
                    .iter()
                    .filter_map(|r| match r.probe {
                        Probe::Answered(t) => Some(t.as_millis() as f32),
                        _ => None,
                    })
                    .fold(1.0f32, f32::max);
                for (i, r) in ranking.gateways.iter().enumerate() {
                    let label = r.gateway.label().to_string();
                    let chosen_here = match mode {
                        GatewayMode::Always => gp.gateway.as_deref() == Some(label.as_str()),
                        _ => gp.preferred_gateway.as_deref() == Some(label.as_str()),
                    };
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("{}", i + 1))
                                .size(12.0)
                                .color(p.muted),
                        );
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            ui.set_width((ui.available_width() - 120.0).max(80.0));
                            ui.add(Label::new(RichText::new(&label).size(12.0)).truncate());
                            let (rect, _) = ui.allocate_exact_size(
                                vec2(ui.available_width(), 4.0),
                                Sense::hover(),
                            );
                            ui.painter().rect_filled(rect, 2, p.sunken);
                            if let Probe::Answered(t) = r.probe {
                                let share = 1.0 - (t.as_millis() as f32 / (slowest * 1.25));
                                let fill = Rect::from_min_size(
                                    rect.min,
                                    vec2(rect.width() * share.clamp(0.08, 1.0), rect.height()),
                                );
                                let color = if ranking.chosen == Some(i) {
                                    p.dot_green
                                } else {
                                    p.accent
                                };
                                ui.painter().rect_filled(fill, 2, color);
                            }
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if chosen_here {
                                let tag = if mode == GatewayMode::Always {
                                    "In use"
                                } else {
                                    "Preferred"
                                };
                                widgets::pill(ui, tag, p.accent, p.accent_soft);
                            } else if mode != GatewayMode::Fastest
                                && !matches!(r.probe, Probe::Failed)
                            {
                                let verb = if mode == GatewayMode::Always {
                                    "Use"
                                } else {
                                    "Prefer"
                                };
                                if ui.add(widgets::mini(ui, verb)).clicked() {
                                    action = Some(label.clone());
                                }
                            } else if ranking.chosen == Some(i) {
                                widgets::pill(ui, "Fastest", p.green, p.green_soft);
                            }
                            let ms = match r.probe {
                                Probe::Answered(t) => format!("{} ms", t.as_millis()),
                                Probe::Failed => "none".into(),
                                Probe::Unknown => "-".into(),
                            };
                            ui.label(RichText::new(ms).size(12.0).color(p.muted));
                        });
                    });
                }
            }
            if let Some(note) = &view.note {
                ui.label(RichText::new(note).size(11.0).color(p.muted));
            }
        }
        ui.horizontal(|ui| {
            let label = if shown {
                "Measure again"
            } else {
                "Measure the gateways"
            };
            if ui
                .add_enabled(!measuring, widgets::mini(ui, label))
                .clicked()
            {
                self.find_best_gateway(ui.ctx(), name, gp);
            }
            if measuring {
                ui.add(egui::Spinner::new());
            }
        });
        if let Some(label) = action {
            let (gateway, preferred) = match mode {
                GatewayMode::Always => (Some(label), None),
                _ => (None, Some(label)),
            };
            self.set_gateway_choice(name, gateway, preferred);
        }
    }

    /// Saves a GlobalProtect profile's gateway choice.
    fn set_gateway_choice(
        &mut self,
        name: &str,
        gateway: Option<String>,
        preferred: Option<String>,
    ) {
        let before = self.profiles.clone();
        if let Some(Profile::GlobalProtect(p)) = self.profiles.profiles.get_mut(name) {
            p.gateway = gateway;
            p.preferred_gateway = preferred;
            if let Err(e) = save_profiles(&self.profiles) {
                self.profiles = before;
                self.log_at(
                    crate::gui::Level::Problem,
                    format!("Could not save the profiles: {e}"),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_modes_map_to_the_profile_fields() {
        let mut gp = GlobalProtectProfile {
            portal: "vpn.example.com".into(),
            ..Default::default()
        };
        assert_eq!(gateway_mode(&gp), GatewayMode::Fastest);
        // Prefer with nothing chosen takes the best measured gateway.
        assert_eq!(
            with_mode(&gp, GatewayMode::Prefer, Some("east")),
            (None, Some("east".into()))
        );
        gp.preferred_gateway = Some("west".into());
        assert_eq!(gateway_mode(&gp), GatewayMode::Prefer);
        // Always keeps the gateway already chosen.
        assert_eq!(
            with_mode(&gp, GatewayMode::Always, Some("east")),
            (Some("west".into()), None)
        );
        gp.gateway = Some("west".into());
        assert_eq!(gateway_mode(&gp), GatewayMode::Always);
        assert_eq!(
            with_mode(&gp, GatewayMode::Fastest, Some("east")),
            (None, None)
        );
    }
}
