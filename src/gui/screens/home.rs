//! Home: the profile switcher, the connect button and what the connection is doing.

use eframe::egui::{self, CursorIcon, FontId, Label, Rect, RichText, Sense, Stroke, vec2};
use polytunnel_core::ipc::{KillSwitchMode, Status};
use polytunnel_core::profile::Profile;

use crate::connect;
use crate::gui::icons::{self, Icon};
use crate::gui::theme::{self, Palette};
use crate::gui::widgets::{self, RingLook, Tone};
use crate::gui::{App, Screen, active_profile, backup_note, bytes, elapsed};

/// What the connect button does now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Connect,
    Cancel,
    Disconnect,
    Nothing,
}

/// How the connection looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mood {
    Idle,
    Busy,
    Good,
    Limited,
    Problem,
}

/// What Home shows for a status.
#[derive(Debug, Clone, PartialEq)]
pub struct Hero {
    pub title: String,
    pub line: String,
    pub action: Action,
    pub spinning: bool,
    pub mood: Mood,
}

fn hero_of(
    title: &str,
    line: impl Into<String>,
    action: Action,
    spinning: bool,
    mood: Mood,
) -> Hero {
    Hero {
        title: title.into(),
        line: line.into(),
        action,
        spinning,
        mood,
    }
}

/// Home's title, line and button for `status` (`selected`: the profile Connect would use).
pub fn hero(status: Option<&Result<Status, String>>, selected: Option<&str>) -> Hero {
    match status {
        None => hero_of("Checking…", "", Action::Nothing, true, Mood::Busy),
        Some(Err(e)) => hero_of(
            "Service unavailable",
            connect::service_problem(e),
            Action::Nothing,
            false,
            Mood::Problem,
        ),
        Some(Ok(Status::Idle {})) => match selected {
            Some(name) => hero_of(
                "Not connected",
                format!("Press to connect to {name}."),
                Action::Connect,
                false,
                Mood::Idle,
            ),
            None => hero_of(
                "Not connected",
                "Add a profile under Profiles to connect.",
                Action::Nothing,
                false,
                Mood::Idle,
            ),
        },
        Some(Ok(Status::Connecting { .. })) => hero_of(
            "Connecting…",
            "Signing in and bringing the tunnel up.",
            Action::Cancel,
            true,
            Mood::Busy,
        ),
        Some(Ok(Status::NeedsInput { .. })) => hero_of(
            "Waiting for you",
            "The gateway needs more sign-in details.",
            Action::Cancel,
            true,
            Mood::Busy,
        ),
        Some(Ok(Status::Connected {
            server,
            transport,
            notice,
            ..
        })) => match notice {
            None => hero_of(
                "Connected",
                format!("{server} · {}", connect::transport_name(transport)),
                Action::Disconnect,
                false,
                Mood::Good,
            ),
            Some(_) => hero_of(
                "Connected, with limits",
                server.clone(),
                Action::Disconnect,
                false,
                Mood::Limited,
            ),
        },
        Some(Ok(Status::Reconnecting {
            server, attempt, ..
        })) => hero_of(
            "Reconnecting…",
            format!("The connection to {server} dropped. Try {attempt}."),
            Action::Disconnect,
            true,
            Mood::Limited,
        ),
        Some(Ok(Status::Disconnecting { .. })) => {
            hero_of("Disconnecting…", "", Action::Nothing, true, Mood::Busy)
        }
        Some(Ok(Status::Failed { message, .. })) => hero_of(
            "Couldn't connect",
            message.clone(),
            Action::Connect,
            false,
            Mood::Problem,
        ),
    }
}

/// The connect button's colours for `mood`.
fn ring(p: &Palette, mood: Mood, spinning: bool) -> RingLook {
    match mood {
        Mood::Idle => RingLook {
            ring: p.border,
            arc: p.border,
            core: p.sunken,
            ink: p.muted,
        },
        Mood::Busy => RingLook {
            ring: p.accent_soft,
            arc: p.accent,
            core: p.accent_soft,
            ink: p.accent,
        },
        Mood::Good => RingLook {
            ring: p.dot_green,
            arc: p.dot_green,
            core: p.green_soft,
            ink: p.green,
        },
        Mood::Limited => RingLook {
            ring: if spinning { p.amber_soft } else { p.dot_amber },
            arc: p.dot_amber,
            core: p.amber_soft,
            ink: p.amber,
        },
        Mood::Problem => RingLook {
            ring: p.red,
            arc: p.red,
            core: p.red_soft,
            ink: p.red,
        },
    }
}

fn mood_ink(p: &Palette, mood: Mood) -> egui::Color32 {
    match mood {
        Mood::Idle | Mood::Busy => p.text,
        Mood::Good => p.green,
        Mood::Limited => p.amber,
        Mood::Problem => p.red,
    }
}

/// `GlobalProtect · vpn.example.com` and similar.
pub fn profile_line(profile: &Profile) -> String {
    match profile {
        Profile::GlobalProtect(p) => format!("GlobalProtect · {}", p.portal),
        Profile::FortinetSsl(p) => format!(
            "Fortinet SSL · {}{}",
            p.server,
            backup_note(p.servers().len())
        ),
        Profile::FortinetIpsec(p) => format!(
            "Fortinet IPsec · {}{}",
            p.server,
            backup_note(p.servers().len())
        ),
    }
}

impl App {
    pub(in crate::gui) fn home_screen(&mut self, ui: &mut egui::Ui) {
        let p = widgets::pal(ui);
        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let width = ui.available_width() - 34.0 - ui.spacing().item_spacing.x;
                    self.profile_switcher(ui, width);
                    let protecting = self
                        .killswitch
                        .as_ref()
                        .is_some_and(|(s, active, _)| s.mode != KillSwitchMode::Off && *active);
                    let (icon, tip) = if protecting {
                        (Icon::ShieldCheck, "The kill switch is on")
                    } else {
                        (Icon::Shield, "Kill switch")
                    };
                    if widgets::icon_button(ui, icon, tip).clicked() {
                        self.screen = Screen::Settings;
                    }
                });
                ui.add_space(14.0);

                let hero = hero(self.status.as_ref(), self.selected.as_deref());
                ui.vertical_centered(|ui| {
                    let look = ring(p, hero.mood, hero.spinning);
                    let label = match hero.action {
                        Action::Connect => "Connect",
                        Action::Cancel => "Cancel",
                        Action::Disconnect => "Disconnect",
                        Action::Nothing => "",
                    };
                    let response = widgets::connect_button(ui, look, hero.spinning, label);
                    if response.clicked() {
                        self.hero_action(ui.ctx(), hero.action);
                    }
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(&hero.title)
                            .text_style(theme::title_style())
                            .color(mood_ink(p, hero.mood)),
                    );
                    if !hero.line.is_empty() {
                        ui.add(
                            Label::new(RichText::new(&hero.line).size(12.0).color(p.muted)).wrap(),
                        );
                    }
                });
                ui.add_space(10.0);
                self.home_below(ui, &hero);
            });
    }

    fn hero_action(&mut self, ctx: &egui::Context, action: Action) {
        match action {
            Action::Connect if !self.busy() => {
                if let Some(name) = self.selected.clone() {
                    self.connect(ctx, name);
                }
            }
            Action::Cancel | Action::Disconnect if !self.running.disconnect => {
                self.disconnect(ctx);
            }
            _ => {}
        }
    }

    /// The profile button at the top: shows the profile Connect uses and lists the others.
    fn profile_switcher(&mut self, ui: &mut egui::Ui, width: f32) {
        let p = widgets::pal(ui);
        let (rect, response) = ui.allocate_exact_size(vec2(width, 44.0), Sense::click());
        let response = response.on_hover_cursor(CursorIcon::PointingHand);
        let name = self.selected.clone();
        let line = name
            .as_deref()
            .and_then(|n| self.profiles.get(n))
            .map(profile_line)
            .unwrap_or_else(|| "No profiles yet".into());
        let (dot, _, _) = theme::status_colors(p, self.status.as_ref());
        let active = active_profile(&self.status).map(str::to_string);
        if ui.is_rect_visible(rect) {
            let painter = ui.painter();
            painter.rect(
                rect,
                12,
                if response.hovered() {
                    p.sunken
                } else {
                    p.surface
                },
                Stroke::new(1.0, p.border),
                egui::StrokeKind::Inside,
            );
            let dot_color = if active.is_some() && active == name {
                dot
            } else {
                p.dot_idle
            };
            painter.circle_filled(rect.left_center() + vec2(16.0, 0.0), 4.5, dot_color);
            let text_rect =
                Rect::from_min_max(rect.min + vec2(30.0, 5.0), rect.max - vec2(30.0, 5.0));
            let semibold = egui::FontFamily::Name(theme::SEMIBOLD.into());
            let title = painter.layout(
                name.clone().unwrap_or_else(|| "Polytunnel".into()),
                FontId::new(14.0, semibold),
                p.text,
                text_rect.width(),
            );
            painter.galley(text_rect.min, title, p.text);
            let sub = painter.layout(line, FontId::proportional(11.0), p.muted, text_rect.width());
            painter.galley(text_rect.min + vec2(0.0, 19.0), sub, p.muted);
            icons::paint(
                painter,
                Rect::from_center_size(rect.right_center() - vec2(16.0, 0.0), vec2(14.0, 14.0)),
                Icon::ChevronDown,
                p.muted,
                2.0,
            );
        }
        let names: Vec<String> = self.profiles.profiles.keys().cloned().collect();
        let mut choice = None;
        egui::Popup::menu(&response).width(width).show(|ui| {
            if names.is_empty() {
                ui.label(RichText::new("Add a profile under Profiles.").color(p.muted));
            }
            for candidate in &names {
                let current = name.as_deref() == Some(candidate.as_str());
                let text = match &active {
                    Some(a) if a != candidate => format!("Switch to {candidate}"),
                    _ => candidate.clone(),
                };
                if ui.add(egui::Button::selectable(current, text)).clicked() {
                    choice = Some(candidate.clone());
                    ui.close();
                }
            }
        });
        if let Some(candidate) = choice {
            let switching = active.as_ref().is_some_and(|a| *a != candidate);
            self.selected = Some(candidate.clone());
            if switching && !self.busy() {
                self.connect(ui.ctx(), candidate);
            }
        }
    }

    /// Everything under the button: messages, figures and details.
    fn home_below(&mut self, ui: &mut egui::Ui, hero: &Hero) {
        let p = widgets::pal(ui);
        match self.status.clone() {
            Some(Ok(Status::Connecting { .. } | Status::NeedsInput { .. })) => {
                ui.vertical_centered(|ui| {
                    if ui.add(widgets::secondary(ui, "Cancel")).clicked() {
                        self.disconnect(ui.ctx());
                    }
                });
            }
            Some(Ok(Status::Failed { .. })) => {
                ui.vertical_centered(|ui| {
                    ui.horizontal(|ui| {
                        let w = 210.0;
                        ui.add_space(((ui.available_width() - w) / 2.0).max(0.0));
                        if ui.add(widgets::primary(ui, "Try again")).clicked() {
                            self.hero_action(ui.ctx(), Action::Connect);
                        }
                        if ui.add(widgets::secondary(ui, "Dismiss")).clicked() {
                            self.disconnect(ui.ctx());
                        }
                        if ui.add(widgets::secondary(ui, "Details")).clicked() {
                            self.screen = Screen::Activity;
                        }
                    });
                });
            }
            Some(Ok(Status::Idle {})) => {
                if let Some((settings, true, _)) = &self.killswitch {
                    let text = if settings.mode == KillSwitchMode::Always {
                        "Lockdown is on: there is no internet until the VPN connects."
                    } else {
                        "The connection dropped, so the kill switch blocks internet traffic \
                         until you connect again or press Disconnect."
                    };
                    widgets::banner(ui, Tone::Warning, "Internet traffic is blocked", text);
                    ui.add_space(6.0);
                }
                self.idle_card(ui);
            }
            Some(Ok(Status::Connected {
                server,
                addresses,
                transport,
                since_unix,
                notice,
                gateway,
                bytes_in,
                bytes_out,
                profile,
            })) => {
                if let Some(notice) = &notice {
                    widgets::banner(
                        ui,
                        Tone::Warning,
                        "The gateway limited this connection",
                        notice,
                    );
                    ui.add_space(6.0);
                }
                ui.columns_const(|[a, b, c]| {
                    widgets::stat_tile(a, "RECEIVED", &bytes(bytes_in));
                    widgets::stat_tile(b, "SENT", &bytes(bytes_out));
                    widgets::stat_tile(c, "TIME", &elapsed(since_unix));
                });
                ui.add_space(6.0);
                widgets::card(ui, |ui| {
                    let summary = connect::transport_name(&transport);
                    if widgets::fold(ui, "home-details", "Details", Some((&summary, p.muted))) {
                        detail(ui, "Profile", &profile);
                        detail(ui, "Server", &server);
                        if let Some(gateway) = &gateway {
                            detail(ui, "Gateway address", gateway);
                        }
                        detail(ui, "Your address", &addresses.join(", "));
                        detail(ui, "Tunnel", &summary);
                    }
                });
            }
            Some(Ok(Status::Reconnecting { .. })) => {
                widgets::banner(
                    ui,
                    Tone::Info,
                    "",
                    "Polytunnel keeps trying for up to 5 minutes, with the same sign-in.",
                );
            }
            _ => {}
        }
        let _ = hero.mood;
    }

    /// Idle: how this profile picks its gateway, with a way to change it.
    fn idle_card(&mut self, ui: &mut egui::Ui) {
        let p = widgets::pal(ui);
        let Some(name) = self.selected.clone() else {
            return;
        };
        let Some(profile) = self.profiles.get(&name).cloned() else {
            return;
        };
        let (title, line) = match &profile {
            Profile::GlobalProtect(gp) => match (&gp.gateway, &gp.preferred_gateway) {
                (Some(g), _) => ("Gateway: always one".to_string(), g.clone()),
                (None, Some(g)) => (
                    "Gateway: preferred".to_string(),
                    format!("{g}, or the fastest other"),
                ),
                (None, None) => (
                    "Gateway: automatic".to_string(),
                    "The fastest each time".to_string(),
                ),
            },
            Profile::FortinetSsl(f) => (
                "Gateways".to_string(),
                format!("{} in order", f.servers().len()),
            ),
            Profile::FortinetIpsec(f) => (
                "Gateways".to_string(),
                format!("{} in order", f.servers().len()),
            ),
        };
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.label(RichText::new(title).strong());
                    ui.label(RichText::new(line).size(12.0).color(p.muted));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(widgets::mini(ui, "Change")).clicked() {
                        self.expanded = Some(name.clone());
                        self.screen = Screen::Profiles;
                    }
                });
            });
        });
    }
}

/// A label and value line in a details card.
fn detail(ui: &mut egui::Ui, label: &str, value: &str) {
    let p = widgets::pal(ui);
    widgets::divider(ui);
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).size(12.0).color(p.muted));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add(Label::new(RichText::new(value).size(12.0)).truncate());
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_follows_the_connection() {
        let idle = hero(Some(&Ok(Status::Idle {})), Some("work"));
        assert_eq!((idle.action, idle.mood), (Action::Connect, Mood::Idle));
        assert!(idle.line.contains("work"));
        let nothing = hero(Some(&Ok(Status::Idle {})), None);
        assert_eq!(nothing.action, Action::Nothing);
        let connecting = hero(
            Some(&Ok(Status::Connecting {
                profile: "work".into(),
            })),
            Some("work"),
        );
        assert!(connecting.spinning && connecting.action == Action::Cancel);
        let connected = Status::Connected {
            profile: "work".into(),
            server: "gw.example.com".into(),
            addresses: vec!["10.0.0.2".into()],
            transport: "esp".into(),
            since_unix: 0,
            notice: None,
            gateway: None,
            bytes_in: 0,
            bytes_out: 0,
        };
        let up = hero(Some(&Ok(connected.clone())), Some("work"));
        assert_eq!((up.action, up.mood), (Action::Disconnect, Mood::Good));
        assert_eq!(up.line, "gw.example.com · ESP");
        let mut limited = connected;
        if let Status::Connected { notice, .. } = &mut limited {
            *notice = Some("VPN Access Denied".into());
        }
        assert_eq!(hero(Some(&Ok(limited)), None).mood, Mood::Limited);
        let failed = hero(
            Some(&Ok(Status::Failed {
                profile: "work".into(),
                message: "no answer".into(),
                since_unix: 0,
            })),
            Some("work"),
        );
        assert_eq!(
            (failed.action, failed.mood),
            (Action::Connect, Mood::Problem)
        );
        let down = hero(
            Some(&Err("cannot reach the Polytunnel service".into())),
            None,
        );
        assert_eq!((down.action, down.mood), (Action::Nothing, Mood::Problem));
        assert_eq!(hero(None, None).title, "Checking…");
    }
}
