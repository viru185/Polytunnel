//! Gateways: a GlobalProtect profile's picker (measured gateways; Fastest, Prefer one or Only
//! one) and a Fortinet profile's gateway order.

use eframe::egui::{self, Align2, Rect, Sense, Ui, pos2, vec2};
use polytunnel_core::ipc::Status;
use polytunnel_core::profile::{GatewayPolicy, ProbeMethod, Profile};
use polytunnel_gp::portal::host_of;
use polytunnel_gp::rank::Probe;

use super::body;
use super::profiles::{GatewayMode, gateway_mode, with_mode};
use crate::gui::icons::Icon;
use crate::gui::integrations;
use crate::gui::widgets::{self, Kind as Button, Tone};
use crate::gui::{App, Editor, Level, theme};

/// Latency bars (of 4) for a measurement.
pub fn bars_for(probe: &Probe) -> usize {
    match probe {
        Probe::Answered(t) => match t.as_millis() {
            0..=60 => 4,
            61..=150 => 3,
            151..=300 => 2,
            _ => 1,
        },
        Probe::Failed | Probe::Unknown => 0,
    }
}

enum Do {
    Mode(GatewayMode),
    Choose(String),
    Measure,
    StrictTiers(bool),
    TcpProbe(bool),
}

impl App {
    /// The gateway this GlobalProtect profile would switch to now, when it is connected to
    /// another one (the picker's sticky "Switch to …").
    pub(in crate::gui) fn gateway_switch_target(&self, name: &str) -> Option<String> {
        let Some(Ok(Status::Connected {
            profile, server, ..
        })) = &self.status
        else {
            return None;
        };
        if profile != name {
            return None;
        }
        let Some(Profile::GlobalProtect(gp)) = self.profiles.get(name) else {
            return None;
        };
        let wanted = gp
            .gateway
            .clone()
            .or_else(|| gp.preferred_gateway.clone())?;
        // The choice is the portal's name for a gateway; match it to an address if measured.
        let address = self
            .gateways
            .as_ref()
            .filter(|g| g.profile == name)
            .and_then(|g| g.ranking.as_ref())
            .and_then(|r| r.gateways.iter().find(|g| g.gateway.label() == wanted))
            .map(|g| host_of(&g.gateway.address).to_string());
        let host = address.unwrap_or_else(|| wanted.clone());
        let same = host.eq_ignore_ascii_case(server) || wanted.eq_ignore_ascii_case(server);
        (!same).then_some(wanted)
    }

    pub(in crate::gui) fn gateways_page(&mut self, ui: &mut Ui, name: &str) {
        let p = widgets::pal(ui);
        let Some(Profile::GlobalProtect(gp)) = self.profiles.get(name).cloned() else {
            self.back();
            return;
        };
        let mut todo = Vec::new();
        let measuring = self.gateways.as_ref().is_some_and(|g| g.pending.is_some());
        if widgets::page_header(ui, "Gateway", &format!("{name} · GlobalProtect"), |ui| {
            ui.add_enabled_ui(!measuring, |ui| {
                if widgets::icon_button(ui, Icon::Refresh, "Measure again", 36.0, None).clicked() {
                    todo.push(Do::Measure);
                }
            });
        }) {
            self.back();
            return;
        }
        // Measure when the page opens.
        if self.gateways.as_ref().is_none_or(|g| g.profile != name) && !self.fake {
            self.find_best_gateway(ui.ctx(), name, &gp);
        }
        let mode = gateway_mode(&gp);
        let connected_to = match &self.status {
            Some(Ok(Status::Connected {
                profile, server, ..
            })) if profile == name => Some(server.clone()),
            _ => None,
        };
        let view = self.gateways.as_ref().filter(|g| g.profile == name);
        let ranking = view.and_then(|g| g.ranking.clone());
        let note = view.and_then(|g| g.note.clone());
        let read_only = self.read_only();
        body(ui, "gateways", |ui| {
            ui.add_space(4.0);
            let mut m = mode;
            ui.add_enabled_ui(!read_only, |ui| {
                if widgets::segmented(
                    ui,
                    &mut m,
                    &[
                        (GatewayMode::Fastest, "Fastest"),
                        (GatewayMode::Prefer, "Prefer one"),
                        (GatewayMode::Always, "Only one"),
                    ],
                ) {
                    todo.push(Do::Mode(m));
                }
            });
            ui.add_space(8.0);
            widgets::help(
                ui,
                match mode {
                    GatewayMode::Fastest => {
                        "Polytunnel picks the fastest each time. Select a gateway to prefer it."
                    }
                    GatewayMode::Prefer => {
                        "Uses your choice while it answers, otherwise the fastest."
                    }
                    GatewayMode::Always => {
                        "Always uses your choice. Connecting fails if it doesn't answer."
                    }
                },
            );
            ui.add_space(16.0);
            match &ranking {
                None => {
                    widgets::card(ui, true, |ui| {
                        if measuring {
                            ui.horizontal(|ui| {
                                ui.add(egui::Spinner::new());
                                ui.label(
                                    egui::RichText::new("Measuring the gateways…").color(p.text2),
                                );
                            });
                        } else {
                            widgets::help(
                                ui,
                                note.as_deref()
                                    .unwrap_or("Connect once to fetch this portal's gateway list."),
                            );
                        }
                    });
                }
                Some(ranking) => {
                    let count = ranking.gateways.len();
                    widgets::card(ui, false, |ui| {
                        for (i, r) in ranking.gateways.iter().enumerate() {
                            let label = r.gateway.label().to_string();
                            let host = host_of(&r.gateway.address).to_string();
                            let failed = matches!(r.probe, Probe::Failed);
                            let selected = match mode {
                                GatewayMode::Always => {
                                    gp.gateway.as_deref() == Some(label.as_str())
                                }
                                GatewayMode::Prefer => {
                                    gp.preferred_gateway.as_deref() == Some(label.as_str())
                                }
                                GatewayMode::Fastest => false,
                            };
                            let is_connected = connected_to
                                .as_deref()
                                .is_some_and(|s| s.eq_ignore_ascii_case(&host));
                            let sub = if failed {
                                format!("{host} · no reply")
                            } else if is_connected {
                                format!("{host} · connected")
                            } else {
                                host.clone()
                            };
                            let ms = match r.probe {
                                Probe::Answered(t) => format!("{} ms", t.as_millis()),
                                Probe::Failed => "No reply".into(),
                                Probe::Unknown => "—".into(),
                            };
                            let fastest = mode == GatewayMode::Fastest && ranking.chosen == Some(i);
                            let clicked = gateway_row(
                                ui,
                                (mode != GatewayMode::Fastest).then_some(selected),
                                &label,
                                &sub,
                                fastest,
                                bars_for(&r.probe),
                                &ms,
                                failed,
                                i == 0,
                                i + 1 == count,
                            );
                            if clicked && !failed && !read_only {
                                todo.push(Do::Choose(label));
                            }
                        }
                    });
                    ui.add_space(8.0);
                    if let Some(note) = &note {
                        widgets::help(ui, note);
                    }
                }
            }
            ui.add_space(24.0);
            widgets::card(ui, false, |ui| {
                if widgets::fold_row(
                    ui,
                    "gateway-ranking",
                    "Advanced",
                    "How gateways are ranked",
                    true,
                ) {
                    let mut strict = gp.gateway_selection == Some(GatewayPolicy::StrictTiers);
                    if widgets::toggle_row(
                        ui,
                        "Rank by the portal's priority first",
                        Some("Then by speed within the same priority"),
                        !read_only,
                        &mut strict,
                        false,
                        false,
                    ) {
                        todo.push(Do::StrictTiers(strict));
                    }
                    let mut tcp = gp.probe == Some(ProbeMethod::Tcp);
                    if widgets::toggle_row(
                        ui,
                        "Measure with TCP instead of TLS",
                        Some("For networks that slow down TLS"),
                        !read_only,
                        &mut tcp,
                        false,
                        true,
                    ) {
                        todo.push(Do::TcpProbe(tcp));
                    }
                }
            });
        });
        let best = ranking
            .as_ref()
            .and_then(|r| r.chosen.and_then(|i| r.gateways.get(i)))
            .map(|r| r.gateway.label().to_string());
        let ctx = ui.ctx().clone();
        for action in todo {
            match action {
                Do::Mode(m) => {
                    let (gateway, preferred) = with_mode(&gp, m, best.as_deref());
                    self.set_gateway_choice(name, gateway, preferred);
                }
                Do::Choose(label) => {
                    let (gateway, preferred) = match mode {
                        GatewayMode::Always => (Some(label), None),
                        _ => (None, Some(label)),
                    };
                    self.set_gateway_choice(name, gateway, preferred);
                }
                Do::Measure => self.find_best_gateway(&ctx, name, &gp),
                Do::StrictTiers(on) => self.change_gp(name, |p| {
                    p.gateway_selection = on.then_some(GatewayPolicy::StrictTiers);
                }),
                Do::TcpProbe(on) => self.change_gp(name, |p| {
                    p.probe = on.then_some(ProbeMethod::Tcp);
                }),
            }
        }
    }

    /// The picker's sticky bar while connected to another gateway than the one chosen.
    pub(in crate::gui) fn gateways_footer(&mut self, ui: &mut Ui, name: &str) {
        let p = widgets::pal(ui);
        let Some(target) = self.gateway_switch_target(name) else {
            return;
        };
        let server = match &self.status {
            Some(Ok(Status::Connected { server, .. })) => server.clone(),
            _ => String::new(),
        };
        let mut switch = false;
        ui.horizontal_centered(|ui| {
            ui.label(
                egui::RichText::new(format!("Connected to {server}"))
                    .size(12.0)
                    .color(p.text2),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                switch = widgets::button(
                    ui,
                    Button::Primary,
                    &format!("Switch to {target}"),
                    None,
                    false,
                )
                .on_hover_text("Reconnects through this gateway")
                .clicked();
            });
        });
        if switch {
            let ctx = ui.ctx().clone();
            self.connect(&ctx, name.to_string());
        }
    }

    /// A Fortinet profile's gateways, in the order they are tried.
    pub(in crate::gui) fn gateway_order_page(&mut self, ui: &mut Ui, name: &str) {
        let Some(profile) = self.profiles.get(name).cloned() else {
            self.back();
            return;
        };
        let (_, conn) = integrations::of(&profile);
        if widgets::page_header(
            ui,
            "Gateways",
            &format!("{name} · {}", conn.full_name),
            |_| {},
        ) {
            self.back();
            return;
        }
        let servers = integrations::servers(&profile);
        let in_use = match &self.status {
            Some(Ok(Status::Connected {
                profile: active,
                server,
                ..
            })) if active == name => Some(server.clone()),
            _ => None,
        };
        let mut edit = false;
        let read_only = self.read_only();
        body(ui, "gateway-order", |ui| {
            ui.add_space(4.0);
            widgets::card(ui, false, |ui| {
                for (i, server) in servers.iter().enumerate() {
                    let p = widgets::pal(ui);
                    let (rect, _) = widgets::row_frame(
                        ui,
                        48.0,
                        i == 0,
                        i + 1 == servers.len(),
                        Sense::hover(),
                    );
                    ui.painter().text(
                        pos2(rect.left() + 16.0, rect.center().y),
                        Align2::LEFT_CENTER,
                        format!("{}", i + 1),
                        theme::regular(12.0),
                        p.text3,
                    );
                    widgets::text_cut(
                        ui,
                        pos2(rect.left() + 40.0, rect.center().y),
                        Align2::LEFT_CENTER,
                        server,
                        theme::regular(14.0),
                        p.text,
                        rect.width() - 40.0 - 100.0,
                    );
                    let host = server.split(':').next().unwrap_or(server);
                    let (text, tone) = if in_use.as_deref().is_some_and(|s| {
                        s.eq_ignore_ascii_case(host) || s.eq_ignore_ascii_case(server)
                    }) {
                        ("In use", Tone::Good)
                    } else if i == 0 {
                        ("First", Tone::Mute)
                    } else {
                        ("Backup", Tone::Mute)
                    };
                    let font = theme::semibold(12.0);
                    let w = ui
                        .painter()
                        .layout_no_wrap(text.to_string(), font.clone(), p.text)
                        .size()
                        .x
                        + 16.0;
                    let pill = Rect::from_min_size(
                        pos2(rect.right() - 16.0 - w, rect.center().y - 10.0),
                        vec2(w, 20.0),
                    );
                    let (ink, fill) = match tone {
                        Tone::Good => (p.green_text, p.green_soft),
                        _ => (p.text2, p.surface3),
                    };
                    ui.painter()
                        .rect_filled(pill, egui::CornerRadius::same(10), fill);
                    ui.painter()
                        .text(pill.center(), Align2::CENTER_CENTER, text, font, ink);
                }
            });
            ui.add_space(8.0);
            widgets::help(
                ui,
                "Polytunnel tries them in this order. A wrong password stops at the first one.",
            );
            ui.add_space(16.0);
            ui.add_enabled_ui(!read_only, |ui| {
                edit =
                    widgets::button(ui, Button::Secondary, "Edit order", Some(Icon::Edit), false)
                        .clicked();
            });
        });
        if edit {
            self.open_editor(Editor::from_profile(name, &profile));
        }
    }

    /// Saves a GlobalProtect profile's gateway choice.
    pub(in crate::gui) fn set_gateway_choice(
        &mut self,
        name: &str,
        gateway: Option<String>,
        preferred: Option<String>,
    ) {
        self.change_gp(name, |p| {
            p.gateway = gateway;
            p.preferred_gateway = preferred;
        });
    }

    /// Changes a GlobalProtect profile and saves the profiles.
    fn change_gp(
        &mut self,
        name: &str,
        change: impl FnOnce(&mut polytunnel_core::profile::GlobalProtectProfile),
    ) {
        if self.read_only() {
            return;
        }
        let before = self.profiles.clone();
        if let Some(Profile::GlobalProtect(p)) = self.profiles.profiles.get_mut(name) {
            change(p);
            if let Err(e) = self.store() {
                self.profiles = before;
                self.log_at(Level::Problem, format!("Could not save the profiles: {e}"));
            }
        }
    }
}

/// A gateway row: radio (when a choice is made), name and host, latency bars and time.
#[allow(clippy::too_many_arguments)]
fn gateway_row(
    ui: &mut Ui,
    radio: Option<bool>,
    name: &str,
    sub: &str,
    fastest: bool,
    bars: usize,
    ms: &str,
    failed: bool,
    first: bool,
    last: bool,
) -> bool {
    let p = widgets::pal(ui);
    let sense = if failed {
        Sense::hover()
    } else {
        Sense::click()
    };
    let (rect, response) = widgets::row_frame(ui, 56.0, first, last, sense);
    let response = if failed {
        response.on_hover_text("This gateway doesn't reply, so it can't be chosen now")
    } else if radio.is_none() {
        response.on_hover_text("Prefer this gateway")
    } else {
        response
    };
    let mut x = rect.left() + 16.0;
    let cy = rect.center().y;
    if let Some(on) = radio {
        let c = pos2(x + 10.0, cy);
        let alpha = if failed { 0.4 } else { 1.0 };
        if on {
            ui.painter().circle_stroke(
                c,
                9.25,
                egui::Stroke::new(1.5, p.accent.gamma_multiply(alpha)),
            );
            ui.painter()
                .circle_filled(c, 4.5, p.accent.gamma_multiply(alpha));
        } else {
            ui.painter().circle_stroke(
                c,
                9.25,
                egui::Stroke::new(1.5, p.control_line.gamma_multiply(alpha)),
            );
        }
        x += 32.0;
    }
    let right = rect.right() - 16.0;
    // Time, then bars, from the right.
    ui.painter().text(
        pos2(right, cy),
        Align2::RIGHT_CENTER,
        ms,
        theme::regular(12.0),
        p.text2,
    );
    let bars_rect = Rect::from_min_size(pos2(right - 56.0 - 18.0, cy - 7.0), vec2(18.0, 14.0));
    let alpha = if failed { 0.45 } else { 1.0 };
    for (i, h) in [5.0, 8.0, 11.0, 14.0].into_iter().enumerate() {
        let bar = Rect::from_min_size(
            pos2(bars_rect.left() + i as f32 * 5.0, bars_rect.bottom() - h),
            vec2(3.0, h),
        );
        let color = if i < bars { p.text2 } else { p.line_strong };
        ui.painter().rect_filled(
            bar,
            egui::CornerRadius::same(1),
            color.gamma_multiply(alpha),
        );
    }
    let text_right = bars_rect.left() - 12.0;
    let title_font = if failed {
        theme::regular(14.0)
    } else {
        theme::semibold(14.0)
    };
    let title_ink = if failed { p.text2 } else { p.text };
    let t = widgets::text_cut(
        ui,
        pos2(x, cy - 9.0),
        Align2::LEFT_CENTER,
        name,
        title_font,
        title_ink,
        text_right - x,
    );
    if fastest {
        let font = theme::semibold(12.0);
        let w = ui
            .painter()
            .layout_no_wrap("Fastest".into(), font.clone(), p.text)
            .size()
            .x
            + 16.0;
        let pill = Rect::from_min_size(pos2(t.right() + 8.0, t.center().y - 10.0), vec2(w, 20.0));
        if pill.right() < text_right {
            ui.painter()
                .rect_filled(pill, egui::CornerRadius::same(10), p.surface3);
            ui.painter().text(
                pill.center(),
                Align2::CENTER_CENTER,
                "Fastest",
                font,
                p.text2,
            );
        }
    }
    widgets::text_cut(
        ui,
        pos2(x, cy + 10.0),
        Align2::LEFT_CENTER,
        sub,
        theme::regular(12.0),
        p.text3,
        text_right - x,
    );
    response.clicked()
}
