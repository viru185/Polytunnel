//! Settings: kill switch, start-up, notifications, appearance, updates and the advanced bits.

use eframe::egui::{self, RichText};
use polytunnel_core::ipc::{KillSwitchMode, KillSwitchSettings};

use crate::gui::prefs::Appearance;
use crate::gui::widgets;
use crate::gui::{App, Confirm, Job, Level, link_status_text};
use crate::{autostart, connect, uri};

/// The kill switch's state in a word, with its colours.
fn killswitch_word(
    p: &crate::gui::theme::Palette,
    settings: &KillSwitchSettings,
    active: bool,
    problem: Option<&str>,
) -> (&'static str, egui::Color32, egui::Color32) {
    match (settings.mode, active, problem) {
        (_, _, Some(_)) => ("Problem", p.red, p.red_soft),
        (KillSwitchMode::Off, _, _) => ("Off", p.muted, p.sunken),
        (KillSwitchMode::Always, true, _) => ("Lockdown", p.amber, p.amber_soft),
        (_, true, _) => ("Protecting", p.green, p.green_soft),
        (_, false, _) => ("Ready", p.muted, p.sunken),
    }
}

impl App {
    pub(in crate::gui) fn settings_screen(&mut self, ui: &mut egui::Ui) {
        let p = widgets::pal(ui);
        ui.heading("Settings");
        ui.add_space(4.0);
        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 6.0;

                widgets::section(ui, "Security");
                widgets::card(ui, |ui| match self.killswitch.clone() {
                    None => {
                        ui.label(RichText::new("Kill switch").strong());
                        ui.label(
                            RichText::new("Unavailable while the Polytunnel service isn't running.")
                                .size(12.0)
                                .color(p.muted),
                        );
                    }
                    Some((settings, active, problem)) => {
                        let (word, fg, bg) = killswitch_word(p, &settings, active, problem.as_deref());
                        widgets::row(ui, "Kill switch", None, |ui| widgets::pill(ui, word, fg, bg));
                        let mut ks = settings;
                        ui.add_enabled_ui(!self.running.killswitch, |ui| {
                            widgets::segmented(
                                ui,
                                &mut ks.mode,
                                &[
                                    (KillSwitchMode::Off, "Off"),
                                    (KillSwitchMode::Connected, "While on"),
                                    (KillSwitchMode::Always, "Always"),
                                ],
                            );
                        });
                        let help = match settings.mode {
                            KillSwitchMode::Off => "Traffic may leave outside the VPN.",
                            KillSwitchMode::Connected => {
                                "While a connection is wanted, nothing leaves outside the tunnel, \
                                 even if it drops."
                            }
                            KillSwitchMode::Always => {
                                "Nothing ever leaves outside the tunnel. No VPN, no internet."
                            }
                        };
                        ui.label(RichText::new(help).size(11.0).color(p.muted));
                        if let Some(problem) = &problem {
                            ui.label(RichText::new(problem).size(11.0).color(p.red));
                        }
                        widgets::divider(ui);
                        let enabled = ks.mode != KillSwitchMode::Off && !self.running.killswitch;
                        widgets::row(
                            ui,
                            "Allow the local network",
                            Some("Printers and file shares keep working"),
                            |ui| {
                                widgets::toggle(ui, enabled, &mut ks.allow_lan);
                            },
                        );
                        if ks != settings {
                            if ks.mode == KillSwitchMode::Always
                                && settings.mode != KillSwitchMode::Always
                            {
                                self.confirm = Some(Confirm::Lockdown(ks));
                            } else {
                                self.set_killswitch(ui.ctx(), ks);
                            }
                        }
                    }
                });

                widgets::section(ui, "General");
                widgets::card(ui, |ui| {
                    if autostart::SUPPORTED {
                        let mut on = self.autostart;
                        widgets::row(ui, "Start in the tray at sign-in", None, |ui| {
                            if widgets::toggle(ui, true, &mut on).changed() {
                                if let Err(e) = autostart::set(on) {
                                    self.log_at(
                                        Level::Problem,
                                        format!("Could not change the start-up setting: {e}"),
                                    );
                                }
                                self.autostart = autostart::enabled();
                            }
                        });
                        widgets::divider(ui);
                    }
                    let mut notify = self.prefs.notifications;
                    widgets::row(
                        ui,
                        "Notifications",
                        Some("When the VPN connects, drops, or needs you"),
                        |ui| {
                            if widgets::toggle(ui, true, &mut notify).changed() {
                                self.prefs.notifications = notify;
                                self.save_prefs();
                            }
                        },
                    );
                    widgets::divider(ui);
                    ui.label(RichText::new("Appearance").color(p.text));
                    let mut appearance = self.prefs.appearance;
                    if widgets::segmented(
                        ui,
                        &mut appearance,
                        &[
                            (Appearance::System, "System"),
                            (Appearance::Light, "Light"),
                            (Appearance::Dark, "Dark"),
                        ],
                    ) {
                        self.set_appearance(ui.ctx(), appearance);
                    }
                });

                widgets::section(ui, "Updates");
                widgets::card(ui, |ui| {
                    let detail = match &self.update {
                        Some(version) => format!("Polytunnel {version} is available"),
                        None => "Updates install only when you choose".into(),
                    };
                    let title = format!("Polytunnel {}", polytunnel_core::VERSION);
                    widgets::row(ui, &title, Some(&detail), |ui| {
                        if let Some(version) = self.update.clone() {
                            if ui
                                .add_enabled(!self.running.update, widgets::mini(ui, "Install"))
                                .clicked()
                            {
                                self.confirm = Some(Confirm::Install(version));
                            }
                        } else if ui
                            .add_enabled(!self.running.update, widgets::mini(ui, "Check"))
                            .clicked()
                        {
                            self.running.update = true;
                            self.spawn_job(ui.ctx(), || Job::UpdateChecked(connect::update(false)));
                        }
                        if self.running.update {
                            ui.add(egui::Spinner::new());
                        }
                    });
                });

                widgets::section(ui, "Advanced");
                widgets::card(ui, |ui| {
                    if !self.link_status.is_empty() {
                        let handled = matches!(uri::status(), uri::Status::Polytunnel(_));
                        let detail = self.link_status.clone();
                        widgets::row(ui, "GlobalProtect browser sign-in", Some(&detail), |ui| {
                            let label = if handled { "Stop" } else { "Handle" };
                            if ui.add(widgets::mini(ui, label)).clicked() {
                                let result = if handled {
                                    uri::unregister()
                                } else {
                                    uri::register()
                                };
                                match result {
                                    Ok(()) if handled => self.log(
                                        "Polytunnel no longer handles GlobalProtect sign-ins (it \
                                         registers again the next time a browser sign-in needs it).",
                                    ),
                                    Ok(()) => self.log("Polytunnel now handles GlobalProtect sign-ins."),
                                    Err(e) => self.log_at(Level::Problem, format!("Could not change it: {e}")),
                                }
                                self.link_status = link_status_text();
                            }
                        });
                        widgets::divider(ui);
                    }
                    let mut trace = self.trace;
                    let file = crate::trace::file().display().to_string();
                    widgets::row(
                        ui,
                        "Troubleshooting trace",
                        Some("Passwords, codes and cookies are removed"),
                        |ui| {
                            if widgets::toggle(ui, true, &mut trace).changed() {
                                match crate::trace::set(trace) {
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
                        },
                    );
                    if self.trace {
                        ui.label(RichText::new(format!("App: {file}")).size(11.0).color(p.muted));
                        if cfg!(windows) {
                            ui.label(
                                RichText::new(r"Service: %ProgramData%\Polytunnel\trace.log")
                                    .size(11.0)
                                    .color(p.muted),
                            );
                        }
                    }
                    if std::env::var_os("POLYTUNNEL_TRACE").is_some() {
                        ui.label(
                            RichText::new("POLYTUNNEL_TRACE is set, so traces stay on.")
                                .size(11.0)
                                .color(p.amber),
                        );
                    }
                    widgets::divider(ui);
                    let (word, fg, bg, detail) = match &self.status {
                        Some(Ok(_)) => ("Running", p.green, p.green_soft, "Restarts by itself if it stops"),
                        Some(Err(_)) => ("Not running", p.red, p.red_soft, "Restart the computer or reinstall"),
                        None => ("Checking", p.muted, p.sunken, ""),
                    };
                    widgets::row(ui, "Polytunnel service", Some(detail), |ui| {
                        widgets::pill(ui, word, fg, bg);
                    });
                });
                ui.add_space(8.0);
            });
    }
}
