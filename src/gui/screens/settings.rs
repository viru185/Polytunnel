//! Settings: one scrolling page of cards that apply at once — Protection, Startup,
//! Notifications, Appearance, Updates, Troubleshooting, About, and Quit.

use eframe::egui::{self, Ui};
use polytunnel_core::ipc::{KillSwitchMode, KillSwitchSettings};

use super::body;
use crate::gui::icons::Icon;
use crate::gui::prefs::Appearance;
use crate::gui::widgets::{self, Kind as Button, Tone};
use crate::gui::{App, Confirm, Job, Level, Page};
use crate::{autostart, connect, uri};

/// The kill switch's state in a word, with its tone.
fn killswitch_word(
    settings: &KillSwitchSettings,
    active: bool,
    problem: Option<&str>,
) -> (&'static str, Tone) {
    match (settings.mode, active, problem) {
        (_, _, Some(_)) => ("Problem", Tone::Bad),
        (KillSwitchMode::Off, _, _) => ("Off", Tone::Mute),
        (KillSwitchMode::Always, _, _) => ("Lockdown", Tone::Warn),
        (KillSwitchMode::Connected, true, _) => ("Protecting", Tone::Good),
        (KillSwitchMode::Connected, false, _) => ("Ready", Tone::Mute),
    }
}

enum Do {
    KillSwitch(KillSwitchSettings),
    Autostart(bool),
    Notifications(bool),
    Appearance(Appearance),
    Check,
    Install(String),
    Links(bool),
    Activity,
    Source,
    Quit,
}

impl App {
    pub(in crate::gui) fn settings_page(&mut self, ui: &mut Ui) {
        if widgets::page_header(ui, "Settings", "", |_| {}) {
            self.back();
            return;
        }
        let mut todo = Vec::new();
        let killswitch = self.killswitch.clone();
        let running_ks = self.running.killswitch;
        let mut autostart_on = self.autostart;
        let mut notify = self.prefs.notifications;
        let mut appearance = self.prefs.appearance;
        let update = self.update.clone();
        let running_update = self.running.update;
        let service = self.status.clone();
        let links = matches!(uri::status(), uri::Status::Polytunnel(_));
        let links_supported = !self.link_status.is_empty();
        body(ui, "settings", |ui| {
            let p = widgets::pal(ui);
            // Protection
            match &killswitch {
                None => {
                    widgets::section(ui, "Protection", None);
                    widgets::card(ui, true, |ui| {
                        ui.label(egui::RichText::new("Kill switch").strong());
                        widgets::help(
                            ui,
                            "Unavailable while the Polytunnel service isn't running.",
                        );
                    });
                }
                Some((settings, active, problem)) => {
                    let (word, tone) = killswitch_word(settings, *active, problem.as_deref());
                    let mut right = |ui: &mut Ui| {
                        widgets::pill(ui, word, tone);
                    };
                    widgets::section(ui, "Protection", Some(&mut right));
                    widgets::card(ui, false, |ui| {
                        egui::Frame::NONE
                            .inner_margin(egui::Margin {
                                left: 16,
                                right: 16,
                                top: 12,
                                bottom: 4,
                            })
                            .show(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = 2.0;
                                ui.label(
                                    egui::RichText::new("Kill switch")
                                        .font(crate::gui::theme::semibold(14.0))
                                        .color(p.text),
                                );
                                ui.label(
                                    egui::RichText::new("Keeps traffic inside the VPN.")
                                        .size(12.0)
                                        .color(p.text2),
                                );
                            });
                        let mut ks = *settings;
                        ui.add_enabled_ui(!running_ks, |ui| {
                            for (mode, title, desc) in [
                                (KillSwitchMode::Off, "Off", "Traffic can leave outside the VPN."),
                                (
                                    KillSwitchMode::Connected,
                                    "While connected",
                                    "If the VPN drops, nothing leaves until it's back or you disconnect.",
                                ),
                                (
                                    KillSwitchMode::Always,
                                    "Always (lockdown)",
                                    "No VPN, no internet, even when Polytunnel isn't running.",
                                ),
                            ] {
                                if widgets::radio_row(ui, ks.mode == mode, title, None, Some(desc), !running_ks, false, false)
                                    .clicked()
                                {
                                    ks.mode = mode;
                                }
                            }
                            let lan_enabled = ks.mode != KillSwitchMode::Off && !running_ks;
                            widgets::toggle_row(
                                ui,
                                "Allow the local network",
                                Some(if ks.mode == KillSwitchMode::Off {
                                    "Turn on the kill switch to use this"
                                } else {
                                    "Printers and file shares keep working"
                                }),
                                lan_enabled,
                                &mut ks.allow_lan,
                                false,
                                true,
                            );
                        });
                        if let Some(problem) = problem {
                            egui::Frame::NONE
                                .inner_margin(egui::Margin::symmetric(16, 8))
                                .show(ui, |ui| {
                                    ui.label(
                                        egui::RichText::new(problem).size(12.0).color(p.red_text),
                                    );
                                });
                        }
                        if ks != *settings {
                            todo.push(Do::KillSwitch(ks));
                        }
                    });
                }
            }
            // Startup
            if autostart::SUPPORTED {
                widgets::section(ui, "Startup", None);
                widgets::card(ui, false, |ui| {
                    if widgets::toggle_row(
                        ui,
                        "Start in the tray when I sign in",
                        Some("Waits quietly until you connect"),
                        true,
                        &mut autostart_on,
                        true,
                        true,
                    ) {
                        todo.push(Do::Autostart(autostart_on));
                    }
                });
            }
            // Notifications
            widgets::section(ui, "Notifications", None);
            widgets::card(ui, false, |ui| {
                if widgets::toggle_row(
                    ui,
                    "Connected and disconnected",
                    Some("Problems are always shown"),
                    true,
                    &mut notify,
                    true,
                    true,
                ) {
                    todo.push(Do::Notifications(notify));
                }
            });
            // Appearance
            widgets::section(ui, "Appearance", None);
            widgets::card(ui, true, |ui| {
                if widgets::segmented(
                    ui,
                    &mut appearance,
                    &[
                        (Appearance::System, "System"),
                        (Appearance::Light, "Light"),
                        (Appearance::Dark, "Dark"),
                    ],
                ) {
                    todo.push(Do::Appearance(appearance));
                }
            });
            // Updates
            widgets::section(ui, "Updates", None);
            widgets::card(ui, false, |ui| {
                let detail = match &update {
                    Some(version) => format!("Polytunnel {version} is available"),
                    None => "Updates install only when you choose".into(),
                };
                widgets::setting_row(
                    ui,
                    &format!("Polytunnel {}", polytunnel_core::VERSION),
                    Some(&detail),
                    true,
                    |ui| {
                        if running_update {
                            ui.add(egui::Spinner::new());
                        } else if let Some(version) = update.clone() {
                            if widgets::button(ui, Button::Secondary, "Install", None, true)
                                .clicked()
                            {
                                todo.push(Do::Install(version));
                            }
                        } else if widgets::button(ui, Button::Secondary, "Check", None, true)
                            .clicked()
                        {
                            todo.push(Do::Check);
                        }
                    },
                );
            });
            // Troubleshooting
            widgets::section(ui, "Troubleshooting", None);
            widgets::card(ui, false, |ui| {
                let (word, tone, detail) = match &service {
                    Some(Ok(_)) => ("Running", Tone::Good, "Restarts by itself if it stops"),
                    Some(Err(_)) => (
                        "Not running",
                        Tone::Bad,
                        "Restart the PC or reinstall Polytunnel",
                    ),
                    None => ("Checking", Tone::Mute, ""),
                };
                widgets::setting_row(ui, "Polytunnel service", Some(detail), true, |ui| {
                    widgets::pill(ui, word, tone);
                });
                if links_supported {
                    let mut on = links;
                    if widgets::toggle_row(
                        ui,
                        "Sign-in links from your browser",
                        Some(
                            "Browser sign-in hands its result to Polytunnel. Turning this off stops browser sign-in.",
                        ),
                        true,
                        &mut on,
                        false,
                        false,
                    ) {
                        todo.push(Do::Links(on));
                    }
                }
                if widgets::link_row(
                    ui,
                    "Activity, report and trace",
                    None,
                    Icon::ChevronRight,
                    false,
                    true,
                )
                .clicked()
                {
                    todo.push(Do::Activity);
                }
            });
            // About
            widgets::section(ui, "About", None);
            widgets::card(ui, false, |ui| {
                if widgets::link_row(
                    ui,
                    "Source code and license",
                    Some("MIT License · github.com/viru185/Polytunnel"),
                    Icon::External,
                    true,
                    true,
                )
                .clicked()
                {
                    todo.push(Do::Source);
                }
            });
            ui.add_space(24.0);
            widgets::card(ui, false, |ui| {
                let (rect, response) =
                    widgets::row_frame(ui, 56.0, true, true, egui::Sense::click());
                crate::gui::icons::paint(
                    ui.painter(),
                    egui::Rect::from_min_size(
                        rect.left_center() + egui::vec2(16.0, -10.0),
                        egui::vec2(20.0, 20.0),
                    ),
                    Icon::Power,
                    p.red_text,
                );
                ui.painter().text(
                    rect.left_center() + egui::vec2(48.0, -9.0),
                    egui::Align2::LEFT_CENTER,
                    "Quit Polytunnel",
                    crate::gui::theme::semibold(14.0),
                    p.red_text,
                );
                ui.painter().text(
                    rect.left_center() + egui::vec2(48.0, 10.0),
                    egui::Align2::LEFT_CENTER,
                    "Disconnects and closes the tray icon",
                    crate::gui::theme::regular(12.0),
                    p.text3,
                );
                if response.clicked() {
                    todo.push(Do::Quit);
                }
            });
        });
        let ctx = ui.ctx().clone();
        for action in todo {
            match action {
                Do::KillSwitch(ks) => {
                    let was_always = self
                        .killswitch
                        .as_ref()
                        .is_some_and(|(s, _, _)| s.mode == KillSwitchMode::Always);
                    if ks.mode == KillSwitchMode::Always && !was_always {
                        self.confirm = Some(Confirm::Lockdown(ks));
                    } else if self.fake {
                        if let Some(state) = &mut self.killswitch {
                            state.0 = ks;
                        }
                    } else {
                        self.set_killswitch(&ctx, ks);
                    }
                }
                Do::Autostart(on) => {
                    if !self.fake {
                        if let Err(e) = autostart::set(on) {
                            self.log_at(
                                Level::Problem,
                                format!("Could not change the start-up setting: {e}"),
                            );
                        }
                        self.autostart = autostart::enabled();
                    } else {
                        self.autostart = on;
                    }
                }
                Do::Notifications(on) => {
                    self.prefs.notifications = on;
                    self.save_prefs();
                }
                Do::Appearance(a) => self.set_appearance(&ctx, a),
                Do::Check => {
                    self.running.update = true;
                    self.spawn_job(&ctx, || Job::UpdateChecked(connect::update(false)));
                }
                Do::Install(version) => self.confirm = Some(Confirm::Install(version)),
                Do::Links(on) => {
                    let result = if on {
                        uri::register()
                    } else {
                        uri::unregister()
                    };
                    match result {
                        Ok(()) if on => self.log("Polytunnel now receives browser sign-in links."),
                        Ok(()) => self.log("Polytunnel no longer receives browser sign-in links."),
                        Err(e) => self.log_at(Level::Problem, format!("Could not change it: {e}")),
                    }
                    self.link_status = crate::gui::link_status_text();
                }
                Do::Activity => self.go(Page::Activity),
                Do::Source => {
                    let _ = crate::browser::open("https://github.com/viru185/Polytunnel");
                }
                Do::Quit => {
                    let lockdown = self
                        .killswitch
                        .as_ref()
                        .is_some_and(|(s, _, _)| s.mode == KillSwitchMode::Always);
                    if lockdown {
                        self.confirm = Some(Confirm::QuitLockdown);
                    } else {
                        self.quit_all(&ctx);
                    }
                }
            }
        }
    }
}
