//! The profile form: one screen for the three VPN types, with Save at the bottom.

use eframe::egui::{self, Align, Layout, RichText, TextEdit};

use crate::gui::icons::Icon;
use crate::gui::widgets::{self, Tone};
use crate::gui::{App, Confirm, Editor, Kind, Leave};

/// A labelled one-line text field as wide as the space.
fn field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    let p = widgets::pal(ui);
    ui.label(RichText::new(label).size(11.0).strong().color(p.muted));
    ui.add(
        TextEdit::singleline(value)
            .hint_text(hint)
            .desired_width(f32::INFINITY),
    );
}

/// The editable list of backup gateways: edit, move up or down, remove, add.
fn backup_list(ui: &mut egui::Ui, backups: &mut Vec<String>) {
    let p = widgets::pal(ui);
    let count = backups.len();
    let mut action: Option<(usize, i8)> = None;
    for (i, gateway) in backups.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("{}", i + 2))
                    .size(11.0)
                    .color(p.muted),
            );
            let buttons = 3.0 * 30.0 + 3.0 * ui.spacing().item_spacing.x;
            ui.add(
                TextEdit::singleline(gateway)
                    .hint_text("host or host:port")
                    .desired_width((ui.available_width() - buttons).max(80.0)),
            );
            if widgets::icon_button_sized(ui, Icon::Up, "Try earlier", 30.0, i > 0).clicked() {
                action = Some((i, -1));
            }
            if widgets::icon_button_sized(ui, Icon::Down, "Try later", 30.0, i + 1 < count)
                .clicked()
            {
                action = Some((i, 1));
            }
            if widgets::icon_button_sized(ui, Icon::Close, "Remove", 30.0, true).clicked() {
                action = Some((i, 0));
            }
        });
    }
    match action {
        Some((i, 0)) => {
            backups.remove(i);
        }
        Some((i, -1)) => backups.swap(i, i - 1),
        Some((i, _)) => backups.swap(i, i + 1),
        None => {}
    }
    if backups.len() < 16
        && ui
            .add(widgets::mini(ui, "+ Add a backup gateway"))
            .clicked()
    {
        backups.push(String::new());
    }
}

impl App {
    pub(in crate::gui) fn editor_screen(&mut self, ui: &mut egui::Ui) {
        let p = widgets::pal(ui);
        let new = self.editor.as_ref().is_some_and(|e| e.original.is_none());
        ui.horizontal(|ui| {
            if widgets::icon_button(ui, Icon::Back, "Back to the profiles").clicked() {
                self.leave_editor(Leave::Close);
            }
            ui.heading(if new { "New profile" } else { "Edit profile" });
        });
        ui.add_space(6.0);
        let Some(editor) = &mut self.editor else {
            return;
        };
        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 6.0;
                if editor.original.is_none() {
                    let mut kind = editor.kind;
                    if widgets::segmented(
                        ui,
                        &mut kind,
                        &[
                            (Kind::GlobalProtect, "GlobalProtect"),
                            (Kind::FortinetSsl, "Fortinet SSL"),
                            (Kind::FortinetIpsec, "IPsec"),
                        ],
                    ) {
                        let (name, username) = (editor.name.clone(), editor.username.clone());
                        *editor = Editor {
                            name,
                            username,
                            ..Editor::new(kind)
                        };
                    }
                }
                ui.columns_const(|[a, b]| {
                    field(a, "Name", &mut editor.name, "work");
                    field(b, "Username", &mut editor.username, "Ask each time");
                });
                match editor.kind {
                    Kind::GlobalProtect => {
                        field(ui, "Portal", &mut editor.server, "vpn.example.com");
                        if crate::embedded::helper().is_some() {
                            ui.label(
                                RichText::new("Sign in with")
                                    .size(11.0)
                                    .strong()
                                    .color(p.muted),
                            );
                            ui.radio_value(
                                &mut editor.embedded,
                                false,
                                "Your browser (single sign-on)",
                            );
                            ui.radio_value(
                                &mut editor.embedded,
                                true,
                                "Polytunnel's sign-in window",
                            );
                        }
                        if widgets::fold(ui, "editor-gp-advanced", "Advanced", None) {
                            field(ui, "Always use gateway", &mut editor.gateway, "Any");
                            field(ui, "Preferred gateway", &mut editor.preferred, "None");
                            ui.checkbox(
                                &mut editor.strict_tiers,
                                "Rank by the portal's priority first",
                            );
                            ui.checkbox(&mut editor.tcp_probe, "Measure with TCP instead of TLS");
                        }
                    }
                    Kind::FortinetSsl | Kind::FortinetIpsec => {
                        let ipsec = editor.kind == Kind::FortinetIpsec;
                        field(
                            ui,
                            "Gateway",
                            &mut editor.server,
                            if ipsec {
                                "198.51.100.7"
                            } else {
                                "vpn.example.com:10443"
                            },
                        );
                        ui.label(
                            RichText::new(
                                "Backup gateways are tried in order when the one above cannot be \
                                 reached. A wrong password stops there.",
                            )
                            .size(11.0)
                            .color(p.muted),
                        );
                        backup_list(ui, &mut editor.backups);
                        if ipsec {
                            ui.add_space(4.0);
                            ui.label(RichText::new("IKE").size(11.0).strong().color(p.muted));
                            widgets::segmented(
                                ui,
                                &mut editor.ike2,
                                &[(false, "IKEv1 + XAuth"), (true, "IKEv2 + EAP")],
                            );
                            if editor.ike2 {
                                ui.checkbox(
                                    &mut editor.eap,
                                    "Sign in with username and password (EAP)",
                                );
                            } else {
                                ui.checkbox(
                                    &mut editor.xauth,
                                    "Sign in with username and password (XAuth)",
                                );
                            }
                            ui.checkbox(&mut editor.pfs, "Perfect forward secrecy");
                            ui.label(
                                RichText::new(
                                    "The pre-shared key is asked when you connect and never saved.",
                                )
                                .size(11.0)
                                .color(p.muted),
                            );
                            if widgets::fold(ui, "editor-ipsec-advanced", "Advanced", None) {
                                ui.columns_const(|[a, b]| {
                                    field(a, "DH group", &mut editor.dh_group, "14");
                                    field(b, "Local ID", &mut editor.local_id, "This computer");
                                });
                                if editor.ike2 {
                                    ui.checkbox(&mut editor.tcp, "IPsec over TCP (port 443)");
                                }
                            }
                        } else if widgets::fold(ui, "editor-ssl-advanced", "Advanced", None) {
                            field(ui, "Realm", &mut editor.realm, "None");
                            field(
                                ui,
                                "Trusted certificate (SHA-256)",
                                &mut editor.server_cert,
                                "The system decides",
                            );
                        }
                    }
                }
                if let Some(e) = editor.error.clone() {
                    widgets::banner(ui, Tone::Error, "", &e);
                }
            });
    }

    /// The bar at the bottom of the form: Delete, Cancel, Save.
    pub(in crate::gui) fn editor_footer(&mut self, ui: &mut egui::Ui) {
        let existing = self.editor.as_ref().and_then(|e| e.original.clone());
        ui.horizontal(|ui| {
            if let Some(name) = existing
                && ui.add(widgets::danger(ui, "Delete…")).clicked()
            {
                self.confirm = Some(Confirm::Delete(name));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(widgets::primary(ui, "Save")).clicked() {
                    self.save_editor();
                }
                if ui.add(widgets::secondary(ui, "Cancel")).clicked() {
                    self.leave_editor(Leave::Close);
                }
            });
        });
    }
}
