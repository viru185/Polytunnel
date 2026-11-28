//! The dialogs over the window, in one layout (`design/mockups.html`): an icon tile, a title,
//! a line of text, fields, and the actions in Windows order (the main one first, Cancel last).
//! Sign-in, codes, the service's questions, untrusted certificates, and confirmations. Enter
//! submits (only when filled in, and never trusts a certificate); Escape or a click outside
//! cancels.

use eframe::egui::{self, Align2, Color32, CornerRadius, Margin, Rect, Sense, Stroke, Ui, vec2};

use polytunnel_core::Secret;
use polytunnel_core::pin::CertFingerprint;
use polytunnel_http::CertInfo;

use super::icons::{self, Icon};
use super::widgets::{self, Kind as Button};
use super::{App, Confirm, Job, PromptUi, theme};
use crate::auth::{self, Trust};
use crate::connect;

/// The dialogs' frame.
fn frame(ctx: &egui::Context) -> egui::Frame {
    let p = theme::palette(ctx);
    egui::Frame::NONE
        .fill(p.dialog)
        .stroke(Stroke::new(1.0, p.line_strong))
        .corner_radius(16)
        .inner_margin(Margin {
            left: 20,
            right: 20,
            top: 24,
            bottom: 20,
        })
        .shadow(egui::Shadow {
            offset: [0, 8],
            blur: 28,
            spread: 0,
            color: p.shadow,
        })
}

/// Dialogs fill the compact window, 16 points in from each side.
fn width(ctx: &egui::Context) -> f32 {
    (ctx.content_rect().width() - 32.0 - 40.0).clamp(260.0, 360.0)
}

#[derive(Clone, Copy)]
enum Tile {
    Accent,
    Warn,
    Bad,
}

/// The icon tile, title and text at the top of a dialog.
fn head(ui: &mut Ui, tile: Tile, icon: Icon, title: &str, text: &str) {
    let p = widgets::pal(ui);
    let (ink, fill) = match tile {
        Tile::Accent => (p.accent, p.accent_soft),
        Tile::Warn => (p.amber_text, p.amber_soft),
        Tile::Bad => (p.red_text, p.red_soft),
    };
    let (rect, _) = ui.allocate_exact_size(vec2(40.0, 40.0), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::same(8), fill);
    icons::paint(
        ui.painter(),
        Rect::from_center_size(rect.center(), vec2(20.0, 20.0)),
        icon,
        ink,
    );
    ui.add_space(16.0);
    ui.add(
        egui::Label::new(
            egui::RichText::new(title)
                .font(theme::semibold(18.0))
                .color(p.text),
        )
        .wrap(),
    );
    if !text.is_empty() {
        ui.add_space(4.0);
        ui.add(egui::Label::new(egui::RichText::new(text).size(14.0).color(p.text2)).wrap());
    }
}

/// A two-column "label value" line (certificate details).
fn kv(ui: &mut Ui, label: &str, value: &str, value_ink: Option<Color32>, mono: bool) {
    let p = widgets::pal(ui);
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 12.0;
        let (r, _) = ui.allocate_exact_size(vec2(84.0, 20.0), Sense::hover());
        ui.painter().text(
            r.left_center(),
            Align2::LEFT_CENTER,
            label,
            theme::regular(14.0),
            p.text3,
        );
        let text = egui::RichText::new(value).color(value_ink.unwrap_or(p.text));
        let text = if mono {
            text.font(theme::mono(12.0))
        } else {
            text.size(14.0)
        };
        ui.add(egui::Label::new(text).wrap());
    });
}

/// A fingerprint as four lines of eight bytes, to fit the dialog.
fn fingerprint_lines(fingerprint: &CertFingerprint) -> String {
    fingerprint
        .digest()
        .chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        })
        .collect::<Vec<_>>()
        .join(":\n")
}

/// `8D:3D:41:78 … CC:AD:68`.
fn short_fingerprint(fingerprint: &CertFingerprint) -> String {
    let hex = fingerprint.colon_hex();
    let parts: Vec<&str> = hex.split(':').collect();
    format!(
        "{} … {}",
        parts[..4].join(":"),
        parts[parts.len() - 3..].join(":")
    )
}

/// The fingerprint box: label, four lines of colon hex, and Copy.
fn fingerprint_box(ui: &mut Ui, fingerprint: &CertFingerprint) {
    let p = widgets::pal(ui);
    egui::Frame::NONE
        .fill(p.surface2)
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(8)
        .inner_margin(Margin {
            left: 12,
            right: 4,
            top: 8,
            bottom: 8,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.label(
                        egui::RichText::new("SHA-256 fingerprint")
                            .font(theme::semibold(12.0))
                            .color(p.text2),
                    );
                    ui.label(
                        egui::RichText::new(fingerprint_lines(fingerprint))
                            .font(theme::mono(12.0))
                            .color(p.text),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                    if widgets::icon_button(ui, Icon::Copy, "Copy the fingerprint", 32.0, None)
                        .clicked()
                    {
                        ui.ctx().copy_text(fingerprint.colon_hex());
                    }
                });
            });
        });
}

/// What "Copy details" copies, as plain text: the gateway, the issuer, the validity and the
/// fingerprints.
fn certificate_details(
    server: &str,
    info: &CertInfo,
    previous: Option<&CertFingerprint>,
) -> String {
    let (dates, warning) = auth::certificate_dates(info);
    let mut lines = vec![
        format!("Gateway: {server}"),
        format!("Issued by: {}", auth::certificate_issuer(info)),
        match warning {
            Some(warning) => format!("Valid: {dates} ({warning})"),
            None => format!("Valid: {dates}"),
        },
    ];
    match previous {
        Some(previous) => {
            lines.push(format!(
                "Previously trusted SHA-256: {}",
                previous.colon_hex()
            ));
            lines.push(format!("New SHA-256: {}", info.fingerprint.colon_hex()));
        }
        None => lines.push(format!("SHA-256: {}", info.fingerprint.colon_hex())),
    }
    lines.join("\n") + "\n"
}

/// The untrusted-certificate dialog (`previous`: the certificate trusted before, when this
/// one replaces it); the user's choice once made. Cancel has the keyboard focus first, and
/// Enter means Cancel unless a trust button was given the focus. No trust button is drawn as
/// the default action.
fn certificate_dialog(
    ui: &mut Ui,
    server: &str,
    info: &CertInfo,
    previous: Option<&CertFingerprint>,
    focused: &mut bool,
    enter: bool,
    can_save: bool,
) -> Option<Trust> {
    let p = widgets::pal(ui);
    let (dates, warning) = auth::certificate_dates(info);
    match previous {
        Some(previous) => {
            head(
                ui,
                Tile::Bad,
                Icon::Warning,
                "This certificate changed",
                &format!(
                    "{server} sends a different certificate from the one you trusted. That's \
                     normal after a renewal, but it can also mean someone is intercepting the \
                     connection. Check with IT first."
                ),
            );
            ui.add_space(16.0);
            ui.spacing_mut().item_spacing.y = 8.0;
            let full_key = egui::Id::unique("cert-show-full");
            let full = ui.data(|d| d.get_temp::<bool>(full_key).unwrap_or(false));
            if full {
                kv(ui, "Trusted", &fingerprint_lines(previous), None, true);
                kv(
                    ui,
                    "Now",
                    &fingerprint_lines(&info.fingerprint),
                    Some(p.red_text),
                    true,
                );
            } else {
                kv(ui, "Trusted", &short_fingerprint(previous), None, true);
                kv(
                    ui,
                    "Now",
                    &short_fingerprint(&info.fingerprint),
                    Some(p.red_text),
                    true,
                );
            }
            kv(
                ui,
                "Issued by",
                &auth::certificate_issuer(info),
                None,
                false,
            );
            kv(ui, "Valid", &dates, None, false);
            if let Some(warning) = &warning {
                kv(ui, "", warning, Some(p.red_text), false);
            }
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.add_space(-12.0);
                if widgets::link(ui, if full { "Show less" } else { "Show full" }, true, None)
                    .clicked()
                {
                    ui.data_mut(|d| d.insert_temp(full_key, !full));
                }
                if widgets::link(ui, "Copy details for IT", true, Some(Icon::Copy)).clicked() {
                    ui.ctx()
                        .copy_text(certificate_details(server, info, Some(previous)));
                }
            });
        }
        None => {
            head(
                ui,
                Tile::Warn,
                Icon::Rosette,
                "Check this certificate",
                &format!(
                    "{server} sent a certificate this PC doesn't trust. Trust it only if your IT \
                     team confirms it's theirs."
                ),
            );
            ui.add_space(16.0);
            ui.spacing_mut().item_spacing.y = 8.0;
            let subject = info.subject.summary();
            kv(
                ui,
                "Issued to",
                if subject.is_empty() {
                    "Not named"
                } else {
                    &subject
                },
                None,
                false,
            );
            let mut issuer = auth::certificate_issuer(info);
            if info.self_signed && !issuer.contains("self-signed") {
                issuer.push_str(" (self-signed)");
            }
            kv(ui, "Issued by", &issuer, None, false);
            kv(ui, "Valid", &dates, None, false);
            if let Some(warning) = &warning {
                kv(ui, "", warning, Some(p.red_text), false);
            }
            ui.add_space(8.0);
            fingerprint_box(ui, &info.fingerprint);
        }
    }
    ui.add_space(16.0);
    ui.spacing_mut().item_spacing.y = 8.0;
    let trust = if previous.is_some() {
        "Trust the new one"
    } else {
        "Always trust"
    };
    let always = ui
        .add_enabled_ui(can_save, |ui| {
            widgets::button_block(ui, Button::Secondary, trust, None)
        })
        .inner
        .on_disabled_hover_text(
            "The profiles file could not be read, so nothing can be saved in it.",
        );
    let once = widgets::button_block(ui, Button::Secondary, "Trust once", None);
    let cancel = widgets::button_block(ui, Button::Secondary, "Cancel", None);
    if !*focused {
        cancel.request_focus();
        *focused = true;
    }
    let trust_focused = always.has_focus() || once.has_focus();
    if always.clicked() || (enter && always.has_focus()) {
        Some(Trust::Always)
    } else if once.clicked() || (enter && once.has_focus()) {
        Some(Trust::Once)
    } else if cancel.clicked() || (enter && !trust_focused) {
        Some(Trust::Cancel)
    } else {
        None
    }
}

/// The action row, right-aligned: the main button first, then the others (Windows order).
/// Returns which was pressed (0 = main).
fn actions(ui: &mut Ui, main: (&str, Button, bool), others: &[&str]) -> Option<usize> {
    let mut pressed = None;
    ui.add_space(24.0);
    ui.allocate_ui_with_layout(
        vec2(ui.available_width(), 36.0),
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            for (i, label) in others.iter().enumerate().rev() {
                if widgets::button(ui, Button::Secondary, label, None, false).clicked() {
                    pressed = Some(i + 1);
                }
            }
            ui.add_enabled_ui(main.2, |ui| {
                if widgets::button(ui, main.1, main.0, None, false).clicked() {
                    pressed = Some(0);
                }
            });
        },
    );
    pressed
}

impl App {
    pub(super) fn prompts(&mut self, ctx: &egui::Context) {
        let mut close = false;
        let w = width(ctx);
        let can_save = !self.read_only();
        if let Some(prompt) = &mut self.prompt {
            let modal = egui::Modal::new(egui::Id::unique("prompt"))
                .frame(frame(ctx))
                .backdrop_color(theme::palette(ctx).scrim)
                .show(ctx, |ui| {
                    ui.set_width(w);
                    ui.spacing_mut().item_spacing.y = 0.0;
                    let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                    match prompt {
                        PromptUi::Credentials {
                            title,
                            message,
                            username_label,
                            password_label,
                            username,
                            password,
                            reply,
                            focused,
                        } => {
                            // A message starting with "!" is the previous try's rejection.
                            let (sub, error) = match message.as_deref() {
                                Some(m) if m.starts_with('!') => {
                                    (String::new(), Some(m[1..].to_string()))
                                }
                                Some(m) => (m.to_string(), None),
                                None => (String::new(), None),
                            };
                            head(ui, Tile::Accent, Icon::User, title, &sub);
                            ui.add_space(16.0);
                            let user = widgets::Field::new(username_label).show(ui, username);
                            ui.add_space(16.0);
                            let pass = widgets::Field::new(password_label)
                                .secret()
                                .error(error.as_deref())
                                .show(ui, password);
                            if !*focused {
                                if username.is_empty() {
                                    user.request_focus();
                                } else {
                                    pass.request_focus();
                                }
                                *focused = true;
                            }
                            let ready = !username.trim().is_empty() && !password.is_empty();
                            let answer =
                                actions(ui, ("Sign in", Button::Primary, ready), &["Cancel"]);
                            if answer == Some(0) || (ready && enter) {
                                let _ = reply.send(Some((
                                    username.trim().to_string(),
                                    Secret::new(std::mem::take(password)),
                                )));
                                close = true;
                            } else if answer == Some(1) {
                                let _ = reply.send(None);
                                close = true;
                            }
                        }
                        PromptUi::Code {
                            title,
                            message,
                            code,
                            reply,
                            focused,
                        } => {
                            head(ui, Tile::Accent, Icon::Key, title, message);
                            ui.add_space(16.0);
                            let field = widgets::Field::new("Code").secret().show(ui, code);
                            if !*focused {
                                field.request_focus();
                                *focused = true;
                            }
                            let ready = !code.trim().is_empty();
                            let answer =
                                actions(ui, ("Continue", Button::Primary, ready), &["Cancel"]);
                            if answer == Some(0) || (ready && enter) {
                                let _ = reply.send(Some(Secret::new(std::mem::take(code))));
                                close = true;
                            } else if answer == Some(1) {
                                let _ = reply.send(None);
                                close = true;
                            }
                        }
                        PromptUi::Fields {
                            title,
                            message,
                            fields,
                            reply,
                            focused,
                        } => {
                            let key = fields.iter().any(|(_, secret, _)| *secret);
                            head(
                                ui,
                                Tile::Accent,
                                if key { Icon::Lock } else { Icon::User },
                                title,
                                message,
                            );
                            for (i, (name, secret, value)) in fields.iter_mut().enumerate() {
                                ui.add_space(16.0);
                                let mut field = widgets::Field::new(name);
                                if *secret {
                                    field = field.secret();
                                }
                                let response = field.show(ui, value);
                                if i == 0 && !*focused {
                                    response.request_focus();
                                    *focused = true;
                                }
                            }
                            let ready = fields.iter().all(|(_, _, v)| !v.trim().is_empty());
                            let answer =
                                actions(ui, ("Connect", Button::Primary, ready), &["Cancel"]);
                            if answer == Some(0) || (ready && enter) {
                                let values = fields
                                    .iter_mut()
                                    .map(|(_, _, v)| Secret::new(std::mem::take(v)))
                                    .collect();
                                let _ = reply.send(Some(values));
                                close = true;
                            } else if answer == Some(1) {
                                let _ = reply.send(None);
                                close = true;
                            }
                        }
                        PromptUi::Certificate {
                            server,
                            info,
                            previous,
                            reply,
                            focused,
                        } => {
                            if let Some(choice) = certificate_dialog(
                                ui,
                                server,
                                info,
                                previous.as_ref(),
                                focused,
                                enter,
                                can_save,
                            ) {
                                let _ = reply.send(choice);
                                close = true;
                            }
                        }
                    }
                });
            // Escape (or a click outside) cancels.
            if modal.should_close() && !close {
                match prompt {
                    PromptUi::Credentials { reply, .. } => {
                        let _ = reply.send(None);
                    }
                    PromptUi::Code { reply, .. } => {
                        let _ = reply.send(None);
                    }
                    PromptUi::Fields { reply, .. } => {
                        let _ = reply.send(None);
                    }
                    PromptUi::Certificate { reply, .. } => {
                        let _ = reply.send(Trust::Cancel);
                    }
                }
                close = true;
            }
        }
        if close {
            self.prompt = None;
        }
    }

    pub(super) fn confirmations(&mut self, ctx: &egui::Context) {
        let Some(confirm) = &self.confirm else {
            return;
        };
        let (tile, icon, title, text, main, main_kind, others): (
            Tile,
            Icon,
            String,
            String,
            &str,
            Button,
            Vec<&str>,
        ) = match confirm {
            Confirm::Delete(name) => (
                Tile::Bad,
                Icon::Trash,
                format!("Delete {name}?"),
                "This removes the profile and its trusted certificates. It can't be undone.".into(),
                "Delete",
                Button::Danger,
                vec!["Cancel"],
            ),
            Confirm::Lockdown(_) => (
                Tile::Warn,
                Icon::Lock,
                "Turn on lockdown?".into(),
                "Nothing reaches the internet unless the VPN is connected, even when \
                     Polytunnel isn't running. Hotel and airport Wi-Fi sign-in pages won't load, \
                     and browser sign-in uses Polytunnel's own window.\n\nTurn it off in Settings \
                     or from the tray menu."
                    .into(),
                "Turn on lockdown",
                Button::Primary,
                vec!["Cancel"],
            ),
            Confirm::Install(version) => (
                Tile::Accent,
                Icon::Download,
                format!("Install Polytunnel {version}?"),
                "The VPN disconnects and Polytunnel closes while the update installs, then \
                     it reopens by itself."
                    .into(),
                "Install",
                Button::Primary,
                vec!["Cancel"],
            ),
            Confirm::Discard(_) => {
                let name = self
                    .editor
                    .as_ref()
                    .map(|e| e.original.clone().unwrap_or_else(|| e.name.clone()))
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| "this profile".into());
                (
                    Tile::Accent,
                    Icon::Edit,
                    format!("Save changes to {name}?"),
                    "The form has changes that aren't saved.".into(),
                    "Save",
                    Button::Primary,
                    vec!["Don't save", "Cancel"],
                )
            }
            Confirm::QuitLockdown => (
                Tile::Warn,
                Icon::Lock,
                "Quit with lockdown on?".into(),
                "The internet stays blocked until Polytunnel runs again or lockdown is turned \
                     off."
                    .into(),
                "Quit",
                Button::Primary,
                vec!["Cancel"],
            ),
        };
        let w = width(ctx);
        let mut answer = None;
        let modal = egui::Modal::new(egui::Id::unique("confirm"))
            .frame(frame(ctx))
            .backdrop_color(theme::palette(ctx).scrim)
            .show(ctx, |ui| {
                ui.set_width(w);
                ui.spacing_mut().item_spacing.y = 0.0;
                head(ui, tile, icon, &title, &text);
                answer = actions(ui, (main, main_kind, true), &others);
            });
        let cancel_index = others.len();
        if modal.should_close() && answer.is_none() {
            answer = Some(cancel_index);
        }
        let Some(answer) = answer else {
            return;
        };
        let Some(confirm) = self.confirm.take() else {
            return;
        };
        match (confirm, answer) {
            (Confirm::Delete(name), 0) => self.delete_profile(&name),
            (Confirm::Lockdown(settings), 0) => {
                if self.fake {
                    if let Some(state) = &mut self.killswitch {
                        state.0 = settings;
                    }
                } else {
                    self.set_killswitch(ctx, settings);
                }
            }
            (Confirm::Install(_), 0) => {
                self.running.update = true;
                self.spawn_job(ctx, || Job::UpdateStarted(connect::update(true)));
            }
            (Confirm::Discard(_), 0) => {
                let new = self.editor.as_ref().is_some_and(|e| e.original.is_none());
                self.save_editor(ctx, false);
                let _ = new;
            }
            (Confirm::Discard(leave), 1) => self.do_leave(leave),
            (Confirm::QuitLockdown, 0) => self.quit_all(ctx),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_shown_in_four_lines() {
        let pin: CertFingerprint = "0123456789abcdef".repeat(4).parse().unwrap();
        let lines = fingerprint_lines(&pin);
        assert_eq!(lines.lines().count(), 4);
        assert_eq!(lines.replace('\n', ""), pin.colon_hex());
        assert!(short_fingerprint(&pin).contains(" … "));
    }

    #[test]
    fn copied_details_name_the_gateway_issuer_dates_and_both_fingerprints() {
        let old: CertFingerprint = "11".repeat(32).parse().unwrap();
        let new: CertFingerprint = "22".repeat(32).parse().unwrap();
        let info = CertInfo {
            fingerprint: new,
            subject: Default::default(),
            issuer: polytunnel_http::x509::CertName {
                common_name: Some("Example Test CA".into()),
                ..Default::default()
            },
            not_before: Some("2024-01-01".into()),
            not_after: Some("2999-12-31".into()),
            dns_names: Vec::new(),
            self_signed: false,
        };
        let text = certificate_details("fw.example.net:10443", &info, Some(&old));
        assert_eq!(
            text,
            format!(
                "Gateway: fw.example.net:10443\nIssued by: Example Test CA\n\
                 Valid: 2024-01-01 to 2999-12-31\nPreviously trusted SHA-256: {}\n\
                 New SHA-256: {}\n",
                old.colon_hex(),
                new.colon_hex()
            )
        );
        assert!(certificate_details("fw.example.net:10443", &info, None).contains("\nSHA-256: "));
    }
}
