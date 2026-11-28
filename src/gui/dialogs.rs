//! The dialogs over the window: sign-in, codes, the service's questions, untrusted
//! certificates, browser sign-in, and confirmations. Enter submits (only when filled in, and
//! never trusts a certificate); Escape or a click outside cancels.

use eframe::egui::{self, Label, Margin, RichText, Stroke, TextEdit};

use polytunnel_core::Secret;
use polytunnel_core::pin::CertFingerprint;
use polytunnel_http::CertInfo;

use super::widgets::{self, Tone};
use super::{App, Confirm, Job, PromptUi};
use crate::auth::{self, Trust};
use crate::connect;

/// The dialogs' frame: the surface colour with a border, rounded.
fn frame(ctx: &egui::Context) -> egui::Frame {
    let p = super::theme::palette(ctx);
    egui::Frame::NONE
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border_strong))
        .corner_radius(14)
        .inner_margin(Margin::same(16))
}

/// Dialogs fit the compact window.
fn width(ctx: &egui::Context) -> f32 {
    (ctx.content_rect().width() - 48.0).clamp(240.0, 340.0)
}

fn label(ui: &mut egui::Ui, text: &str) {
    let p = widgets::pal(ui);
    ui.label(RichText::new(text).size(11.0).strong().color(p.muted));
}

/// A value under a [`label`], wrapped.
fn value(ui: &mut egui::Ui, text: &str) {
    ui.add(Label::new(RichText::new(text).size(12.0)).wrap());
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

/// A fingerprint under a [`label`]: four lines of colon hex, with a Copy button.
fn fingerprint_block(ui: &mut egui::Ui, title: &str, fingerprint: &CertFingerprint) {
    label(ui, title);
    ui.horizontal_top(|ui| {
        ui.label(
            RichText::new(fingerprint_lines(fingerprint))
                .monospace()
                .size(11.0),
        );
        if ui.add(widgets::mini(ui, "Copy")).clicked() {
            ui.ctx().copy_text(fingerprint.colon_hex());
        }
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
/// Enter means Cancel unless a trust button was given the focus.
fn certificate_dialog(
    ui: &mut egui::Ui,
    server: &str,
    info: &CertInfo,
    previous: Option<&CertFingerprint>,
    focused: &mut bool,
    enter: bool,
    can_save: bool,
) -> Option<Trust> {
    let p = widgets::pal(ui);
    if previous.is_some() {
        ui.heading("This certificate changed");
        widgets::banner(
            ui,
            Tone::Error,
            "",
            &format!(
                "{server} sent a different certificate from the one trusted before. Trust the \
                 new one only if your IT team confirms they replaced it."
            ),
        );
    } else {
        ui.heading("Check this certificate");
        value(
            ui,
            &format!(
                "{server} sent a certificate this PC doesn't trust. Trust it only if your IT \
                 team confirms it's theirs."
            ),
        );
        label(ui, "Issued to");
        let subject = info.subject.summary();
        value(
            ui,
            if subject.is_empty() {
                "Not named"
            } else {
                &subject
            },
        );
        if !info.dns_names.is_empty() {
            ui.add(
                Label::new(
                    RichText::new(format!("Names: {}", info.dns_names.join(", ")))
                        .size(11.0)
                        .color(p.muted),
                )
                .wrap(),
            );
        }
    }
    label(ui, "Issued by");
    value(ui, &auth::certificate_issuer(info));
    label(ui, "Valid");
    let (dates, warning) = auth::certificate_dates(info);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(dates).size(12.0));
        if let Some(warning) = warning {
            ui.label(RichText::new(warning).size(12.0).strong().color(p.red));
        }
    });
    match previous {
        Some(previous) => {
            fingerprint_block(ui, "Previously trusted SHA-256", previous);
            fingerprint_block(ui, "New SHA-256", &info.fingerprint);
            if ui.add(widgets::mini(ui, "Copy details")).clicked() {
                ui.ctx()
                    .copy_text(certificate_details(server, info, Some(previous)));
            }
        }
        None => fingerprint_block(ui, "SHA-256 fingerprint", &info.fingerprint),
    }
    ui.add_space(4.0);
    // Windows order, and nothing drawn as the default action.
    let mut choice = None;
    ui.horizontal_wrapped(|ui| {
        let trust = if previous.is_some() {
            "Trust the new one"
        } else {
            "Always trust"
        };
        let always = ui
            .add_enabled(can_save, widgets::secondary(ui, trust))
            .on_disabled_hover_text(
                "The profiles file could not be read, so nothing can be saved in it.",
            );
        let once = ui.add(widgets::secondary(ui, "Trust once"));
        let cancel = ui.add(widgets::secondary(ui, "Cancel"));
        if !*focused {
            cancel.request_focus();
            *focused = true;
        }
        let trust_focused = always.has_focus() || once.has_focus();
        choice = if always.clicked() {
            Some(Trust::Always)
        } else if once.clicked() {
            Some(Trust::Once)
        } else if cancel.clicked() || (enter && !trust_focused) {
            Some(Trust::Cancel)
        } else {
            None
        };
    });
    choice
}

impl App {
    pub(super) fn prompts(&mut self, ctx: &egui::Context) {
        let mut close = false;
        let w = width(ctx);
        let can_save = !self.read_only();
        if let Some(prompt) = &mut self.prompt {
            let modal = egui::Modal::new(egui::Id::unique("prompt"))
                .frame(frame(ctx))
                .show(ctx, |ui| {
                    ui.set_width(w);
                    ui.spacing_mut().item_spacing.y = 6.0;
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
                            ui.heading(title.as_str());
                            if let Some(m) = message {
                                ui.add(Label::new(RichText::new(m.as_str()).size(12.0)).wrap());
                            }
                            label(ui, username_label);
                            let user_field =
                                ui.add(TextEdit::singleline(username).desired_width(f32::INFINITY));
                            label(ui, password_label);
                            let pass_field = ui.add(
                                TextEdit::singleline(password)
                                    .password(true)
                                    .desired_width(f32::INFINITY),
                            );
                            if !*focused {
                                if username.is_empty() {
                                    user_field.request_focus();
                                } else {
                                    pass_field.request_focus();
                                }
                                *focused = true;
                            }
                            let ready = !username.trim().is_empty() && !password.is_empty();
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                if ui.add(widgets::secondary(ui, "Cancel")).clicked() {
                                    let _ = reply.send(None);
                                    close = true;
                                }
                                let sign_in =
                                    ui.add_enabled(ready, widgets::primary(ui, "Sign in"));
                                if sign_in.clicked() || (ready && enter) {
                                    let _ = reply.send(Some((
                                        username.trim().to_string(),
                                        Secret::new(std::mem::take(password)),
                                    )));
                                    close = true;
                                }
                            });
                        }
                        PromptUi::Code {
                            title,
                            message,
                            code,
                            reply,
                            focused,
                        } => {
                            ui.heading(title.as_str());
                            ui.add(Label::new(RichText::new(message.as_str()).size(12.0)).wrap());
                            let field = ui.add(
                                TextEdit::singleline(code)
                                    .password(true)
                                    .desired_width(f32::INFINITY),
                            );
                            if !*focused {
                                field.request_focus();
                                *focused = true;
                            }
                            let ready = !code.trim().is_empty();
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                if ui.add(widgets::secondary(ui, "Cancel")).clicked() {
                                    let _ = reply.send(None);
                                    close = true;
                                }
                                let ok = ui.add_enabled(ready, widgets::primary(ui, "OK"));
                                if ok.clicked() || (ready && enter) {
                                    let _ = reply.send(Some(Secret::new(std::mem::take(code))));
                                    close = true;
                                }
                            });
                        }
                        PromptUi::Fields {
                            title,
                            message,
                            fields,
                            reply,
                            focused,
                        } => {
                            ui.heading(title.as_str());
                            ui.add(Label::new(RichText::new(message.as_str()).size(12.0)).wrap());
                            for (i, (name, secret, value)) in fields.iter_mut().enumerate() {
                                label(ui, name);
                                let field = ui.add(
                                    TextEdit::singleline(value)
                                        .password(*secret)
                                        .desired_width(f32::INFINITY),
                                );
                                if i == 0 && !*focused {
                                    field.request_focus();
                                    *focused = true;
                                }
                            }
                            let ready = fields.iter().all(|(_, _, v)| !v.trim().is_empty());
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                if ui.add(widgets::secondary(ui, "Cancel")).clicked() {
                                    let _ = reply.send(None);
                                    close = true;
                                }
                                let ok = ui.add_enabled(ready, widgets::primary(ui, "OK"));
                                if ok.clicked() || (ready && enter) {
                                    let values = fields
                                        .iter_mut()
                                        .map(|(_, _, v)| Secret::new(std::mem::take(v)))
                                        .collect();
                                    let _ = reply.send(Some(values));
                                    close = true;
                                }
                            });
                        }
                        PromptUi::Certificate {
                            server,
                            info,
                            previous,
                            reply,
                            focused,
                        } => {
                            let choice = certificate_dialog(
                                ui,
                                server,
                                info,
                                previous.as_ref(),
                                focused,
                                enter,
                                can_save,
                            );
                            if let Some(choice) = choice {
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

        let mut cancel = false;
        if let Some(browser) = &mut self.browser {
            let modal = egui::Modal::new(egui::Id::unique("browser"))
                .frame(frame(ctx))
                .show(ctx, |ui| {
                    let p = widgets::pal(ui);
                    ui.set_width(w);
                    ui.spacing_mut().item_spacing.y = 6.0;
                    ui.heading("Finish signing in in your browser");
                    match &browser.not_opened {
                        None => ui.add(
                            Label::new(
                                RichText::new(format!(
                                    "Your browser opened the sign-in page for {}. Polytunnel \
                                     continues by itself when you are done.",
                                    browser.server
                                ))
                                .size(12.0),
                            )
                            .wrap(),
                        ),
                        Some(e) => ui.add(
                            Label::new(
                                RichText::new(format!(
                                    "The browser could not be opened ({e}). Copy the link into \
                                     your browser."
                                ))
                                .size(12.0)
                                .color(p.red),
                            )
                            .wrap(),
                        ),
                    };
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new());
                        ui.label(
                            RichText::new("Waiting for the browser…")
                                .size(12.0)
                                .color(p.muted),
                        );
                    });
                    ui.horizontal(|ui| {
                        if ui.add(widgets::mini(ui, "Open again")).clicked() {
                            browser.not_opened = crate::browser::open(&browser.url).err();
                        }
                        if ui.add(widgets::mini(ui, "Copy the link")).clicked() {
                            ui.ctx().copy_text(browser.url.clone());
                        }
                    });
                    if widgets::fold(ui, "browser-paste", "The browser can't hand it back", None) {
                        ui.add(
                            Label::new(
                                RichText::new(
                                    "Paste the globalprotectcallback: link (or the final page's \
                                     source):",
                                )
                                .size(12.0),
                            )
                            .wrap(),
                        );
                        ui.add(
                            TextEdit::multiline(&mut browser.pasted)
                                .desired_rows(3)
                                .desired_width(f32::INFINITY),
                        );
                        if let Some(e) = &browser.paste_error {
                            ui.label(RichText::new(e).size(12.0).color(p.red));
                        }
                        let ready = !browser.pasted.trim().is_empty();
                        if ui
                            .add_enabled(ready, widgets::mini(ui, "Use pasted result"))
                            .clicked()
                        {
                            browser.paste_error = None;
                            let _ = browser.paste.send(browser.pasted.clone());
                        }
                    }
                    ui.add_space(4.0);
                    if ui.add(widgets::secondary(ui, "Cancel")).clicked() {
                        cancel = true;
                    }
                });
            if modal.should_close() {
                cancel = true;
            }
        }
        if cancel {
            if let Some(worker) = &self.worker {
                worker.cancel();
            }
            self.browser = None;
        }
    }

    pub(super) fn confirmations(&mut self, ctx: &egui::Context) {
        let Some(confirm) = &self.confirm else {
            return;
        };
        let (title, text, yes) = match confirm {
            Confirm::Delete(name) => (
                format!("Delete '{name}'?"),
                "The profile is removed from Polytunnel. The previous profiles file is kept as \
                 profiles.toml.bak."
                    .to_string(),
                "Delete",
            ),
            Confirm::Lockdown(_) => (
                "Turn on lockdown?".to_string(),
                "Lockdown blocks all internet traffic whenever the VPN is not connected, \
                 including right now, and after restarts."
                    .to_string(),
                "Turn on",
            ),
            Confirm::Install(version) => (
                format!("Install Polytunnel {version}?"),
                "The VPN disconnects and Polytunnel closes while the update installs, then the \
                 tray icon comes back."
                    .to_string(),
                "Install",
            ),
            Confirm::Discard(_) => (
                "Discard your changes?".to_string(),
                "The profile has changes that are not saved.".to_string(),
                "Discard",
            ),
        };
        let w = width(ctx);
        let mut answer = None;
        let modal = egui::Modal::new(egui::Id::unique("confirm"))
            .frame(frame(ctx))
            .show(ctx, |ui| {
                ui.set_width(w);
                ui.spacing_mut().item_spacing.y = 6.0;
                ui.heading(title);
                ui.add(Label::new(RichText::new(text).size(12.0)).wrap());
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui.add(widgets::secondary(ui, "Cancel")).clicked() {
                        answer = Some(false);
                    }
                    if ui.add(widgets::primary(ui, yes)).clicked() {
                        answer = Some(true);
                    }
                });
            });
        if modal.should_close() && answer.is_none() {
            answer = Some(false);
        }
        let Some(yes) = answer else {
            return;
        };
        let Some(confirm) = self.confirm.take() else {
            return;
        };
        if !yes {
            return;
        }
        match confirm {
            Confirm::Delete(name) => self.delete_profile(&name),
            Confirm::Lockdown(settings) => self.set_killswitch(ctx, settings),
            Confirm::Install(_) => {
                self.running.update = true;
                self.spawn_job(ctx, || Job::UpdateStarted(connect::update(true)));
            }
            Confirm::Discard(leave) => self.do_leave(leave),
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
