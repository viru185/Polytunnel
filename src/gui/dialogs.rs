//! The dialogs over the window: sign-in, codes, the service's questions, browser sign-in, and
//! confirmations. Enter submits (only when filled in); Escape or a click outside cancels.

use eframe::egui::{self, Label, Margin, RichText, Stroke, TextEdit};

use polytunnel_core::Secret;

use super::widgets;
use super::{App, Confirm, Job, PromptUi};
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

impl App {
    pub(super) fn prompts(&mut self, ctx: &egui::Context) {
        let mut close = false;
        let w = width(ctx);
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
