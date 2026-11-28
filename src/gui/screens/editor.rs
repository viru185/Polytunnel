//! The profile form. Its sections and fields come from the integration's description
//! ([`crate::gui::integrations`]): Basics, Gateways, Sign-in, Security and Advanced, in that
//! order, each shown only when the connection type has fields for it.

use eframe::egui::{self, Align2, Sense, Ui, pos2};

use super::body;
use super::profiles::menu_item;
use crate::gui::icons::Icon;
use crate::gui::integrations::{self, Field, FieldId, SectionKind};
use crate::gui::widgets::{self, Banner, Kind as Button, Lead};
use crate::gui::{App, Confirm, Editor, Kind, Leave, theme};

/// The editable gateway list: edit, move up or down, remove, add.
fn gateway_list(ui: &mut Ui, server: &mut String, backups: &mut Vec<String>, hint: &str) {
    let p = widgets::pal(ui);
    // One ordered list: the first is the server.
    let mut list: Vec<String> = std::iter::once(server.clone())
        .chain(backups.iter().cloned())
        .collect();
    let count = list.len();
    let mut action: Option<(usize, i8)> = None;
    widgets::card(ui, false, |ui| {
        for (i, gateway) in list.iter_mut().enumerate() {
            let (rect, _) = widgets::row_frame(ui, 48.0, i == 0, false, Sense::hover());
            ui.painter().text(
                pos2(rect.left() + 16.0, rect.center().y),
                Align2::LEFT_CENTER,
                format!("{}", i + 1),
                theme::regular(12.0),
                p.text3,
            );
            let edit_rect = egui::Rect::from_min_max(
                pos2(rect.left() + 32.0, rect.top() + 6.0),
                pos2(rect.right() - 16.0 - 3.0 * 36.0, rect.bottom() - 6.0),
            );
            widgets::place(ui, egui::UiBuilder::new().max_rect(edit_rect), |ui| {
                ui.add_sized(
                    edit_rect.size(),
                    egui::TextEdit::singleline(gateway)
                        .hint_text(
                            egui::RichText::new(if i == 0 { hint } else { "host or host:port" })
                                .color(p.text3),
                        )
                        .frame(egui::Frame::NONE)
                        .align(Align2::LEFT_CENTER)
                        .margin(egui::Margin::ZERO)
                        .desired_width(edit_rect.width()),
                )
            });
            let buttons = egui::Rect::from_min_max(
                pos2(rect.right() - 12.0 - 3.0 * 36.0, rect.top()),
                pos2(rect.right() - 12.0, rect.bottom()),
            );
            widgets::place(
                ui,
                egui::UiBuilder::new()
                    .max_rect(buttons)
                    .layout(egui::Layout::left_to_right(egui::Align::Center)),
                |ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.add_enabled_ui(i > 0, |ui| {
                        if widgets::icon_button(ui, Icon::Up, "Try earlier", 32.0, None).clicked() {
                            action = Some((i, -1));
                        }
                    });
                    ui.add_enabled_ui(i + 1 < count, |ui| {
                        if widgets::icon_button(ui, Icon::Down, "Try later", 32.0, None).clicked() {
                            action = Some((i, 1));
                        }
                    });
                    ui.add_enabled_ui(count > 1, |ui| {
                        if widgets::icon_button(ui, Icon::Close, "Remove", 32.0, None).clicked() {
                            action = Some((i, 0));
                        }
                    });
                },
            );
        }
        if count < 16 {
            let (rect, response) = widgets::row_frame(ui, 48.0, false, true, Sense::click());
            let ink = p.accent;
            crate::gui::icons::paint(
                ui.painter(),
                egui::Rect::from_min_size(
                    pos2(rect.left() + 16.0, rect.center().y - 8.0),
                    egui::vec2(16.0, 16.0),
                ),
                Icon::Plus,
                ink,
            );
            ui.painter().text(
                pos2(rect.left() + 40.0, rect.center().y),
                Align2::LEFT_CENTER,
                "Add a gateway",
                theme::semibold(14.0),
                ink,
            );
            if response.clicked() {
                action = Some((count, 2));
            }
        }
    });
    match action {
        Some((i, 0)) => {
            list.remove(i);
        }
        Some((i, -1)) => list.swap(i, i - 1),
        Some((i, 1)) => list.swap(i, i + 1),
        Some((_, 2)) => list.push(String::new()),
        _ => {}
    }
    *server = list.first().cloned().unwrap_or_default();
    *backups = list.into_iter().skip(1).collect();
}

impl App {
    pub(in crate::gui) fn editor_page(&mut self, ui: &mut Ui) {
        let Some(editor) = &self.editor else {
            return;
        };
        let (_, conn) = integrations::find(editor.kind, editor.ike2);
        let new = editor.original.is_none();
        let title = if new {
            format!("New {} profile", conn.full_name)
        } else {
            editor.original.clone().unwrap_or_default()
        };
        let sub = if new {
            String::new()
        } else {
            conn.full_name.to_string()
        };
        let mut delete = false;
        let mut duplicate = false;
        let original = editor.original.clone();
        let back = widgets::page_header(ui, &title, &sub, |ui| {
            if original.is_some() {
                let more = widgets::icon_button(ui, Icon::More, "More", 36.0, None);
                egui::Popup::menu(&more).width(176.0).show(|ui| {
                    let p = widgets::pal(ui);
                    if menu_item(ui, Icon::Copy, "Duplicate", p.text) {
                        duplicate = true;
                        ui.close();
                    }
                    ui.separator();
                    if menu_item(ui, Icon::Trash, "Delete…", p.red_text) {
                        delete = true;
                        ui.close();
                    }
                });
            }
        });
        if back {
            self.leave_editor(Leave::Close);
            return;
        }
        if delete && let Some(name) = original.clone() {
            self.confirm = Some(Confirm::Delete(name));
        }
        if duplicate && let Some(editor) = &self.editor {
            let mut copy = editor.clone();
            copy.original = None;
            copy.name = format!("{}-copy", editor.name);
            self.editor_initial = Some(copy.clone());
            self.editor = Some(copy);
            return;
        }
        let active = crate::gui::active_profile(&self.status).map(str::to_string);
        let Some(editor) = &mut self.editor else {
            return;
        };
        let editing_active = editor.original.is_some() && editor.original == active;
        body(ui, "editor", |ui| {
            if editing_active {
                ui.add_space(4.0);
                widgets::banner(
                    ui,
                    Banner::Info,
                    Icon::Info,
                    "This profile is connected",
                    "Changes apply the next time you connect.",
                    |_| {},
                );
            }
            for section in conn.sections {
                let fields: Vec<&Field> = section
                    .fields
                    .iter()
                    .filter(|f| shown(editor, f.id))
                    .collect();
                if fields.is_empty() {
                    continue;
                }
                if section.kind == SectionKind::Advanced {
                    ui.add_space(24.0);
                    widgets::card(ui, false, |ui| {
                        if widgets::fold_row(
                            ui,
                            &format!("editor-advanced-{}", conn.id),
                            "Advanced",
                            section.summary,
                            true,
                        ) {
                            advanced_fields(ui, editor, &fields);
                        }
                    });
                    continue;
                }
                widgets::section(ui, section.kind.title(), None);
                section_fields(ui, editor, &fields);
            }
            if let Some(e) = editor.error.clone() {
                ui.add_space(16.0);
                widgets::banner(
                    ui,
                    Banner::Bad,
                    Icon::Error,
                    "This can't be saved yet",
                    &e,
                    |_| {},
                );
            }
        });
    }

    /// The form's sticky bar: Save (Save and connect for a new profile) and Cancel or Back.
    pub(in crate::gui) fn editor_footer(&mut self, ui: &mut Ui) {
        let new = self.editor.as_ref().is_some_and(|e| e.original.is_none());
        let mut save = false;
        let mut cancel = false;
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            cancel = widgets::button(
                ui,
                Button::Secondary,
                if new { "Back" } else { "Cancel" },
                None,
                false,
            )
            .clicked();
            ui.add_enabled_ui(!self.read_only(), |ui| {
                save = widgets::button(
                    ui,
                    Button::Primary,
                    if new { "Save and connect" } else { "Save" },
                    None,
                    false,
                )
                .clicked();
            });
        });
        let ctx = ui.ctx().clone();
        if save {
            self.save_editor(&ctx, new);
        } else if cancel {
            self.leave_editor(Leave::Close);
        }
    }
}

/// Is `id` shown for this form (some fields depend on others)?
fn shown(editor: &Editor, id: FieldId) -> bool {
    match id {
        FieldId::SignInMode => crate::embedded::helper().is_some(),
        FieldId::Tcp => editor.kind == Kind::FortinetIpsec,
        FieldId::TrustedCertificates => {
            editor.forti_base.server_cert.is_some() || !editor.forti_base.trusted_certs.is_empty()
        }
        _ => true,
    }
}

/// The fields of one section, each in its own card part.
fn section_fields(ui: &mut Ui, editor: &mut Editor, fields: &[&Field]) {
    // Fields that are rows (not text boxes) go in a plain card; text fields in a padded one.
    let rows = |id: FieldId| {
        matches!(
            id,
            FieldId::GatewayList
                | FieldId::SignInMode
                | FieldId::AskedWhenConnecting
                | FieldId::TrustedCertificates
        )
    };
    let mut i = 0;
    while i < fields.len() {
        let field = fields[i];
        match field.id {
            FieldId::GatewayList => {
                let hint = if editor.kind == Kind::FortinetIpsec {
                    "198.51.100.7"
                } else {
                    "vpn.example.com:10443"
                };
                gateway_list(ui, &mut editor.server, &mut editor.backups, hint);
                if let Some(help) = field.help.filter(|_| !editor.backups.is_empty()) {
                    ui.add_space(8.0);
                    widgets::help(ui, help);
                }
                i += 1;
            }
            FieldId::TrustedCertificates => {
                trusted_certificates(ui, editor);
                ui.add_space(8.0);
                widgets::help(
                    ui,
                    "Trusted certificates are added when you choose Always trust. Remove one to be asked again.",
                );
                i += 1;
            }
            _ => {
                // A run of fields in one card.
                let start = i;
                while i < fields.len()
                    && !matches!(
                        fields[i].id,
                        FieldId::GatewayList | FieldId::TrustedCertificates
                    )
                {
                    i += 1;
                }
                let group = &fields[start..i];
                let padded = group.iter().all(|f| !rows(f.id));
                widgets::card(ui, padded, |ui| {
                    for (k, f) in group.iter().enumerate() {
                        field_ui(ui, editor, f, k == 0, k + 1 == group.len(), padded);
                    }
                });
            }
        }
    }
}

/// One field.
fn field_ui(
    ui: &mut Ui,
    editor: &mut Editor,
    field: &Field,
    first: bool,
    last: bool,
    padded: bool,
) {
    let p = widgets::pal(ui);
    if padded && !first {
        ui.add_space(16.0);
    }
    match field.id {
        FieldId::Name => {
            widgets::Field::new(field.label)
                .hint(if editor.kind == Kind::GlobalProtect {
                    "Work"
                } else {
                    "Office"
                })
                .help("Letters, digits, - or _.")
                .show(ui, &mut editor.name);
        }
        FieldId::Server => {
            let mut f = widgets::Field::new(field.label).hint(field.hint);
            if let Some(help) = field.help {
                f = f.help(help);
            }
            f.show(ui, &mut editor.server);
        }
        FieldId::Username | FieldId::Realm | FieldId::LocalId => {
            let value = match field.id {
                FieldId::Username => &mut editor.username,
                FieldId::Realm => &mut editor.realm,
                _ => &mut editor.local_id,
            };
            let help = field
                .help
                .filter(|_| field.id != FieldId::Username || value.is_empty());
            let wrap = !padded;
            if wrap {
                egui::Frame::NONE
                    .inner_margin(egui::Margin::same(16))
                    .show(ui, |ui| {
                        let mut f = widgets::Field::new(field.label).hint(field.hint);
                        if let Some(help) = field.help {
                            f = f.help(help);
                        }
                        f.show(ui, value);
                    });
            } else {
                let mut f = widgets::Field::new(field.label).hint(field.hint);
                if let Some(help) = help {
                    f = f.help(help);
                }
                f.show(ui, value);
            }
        }
        FieldId::SignInMode => {
            if widgets::radio_row(
                ui,
                !editor.embedded,
                "In your browser",
                Some("Recommended"),
                Some("Uses your organization's single sign-on and saved sign-ins."),
                true,
                !first,
                true,
            )
            .clicked()
            {
                editor.embedded = false;
            }
            if widgets::radio_row(
                ui,
                editor.embedded,
                "In a Polytunnel window",
                None,
                Some("For portals that don't finish in a browser. Also used while the kill switch holds traffic."),
                true,
                true,
                true,
            )
            .clicked()
            {
                editor.embedded = true;
            }
        }
        FieldId::AskedWhenConnecting => {
            widgets::list_row(
                ui,
                Lead::Icon(Icon::Key),
                field.label,
                "Asked when you connect. Never saved.",
                false,
                first,
                last,
                |_| {},
            );
        }
        FieldId::Pfs
        | FieldId::DhGroup
        | FieldId::Tcp
        | FieldId::GatewayList
        | FieldId::TrustedCertificates => {
            let _ = p;
        }
    }
}

/// The Advanced fold's fields (inside its card).
fn advanced_fields(ui: &mut Ui, editor: &mut Editor, fields: &[&Field]) {
    for field in fields {
        match field.id {
            FieldId::Pfs => {
                widgets::toggle_row(
                    ui,
                    "Perfect forward secrecy",
                    Some("Fresh keys for each session"),
                    true,
                    &mut editor.pfs,
                    false,
                    false,
                );
            }
            FieldId::DhGroup => {
                egui::Frame::NONE
                    .inner_margin(egui::Margin::same(16))
                    .show(ui, |ui| {
                        let p = widgets::pal(ui);
                        let (r, _) = ui.allocate_exact_size(
                            egui::vec2(ui.available_width(), 1.0),
                            Sense::hover(),
                        );
                        let _ = r;
                        widgets::Field::new(field.label)
                            .hint("14")
                            .help("2, 5, 14, 15, 16, 19 or 20. Ask IT if unsure.")
                            .show(ui, &mut editor.dh_group);
                        let _ = p;
                    });
            }
            FieldId::Tcp => {
                let enabled = editor.ike2;
                let desc = if enabled {
                    "For networks that block IPsec"
                } else {
                    "Only with IKEv2"
                };
                widgets::toggle_row(
                    ui,
                    field.label,
                    Some(desc),
                    enabled,
                    &mut editor.tcp,
                    false,
                    true,
                );
            }
            FieldId::Realm | FieldId::LocalId => {
                field_ui(ui, editor, field, false, false, false);
            }
            _ => field_ui(ui, editor, field, false, false, false),
        }
    }
}

/// The trusted gateway certificates, each with Remove.
fn trusted_certificates(ui: &mut Ui, editor: &mut Editor) {
    let mut entries: Vec<(String, String)> = editor
        .forti_base
        .trusted_certs
        .iter()
        .map(|(gateway, fp)| (gateway.clone(), short(&fp.colon_hex())))
        .collect();
    if let Some(all) = editor.forti_base.server_cert {
        entries.push(("Every gateway".into(), short(&all.colon_hex())));
    }
    let count = entries.len();
    let mut remove = None;
    widgets::card(ui, false, |ui| {
        for (i, (gateway, fp)) in entries.iter().enumerate() {
            widgets::list_row(
                ui,
                Lead::Icon(Icon::Rosette),
                gateway,
                fp,
                false,
                i == 0,
                i + 1 == count,
                |ui| {
                    if widgets::link(ui, "Remove", false, None).clicked() {
                        remove = Some(i);
                    }
                },
            );
        }
    });
    if let Some((gateway, _)) = remove.and_then(|i| entries.get(i).map(|e| (e.0.clone(), i))) {
        let (gateway, i) = (gateway, remove.unwrap_or_default());
        if gateway == "Every gateway" && i + 1 == count && editor.forti_base.server_cert.is_some() {
            editor.forti_base.server_cert = None;
            editor.server_cert.clear();
        } else {
            editor.forti_base.trusted_certs.remove(&gateway);
        }
    }
}

/// `3F:9A:5C:2E … 73:A2:5E`.
fn short(colon_hex: &str) -> String {
    let parts: Vec<&str> = colon_hex.split(':').collect();
    if parts.len() < 8 {
        return colon_hex.to_string();
    }
    format!(
        "{} … {}",
        parts[..4].join(":"),
        parts[parts.len() - 3..].join(":")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_shortened() {
        let hex = "3F:9A:5C:2E:71:D0:4B:8E:6A:1C:9F:37:B2:E0:5D:48:C6:A9:1F:0E:3B:7D:25:A8:E4:C1:F6:9B:0D:73:A2:5E";
        assert_eq!(short(hex), "3F:9A:5C:2E … 73:A2:5E");
    }
}
