//! Managing profiles: the list with each profile's menu, "Add a profile" (integration, then
//! connection type, then the form) and importing another program's profiles.

use eframe::egui::{self, Ui};
use polytunnel_core::profile::GlobalProtectProfile;

use super::body;
use crate::gui::icons::Icon;
use crate::gui::integrations::{self, ALL};
use crate::gui::widgets::{self, Banner, Kind as Button, Lead};
use crate::gui::{App, Confirm, Editor, Page};

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

/// The profile's gateway settings for `mode`, choosing `candidate` when the mode needs one and
/// none is set.
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

enum Do {
    Add,
    Edit(String),
    Duplicate(String),
    Delete(String),
    Scan,
    Integration(usize),
}

impl App {
    pub(in crate::gui) fn profiles_page(&mut self, ui: &mut Ui) {
        let count = self.profiles.profiles.len();
        let sub = match count {
            1 => "1 profile".to_string(),
            n => format!("{n} profiles"),
        };
        let mut todo = Vec::new();
        let read_only = self.read_only();
        if widgets::page_header(ui, "Profiles", &sub, |ui| {
            ui.add_enabled_ui(!read_only, |ui| {
                if widgets::icon_button(ui, Icon::Plus, "Add a profile", 36.0, None).clicked() {
                    todo.push(Do::Add);
                }
            });
        }) {
            self.back();
            return;
        }
        if cfg!(windows) && self.import_count.is_none() && !self.fake {
            self.import_count = Some(
                crate::forticlient::ssl_tunnels().len()
                    + crate::forticlient::ipsec_tunnels().tunnels.len(),
            );
        }
        let found = if self.fake {
            2
        } else {
            self.import_count.unwrap_or(0)
        };
        let names: Vec<String> = self.profiles.profiles.keys().cloned().collect();
        body(ui, "profiles", |ui| {
            ui.add_space(4.0);
            if let Some(e) = &self.load_error {
                widgets::banner(
                    ui,
                    Banner::Bad,
                    Icon::Error,
                    "Your profiles file could not be read",
                    &format!("{e}\nFix or remove it, then reopen Polytunnel."),
                    |_| {},
                );
            } else if names.is_empty() {
                widgets::card(ui, true, |ui| {
                    ui.label(egui::RichText::new("No profiles yet").strong());
                    widgets::help(ui, "Add your organization's VPN below.");
                });
            } else {
                widgets::card(ui, false, |ui| {
                    for (i, name) in names.iter().enumerate() {
                        let Some(profile) = self.profiles.get(name) else {
                            continue;
                        };
                        let (integration, _) = integrations::of(profile);
                        let line = integrations::profile_line(profile);
                        let row = widgets::list_row(
                            ui,
                            Lead::Badge(integration.badge),
                            name,
                            &line,
                            false,
                            i == 0,
                            i + 1 == names.len(),
                            |ui| {
                                let more = widgets::icon_button(ui, Icon::More, "More", 32.0, None);
                                egui::Popup::menu(&more).width(176.0).show(|ui| {
                                    menu_items(ui, name, read_only, &mut todo);
                                });
                            },
                        );
                        if row.clicked() && !read_only {
                            todo.push(Do::Edit(name.clone()));
                        }
                    }
                });
            }
            widgets::section(ui, "Add", None);
            widgets::card(ui, false, |ui| {
                let types: Vec<&str> = ALL.iter().map(|i| i.name).collect();
                if widgets::list_row(
                    ui,
                    Lead::IconBadge(Icon::Plus),
                    "Add a profile",
                    &types.join(" or "),
                    false,
                    true,
                    !cfg!(windows),
                    chevron,
                )
                .clicked()
                    && !read_only
                {
                    todo.push(Do::Add);
                }
                if cfg!(windows) {
                    let sub = match found {
                        0 => "None found on this PC".to_string(),
                        1 => "1 connection found on this PC".into(),
                        n => format!("{n} connections found on this PC"),
                    };
                    if widgets::list_row(
                        ui,
                        Lead::IconBadge(Icon::Download),
                        "Import from FortiClient",
                        &sub,
                        false,
                        false,
                        true,
                        chevron,
                    )
                    .clicked()
                        && !read_only
                    {
                        todo.push(Do::Scan);
                    }
                }
            });
        });
        for action in todo {
            self.profiles_do(action);
        }
    }

    fn profiles_do(&mut self, action: Do) {
        match action {
            Do::Add => self.go(Page::AddIntegration),
            Do::Edit(name) => {
                if let Some(profile) = self.profiles.get(&name).cloned() {
                    self.open_editor(Editor::from_profile(&name, &profile));
                }
            }
            Do::Duplicate(name) => {
                if let Some(profile) = self.profiles.get(&name).cloned() {
                    let mut editor = Editor::from_profile(&name, &profile);
                    editor.original = None;
                    let mut copy = format!("{name}-copy");
                    while self.profiles.profiles.contains_key(&copy) {
                        copy.push('-');
                    }
                    editor.name = copy;
                    self.open_editor(editor);
                }
            }
            Do::Delete(name) => self.confirm = Some(Confirm::Delete(name)),
            Do::Scan => self.scan_import(),
            Do::Integration(i) => self.choose_integration(i),
        }
    }

    /// Step 1 of "Add a profile": the integration.
    pub(in crate::gui) fn add_integration_page(&mut self, ui: &mut Ui) {
        let mut todo = Vec::new();
        if widgets::page_header(
            ui,
            "Add a profile",
            "Which VPN does your organization use?",
            |_| {},
        ) {
            self.back();
            return;
        }
        if cfg!(windows) && self.import_count.is_none() && !self.fake {
            self.import_count = Some(
                crate::forticlient::ssl_tunnels().len()
                    + crate::forticlient::ipsec_tunnels().tunnels.len(),
            );
        }
        let found = if self.fake {
            2
        } else {
            self.import_count.unwrap_or(0)
        };
        body(ui, "add-integration", |ui| {
            ui.add_space(4.0);
            widgets::card(ui, false, |ui| {
                for (i, integration) in ALL.iter().enumerate() {
                    if widgets::list_row(
                        ui,
                        Lead::BigBadge(integration.badge),
                        integration.name,
                        integration.summary,
                        false,
                        i == 0,
                        i + 1 == ALL.len(),
                        chevron,
                    )
                    .clicked()
                    {
                        todo.push(Do::Integration(i));
                    }
                }
            });
            let sources: Vec<&str> = ALL
                .iter()
                .filter_map(|i| i.import.as_ref().map(|s| s.name))
                .collect();
            if cfg!(windows) && !sources.is_empty() {
                widgets::section(ui, "Already set up elsewhere?", None);
                widgets::card(ui, false, |ui| {
                    for (k, source) in sources.iter().enumerate() {
                        let sub = match found {
                            0 => "None found on this PC".to_string(),
                            1 => "1 connection found on this PC".into(),
                            n => format!("{n} connections found on this PC"),
                        };
                        if widgets::list_row(
                            ui,
                            Lead::BigIconBadge(Icon::Download),
                            &format!("Import from {source}"),
                            &sub,
                            false,
                            k == 0,
                            k + 1 == sources.len(),
                            chevron,
                        )
                        .clicked()
                        {
                            todo.push(Do::Scan);
                        }
                    }
                });
            }
            ui.add_space(16.0);
            widgets::help(
                ui,
                "Product names belong to their owners. Polytunnel is an independent client.",
            );
        });
        for action in todo {
            self.profiles_do(action);
        }
    }

    /// An integration was chosen: its type picker, or the form when it has one type.
    fn choose_integration(&mut self, i: usize) {
        let Some(integration) = ALL.get(i) else {
            return;
        };
        if integration.types.len() == 1 {
            self.new_profile(i, 0);
        } else {
            self.go(Page::AddType(i));
        }
    }

    /// Opens the form for a new profile of integration `i`, type `t`.
    fn new_profile(&mut self, i: usize, t: usize) {
        let Some(conn) = ALL.get(i).and_then(|integration| integration.types.get(t)) else {
            return;
        };
        let mut editor = Editor::new(conn.kind);
        editor.ike2 = conn.ike2;
        editor.eap = conn.ike2;
        editor.xauth = !conn.ike2;
        self.open_editor(editor);
    }

    /// Step 2 of "Add a profile": the connection type.
    pub(in crate::gui) fn add_type_page(&mut self, ui: &mut Ui, i: usize) {
        let Some(integration) = ALL.get(i) else {
            self.back();
            return;
        };
        if widgets::page_header(ui, integration.name, "How does it connect?", |_| {}) {
            self.back();
            return;
        }
        let key = egui::Id::unique(("add-type-choice", i));
        let mut choice = ui.data(|d| d.get_temp::<usize>(key).unwrap_or(0));
        body(ui, "add-type", |ui| {
            ui.add_space(4.0);
            widgets::card(ui, false, |ui| {
                for (t, conn) in integration.types.iter().enumerate() {
                    if widgets::radio_row(
                        ui,
                        choice == t,
                        conn.name,
                        conn.tag,
                        Some(conn.summary),
                        true,
                        t > 0,
                        true,
                    )
                    .clicked()
                    {
                        choice = t;
                    }
                }
            });
            ui.add_space(8.0);
            if integration.id == "fortinet" {
                widgets::help(
                    ui,
                    "Not sure? FortiClient shows it in the connection's settings, or ask IT.",
                );
            }
        });
        ui.data_mut(|d| d.insert_temp(key, choice));
    }

    pub(in crate::gui) fn add_type_footer(&mut self, ui: &mut Ui, i: usize) {
        let key = egui::Id::unique(("add-type-choice", i));
        let choice = ui.data(|d| d.get_temp::<usize>(key).unwrap_or(0));
        let mut go = false;
        let mut back = false;
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            back = widgets::button(ui, Button::Secondary, "Back", None, false).clicked();
            go = widgets::button(ui, Button::Primary, "Continue", None, false).clicked();
        });
        if go {
            self.new_profile(i, choice);
        } else if back {
            self.back();
        }
    }

    /// Import: the profiles found in another program, to tick and import.
    pub(in crate::gui) fn import_page(&mut self, ui: &mut Ui) {
        let p = widgets::pal(ui);
        let sub = match self.import.len() {
            0 => "None found".to_string(),
            1 => "1 connection found".into(),
            n => format!("{n} connections found"),
        };
        if widgets::page_header(ui, "Import from FortiClient", &sub, |_| {}) {
            self.back();
            return;
        }
        body(ui, "import", |ui| {
            ui.add_space(4.0);
            if self.import.is_empty() {
                widgets::card(ui, true, |ui| {
                    widgets::help(ui, "FortiClient has no VPN connections on this PC.");
                });
                return;
            }
            widgets::card(ui, false, |ui| {
                for (k, item) in self.import.iter_mut().enumerate() {
                    let (_, conn) = integrations::of(&item.profile);
                    let mut desc = format!(
                        "{} · {}",
                        conn.full_name,
                        integrations::hosts_line(&integrations::servers(&item.profile))
                    );
                    if let Some(note) = &item.note {
                        desc.push('\n');
                        desc.push_str(note);
                    }
                    let skip = item
                        .note
                        .as_deref()
                        .is_some_and(|n| n.starts_with("Already"));
                    if widgets::check_row(ui, item.checked, &item.name, Some(&desc), k > 0)
                        .clicked()
                        && !skip
                    {
                        item.checked = !item.checked;
                    }
                }
            });
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(
                    "Passwords and pre-shared keys aren't copied. Polytunnel asks for them when \
                     you connect.",
                )
                .size(12.0)
                .color(p.text3),
            );
        });
    }

    pub(in crate::gui) fn import_footer(&mut self, ui: &mut Ui) {
        let checked = self.import.iter().filter(|i| i.checked).count();
        let mut go = false;
        let mut cancel = false;
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            cancel = widgets::button(ui, Button::Secondary, "Cancel", None, false).clicked();
            ui.add_enabled_ui(checked > 0, |ui| {
                go = widgets::button(
                    ui,
                    Button::Primary,
                    &format!("Import {checked}"),
                    None,
                    false,
                )
                .clicked();
            });
        });
        if go {
            self.do_import();
        } else if cancel {
            self.import.clear();
            self.back();
        }
    }
}

/// The ⋮ menu of a profile.
fn menu_items(ui: &mut Ui, name: &str, read_only: bool, todo: &mut Vec<Do>) {
    let p = widgets::pal(ui);
    ui.add_enabled_ui(!read_only, |ui| {
        if menu_item(ui, Icon::Edit, "Edit", p.text) {
            todo.push(Do::Edit(name.to_string()));
            ui.close();
        }
        if menu_item(ui, Icon::Copy, "Duplicate", p.text) {
            todo.push(Do::Duplicate(name.to_string()));
            ui.close();
        }
        ui.separator();
        if menu_item(ui, Icon::Trash, "Delete…", p.red_text) {
            todo.push(Do::Delete(name.to_string()));
            ui.close();
        }
    });
}

/// A 36 point menu item with an icon. True when chosen.
pub(in crate::gui) fn menu_item(ui: &mut Ui, icon: Icon, text: &str, ink: egui::Color32) -> bool {
    let p = widgets::pal(ui);
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width().max(168.0), 36.0),
        egui::Sense::click(),
    );
    if response.hovered() || response.has_focus() {
        ui.painter()
            .rect_filled(rect, egui::CornerRadius::same(4), p.surface3);
    }
    crate::gui::icons::paint(
        ui.painter(),
        egui::Rect::from_min_size(
            rect.left_center() + egui::vec2(12.0, -8.0),
            egui::vec2(16.0, 16.0),
        ),
        icon,
        ink,
    );
    ui.painter().text(
        rect.left_center() + egui::vec2(40.0, 0.0),
        egui::Align2::LEFT_CENTER,
        text,
        crate::gui::theme::regular(14.0),
        ink,
    );
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

/// A row's trailing chevron.
fn chevron(ui: &mut Ui) {
    let p = widgets::pal(ui);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
    crate::gui::icons::paint(ui.painter(), rect, Icon::ChevronRight, p.text3);
}

#[cfg(test)]
mod tests {
    use super::*;
    use polytunnel_core::profile::Profile;

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

    #[test]
    fn profiles_are_counted() {
        let profile = Profile::GlobalProtect(GlobalProtectProfile {
            portal: "vpn.example.com".into(),
            ..Default::default()
        });
        assert_eq!(
            integrations::profile_line(&profile),
            "GlobalProtect · vpn.example.com"
        );
    }
}
