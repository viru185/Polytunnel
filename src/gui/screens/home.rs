//! Home: the kill switch chip, the connect button and what the connection is doing, one
//! banner slot, the connection card (live figures, details, gateway) and the profiles.

use eframe::egui::{self, Align2, CornerRadius, Rect, Sense, Shadow, Ui, pos2, vec2};
use polytunnel_core::ipc::{KillSwitchMode, KillSwitchSettings, Status};
use polytunnel_core::profile::Profile;

use super::body;
use super::profiles::{GatewayMode, gateway_mode};
use crate::connect;
use crate::gui::icons::{self, Icon};
use crate::gui::integrations::{self, Gateways};
use crate::gui::widgets::{self, Banner, Kind as Button, Lead, Mood, Tone};
use crate::gui::{App, Confirm, Page, active_profile, bytes, elapsed, theme};

/// What Home shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No profiles yet.
    First,
    /// The service has not answered yet.
    Checking,
    Idle,
    /// Lockdown is on and nothing is connected: no internet.
    Lockdown,
    /// The connection dropped and the kill switch holds traffic.
    Blocked,
    Connecting,
    /// A question is open (sign-in, code, key, certificate).
    Waiting,
    /// Sign-in is in the browser.
    Browser,
    /// Sign-in is in Polytunnel's window because the kill switch holds traffic.
    Held,
    Connected,
    Limited,
    Reconnecting,
    Disconnecting,
    Failed,
    Service,
}

/// What the big button does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Connect,
    Cancel,
    Disconnect,
    TryAgain,
    Nothing,
}

/// The hero for `state`: button mood and label, the action, the state word and its colour
/// (None: the normal text colour).
pub fn hero_of(state: State) -> (Mood, &'static str, Action, &'static str) {
    match state {
        State::First | State::Idle => (Mood::Cta, "Connect", Action::Connect, "Not connected"),
        State::Checking => (Mood::Busy, "", Action::Nothing, "Checking…"),
        State::Lockdown => (Mood::Cta, "Connect", Action::Connect, "Internet blocked"),
        State::Blocked => (
            Mood::Blocked,
            "Try again",
            Action::TryAgain,
            "Internet blocked",
        ),
        State::Connecting => (Mood::Busy, "Cancel", Action::Cancel, "Connecting…"),
        State::Waiting | State::Browser | State::Held => {
            (Mood::Busy, "Cancel", Action::Cancel, "Waiting for you")
        }
        State::Connected => (Mood::Good, "Disconnect", Action::Disconnect, "Connected"),
        State::Limited => (
            Mood::Warn,
            "Disconnect",
            Action::Disconnect,
            "Connected, limited",
        ),
        State::Reconnecting => (
            Mood::WarnSpin,
            "Disconnect",
            Action::Disconnect,
            "Reconnecting…",
        ),
        State::Disconnecting => (Mood::Busy, "", Action::Nothing, "Disconnecting…"),
        State::Failed => (Mood::Bad, "Try again", Action::TryAgain, "Couldn't connect"),
        State::Service => (Mood::Off, "Connect", Action::Nothing, "Service stopped"),
    }
}

/// A short title for a failure message (the banner's first line).
pub fn failure_title(message: &str) -> &'static str {
    let m = message.to_ascii_lowercase();
    if m.contains("certificate") {
        "The gateway's certificate wasn't trusted"
    } else if m.contains("authentication") || m.contains("rejected") || m.contains("password") {
        "The gateway rejected the sign-in"
    } else if m.contains("cannot be reached")
        || m.contains("network error")
        || m.contains("timed out")
    {
        "Couldn't reach the gateway"
    } else {
        "The connection couldn't be set up"
    }
}

/// What to do about a failure (the banner's second sentence).
pub fn failure_hint(message: &str) -> &'static str {
    match failure_title(message) {
        "Couldn't reach the gateway" => "Check your internet connection, then try again.",
        "The gateway rejected the sign-in" => "Check your username and password, then try again.",
        "The gateway's certificate wasn't trusted" => {
            "Ask IT whether the gateway's certificate changed."
        }
        _ => "Open Details to see what happened.",
    }
}

/// The tunnel in plain words.
fn tunnel_name(transport: &str) -> String {
    match transport.to_ascii_lowercase().as_str() {
        "esp" => "Fast (UDP, ESP)".into(),
        "tls" => "Steady (TCP, TLS)".into(),
        "ppp" => "TCP (PPP over TLS)".into(),
        other => other.to_uppercase(),
    }
}

/// The current profile's pill on its row, for `state`.
fn row_pill(state: State) -> Option<(&'static str, Tone)> {
    match state {
        State::Connecting => Some(("Connecting…", Tone::Accent)),
        State::Waiting | State::Browser | State::Held => Some(("Waiting", Tone::Accent)),
        State::Connected => Some(("Connected", Tone::Good)),
        State::Limited => Some(("Limited", Tone::Warn)),
        State::Reconnecting => Some(("Reconnecting…", Tone::Warn)),
        State::Failed => Some(("Failed", Tone::Bad)),
        State::Blocked => Some(("Dropped", Tone::Warn)),
        _ => None,
    }
}

/// Things pressed on Home, done after drawing.
enum Do {
    Hero(Action),
    Connect(String),
    Select(String),
    Go(Page),
    Settings,
    Activity,
    Install(String),
    UpdateLater,
    SaveReport,
    Dismiss,
    Unblock,
    WhileConnected,
    StartService,
    AddProfile,
    Import,
    ToggleDetails,
    OpenBrowser,
    PasteToggle,
    UsePaste,
}

impl App {
    /// The state Home shows now.
    pub(in crate::gui) fn home_state(&self) -> State {
        if self.profiles.profiles.is_empty() && self.load_error.is_none() && self.worker.is_none() {
            return State::First;
        }
        let busy = || {
            if self.browser.is_some() {
                State::Browser
            } else if self.signin_held {
                State::Held
            } else if self.prompt.is_some()
                || matches!(&self.status, Some(Ok(Status::NeedsInput { .. })))
            {
                State::Waiting
            } else {
                State::Connecting
            }
        };
        let mode = self.killswitch.as_ref().map(|(s, _, _)| s.mode);
        match &self.status {
            None => State::Checking,
            Some(Err(_)) => State::Service,
            Some(Ok(status)) => match status {
                _ if self.worker.is_some()
                    && !matches!(
                        status,
                        Status::Connected { .. } | Status::Reconnecting { .. }
                    ) =>
                {
                    busy()
                }
                Status::Connecting { .. } | Status::NeedsInput { .. } => busy(),
                Status::Connected { notice: None, .. } => State::Connected,
                Status::Connected { .. } => State::Limited,
                Status::Reconnecting { .. } => State::Reconnecting,
                Status::Disconnecting { .. } => State::Disconnecting,
                Status::Failed { .. } => State::Failed,
                Status::Idle {} => {
                    if mode == Some(KillSwitchMode::Always) {
                        State::Lockdown
                    } else if self.traffic_held() {
                        State::Blocked
                    } else if self
                        .last_attempt
                        .as_ref()
                        .is_some_and(|a| a.result.is_err() && !a.dismissed)
                    {
                        State::Failed
                    } else {
                        State::Idle
                    }
                }
            },
        }
    }

    /// The failure Home shows (the service's, or this window's last attempt).
    fn failure_message(&self) -> String {
        match &self.status {
            Some(Ok(Status::Failed { message, .. })) => message.clone(),
            _ => self
                .last_attempt
                .as_ref()
                .and_then(|a| a.result.clone().err())
                .unwrap_or_default(),
        }
    }

    pub(in crate::gui) fn home_page(&mut self, ui: &mut Ui) {
        let state = self.home_state();
        let mut todo: Vec<Do> = Vec::new();
        self.home_header(ui, state, &mut todo);
        if state == State::First {
            self.first_run(ui, &mut todo);
        } else {
            body(ui, "home", |ui| {
                self.hero(ui, state, &mut todo);
                self.banner_slot(ui, state, &mut todo);
                self.connection_card(ui, state, &mut todo);
                self.profile_list(ui, state, &mut todo);
            });
        }
        let ctx = ui.ctx().clone();
        for action in todo {
            self.home_do(&ctx, state, action);
        }
    }

    fn home_header(&self, ui: &mut Ui, state: State, todo: &mut Vec<Do>) {
        let p = widgets::pal(ui);
        let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 52.0), Sense::hover());
        widgets::place(
            ui,
            egui::UiBuilder::new()
                .max_rect(Rect::from_min_max(
                    pos2(rect.left() + 16.0, rect.top()),
                    pos2(rect.right() - 12.0, rect.bottom()),
                ))
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
            |ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                if state != State::First
                    && let Some((settings, active, _)) = &self.killswitch
                {
                    let connected = matches!(
                        state,
                        State::Connected | State::Limited | State::Reconnecting
                    );
                    let (icon, text, warn) = match settings.mode {
                        KillSwitchMode::Off => (Icon::Shield, "Kill switch off", false),
                        KillSwitchMode::Always => (Icon::Lock, "Lockdown", true),
                        KillSwitchMode::Connected if connected => {
                            (Icon::ShieldCheck, "Kill switch on", false)
                        }
                        KillSwitchMode::Connected if *active => {
                            (Icon::Shield, "Blocking internet", true)
                        }
                        KillSwitchMode::Connected => (Icon::Shield, "Kill switch ready", false),
                    };
                    if widgets::chip(ui, icon, text, warn)
                        .on_hover_text("Kill switch settings")
                        .clicked()
                    {
                        todo.push(Do::Settings);
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if widgets::icon_button(ui, Icon::Gear, "Settings", 36.0, None).clicked() {
                        todo.push(Do::Settings);
                    }
                    let problem = matches!(state, State::Service | State::Blocked)
                        || self
                            .last_attempt
                            .as_ref()
                            .is_some_and(|a| a.result.is_err() && !a.dismissed);
                    let tip = if problem {
                        "Activity: the last attempt failed"
                    } else {
                        "Activity"
                    };
                    if widgets::icon_button(ui, Icon::Log, tip, 36.0, problem.then_some(p.red))
                        .clicked()
                    {
                        todo.push(Do::Activity);
                    }
                });
            },
        );
    }

    fn first_run(&mut self, ui: &mut Ui, todo: &mut Vec<Do>) {
        let p = widgets::pal(ui);
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
        body(ui, "first", |ui| {
            let height = ui.available_height().max(480.0);
            let content = 88.0 + 24.0 + 32.0 + 8.0 + 40.0 + 32.0 + 36.0 + 8.0 + 36.0 + 16.0 + 16.0;
            ui.add_space(((height - content) / 2.0 - 24.0).max(16.0));
            ui.vertical_centered(|ui| {
                let (r, _) = ui.allocate_exact_size(vec2(88.0, 88.0), Sense::hover());
                ui.painter().add(
                    Shadow {
                        offset: [0, 12],
                        blur: 28,
                        spread: 0,
                        color: p.accent_shadow,
                    }
                    .as_shape(r.shrink(4.0), CornerRadius::same(20)),
                );
                let logo = widgets::logo_texture(ui.ctx());
                ui.painter().image(
                    logo.id(),
                    r,
                    Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
                    egui::Color32::WHITE,
                );
                ui.add_space(24.0);
                ui.label(
                    egui::RichText::new("Welcome to Polytunnel")
                        .font(theme::semibold(26.0))
                        .color(p.text),
                );
                ui.add_space(8.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "Add your organization's VPN once. After that, connecting is one \
                             click.",
                        )
                        .size(14.0)
                        .color(p.text2),
                    )
                    .wrap(),
                );
            });
            ui.add_space(32.0);
            if widgets::button_block(ui, Button::Primary, "Add a profile", Some(Icon::Plus))
                .clicked()
            {
                todo.push(Do::AddProfile);
            }
            if cfg!(windows) && found > 0 {
                ui.add_space(8.0);
                let label = format!("Import from FortiClient · {found} found");
                if widgets::button_block(ui, Button::Secondary, &label, Some(Icon::Download))
                    .clicked()
                {
                    todo.push(Do::Import);
                }
            }
            ui.add_space(16.0);
            let names: Vec<&str> = integrations::ALL.iter().map(|i| i.name).collect();
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new(format!("Works with {}.", names.join(" and ")))
                        .size(12.0)
                        .color(p.text3),
                );
            });
        });
    }

    fn hero(&self, ui: &mut Ui, state: State, todo: &mut Vec<Do>) {
        let p = widgets::pal(ui);
        let (mood, label, action, word) = hero_of(state);
        let current = self.current_profile();
        let profile = current.as_deref().and_then(|n| self.profiles.get(n));
        // The main server only: the gateway row below says how many backups there are.
        let hosts = profile
            .and_then(|pr| integrations::servers(pr).into_iter().next())
            .map(|s| s.trim_start_matches("https://").to_string())
            .unwrap_or_default();
        let name = current.clone().unwrap_or_default();
        let server = match &self.status {
            Some(Ok(Status::Connected { server, .. } | Status::Reconnecting { server, .. })) => {
                server.clone()
            }
            _ => hosts.clone(),
        };
        let line = match state {
            State::Checking | State::Disconnecting => String::new(),
            State::Idle | State::Connecting | State::Failed if name.is_empty() => {
                "Choose a profile below.".into()
            }
            State::Idle | State::Connecting | State::Failed => format!("{name} · {hosts}"),
            State::Lockdown => "Lockdown is on. Connect to use the internet.".into(),
            State::Blocked => format!("{name} dropped, so the kill switch is holding traffic."),
            State::Waiting => format!("{name} needs your sign-in."),
            State::Browser => format!("Finish signing in to {name} in your browser."),
            State::Held => format!("Sign in to {name} in the Polytunnel window."),
            State::Connected | State::Limited => format!("{name} · {server}"),
            State::Reconnecting => match &self.status {
                Some(Ok(Status::Reconnecting { attempt, .. })) => {
                    let left = self
                        .reconnect_started
                        .map_or(300, |t| 300u64.saturating_sub(t.elapsed().as_secs()));
                    format!(
                        "{name} · attempt {attempt} · trying until {}",
                        crate::gui::clock_in(left)
                    )
                }
                _ => name.clone(),
            },
            State::Service => "Connecting needs the Polytunnel service.".into(),
            State::First => String::new(),
        };
        let word_color = match state {
            State::Failed => p.red_text,
            State::Blocked | State::Lockdown => p.amber_text,
            State::Service => p.text2,
            _ => p.text,
        };
        let connected = matches!(state, State::Connected | State::Limited);
        let light_on = if matches!(mood, Mood::Good | Mood::Warn) {
            ui.ctx()
                .animate_bool_with_time(egui::Id::unique("hero-light"), connected, 0.24)
        } else {
            1.0
        };
        ui.add_space(4.0);
        ui.vertical_centered(|ui| {
            let response = widgets::hero_button(ui, mood, label, light_on);
            let response = match action {
                Action::Connect => response.on_hover_text("Connect"),
                Action::Cancel => response.on_hover_text("Stop connecting"),
                Action::Disconnect => response.on_hover_text("Disconnect"),
                Action::TryAgain => response.on_hover_text("Try again"),
                Action::Nothing if state == State::Service => {
                    response.on_hover_text("Connecting needs the Polytunnel service")
                }
                Action::Nothing => response,
            };
            if response.clicked() && action != Action::Nothing {
                todo.push(Do::Hero(action));
            }
            ui.add_space(12.0);
            ui.label(
                egui::RichText::new(word)
                    .font(theme::semibold(26.0))
                    .color(word_color),
            );
            if !line.is_empty() {
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(egui::RichText::new(&line).size(14.0).color(p.text2))
                        .truncate(),
                );
            }
            if state == State::Connecting {
                ui.add_space(12.0);
                self.steps(ui);
            }
        });
        ui.add_space(16.0);
    }

    /// The connecting steps: gateway found, signing in, tunnel.
    fn steps(&self, ui: &mut Ui) {
        let p = widgets::pal(ui);
        // The window signs in first; then the service brings the tunnel up.
        let tunnel =
            matches!(&self.status, Some(Ok(Status::Connecting { .. }))) && self.worker.is_none();
        let steps = [
            (Icon::Check, "Gateway found", true, false),
            (
                if tunnel { Icon::Check } else { Icon::Refresh },
                "Signing in",
                tunnel,
                !tunnel,
            ),
            (
                if tunnel { Icon::Refresh } else { Icon::Lock },
                "Tunnel",
                false,
                tunnel,
            ),
        ];
        let font = theme::regular(12.0);
        let semi = theme::semibold(12.0);
        let widths: Vec<f32> = steps
            .iter()
            .map(|(_, t, _, now)| {
                20.0 + ui
                    .painter()
                    .layout_no_wrap(
                        t.to_string(),
                        if *now { semi.clone() } else { font.clone() },
                        p.text,
                    )
                    .size()
                    .x
            })
            .collect();
        let total: f32 = widths.iter().sum::<f32>() + 16.0 * 2.0;
        let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 16.0), Sense::hover());
        let mut x = rect.center().x - total / 2.0;
        for ((icon, text, done, now), w) in steps.iter().zip(widths) {
            let ink = if *now {
                p.accent
            } else if *done {
                p.text2
            } else {
                p.text3
            };
            icons::paint(
                ui.painter(),
                Rect::from_min_size(pos2(x, rect.top()), vec2(16.0, 16.0)),
                *icon,
                ink,
            );
            ui.painter().text(
                pos2(x + 20.0, rect.center().y),
                Align2::LEFT_CENTER,
                *text,
                if *now { semi.clone() } else { font.clone() },
                ink,
            );
            x += w + 16.0;
        }
    }

    fn banner_slot(&mut self, ui: &mut Ui, state: State, todo: &mut Vec<Do>) {
        let ks_on = self
            .killswitch
            .as_ref()
            .is_some_and(|(s, _, _)| s.mode != KillSwitchMode::Off);
        let before = ui.cursor().top();
        match state {
            State::Idle | State::Lockdown if self.update.is_some() && !self.update_later => {
                let version = self.update.clone().unwrap_or_default();
                widgets::banner(
                    ui,
                    Banner::Info,
                    Icon::Download,
                    &format!("Polytunnel {version} is ready"),
                    "Installs in about a minute and reopens by itself.",
                    |ui| {
                        if widgets::button(ui, Button::Secondary, "Install now", None, true)
                            .clicked()
                        {
                            todo.push(Do::Install(version.clone()));
                        }
                        if widgets::button(ui, Button::Quiet, "Later", None, true).clicked() {
                            todo.push(Do::UpdateLater);
                        }
                    },
                );
            }
            _ => {}
        }
        match state {
            State::Limited => {
                let notice = match &self.status {
                    Some(Ok(Status::Connected {
                        notice: Some(n), ..
                    })) => n.clone(),
                    _ => String::new(),
                };
                widgets::banner(
                    ui,
                    Banner::Warn,
                    Icon::Warning,
                    "Some sites may be blocked",
                    &format!("{notice} Send IT the report."),
                    |ui| {
                        if widgets::button(
                            ui,
                            Button::Secondary,
                            "Save report for IT",
                            Some(Icon::Download),
                            true,
                        )
                        .clicked()
                        {
                            todo.push(Do::SaveReport);
                        }
                        if widgets::button(ui, Button::Quiet, "Details", None, true).clicked() {
                            todo.push(Do::Activity);
                        }
                    },
                );
            }
            State::Reconnecting => widgets::banner(
                ui,
                Banner::Info,
                Icon::Info,
                "Your network changed",
                if ks_on {
                    "Polytunnel reconnects with the same sign-in. The kill switch holds traffic \
                     meanwhile."
                } else {
                    "Polytunnel reconnects with the same sign-in."
                },
                |_| {},
            ),
            State::Failed => {
                let message = self.failure_message();
                widgets::banner(
                    ui,
                    Banner::Bad,
                    Icon::Error,
                    failure_title(&message),
                    &format!(
                        "{}. {}",
                        message
                            .split(" (")
                            .next()
                            .unwrap_or(&message)
                            .trim_end_matches('.'),
                        failure_hint(&message)
                    ),
                    |ui| {
                        if widgets::button(ui, Button::Secondary, "Details", None, true).clicked() {
                            todo.push(Do::Activity);
                        }
                        if widgets::button(ui, Button::Quiet, "Dismiss", None, true).clicked() {
                            todo.push(Do::Dismiss);
                        }
                    },
                );
            }
            State::Blocked => widgets::banner(
                ui,
                Banner::Warn,
                Icon::Shield,
                "Nothing leaves this PC until the VPN is back",
                "Try again, or unblock to use the internet without the VPN.",
                |ui| {
                    if widgets::button(
                        ui,
                        Button::Secondary,
                        "Unblock until I reconnect",
                        None,
                        true,
                    )
                    .clicked()
                    {
                        todo.push(Do::Unblock);
                    }
                },
            ),
            State::Lockdown => widgets::banner(
                ui,
                Banner::Warn,
                Icon::Lock,
                "Lockdown keeps the internet off without the VPN",
                "Hotel and airport Wi-Fi sign-in pages won't load either.",
                |ui| {
                    if widgets::button(
                        ui,
                        Button::Secondary,
                        "Switch to While connected",
                        None,
                        true,
                    )
                    .clicked()
                    {
                        todo.push(Do::WhileConnected);
                    }
                },
            ),
            State::Service => widgets::banner(
                ui,
                Banner::Bad,
                Icon::Error,
                "The Polytunnel service isn't running",
                "It normally restarts by itself. Starting it needs administrator approval.",
                |ui| {
                    if widgets::button(
                        ui,
                        Button::Secondary,
                        "Start service",
                        Some(Icon::Uac),
                        true,
                    )
                    .clicked()
                    {
                        todo.push(Do::StartService);
                    }
                    if widgets::button(ui, Button::Quiet, "Details", None, true).clicked() {
                        todo.push(Do::Activity);
                    }
                },
            ),
            State::Held => {
                let lockdown = self
                    .killswitch
                    .as_ref()
                    .is_some_and(|(s, _, _)| s.mode == KillSwitchMode::Always);
                widgets::banner(
                    ui,
                    Banner::Info,
                    Icon::Info,
                    "Your browser is offline for now",
                    if lockdown {
                        "Lockdown keeps traffic inside the VPN, so sign-in opens in Polytunnel's \
                         own window instead."
                    } else {
                        "The kill switch is holding traffic, so sign-in opens in Polytunnel's own \
                         window instead."
                    },
                    |_| {},
                );
            }
            State::Browser => self.browser_card(ui, todo),
            _ => {}
        }
        if ui.cursor().top() > before + 1.0 {
            ui.add_space(8.0);
        }
    }

    /// While sign-in is in the browser: open it again, or paste the sign-in link.
    fn browser_card(&mut self, ui: &mut Ui, todo: &mut Vec<Do>) {
        let p = widgets::pal(ui);
        let paste_open = ui.data(|d| {
            d.get_temp::<bool>(egui::Id::unique("paste-open"))
                .unwrap_or(false)
        });
        let Some(browser) = &mut self.browser else {
            return;
        };
        widgets::card(ui, true, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.label(
                egui::RichText::new("Didn't see the page?")
                    .font(theme::semibold(14.0))
                    .color(p.text),
            );
            let text = match &browser.not_opened {
                None => {
                    "Open it again, or paste the sign-in link from a browser on another device."
                        .to_string()
                }
                Some(e) => {
                    format!("The browser couldn't be opened ({e}). Copy the link into a browser.")
                }
            };
            ui.add(
                egui::Label::new(egui::RichText::new(text).size(12.0).color(
                    if browser.not_opened.is_some() {
                        p.red_text
                    } else {
                        p.text2
                    },
                ))
                .wrap(),
            );
            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = vec2(8.0, 8.0);
                if widgets::button(
                    ui,
                    Button::Secondary,
                    "Open the page again",
                    Some(Icon::External),
                    true,
                )
                .clicked()
                {
                    todo.push(Do::OpenBrowser);
                }
                if widgets::button(
                    ui,
                    Button::Secondary,
                    "Paste the sign-in link",
                    Some(Icon::Paste),
                    true,
                )
                .clicked()
                {
                    todo.push(Do::PasteToggle);
                }
            });
            if paste_open {
                ui.add_space(12.0);
                ui.spacing_mut().item_spacing.y = 0.0;
                widgets::Field::new("Sign-in link or the final page's source")
                    .hint("globalprotectcallback:…")
                    .error(browser.paste_error.as_deref())
                    .show(ui, &mut browser.pasted);
                ui.add_space(8.0);
                let ready = !browser.pasted.trim().is_empty();
                ui.add_enabled_ui(ready, |ui| {
                    if widgets::button(ui, Button::Primary, "Use it", None, true).clicked() {
                        todo.push(Do::UsePaste);
                    }
                });
            }
        });
        ui.add_space(8.0);
    }

    fn connection_card(&self, ui: &mut Ui, state: State, todo: &mut Vec<Do>) {
        let Some(name) = self.current_profile() else {
            return;
        };
        let Some(profile) = self.profiles.get(&name).cloned() else {
            return;
        };
        if matches!(state, State::Checking) {
            return;
        }
        let live = match &self.status {
            Some(Ok(Status::Connected {
                server,
                addresses,
                transport,
                since_unix,
                notice,
                gateway,
                bytes_in,
                bytes_out,
                ..
            })) if matches!(state, State::Connected | State::Limited) => Some((
                server.clone(),
                addresses.join(", "),
                connect::transport_name(transport),
                *since_unix,
                notice.is_some(),
                gateway.clone(),
                *bytes_in,
                *bytes_out,
            )),
            _ => None,
        };
        widgets::card(ui, false, |ui| {
            let mut first = true;
            if let Some((server, addresses, tunnel, since, limited, gateway, rx, tx)) = &live {
                if widgets::stats_row(
                    ui,
                    &bytes(*rx),
                    &bytes(*tx),
                    &elapsed(*since),
                    self.details_open,
                )
                .clicked()
                {
                    todo.push(Do::ToggleDetails);
                }
                if self.details_open {
                    let p = widgets::pal(ui);
                    widgets::value_row(ui, "Server", server, None);
                    if let Some(gateway) = gateway {
                        widgets::value_row(ui, "Gateway address", gateway, None);
                    }
                    widgets::value_row(ui, "Your VPN address", addresses, None);
                    widgets::value_row(ui, "Tunnel", &tunnel_name(tunnel), None);
                    if let Profile::GlobalProtect(_) = &profile {
                        let (text, ink) = if *limited {
                            ("Limited", Some(p.amber_text))
                        } else {
                            ("Passed", None)
                        };
                        widgets::value_row(ui, "Device check", text, ink);
                    }
                }
                first = false;
            }
            self.gateway_row(ui, &name, &profile, first, todo);
        });
    }

    /// The gateway row, from what the profile's integration can do.
    fn gateway_row(
        &self,
        ui: &mut Ui,
        name: &str,
        profile: &Profile,
        first: bool,
        todo: &mut Vec<Do>,
    ) {
        let (_, t) = integrations::of(profile);
        match (t.gateways, profile) {
            (Gateways::Ranked, Profile::GlobalProtect(gp)) => {
                let connected_to = match &self.status {
                    Some(Ok(Status::Connected {
                        profile: active,
                        server,
                        ..
                    })) if active == name => Some(server.clone()),
                    _ => None,
                };
                let value = match (gateway_mode(gp), &gp.gateway, &gp.preferred_gateway) {
                    (GatewayMode::Always, Some(g), _) => format!("Only {g}"),
                    (GatewayMode::Prefer, _, Some(g)) => format!("Prefer {g}"),
                    _ => match connected_to {
                        Some(server) => format!("Fastest · {server}"),
                        None => "Fastest".into(),
                    },
                };
                if widgets::nav_row(ui, "Gateway", &value, Some(Icon::ChevronRight), first, true)
                    .on_hover_text("Choose the gateway")
                    .clicked()
                {
                    todo.push(Do::Go(Page::Gateways(name.to_string())));
                }
            }
            _ => {
                let servers = integrations::servers(profile);
                let value = integrations::hosts_line(&servers);
                let label = "Gateway";
                let chevron = (servers.len() > 1).then_some(Icon::ChevronRight);
                if widgets::nav_row(ui, label, &value, chevron, first, true).clicked()
                    && chevron.is_some()
                {
                    todo.push(Do::Go(Page::GatewayOrder(name.to_string())));
                }
            }
        }
    }

    fn profile_list(&self, ui: &mut Ui, state: State, todo: &mut Vec<Do>) {
        let mut right = |ui: &mut Ui| {
            if widgets::icon_button(ui, Icon::Plus, "Add a profile", 32.0, None).clicked() {
                todo.push(Do::AddProfile);
            }
            if widgets::link(ui, "Manage", false, None).clicked() {
                todo.push(Do::Go(Page::Profiles));
            }
        };
        widgets::section(ui, "Profiles", Some(&mut right));
        if let Some(e) = &self.load_error {
            widgets::banner(
                ui,
                Banner::Bad,
                Icon::Error,
                "Your profiles file could not be read",
                &format!(
                    "{e}\nFix or remove it, then reopen Polytunnel. Nothing is changed until then."
                ),
                |_| {},
            );
            return;
        }
        let current = self.current_profile();
        let active = active_profile(&self.status).is_some() || self.worker.is_some();
        // The current profile first, so it is always in view; the others alphabetically.
        let mut names: Vec<String> = self.profiles.profiles.keys().cloned().collect();
        if let Some(i) = current
            .as_ref()
            .and_then(|c| names.iter().position(|n| n == c))
        {
            let name = names.remove(i);
            names.insert(0, name);
        }
        let count = names.len();
        widgets::card(ui, false, |ui| {
            for (i, name) in names.iter().enumerate() {
                let Some(profile) = self.profiles.get(name) else {
                    continue;
                };
                let (integration, _) = integrations::of(profile);
                let is_current = current.as_deref() == Some(name.as_str());
                let line = integrations::profile_line(profile);
                let response = widgets::list_row(
                    ui,
                    Lead::Badge(integration.badge),
                    name,
                    &line,
                    is_current,
                    i == 0,
                    i + 1 == count,
                    |ui| {
                        if is_current {
                            if let Some((text, tone)) = row_pill(state) {
                                widgets::pill(ui, text, tone);
                            }
                        } else if state != State::Service {
                            let busy = active
                                && !matches!(state, State::Failed | State::Blocked | State::Idle);
                            let verb = if busy { "Switch" } else { "Connect" };
                            if widgets::button(ui, Button::Quiet, verb, None, true)
                                .on_hover_text(if busy {
                                    format!("Stop this connection and connect to {name}")
                                } else {
                                    format!("Connect to {name}")
                                })
                                .clicked()
                            {
                                todo.push(Do::Connect(name.clone()));
                            }
                        }
                    },
                );
                if response.clicked() && !active && !is_current {
                    todo.push(Do::Select(name.clone()));
                }
            }
        });
    }

    fn home_do(&mut self, ctx: &egui::Context, state: State, action: Do) {
        match action {
            Do::Hero(Action::Connect | Action::TryAgain) => {
                if (state == State::Blocked || state == State::Failed)
                    && let Some(a) = &mut self.last_attempt
                {
                    a.dismissed = true;
                }
                if let Some(name) = self.current_profile() {
                    self.connect(ctx, name);
                }
            }
            Do::Hero(Action::Cancel | Action::Disconnect) => {
                if !self.running.disconnect {
                    self.disconnect(ctx);
                }
            }
            Do::Hero(Action::Nothing) => {}
            Do::Connect(name) => self.connect(ctx, name),
            Do::Select(name) => {
                if let Some(a) = &mut self.last_attempt {
                    a.dismissed = true;
                }
                self.selected = Some(name);
            }
            Do::Go(page) => self.go(page),
            Do::Settings => self.go(Page::Settings),
            Do::Activity => self.go(Page::Activity),
            Do::Install(version) => self.confirm = Some(Confirm::Install(version)),
            Do::UpdateLater => self.update_later = true,
            Do::SaveReport => self.save_report(),
            Do::Dismiss => {
                if let Some(a) = &mut self.last_attempt {
                    a.dismissed = true;
                }
                if matches!(&self.status, Some(Ok(Status::Failed { .. }))) && !self.fake {
                    self.disconnect(ctx);
                }
            }
            Do::Unblock => self.disconnect(ctx),
            Do::WhileConnected => {
                let allow_lan = self
                    .killswitch
                    .as_ref()
                    .is_some_and(|(s, _, _)| s.allow_lan);
                self.set_killswitch(
                    ctx,
                    KillSwitchSettings {
                        mode: KillSwitchMode::Connected,
                        allow_lan,
                    },
                );
            }
            Do::StartService => self.start_service(),
            Do::AddProfile => self.go(Page::AddIntegration),
            Do::Import => self.scan_import(),
            Do::ToggleDetails => self.details_open = !self.details_open,
            Do::OpenBrowser => {
                if let Some(browser) = &mut self.browser {
                    browser.not_opened = crate::browser::open(&browser.url).err();
                }
            }
            Do::PasteToggle => {
                let id = egui::Id::unique("paste-open");
                let open = ctx.data(|d| d.get_temp::<bool>(id).unwrap_or(false));
                ctx.data_mut(|d| d.insert_temp(id, !open));
            }
            Do::UsePaste => {
                if let Some(browser) = &mut self.browser {
                    browser.paste_error = None;
                    let _ = browser.paste.send(browser.pasted.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heroes_say_what_the_button_does() {
        assert_eq!(hero_of(State::Idle).2, Action::Connect);
        assert_eq!(hero_of(State::Connecting).2, Action::Cancel);
        assert_eq!(hero_of(State::Waiting).3, "Waiting for you");
        assert_eq!(hero_of(State::Browser).3, "Waiting for you");
        assert_eq!(hero_of(State::Connected).1, "Disconnect");
        assert_eq!(hero_of(State::Reconnecting).1, "Disconnect");
        assert_eq!(hero_of(State::Failed).1, "Try again");
        assert_eq!(hero_of(State::Blocked).1, "Try again");
        assert_eq!(hero_of(State::Service).2, Action::Nothing);
        // Four verbs only.
        for state in [
            State::Idle,
            State::Lockdown,
            State::Blocked,
            State::Connecting,
            State::Waiting,
            State::Connected,
            State::Limited,
            State::Reconnecting,
            State::Failed,
        ] {
            assert!(["Connect", "Cancel", "Disconnect", "Try again"].contains(&hero_of(state).1));
        }
    }

    #[test]
    fn failures_get_a_short_title() {
        assert_eq!(
            failure_title("gw.example.net cannot be reached (network error: timed out)"),
            "Couldn't reach the gateway"
        );
        assert_eq!(
            failure_title("authentication failed: bad password"),
            "The gateway rejected the sign-in"
        );
        assert_eq!(
            failure_title("the server's certificate (AA) is not the trusted one"),
            "The gateway's certificate wasn't trusted"
        );
        assert_eq!(
            failure_title("something odd"),
            "The connection couldn't be set up"
        );
    }
}
