//! The Polytunnel window (egui). It runs only while open and exits completely when closed;
//! the always-on tray agent ([`agent`]) is a separate, tiny process.

pub mod agent;
mod worker;

use std::collections::VecDeque;
use std::fs;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use eframe::egui;
use polytunnel_core::Secret;
use polytunnel_core::ipc::Status;
use polytunnel_core::profile::{
    EapMethodName, FortinetIpsecProfile, FortinetSslProfile, GatewayPolicy, GlobalProtectProfile,
    IpsecTransport, ProbeMethod, Profile, Profiles, normalize_server, valid_host,
};
use polytunnel_gp::rank::{self, Probe, Ranking};

use crate::instance::{self, Instance, Message, Role};
use crate::{autostart, connect, forticlient, gateways, paths, uri};

const TITLE: &str = "Polytunnel";
const LOG_LINES: usize = 200;

/// Opens the window (or brings the open one to the front) and makes sure the tray agent runs.
pub fn run_window() -> i32 {
    #[cfg(windows)]
    crate::win::hide_own_console();
    let instance = match instance::claim(Role::Gui) {
        Ok(Some(instance)) => Some(instance),
        Ok(None) => {
            return match instance::send(Role::Gui, Message::Show) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("polytunnel: the window is already open ({e})");
                    1
                }
            };
        }
        Err(e) => {
            eprintln!("polytunnel: single-instance lock unavailable: {e}");
            None
        }
    };
    agent::ensure_running();

    let icon = egui::IconData {
        rgba: include_bytes!(concat!(env!("OUT_DIR"), "/icon48.rgba")).to_vec(),
        width: 48,
        height: 48,
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(TITLE)
            .with_app_id("polytunnel")
            .with_icon(icon)
            .with_inner_size([760.0, 520.0])
            .with_min_inner_size([560.0, 380.0]),
        ..Default::default()
    };
    let result = eframe::run_native(
        TITLE,
        options,
        Box::new(move |cc| {
            let (ipc_tx, ipc_rx) = mpsc::channel();
            if let Some(instance) = &instance {
                let ctx = cc.egui_ctx.clone();
                let _ = instance.listen(Role::Gui, move |m| {
                    let _ = ipc_tx.send(m);
                    ctx.request_repaint();
                });
            }
            Ok(Box::new(App::new(&cc.egui_ctx, ipc_rx, instance)))
        }),
    );
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("polytunnel: cannot open the window: {e}");
            1
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    GlobalProtect,
    FortinetSsl,
    FortinetIpsec,
}

/// The profile form.
struct Editor {
    original: Option<String>,
    kind: Kind,
    name: String,
    server: String,
    username: String,
    gateway: String,
    preferred: String,
    realm: String,
    strict_tiers: bool,
    tcp_probe: bool,
    local_id: String,
    dh_group: String,
    pfs: bool,
    xauth: bool,
    ike2: bool,
    eap: bool,
    tcp: bool,
    /// The IPsec profile being edited: settings the form does not show are kept.
    ipsec_base: FortinetIpsecProfile,
    error: Option<String>,
}

impl Editor {
    fn new(kind: Kind) -> Self {
        Editor {
            original: None,
            kind,
            name: String::new(),
            server: String::new(),
            username: String::new(),
            gateway: String::new(),
            preferred: String::new(),
            realm: String::new(),
            strict_tiers: false,
            tcp_probe: false,
            local_id: String::new(),
            dh_group: crate::ipsec::DEFAULT_DH_GROUP.to_string(),
            pfs: true,
            xauth: true,
            ike2: false,
            eap: false,
            tcp: false,
            ipsec_base: FortinetIpsecProfile::default(),
            error: None,
        }
    }

    fn from_profile(name: &str, profile: &Profile) -> Self {
        let text = |v: &Option<String>| v.clone().unwrap_or_default();
        match profile {
            Profile::GlobalProtect(p) => Editor {
                original: Some(name.to_string()),
                name: name.to_string(),
                server: p.portal.clone(),
                username: text(&p.username),
                gateway: text(&p.gateway),
                preferred: text(&p.preferred_gateway),
                strict_tiers: p.gateway_selection == Some(GatewayPolicy::StrictTiers),
                tcp_probe: p.probe == Some(ProbeMethod::Tcp),
                ..Editor::new(Kind::GlobalProtect)
            },
            Profile::FortinetSsl(p) => Editor {
                original: Some(name.to_string()),
                name: name.to_string(),
                server: p.server.clone(),
                username: text(&p.username),
                realm: text(&p.realm),
                ..Editor::new(Kind::FortinetSsl)
            },
            Profile::FortinetIpsec(p) => Editor {
                original: Some(name.to_string()),
                name: name.to_string(),
                server: p.server.clone(),
                username: text(&p.username),
                local_id: text(&p.local_id),
                dh_group: p
                    .dh_group
                    .unwrap_or(crate::ipsec::DEFAULT_DH_GROUP)
                    .to_string(),
                pfs: p.pfs_group != Some(0),
                xauth: crate::ipsec::uses_xauth(p),
                ike2: crate::ipsec::ike_version(p) == 2,
                eap: p.eap.is_some(),
                tcp: p.transport == Some(IpsecTransport::Tcp),
                ipsec_base: p.clone(),
                ..Editor::new(Kind::FortinetIpsec)
            },
        }
    }

    fn to_profile(&self) -> Result<(String, Profile), String> {
        let name = self.name.trim().to_string();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("Use letters, digits, '-' or '_' for the name.".into());
        }
        if self.kind == Kind::FortinetIpsec {
            if !valid_host(self.server.trim()) {
                return Err(
                    "Enter the gateway's host name or IPv4 address (no https:// or port).".into(),
                );
            }
        } else {
            normalize_server(&self.server).map_err(|e| e.to_string())?;
        }
        let opt = |s: &str| Some(s.trim().to_string()).filter(|s| !s.is_empty());
        let profile = match self.kind {
            Kind::GlobalProtect => Profile::GlobalProtect(GlobalProtectProfile {
                portal: self.server.trim().to_string(),
                username: opt(&self.username),
                gateway: opt(&self.gateway),
                preferred_gateway: opt(&self.preferred),
                gateway_selection: self.strict_tiers.then_some(GatewayPolicy::StrictTiers),
                probe: self.tcp_probe.then_some(ProbeMethod::Tcp),
                ..Default::default()
            }),
            Kind::FortinetSsl => Profile::FortinetSsl(FortinetSslProfile {
                server: self.server.trim().to_string(),
                username: opt(&self.username),
                realm: opt(&self.realm),
            }),
            Kind::FortinetIpsec => {
                let group: u16 = self
                    .dh_group
                    .trim()
                    .parse()
                    .ok()
                    .filter(|g| polytunnel_core::ipc::ike_group_name(*g).is_some())
                    .ok_or("Use DH group 2, 5, 14, 15, 16, 19 or 20.")?;
                let base = &self.ipsec_base;
                Profile::FortinetIpsec(FortinetIpsecProfile {
                    server: self.server.trim().to_string(),
                    username: opt(&self.username),
                    local_id: opt(&self.local_id),
                    dh_group: (group != crate::ipsec::DEFAULT_DH_GROUP).then_some(group),
                    pfs_group: match (self.pfs, base.pfs_group) {
                        (false, _) => Some(0),
                        (true, Some(0)) => None,
                        (true, other) => other,
                    },
                    xauth: (!self.ike2 && !self.xauth).then_some(false),
                    ike_version: self.ike2.then_some(2),
                    eap: if self.ike2 && self.eap {
                        base.eap.or(Some(EapMethodName::Mschapv2))
                    } else {
                        None
                    },
                    transport: (self.ike2 && self.tcp).then_some(IpsecTransport::Tcp),
                    server_auth: base.server_auth.filter(|_| self.ike2),
                    tcp_port: base.tcp_port.filter(|_| self.ike2 && self.tcp),
                    ..base.clone()
                })
            }
        };
        Ok((name, profile))
    }
}

enum PromptUi {
    Credentials {
        title: String,
        message: Option<String>,
        username_label: String,
        password_label: String,
        username: String,
        password: String,
        reply: Sender<Option<(String, Secret)>>,
    },
    Code {
        title: String,
        message: String,
        code: String,
        reply: Sender<Option<Secret>>,
    },
}

struct BrowserUi {
    server: String,
    url: String,
    pasted: String,
    paste: Sender<String>,
}

struct GatewaysUi {
    profile: String,
    ranking: Option<Ranking>,
    note: Option<String>,
    pending: Option<Receiver<Result<Ranking, String>>>,
}

struct App {
    profiles: Profiles,
    load_error: Option<String>,
    selected: Option<String>,
    editor: Option<Editor>,
    status: Result<Status, String>,
    status_rx: Receiver<Result<Status, String>>,
    worker: Option<worker::Worker>,
    prompt: Option<PromptUi>,
    browser: Option<BrowserUi>,
    log: VecDeque<String>,
    gateways: Option<GatewaysUi>,
    ipc_rx: Receiver<Message>,
    autostart: bool,
    link_status: String,
    _instance: Option<Instance>,
}

fn load_profiles() -> (Profiles, Option<String>) {
    let Some(path) = paths::profiles_file() else {
        return (
            Profiles::default(),
            Some("No configuration directory".into()),
        );
    };
    match fs::read_to_string(&path) {
        Ok(text) => match Profiles::parse(&text) {
            Ok(p) => (p, None),
            Err(e) => (
                Profiles::default(),
                Some(format!("{}: {e}", path.display())),
            ),
        },
        Err(_) => (Profiles::default(), None),
    }
}

fn save_profiles(profiles: &Profiles) -> Result<(), String> {
    let path = paths::profiles_file().ok_or("no configuration directory")?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    fs::write(&path, profiles.to_toml()).map_err(|e| format!("{}: {e}", path.display()))
}

fn link_status_text() -> String {
    match uri::status() {
        uri::Status::Polytunnel(_) => "Polytunnel handles GlobalProtect browser logins.".into(),
        uri::Status::Other(_) => "Another program handles GlobalProtect browser logins.".into(),
        uri::Status::NotRegistered => "No program handles GlobalProtect browser logins.".into(),
        uri::Status::Unsupported => "Browser-login hand-off is not available here yet.".into(),
    }
}

impl App {
    fn new(ctx: &egui::Context, ipc_rx: Receiver<Message>, instance: Option<Instance>) -> Self {
        let (status_tx, status_rx) = mpsc::channel();
        let repaint = ctx.clone();
        thread::Builder::new()
            .name("status".into())
            .spawn(move || {
                loop {
                    if status_tx.send(connect::status()).is_err() {
                        return;
                    }
                    repaint.request_repaint();
                    thread::sleep(Duration::from_millis(1500));
                }
            })
            .ok();
        let (profiles, load_error) = load_profiles();
        let selected = profiles.profiles.keys().next().cloned();
        App {
            profiles,
            load_error,
            selected,
            editor: None,
            status: Ok(Status::Idle {}),
            status_rx,
            worker: None,
            prompt: None,
            browser: None,
            log: VecDeque::new(),
            gateways: None,
            ipc_rx,
            autostart: autostart::enabled(),
            link_status: link_status_text(),
            _instance: instance,
        }
    }

    fn log(&mut self, line: impl Into<String>) {
        if self.log.len() >= LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back(line.into());
    }

    fn busy(&self) -> bool {
        self.worker.is_some()
    }

    fn connect(&mut self, ctx: &egui::Context, name: String) {
        let Some(profile) = self.profiles.get(&name).cloned() else {
            return;
        };
        self.log(format!("Connecting with '{name}'..."));
        let repaint = ctx.clone();
        self.worker = Some(worker::start(name, profile, move || {
            repaint.request_repaint()
        }));
    }

    fn poll(&mut self, ctx: &egui::Context) {
        while let Ok(status) = self.status_rx.try_recv() {
            self.status = status;
        }
        while let Ok(message) = self.ipc_rx.try_recv() {
            match message {
                Message::Show => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                Message::Quit => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            }
        }
        let mut finished = false;
        let mut lines = Vec::new();
        if let Some(worker) = &self.worker {
            while let Ok(event) = worker.events.try_recv() {
                match event {
                    worker::Event::Progress(line) => lines.push(line),
                    worker::Event::Prompt(worker::Prompt::Credentials {
                        title,
                        message,
                        username_label,
                        password_label,
                        username,
                        reply,
                    }) => {
                        self.prompt = Some(PromptUi::Credentials {
                            title,
                            message,
                            username_label,
                            password_label,
                            username: username.unwrap_or_default(),
                            password: String::new(),
                            reply,
                        });
                    }
                    worker::Event::Prompt(worker::Prompt::Code {
                        title,
                        message,
                        reply,
                    }) => {
                        self.prompt = Some(PromptUi::Code {
                            title,
                            message,
                            code: String::new(),
                            reply,
                        });
                    }
                    worker::Event::Prompt(worker::Prompt::Browser { server, url, paste }) => {
                        self.browser = Some(BrowserUi {
                            server,
                            url,
                            pasted: String::new(),
                            paste,
                        });
                    }
                    worker::Event::BrowserDone => self.browser = None,
                    worker::Event::Finished(result) => {
                        lines.push(match result {
                            Ok(message) => message,
                            Err(e) => format!("Could not connect: {e}"),
                        });
                        finished = true;
                    }
                }
            }
        }
        for line in lines {
            self.log(line);
        }
        if finished {
            self.worker = None;
            self.prompt = None;
            self.browser = None;
        }
        if let Some(view) = &mut self.gateways
            && let Some(rx) = &view.pending
            && let Ok(result) = rx.try_recv()
        {
            view.pending = None;
            match result {
                Ok(ranking) => {
                    view.note = ranking.explanation.last().cloned();
                    view.ranking = Some(ranking);
                }
                Err(e) => view.note = Some(e),
            }
        }
    }

    fn find_best_gateway(&mut self, ctx: &egui::Context, name: &str, p: &GlobalProtectProfile) {
        let Ok(portal) = normalize_server(&p.portal) else {
            return;
        };
        let prefs = gateways::GatewayPrefs {
            preferred: p.preferred_gateway.clone(),
            policy: p.gateway_selection.unwrap_or_default(),
            method: p.probe.unwrap_or_default(),
        };
        let (tx, rx) = mpsc::channel();
        let repaint = ctx.clone();
        thread::spawn(move || {
            let result = match gateways::load_cache(&portal) {
                None => Err("Connect once to fetch this portal's gateway list.".to_string()),
                Some(c) if c.gateways.is_empty() => {
                    Err("This portal lists no separate gateways.".to_string())
                }
                Some(c) => Ok(gateways::rank_gateways(
                    &c.gateways,
                    c.region.as_deref(),
                    c.cutoff_time,
                    &prefs,
                )),
            };
            let _ = tx.send(result);
            repaint.request_repaint();
        });
        self.gateways = Some(GatewaysUi {
            profile: name.to_string(),
            ranking: None,
            note: Some("Measuring the gateways...".into()),
            pending: Some(rx),
        });
    }

    fn set_preferred(&mut self, name: &str, label: Option<String>) {
        if let Some(Profile::GlobalProtect(p)) = self.profiles.profiles.get_mut(name) {
            p.preferred_gateway = label;
            if let Err(e) = save_profiles(&self.profiles) {
                self.log(format!("Could not save the profiles: {e}"));
            }
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let (text, color) = match &self.status {
                Ok(s @ Status::Connected { .. }) => {
                    (connect::describe(s), egui::Color32::from_rgb(22, 163, 74))
                }
                Ok(Status::Failed { message, .. }) => (
                    format!("Not connected: {message}"),
                    egui::Color32::from_rgb(220, 38, 38),
                ),
                Ok(s) => (connect::describe(s), ui.visuals().text_color()),
                Err(e) => (e.clone(), egui::Color32::from_rgb(217, 119, 6)),
            };
            ui.colored_label(color, text);
            let connected = matches!(
                &self.status,
                Ok(Status::Connected { .. }
                    | Status::Connecting { .. }
                    | Status::NeedsInput { .. })
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if connected && ui.button("Disconnect").clicked() {
                    if let Some(worker) = &self.worker {
                        worker.cancel();
                    }
                    match connect::disconnect() {
                        Ok(()) => self.log("Disconnected."),
                        Err(e) => self.log(format!("Could not disconnect: {e}")),
                    }
                }
            });
        });
    }

    fn profile_list(&mut self, ui: &mut egui::Ui) {
        ui.heading("Profiles");
        if let Some(e) = &self.load_error {
            ui.colored_label(egui::Color32::from_rgb(220, 38, 38), e);
        }
        let names: Vec<String> = self.profiles.profiles.keys().cloned().collect();
        for name in names {
            let kind = self
                .profiles
                .get(&name)
                .map(Profile::kind)
                .unwrap_or_default();
            let selected = self.selected.as_deref() == Some(name.as_str()) && self.editor.is_none();
            if ui
                .selectable_label(selected, format!("{name}  ·  {kind}"))
                .clicked()
            {
                self.selected = Some(name);
                self.editor = None;
            }
        }
        ui.separator();
        if ui.button("Add GlobalProtect").clicked() {
            self.editor = Some(Editor::new(Kind::GlobalProtect));
        }
        if ui.button("Add Fortinet SSL VPN").clicked() {
            self.editor = Some(Editor::new(Kind::FortinetSsl));
        }
        if ui.button("Add Fortinet IPsec").clicked() {
            self.editor = Some(Editor::new(Kind::FortinetIpsec));
        }
        if cfg!(windows) && ui.button("Import from FortiClient").clicked() {
            let mut found: Vec<(String, Profile)> = forticlient::ssl_tunnels()
                .into_iter()
                .map(|t| (t.name, Profile::FortinetSsl(t.profile)))
                .collect();
            let ipsec = forticlient::ipsec_tunnels();
            for skipped in &ipsec.skipped {
                self.log(skipped.clone());
            }
            found.extend(
                ipsec
                    .tunnels
                    .into_iter()
                    .map(|t| (t.name, Profile::FortinetIpsec(t.profile))),
            );
            if found.is_empty() {
                self.log("No FortiClient VPN profiles found.");
            }
            for (base, profile) in found {
                let mut name = base;
                while self.profiles.profiles.contains_key(&name) {
                    name.push('-');
                }
                self.log(format!(
                    "Imported the FortiClient {} profile as '{name}'.",
                    profile.kind()
                ));
                self.profiles.profiles.insert(name, profile);
            }
            if let Err(e) = save_profiles(&self.profiles) {
                self.log(format!("Could not save the profiles: {e}"));
            }
        }
    }

    fn editor_form(&mut self, ui: &mut egui::Ui) {
        let Some(editor) = &mut self.editor else {
            return;
        };
        ui.heading(match editor.kind {
            Kind::GlobalProtect => "GlobalProtect profile",
            Kind::FortinetSsl => "Fortinet SSL VPN profile",
            Kind::FortinetIpsec => "Fortinet IPsec profile",
        });
        egui::Grid::new("editor")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Name");
                ui.text_edit_singleline(&mut editor.name);
                ui.end_row();
                ui.label(match editor.kind {
                    Kind::GlobalProtect => "Portal",
                    Kind::FortinetSsl => "Server",
                    Kind::FortinetIpsec => "Gateway",
                });
                ui.text_edit_singleline(&mut editor.server);
                ui.end_row();
                ui.label("Username (optional)");
                ui.text_edit_singleline(&mut editor.username);
                ui.end_row();
                match editor.kind {
                    Kind::GlobalProtect => {
                        ui.label("Always use gateway");
                        ui.text_edit_singleline(&mut editor.gateway);
                        ui.end_row();
                        ui.label("Preferred gateway");
                        ui.text_edit_singleline(&mut editor.preferred);
                        ui.end_row();
                        ui.label("");
                        ui.checkbox(
                            &mut editor.strict_tiers,
                            "Rank strictly by priority, then speed",
                        );
                        ui.end_row();
                        ui.label("");
                        ui.checkbox(
                            &mut editor.tcp_probe,
                            "Measure the TCP handshake instead of TLS",
                        );
                        ui.end_row();
                    }
                    Kind::FortinetSsl => {
                        ui.label("Realm (optional)");
                        ui.text_edit_singleline(&mut editor.realm);
                        ui.end_row();
                    }
                    Kind::FortinetIpsec => {
                        ui.label("Local ID (optional)");
                        ui.text_edit_singleline(&mut editor.local_id);
                        ui.end_row();
                        ui.label("DH group");
                        ui.text_edit_singleline(&mut editor.dh_group);
                        ui.end_row();
                        ui.label("");
                        ui.checkbox(&mut editor.pfs, "Perfect forward secrecy");
                        ui.end_row();
                        ui.label("");
                        ui.checkbox(&mut editor.ike2, "IKEv2");
                        ui.end_row();
                        if editor.ike2 {
                            ui.label("");
                            ui.checkbox(
                                &mut editor.eap,
                                "Sign in with username and password (EAP-MSCHAPv2)",
                            );
                            ui.end_row();
                            ui.label("");
                            ui.checkbox(
                                &mut editor.tcp,
                                "IPsec over TCP (port 443 unless profiles.toml says otherwise)",
                            );
                            ui.end_row();
                        } else {
                            ui.label("");
                            ui.checkbox(
                                &mut editor.xauth,
                                "Sign in with username and password (XAuth)",
                            );
                            ui.end_row();
                        }
                    }
                }
            });
        if let Some(e) = &editor.error {
            ui.colored_label(egui::Color32::from_rgb(220, 38, 38), e);
        }
        let mut action = None;
        ui.horizontal(|ui| {
            if ui.button("Save").clicked() {
                action = Some("save");
            }
            if ui.button("Cancel").clicked() {
                action = Some("cancel");
            }
            if editor.original.is_some() && ui.button("Delete").clicked() {
                action = Some("delete");
            }
        });
        match action {
            Some("save") => match editor.to_profile() {
                Ok((name, profile)) => {
                    if let Some(original) = &editor.original
                        && original != &name
                    {
                        self.profiles.profiles.remove(original);
                    }
                    self.profiles.profiles.insert(name.clone(), profile);
                    match save_profiles(&self.profiles) {
                        Ok(()) => {
                            self.selected = Some(name);
                            self.editor = None;
                        }
                        Err(e) => editor.error = Some(e),
                    }
                }
                Err(e) => editor.error = Some(e),
            },
            Some("cancel") => self.editor = None,
            Some("delete") => {
                if let Some(original) = editor.original.clone() {
                    self.profiles.profiles.remove(&original);
                    if let Err(e) = save_profiles(&self.profiles) {
                        self.log(format!("Could not save the profiles: {e}"));
                    }
                    self.selected = self.profiles.profiles.keys().next().cloned();
                }
                self.editor = None;
            }
            _ => {}
        }
    }

    fn profile_view(&mut self, ui: &mut egui::Ui) {
        let Some(name) = self.selected.clone() else {
            ui.heading("Welcome to Polytunnel");
            ui.label("Add a GlobalProtect or Fortinet profile on the left to get started.");
            return;
        };
        let Some(profile) = self.profiles.get(&name).cloned() else {
            return;
        };
        ui.heading(&name);
        match &profile {
            Profile::GlobalProtect(p) => ui.label(format!("GlobalProtect portal {}", p.portal)),
            Profile::FortinetSsl(p) => ui.label(format!("Fortinet SSL VPN {}", p.server)),
            Profile::FortinetIpsec(p) => ui.label(format!("Fortinet IPsec {}", p.server)),
        };
        ui.horizontal(|ui| {
            let busy = self.busy();
            if ui
                .add_enabled(!busy, egui::Button::new("Connect"))
                .clicked()
            {
                self.connect(ui.ctx(), name.clone());
            }
            if busy
                && ui.button("Cancel").clicked()
                && let Some(worker) = &self.worker
            {
                worker.cancel();
            }
            if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
                self.editor = Some(Editor::from_profile(&name, &profile));
            }
        });

        if let Profile::GlobalProtect(p) = &profile {
            ui.separator();
            ui.horizontal(|ui| {
                ui.strong("Gateways");
                let measuring = self.gateways.as_ref().is_some_and(|g| g.pending.is_some());
                if ui
                    .add_enabled(!measuring, egui::Button::new("Find best gateway"))
                    .clicked()
                {
                    self.find_best_gateway(ui.ctx(), &name, p);
                }
                if let Some(preferred) = &p.preferred_gateway {
                    ui.label(format!("Preferred: {preferred}"));
                    if ui.small_button("Clear").clicked() {
                        self.set_preferred(&name, None);
                    }
                }
            });
            let mut prefer = None;
            if let Some(view) = self.gateways.as_ref().filter(|g| g.profile == name) {
                if let Some(ranking) = &view.ranking {
                    egui::Grid::new("gateways")
                        .striped(true)
                        .num_columns(5)
                        .show(ui, |ui| {
                            for header in ["Gateway", "Priority", "Response", "Status", ""] {
                                ui.strong(header);
                            }
                            ui.end_row();
                            for (i, r) in ranking.gateways.iter().enumerate() {
                                ui.label(format!("{} ({})", r.gateway.label(), r.gateway.host()));
                                ui.label(if r.priority == u32::MAX {
                                    "-"
                                } else {
                                    rank::priority_name(r.priority)
                                });
                                ui.label(match r.probe {
                                    Probe::Answered(t) => format!("{} ms", t.as_millis()),
                                    Probe::Failed => "no answer".into(),
                                    Probe::Unknown => "-".into(),
                                });
                                ui.label(if ranking.chosen == Some(i) {
                                    "best"
                                } else {
                                    rank::describe(&r.status)
                                });
                                if ui.small_button("Prefer").clicked() {
                                    prefer = Some(r.gateway.label().to_string());
                                }
                                ui.end_row();
                            }
                        });
                }
                if let Some(note) = &view.note {
                    ui.label(note);
                }
            }
            if let Some(label) = prefer {
                self.set_preferred(&name, Some(label));
            }
        }
    }

    fn settings(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Settings").show(ui, |ui| {
            if ui
                .checkbox(
                    &mut self.autostart,
                    "Start Polytunnel in the tray when I sign in",
                )
                .changed()
                && let Err(e) = autostart::set(self.autostart)
            {
                self.autostart = autostart::enabled();
                self.log(format!("Could not change the start-up setting: {e}"));
            }
            ui.label(&self.link_status);
            ui.horizontal(|ui| {
                if ui.button("Handle GlobalProtect browser logins").clicked() {
                    if let Err(e) = uri::register() {
                        self.log(format!("Could not register: {e}"));
                    }
                    self.link_status = link_status_text();
                }
                if ui.button("Stop handling them").clicked() {
                    let _ = uri::unregister();
                    self.link_status = link_status_text();
                }
            });
        });
    }

    fn prompts(&mut self, ctx: &egui::Context) {
        let mut close = false;
        if let Some(prompt) = &mut self.prompt {
            egui::Modal::new(egui::Id::unique("prompt")).show(ctx, |ui| {
                ui.set_min_width(320.0);
                match prompt {
                    PromptUi::Credentials {
                        title,
                        message,
                        username_label,
                        password_label,
                        username,
                        password,
                        reply,
                    } => {
                        ui.heading(title.as_str());
                        if let Some(m) = message {
                            ui.label(m.as_str());
                        }
                        ui.label(username_label.as_str());
                        ui.text_edit_singleline(username);
                        ui.label(password_label.as_str());
                        let field = ui.add(egui::TextEdit::singleline(password).password(true));
                        let enter =
                            field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        ui.horizontal(|ui| {
                            if ui.button("Sign in").clicked() || enter {
                                let _ = reply.send(Some((
                                    username.clone(),
                                    Secret::new(std::mem::take(password)),
                                )));
                                close = true;
                            }
                            if ui.button("Cancel").clicked() {
                                let _ = reply.send(None);
                                close = true;
                            }
                        });
                    }
                    PromptUi::Code {
                        title,
                        message,
                        code,
                        reply,
                    } => {
                        ui.heading(title.as_str());
                        ui.label(message.as_str());
                        let field = ui.add(egui::TextEdit::singleline(code).password(true));
                        let enter =
                            field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        ui.horizontal(|ui| {
                            if ui.button("OK").clicked() || enter {
                                let _ = reply.send(Some(Secret::new(std::mem::take(code))));
                                close = true;
                            }
                            if ui.button("Cancel").clicked() {
                                let _ = reply.send(None);
                                close = true;
                            }
                        });
                    }
                }
            });
        }
        if close {
            self.prompt = None;
        }

        let mut cancel = false;
        if let Some(browser) = &mut self.browser {
            egui::Modal::new(egui::Id::unique("browser")).show(ctx, |ui| {
                ui.set_max_width(460.0);
                ui.heading("Finish signing in in your browser");
                ui.label(format!(
                    "Polytunnel opened your browser for {}. When the login completes, the browser hands it back here.",
                    browser.server
                ));
                if ui.button("Open the browser again").clicked() {
                    let _ = crate::browser::open(&browser.url);
                }
                ui.separator();
                ui.label("If the browser cannot hand it back, paste the globalprotectcallback: link (or the final page's source) here:");
                ui.add(egui::TextEdit::multiline(&mut browser.pasted).desired_rows(3));
                ui.horizontal(|ui| {
                    if ui.button("Use pasted result").clicked() && !browser.pasted.trim().is_empty() {
                        let _ = browser.paste.send(std::mem::take(&mut browser.pasted));
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        }
        if cancel {
            if let Some(worker) = &self.worker {
                worker.cancel();
            }
            self.browser = None;
        }
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("status").show(ui, |ui| {
            ui.add_space(4.0);
            self.status_bar(ui);
            ui.add_space(4.0);
        });
        egui::Panel::bottom("log")
            .resizable(true)
            .default_size(110.0)
            .show(ui, |ui| {
                ui.strong("Activity");
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        for line in &self.log {
                            ui.label(line);
                        }
                    });
            });
        egui::Panel::left("profiles")
            .resizable(true)
            .default_size(220.0)
            .show(ui, |ui| self.profile_list(ui));
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink(false)
                .show(ui, |ui| {
                    if self.editor.is_some() {
                        self.editor_form(ui);
                    } else {
                        self.profile_view(ui);
                    }
                    ui.separator();
                    self.settings(ui);
                });
        });
        let ctx = ui.ctx().clone();
        self.prompts(&ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(worker) = &self.worker {
            worker.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_round_trips_profiles() {
        let gp = Profile::GlobalProtect(GlobalProtectProfile {
            portal: "vpn.example.com".into(),
            preferred_gateway: Some("East".into()),
            gateway_selection: Some(GatewayPolicy::StrictTiers),
            probe: Some(ProbeMethod::Tcp),
            ..Default::default()
        });
        let editor = Editor::from_profile("work", &gp);
        assert_eq!(editor.to_profile(), Ok(("work".to_string(), gp)));

        let forti = Profile::FortinetSsl(FortinetSslProfile {
            server: "vpn.example.net:10443".into(),
            username: Some("me".into()),
            realm: None,
        });
        assert_eq!(
            Editor::from_profile("office", &forti).to_profile(),
            Ok(("office".to_string(), forti))
        );

        // Settings the form does not show survive an edit.
        let ipsec = Profile::FortinetIpsec(FortinetIpsecProfile {
            server: "vpn.example.net".into(),
            dh_group: Some(5),
            pfs_group: Some(0),
            esp_proposals: Some(vec!["aes128-sha1".into()]),
            nat_keepalive: Some(10),
            ..Default::default()
        });
        assert_eq!(
            Editor::from_profile("ipsec", &ipsec).to_profile(),
            Ok(("ipsec".to_string(), ipsec))
        );
        let mut e = Editor::new(Kind::FortinetIpsec);
        e.name = "new".into();
        e.server = "203.0.113.9".into();
        assert_eq!(
            e.to_profile(),
            Ok((
                "new".to_string(),
                Profile::FortinetIpsec(FortinetIpsecProfile {
                    server: "203.0.113.9".into(),
                    ..Default::default()
                })
            ))
        );
        e.dh_group = "1".into();
        assert!(e.to_profile().is_err());
        e.dh_group = "14".into();
        e.server = "https://vpn.example.net".into();
        assert!(e.to_profile().is_err());
    }

    #[test]
    fn editor_keeps_ikev2_settings() {
        let v2 = Profile::FortinetIpsec(FortinetIpsecProfile {
            server: "vpn.example.net".into(),
            ike_version: Some(2),
            eap: Some(EapMethodName::Mschapv2),
            server_auth: Some(polytunnel_core::profile::ServerAuthStyle::Certificate),
            transport: Some(IpsecTransport::Tcp),
            tcp_port: Some(4500),
            ca_file: Some("ca.pem".into()),
            remote_id: Some("vpn.example.net".into()),
            ..Default::default()
        });
        assert_eq!(
            Editor::from_profile("v2", &v2).to_profile(),
            Ok(("v2".to_string(), v2.clone()))
        );
        // Back to IKEv1: the IKEv2-only settings go.
        let mut e = Editor::from_profile("v2", &v2);
        e.ike2 = false;
        let Ok((_, Profile::FortinetIpsec(p))) = e.to_profile() else {
            panic!("not IPsec");
        };
        assert_eq!(
            (p.ike_version, p.eap, p.transport, p.tcp_port),
            (None, None, None, None)
        );
    }

    #[test]
    fn editor_validates() {
        let mut e = Editor::new(Kind::GlobalProtect);
        e.name = "bad name".into();
        e.server = "vpn.example.com".into();
        assert!(e.to_profile().is_err());
        e.name = "ok".into();
        e.server = "http://vpn.example.com".into();
        assert!(e.to_profile().is_err());
    }
}
