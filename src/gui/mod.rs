//! The Polytunnel window (egui). It runs only while open and exits completely when closed;
//! the always-on tray agent ([`agent`]) is a separate, tiny process.

pub mod agent;
mod worker;

use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;
use polytunnel_core::Secret;
use polytunnel_core::ipc::{KillSwitchMode, KillSwitchSettings, Status};
use polytunnel_core::profile::{
    EapMethodName, FortinetIpsecProfile, FortinetSslProfile, GatewayPolicy, GlobalProtectProfile,
    IpsecTransport, ProbeMethod, Profile, Profiles, normalize_server, valid_host,
};
use polytunnel_gp::rank::{self, Probe, Ranking};

use crate::instance::{self, Instance, Message, Role};
use crate::{autostart, connect, forticlient, gateways, paths, uri};

const TITLE: &str = "Polytunnel";
const LOG_LINES: usize = 500;
/// Status polls: often while the service answers, less often while it does not.
const POLL: Duration = Duration::from_millis(1500);
const POLL_UNREACHABLE: Duration = Duration::from_secs(10);
/// The kill switch is asked about once every this many status polls.
const KILLSWITCH_EVERY: u32 = 4;

const GREEN: egui::Color32 = egui::Color32::from_rgb(22, 163, 74);
const AMBER: egui::Color32 = egui::Color32::from_rgb(217, 119, 6);
const RED: egui::Color32 = egui::Color32::from_rgb(220, 38, 38);

/// Opens the window (or brings the open one to the front) and makes sure the tray agent runs.
pub fn run_window() -> i32 {
    #[cfg(windows)]
    crate::win::hide_own_console();
    let instance = match instance::claim(Role::Gui) {
        Ok(Some(instance)) => Some(instance),
        Ok(None) => {
            // The window is open already; the tray may have been quit since.
            agent::ensure_running();
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
            .with_inner_size([820.0, 580.0])
            .with_min_inner_size([560.0, 400.0]),
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
#[derive(Debug, Clone, PartialEq)]
struct Editor {
    original: Option<String>,
    kind: Kind,
    name: String,
    server: String,
    username: String,
    gateway: String,
    preferred: String,
    realm: String,
    /// Fortinet: more gateways, tried in order after `server`.
    backups: Vec<String>,
    /// Fortinet SSL: the trusted certificate's SHA-256 (empty: the system decides).
    server_cert: String,
    strict_tiers: bool,
    tcp_probe: bool,
    embedded: bool,
    local_id: String,
    dh_group: String,
    pfs: bool,
    xauth: bool,
    ike2: bool,
    eap: bool,
    tcp: bool,
    /// The profile being edited: settings the form does not show are kept.
    gp_base: GlobalProtectProfile,
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
            backups: Vec::new(),
            server_cert: String::new(),
            strict_tiers: false,
            tcp_probe: false,
            embedded: false,
            local_id: String::new(),
            dh_group: crate::ipsec::DEFAULT_DH_GROUP.to_string(),
            pfs: true,
            xauth: true,
            ike2: false,
            eap: false,
            tcp: false,
            gp_base: GlobalProtectProfile::default(),
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
                embedded: p.embedded_login == Some(true),
                gp_base: p.clone(),
                ..Editor::new(Kind::GlobalProtect)
            },
            Profile::FortinetSsl(p) => Editor {
                original: Some(name.to_string()),
                name: name.to_string(),
                server: p.server.clone(),
                username: text(&p.username),
                realm: text(&p.realm),
                backups: p.backup_servers.clone(),
                server_cert: p.server_cert.map(|c| c.to_string()).unwrap_or_default(),
                ..Editor::new(Kind::FortinetSsl)
            },
            Profile::FortinetIpsec(p) => Editor {
                original: Some(name.to_string()),
                name: name.to_string(),
                server: p.server.clone(),
                username: text(&p.username),
                local_id: text(&p.local_id),
                backups: p.backup_servers.clone(),
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

    /// Has the form changed since it was opened?
    fn changed_from(&self, initial: &Editor) -> bool {
        let mut a = self.clone();
        let mut b = initial.clone();
        a.error = None;
        b.error = None;
        a != b
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
        let mut backups = Vec::new();
        for (i, gateway) in self.backups.iter().map(|g| g.trim()).enumerate() {
            if gateway.is_empty() {
                continue;
            }
            let usable = match self.kind {
                Kind::FortinetIpsec => valid_host(gateway),
                _ => normalize_server(gateway).is_ok(),
            };
            if !usable {
                return Err(format!(
                    "Backup gateway {} ('{gateway}') is not a usable address.",
                    i + 1
                ));
            }
            backups.push(gateway.to_string());
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
                embedded_login: self.embedded.then_some(true),
                ..self.gp_base.clone()
            }),
            Kind::FortinetSsl => Profile::FortinetSsl(FortinetSslProfile {
                server: self.server.trim().to_string(),
                backup_servers: backups,
                username: opt(&self.username),
                realm: opt(&self.realm),
                server_cert: match self.server_cert.trim() {
                    "" => None,
                    pin => Some(
                        pin.parse()
                            .map_err(|e| format!("Server certificate: {e}."))?,
                    ),
                },
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
                    backup_servers: backups,
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
        focused: bool,
    },
    Code {
        title: String,
        message: String,
        code: String,
        reply: Sender<Option<Secret>>,
        focused: bool,
    },
    /// The service's question: every field at once, only secret ones hidden.
    Fields {
        title: String,
        message: String,
        /// (label, secret, value)
        fields: Vec<(String, bool, String)>,
        reply: Sender<Option<Vec<Secret>>>,
        focused: bool,
    },
}

struct BrowserUi {
    server: String,
    url: String,
    not_opened: Option<String>,
    pasted: String,
    paste_error: Option<String>,
    paste: Sender<String>,
}

struct GatewaysUi {
    profile: String,
    ranking: Option<Ranking>,
    note: Option<String>,
    pending: Option<Receiver<Result<Ranking, String>>>,
}

/// What the background status thread reports.
enum Poll {
    Status(Result<Status, String>),
    KillSwitch(Result<KillSwitchState, String>),
}

/// The kill switch as the service reports it: the setting, whether rules are in force, and a
/// problem applying them.
type KillSwitchState = (KillSwitchSettings, bool, Option<String>);

/// Results of service calls made off the window's thread.
enum Job {
    Disconnected(Result<(), String>),
    UpdateChecked(Result<connect::UpdateInfo, String>),
    UpdateStarted(Result<connect::UpdateInfo, String>),
    KillSwitch(Result<KillSwitchState, String>),
}

/// Something to confirm before it happens.
enum Confirm {
    Delete(String),
    Lockdown(KillSwitchSettings),
    Install(String),
    /// Leave the form with unsaved changes, then do this.
    Discard(Leave),
}

enum Leave {
    Select(String),
    New(Kind),
}

#[derive(Default)]
struct Running {
    disconnect: bool,
    update: bool,
    killswitch: bool,
}

struct App {
    profiles: Profiles,
    /// The profiles file could not be read: the list is shown read-only so nothing overwrites
    /// it.
    load_error: Option<String>,
    selected: Option<String>,
    editor: Option<Editor>,
    /// The form as it was opened, to notice unsaved changes.
    editor_initial: Option<Editor>,
    /// `None` until the service first answers.
    status: Option<Result<Status, String>>,
    /// The last service problem written to the activity log (each is logged once).
    logged_problem: Option<String>,
    poll_rx: Receiver<Poll>,
    worker: Option<worker::Worker>,
    prompt: Option<PromptUi>,
    browser: Option<BrowserUi>,
    log: VecDeque<(String, String)>,
    gateways: Option<GatewaysUi>,
    ipc_rx: Receiver<Message>,
    job_tx: Sender<Job>,
    job_rx: Receiver<Job>,
    running: Running,
    confirm: Option<Confirm>,
    autostart: bool,
    /// The troubleshooting trace switch.
    trace: bool,
    link_status: String,
    /// The kill switch, as last reported (`None` while the service cannot be asked).
    killswitch: Option<KillSwitchState>,
    /// A newer release the service can install.
    update: Option<String>,
    was_focused: bool,
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Profiles::default(), None),
        Err(e) => (
            Profiles::default(),
            Some(format!("{}: {e}", path.display())),
        ),
    }
}

/// Writes `text` to `path` through a temporary file, so a failed write never leaves half a
/// file, and keeps the previous version next to it as `<name>.bak`.
fn write_with_backup(path: &Path, text: &str) -> Result<(), String> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!("{name}.tmp"));
    fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
    if path.exists() {
        let _ = fs::copy(path, path.with_file_name(format!("{name}.bak")));
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })
}

fn save_profiles(profiles: &Profiles) -> Result<(), String> {
    let path = paths::profiles_file().ok_or("no configuration directory")?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    write_with_backup(&path, &profiles.to_toml())
}

fn link_status_text() -> String {
    match uri::status() {
        uri::Status::Polytunnel(_) => "Polytunnel handles GlobalProtect browser sign-ins.".into(),
        uri::Status::Other(_) => "Another program handles GlobalProtect browser sign-ins.".into(),
        uri::Status::NotRegistered => "No program handles GlobalProtect browser sign-ins.".into(),
        uri::Status::Unsupported => String::new(),
    }
}

/// The local time of day, `HH:MM:SS`, for the activity log.
fn clock() -> String {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::SystemInformation::GetLocalTime;
        // SAFETY: plain data out-parameter, written by GetLocalTime.
        let mut t = unsafe { std::mem::zeroed() };
        unsafe { GetLocalTime(&mut t) };
        format!("{:02}:{:02}:{:02}", t.wHour, t.wMinute, t.wSecond)
    }
    #[cfg(unix)]
    {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()) as libc::time_t;
        // SAFETY: plain data out-parameter, written by localtime_r.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        unsafe { libc::localtime_r(&now, &mut tm) };
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `1:02:03` (or `2:03`) since `since_unix`.
fn elapsed(since_unix: u64) -> String {
    let secs = now_unix().saturating_sub(since_unix);
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

/// `950 B`, `12.3 KB`, `4.5 MB`, `1.23 GB`.
fn bytes(n: u64) -> String {
    const K: f64 = 1024.0;
    let f = n as f64;
    if f < K {
        format!("{n} B")
    } else if f < K * K {
        format!("{:.1} KB", f / K)
    } else if f < K * K * K {
        format!("{:.1} MB", f / (K * K))
    } else {
        format!("{:.2} GB", f / (K * K * K))
    }
}

/// ` (+2 backup gateways)` for a list of `count` gateways.
fn backup_note(count: usize) -> String {
    match count {
        0 | 1 => String::new(),
        2 => " (+1 backup gateway)".into(),
        n => format!(" (+{} backup gateways)", n - 1),
    }
}

/// The editor's list of backup gateways: each can be edited, moved up or down, or removed.
fn backup_list(ui: &mut egui::Ui, backups: &mut Vec<String>) {
    ui.vertical(|ui| {
        let count = backups.len();
        let mut action: Option<(usize, i8)> = None;
        for (i, gateway) in backups.iter_mut().enumerate() {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(gateway)
                        .desired_width(220.0)
                        .hint_text("host or host:port"),
                );
                if ui
                    .add_enabled(i > 0, egui::Button::new("Up").small())
                    .on_hover_text("Try earlier")
                    .clicked()
                {
                    action = Some((i, -1));
                }
                if ui
                    .add_enabled(i + 1 < count, egui::Button::new("Down").small())
                    .on_hover_text("Try later")
                    .clicked()
                {
                    action = Some((i, 1));
                }
                if ui
                    .add(egui::Button::new("Remove").small())
                    .on_hover_text("Remove")
                    .clicked()
                {
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
        if backups.len() < 16 && ui.small_button("Add a gateway").clicked() {
            backups.push(String::new());
        }
    });
}

/// The profile of the connection that is on, on its way, or stopping.
fn active_profile(status: &Option<Result<Status, String>>) -> Option<&str> {
    match status {
        Some(Ok(
            Status::Connected { profile, .. }
            | Status::Connecting { profile }
            | Status::NeedsInput { profile, .. }
            | Status::Reconnecting { profile, .. }
            | Status::Disconnecting { profile },
        )) => Some(profile),
        _ => None,
    }
}

/// The status bar's line: text, colour (`None`: normal text) and whether something is under
/// way (a spinner).
fn status_line(
    status: &Option<Result<Status, String>>,
    killswitch: Option<&KillSwitchState>,
) -> (String, Option<egui::Color32>, bool) {
    let Some(status) = status else {
        return ("Checking…".into(), None, true);
    };
    match status {
        Err(e) => (connect::service_problem(e), Some(RED), false),
        Ok(Status::Idle {}) => match killswitch {
            Some((settings, true, _)) if settings.mode == KillSwitchMode::Always => (
                "Not connected. The kill switch blocks internet traffic (lockdown).".into(),
                Some(AMBER),
                false,
            ),
            Some((_, true, _)) => (
                "Not connected. The kill switch keeps blocking internet traffic until you \
                 disconnect."
                    .into(),
                Some(AMBER),
                false,
            ),
            _ => ("Not connected.".into(), None, false),
        },
        Ok(Status::Connecting { profile }) => (format!("Connecting ({profile})…"), None, true),
        Ok(Status::NeedsInput { profile, .. }) => (
            format!("Waiting for your sign-in details ({profile})…"),
            Some(AMBER),
            true,
        ),
        Ok(Status::Connected {
            profile,
            server,
            addresses,
            transport,
            since_unix,
            notice,
            bytes_in,
            bytes_out,
            ..
        }) => {
            let details = format!(
                "{server} ({profile}) over {} · {} · {} · {} received · {} sent",
                connect::transport_name(transport),
                addresses.join(", "),
                elapsed(*since_unix),
                bytes(*bytes_in),
                bytes(*bytes_out),
            );
            match notice {
                Some(notice) => (
                    format!("Connected, with limits: {notice} · {details}"),
                    Some(AMBER),
                    false,
                ),
                None => (format!("Connected to {details}"), Some(GREEN), false),
            }
        }
        Ok(Status::Reconnecting {
            profile,
            server,
            attempt,
            ..
        }) => (
            format!("The connection dropped. Reconnecting to {server} ({profile}), try {attempt}…"),
            Some(AMBER),
            true,
        ),
        Ok(Status::Disconnecting { profile }) => {
            (format!("Disconnecting ({profile})…"), None, true)
        }
        Ok(Status::Failed {
            profile, message, ..
        }) => (
            format!("Couldn't connect ({profile}): {message}"),
            Some(RED),
            false,
        ),
    }
}

impl App {
    fn new(ctx: &egui::Context, ipc_rx: Receiver<Message>, instance: Option<Instance>) -> Self {
        let (poll_tx, poll_rx) = mpsc::channel();
        let repaint = ctx.clone();
        thread::Builder::new()
            .name("status".into())
            .spawn(move || {
                let mut round = 0u32;
                loop {
                    let status = connect::status();
                    let reachable = status.is_ok();
                    if poll_tx.send(Poll::Status(status)).is_err() {
                        return;
                    }
                    if round.is_multiple_of(KILLSWITCH_EVERY) || !reachable {
                        let _ = poll_tx.send(Poll::KillSwitch(connect::killswitch(None)));
                    }
                    round = round.wrapping_add(1);
                    repaint.request_repaint();
                    thread::sleep(if reachable { POLL } else { POLL_UNREACHABLE });
                }
            })
            .ok();
        let (profiles, load_error) = load_profiles();
        let selected = profiles.profiles.keys().next().cloned();
        let (job_tx, job_rx) = mpsc::channel();
        App {
            profiles,
            load_error,
            selected,
            editor: None,
            editor_initial: None,
            status: None,
            logged_problem: None,
            poll_rx,
            worker: None,
            prompt: None,
            browser: None,
            log: VecDeque::new(),
            gateways: None,
            ipc_rx,
            job_tx,
            job_rx,
            running: Running::default(),
            confirm: None,
            autostart: autostart::enabled(),
            trace: crate::trace::enabled(),
            link_status: link_status_text(),
            killswitch: None,
            update: None,
            was_focused: true,
            _instance: instance,
        }
    }

    fn log(&mut self, line: impl Into<String>) {
        if self.log.len() >= LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back((clock(), line.into()));
    }

    fn busy(&self) -> bool {
        self.worker.is_some()
    }

    fn read_only(&self) -> bool {
        self.load_error.is_some()
    }

    /// Runs `f` (a service call) on a background thread; its result comes back as a [`Job`].
    fn spawn_job(&self, ctx: &egui::Context, f: impl FnOnce() -> Job + Send + 'static) {
        let tx = self.job_tx.clone();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let _ = tx.send(f());
            ctx.request_repaint();
        });
    }

    fn disconnect(&mut self, ctx: &egui::Context) {
        if let Some(worker) = &self.worker {
            worker.cancel();
        }
        self.running.disconnect = true;
        self.spawn_job(ctx, || Job::Disconnected(connect::disconnect()));
    }

    fn set_killswitch(&mut self, ctx: &egui::Context, settings: KillSwitchSettings) {
        self.running.killswitch = true;
        self.spawn_job(ctx, move || {
            Job::KillSwitch(connect::killswitch(Some(settings)))
        });
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

    /// Opens the form (or selects a profile), asking first when the open form has unsaved
    /// changes.
    fn leave_editor(&mut self, leave: Leave) {
        let unsaved = match (&self.editor, &self.editor_initial) {
            (Some(editor), Some(initial)) => editor.changed_from(initial),
            _ => false,
        };
        if unsaved {
            self.confirm = Some(Confirm::Discard(leave));
        } else {
            self.do_leave(leave);
        }
    }

    fn do_leave(&mut self, leave: Leave) {
        match leave {
            Leave::Select(name) => {
                self.selected = Some(name);
                self.editor = None;
                self.editor_initial = None;
            }
            Leave::New(kind) => self.open_editor(Editor::new(kind)),
        }
    }

    fn open_editor(&mut self, editor: Editor) {
        self.editor_initial = Some(editor.clone());
        self.editor = Some(editor);
    }

    fn poll(&mut self, ctx: &egui::Context) {
        while let Ok(poll) = self.poll_rx.try_recv() {
            match poll {
                Poll::Status(status) => {
                    if let Err(e) = &status
                        && self.logged_problem.as_ref() != Some(e)
                    {
                        self.logged_problem = Some(e.clone());
                        let line = format!("Service: {e}");
                        self.log(line);
                    } else if status.is_ok() {
                        self.logged_problem = None;
                    }
                    self.status = Some(status);
                }
                Poll::KillSwitch(state) => self.killswitch = state.ok(),
            }
        }
        while let Ok(message) = self.ipc_rx.try_recv() {
            match message {
                Message::Show => {
                    agent::ensure_running();
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                Message::Quit => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            }
        }
        while let Ok(job) = self.job_rx.try_recv() {
            self.finish_job(ctx, job);
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
                            focused: false,
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
                            focused: false,
                        });
                    }
                    worker::Event::Prompt(worker::Prompt::Fields {
                        title,
                        message,
                        fields,
                        reply,
                        ..
                    }) => {
                        self.prompt = Some(PromptUi::Fields {
                            title,
                            message,
                            fields: fields
                                .into_iter()
                                .map(|(label, secret)| (label, secret, String::new()))
                                .collect(),
                            reply,
                            focused: false,
                        });
                    }
                    worker::Event::PromptClosed => self.prompt = None,
                    worker::Event::Prompt(worker::Prompt::Browser {
                        server,
                        url,
                        not_opened,
                        paste,
                    }) => {
                        self.browser = Some(BrowserUi {
                            server,
                            url,
                            not_opened,
                            pasted: String::new(),
                            paste_error: None,
                            paste,
                        });
                    }
                    worker::Event::PasteRejected(e) => {
                        if let Some(browser) = &mut self.browser {
                            browser.paste_error = Some(e);
                        }
                    }
                    worker::Event::BrowserDone => self.browser = None,
                    worker::Event::Finished(result) => {
                        lines.push(match result {
                            Ok(message) => message,
                            Err(e) if e == connect::CANCELLED => "Cancelled.".into(),
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
            // A browser sign-in may have registered Polytunnel for GlobalProtect links.
            self.link_status = link_status_text();
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

    fn finish_job(&mut self, ctx: &egui::Context, job: Job) {
        match job {
            Job::Disconnected(result) => {
                self.running.disconnect = false;
                match result {
                    Ok(()) => self.log("Disconnected."),
                    Err(e) => self.log(format!("Could not disconnect: {e}")),
                }
            }
            Job::KillSwitch(result) => {
                self.running.killswitch = false;
                match result {
                    Ok(state) => {
                        self.log(connect::describe_killswitch(
                            &state.0,
                            state.1,
                            state.2.as_deref(),
                        ));
                        self.killswitch = Some(state);
                    }
                    Err(e) => self.log(format!("Could not change the kill switch: {e}")),
                }
            }
            Job::UpdateChecked(result) => {
                self.running.update = false;
                match result {
                    Ok((current, Some(latest), _, message)) => {
                        let newer = polytunnel_core::is_newer_version(&latest, &current);
                        self.update = (newer && (cfg!(windows) || cfg!(target_os = "macos")))
                            .then_some(latest);
                        self.log(message);
                    }
                    Ok((_, None, _, message)) => {
                        self.update = None;
                        self.log(format!("Could not check for updates: {message}"));
                    }
                    Err(e) => self.log(format!("Could not check for updates: {e}")),
                }
            }
            Job::UpdateStarted(result) => {
                self.running.update = false;
                self.update = None;
                match result {
                    Ok((_, _, true, message)) => {
                        self.log(message);
                        // The installer replaces Polytunnel's files: close everything and come
                        // back once it is done.
                        #[cfg(windows)]
                        {
                            agent::reopen_after_update();
                            let _ = instance::send(Role::Agent, Message::Quit);
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        #[cfg(not(windows))]
                        let _ = ctx;
                    }
                    Ok((_, _, false, message)) => {
                        self.log(format!("The update could not start: {message}"));
                    }
                    Err(e) => self.log(format!("Could not install the update: {e}")),
                }
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
        let before = self.profiles.clone();
        if let Some(Profile::GlobalProtect(p)) = self.profiles.profiles.get_mut(name) {
            p.preferred_gateway = label;
            if let Err(e) = save_profiles(&self.profiles) {
                self.profiles = before;
                self.log(format!("Could not save the profiles: {e}"));
            }
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        let (text, color, working) = status_line(&self.status, self.killswitch.as_ref());
        let can_disconnect = matches!(
            &self.status,
            Some(Ok(Status::Connected { .. }
                | Status::Connecting { .. }
                | Status::NeedsInput { .. }
                | Status::Reconnecting { .. }))
        ) && !self.running.disconnect;
        let failed = matches!(&self.status, Some(Ok(Status::Failed { .. })));
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if can_disconnect && ui.button("Disconnect").clicked() {
                    self.disconnect(ui.ctx());
                }
                if failed
                    && ui
                        .button("Dismiss")
                        .on_hover_text("Clear this message")
                        .clicked()
                {
                    self.disconnect(ui.ctx());
                }
                if self.running.disconnect {
                    ui.add(egui::Spinner::new());
                }
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    if working {
                        ui.add(egui::Spinner::new());
                    }
                    let label = match color {
                        Some(color) => egui::RichText::new(text).color(color),
                        None => egui::RichText::new(text),
                    };
                    ui.add(egui::Label::new(label).wrap());
                });
            });
        });
    }

    fn profile_list(&mut self, ui: &mut egui::Ui) {
        ui.heading("Profiles");
        if let Some(e) = self.load_error.clone() {
            ui.colored_label(RED, "Your profiles file could not be read:");
            ui.add(egui::Label::new(egui::RichText::new(&e).small()).wrap());
            ui.label("Fix or remove it, then reopen Polytunnel. Nothing is changed until then.");
            if let Some(path) = paths::profiles_file()
                && ui.small_button("Copy the file's location").clicked()
            {
                ui.ctx().copy_text(path.display().to_string());
            }
            ui.separator();
        }
        let active = active_profile(&self.status).map(str::to_string);
        let connected = matches!(
            &self.status,
            Some(Ok(Status::Connected { notice: None, .. }))
        );
        let names: Vec<String> = self.profiles.profiles.keys().cloned().collect();
        let mut clicked = None;
        egui::ScrollArea::vertical()
            .id_salt("profile-list")
            .max_height((ui.available_height() - 140.0).max(80.0))
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for name in &names {
                    let kind = self
                        .profiles
                        .get(name)
                        .map(Profile::kind)
                        .unwrap_or_default();
                    let selected =
                        self.selected.as_deref() == Some(name.as_str()) && self.editor.is_none();
                    let is_active = active.as_deref() == Some(name.as_str());
                    let mut text = egui::RichText::new(format!("{name}  ·  {kind}"));
                    if is_active {
                        text = text.color(if connected { GREEN } else { AMBER });
                    }
                    let response = ui.selectable_label(selected, text);
                    let response = if is_active {
                        response.on_hover_text(if connected {
                            "Connected"
                        } else {
                            "Connecting or reconnecting"
                        })
                    } else {
                        response
                    };
                    if response.clicked() {
                        clicked = Some(name.clone());
                    }
                }
            });
        if let Some(name) = clicked {
            self.leave_editor(Leave::Select(name));
        }
        ui.separator();
        ui.add_enabled_ui(!self.read_only(), |ui| {
            if ui.button("Add GlobalProtect").clicked() {
                self.leave_editor(Leave::New(Kind::GlobalProtect));
            }
            if ui.button("Add Fortinet SSL VPN").clicked() {
                self.leave_editor(Leave::New(Kind::FortinetSsl));
            }
            if ui.button("Add Fortinet IPsec").clicked() {
                self.leave_editor(Leave::New(Kind::FortinetIpsec));
            }
            if cfg!(windows) && ui.button("Import from FortiClient").clicked() {
                self.import_forticlient();
            }
        });
    }

    /// The name of a profile that already connects to the same place as `profile`.
    fn same_profile(&self, profile: &Profile) -> Option<String> {
        let target = |p: &Profile| -> (String, String) {
            let server = match p {
                Profile::GlobalProtect(p) => p.portal.clone(),
                Profile::FortinetSsl(p) => p.server.clone(),
                Profile::FortinetIpsec(p) => p.server.clone(),
            };
            (p.kind().to_string(), server.trim().to_ascii_lowercase())
        };
        let wanted = target(profile);
        self.profiles
            .profiles
            .iter()
            .find(|(_, p)| target(p) == wanted)
            .map(|(name, _)| name.clone())
    }

    fn import_forticlient(&mut self) {
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
            return;
        }
        let before = self.profiles.clone();
        let mut first_new = None;
        for (base, profile) in found {
            if let Some(existing) = self.same_profile(&profile) {
                self.log(format!(
                    "The FortiClient profile '{base}' is already here as '{existing}'."
                ));
                continue;
            }
            let mut name = base;
            while self.profiles.profiles.contains_key(&name) {
                name.push('-');
            }
            self.log(format!(
                "Imported the FortiClient {} profile as '{name}'.",
                profile.kind()
            ));
            self.profiles.profiles.insert(name.clone(), profile);
            first_new.get_or_insert(name);
        }
        let Some(first) = first_new else {
            return;
        };
        match save_profiles(&self.profiles) {
            Ok(()) => {
                self.selected = Some(first);
                self.editor = None;
                self.editor_initial = None;
            }
            Err(e) => {
                self.profiles = before;
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
                if editor.kind != Kind::GlobalProtect {
                    ui.label("Backup gateways").on_hover_text(
                        "Tried from the top when the gateway above cannot be reached. A wrong \
                         password stops there.",
                    );
                    backup_list(ui, &mut editor.backups);
                    ui.end_row();
                }
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
                        if crate::embedded::helper().is_some() {
                            ui.label("");
                            ui.checkbox(
                                &mut editor.embedded,
                                "Sign in in Polytunnel's own window instead of the browser",
                            );
                            ui.end_row();
                        }
                    }
                    Kind::FortinetSsl => {
                        ui.label("Realm (optional)");
                        ui.text_edit_singleline(&mut editor.realm);
                        ui.end_row();
                        ui.label("Server certificate (optional)").on_hover_text(
                            "The SHA-256 fingerprint of the FortiGate's certificate, when the \
                             system does not trust it (a factory certificate). Polytunnel then \
                             trusts exactly that certificate for this server.",
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut editor.server_cert)
                                .hint_text("sha256:... (from the sign-in error)"),
                        );
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
            ui.colored_label(RED, e);
        }
        let mut action = None;
        ui.horizontal(|ui| {
            if ui.button("Save").clicked() {
                action = Some("save");
            }
            if ui.button("Cancel").clicked() {
                action = Some("cancel");
            }
            if editor.original.is_some() && ui.button("Delete…").clicked() {
                action = Some("delete");
            }
        });
        match action {
            Some("save") => self.save_editor(),
            Some("cancel") => {
                self.editor = None;
                self.editor_initial = None;
            }
            Some("delete") => {
                if let Some(original) = self.editor.as_ref().and_then(|e| e.original.clone()) {
                    self.confirm = Some(Confirm::Delete(original));
                }
            }
            _ => {}
        }
    }

    fn save_editor(&mut self) {
        let Some(editor) = &mut self.editor else {
            return;
        };
        let (name, profile) = match editor.to_profile() {
            Ok(result) => result,
            Err(e) => {
                editor.error = Some(e);
                return;
            }
        };
        if editor.original.as_deref() != Some(name.as_str())
            && self.profiles.profiles.contains_key(&name)
        {
            editor.error = Some(format!(
                "A profile named '{name}' exists already. Choose another name."
            ));
            return;
        }
        let before = self.profiles.clone();
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
                self.editor_initial = None;
            }
            Err(e) => {
                self.profiles = before;
                if let Some(editor) = &mut self.editor {
                    editor.error = Some(format!("Could not save: {e}"));
                }
            }
        }
    }

    fn delete_profile(&mut self, name: &str) {
        let before = self.profiles.clone();
        self.profiles.profiles.remove(name);
        match save_profiles(&self.profiles) {
            Ok(()) => {
                self.log(format!("Deleted the profile '{name}'."));
                self.selected = self.profiles.profiles.keys().next().cloned();
                self.editor = None;
                self.editor_initial = None;
            }
            Err(e) => {
                self.profiles = before;
                self.log(format!("Could not save the profiles: {e}"));
            }
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
            Profile::FortinetSsl(p) => ui.label(format!(
                "Fortinet SSL VPN {}{}",
                p.server,
                backup_note(p.servers().len())
            )),
            Profile::FortinetIpsec(p) => ui.label(format!(
                "Fortinet IPsec {}{}",
                p.server,
                backup_note(p.servers().len())
            )),
        };
        let active = active_profile(&self.status).map(str::to_string);
        let this_active = active.as_deref() == Some(name.as_str());
        let up = matches!(
            &self.status,
            Some(Ok(Status::Connected { .. } | Status::Reconnecting { .. }))
        );
        ui.horizontal(|ui| {
            let busy = self.busy();
            if this_active && (busy || !up) {
                if ui.button("Cancel").clicked() {
                    self.disconnect(ui.ctx());
                }
            } else if this_active {
                if ui
                    .add_enabled(!self.running.disconnect, egui::Button::new("Disconnect"))
                    .clicked()
                {
                    self.disconnect(ui.ctx());
                }
            } else {
                let label = match &active {
                    Some(other) => format!("Switch from {other} to {name}"),
                    None => "Connect".into(),
                };
                if ui
                    .add_enabled(!busy, egui::Button::new(label))
                    .on_disabled_hover_text("Wait until the current connection attempt finishes.")
                    .clicked()
                {
                    self.connect(ui.ctx(), name.clone());
                }
            }
            if ui
                .add_enabled(
                    !busy && !this_active && !self.read_only(),
                    egui::Button::new("Edit"),
                )
                .on_disabled_hover_text("Disconnect first to change this profile.")
                .clicked()
            {
                self.open_editor(Editor::from_profile(&name, &profile));
            }
        });

        if let Profile::GlobalProtect(p) = &profile {
            ui.separator();
            ui.horizontal(|ui| {
                ui.strong("Gateways");
                let measuring = self.gateways.as_ref().is_some_and(|g| g.pending.is_some());
                let shown = self.gateways.as_ref().is_some_and(|g| g.profile == name);
                if ui
                    .add_enabled(
                        !measuring,
                        egui::Button::new(if shown {
                            "Measure again"
                        } else {
                            "Find best gateway"
                        }),
                    )
                    .clicked()
                {
                    self.find_best_gateway(ui.ctx(), &name, p);
                }
                if measuring {
                    ui.add(egui::Spinner::new());
                }
                if let Some(preferred) = &p.preferred_gateway {
                    ui.label(format!("Preferred: {preferred}"));
                    if ui.small_button("Clear").clicked() {
                        self.set_preferred(&name, None);
                        if shown {
                            let mut p = p.clone();
                            p.preferred_gateway = None;
                            self.find_best_gateway(ui.ctx(), &name, &p);
                        }
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
                                let is_preferred =
                                    p.preferred_gateway.as_deref() == Some(r.gateway.label());
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
                                let status = match (ranking.chosen == Some(i), is_preferred) {
                                    (true, true) => "best · preferred".to_string(),
                                    (true, false) => "best".to_string(),
                                    (false, true) => {
                                        format!("preferred · {}", rank::describe(&r.status))
                                    }
                                    (false, false) => rank::describe(&r.status).to_string(),
                                };
                                ui.label(status);
                                if !is_preferred && ui.small_button("Prefer").clicked() {
                                    prefer = Some(r.gateway.label().to_string());
                                }
                                if is_preferred {
                                    ui.label("");
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
                self.set_preferred(&name, Some(label.clone()));
                let mut p = p.clone();
                p.preferred_gateway = Some(label);
                self.find_best_gateway(ui.ctx(), &name, &p);
            }
        }
    }

    fn settings(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Settings").show(ui, |ui| {
            if autostart::SUPPORTED
                && ui
                    .checkbox(
                        &mut self.autostart,
                        "Start Polytunnel in the tray when I sign in",
                    )
                    .changed()
            {
                if let Err(e) = autostart::set(self.autostart) {
                    self.log(format!("Could not change the start-up setting: {e}"));
                }
                self.autostart = autostart::enabled();
            }

            ui.separator();
            ui.strong("Kill switch");
            match self.killswitch.clone() {
                None => {
                    ui.label("Unavailable while the Polytunnel service isn't running.");
                }
                Some((settings, active, problem)) => {
                    let mut ks = settings;
                    ui.add_enabled_ui(!self.running.killswitch, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.radio_value(&mut ks.mode, KillSwitchMode::Off, "Off");
                            ui.radio_value(
                                &mut ks.mode,
                                KillSwitchMode::Connected,
                                "While connected",
                            );
                            ui.radio_value(
                                &mut ks.mode,
                                KillSwitchMode::Always,
                                "Always (lockdown)",
                            );
                            if self.running.killswitch {
                                ui.add(egui::Spinner::new());
                            }
                        });
                        ui.add_enabled(
                            ks.mode != KillSwitchMode::Off,
                            egui::Checkbox::new(&mut ks.allow_lan, "Allow the local network"),
                        );
                    });
                    ui.label(
                        egui::RichText::new(connect::describe_killswitch(
                            &settings,
                            active,
                            problem.as_deref(),
                        ))
                        .small(),
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
            }

            ui.separator();
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.running.update, egui::Button::new("Check for updates"))
                    .clicked()
                {
                    self.running.update = true;
                    self.spawn_job(ui.ctx(), || Job::UpdateChecked(connect::update(false)));
                }
                if self.running.update {
                    ui.add(egui::Spinner::new());
                }
                if let Some(version) = self.update.clone()
                    && ui
                        .add_enabled(
                            !self.running.update,
                            egui::Button::new(format!("Install Polytunnel {version}")),
                        )
                        .clicked()
                {
                    self.confirm = Some(Confirm::Install(version));
                }
            });

            if !self.link_status.is_empty() {
                ui.separator();
                ui.label(&self.link_status);
                ui.horizontal(|ui| {
                    if ui.button("Handle GlobalProtect browser sign-ins").clicked() {
                        match uri::register() {
                            Ok(()) => self.log("Polytunnel now handles GlobalProtect sign-ins."),
                            Err(e) => self.log(format!("Could not register: {e}")),
                        }
                        self.link_status = link_status_text();
                    }
                    if ui.button("Stop handling them").clicked() {
                        match uri::unregister() {
                            Ok(()) => self.log(
                                "Polytunnel no longer handles GlobalProtect sign-ins (it \
                                 registers again the next time a browser sign-in needs it).",
                            ),
                            Err(e) => self.log(format!("Could not unregister: {e}")),
                        }
                        self.link_status = link_status_text();
                    }
                });
            }

            ui.separator();
            let mut trace = self.trace;
            if ui
                .checkbox(
                    &mut trace,
                    "Record a troubleshooting trace (passwords and cookies are removed)",
                )
                .changed()
            {
                match crate::trace::set(trace) {
                    Ok(()) => {
                        self.trace = crate::trace::enabled();
                        self.log(if self.trace {
                            format!(
                                "Recording connection traces in {} (the service keeps its own \
                                 in its folder).",
                                crate::trace::file().display()
                            )
                        } else {
                            "Connection traces are off.".to_string()
                        });
                    }
                    Err(e) => self.log(format!("Could not change the trace setting: {e}")),
                }
            }
            if std::env::var_os("POLYTUNNEL_TRACE").is_some() {
                ui.label(
                    egui::RichText::new("POLYTUNNEL_TRACE is set, so traces stay on.").small(),
                );
            }
            if self.trace {
                ui.label(format!("App: {}", crate::trace::file().display()));
                if cfg!(windows) {
                    ui.label(r"Service: %ProgramData%\Polytunnel\trace.log (administrators only)");
                }
            }
        });
    }

    fn confirmations(&mut self, ctx: &egui::Context) {
        let Some(confirm) = &self.confirm else {
            return;
        };
        let (title, text, yes) = match confirm {
            Confirm::Delete(name) => (
                format!("Delete '{name}'?"),
                "The profile is removed from Polytunnel. This cannot be undone (a copy of the \
                 previous profiles file is kept as profiles.toml.bak)."
                    .to_string(),
                "Delete",
            ),
            Confirm::Lockdown(_) => (
                "Turn on lockdown?".to_string(),
                "Lockdown blocks all internet traffic whenever the VPN is not connected, \
                 including right now, and after restarts."
                    .to_string(),
                "Turn on lockdown",
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
        let mut answer = None;
        let modal = egui::Modal::new(egui::Id::unique("confirm")).show(ctx, |ui| {
            ui.set_max_width(400.0);
            ui.heading(title);
            ui.add(egui::Label::new(text).wrap());
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button(yes).clicked() {
                    answer = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    answer = Some(false);
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

    fn prompts(&mut self, ctx: &egui::Context) {
        let mut close = false;
        if let Some(prompt) = &mut self.prompt {
            let modal = egui::Modal::new(egui::Id::unique("prompt")).show(ctx, |ui| {
                ui.set_min_width(340.0);
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
                            ui.add(egui::Label::new(m.as_str()).wrap());
                        }
                        ui.label(username_label.as_str());
                        let user_field = ui.text_edit_singleline(username);
                        ui.label(password_label.as_str());
                        let pass_field =
                            ui.add(egui::TextEdit::singleline(password).password(true));
                        if !*focused {
                            if username.is_empty() {
                                user_field.request_focus();
                            } else {
                                pass_field.request_focus();
                            }
                            *focused = true;
                        }
                        let ready = !username.trim().is_empty() && !password.is_empty();
                        ui.horizontal(|ui| {
                            let sign_in = ui.add_enabled(ready, egui::Button::new("Sign in"));
                            if sign_in.clicked() || (ready && enter) {
                                let _ = reply.send(Some((
                                    username.trim().to_string(),
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
                        focused,
                    } => {
                        ui.heading(title.as_str());
                        ui.add(egui::Label::new(message.as_str()).wrap());
                        let field = ui.add(egui::TextEdit::singleline(code).password(true));
                        if !*focused {
                            field.request_focus();
                            *focused = true;
                        }
                        let ready = !code.trim().is_empty();
                        ui.horizontal(|ui| {
                            let ok = ui.add_enabled(ready, egui::Button::new("OK"));
                            if ok.clicked() || (ready && enter) {
                                let _ = reply.send(Some(Secret::new(std::mem::take(code))));
                                close = true;
                            }
                            if ui.button("Cancel").clicked() {
                                let _ = reply.send(None);
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
                        ui.add(egui::Label::new(message.as_str()).wrap());
                        for (i, (label, secret, value)) in fields.iter_mut().enumerate() {
                            ui.label(label.as_str());
                            let field = ui.add(egui::TextEdit::singleline(value).password(*secret));
                            if i == 0 && !*focused {
                                field.request_focus();
                                *focused = true;
                            }
                        }
                        let ready = fields.iter().all(|(_, _, v)| !v.trim().is_empty());
                        ui.horizontal(|ui| {
                            let ok = ui.add_enabled(ready, egui::Button::new("OK"));
                            if ok.clicked() || (ready && enter) {
                                let values = fields
                                    .iter_mut()
                                    .map(|(_, _, v)| Secret::new(std::mem::take(v)))
                                    .collect();
                                let _ = reply.send(Some(values));
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
            let modal = egui::Modal::new(egui::Id::unique("browser")).show(ctx, |ui| {
                ui.set_max_width(480.0);
                ui.heading("Finish signing in in your browser");
                match &browser.not_opened {
                    None => ui.add(
                        egui::Label::new(format!(
                            "Your browser opened the sign-in page for {}. Polytunnel continues \
                             by itself when you are done.",
                            browser.server
                        ))
                        .wrap(),
                    ),
                    Some(e) => ui.colored_label(
                        RED,
                        format!("The browser could not be opened ({e}). Open the link below."),
                    ),
                };
                ui.horizontal(|ui| {
                    if ui.button("Open the browser again").clicked() {
                        browser.not_opened = crate::browser::open(&browser.url).err();
                    }
                    if ui.button("Copy the link").clicked() {
                        ui.ctx().copy_text(browser.url.clone());
                    }
                });
                ui.separator();
                ui.add(
                    egui::Label::new(
                        "If the browser cannot hand the result back, paste the \
                         globalprotectcallback: link (or the final page's source) here:",
                    )
                    .wrap(),
                );
                ui.add(egui::TextEdit::multiline(&mut browser.pasted).desired_rows(3));
                if let Some(e) = &browser.paste_error {
                    ui.colored_label(RED, e);
                }
                ui.horizontal(|ui| {
                    let ready = !browser.pasted.trim().is_empty();
                    if ui
                        .add_enabled(ready, egui::Button::new("Use pasted result"))
                        .clicked()
                    {
                        browser.paste_error = None;
                        let _ = browser.paste.send(browser.pasted.clone());
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
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

    fn activity(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong("Activity");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Clear").clicked() {
                    self.log.clear();
                }
                if ui.small_button("Copy").clicked() {
                    let text: Vec<String> = self
                        .log
                        .iter()
                        .map(|(time, line)| format!("{time}  {line}"))
                        .collect();
                    ui.ctx().copy_text(text.join("\n"));
                }
            });
        });
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink(false)
            .show(ui, |ui| {
                for (time, line) in &self.log {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(egui::RichText::new(time).weak().monospace());
                        ui.add(egui::Label::new(line).wrap());
                    });
                }
            });
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        // Back in the window: settings changed elsewhere (Task Manager, another program)
        // show as they are now.
        let focused = ctx.input(|i| i.focused);
        if focused && !self.was_focused {
            self.autostart = autostart::enabled();
            self.link_status = link_status_text();
        }
        self.was_focused = focused;
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
            .default_size(130.0)
            .show(ui, |ui| self.activity(ui));
        egui::Panel::left("profiles")
            .resizable(true)
            .default_size(230.0)
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
        self.confirmations(&ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // A connection still being set up is stopped (nobody could answer its questions any
        // more); one that is up keeps running in the service.
        let setting_up = matches!(
            &self.status,
            Some(Ok(Status::Connecting { .. } | Status::NeedsInput { .. }))
        );
        if let Some(worker) = &self.worker {
            worker.cancel();
            if setting_up {
                let _ = connect::disconnect();
            }
            // Give the worker a moment to close an embedded sign-in window.
            let deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < deadline {
                match worker.events.recv_timeout(Duration::from_millis(100)) {
                    Ok(worker::Event::Finished(_)) => break,
                    Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        } else if setting_up {
            let _ = connect::disconnect();
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
            server_cert: Some("0123456789abcdef".repeat(4).parse().unwrap()),
            ..Default::default()
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
    fn editing_a_globalprotect_profile_keeps_what_the_form_does_not_show() {
        let gp = Profile::GlobalProtect(GlobalProtectProfile {
            portal: "vpn.example.com".into(),
            client_version: Some("6.3.0-33".into()),
            client_os: Some(polytunnel_core::profile::ClientOs::Linux),
            ..Default::default()
        });
        let mut editor = Editor::from_profile("work", &gp);
        editor.username = "me".into();
        let Ok((_, Profile::GlobalProtect(p))) = editor.to_profile() else {
            panic!("not GlobalProtect");
        };
        assert_eq!(p.client_version.as_deref(), Some("6.3.0-33"));
        assert_eq!(p.client_os, Some(polytunnel_core::profile::ClientOs::Linux));
        assert_eq!(p.username.as_deref(), Some("me"));
    }

    #[test]
    fn editor_keeps_and_checks_backup_gateways() {
        let forti = Profile::FortinetSsl(FortinetSslProfile {
            server: "fw.example.net:10443".into(),
            backup_servers: vec!["fw-backup.example.net:10443".into()],
            ..Default::default()
        });
        let mut editor = Editor::from_profile("office", &forti);
        assert_eq!(editor.to_profile(), Ok(("office".to_string(), forti)));
        // Blank rows are dropped; a bad address is refused with its position.
        editor.backups.push("  ".into());
        assert!(editor.to_profile().is_ok());
        editor.backups.push("http://plain.example.net".into());
        assert!(
            editor
                .to_profile()
                .unwrap_err()
                .contains("Backup gateway 3")
        );
        let mut ipsec = Editor::new(Kind::FortinetIpsec);
        ipsec.name = "lab".into();
        ipsec.server = "198.51.100.7".into();
        ipsec.backups = vec!["198.51.100.8".into()];
        let Ok((_, Profile::FortinetIpsec(p))) = ipsec.to_profile() else {
            panic!("not IPsec");
        };
        assert_eq!(p.backup_servers, ["198.51.100.8"]);
        ipsec.backups = vec!["198.51.100.8:500".into()];
        assert!(ipsec.to_profile().is_err());
        assert_eq!(backup_note(1), "");
        assert_eq!(backup_note(3), " (+2 backup gateways)");
    }

    #[test]
    fn editor_notices_unsaved_changes() {
        let editor = Editor::new(Kind::FortinetSsl);
        let initial = editor.clone();
        let mut changed = editor.clone();
        assert!(!changed.changed_from(&initial));
        changed.error = Some("shown, not a change".into());
        assert!(!changed.changed_from(&initial));
        changed.server = "vpn.example.net".into();
        assert!(changed.changed_from(&initial));
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

    #[test]
    fn saving_keeps_the_previous_file() {
        let dir = std::env::temp_dir().join(format!("polytunnel-save-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profiles.toml");
        write_with_backup(&path, "first").unwrap();
        write_with_backup(&path, "second").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
        assert_eq!(
            fs::read_to_string(dir.join("profiles.toml.bak")).unwrap(),
            "first"
        );
        assert!(!dir.join("profiles.toml.tmp").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_lines_read_well() {
        assert_eq!(status_line(&None, None).0, "Checking…");
        let down = Some(Err(
            "cannot reach the Polytunnel service (os error 2)".to_string()
        ));
        let (text, color, _) = status_line(&down, None);
        assert!(text.contains("isn't running") && color == Some(RED));
        let lockdown = (
            KillSwitchSettings {
                mode: KillSwitchMode::Always,
                allow_lan: false,
            },
            true,
            None,
        );
        assert!(
            status_line(&Some(Ok(Status::Idle {})), Some(&lockdown))
                .0
                .contains("lockdown")
        );
        let connected = Some(Ok(Status::Connected {
            profile: "work".into(),
            server: "gw.example.com".into(),
            addresses: vec!["10.0.0.2".into()],
            transport: "esp-tcp".into(),
            since_unix: now_unix(),
            notice: None,
            gateway: None,
            bytes_in: 5 * 1024 * 1024,
            bytes_out: 900,
        }));
        let (text, color, _) = status_line(&connected, None);
        assert!(text.starts_with("Connected to gw.example.com (work) over ESP over TCP"));
        assert!(text.contains("5.0 MB received · 900 B sent"));
        assert_eq!(color, Some(GREEN));
        assert_eq!(active_profile(&connected), Some("work"));
        let failed = Some(Ok(Status::Failed {
            profile: "work".into(),
            message: "no answer".into(),
            since_unix: 0,
        }));
        assert_eq!(active_profile(&failed), None);
        assert!(status_line(&failed, None).0.starts_with("Couldn't connect"));
    }

    #[test]
    fn sizes_and_durations() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
        assert_eq!(elapsed(now_unix() - 65), "1:05");
        assert_eq!(elapsed(now_unix() - 3725), "1:02:05");
    }
}
