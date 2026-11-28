//! The Polytunnel window (egui). It runs only while open and exits completely when closed;
//! the always-on tray agent ([`agent`]) is a separate, tiny process.

pub mod agent;
mod dialogs;
mod icons;
mod integrations;
mod notify;
mod prefs;
mod screens;
mod theme;
mod widgets;
mod worker;

use std::collections::VecDeque;
use std::fs;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;
use polytunnel_core::Secret;
use polytunnel_core::ipc::{KillSwitchSettings, Status};
use polytunnel_core::pin::CertFingerprint;
use polytunnel_core::profile::{
    EapMethodName, FortinetIpsecProfile, FortinetSslProfile, GatewayPolicy, GlobalProtectProfile,
    IpsecTransport, ProbeMethod, Profile, Profiles, normalize_server, valid_host,
};
use polytunnel_gp::rank::Ranking;
use polytunnel_http::CertInfo;

use crate::auth::Trust;
use crate::instance::{self, Instance, Message, Role};
use crate::profiles_file::{save_profiles, trust_certificate};
use crate::{autostart, connect, forticlient, gateways, paths, uri};

const TITLE: &str = "Polytunnel";
const LOG_LINES: usize = 500;
/// Status polls: often while the service answers, less often while it does not.
const POLL: Duration = Duration::from_millis(1500);
const POLL_UNREACHABLE: Duration = Duration::from_secs(10);
/// The kill switch is asked about once every this many status polls.
const KILLSWITCH_EVERY: u32 = 4;

/// The window's size by default and at least, in points.
const WINDOW_SIZE: [f32; 2] = [380.0, 680.0];
const WINDOW_MIN: [f32; 2] = [340.0, 520.0];

/// Opens the window (or brings the open one to the front) and makes sure the tray agent runs.
pub fn run_window() -> i32 {
    run_window_with(None)
}

/// [`run_window`], then connects with profile `connect` (a request from the tray).
pub fn run_window_with(connect: Option<String>) -> i32 {
    #[cfg(windows)]
    crate::win::hide_own_console();
    let instance = match instance::claim(Role::Gui) {
        Ok(Some(instance)) => Some(instance),
        Ok(None) => {
            // The window is open already; the tray may have been quit since.
            agent::ensure_running();
            let message = match connect {
                Some(name) => Message::Connect(name),
                None => Message::Show,
            };
            return match instance::send(Role::Gui, message) {
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

    let prefs = prefs::load();
    // Debug screenshots open at the design size, not where the window was last.
    let place = prefs
        .window
        .filter(|_| debug_pages().is_none())
        .and_then(|place| {
            prefs::placement(place, prefs::screens()?, (WINDOW_MIN[0], WINDOW_MIN[1]))
        });
    let icon = egui::IconData {
        rgba: include_bytes!(concat!(env!("OUT_DIR"), "/icon48.rgba")).to_vec(),
        width: 48,
        height: 48,
    };
    let mut viewport = egui::ViewportBuilder::default()
        .with_title(TITLE)
        .with_app_id("polytunnel")
        .with_icon(icon)
        .with_inner_size(WINDOW_SIZE)
        .with_min_inner_size(WINDOW_MIN)
        .with_maximize_button(false);
    if let Some(place) = place {
        viewport = viewport
            .with_inner_size([place.width, place.height])
            .with_position([place.x, place.y]);
    }
    let options = eframe::NativeOptions {
        viewport,
        centered: place.is_none(),
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
            theme::fonts(&cc.egui_ctx);
            theme::apply(&cc.egui_ctx, prefs.appearance);
            Ok(Box::new(App::new(
                &cc.egui_ctx,
                ipc_rx,
                instance,
                prefs,
                connect,
            )))
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
    forti_base: FortinetSslProfile,
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
            forti_base: FortinetSslProfile::default(),
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
                forti_base: p.clone(),
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
                ..self.forti_base.clone()
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
    /// A gateway certificate to trust or not.
    Certificate {
        /// `host:port`
        server: String,
        info: Box<CertInfo>,
        /// The certificate the profile trusted before, when this one replaces it.
        previous: Option<CertFingerprint>,
        reply: Sender<Trust>,
        focused: bool,
    },
}

struct BrowserUi {
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
    /// Quit while lockdown keeps the internet off.
    QuitLockdown,
}

enum Leave {
    /// Back to the page before the form.
    Close,
}

/// The window's pages: Home, and the pages opened from it (with a back arrow).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Page {
    Home,
    /// Manage profiles.
    Profiles,
    /// Add a profile, step 1: the integration.
    AddIntegration,
    /// Add a profile, step 2: the connection type (index into `integrations::ALL`).
    AddType(usize),
    /// The profile form (`App::editor`).
    Edit,
    /// A GlobalProtect profile's gateway picker.
    Gateways(String),
    /// A Fortinet profile's gateways, in order.
    GatewayOrder(String),
    /// Import another program's profiles.
    Import,
    Settings,
    Activity,
}

/// The last connection attempt this window made: the profile, when, and how it ended.
#[derive(Debug, Clone)]
struct Attempt {
    profile: String,
    time: String,
    result: Result<(), String>,
    /// Home no longer shows its failure (Dismiss, or a newer attempt).
    dismissed: bool,
}

/// A profile found in another program, offered for import.
struct ImportItem {
    name: String,
    profile: Profile,
    checked: bool,
    /// Why it is renamed or skipped, if it is.
    note: Option<String>,
}

/// How an activity log line is marked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Info,
    Good,
    Warning,
    Problem,
}

struct LogLine {
    time: String,
    level: Level,
    text: String,
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
    log: VecDeque<LogLine>,
    /// The page stack: Home at the bottom, the open page on top.
    pages: Vec<Page>,
    prefs: prefs::Prefs,
    /// Where the window is now (saved when it closes).
    place: Option<prefs::WindowPlace>,
    /// Home's connection details are open.
    details_open: bool,
    /// The profile this window is connecting with (until the attempt ends).
    attempt: Option<String>,
    /// That attempt signs in through Polytunnel's window because the kill switch holds
    /// traffic (the browser is offline).
    signin_held: bool,
    /// How the last attempt ended (for Activity's summary).
    last_attempt: Option<Attempt>,
    /// The log as it was before Clear, for Undo (for a few seconds).
    cleared: Option<(VecDeque<LogLine>, Instant)>,
    /// Profiles found to import.
    import: Vec<ImportItem>,
    /// How many FortiClient profiles there are to import (counted when first needed).
    import_count: Option<usize>,
    /// The update banner was put off for now.
    update_later: bool,
    /// The user closed the window (not Quit or an update).
    user_closed: bool,
    /// The theme the title bar was last coloured for (dark?).
    caption: Option<bool>,
    /// When the service started reconnecting (it tries for five minutes).
    reconnect_started: Option<Instant>,
    /// Debug builds: a made-up status for screenshots (`POLYTUNNEL_STATE`); nothing is saved.
    fake: bool,
    /// The activity log shows only warnings and problems.
    problems_only: bool,
    /// A connection the tray asked for, started on the first frame.
    pending_connect: Option<String>,
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
        tidy(f / K, "KB")
    } else if f < K * K * K {
        tidy(f / (K * K), "MB")
    } else {
        format!("{:.2} GB", f / (K * K * K))
    }
}

/// `12.3 KB` below 100, `182 MB` from 100 up.
fn tidy(value: f64, unit: &str) -> String {
    if value >= 100.0 {
        format!("{value:.0} {unit}")
    } else {
        format!("{value:.1} {unit}")
    }
}

/// The local time of day `secs` from now, `HH:MM`.
fn clock_in(secs: u64) -> String {
    let now = clock();
    let parts: Vec<u64> = now.split(':').filter_map(|p| p.parse().ok()).collect();
    let [h, m, s] = parts[..] else {
        return now;
    };
    let t = (h * 3600 + m * 60 + s + secs) % 86_400;
    format!("{:02}:{:02}", t / 3600, t / 60 % 60)
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

impl App {
    fn new(
        ctx: &egui::Context,
        ipc_rx: Receiver<Message>,
        instance: Option<Instance>,
        prefs: prefs::Prefs,
        pending_connect: Option<String>,
    ) -> Self {
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
        let fake = debug_state();
        let (profiles, load_error) = match &fake {
            Some(state) if state.as_str() == "first" => (Profiles::default(), None),
            Some(_) => (sample_profiles(), None),
            None => load_profiles(),
        };
        let selected = prefs
            .last_profile
            .clone()
            .filter(|name| profiles.get(name).is_some())
            .or_else(|| profiles.profiles.keys().next().cloned());
        let (job_tx, job_rx) = mpsc::channel();
        let mut app = App {
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
            pages: vec![Page::Home],
            prefs,
            place: None,
            details_open: false,
            attempt: None,
            signin_held: false,
            last_attempt: None,
            cleared: None,
            import: Vec::new(),
            import_count: None,
            update_later: false,
            user_closed: false,
            caption: None,
            reconnect_started: None,
            fake: fake.is_some(),
            problems_only: false,
            pending_connect,
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
        };
        if let Some(state) = fake {
            app.fake_state(&state);
        }
        if let Some(pages) = debug_pages() {
            if pages.last() == Some(&Page::Edit) {
                let which = std::env::var("POLYTUNNEL_SCREEN").unwrap_or_default();
                let name = match which.as_str() {
                    "edit-gp" => "Work",
                    "edit-ipsec" => "Lab",
                    _ => "Office",
                };
                if let Some(profile) = app.profiles.get(name).cloned() {
                    app.open_editor(Editor::from_profile(name, &profile));
                }
            } else {
                app.pages = pages;
            }
        }
        app
    }

    /// The open page.
    fn page(&self) -> &Page {
        self.pages.last().unwrap_or(&Page::Home)
    }

    /// Opens `page` over the current one.
    fn go(&mut self, page: Page) {
        if self.page() != &page {
            self.pages.push(page);
        }
    }

    /// Back to the page before (the form asks first when it has unsaved changes).
    fn back(&mut self) {
        if self.page() == &Page::Edit {
            self.leave_editor(Leave::Close);
        } else if self.pages.len() > 1 {
            self.pages.pop();
        }
    }

    /// Back to Home.
    fn home(&mut self) {
        self.pages.truncate(1);
    }

    /// Saves the profiles (not in a debug build showing made-up profiles).
    fn store(&self) -> Result<(), String> {
        if self.fake {
            return Ok(());
        }
        save_profiles(&self.profiles)
    }

    /// The profile Home shows: the one connected or connecting, else the one chosen last.
    fn current_profile(&self) -> Option<String> {
        active_profile(&self.status)
            .map(str::to_string)
            .or_else(|| self.attempt.clone())
            .or_else(|| self.selected.clone())
            .filter(|name| self.profiles.get(name).is_some())
    }

    /// Is the kill switch holding traffic now (lockdown, or a dropped connection)?
    fn traffic_held(&self) -> bool {
        let connected = matches!(&self.status, Some(Ok(Status::Connected { .. })));
        matches!(&self.killswitch, Some((settings, active, _))
            if *active && settings.mode != polytunnel_core::ipc::KillSwitchMode::Off)
            && !connected
    }

    fn log(&mut self, line: impl Into<String>) {
        self.log_at(Level::Info, line);
    }

    fn log_at(&mut self, level: Level, line: impl Into<String>) {
        if self.log.len() >= LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back(LogLine {
            time: clock(),
            level,
            text: line.into(),
        });
    }

    /// Leaves the profile form, back to the page before it.
    fn close_editor(&mut self) {
        self.editor = None;
        self.editor_initial = None;
        if self.page() == &Page::Edit {
            self.pages.pop();
        }
    }

    /// Leaves the form after saving: a new profile's "Add" steps go too.
    fn finish_editor(&mut self) {
        self.close_editor();
        while matches!(self.page(), Page::AddIntegration | Page::AddType(_)) {
            self.pages.pop();
        }
    }

    /// Changes the appearance now and remembers it.
    fn set_appearance(&mut self, ctx: &egui::Context, appearance: prefs::Appearance) {
        self.prefs.appearance = appearance;
        theme::apply(ctx, appearance);
        self.save_prefs();
    }

    /// Saves the window's preferences (keeping the remembered place as it is on disk).
    fn save_prefs(&mut self) {
        if self.fake {
            return;
        }
        let mut stored = prefs::load();
        stored.appearance = self.prefs.appearance;
        stored.notifications = self.prefs.notifications;
        stored.last_profile = self.prefs.last_profile.clone();
        if let Err(e) = prefs::save(&stored) {
            self.log_at(Level::Problem, format!("Could not save the settings: {e}"));
        }
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

    /// Connects with profile `name`; an attempt already under way is cancelled first (Switch).
    fn connect(&mut self, ctx: &egui::Context, name: String) {
        let Some(mut profile) = self.profiles.get(&name).cloned() else {
            return;
        };
        self.selected = Some(name.clone());
        if self.fake {
            self.log(format!("Not connecting to '{name}' (screenshot mode)."));
            return;
        }
        if let Some(worker) = self.worker.take() {
            worker.cancel();
        }
        self.prompt = None;
        self.browser = None;
        // While the kill switch holds traffic the browser is offline too: sign in through
        // Polytunnel's own window, which the kill switch lets through.
        self.signin_held = false;
        if let Profile::GlobalProtect(gp) = &mut profile
            && gp.embedded_login != Some(true)
            && self.traffic_held()
            && crate::embedded::helper().is_some()
        {
            gp.embedded_login = Some(true);
            self.signin_held = true;
            self.log(
                "The kill switch is holding traffic, so sign-in opens in Polytunnel's window.",
            );
        }
        self.log(format!("Connecting with '{name}'..."));
        self.attempt = Some(name.clone());
        if self.prefs.last_profile.as_deref() != Some(name.as_str()) {
            self.prefs.last_profile = Some(name.clone());
            self.save_prefs();
        }
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
            Leave::Close => self.close_editor(),
        }
    }

    fn open_editor(&mut self, editor: Editor) {
        self.editor_initial = Some(editor.clone());
        self.editor = Some(editor);
        self.go(Page::Edit);
    }

    fn poll(&mut self, ctx: &egui::Context) {
        while let Ok(poll) = self.poll_rx.try_recv() {
            if self.fake {
                continue;
            }
            match poll {
                Poll::Status(status) => {
                    if let Err(e) = &status
                        && self.logged_problem.as_ref() != Some(e)
                    {
                        self.logged_problem = Some(e.clone());
                        let line = format!("Service: {e}");
                        self.log_at(Level::Problem, line);
                    } else if status.is_ok() {
                        self.logged_problem = None;
                    }
                    if let Some((level, line)) =
                        change_line(self.status.as_ref(), &status, self.worker.is_some())
                    {
                        self.log_at(level, line);
                    }
                    let reconnecting = matches!(&status, Ok(Status::Reconnecting { .. }));
                    if !reconnecting {
                        self.reconnect_started = None;
                    } else if self.reconnect_started.is_none() {
                        self.reconnect_started = Some(Instant::now());
                    }
                    // Home shows the connection that is on.
                    if let Some(active) = active_profile(&Some(status.clone()))
                        && self.profiles.get(active).is_some()
                    {
                        self.selected = Some(active.to_string());
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
                Message::Connect(name) => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    self.pending_connect = Some(name);
                }
                #[allow(unreachable_patterns)]
                other => self.other_message(ctx, other),
            }
        }
        while let Ok(job) = self.job_rx.try_recv() {
            self.finish_job(ctx, job);
        }
        let mut finished = false;
        let mut outcome: Option<Result<(), String>> = None;
        let mut lines = Vec::new();
        let mut trusted = Vec::new();
        if let Some(worker) = &self.worker {
            while let Ok(event) = worker.events.try_recv() {
                match event {
                    worker::Event::Progress(line) => lines.push((Level::Info, line)),
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
                    worker::Event::Prompt(worker::Prompt::Certificate {
                        server,
                        info,
                        previous,
                        reply,
                    }) => {
                        self.prompt = Some(PromptUi::Certificate {
                            server,
                            info,
                            previous,
                            reply,
                            focused: false,
                        });
                    }
                    worker::Event::TrustCertificate {
                        profile,
                        gateway,
                        fingerprint,
                    } => trusted.push((profile, gateway, fingerprint)),
                    worker::Event::PromptClosed => self.prompt = None,
                    worker::Event::Prompt(worker::Prompt::Browser {
                        url,
                        not_opened,
                        paste,
                    }) => {
                        self.browser = Some(BrowserUi {
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
                        lines.push(match &result {
                            Ok(message) => (Level::Good, message.clone()),
                            Err(e) if e == connect::CANCELLED => (Level::Info, "Cancelled.".into()),
                            Err(e) => (Level::Problem, format!("Could not connect: {e}")),
                        });
                        outcome = match result {
                            Ok(_) => Some(Ok(())),
                            Err(e) if e == connect::CANCELLED => None,
                            Err(e) => Some(Err(e)),
                        };
                        finished = true;
                    }
                }
            }
        }
        for (level, line) in lines {
            self.log_at(level, line);
        }
        for (profile, gateway, fingerprint) in trusted {
            self.save_trusted_certificate(&profile, &gateway, fingerprint);
        }
        if finished {
            if let (Some(result), Some(profile)) = (outcome, self.attempt.clone()) {
                self.last_attempt = Some(Attempt {
                    profile,
                    time: clock()[..5].to_string(),
                    result,
                    dismissed: false,
                });
            }
            self.attempt = None;
            self.signin_held = false;
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
                    Err(e) => self.log_at(Level::Problem, format!("Could not disconnect: {e}")),
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
                    Err(e) => {
                        self.log_at(
                            Level::Problem,
                            format!("Could not change the kill switch: {e}"),
                        );
                    }
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

    /// Looks for FortiClient's profiles and opens the import page with them.
    fn scan_import(&mut self) {
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
        self.import_count = Some(found.len());
        self.import = found
            .into_iter()
            .map(|(base, profile)| {
                if let Some(existing) = self.same_profile(&profile) {
                    return ImportItem {
                        name: base,
                        profile,
                        checked: false,
                        note: Some(format!("Already here as \"{existing}\".")),
                    };
                }
                let mut name = base.clone();
                while self.profiles.profiles.contains_key(&name) {
                    name.push('-');
                }
                let note = (name != base)
                    .then(|| format!("You already have \"{base}\". This one becomes \"{name}\"."));
                ImportItem {
                    name,
                    profile,
                    checked: true,
                    note,
                }
            })
            .collect();
        self.go(Page::Import);
    }

    /// Adds the checked import items as profiles.
    fn do_import(&mut self) {
        let items = std::mem::take(&mut self.import);
        let before = self.profiles.clone();
        let mut first_new = None;
        let mut count = 0;
        for item in items.into_iter().filter(|i| i.checked) {
            self.log(format!(
                "Imported the FortiClient {} profile as '{}'.",
                item.profile.kind(),
                item.name
            ));
            self.profiles
                .profiles
                .insert(item.name.clone(), item.profile);
            first_new.get_or_insert(item.name);
            count += 1;
        }
        if count == 0 {
            self.back();
            return;
        }
        match self.store() {
            Ok(()) => {
                self.selected = first_new;
                self.import_count = Some(0);
                self.home();
            }
            Err(e) => {
                self.profiles = before;
                self.log_at(Level::Problem, format!("Could not save the profiles: {e}"));
            }
        }
    }

    /// Saves the form; `connect_after`: a new profile connects right away (from Home).
    fn save_editor(&mut self, ctx: &egui::Context, connect_after: bool) {
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
        let new = editor.original.is_none();
        match self.store() {
            Ok(()) => {
                self.selected = Some(name.clone());
                self.finish_editor();
                if new && connect_after {
                    self.home();
                    self.connect(ctx, name);
                }
            }
            Err(e) => {
                self.profiles = before;
                if let Some(editor) = &mut self.editor {
                    editor.error = Some(format!("Could not save: {e}"));
                }
            }
        }
    }

    /// Saves a certificate the user chose to always trust on one of a Fortinet profile's
    /// gateways.
    fn save_trusted_certificate(
        &mut self,
        name: &str,
        gateway: &str,
        fingerprint: CertFingerprint,
    ) {
        if self.read_only() {
            self.log_at(
                Level::Warning,
                format!(
                    "The certificate of {gateway} was trusted for this connection only: the \
                     profiles file could not be read, so nothing was saved."
                ),
            );
            return;
        }
        let before = self.profiles.clone();
        let saved = trust_certificate(&mut self.profiles, name, gateway, fingerprint)
            .and_then(|()| self.store());
        match saved {
            Ok(()) => self.log(format!(
                "'{name}' now always trusts this certificate on {gateway}."
            )),
            Err(e) => {
                self.profiles = before;
                self.log_at(
                    Level::Problem,
                    format!("Could not save the trusted certificate: {e}"),
                );
            }
        }
    }

    fn delete_profile(&mut self, name: &str) {
        let before = self.profiles.clone();
        self.profiles.profiles.remove(name);
        match self.store() {
            Ok(()) => {
                self.log(format!("Deleted the profile '{name}'."));
                if self.selected.as_deref() == Some(name) {
                    self.selected = self.profiles.profiles.keys().next().cloned();
                }
                if self.editor.as_ref().and_then(|e| e.original.as_deref()) == Some(name) {
                    self.close_editor();
                }
            }
            Err(e) => {
                self.profiles = before;
                self.log(format!("Could not save the profiles: {e}"));
            }
        }
    }
}

/// Debug builds: the page to open on (`POLYTUNNEL_SCREEN`), for screenshots.
fn debug_pages() -> Option<Vec<Page>> {
    if !cfg!(debug_assertions) {
        return None;
    }
    let top = match std::env::var("POLYTUNNEL_SCREEN").ok()?.as_str() {
        "profiles" => Page::Profiles,
        "add" => Page::AddIntegration,
        "add-type" => Page::AddType(1),
        "edit" | "edit-ssl" | "edit-gp" | "edit-ipsec" => Page::Edit,
        "gateways" => Page::Gateways("Work".into()),
        "gateway-order" => Page::GatewayOrder("Office".into()),
        "import" => Page::Import,
        "settings" => Page::Settings,
        "activity" => Page::Activity,
        _ => return Some(vec![Page::Home]),
    };
    Some(vec![Page::Home, top])
}

/// Debug builds: a made-up state to show (`POLYTUNNEL_STATE`), with made-up profiles.
fn debug_state() -> Option<String> {
    if !cfg!(debug_assertions) {
        return None;
    }
    std::env::var("POLYTUNNEL_STATE")
        .ok()
        .filter(|s| !s.is_empty())
}

fn debug_appearance() -> Option<prefs::Appearance> {
    if !cfg!(debug_assertions) {
        return None;
    }
    match std::env::var("POLYTUNNEL_THEME").ok()?.as_str() {
        "light" => Some(prefs::Appearance::Light),
        "dark" => Some(prefs::Appearance::Dark),
        _ => None,
    }
}

/// Made-up profiles for screenshots (example addresses only).
fn sample_profiles() -> Profiles {
    let text = r#"
[profile.Work]
type = "global-protect"
portal = "vpn.example.com"

[profile.Office]
type = "fortinet-ssl"
server = "gw.example.net:10443"
backup-servers = ["gw2.example.net:10443"]
trusted-certs = { "gw.example.net:10443" = "sha256:3f9a5c2e71d04b8e6a1c9f37b2e05d48c6a91f0e3b7d25a8e4c1f69b0d73a25e" }

[profile.Lab]
type = "fortinet-ipsec"
server = "198.51.100.7"
username = "a.user"

[profile.Branch]
type = "global-protect"
portal = "branch.example.org"
"#;
    Profiles::parse(text).unwrap_or_default()
}

impl App {
    /// Debug builds: shows a made-up connection state.
    fn fake_state(&mut self, state: &str) {
        use polytunnel_core::ipc::KillSwitchMode;
        let ks = |mode, active| {
            Some((
                KillSwitchSettings {
                    mode,
                    allow_lan: true,
                },
                active,
                None,
            ))
        };
        let connected = |notice: Option<&str>| Status::Connected {
            profile: "Work".into(),
            server: "gw-use.example.com".into(),
            addresses: vec!["10.20.30.40".into()],
            transport: "esp".into(),
            since_unix: now_unix().saturating_sub(6130),
            notice: notice.map(str::to_string),
            gateway: Some("203.0.113.10".into()),
            bytes_in: 190_840_832,
            bytes_out: 25_794_560,
        };
        self.selected = Some("Work".into());
        self.killswitch = ks(KillSwitchMode::Connected, false);
        self.status = Some(Ok(Status::Idle {}));
        match state {
            "connecting" => {
                self.selected = Some("Office".into());
                self.status = Some(Ok(Status::Connecting {
                    profile: "Office".into(),
                }));
            }
            "waiting" => {
                self.selected = Some("Office".into());
                self.status = Some(Ok(Status::Connecting {
                    profile: "Office".into(),
                }));
                let (reply, _) = mpsc::channel();
                self.prompt = Some(PromptUi::Credentials {
                    title: "Sign in to Office".into(),
                    message: Some("gw.example.net:10443".into()),
                    username_label: "Username".into(),
                    password_label: "Password".into(),
                    username: "a.user".into(),
                    password: String::new(),
                    reply,
                    focused: false,
                });
            }
            "browser" => {
                self.status = Some(Ok(Status::Connecting {
                    profile: "Work".into(),
                }));
                let (paste, _) = mpsc::channel();
                self.browser = Some(BrowserUi {
                    url: "https://vpn.example.com/".into(),
                    not_opened: None,
                    pasted: String::new(),
                    paste_error: None,
                    paste,
                });
            }
            "held" => {
                self.killswitch = ks(KillSwitchMode::Always, true);
                self.status = Some(Ok(Status::Connecting {
                    profile: "Work".into(),
                }));
                self.signin_held = true;
            }
            "connected" | "details" => {
                self.killswitch = ks(KillSwitchMode::Connected, true);
                self.status = Some(Ok(connected(None)));
                self.details_open = state == "details";
            }
            "limited" => {
                self.killswitch = ks(KillSwitchMode::Connected, true);
                self.status = Some(Ok(connected(Some(
                    "VPN access is limited: the device check did not pass.",
                ))));
            }
            "reconnecting" => {
                self.reconnect_started = Some(Instant::now());
                self.killswitch = ks(KillSwitchMode::Connected, true);
                self.status = Some(Ok(Status::Reconnecting {
                    profile: "Work".into(),
                    server: "gw-use.example.com".into(),
                    attempt: 3,
                    since_unix: now_unix().saturating_sub(6130),
                }));
            }
            "failed" => {
                self.selected = Some("Office".into());
                self.status = Some(Ok(Status::Failed {
                    profile: "Office".into(),
                    message: "gw.example.net cannot be reached (network error: connection timed \
                              out)"
                        .into(),
                    since_unix: now_unix(),
                }));
                self.last_attempt = Some(Attempt {
                    profile: "Office".into(),
                    time: "13:12".into(),
                    result: Err("gw.example.net cannot be reached".into()),
                    dismissed: false,
                });
                self.log_at(Level::Info, "Connecting with 'Office'...");
                self.log_at(
                    Level::Problem,
                    "Could not connect: gw.example.net and its backup didn't answer.",
                );
            }
            "blocked" => self.killswitch = ks(KillSwitchMode::Connected, true),
            "lockdown" => self.killswitch = ks(KillSwitchMode::Always, true),
            "service" => {
                self.status = Some(Err("cannot reach the Polytunnel service".into()));
                self.killswitch = None;
            }
            "update" => self.update = Some("0.0.14".into()),
            _ => {}
        }
        if self.log.is_empty() {
            self.log_at(Level::Warning, "Reconnecting: the network changed.");
            self.log_at(Level::Good, "Connected to Work (US East).");
        }
    }

    /// The tray's other requests.
    fn other_message(&mut self, ctx: &egui::Context, message: Message) {
        match message {
            Message::Lockdown => {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                self.home();
                self.go(Page::Settings);
                let allow_lan = self
                    .killswitch
                    .as_ref()
                    .is_some_and(|(s, _, _)| s.allow_lan);
                self.confirm = Some(Confirm::Lockdown(KillSwitchSettings {
                    mode: polytunnel_core::ipc::KillSwitchMode::Always,
                    allow_lan,
                }));
            }
            Message::Show | Message::Quit | Message::Connect(_) | Message::Closed => {}
        }
    }

    /// Quits Polytunnel: the tray disconnects and closes everything (or this window does it
    /// when there is no tray).
    fn quit_all(&mut self, ctx: &egui::Context) {
        if self.fake || instance::send(Role::Agent, Message::Quit).is_err() {
            if active_profile(&self.status).is_some() && !self.fake {
                let _ = connect::disconnect();
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    /// Starts the Polytunnel service (Windows asks for an administrator's approval).
    fn start_service(&mut self) {
        #[cfg(windows)]
        {
            match run_elevated("sc.exe", "start Polytunnel") {
                Ok(()) => self.log("Starting the Polytunnel service..."),
                Err(e) => self.log_at(Level::Problem, format!("Could not start the service: {e}")),
            }
        }
        #[cfg(not(windows))]
        self.log("Start the polytunnel service with your system's service manager.");
    }

    /// Writes a report for IT (status, kill switch, the profiles' servers, this log and the
    /// recent app and trace logs) to Downloads and shows it.
    fn save_report(&mut self) {
        let mut text = String::new();
        let mut line = |l: String| {
            text.push_str(&l);
            text.push('\n');
        };
        line(format!(
            "Polytunnel {} report, {}",
            polytunnel_core::VERSION,
            clock()
        ));
        line(String::new());
        line(format!(
            "Status: {}",
            match &self.status {
                Some(Ok(s)) => connect::describe(s),
                Some(Err(e)) => connect::service_problem(e),
                None => "checking".into(),
            }
        ));
        if let Some((settings, active, problem)) = &self.killswitch {
            line(format!(
                "Kill switch: {}",
                connect::describe_killswitch(settings, *active, problem.as_deref())
            ));
        }
        if let Some(a) = &self.last_attempt {
            line(format!(
                "Last attempt: {} at {}: {}",
                a.profile,
                a.time,
                match &a.result {
                    Ok(()) => "connected".to_string(),
                    Err(e) => e.clone(),
                }
            ));
        }
        line(String::new());
        line("Profiles:".into());
        for (name, profile) in &self.profiles.profiles {
            line(format!("  {name}: {}", integrations::profile_line(profile)));
        }
        line(String::new());
        line("Activity:".into());
        for l in &self.log {
            line(format!("  {}  {}", l.time, l.text));
        }
        for (title, file) in [
            ("App log", paths::log_dir().join("app.log")),
            (
                "Trace (passwords, codes and cookies removed)",
                crate::trace::file(),
            ),
        ] {
            if let Ok(content) = fs::read_to_string(&file) {
                let tail: Vec<&str> = content.lines().rev().take(300).collect();
                line(String::new());
                line(format!("{title}, last {} lines:", tail.len()));
                for l in tail.into_iter().rev() {
                    line(format!("  {l}"));
                }
            }
        }
        let dir = std::env::var_os("USERPROFILE")
            .map(|home| std::path::PathBuf::from(home).join("Downloads"))
            .filter(|d| d.is_dir())
            .unwrap_or_else(std::env::temp_dir);
        let path = dir.join(format!("Polytunnel report {}.txt", now_unix()));
        match fs::write(&path, text) {
            Ok(()) => {
                self.log(format!("Saved a report for IT: {}", path.display()));
                #[cfg(windows)]
                let _ = std::process::Command::new("explorer.exe")
                    .arg(format!("/select,{}", path.display()))
                    .spawn();
            }
            Err(e) => self.log_at(Level::Problem, format!("Could not save the report: {e}")),
        }
    }
}

/// Runs `program` with `args` as an administrator (Windows asks first).
#[cfg(windows)]
fn run_elevated(program: &str, args: &str) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (verb, file, params) = (wide("runas"), wide(program), wide(args));
    // SAFETY: NUL-terminated wide strings that outlive the call.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_HIDE,
        )
    };
    // ShellExecute returns a value greater than 32 on success.
    if result as usize > 32 {
        Ok(())
    } else {
        Err(format!("Windows refused (code {})", result as usize))
    }
}

/// Colours the window's title bar like the page under it (Windows 11; older Windows keeps its
/// own).
#[cfg(windows)]
fn color_title_bar(p: &theme::Palette) -> bool {
    use windows_sys::Win32::Foundation::{HWND, LPARAM};
    use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumThreadWindows, GetWindowTextW, IsWindowVisible,
    };

    /// The window titled like ours (winit's event window on this thread is "visible" too).
    unsafe extern "system" fn found(hwnd: HWND, out: LPARAM) -> i32 {
        let mut title = [0u16; 64];
        // SAFETY: `title` is a writable buffer of the given length; `out` points at the HWND
        // slot below, alive for the enumeration.
        unsafe {
            let n = GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32);
            let ours = String::from_utf16_lossy(&title[..n.max(0) as usize]) == TITLE;
            if ours && IsWindowVisible(hwnd) != 0 {
                *(out as *mut HWND) = hwnd;
                return 0;
            }
        }
        1
    }
    let mut hwnd: HWND = std::ptr::null_mut();
    // SAFETY: enumerates this thread's windows into a local; the callback only writes it.
    unsafe {
        EnumThreadWindows(
            GetCurrentThreadId(),
            Some(found),
            &mut hwnd as *mut HWND as LPARAM,
        );
    }
    if hwnd.is_null() {
        return false;
    }
    let colorref =
        |c: egui::Color32| u32::from(c.r()) | (u32::from(c.g()) << 8) | (u32::from(c.b()) << 16);
    // DWMWA_BORDER_COLOR = 34, DWMWA_CAPTION_COLOR = 35, DWMWA_TEXT_COLOR = 36.
    for (attribute, value) in [
        (35u32, colorref(p.title_bar)),
        (36, colorref(p.title_ink)),
        (34, colorref(p.line)),
    ] {
        // SAFETY: a valid window handle and a 4-byte COLORREF value.
        unsafe {
            DwmSetWindowAttribute(
                hwnd,
                attribute,
                &value as *const u32 as *const core::ffi::c_void,
                4,
            );
        }
    }
    true
}

/// A log line for a change of the connection the window did not start itself (or that
/// happened later): dropped, back, failed.
fn change_line(
    before: Option<&Result<Status, String>>,
    now: &Result<Status, String>,
    own_attempt: bool,
) -> Option<(Level, String)> {
    let before = before.and_then(|b| b.as_ref().ok());
    match (before, now) {
        (Some(Status::Connected { .. }), Ok(Status::Reconnecting { server, .. })) => Some((
            Level::Warning,
            format!("The connection to {server} dropped; reconnecting..."),
        )),
        (Some(Status::Reconnecting { .. }), Ok(Status::Connected { server, .. })) => {
            Some((Level::Good, format!("The connection to {server} is back.")))
        }
        (
            Some(Status::Connected { .. } | Status::Reconnecting { .. }),
            Ok(Status::Failed { message, .. }),
        ) if !own_attempt => Some((Level::Problem, format!("The connection ended: {message}"))),
        _ => None,
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(name) = self.pending_connect.take() {
            if self.busy() {
                self.log_at(
                    Level::Warning,
                    format!("Not connecting to '{name}': another connection is being set up."),
                );
            } else if self.profiles.get(&name).is_some() {
                self.home();
                self.connect(ctx, name);
            } else {
                self.log_at(
                    Level::Problem,
                    format!("There is no profile named '{name}'."),
                );
            }
        }
        if let Some(appearance) = debug_appearance()
            && appearance != self.prefs.appearance
        {
            self.prefs.appearance = appearance;
            theme::apply(ctx, appearance);
        }
        self.poll(ctx);
        // The user closed the window (the tray says once that Polytunnel keeps running).
        if ctx.input(|i| i.viewport().close_requested()) {
            self.user_closed = true;
        }
        // Esc, Alt+Left and the mouse's back button go back a page (dialogs take Esc first).
        let nothing_open =
            self.prompt.is_none() && self.confirm.is_none() && self.browser.is_none();
        let back = ctx.input(|i| {
            i.key_pressed(egui::Key::Escape)
                || (i.modifiers.alt && i.key_pressed(egui::Key::ArrowLeft))
                || i.pointer.button_pressed(egui::PointerButton::Extra1)
        });
        if back && nothing_open && ctx.memory(|m| m.focused().is_none()) {
            self.back();
        }
        // Undo for Clear lasts ten seconds.
        if self
            .cleared
            .as_ref()
            .is_some_and(|(_, at)| at.elapsed() > Duration::from_secs(10))
        {
            self.cleared = None;
        }
        // The title bar follows the theme.
        let dark = theme::palette(ctx).dark;
        if self.caption != Some(dark) {
            #[cfg(windows)]
            if color_title_bar(theme::palette(ctx)) {
                self.caption = Some(dark);
            }
            #[cfg(not(windows))]
            {
                self.caption = Some(dark);
            }
        }
        // Back in the window: settings changed elsewhere (Task Manager, another program)
        // show as they are now.
        let focused = ctx.input(|i| i.focused);
        if focused && !self.was_focused {
            self.autostart = autostart::enabled();
            self.link_status = link_status_text();
        }
        self.was_focused = focused;
        // Where the window is, to open it there next time.
        let (outer, inner, scale) = ctx.input(|i| {
            let v = i.viewport();
            (v.outer_rect, v.inner_rect, v.native_pixels_per_point)
        });
        if let (Some(outer), Some(inner)) = (outer, inner) {
            self.place = Some(prefs::WindowPlace {
                x: outer.min.x,
                y: outer.min.y,
                width: inner.width(),
                height: inner.height(),
                scale: scale.unwrap_or(1.0),
            });
        }
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        visuals.panel_fill.to_normalized_gamma_f32()
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let p = theme::palette(ui.ctx());
        if self.page() == &Page::Edit && self.editor.is_none() {
            self.pages.pop();
        }
        let page = self.page().clone();
        let footer = match &page {
            Page::Edit | Page::AddType(_) | Page::Import => true,
            Page::Gateways(name) => self.gateway_switch_target(name).is_some(),
            _ => false,
        };
        if footer {
            egui::Panel::bottom("footer")
                .exact_size(60.0)
                .frame(
                    egui::Frame::NONE
                        .fill(p.bg)
                        .inner_margin(egui::Margin::symmetric(16, 12)),
                )
                .show(ui, |ui| {
                    let r = ui.max_rect();
                    ui.painter().hline(
                        (r.left() - 16.0)..=(r.right() + 16.0),
                        r.top() - 12.0 + 0.5,
                        egui::Stroke::new(1.0, p.line),
                    );
                    match &page {
                        Page::Edit => self.editor_footer(ui),
                        Page::AddType(i) => self.add_type_footer(ui, *i),
                        Page::Import => self.import_footer(ui),
                        Page::Gateways(name) => self.gateways_footer(ui, name),
                        _ => {}
                    }
                });
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(p.bg))
            .show(ui, |ui| match &page {
                Page::Home => self.home_page(ui),
                Page::Profiles => self.profiles_page(ui),
                Page::AddIntegration => self.add_integration_page(ui),
                Page::AddType(i) => self.add_type_page(ui, *i),
                Page::Edit => self.editor_page(ui),
                Page::Gateways(name) => self.gateways_page(ui, name),
                Page::GatewayOrder(name) => self.gateway_order_page(ui, name),
                Page::Import => self.import_page(ui),
                Page::Settings => self.settings_page(ui),
                Page::Activity => self.activity_page(ui),
            });
        let ctx = ui.ctx().clone();
        self.prompts(&ctx);
        self.confirmations(&ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Remember where the window was.
        if let Some(place) = self.place {
            let mut stored = prefs::load();
            stored.window = Some(place);
            let _ = prefs::save(&stored);
        }
        // Closed by the user (not Quit or an update): the tray says once that it keeps
        // running. Sent after saving the place, so the two saves of the preferences don't
        // overlap.
        if self.user_closed && !self.fake {
            let _ = instance::send(Role::Agent, Message::Closed);
        }
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
    fn screenshot_profiles_parse() {
        let profiles = sample_profiles();
        assert_eq!(profiles.profiles.len(), 4);
        for name in ["Work", "Office", "Lab", "Branch"] {
            assert!(profiles.get(name).is_some(), "{name}");
        }
    }

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

        // Certificates trusted with "Always trust" have no field in the form, and are kept.
        let forti = Profile::FortinetSsl(FortinetSslProfile {
            server: "vpn.example.net:10443".into(),
            username: Some("me".into()),
            realm: None,
            server_cert: Some("0123456789abcdef".repeat(4).parse().unwrap()),
            trusted_certs: [(
                "vpn.example.net:10443".to_string(),
                "ab".repeat(32).parse().unwrap(),
            )]
            .into(),
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
    fn connection_changes_are_logged_once() {
        let connected = Ok(Status::Connected {
            profile: "work".into(),
            server: "gw.example.com".into(),
            addresses: vec![],
            transport: "esp".into(),
            since_unix: 0,
            notice: None,
            gateway: None,
            bytes_in: 0,
            bytes_out: 0,
        });
        let reconnecting = Ok(Status::Reconnecting {
            profile: "work".into(),
            server: "gw.example.com".into(),
            attempt: 1,
            since_unix: 0,
        });
        let failed = Ok(Status::Failed {
            profile: "work".into(),
            message: "no answer".into(),
            since_unix: 0,
        });
        assert_eq!(
            change_line(Some(&connected), &reconnecting, false).map(|l| l.0),
            Some(Level::Warning)
        );
        assert_eq!(
            change_line(Some(&reconnecting), &connected, false).map(|l| l.0),
            Some(Level::Good)
        );
        assert_eq!(
            change_line(Some(&connected), &failed, false).map(|l| l.0),
            Some(Level::Problem)
        );
        // The window's own attempt reports its failure itself; no change, no line.
        assert_eq!(change_line(Some(&connected), &failed, true), None);
        assert_eq!(change_line(Some(&connected), &connected, false), None);
        assert_eq!(change_line(None, &connected, false), None);
    }

    #[test]
    fn sizes_and_durations() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(190_840_832), "182 MB");
        assert_eq!(bytes(25_794_560), "24.6 MB");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
        assert_eq!(elapsed(now_unix() - 65), "1:05");
        assert_eq!(elapsed(now_unix() - 3725), "1:02:05");
    }
}
