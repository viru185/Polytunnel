//! The Polytunnel window (egui). It runs only while open and exits completely when closed;
//! the always-on tray agent ([`agent`]) is a separate, tiny process.

pub mod agent;
mod dialogs;
mod icons;
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
    let place = prefs.window.and_then(|place| {
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
    New(Kind),
    /// Back to the profiles.
    Close,
}

/// The window's screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Home,
    Profiles,
    Edit,
    Settings,
    Activity,
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
    screen: Screen,
    prefs: prefs::Prefs,
    /// Where the window is now (saved when it closes).
    place: Option<prefs::WindowPlace>,
    /// The profile opened in the Profiles list.
    expanded: Option<String>,
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
            screen: debug_screen().unwrap_or(Screen::Home),
            prefs,
            place: None,
            expanded: None,
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
        }
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

    /// Leaves the profile form (back to the profiles).
    fn close_editor(&mut self) {
        self.editor = None;
        self.editor_initial = None;
        if self.screen == Screen::Edit {
            self.screen = Screen::Profiles;
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
        let mut stored = prefs::load();
        stored.appearance = self.prefs.appearance;
        stored.notifications = self.prefs.notifications;
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
            Leave::New(kind) => self.open_editor(Editor::new(kind)),
            Leave::Close => self.close_editor(),
        }
    }

    fn open_editor(&mut self, editor: Editor) {
        self.editor_initial = Some(editor.clone());
        self.editor = Some(editor);
        self.screen = Screen::Edit;
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
                        self.log_at(Level::Problem, line);
                    } else if status.is_ok() {
                        self.logged_problem = None;
                    }
                    if let Some((level, line)) =
                        change_line(self.status.as_ref(), &status, self.worker.is_some())
                    {
                        self.log_at(level, line);
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
            }
        }
        while let Ok(job) = self.job_rx.try_recv() {
            self.finish_job(ctx, job);
        }
        let mut finished = false;
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
                            Ok(message) => (Level::Good, message),
                            Err(e) if e == connect::CANCELLED => (Level::Info, "Cancelled.".into()),
                            Err(e) => (Level::Problem, format!("Could not connect: {e}")),
                        });
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
                self.close_editor();
            }
            Err(e) => {
                self.profiles = before;
                self.log(format!("Could not save the profiles: {e}"));
            }
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
                self.close_editor();
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
            .and_then(|()| save_profiles(&self.profiles));
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
        match save_profiles(&self.profiles) {
            Ok(()) => {
                self.log(format!("Deleted the profile '{name}'."));
                self.selected = self.profiles.profiles.keys().next().cloned();
                self.close_editor();
            }
            Err(e) => {
                self.profiles = before;
                self.log(format!("Could not save the profiles: {e}"));
            }
        }
    }
}

/// The bottom bar's tabs.
const NAV: [(Screen, icons::Icon, &str); 4] = [
    (Screen::Home, icons::Icon::Power, "Connect"),
    (Screen::Profiles, icons::Icon::List, "Profiles"),
    (Screen::Activity, icons::Icon::Activity, "Activity"),
    (Screen::Settings, icons::Icon::Gear, "Settings"),
];

/// A debug build can open on a given screen and theme (`POLYTUNNEL_SCREEN`,
/// `POLYTUNNEL_THEME`), for screenshots.
fn debug_screen() -> Option<Screen> {
    if !cfg!(debug_assertions) {
        return None;
    }
    match std::env::var("POLYTUNNEL_SCREEN").ok()?.as_str() {
        "profiles" => Some(Screen::Profiles),
        "settings" => Some(Screen::Settings),
        "activity" => Some(Screen::Activity),
        _ => Some(Screen::Home),
    }
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
                self.selected = Some(name.clone());
                self.screen = Screen::Home;
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
        let bar = egui::Frame::NONE
            .fill(p.surface)
            .inner_margin(egui::Margin::symmetric(6, 4));
        if self.screen == Screen::Edit && self.editor.is_none() {
            self.screen = Screen::Profiles;
        }
        if self.screen == Screen::Edit {
            egui::Panel::bottom("editor-actions")
                .exact_size(56.0)
                .frame(bar.inner_margin(egui::Margin::symmetric(14, 10)))
                .show(ui, |ui| self.editor_footer(ui));
        } else {
            egui::Panel::bottom("nav")
                .exact_size(56.0)
                .frame(bar)
                .show(ui, |ui| {
                    let mut screen = self.screen;
                    widgets::nav_bar(ui, &mut screen, &NAV);
                    self.screen = screen;
                });
        }
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(p.bg)
                    .inner_margin(egui::Margin::symmetric(14, 10)),
            )
            .show(ui, |ui| match self.screen {
                Screen::Home => self.home_screen(ui),
                Screen::Profiles => self.profiles_screen(ui),
                Screen::Edit => self.editor_screen(ui),
                Screen::Settings => self.settings_screen(ui),
                Screen::Activity => self.activity_screen(ui),
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
        assert_eq!(bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
        assert_eq!(elapsed(now_unix() - 65), "1:05");
        assert_eq!(elapsed(now_unix() - 3725), "1:02:05");
    }
}
