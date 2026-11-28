//! The tray agent: a tray icon with no window and no graphics context, so it stays at a few
//! megabytes. It shows the connection state, opens the window, connects and disconnects, and
//! sets the kill switch.

mod glyph;

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use polytunnel_core::ipc::{KillSwitchMode, KillSwitchSettings, Prompt, Status};
use polytunnel_core::profile::{Profile, Profiles};
use tray_icon::menu::{
    CheckMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu,
};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use winit::application::ApplicationHandler;
use winit::event::{StartCause, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::window::WindowId;

use super::notify::{self, Notice};
use super::prefs::{self, Appearance, Prefs};
use crate::connect;
use crate::instance::{self, Instance, Message, Role};

const TITLE: &str = "Polytunnel";
/// Windows cuts tray tooltips at 127 characters.
const TOOLTIP_MAX: usize = 127;
/// Clicks closer together than this open the window once (a double-click is two clicks).
const CLICK_DEBOUNCE: Duration = Duration::from_millis(700);
/// Status polls: often while the service answers, less often while it does not.
const POLL: Duration = Duration::from_secs(3);
const POLL_UNREACHABLE: Duration = Duration::from_secs(10);
/// While busy, the gap in the badge's ring moves on this often.
const FRAME: Duration = Duration::from_millis(400);
/// How often the taskbar's theme and the tray's icon size are checked.
const LOOK_CHECK: Duration = Duration::from_secs(3);
/// How long a window started for the lockdown question has to start listening.
const WINDOW_START: Duration = Duration::from_secs(10);
/// An update that started installing but did not close Polytunnel is given up on after this.
#[cfg_attr(windows, allow(dead_code))]
const INSTALL_TIMEOUT: Duration = Duration::from_secs(600);
/// The kill switch submenu's place in the menu (for its radio marks).
#[cfg(windows)]
const KILLSWITCH_POSITION: i32 = 5;

/// The kill switch as the service reports it: the setting, whether it blocks right now, and
/// why it could not be applied (if it could not).
type KillSwitch = (KillSwitchSettings, bool, Option<String>);

/// The kill switch modes in menu order, with their menu ids and labels.
const KILLSWITCH_MODES: [(KillSwitchMode, &str, &str); 3] = [
    (KillSwitchMode::Off, "killswitch:off", "Off"),
    (
        KillSwitchMode::Connected,
        "killswitch:connected",
        "While connected",
    ),
    (
        KillSwitchMode::Always,
        "killswitch:always",
        "Always (lockdown)",
    ),
];

#[derive(Debug)]
enum UserEvent {
    Tray(TrayIconEvent),
    Menu(MenuEvent),
    Ipc(Message),
    /// A poll: the status, and the kill switch when the service answered.
    Status(Result<Status, String>, Option<KillSwitch>),
    /// The kill switch was set from the menu (or could not be).
    KillSwitchSet(Result<KillSwitch, String>),
    /// The user clicked one of our notifications.
    #[cfg_attr(not(windows), allow(dead_code))]
    NoticeClicked,
    /// An update check finished: the newer version, if any, or what went wrong.
    UpdateChecked(Result<Option<String>, String>),
    /// An installation was started (or could not be).
    UpdateStarted(Result<String, String>),
    /// An installation never closed Polytunnel: offer the check again.
    #[cfg_attr(windows, allow(dead_code))]
    UpdateTimedOut,
}

/// Asks the service whether a newer release exists. The service answers a failed check
/// without a version (and says why), which is not "up to date".
fn check_for_update() -> Result<Option<String>, String> {
    let (current, latest, _, message) = connect::update(false)?;
    match latest {
        Some(latest) => Ok(polytunnel_core::is_newer_version(&latest, &current).then_some(latest)),
        None if message.is_empty() => Err("no answer".into()),
        None => Err(message),
    }
}

type Proxy = Arc<Mutex<EventLoopProxy<UserEvent>>>;

fn forward(proxy: &Proxy, event: UserEvent) {
    if let Ok(proxy) = proxy.lock() {
        let _ = proxy.send_event(event);
    }
}

/// Starts `polytunnelw` (or this program) with `args`, without a console window.
fn spawn_gui(args: &[&str]) {
    if let Some(exe) = crate::paths::gui_program() {
        let mut command = Command::new(exe);
        command.args(args);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        let _ = command.spawn();
    }
}

/// Starts the tray agent in the background unless it already runs.
pub fn ensure_running() {
    if !instance::is_running(Role::Agent) {
        spawn_gui(&["tray"]);
    }
}

/// After an update starts installing: opens the tray again from the new files once the
/// installer is done. The installer replaces this program, so it waits in `cmd`, not here.
#[cfg(windows)]
pub fn reopen_after_update() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let Some(gui) = crate::paths::gui_program() else {
        return;
    };
    let mut command = Command::new("cmd");
    command.raw_arg(format!(
        "/c ping -n 91 127.0.0.1 >nul & start \"\" \"{}\" tray",
        gui.display()
    ));
    command.creation_flags(CREATE_NO_WINDOW);
    let _ = command.spawn();
}

/// Makes the tray's menu follow the appearance setting: dark with Dark, light with Light, and
/// the system's apps theme otherwise (uxtheme's `SetPreferredAppMode`, ordinal 135, then
/// `FlushMenuThemes`, ordinal 136; Windows 10 1903 and later). Elsewhere: nothing.
#[cfg(windows)]
fn set_menu_theme(appearance: Appearance) {
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    };
    type SetPreferredAppMode = unsafe extern "system" fn(i32) -> i32;
    type FlushMenuThemes = unsafe extern "system" fn();
    let mode = match appearance {
        Appearance::System => 1, // allow dark
        Appearance::Dark => 2,   // force dark
        Appearance::Light => 3,  // force light
    };
    let name: Vec<u16> = "uxtheme.dll\0".encode_utf16().collect();
    // SAFETY: a NUL-terminated name, loaded from System32 only; the two exports are looked up
    // by ordinal and only called when present, with the signatures they have.
    unsafe {
        let module = LoadLibraryExW(
            name.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        );
        if module.is_null() {
            return;
        }
        let set = GetProcAddress(module, 135usize as *const u8);
        let flush = GetProcAddress(module, 136usize as *const u8);
        if let (Some(set), Some(flush)) = (set, flush) {
            let set: SetPreferredAppMode = std::mem::transmute(set);
            let flush: FlushMenuThemes = std::mem::transmute(flush);
            set(mode);
            flush();
        }
    }
}

#[cfg(not(windows))]
fn set_menu_theme(_appearance: Appearance) {}

/// Windows menu touches muda has no API for: "Open Polytunnel" (the first item) is the default
/// item, shown bold, and the kill switch modes get radio marks instead of check marks.
#[cfg(windows)]
fn style_menu(menu: &Menu) {
    use tray_icon::menu::ContextMenu;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetSubMenu, HMENU, MENUITEMINFOW, MFT_RADIOCHECK, MIIM_FTYPE, SetMenuDefaultItem,
        SetMenuItemInfoW,
    };
    let hmenu = menu.hpopupmenu() as HMENU;
    // SAFETY: `hmenu` is the menu's live popup handle (valid while `menu` is); the item info is
    // fully initialised and only sets the item type.
    unsafe {
        SetMenuDefaultItem(hmenu, 0, 1);
        let modes = GetSubMenu(hmenu, KILLSWITCH_POSITION);
        if modes.is_null() {
            return;
        }
        for position in 0..KILLSWITCH_MODES.len() as u32 {
            let mut info: MENUITEMINFOW = std::mem::zeroed();
            info.cbSize = size_of::<MENUITEMINFOW>() as u32;
            info.fMask = MIIM_FTYPE;
            info.fType = MFT_RADIOCHECK;
            SetMenuItemInfoW(modes, position, 1, &info);
        }
    }
}

/// The profiles file's names, in order (none when it is missing or unreadable).
fn profile_names() -> Vec<String> {
    read_profiles()
        .map(|p| p.profiles.keys().cloned().collect())
        .unwrap_or_default()
}

fn read_profiles() -> Option<Profiles> {
    let text = std::fs::read_to_string(crate::paths::profiles_file()?).ok()?;
    Profiles::parse(&text).ok()
}

fn profiles_changed_at() -> Option<SystemTime> {
    crate::paths::profiles_file()
        .and_then(|f| std::fs::metadata(f).ok())
        .and_then(|m| m.modified().ok())
}

/// What the portal calls the gateway `server` of `profile` ("US East"), from the gateway list
/// cached at the last sign-in, when it names it.
fn gateway_name(profile: &str, server: &str) -> Option<String> {
    let profiles = read_profiles()?;
    let Profile::GlobalProtect(gp) = profiles.get(profile)? else {
        return None;
    };
    let host = polytunnel_gp::portal::host_of(server);
    crate::gateways::load_cache(&gp.portal)?
        .gateways
        .into_iter()
        .find(|g| g.host().eq_ignore_ascii_case(host))
        .and_then(|g| g.description)
        .filter(|name| !name.trim().is_empty())
}

/// The "Connect to" entries: (menu id, label, checked) for each profile, given the connection
/// that is on (if any).
fn connect_entries(names: &[String], active: Option<&str>) -> Vec<(String, String, bool)> {
    names
        .iter()
        .map(|name| {
            (
                format!("connect:{name}"),
                name.clone(),
                active == Some(name.as_str()),
            )
        })
        .collect()
}

/// The profile "Connect" uses: the last one the tray saw in use while it still exists, else
/// the first (the window's default).
fn connect_target(names: &[String], last: Option<&str>) -> Option<String> {
    last.filter(|last| names.iter().any(|n| n == last))
        .map(str::to_string)
        .or_else(|| names.first().cloned())
}

/// The profile a status is about, if any.
fn profile_of(status: &Status) -> Option<&str> {
    match status {
        Status::Idle {} => None,
        Status::Connecting { profile }
        | Status::NeedsInput { profile, .. }
        | Status::Connected { profile, .. }
        | Status::Reconnecting { profile, .. }
        | Status::Disconnecting { profile }
        | Status::Failed { profile, .. } => Some(profile),
    }
}

/// The connection that is on or on its way.
fn active_profile(status: &Result<Status, String>) -> Option<&str> {
    match status {
        Ok(
            Status::Connected { profile, .. }
            | Status::Connecting { profile }
            | Status::NeedsInput { profile, .. }
            | Status::Reconnecting { profile, .. },
        ) => Some(profile),
        _ => None,
    }
}

/// Does the kill switch hold internet traffic while no connection is up: lockdown while not
/// connected, or a "while connected" block kept after a connection dropped and failed?
fn blocked(status: &Status, killswitch: Option<&KillSwitch>) -> bool {
    let Some((settings, true, None)) = killswitch else {
        return false;
    };
    match status {
        Status::Idle {} => settings.mode != KillSwitchMode::Off,
        Status::Failed { .. } => settings.mode == KillSwitchMode::Connected,
        _ => false,
    }
}

/// A "while connected" block kept after a connection dropped (not lockdown, which the user
/// chose).
fn held(status: &Status, killswitch: Option<&KillSwitch>) -> bool {
    blocked(status, killswitch)
        && killswitch.is_some_and(|(s, ..)| s.mode == KillSwitchMode::Connected)
}

/// What the icon shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Look {
    /// Not connected: the arch alone.
    Idle,
    /// Connecting, reconnecting, waiting for the user or disconnecting: an amber ring that
    /// turns.
    Busy,
    /// Connected: a green dot.
    Connected,
    /// Connected, but the gateway limited the connection: an amber dot.
    Limited,
    /// No connection and the kill switch holds traffic: an amber square.
    Blocked,
    /// The connection failed, or the service cannot be reached: a red square.
    Problem,
}

impl Look {
    /// The badge for this look (`frame`: the busy ring's step).
    fn badge(self, frame: u8) -> (glyph::Badge, glyph::Tone) {
        use glyph::{Badge, Tone};
        match self {
            Look::Idle => (Badge::None, Tone::Green),
            Look::Busy => (Badge::Ring(frame % 3), Tone::Amber),
            Look::Connected => (Badge::Dot, Tone::Green),
            Look::Limited => (Badge::Dot, Tone::Amber),
            Look::Blocked => (Badge::Square, Tone::Amber),
            Look::Problem => (Badge::Square, Tone::Red),
        }
    }
}

fn look(status: &Result<Status, String>, killswitch: Option<&KillSwitch>) -> Look {
    match status {
        Ok(s) if blocked(s, killswitch) => Look::Blocked,
        Ok(Status::Idle {}) => Look::Idle,
        Ok(Status::Connected { notice: None, .. }) => Look::Connected,
        Ok(Status::Connected { .. }) => Look::Limited,
        Ok(
            Status::Connecting { .. }
            | Status::NeedsInput { .. }
            | Status::Reconnecting { .. }
            | Status::Disconnecting { .. },
        ) => Look::Busy,
        Ok(Status::Failed { .. }) | Err(_) => Look::Problem,
    }
}

/// Is a connection on or on its way (so Quit has something to stop)?
fn active(status: &Result<Status, String>) -> bool {
    active_profile(status).is_some()
}

/// What a sign-in prompt asks for: "a code", "a password" or "your sign-in".
fn wanted(prompt: &Prompt) -> &'static str {
    let mut words: Vec<String> = prompt
        .fields
        .iter()
        .map(|f| f.label.to_lowercase())
        .collect();
    if words.is_empty() {
        words.extend(prompt.message.as_deref().map(str::to_lowercase));
    }
    let any = |keys: &[&str]| words.iter().any(|w| keys.iter().any(|k| w.contains(k)));
    if any(&["code", "otp", "token"]) {
        "a code"
    } else if any(&["password"]) {
        "a password"
    } else {
        "your sign-in"
    }
}

/// `h:mm` since `since_unix` (none when it is not known).
fn elapsed(since_unix: u64, now_unix: u64) -> Option<String> {
    (since_unix != 0).then(|| {
        let minutes = now_unix.saturating_sub(since_unix) / 60;
        format!("{}:{:02}", minutes / 60, minutes % 60)
    })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The menu's status line: "Connected to Work · 1:42", "Not connected", ...
fn status_line(
    status: &Result<Status, String>,
    killswitch: Option<&KillSwitch>,
    now_unix: u64,
) -> String {
    match status {
        Err(e) if e.contains("protocol version") => "Polytunnel was updated: reopen it".into(),
        Err(e) if e.contains("cannot reach the Polytunnel service") => "Service stopped".into(),
        Err(_) => "Service not answering".into(),
        Ok(s) if blocked(s, killswitch) => "Internet blocked".into(),
        Ok(Status::Idle {}) => "Not connected".into(),
        Ok(Status::Connecting { profile }) => format!("Connecting to {profile}…"),
        Ok(Status::NeedsInput { profile, prompt }) => {
            format!("Waiting for you · {profile} needs {}", wanted(prompt))
        }
        Ok(Status::Connected {
            profile,
            since_unix,
            notice,
            ..
        }) => {
            let what = match notice {
                None => format!("Connected to {profile}"),
                Some(_) => format!("Connected to {profile} with limits"),
            };
            match elapsed(*since_unix, now_unix) {
                Some(time) => format!("{what} · {time}"),
                None => what,
            }
        }
        Ok(Status::Reconnecting {
            profile, attempt, ..
        }) => format!("Reconnecting to {profile} · try {attempt}"),
        Ok(Status::Disconnecting { profile }) => format!("Disconnecting from {profile}…"),
        Ok(Status::Failed { .. }) => "Couldn't connect".into(),
    }
}

/// What the menu's main item does.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    Disconnect,
    Connect(String),
    Nothing,
}

/// The menu's main item: its label and what it does (`target`: the profile Connect uses).
fn primary(status: &Result<Status, String>, target: Option<&str>) -> (String, Action) {
    let connect = || match target {
        Some(name) => (format!("Connect {name}"), Action::Connect(name.to_string())),
        None => ("Connect".to_string(), Action::Nothing),
    };
    match status {
        Ok(Status::Connected { profile, .. } | Status::Reconnecting { profile, .. }) => {
            (format!("Disconnect {profile}"), Action::Disconnect)
        }
        Ok(Status::Connecting { .. } | Status::NeedsInput { .. }) => {
            ("Cancel connecting".into(), Action::Disconnect)
        }
        Ok(Status::Disconnecting { .. }) => ("Disconnecting…".into(), Action::Nothing),
        Ok(Status::Idle {} | Status::Failed { .. }) => connect(),
        // The service cannot connect anything now.
        Err(_) => (connect().0, Action::Nothing),
    }
}

/// `Polytunnel – <text>`, cut to what Windows shows.
fn tooltip(text: &str) -> String {
    let full = format!("{TITLE} – {text}");
    if full.chars().count() <= TOOLTIP_MAX {
        return full;
    }
    let mut cut: String = full.chars().take(TOOLTIP_MAX - 1).collect();
    cut.push('…');
    cut
}

/// The taskbar's theme (true: light) and the tray's icon size in pixels.
#[cfg(windows)]
fn taskbar() -> (bool, u32) {
    (
        crate::win::taskbar_is_light(),
        crate::win::small_icon_size(),
    )
}

#[cfg(not(windows))]
fn taskbar() -> (bool, u32) {
    (false, 32)
}

pub fn run() -> i32 {
    #[cfg(windows)]
    crate::win::hide_own_console();
    let instance = match instance::claim(Role::Agent) {
        Ok(Some(instance)) => instance,
        Ok(None) => return 0,
        Err(e) => {
            crate::applog::write("WARN", &format!("cannot start the tray icon: {e}"));
            return 1;
        }
    };
    // A sign-in entry left by an older version starts this one from now on.
    crate::autostart::refresh();

    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut builder = EventLoop::<UserEvent>::with_user_event();
    #[cfg(target_os = "macos")]
    {
        use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
        builder.with_activation_policy(ActivationPolicy::Accessory);
    }
    let event_loop = match builder.build() {
        Ok(event_loop) => event_loop,
        Err(e) => {
            crate::applog::write("WARN", &format!("cannot start the tray icon: {e}"));
            return 1;
        }
    };
    event_loop.set_control_flow(ControlFlow::Wait);
    let proxy: Proxy = Arc::new(Mutex::new(event_loop.create_proxy()));

    let p = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |e| forward(&p, UserEvent::Tray(e))));
    let p = proxy.clone();
    MenuEvent::set_event_handler(Some(Arc::new(move |e| forward(&p, UserEvent::Menu(e)))));
    let p = proxy.clone();
    if let Err(e) = instance.listen(Role::Agent, move |m| forward(&p, UserEvent::Ipc(m))) {
        crate::applog::write("WARN", &format!("tray IPC unavailable: {e}"));
    }
    if std::env::var_os("POLYTUNNEL_NO_UPDATE_CHECK").is_none() {
        let p = proxy.clone();
        thread::Builder::new()
            .name("tray-updates".into())
            .spawn(move || {
                thread::sleep(Duration::from_secs(120));
                loop {
                    // Only offers; nothing is downloaded without a click.
                    if let Ok(Some(v)) = check_for_update() {
                        forward(&p, UserEvent::UpdateChecked(Ok(Some(v))));
                    }
                    thread::sleep(Duration::from_secs(24 * 3600));
                }
            })
            .ok();
    }
    let p = proxy.clone();
    thread::Builder::new()
        .name("tray-status".into())
        .spawn(move || {
            loop {
                let status = connect::status();
                // The kill switch decides between "not connected" and "internet blocked".
                let killswitch = status
                    .as_ref()
                    .ok()
                    .and_then(|_| connect::killswitch(None).ok());
                let wait = if status.is_ok() {
                    POLL
                } else {
                    POLL_UNREACHABLE
                };
                forward(&p, UserEvent::Status(status, killswitch));
                thread::sleep(wait);
            }
        })
        .ok();

    let prefs = prefs::load();
    set_menu_theme(prefs.appearance);
    let (light_taskbar, icon_size) = taskbar();
    let mut agent = Agent {
        tray: None,
        connect_menu: Submenu::new("Connect to", true),
        connect_items: Vec::new(),
        killswitch_menu: Submenu::new("Kill switch", true),
        killswitch_items: KILLSWITCH_MODES.map(|(_, id, label)| {
            CheckMenuItem::with_id(MenuId::new(id), label, false, false, None)
        }),
        profiles: None,
        status: None,
        killswitch: None,
        killswitch_busy: false,
        last_profile: None,
        last_status: None,
        prefs,
        prefs_seen: prefs::changed_at(),
        close_hint_said: false,
        click_opens: true,
        icon_gone: false,
        guid: std::env::current_exe()
            .map(|e| notify::tray_guid(&e.display().to_string()))
            .unwrap_or(0x5054_554e_4e45_4c00_8000_4000_0000_0001),
        status_item: MenuItem::new("Checking…", false, None),
        primary_item: MenuItem::with_id(MenuId::new("primary"), "Connect", false, None),
        primary_action: Action::Nothing,
        update_item: MenuItem::with_id(MenuId::new("update"), "Check for updates", true, None),
        available: None,
        proxy: proxy.clone(),
        open_id: MenuId::new("open"),
        quit_id: MenuId::new("quit"),
        look: Look::Idle,
        frame: 0,
        next_frame: None,
        light_taskbar,
        icon_size,
        next_look_check: Instant::now() + LOOK_CHECK,
        drawn: None,
        last_open: None,
        _instance: instance,
    };
    match event_loop.run_app(&mut agent) {
        Ok(()) => 0,
        Err(e) => {
            crate::applog::write("WARN", &format!("the tray stopped: {e}"));
            1
        }
    }
}

struct Agent {
    tray: Option<TrayIcon>,
    /// "Connect to ▸": one entry per profile, the one in use checked.
    connect_menu: Submenu,
    connect_items: Vec<(String, CheckMenuItem)>,
    /// "Kill switch ▸": Off, While connected, Always (lockdown), as radio items.
    killswitch_menu: Submenu,
    killswitch_items: [CheckMenuItem; 3],
    /// The profile names, and the profiles file's time they were read at.
    profiles: Option<(Option<SystemTime>, Vec<String>)>,
    /// The last poll's status and kill switch.
    status: Option<Result<Status, String>>,
    killswitch: Option<KillSwitch>,
    /// A kill switch change is on its way to the service.
    killswitch_busy: bool,
    /// The last profile seen in a status (Connect uses it again).
    last_profile: Option<String>,
    /// The last status the service answered, to notice changes worth a notification.
    last_status: Option<Status>,
    prefs: Prefs,
    prefs_seen: Option<SystemTime>,
    /// "Still running" was said in this run (in case it cannot be saved).
    close_hint_said: bool,
    /// Clicking the last notification opens the window.
    click_opens: bool,
    /// The tray icon's GUID (notifications are sent to it).
    #[cfg_attr(not(windows), allow(dead_code))]
    guid: u128,
    /// The tray icon's window was destroyed (an installer closing Polytunnel does that): the
    /// icon is gone, so this process ends and a fresh tray can start.
    icon_gone: bool,
    status_item: MenuItem,
    primary_item: MenuItem,
    primary_action: Action,
    update_item: MenuItem,
    /// A newer release found by the last check.
    available: Option<String>,
    proxy: Proxy,
    open_id: MenuId,
    quit_id: MenuId,
    look: Look,
    /// The busy ring's step, and when it moves on (while busy).
    frame: u8,
    next_frame: Option<Instant>,
    /// The taskbar is light; the tray's icon size in pixels; when to check them again.
    light_taskbar: bool,
    icon_size: u32,
    next_look_check: Instant,
    /// What the icon shows now: look, ring step, light taskbar, size.
    drawn: Option<(Look, u8, bool, u32)>,
    last_open: Option<Instant>,
    _instance: Instance,
}

impl Agent {
    fn init(&mut self) {
        let menu = Menu::new();
        let open = MenuItem::with_id(self.open_id.clone(), "Open Polytunnel", true, None);
        let quit = MenuItem::with_id(self.quit_id.clone(), "Quit Polytunnel", true, None);
        for item in &self.killswitch_items {
            let _ = self.killswitch_menu.append(item);
        }
        // The kill switch submenu must stay at KILLSWITCH_POSITION.
        let _ = menu.append_items(&[
            &open,
            &self.status_item,
            &PredefinedMenuItem::separator(),
            &self.primary_item,
            &self.connect_menu,
            &self.killswitch_menu,
            &PredefinedMenuItem::separator(),
            &self.update_item,
            &quit,
        ]);
        #[cfg(windows)]
        style_menu(&menu);
        let (light, size) = (self.light_taskbar, self.icon_size);
        let (badge, tone) = Look::Idle.badge(0);
        let icon = Icon::from_rgba(glyph::render(size, light, badge, tone), size, size)
            .expect("the drawn glyph is a valid icon");
        let builder = TrayIconBuilder::new();
        #[cfg(windows)]
        let builder = builder.with_guid(self.guid);
        match builder
            .with_menu(Box::new(menu))
            .with_tooltip(TITLE)
            .with_icon(icon)
            .with_menu_on_left_click(false)
            .build()
        {
            Ok(tray) => self.tray = Some(tray),
            Err(e) => crate::applog::write("WARN", &format!("cannot create the tray icon: {e}")),
        }
        #[cfg(windows)]
        if let Some(tray) = &self.tray {
            let p = self.proxy.clone();
            notify::on_click(tray.window_handle(), move || {
                forward(&p, UserEvent::NoticeClicked);
            });
        }
        self.drawn = Some((Look::Idle, 0, light, size));
    }

    /// The profile names, read again when the profiles file changed.
    fn names(&mut self) -> &[String] {
        let changed = profiles_changed_at();
        if self.profiles.as_ref().is_none_or(|(at, _)| *at != changed) {
            self.profiles = Some((changed, profile_names()));
        }
        match &self.profiles {
            Some((_, names)) => names,
            None => &[],
        }
    }

    /// Rebuilds "Connect to" when the profiles changed, and checks the profile in use.
    fn refresh_connect_menu(&mut self, active: Option<&str>) {
        let names = self.names().to_vec();
        if self.connect_items.len() != names.len()
            || self
                .connect_items
                .iter()
                .zip(&names)
                .any(|((n, _), m)| n != m)
            || (names.is_empty() && self.connect_menu.items().is_empty())
        {
            while self.connect_menu.remove_at(0).is_some() {}
            self.connect_items.clear();
            if names.is_empty() {
                let _ = self
                    .connect_menu
                    .append(&MenuItem::new("No profiles yet", false, None));
            }
            for (id, label, _) in connect_entries(&names, None) {
                let item =
                    CheckMenuItem::with_id(MenuId::new(id), label.clone(), true, false, None);
                let _ = self.connect_menu.append(&item);
                self.connect_items.push((label, item));
            }
        }
        for (name, item) in &self.connect_items {
            item.set_checked(active == Some(name.as_str()));
        }
    }

    /// Checks the kill switch's mode (clicks toggle check items; this puts them right).
    fn refresh_killswitch_menu(&self) {
        let mode = self.killswitch.as_ref().map(|(s, ..)| s.mode);
        for (item, (m, ..)) in self.killswitch_items.iter().zip(KILLSWITCH_MODES) {
            item.set_checked(mode == Some(m));
            item.set_enabled(mode.is_some() && !self.killswitch_busy);
        }
    }

    /// Shows a notification (Windows; elsewhere nothing). `opens`: clicking it opens the
    /// window.
    fn show_notice(&mut self, notice: &Notice, opens: bool) {
        self.click_opens = opens;
        #[cfg(windows)]
        if let Some(tray) = &self.tray {
            notify::show(tray.window_handle(), self.guid, notice);
        }
        #[cfg(not(windows))]
        let _ = notice;
    }

    /// Announces a change of the connection: problems always, news when notifications are
    /// on.
    fn notify_change(&mut self, status: &Result<Status, String>) {
        let Ok(now) = status else {
            self.last_status = None;
            return;
        };
        // The gateway's name is looked up only for a "connected" notification.
        let place = match (&self.last_status, now) {
            (Some(Status::Connected { profile: was, .. }), Status::Connected { profile, .. })
                if was == profile =>
            {
                None
            }
            (
                Some(_),
                Status::Connected {
                    profile, server, ..
                },
            ) => gateway_name(profile, server),
            _ => None,
        };
        let killswitch = self.killswitch.as_ref();
        let context = notify::Context {
            killswitch_on: killswitch.is_some_and(|(s, ..)| s.mode != KillSwitchMode::Off),
            held: held(now, killswitch),
            place: place.as_deref(),
        };
        if let Some(notice) = notify::notice_for(self.last_status.as_ref(), now, &context)
            && (notice.is_problem() || self.prefs.notifications)
        {
            self.show_notice(&notice, true);
        }
        self.last_status = Some(now.clone());
    }

    /// The window was closed while the tray runs: says once, ever, that Polytunnel keeps
    /// running.
    fn window_closed(&mut self) {
        if self.close_hint_said {
            return;
        }
        let mut stored = prefs::load();
        if stored.close_hint_shown {
            return;
        }
        stored.close_hint_shown = true;
        if let Err(e) = prefs::save(&stored) {
            crate::applog::write("WARN", &format!("cannot save the preferences: {e}"));
        }
        self.prefs = stored;
        self.prefs_seen = prefs::changed_at();
        self.close_hint_said = true;
        self.show_notice(&notify::still_running(), false);
    }

    /// Picks up preferences the window changed (appearance, notifications).
    fn refresh_prefs(&mut self) {
        let seen = prefs::changed_at();
        if seen != self.prefs_seen {
            self.prefs_seen = seen;
            self.prefs = prefs::load();
        }
        // Also follows a change of the system theme.
        set_menu_theme(self.prefs.appearance);
    }

    /// Connects with `name` through the window (which asks for passwords and codes).
    fn connect_profile(&mut self, name: String) {
        if !instance::valid_profile_name(&name) {
            return;
        }
        if instance::send(Role::Gui, Message::Connect(name.clone())).is_err() {
            spawn_gui(&["connect", &name]);
        }
    }

    /// Lockdown is never turned on from here: the window opens on Settings and asks first
    /// (started when it is not running, then told once it listens).
    fn ask_lockdown(&mut self) {
        if instance::send(Role::Gui, Message::Lockdown).is_ok() {
            return;
        }
        spawn_gui(&[]);
        thread::spawn(|| {
            let started = Instant::now();
            while started.elapsed() < WINDOW_START {
                thread::sleep(Duration::from_millis(250));
                if instance::send(Role::Gui, Message::Lockdown).is_ok() {
                    return;
                }
            }
            crate::applog::write("WARN", "the window did not start to confirm lockdown");
        });
    }

    /// A kill switch mode was picked from the menu.
    fn killswitch_clicked(&mut self, mode: KillSwitchMode) {
        // A click toggles the item's mark: put the marks back until the service answers.
        self.refresh_killswitch_menu();
        let Some((settings, ..)) = self.killswitch.clone() else {
            return;
        };
        if settings.mode == mode || self.killswitch_busy {
            return;
        }
        if mode == KillSwitchMode::Always {
            self.ask_lockdown();
            return;
        }
        self.killswitch_busy = true;
        self.refresh_killswitch_menu();
        let set = KillSwitchSettings { mode, ..settings };
        let p = self.proxy.clone();
        thread::spawn(move || {
            forward(&p, UserEvent::KillSwitchSet(connect::killswitch(Some(set))));
        });
    }

    fn update(&mut self, status: Result<Status, String>, killswitch: Option<KillSwitch>) {
        #[cfg(windows)]
        if let Some(tray) = &self.tray {
            use windows_sys::Win32::UI::WindowsAndMessaging::IsWindow;
            // SAFETY: IsWindow accepts any handle value.
            if unsafe { IsWindow(tray.window_handle()) } == 0 {
                self.icon_gone = true;
                return;
            }
        }
        self.refresh_prefs();
        // The kill switch first: a dropped connection's notification depends on it.
        if !self.killswitch_busy {
            self.killswitch = killswitch;
        }
        self.notify_change(&status);
        if let Some(profile) = status.as_ref().ok().and_then(profile_of) {
            self.last_profile = Some(profile.to_string());
        }
        self.status = Some(status);
        self.show_state();
    }

    /// Puts the last status into the menu, the tooltip and the icon.
    fn show_state(&mut self) {
        let Some(status) = self.status.clone() else {
            return;
        };
        let killswitch = self.killswitch.clone();
        self.refresh_connect_menu(active_profile(&status));
        self.refresh_killswitch_menu();
        let names = self.names().to_vec();
        let target = connect_target(&names, self.last_profile.as_deref());
        let (label, action) = primary(&status, target.as_deref());
        self.primary_item.set_text(label);
        self.primary_item.set_enabled(action != Action::Nothing);
        self.primary_action = action;
        let text = status_line(&status, killswitch.as_ref(), now_unix());
        self.status_item.set_text(&text);
        if let Some(tray) = &self.tray {
            let _ = tray.set_tooltip(Some(tooltip(&text)));
        }
        let look = look(&status, killswitch.as_ref());
        if look != self.look {
            self.look = look;
            self.frame = 0;
            self.next_frame = (look == Look::Busy).then(|| Instant::now() + FRAME);
        }
        self.redraw_icon();
    }

    /// Draws the icon again when what it shows changed.
    fn redraw_icon(&mut self) {
        let frame = if self.look == Look::Busy {
            self.frame
        } else {
            0
        };
        let key = (self.look, frame, self.light_taskbar, self.icon_size);
        if self.drawn == Some(key) {
            return;
        }
        let Some(tray) = &self.tray else {
            return;
        };
        let (badge, tone) = self.look.badge(frame);
        let size = self.icon_size;
        let rgba = glyph::render(size, self.light_taskbar, badge, tone);
        match Icon::from_rgba(rgba, size, size) {
            Ok(icon) => {
                let _ = tray.set_icon(Some(icon));
                self.drawn = Some(key);
            }
            Err(e) => crate::applog::write("WARN", &format!("cannot draw the tray icon: {e}")),
        }
    }

    /// Moves the busy ring on, and follows the taskbar's theme and the tray's size.
    fn tick(&mut self) {
        let now = Instant::now();
        if self.next_frame.is_some_and(|at| now >= at) {
            self.frame = (self.frame + 1) % 3;
            self.next_frame = Some(now + FRAME);
            self.redraw_icon();
        }
        if now >= self.next_look_check {
            self.next_look_check = now + LOOK_CHECK;
            (self.light_taskbar, self.icon_size) = taskbar();
            self.redraw_icon();
        }
    }

    /// Checks for an update, or installs the one found.
    fn update_clicked(&mut self) {
        self.update_item.set_enabled(false);
        let p = self.proxy.clone();
        let install = self.available.is_some();
        thread::spawn(move || {
            let event = if install {
                UserEvent::UpdateStarted(connect::update(true).and_then(
                    |(_, _, installing, message)| {
                        if installing {
                            Ok(message)
                        } else {
                            Err(message)
                        }
                    },
                ))
            } else {
                UserEvent::UpdateChecked(check_for_update())
            };
            forward(&p, event);
        });
    }

    fn open_window(&mut self) {
        let now = Instant::now();
        if self
            .last_open
            .is_some_and(|last| now.duration_since(last) < CLICK_DEBOUNCE)
        {
            return;
        }
        self.last_open = Some(now);
        if instance::send(Role::Gui, Message::Show).is_err() {
            spawn_gui(&[]);
        }
    }

    fn menu_clicked(&mut self, event_loop: &ActiveEventLoop, id: &MenuId) {
        if *id == self.quit_id {
            self.quit(event_loop);
        } else if *id == self.open_id {
            self.last_open = None;
            self.open_window();
        } else if id == self.primary_item.id() {
            match self.primary_action.clone() {
                Action::Disconnect => {
                    let _ = connect::disconnect();
                }
                Action::Connect(name) => self.connect_profile(name),
                Action::Nothing => {}
            }
        } else if id == self.update_item.id() {
            self.update_clicked();
        } else if let Some(name) = id.0.strip_prefix("connect:") {
            let active = self
                .status
                .as_ref()
                .and_then(active_profile)
                .map(str::to_string);
            // A click toggles the mark: the profile in use stays checked, nothing else is.
            self.refresh_connect_menu(active.as_deref());
            if active.as_deref() != Some(name) {
                self.connect_profile(name.to_string());
            }
        } else if let Some((mode, ..)) = KILLSWITCH_MODES.iter().find(|(_, m, _)| id.0 == *m) {
            self.killswitch_clicked(*mode);
        }
    }

    /// Quit: ends the connection, closes the window and removes the icon, so nothing keeps
    /// running unseen.
    fn quit(&mut self, event_loop: &ActiveEventLoop) {
        if self.status.as_ref().is_some_and(active) {
            let _ = connect::disconnect();
        }
        let _ = instance::send(Role::Gui, Message::Quit);
        event_loop.exit();
    }
}

impl ApplicationHandler<UserEvent> for Agent {
    fn new_events(&mut self, _event_loop: &ActiveEventLoop, cause: StartCause) {
        if matches!(cause, StartCause::Init) {
            self.init();
        }
    }

    fn resumed(&mut self, _event_loop: &ActiveEventLoop) {}

    fn window_event(&mut self, _: &ActiveEventLoop, _: WindowId, _: WindowEvent) {}

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        self.tick();
        let next = match self.next_frame {
            Some(frame) => frame.min(self.next_look_check),
            None => self.next_look_check,
        };
        event_loop.set_control_flow(ControlFlow::WaitUntil(next));
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::Tray(TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            }) => self.open_window(),
            UserEvent::Tray(_) => {}
            UserEvent::Menu(e) => self.menu_clicked(event_loop, &e.id),
            UserEvent::NoticeClicked => {
                if self.click_opens {
                    self.last_open = None;
                    self.open_window();
                }
            }
            UserEvent::KillSwitchSet(result) => {
                self.killswitch_busy = false;
                match result {
                    Ok(state) => self.killswitch = Some(state),
                    Err(e) => {
                        crate::applog::write("WARN", &format!("cannot set the kill switch: {e}"));
                        let notice = Notice {
                            kind: notify::Kind::Error,
                            title: "Couldn't change the kill switch".into(),
                            text: notify::short_reason(&e),
                        };
                        self.show_notice(&notice, true);
                    }
                }
                self.show_state();
            }
            UserEvent::UpdateChecked(result) => {
                self.update_item.set_enabled(true);
                match result {
                    // Linux packages update through the system's package manager.
                    Ok(Some(version)) if cfg!(target_os = "linux") => {
                        self.update_item
                            .set_text(format!("Polytunnel {version} is available"));
                        self.update_item.set_enabled(false);
                    }
                    Ok(Some(version)) => {
                        self.update_item
                            .set_text(format!("Install Polytunnel {version}"));
                        self.available = Some(version);
                    }
                    Ok(None) => self.update_item.set_text("Polytunnel is up to date"),
                    Err(_) => self.update_item.set_text("Could not check for updates"),
                }
            }
            UserEvent::UpdateStarted(Ok(_)) => {
                self.available = None;
                // The installer replaces Polytunnel's files: close the window and the icon,
                // and come back once it is done.
                #[cfg(windows)]
                {
                    reopen_after_update();
                    let _ = instance::send(Role::Gui, Message::Quit);
                    event_loop.exit();
                }
                #[cfg(not(windows))]
                {
                    self.update_item.set_text("Installing the update…");
                    let p = self.proxy.clone();
                    thread::spawn(move || {
                        thread::sleep(INSTALL_TIMEOUT);
                        forward(&p, UserEvent::UpdateTimedOut);
                    });
                }
            }
            UserEvent::UpdateStarted(Err(_)) => {
                self.available = None;
                self.update_item.set_enabled(true);
                self.update_item.set_text("The update could not start");
            }
            UserEvent::UpdateTimedOut => {
                self.update_item.set_enabled(true);
                self.update_item.set_text("Check for updates");
            }
            UserEvent::Ipc(Message::Quit) => self.quit(event_loop),
            UserEvent::Ipc(Message::Show) => {
                self.last_open = None;
                self.open_window();
            }
            UserEvent::Ipc(Message::Connect(name)) => self.connect_profile(name),
            UserEvent::Ipc(Message::Lockdown) => self.ask_lockdown(),
            UserEvent::Ipc(Message::Closed) => self.window_closed(),
            UserEvent::Status(status, killswitch) => {
                self.update(status, killswitch);
                if self.icon_gone {
                    crate::applog::write("INFO", "the tray icon's window was closed; exiting");
                    event_loop.exit();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polytunnel_core::ipc::PromptField;

    fn connected(notice: Option<&str>) -> Status {
        Status::Connected {
            profile: "Work".into(),
            server: "gw.example.com".into(),
            addresses: vec!["10.0.0.2".into()],
            transport: "esp".into(),
            since_unix: 1_000,
            notice: notice.map(str::to_string),
            gateway: None,
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    fn asking(labels: &[&str]) -> Status {
        Status::NeedsInput {
            profile: "Office".into(),
            prompt: Prompt {
                id: 1,
                message: None,
                fields: labels
                    .iter()
                    .map(|l| PromptField {
                        label: l.to_string(),
                        secret: true,
                    })
                    .collect(),
            },
        }
    }

    fn failed() -> Status {
        Status::Failed {
            profile: "Work".into(),
            message: "no answer".into(),
            since_unix: 0,
        }
    }

    fn ks(mode: KillSwitchMode, active: bool) -> KillSwitch {
        (
            KillSwitchSettings {
                mode,
                allow_lan: true,
            },
            active,
            None,
        )
    }

    const DOWN: &str = "cannot reach the Polytunnel service (os error 2)";

    #[test]
    fn each_state_has_its_look() {
        let none = None;
        assert_eq!(look(&Ok(Status::Idle {}), none), Look::Idle);
        assert_eq!(look(&Ok(connected(None)), none), Look::Connected);
        assert_eq!(
            look(&Ok(connected(Some("VPN Access Denied"))), none),
            Look::Limited
        );
        for busy in [
            Status::Connecting {
                profile: "Work".into(),
            },
            asking(&["Password"]),
            Status::Reconnecting {
                profile: "Work".into(),
                server: "gw.example.com".into(),
                attempt: 2,
                since_unix: 0,
            },
            Status::Disconnecting {
                profile: "Work".into(),
            },
        ] {
            assert_eq!(look(&Ok(busy), none), Look::Busy);
        }
        assert_eq!(look(&Ok(failed()), none), Look::Problem);
        assert_eq!(look(&Err(DOWN.into()), none), Look::Problem);
        // Idle with the kill switch holding traffic: blocked (lockdown, or a held block).
        let lockdown = ks(KillSwitchMode::Always, true);
        let while_on = ks(KillSwitchMode::Connected, true);
        assert_eq!(look(&Ok(Status::Idle {}), Some(&lockdown)), Look::Blocked);
        assert_eq!(look(&Ok(Status::Idle {}), Some(&while_on)), Look::Blocked);
        // A drop that could not be brought back while "while connected" holds traffic.
        assert_eq!(look(&Ok(failed()), Some(&while_on)), Look::Blocked);
        assert!(held(&failed(), Some(&while_on)));
        assert!(
            !held(&Status::Idle {}, Some(&lockdown)),
            "lockdown is chosen, not held"
        );
        // A failed connect under lockdown is a failure.
        assert_eq!(look(&Ok(failed()), Some(&lockdown)), Look::Problem);
        // Not blocking (nothing to block, or the rules could not be applied).
        let ready = ks(KillSwitchMode::Connected, false);
        assert_eq!(look(&Ok(Status::Idle {}), Some(&ready)), Look::Idle);
        let broken = (lockdown.0, true, Some("access denied".to_string()));
        assert_eq!(look(&Ok(Status::Idle {}), Some(&broken)), Look::Idle);
        // Connected under the kill switch is just connected.
        assert_eq!(look(&Ok(connected(None)), Some(&while_on)), Look::Connected);
    }

    #[test]
    fn each_look_has_its_badge() {
        use glyph::{Badge, Tone};
        assert_eq!(Look::Idle.badge(2).0, Badge::None);
        assert_eq!(Look::Busy.badge(1), (Badge::Ring(1), Tone::Amber));
        assert_eq!(Look::Busy.badge(4), (Badge::Ring(1), Tone::Amber));
        assert_eq!(Look::Connected.badge(0), (Badge::Dot, Tone::Green));
        assert_eq!(Look::Limited.badge(0), (Badge::Dot, Tone::Amber));
        assert_eq!(Look::Blocked.badge(0), (Badge::Square, Tone::Amber));
        assert_eq!(Look::Problem.badge(0), (Badge::Square, Tone::Red));
    }

    #[test]
    fn the_status_line_says_what_is_going_on() {
        let now = 1_000 + 102 * 60 + 30;
        let line = |s: Result<Status, String>, k: Option<&KillSwitch>| status_line(&s, k, now);
        assert_eq!(line(Ok(connected(None)), None), "Connected to Work · 1:42");
        assert_eq!(
            line(Ok(connected(Some("limited"))), None),
            "Connected to Work with limits · 1:42"
        );
        assert_eq!(line(Ok(Status::Idle {}), None), "Not connected");
        assert_eq!(
            line(Ok(asking(&["Password"])), None),
            "Waiting for you · Office needs a password"
        );
        assert_eq!(
            line(Ok(asking(&["Username", "Password"])), None),
            "Waiting for you · Office needs a password"
        );
        assert_eq!(
            line(Ok(asking(&["One-time code"])), None),
            "Waiting for you · Office needs a code"
        );
        assert_eq!(
            line(Ok(asking(&[])), None),
            "Waiting for you · Office needs your sign-in"
        );
        let lockdown = ks(KillSwitchMode::Always, true);
        assert_eq!(
            line(Ok(Status::Idle {}), Some(&lockdown)),
            "Internet blocked"
        );
        assert_eq!(line(Ok(failed()), None), "Couldn't connect");
        assert_eq!(line(Err(DOWN.into()), None), "Service stopped");
        assert_eq!(
            line(
                Err("protocol version 1 is not supported (the service speaks 2)".into()),
                None
            ),
            "Polytunnel was updated: reopen it"
        );
        assert_eq!(elapsed(0, now), None);
        assert_eq!(elapsed(100, 100 + 59), Some("0:00".into()));
        assert_eq!(elapsed(100, 100 + 26 * 3600 + 5 * 60), Some("26:05".into()));
        assert_eq!(
            elapsed(500, 100),
            Some("0:00".into()),
            "a clock that went back"
        );
    }

    #[test]
    fn the_main_item_follows_the_status() {
        let p = |s: Result<Status, String>| primary(&s, Some("Work"));
        assert_eq!(
            p(Ok(connected(None))),
            ("Disconnect Work".into(), Action::Disconnect)
        );
        assert_eq!(
            p(Ok(asking(&["Password"]))),
            ("Cancel connecting".into(), Action::Disconnect)
        );
        assert_eq!(
            p(Ok(Status::Idle {})),
            ("Connect Work".into(), Action::Connect("Work".into()))
        );
        assert_eq!(
            p(Ok(failed())),
            ("Connect Work".into(), Action::Connect("Work".into()))
        );
        assert_eq!(
            p(Err(DOWN.into())),
            ("Connect Work".into(), Action::Nothing)
        );
        assert_eq!(
            primary(&Ok(Status::Idle {}), None),
            ("Connect".into(), Action::Nothing)
        );
        assert!(active(&Ok(connected(None))));
        assert!(!active(&Ok(Status::Idle {})));
        assert!(!active(&Ok(failed())));
    }

    #[test]
    fn connect_uses_the_last_profile_while_it_exists() {
        let names = vec!["Office".to_string(), "Work".to_string()];
        assert_eq!(
            connect_target(&names, Some("Work")).as_deref(),
            Some("Work")
        );
        assert_eq!(
            connect_target(&names, Some("Gone")).as_deref(),
            Some("Office")
        );
        assert_eq!(connect_target(&names, None).as_deref(), Some("Office"));
        assert_eq!(connect_target(&[], Some("Work")), None);
    }

    #[test]
    fn connect_entries_check_the_connection() {
        let names = vec!["Office".to_string(), "Work".to_string()];
        assert_eq!(
            connect_entries(&names, None),
            [
                ("connect:Office".into(), "Office".into(), false),
                ("connect:Work".into(), "Work".into(), false),
            ]
        );
        let on = connect_entries(&names, Some("Work"));
        assert!(!on[0].2);
        assert!(on[1].2);
        assert!(connect_entries(&[], None).is_empty());
    }

    #[test]
    fn tooltips_fit_windows() {
        assert_eq!(tooltip("Not connected"), "Polytunnel – Not connected");
        let long = tooltip(&"x".repeat(300));
        assert_eq!(long.chars().count(), TOOLTIP_MAX);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn kill_switch_menu_ids_are_distinct() {
        let ids: std::collections::HashSet<_> = KILLSWITCH_MODES.iter().map(|m| m.1).collect();
        assert_eq!(ids.len(), 3);
        assert_eq!(KILLSWITCH_MODES[2].0, KillSwitchMode::Always);
    }
}
