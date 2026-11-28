//! The tray agent: a tray icon with no window and no graphics context, so it stays at a few
//! megabytes. It shows the connection state, opens the window, and disconnects.

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use polytunnel_core::ipc::Status;
use polytunnel_core::profile::Profiles;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use winit::application::ApplicationHandler;
use winit::event::{StartCause, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::window::WindowId;

use super::notify;
use super::prefs::{self, Appearance, Prefs};
use crate::connect;
use crate::instance::{self, Instance, Message, Role};

const TITLE: &str = "Polytunnel";
const ICON_SIZE: usize = 32;
/// Windows cuts tray tooltips at 127 characters.
const TOOLTIP_MAX: usize = 127;
/// Clicks closer together than this open the window once (a double-click is two clicks).
const CLICK_DEBOUNCE: Duration = Duration::from_millis(700);
/// Status polls: often while the service answers, less often while it does not.
const POLL: Duration = Duration::from_secs(3);
const POLL_UNREACHABLE: Duration = Duration::from_secs(10);
/// An update that started installing but did not close Polytunnel is given up on after this.
#[cfg_attr(windows, allow(dead_code))]
const INSTALL_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug)]
enum UserEvent {
    Tray(TrayIconEvent),
    Menu(MenuEvent),
    Ipc(Message),
    Status(Result<Status, String>),
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

/// The profiles file's names, in order (none when it is missing or unreadable).
fn profile_names() -> Vec<String> {
    crate::paths::profiles_file()
        .and_then(|f| std::fs::read_to_string(f).ok())
        .and_then(|text| Profiles::parse(&text).ok())
        .map(|p| p.profiles.keys().cloned().collect())
        .unwrap_or_default()
}

fn profiles_changed_at() -> Option<SystemTime> {
    crate::paths::profiles_file()
        .and_then(|f| std::fs::metadata(f).ok())
        .and_then(|m| m.modified().ok())
}

/// The "Connect to" entries: (menu id, label, enabled) for each profile, given the connection
/// that is on (if any).
fn connect_entries(names: &[String], active: Option<&str>) -> Vec<(String, String, bool)> {
    names
        .iter()
        .map(|name| {
            let (label, enabled) = match active {
                Some(a) if a == name => (format!("{name} (connected)"), false),
                Some(_) => (format!("Switch to {name}"), true),
                None => (name.clone(), true),
            };
            (format!("connect:{name}"), label, enabled)
        })
        .collect()
}

/// What the icon shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Look {
    /// Grey: not connected.
    Idle,
    /// Amber: connecting, reconnecting, waiting for sign-in, or connected with limits.
    Busy,
    /// Green: connected.
    Connected,
    /// Red: the connection failed, or the service cannot be reached.
    Problem,
}

fn look(status: &Result<Status, String>) -> Look {
    match status {
        Ok(Status::Idle {}) => Look::Idle,
        Ok(Status::Connected { notice: None, .. }) => Look::Connected,
        Ok(
            Status::Connected { .. }
            | Status::Connecting { .. }
            | Status::NeedsInput { .. }
            | Status::Reconnecting { .. }
            | Status::Disconnecting { .. },
        ) => Look::Busy,
        Ok(Status::Failed { .. }) | Err(_) => Look::Problem,
    }
}

/// Is a connection on or on its way (so Disconnect and Quit have something to stop)?
fn active(status: &Result<Status, String>) -> bool {
    matches!(
        status,
        Ok(Status::Connected { .. }
            | Status::Connecting { .. }
            | Status::NeedsInput { .. }
            | Status::Reconnecting { .. })
    )
}

/// The menu's status line.
fn status_text(status: &Result<Status, String>) -> String {
    match status {
        Ok(s) => connect::describe(s),
        Err(e) => connect::service_problem(e),
    }
}

/// `Polytunnel: <text>`, cut to what Windows shows.
fn tooltip(text: &str) -> String {
    let full = format!("{TITLE}: {text}");
    if full.chars().count() <= TOOLTIP_MAX {
        return full;
    }
    let mut cut: String = full.chars().take(TOOLTIP_MAX - 1).collect();
    cut.push('…');
    cut
}

/// The icon with a status dot in the colour of `look`.
fn icon(look: Look) -> Icon {
    let mut rgba = include_bytes!(concat!(env!("OUT_DIR"), "/icon32.rgba")).to_vec();
    let color: [u8; 3] = match look {
        Look::Idle => [148, 163, 184],
        Look::Busy => [245, 158, 11],
        Look::Connected => [34, 197, 94],
        Look::Problem => [239, 68, 68],
    };
    let (cx, cy, r) = (25.0f32, 25.0f32, 6.5f32);
    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            let d = ((x as f32 + 0.5 - cx).powi(2) + (y as f32 + 0.5 - cy).powi(2)).sqrt();
            let i = (y * ICON_SIZE + x) * 4;
            if d <= r - 1.5 {
                rgba[i..i + 4].copy_from_slice(&[color[0], color[1], color[2], 255]);
            } else if d <= r {
                rgba[i..i + 4].copy_from_slice(&[255, 255, 255, 255]); // white ring
            }
        }
    }
    Icon::from_rgba(rgba, ICON_SIZE as u32, ICON_SIZE as u32).expect("the embedded icon is valid")
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
                let wait = if status.is_ok() {
                    POLL
                } else {
                    POLL_UNREACHABLE
                };
                forward(&p, UserEvent::Status(status));
                thread::sleep(wait);
            }
        })
        .ok();

    let prefs = prefs::load();
    set_menu_theme(prefs.appearance);
    let mut agent = Agent {
        tray: None,
        connect_menu: Submenu::new("Connect to", true),
        menu_key: None,
        last_status: None,
        prefs,
        prefs_seen: prefs::changed_at(),
        icon_gone: false,
        guid: std::env::current_exe()
            .map(|e| notify::tray_guid(&e.display().to_string()))
            .unwrap_or(0x5054_554e_4e45_4c00_8000_4000_0000_0001),
        status_item: MenuItem::new("Checking…", false, None),
        disconnect_item: MenuItem::with_id(MenuId::new("disconnect"), "Disconnect", false, None),
        update_item: MenuItem::with_id(MenuId::new("update"), "Check for updates", true, None),
        available: None,
        proxy: proxy.clone(),
        open_id: MenuId::new("open"),
        quit_id: MenuId::new("quit"),
        look: None,
        active: false,
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
    /// "Connect to ▸": one entry per profile.
    connect_menu: Submenu,
    /// What the "Connect to" entries were built from: the profiles file's time and the
    /// connection that was on.
    menu_key: Option<(Option<SystemTime>, Option<String>)>,
    /// The last status, to notice changes worth a notification.
    last_status: Option<Status>,
    prefs: Prefs,
    prefs_seen: Option<SystemTime>,
    /// The tray icon's GUID (notifications are sent to it).
    guid: u128,
    /// The tray icon's window was destroyed (an installer closing Polytunnel does that): the
    /// icon is gone, so this process ends and a fresh tray can start.
    icon_gone: bool,
    status_item: MenuItem,
    disconnect_item: MenuItem,
    update_item: MenuItem,
    /// A newer release found by the last check.
    available: Option<String>,
    proxy: Proxy,
    open_id: MenuId,
    quit_id: MenuId,
    look: Option<Look>,
    /// A connection is on or on its way.
    active: bool,
    last_open: Option<Instant>,
    _instance: Instance,
}

impl Agent {
    fn init(&mut self) {
        let menu = Menu::new();
        let open = MenuItem::with_id(self.open_id.clone(), "Open Polytunnel", true, None);
        let quit = MenuItem::with_id(self.quit_id.clone(), "Quit Polytunnel", true, None);
        let _ = menu.append_items(&[
            &self.status_item,
            &PredefinedMenuItem::separator(),
            &open,
            &self.connect_menu,
            &self.disconnect_item,
            &self.update_item,
            &PredefinedMenuItem::separator(),
            &quit,
        ]);
        let builder = TrayIconBuilder::new();
        #[cfg(windows)]
        let builder = builder.with_guid(self.guid);
        match builder
            .with_menu(Box::new(menu))
            .with_tooltip(TITLE)
            .with_icon(icon(Look::Idle))
            .with_menu_on_left_click(false)
            .build()
        {
            Ok(tray) => self.tray = Some(tray),
            Err(e) => crate::applog::write("WARN", &format!("cannot create the tray icon: {e}")),
        }
    }

    /// Rebuilds "Connect to" when the profiles or the connection that is on changed.
    fn refresh_connect_menu(&mut self, active: Option<String>) {
        let key = (profiles_changed_at(), active.clone());
        if self.menu_key.as_ref() == Some(&key) {
            return;
        }
        self.menu_key = Some(key);
        while self.connect_menu.remove_at(0).is_some() {}
        let entries = connect_entries(&profile_names(), active.as_deref());
        if entries.is_empty() {
            let _ = self
                .connect_menu
                .append(&MenuItem::new("No profiles yet", false, None));
        }
        for (id, label, enabled) in entries {
            let _ =
                self.connect_menu
                    .append(&MenuItem::with_id(MenuId::new(id), label, enabled, None));
        }
    }

    /// Announces a change of the connection, when notifications are on.
    fn notify_change(&mut self, status: &Result<Status, String>) {
        let Ok(now) = status else {
            self.last_status = None;
            return;
        };
        if self.prefs.notifications
            && let Some(notice) = notify::notice_for(self.last_status.as_ref(), now)
        {
            #[cfg(windows)]
            if let Some(tray) = &self.tray {
                notify::show(tray.window_handle(), self.guid, &notice);
            }
            #[cfg(not(windows))]
            let _ = notice;
        }
        self.last_status = Some(now.clone());
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

    fn update(&mut self, status: Result<Status, String>) {
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
        self.notify_change(&status);
        let connected_profile = match &status {
            Ok(
                Status::Connected { profile, .. }
                | Status::Connecting { profile }
                | Status::NeedsInput { profile, .. }
                | Status::Reconnecting { profile, .. },
            ) => Some(profile.clone()),
            _ => None,
        };
        self.refresh_connect_menu(connected_profile);
        let text = status_text(&status);
        let look = look(&status);
        self.active = active(&status);
        self.status_item.set_text(&text);
        self.disconnect_item.set_enabled(self.active);
        if let Some(tray) = &self.tray {
            let _ = tray.set_tooltip(Some(tooltip(&text)));
            if self.look != Some(look) {
                let _ = tray.set_icon(Some(icon(look)));
            }
        }
        self.look = Some(look);
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

    /// Quit: ends the connection, closes the window and removes the icon, so nothing keeps
    /// running unseen.
    fn quit(&mut self, event_loop: &ActiveEventLoop) {
        if self.active {
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

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::Tray(TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            }) => self.open_window(),
            UserEvent::Tray(_) => {}
            UserEvent::Menu(e) if e.id == self.quit_id => self.quit(event_loop),
            UserEvent::Menu(e) if e.id == self.open_id => {
                self.last_open = None;
                self.open_window();
            }
            UserEvent::Menu(e) if e.id == *self.disconnect_item.id() => {
                let _ = connect::disconnect();
            }
            UserEvent::Menu(e) if e.id == *self.update_item.id() => self.update_clicked(),
            UserEvent::Menu(e) => {
                if let Some(name) = e.id.0.strip_prefix("connect:") {
                    self.connect_profile(name.to_string());
                }
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
            UserEvent::Status(status) => {
                self.update(status);
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

    #[test]
    fn status_icons_differ() {
        // Building icons must not panic.
        for look in [Look::Idle, Look::Busy, Look::Connected, Look::Problem] {
            let _ = icon(look);
        }
    }

    #[test]
    fn the_icon_and_menu_follow_the_status() {
        let connected = Status::Connected {
            profile: "work".into(),
            server: "gw.example.com".into(),
            addresses: vec!["10.0.0.2".into()],
            transport: "esp".into(),
            since_unix: 0,
            notice: None,
            gateway: None,
            bytes_in: 0,
            bytes_out: 0,
        };
        assert_eq!(look(&Ok(connected.clone())), Look::Connected);
        assert!(active(&Ok(connected.clone())));
        let mut restricted = connected;
        if let Status::Connected { notice, .. } = &mut restricted {
            *notice = Some("VPN Access Denied".into());
        }
        assert_eq!(look(&Ok(restricted)), Look::Busy);
        assert_eq!(look(&Ok(Status::Idle {})), Look::Idle);
        assert!(!active(&Ok(Status::Idle {})));
        let failed = Status::Failed {
            profile: "work".into(),
            message: "no answer".into(),
            since_unix: 0,
        };
        assert_eq!(look(&Ok(failed.clone())), Look::Problem);
        assert!(!active(&Ok(failed)));
        let down: Result<Status, String> =
            Err("cannot reach the Polytunnel service (os error 2)".into());
        assert_eq!(look(&down), Look::Problem);
        assert!(status_text(&down).contains("isn't running"));
        let old: Result<Status, String> =
            Err("protocol version 1 is not supported (the service speaks 2)".into());
        assert!(status_text(&old).contains("was updated"));
    }

    #[test]
    fn connect_entries_follow_the_connection() {
        let names = vec!["office".to_string(), "work".to_string()];
        let idle = connect_entries(&names, None);
        assert_eq!(
            idle,
            [
                ("connect:office".into(), "office".into(), true),
                ("connect:work".into(), "work".into(), true),
            ]
        );
        let busy = connect_entries(&names, Some("work"));
        assert_eq!(
            busy[0],
            ("connect:office".into(), "Switch to office".into(), true)
        );
        assert_eq!(
            busy[1],
            ("connect:work".into(), "work (connected)".into(), false)
        );
        assert!(connect_entries(&[], None).is_empty());
    }

    #[test]
    fn tooltips_fit_windows() {
        assert_eq!(tooltip("Not connected."), "Polytunnel: Not connected.");
        let long = tooltip(&"x".repeat(300));
        assert_eq!(long.chars().count(), TOOLTIP_MAX);
        assert!(long.ends_with('…'));
    }
}
