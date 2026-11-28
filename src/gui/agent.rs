//! The tray agent: a tray icon with no window and no graphics context, so it stays at a few
//! megabytes. It shows the connection state, opens the window, and disconnects.

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use polytunnel_core::ipc::Status;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use winit::application::ApplicationHandler;
use winit::event::{StartCause, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::window::WindowId;

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
            eprintln!("polytunnel: cannot start the tray icon: {e}");
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
            eprintln!("polytunnel: cannot start the tray icon: {e}");
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
        eprintln!("polytunnel: agent IPC unavailable: {e}");
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

    let mut agent = Agent {
        tray: None,
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
            eprintln!("polytunnel: {e}");
            1
        }
    }
}

struct Agent {
    tray: Option<TrayIcon>,
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
            &self.disconnect_item,
            &self.update_item,
            &PredefinedMenuItem::separator(),
            &quit,
        ]);
        match TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(TITLE)
            .with_icon(icon(Look::Idle))
            .with_menu_on_left_click(false)
            .build()
        {
            Ok(tray) => self.tray = Some(tray),
            Err(e) => eprintln!("polytunnel: cannot create the tray icon: {e}"),
        }
    }

    fn update(&mut self, status: Result<Status, String>) {
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
            UserEvent::Menu(_) => {}
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
            UserEvent::Status(status) => self.update(status),
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
    fn tooltips_fit_windows() {
        assert_eq!(tooltip("Not connected."), "Polytunnel: Not connected.");
        let long = tooltip(&"x".repeat(300));
        assert_eq!(long.chars().count(), TOOLTIP_MAX);
        assert!(long.ends_with('…'));
    }
}
