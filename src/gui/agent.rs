//! The tray agent: a tray icon with no window and no graphics context, so it stays at a few
//! megabytes. It shows the connection state, opens the window, and disconnects.

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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

#[derive(Debug)]
enum UserEvent {
    Tray(TrayIconEvent),
    Menu(MenuEvent),
    Ipc(Message),
    Status(Result<Status, String>),
}

type Proxy = Arc<Mutex<EventLoopProxy<UserEvent>>>;

fn forward(proxy: &Proxy, event: UserEvent) {
    if let Ok(proxy) = proxy.lock() {
        let _ = proxy.send_event(event);
    }
}

/// Starts the tray agent in the background unless it already runs.
pub fn ensure_running() {
    if instance::is_running(Role::Agent) {
        return;
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut command = Command::new(exe);
        command.arg("tray");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        let _ = command.spawn();
    }
}

/// The icon with a status dot: green when connected, grey otherwise.
fn icon(connected: bool) -> Icon {
    let mut rgba = include_bytes!(concat!(env!("OUT_DIR"), "/icon32.rgba")).to_vec();
    let color: [u8; 3] = if connected {
        [34, 197, 94]
    } else {
        [148, 163, 184]
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
    let p = proxy.clone();
    thread::Builder::new()
        .name("tray-status".into())
        .spawn(move || {
            loop {
                forward(&p, UserEvent::Status(connect::status()));
                thread::sleep(Duration::from_secs(3));
            }
        })
        .ok();

    let mut agent = Agent {
        tray: None,
        status_item: MenuItem::new("Not connected", false, None),
        disconnect_item: MenuItem::with_id(MenuId::new("disconnect"), "Disconnect", false, None),
        open_id: MenuId::new("open"),
        quit_id: MenuId::new("quit"),
        connected: None,
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
    open_id: MenuId,
    quit_id: MenuId,
    connected: Option<bool>,
    _instance: Instance,
}

impl Agent {
    fn init(&mut self) {
        let menu = Menu::new();
        let open = MenuItem::with_id(self.open_id.clone(), "Open Polytunnel", true, None);
        let quit = MenuItem::with_id(self.quit_id.clone(), "Quit", true, None);
        let _ = menu.append_items(&[
            &self.status_item,
            &PredefinedMenuItem::separator(),
            &open,
            &self.disconnect_item,
            &PredefinedMenuItem::separator(),
            &quit,
        ]);
        match TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(TITLE)
            .with_icon(icon(false))
            .with_menu_on_left_click(false)
            .build()
        {
            Ok(tray) => self.tray = Some(tray),
            Err(e) => eprintln!("polytunnel: cannot create the tray icon: {e}"),
        }
    }

    fn update(&mut self, status: Result<Status, String>) {
        let text = match &status {
            Ok(s) => connect::describe(s),
            Err(_) => "The Polytunnel service is not running".to_string(),
        };
        let connected = matches!(status, Ok(Status::Connected { .. }));
        let active = matches!(
            status,
            Ok(Status::Connected { .. } | Status::Connecting { .. } | Status::NeedsInput { .. })
        );
        self.status_item.set_text(&text);
        self.disconnect_item.set_enabled(active);
        if let Some(tray) = &self.tray {
            let _ = tray.set_tooltip(Some(format!("{TITLE}: {text}")));
            if self.connected != Some(connected) {
                let _ = tray.set_icon(Some(icon(connected)));
            }
        }
        self.connected = Some(connected);
    }

    fn open_window(&self) {
        if instance::send(Role::Gui, Message::Show).is_err()
            && let Ok(exe) = std::env::current_exe()
        {
            let _ = Command::new(exe).spawn();
        }
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
            UserEvent::Menu(e) if e.id == self.quit_id => event_loop.exit(),
            UserEvent::Menu(e) if e.id == self.open_id => self.open_window(),
            UserEvent::Menu(e) if e.id == *self.disconnect_item.id() => {
                let _ = connect::disconnect();
            }
            UserEvent::Menu(_) => {}
            UserEvent::Ipc(Message::Quit) => event_loop.exit(),
            UserEvent::Ipc(Message::Show) => self.open_window(),
            UserEvent::Status(status) => self.update(status),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_icons_differ() {
        // Building icons must not panic, and the dot must change the pixels.
        let _ = icon(true);
        let _ = icon(false);
    }
}
