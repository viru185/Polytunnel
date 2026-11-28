//! `polytunnelw`: the window and the tray icon without a console window (a Windows GUI
//! program). The Start menu, starting at sign-in and the tray use it; `polytunnel` stays the
//! console program for the command line.
//!
//! `polytunnelw tray` starts the tray icon, `polytunnelw connect <profile>` opens the window
//! and connects with that profile, and `polytunnelw autostart on|off` turns starting the tray
//! at sign-in on or off with no window (the installer's Finish page and uninstall use it);
//! anything else opens the window.

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::process::ExitCode;

/// What the command line asks for.
#[derive(Debug, PartialEq)]
enum Command {
    Tray,
    Connect(String),
    Autostart(bool),
    Window,
}

fn parse(args: &[&str]) -> Command {
    match args {
        ["tray"] => Command::Tray,
        ["connect", name] if polytunnel::instance::valid_profile_name(name) => {
            Command::Connect(name.to_string())
        }
        ["autostart", "on"] => Command::Autostart(true),
        ["autostart", "off"] => Command::Autostart(false),
        _ => Command::Window,
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let code = match parse(&args) {
        Command::Tray => polytunnel::gui::agent::run(),
        Command::Connect(name) => polytunnel::gui::run_window_with(Some(name)),
        // No console to print to: the exit code is the only report.
        Command::Autostart(on) => i32::from(polytunnel::autostart::set(on).is_err()),
        Command::Window => polytunnel::gui::run_window(),
    };
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::{Command, parse};

    #[test]
    fn autostart_on_and_off() {
        assert_eq!(parse(&["autostart", "on"]), Command::Autostart(true));
        assert_eq!(parse(&["autostart", "off"]), Command::Autostart(false));
    }

    #[test]
    fn autostart_needs_exactly_on_or_off() {
        assert_eq!(parse(&["autostart"]), Command::Window);
        assert_eq!(parse(&["autostart", "ON"]), Command::Window);
        assert_eq!(parse(&["autostart", "yes"]), Command::Window);
        assert_eq!(parse(&["autostart", "on", "now"]), Command::Window);
    }

    #[test]
    fn tray_connect_and_window() {
        assert_eq!(parse(&["tray"]), Command::Tray);
        assert_eq!(parse(&["connect", "work"]), Command::Connect("work".into()));
        assert_eq!(parse(&["connect", "../x"]), Command::Window);
        assert_eq!(parse(&[]), Command::Window);
        assert_eq!(parse(&["tray", "extra"]), Command::Window);
    }
}
