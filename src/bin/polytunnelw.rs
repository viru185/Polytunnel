//! `polytunnelw`: the window and the tray icon without a console window (a Windows GUI
//! program). The Start menu, starting at sign-in and the tray use it; `polytunnel` stays the
//! console program for the command line.
//!
//! `polytunnelw tray` starts the tray icon, `polytunnelw connect <profile>` opens the window
//! and connects with that profile; anything else opens the window.

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["tray"] => polytunnel::gui::agent::run(),
        ["connect", name] if polytunnel::instance::valid_profile_name(name) => {
            polytunnel::gui::run_window_with(Some(name.to_string()))
        }
        _ => polytunnel::gui::run_window(),
    };
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
