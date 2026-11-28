//! `polytunnelw`: the window and the tray icon without a console window (a Windows GUI
//! program). The Start menu, starting at sign-in and the tray use it; `polytunnel` stays the
//! console program for the command line.
//!
//! `polytunnelw tray` starts the tray icon; anything else opens the window.

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::process::ExitCode;

fn main() -> ExitCode {
    let tray = std::env::args_os().nth(1).is_some_and(|a| a == "tray");
    let code = if tray {
        polytunnel::gui::agent::run()
    } else {
        polytunnel::gui::run_window()
    };
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
