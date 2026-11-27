//! Polytunnel's privileged background service.
//!
//! Runs as LocalSystem (Windows service), root (systemd) or a launchd daemon. It owns the
//! tunnels and every change to the system's network configuration; the user-side app only
//! talks to it over a local, access-controlled IPC channel.
//!
//! `main.rs` only collects the arguments and calls [`run`].

pub mod author;
pub mod cli;
pub mod gp;
pub mod ipc_server;
pub mod log;
pub mod manager;
pub mod packets;
pub mod paths;
pub mod service;

use std::ffi::OsString;

use cli::Command;

/// Side effects [`run`] depends on, replaceable in tests.
pub struct Hooks {
    pub author: fn() -> i32,
}

impl Hooks {
    pub fn real() -> Self {
        Hooks {
            author: || author::show(None),
        }
    }
}

/// The command-line entry point. Returns the process exit code.
pub fn run(argv: Vec<OsString>, hooks: &Hooks) -> i32 {
    // Answered before anything else: no parsing, no settings, no logging.
    if argv.iter().any(|a| a == "--author") {
        return (hooks.author)();
    }

    let command = match cli::parse(argv) {
        Ok(command) => command,
        Err(e) => {
            eprintln!("polytunnel-daemon: {e}\nRun 'polytunnel-daemon --help' for usage.");
            return 2;
        }
    };
    match command {
        Command::Help => {
            print!("{}", cli::help());
            0
        }
        Command::Version => {
            println!("polytunnel-daemon {}", polytunnel_core::VERSION);
            0
        }
        Command::Run { service } => {
            let result = if service {
                #[cfg(windows)]
                {
                    service::windows::run_service()
                }
                #[cfg(not(windows))]
                {
                    Err("--service is only for Windows; run in the foreground instead".to_string())
                }
            } else {
                service::run_foreground()
            };
            report(result.map(|()| String::new()))
        }
        Command::Install => report(service::install()),
        Command::Uninstall => report(service::uninstall()),
    }
}

fn report(result: Result<String, String>) -> i32 {
    match result {
        Ok(message) => {
            if !message.is_empty() {
                println!("{message}");
            }
            0
        }
        Err(e) => {
            eprintln!("polytunnel-daemon: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    static AUTHOR_SHOWN: AtomicBool = AtomicBool::new(false);

    fn hooks() -> Hooks {
        Hooks {
            author: || {
                AUTHOR_SHOWN.store(true, Ordering::SeqCst);
                0
            },
        }
    }

    #[test]
    fn author_needs_no_settings_and_wins_over_everything() {
        for argv in [
            vec!["--author"],
            vec!["--version", "--author"],
            vec!["--nope", "--author"],
        ] {
            AUTHOR_SHOWN.store(false, Ordering::SeqCst);
            let argv = argv.into_iter().map(OsString::from).collect();
            assert_eq!(run(argv, &hooks()), 0);
            assert!(AUTHOR_SHOWN.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn help_hints_at_author_without_explaining_it() {
        let help = cli::help();
        assert!(help.contains("--author") && help.contains("who built this"));
        assert!(!help.contains(author::NAME));
    }

    #[test]
    fn bad_arguments_exit_with_2() {
        assert_eq!(run(vec!["--nope".into()], &hooks()), 2);
    }
}
