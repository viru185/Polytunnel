//! Polytunnel: the user-side program (tray agent, window and command line).
//!
//! `main.rs` only collects the arguments and calls [`run`].

pub mod auth;
pub mod author;
pub mod autostart;
pub mod browser;
pub mod callback;
pub mod cli;
pub mod connect;
pub mod embedded;
pub mod emit;
pub mod forticlient;
pub mod gateways;
pub mod gui;
pub mod instance;
pub mod ipsec;
pub mod paths;
pub mod probe;
pub mod prompter;
pub mod sysinfo;
pub mod uri;
#[cfg(windows)]
pub mod win;

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
            eprintln!("polytunnel: {e}\nRun 'polytunnel --help' for usage.");
            return 2;
        }
    };
    match command {
        Command::Window => gui::run_window(),
        Command::Tray => gui::agent::run(),
        Command::Help => {
            print!("{}", cli::help());
            0
        }
        Command::Version => {
            println!("polytunnel {}", polytunnel_core::VERSION);
            0
        }
        Command::Auth(args) => auth::run(&args),
        Command::Connect(args) => connect::run_connect(&args),
        Command::Disconnect => connect::run_disconnect(),
        Command::Status => connect::run_status(),
        Command::Profiles => auth::list_profiles(),
        Command::Gateways(args) => gateways::run(&args),
        Command::Uri(action) => uri::run(action),
        Command::Callback(link) => callback::run(&link),
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
            vec!["auth", "work", "--author"],
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
