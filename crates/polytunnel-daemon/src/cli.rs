//! Command-line parsing (`lexopt`: tiny, no derive macros).

use std::ffi::OsString;

/// What the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help,
    Version,
    /// Run the daemon: in the foreground, or under the Windows service manager.
    Run {
        service: bool,
    },
    Install,
    Uninstall,
}

pub fn help() -> String {
    format!(
        "\
Polytunnel daemon {version}
Background service that owns Polytunnel's tunnels, routes and DNS settings.

Usage: polytunnel-daemon <COMMAND>

Commands:
  run                    Run in the foreground (Ctrl+C stops it; also used by systemd)
  run --service          Run under the Windows service manager
  install                Register and start the system service (administrator/root)
  uninstall              Stop and remove the system service (administrator/root)

Options:
  -h, --help             Print help
  -V, --version          Print version
      --author           who built this
",
        version = polytunnel_core::VERSION
    )
}

pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    use lexopt::prelude::*;

    let mut parser = lexopt::Parser::from_args(args);
    let mut words = Vec::new();
    let mut service = false;
    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Short('h') | Long("help") => return Ok(Command::Help),
            Short('V') | Long("version") => return Ok(Command::Version),
            // Answered before parsing; accepted here so it never errors.
            Long("author") => {}
            Long("service") => service = true,
            Value(v) => words.push(v.to_string_lossy().into_owned()),
            other => return Err(other.unexpected().to_string()),
        }
    }
    let command = match words.first().map(String::as_str) {
        None => return Ok(Command::Help),
        Some("run") => Command::Run { service },
        Some("install") => Command::Install,
        Some("uninstall") => Command::Uninstall,
        Some(other) => return Err(format!("unknown command '{other}'")),
    };
    if words.len() > 1 {
        return Err(format!("unexpected argument '{}'", words[1]));
    }
    if service && !matches!(command, Command::Run { .. }) {
        return Err("--service only works with `run`".into());
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, String> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn no_arguments_prints_help() {
        assert_eq!(p(&[]), Ok(Command::Help));
    }

    #[test]
    fn commands() {
        assert_eq!(p(&["run"]), Ok(Command::Run { service: false }));
        assert_eq!(p(&["run", "--service"]), Ok(Command::Run { service: true }));
        assert_eq!(p(&["install"]), Ok(Command::Install));
        assert_eq!(p(&["uninstall"]), Ok(Command::Uninstall));
        assert_eq!(p(&["-h"]), Ok(Command::Help));
        assert_eq!(p(&["--version"]), Ok(Command::Version));
    }

    #[test]
    fn errors() {
        for bad in [
            &["--nope"][..],
            &["stray"],
            &["install", "--service"],
            &["run", "extra"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }
}
