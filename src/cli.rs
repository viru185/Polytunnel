//! Command-line parsing (`lexopt`: tiny, no derive macros).

use std::ffi::OsString;

/// What the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help,
    Version,
}

pub fn help() -> String {
    format!(
        "\
Polytunnel {version}
Lightweight VPN client for Palo Alto GlobalProtect and Fortinet (SSL VPN and IPsec).

Usage: polytunnel [OPTIONS]

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
    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Short('h') | Long("help") => return Ok(Command::Help),
            Short('V') | Long("version") => return Ok(Command::Version),
            // Answered before parsing; accepted here so it never errors.
            Long("author") => {}
            other => return Err(other.unexpected().to_string()),
        }
    }
    Ok(Command::Help)
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
    fn help_and_version() {
        assert_eq!(p(&["--help"]), Ok(Command::Help));
        assert_eq!(p(&["-V"]), Ok(Command::Version));
    }

    #[test]
    fn unknown_arguments_are_errors() {
        assert!(p(&["--nope"]).is_err());
        assert!(p(&["stray"]).is_err());
    }

    #[test]
    fn help_lists_every_option() {
        let help = help();
        for flag in ["--help", "--version"] {
            assert!(help.contains(flag), "{flag} missing from --help");
        }
    }
}
