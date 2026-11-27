//! Command-line parsing (`lexopt`: tiny, no derive macros).

use std::ffi::OsString;

/// What the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help,
    Version,
    Auth(AuthArgs),
    Profiles,
    Uri(UriAction),
    /// Deliver a `globalprotectcallback:` link to the waiting login.
    Callback(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthArgs {
    pub target: AuthTarget,
    pub emit: Emit,
    pub user: Option<String>,
    pub gateway: Option<String>,
    pub realm: Option<String>,
    /// GlobalProtect: read the SSO result from the terminal.
    pub paste: bool,
    /// GlobalProtect: open the browser (false: print the URL).
    pub browser: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthTarget {
    Profile(String),
    GlobalProtect(String),
    Fortinet(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emit {
    Openconnect,
    Cookie,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriAction {
    Register,
    Unregister,
    Status,
}

pub fn help() -> String {
    format!(
        "\
Polytunnel {version}
Lightweight VPN client for Palo Alto GlobalProtect and Fortinet (SSL VPN and IPsec).

Usage:
  polytunnel auth <PROFILE> [OPTIONS]        Log in with a saved profile
  polytunnel auth gp <PORTAL> [OPTIONS]      Log in to a GlobalProtect portal
  polytunnel auth fortinet <SERVER> [OPTIONS]  Log in to a FortiGate SSL VPN
  polytunnel profiles                        Show the profiles file and its profiles
  polytunnel uri <register|unregister|status>  Handle GlobalProtect browser logins
  polytunnel --callback <LINK>               Hand a globalprotectcallback: link to a login

Auth options:
  -u, --user <NAME>      Username (default: from the profile, or asked)
  -g, --gateway <NAME>   GlobalProtect gateway to use: address or description
      --realm <REALM>    Fortinet authentication realm
      --emit <FORMAT>    Output: openconnect (default), cookie or json
      --paste            GlobalProtect: paste the browser's login result into the
                         terminal instead of waiting for the globalprotectcallback: link
      --no-browser       GlobalProtect: print the sign-in address instead of opening it

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
    let mut positionals: Vec<String> = Vec::new();
    let mut callback: Option<String> = None;
    let mut emit = None;
    let (mut user, mut gateway, mut realm) = (None, None, None);
    let (mut paste, mut no_browser) = (false, false);

    let value = |parser: &mut lexopt::Parser| -> Result<String, String> {
        parser
            .value()
            .map_err(|e| e.to_string())?
            .into_string()
            .map_err(|_| "arguments must be valid Unicode".to_string())
    };

    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Short('h') | Long("help") => return Ok(Command::Help),
            Short('V') | Long("version") => return Ok(Command::Version),
            // Answered before parsing; accepted here so it never errors.
            Long("author") => {}
            Long("callback") => callback = Some(value(&mut parser)?),
            Short('u') | Long("user") => user = Some(value(&mut parser)?),
            Short('g') | Long("gateway") => gateway = Some(value(&mut parser)?),
            Long("realm") => realm = Some(value(&mut parser)?),
            Long("emit") => {
                emit = Some(match value(&mut parser)?.as_str() {
                    "openconnect" => Emit::Openconnect,
                    "cookie" => Emit::Cookie,
                    "json" => Emit::Json,
                    other => {
                        return Err(format!(
                            "invalid --emit '{other}': use openconnect, cookie or json"
                        ));
                    }
                });
            }
            Long("paste") => paste = true,
            Long("no-browser") => no_browser = true,
            Value(v) => positionals.push(
                v.into_string()
                    .map_err(|_| "arguments must be valid Unicode".to_string())?,
            ),
            other => return Err(other.unexpected().to_string()),
        }
    }

    let auth_flags = user.is_some()
        || gateway.is_some()
        || realm.is_some()
        || emit.is_some()
        || paste
        || no_browser;

    // The browser may pass the link as a bare argument.
    if callback.is_none()
        && positionals.len() == 1
        && crate::callback::is_callback_link(&positionals[0])
    {
        callback = positionals.pop();
    }
    if let Some(link) = callback {
        if !positionals.is_empty() || auth_flags {
            return Err("--callback takes no other arguments".into());
        }
        return Ok(Command::Callback(link));
    }

    let mut words = positionals.into_iter();
    let command = match words.next().as_deref() {
        None => return Ok(Command::Help),
        Some("auth") => {
            let target = match (words.next(), words.next()) {
                (Some(kind), Some(address)) if kind == "gp" || kind == "globalprotect" => {
                    AuthTarget::GlobalProtect(address)
                }
                (Some(kind), Some(address)) if kind == "fortinet" || kind == "forti" => {
                    AuthTarget::Fortinet(address)
                }
                (Some(name), None) if name != "gp" && name != "fortinet" => {
                    AuthTarget::Profile(name)
                }
                (Some(kind), None) => return Err(format!("auth {kind} needs a server address")),
                (Some(_), Some(_)) => {
                    return Err(
                        "use `auth gp <portal>`, `auth fortinet <server>` or `auth <profile>`"
                            .into(),
                    );
                }
                (None, _) => return Err("auth needs a profile name or a server".into()),
            };
            Command::Auth(AuthArgs {
                target,
                emit: emit.unwrap_or(Emit::Openconnect),
                user,
                gateway,
                realm,
                paste,
                browser: !no_browser,
            })
        }
        Some("profiles") => Command::Profiles,
        Some("uri") => match words.next().as_deref() {
            Some("register") => Command::Uri(UriAction::Register),
            Some("unregister") => Command::Uri(UriAction::Unregister),
            Some("status") | None => Command::Uri(UriAction::Status),
            Some(other) => return Err(format!("unknown uri action '{other}'")),
        },
        Some(other) => return Err(format!("unknown command '{other}'")),
    };
    if let Some(extra) = words.next() {
        return Err(format!("unexpected argument '{extra}'"));
    }
    if auth_flags && !matches!(command, Command::Auth(_)) {
        return Err("those options only work with `auth`".into());
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, String> {
        parse(args.iter().map(OsString::from))
    }

    fn auth(target: AuthTarget) -> AuthArgs {
        AuthArgs {
            target,
            emit: Emit::Openconnect,
            user: None,
            gateway: None,
            realm: None,
            paste: false,
            browser: true,
        }
    }

    #[test]
    fn no_arguments_prints_help() {
        assert_eq!(p(&[]), Ok(Command::Help));
    }

    #[test]
    fn auth_variants() {
        assert_eq!(
            p(&["auth", "work"]),
            Ok(Command::Auth(auth(AuthTarget::Profile("work".into()))))
        );
        assert_eq!(
            p(&[
                "auth",
                "gp",
                "vpn.example.com",
                "-g",
                "East",
                "--emit",
                "cookie",
                "--paste"
            ]),
            Ok(Command::Auth(AuthArgs {
                gateway: Some("East".into()),
                emit: Emit::Cookie,
                paste: true,
                ..auth(AuthTarget::GlobalProtect("vpn.example.com".into()))
            }))
        );
        assert_eq!(
            p(&[
                "auth",
                "fortinet",
                "vpn.example.net:10443",
                "-u",
                "me",
                "--realm=staff"
            ]),
            Ok(Command::Auth(AuthArgs {
                user: Some("me".into()),
                realm: Some("staff".into()),
                ..auth(AuthTarget::Fortinet("vpn.example.net:10443".into()))
            }))
        );
    }

    #[test]
    fn callbacks() {
        assert_eq!(
            p(&["--callback", "globalprotectcallback:abc"]),
            Ok(Command::Callback("globalprotectcallback:abc".into()))
        );
        assert_eq!(
            p(&["globalprotectcallback:abc"]),
            Ok(Command::Callback("globalprotectcallback:abc".into()))
        );
        assert!(p(&["--callback", "x", "auth"]).is_err());
    }

    #[test]
    fn other_commands() {
        assert_eq!(p(&["profiles"]), Ok(Command::Profiles));
        assert_eq!(
            p(&["uri", "register"]),
            Ok(Command::Uri(UriAction::Register))
        );
        assert_eq!(p(&["uri"]), Ok(Command::Uri(UriAction::Status)));
        assert_eq!(p(&["--help", "auth"]), Ok(Command::Help));
        assert_eq!(p(&["-V"]), Ok(Command::Version));
    }

    #[test]
    fn errors() {
        for bad in [
            &["--nope"][..],
            &["stray"],
            &["auth"],
            &["auth", "gp"],
            &["auth", "gp", "a", "b"],
            &["auth", "work", "--emit", "xml"],
            &["profiles", "--paste"],
            &["uri", "frobnicate"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn help_lists_every_option() {
        let help = help();
        for flag in [
            "--help",
            "--version",
            "--user",
            "--gateway",
            "--realm",
            "--emit",
            "--paste",
            "--no-browser",
            "--callback",
            "auth",
            "profiles",
            "uri",
        ] {
            assert!(help.contains(flag), "{flag} missing from --help");
        }
    }
}
