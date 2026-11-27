//! Command-line parsing (`lexopt`: tiny, no derive macros).

use std::ffi::OsString;

/// What the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Open the window (no arguments).
    Window,
    /// Run the tray agent.
    Tray,
    Help,
    Version,
    Auth(AuthArgs),
    /// Log in, then have the service bring the tunnel up.
    Connect(AuthArgs),
    Disconnect,
    Status,
    Gateways(GatewaysArgs),
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
    /// GlobalProtect: always use this gateway.
    pub gateway: Option<String>,
    /// GlobalProtect: use this gateway when it answers, else the best one.
    pub prefer: Option<String>,
    pub realm: Option<String>,
    /// GlobalProtect: read the SSO result from the terminal.
    pub paste: bool,
    /// GlobalProtect: open the browser (false: print the URL).
    pub browser: bool,
    /// GlobalProtect: sign in in Polytunnel's own login window.
    pub embedded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewaysArgs {
    pub target: AuthTarget,
    /// Log in to the portal again instead of using the saved gateway list.
    pub refresh: bool,
    pub json: bool,
    pub prefer: Option<String>,
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
  polytunnel                                   Open the Polytunnel window
  polytunnel tray                              Run the tray icon
  polytunnel auth <PROFILE> [OPTIONS]          Log in with a saved profile
  polytunnel auth gp <PORTAL> [OPTIONS]        Log in to a GlobalProtect portal
  polytunnel auth fortinet <SERVER> [OPTIONS]  Log in to a FortiGate SSL VPN
  polytunnel connect <PROFILE> [OPTIONS]       Log in and connect (also `connect gp ...`,
                                               `connect fortinet ...`)
  polytunnel disconnect                        Disconnect
  polytunnel status                            Show the connection status
  polytunnel gateways <PROFILE> [OPTIONS]      Rank a GlobalProtect portal's gateways
  polytunnel gateways gp <PORTAL> [OPTIONS]      (find the best gateway)
  polytunnel profiles                          Show the profiles file and its profiles
  polytunnel uri <register|unregister|status>  Handle GlobalProtect browser logins
  polytunnel --callback <LINK>                 Hand a globalprotectcallback: link to a login

Auth options:
  -u, --user <NAME>      Username (default: from the profile, or asked)
  -g, --gateway <NAME>   GlobalProtect: always use this gateway (address or description)
      --prefer <NAME>    GlobalProtect: use this gateway when it answers, else the best one
      --realm <REALM>    Fortinet authentication realm
      --emit <FORMAT>    Output: openconnect (default), cookie or json
      --paste            GlobalProtect: paste the browser's login result into the
                         terminal instead of waiting for the globalprotectcallback: link
      --no-browser       GlobalProtect: print the sign-in address instead of opening it
      --embedded         GlobalProtect: sign in in Polytunnel's own login window

Gateways options:
      --refresh          Log in to the portal again instead of using the saved list
      --json             Print JSON
      --prefer <NAME>    Prefer this gateway when it answers

Options:
  -h, --help             Print help
  -V, --version          Print version
      --author           who built this
",
        version = polytunnel_core::VERSION
    )
}

/// `auth`/`gateways` target: `<profile>`, `gp <portal>` or `fortinet <server>`.
fn target(command: &str, words: &mut impl Iterator<Item = String>) -> Result<AuthTarget, String> {
    match (words.next(), words.next()) {
        (Some(kind), Some(address)) if kind == "gp" || kind == "globalprotect" => {
            Ok(AuthTarget::GlobalProtect(address))
        }
        (Some(kind), Some(address)) if kind == "fortinet" || kind == "forti" => {
            Ok(AuthTarget::Fortinet(address))
        }
        (Some(name), None) if name != "gp" && name != "fortinet" => Ok(AuthTarget::Profile(name)),
        (Some(kind), None) => Err(format!("{command} {kind} needs a server address")),
        (Some(_), Some(_)) => Err(format!(
            "use `{command} gp <portal>`, `{command} fortinet <server>` or `{command} <profile>`"
        )),
        (None, _) => Err(format!("{command} needs a profile name or a server")),
    }
}

pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    use lexopt::prelude::*;

    let mut parser = lexopt::Parser::from_args(args);
    let mut positionals: Vec<String> = Vec::new();
    let mut callback: Option<String> = None;
    let mut emit = None;
    let (mut user, mut gateway, mut prefer, mut realm) = (None, None, None, None);
    let (mut paste, mut no_browser, mut refresh, mut json) = (false, false, false, false);
    let mut embedded = false;

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
            Long("prefer") => prefer = Some(value(&mut parser)?),
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
            Long("embedded") => embedded = true,
            Long("refresh") => refresh = true,
            Long("json") => json = true,
            Value(v) => positionals.push(
                v.into_string()
                    .map_err(|_| "arguments must be valid Unicode".to_string())?,
            ),
            other => return Err(other.unexpected().to_string()),
        }
    }

    let auth_only = user.is_some()
        || gateway.is_some()
        || realm.is_some()
        || emit.is_some()
        || paste
        || no_browser
        || embedded;
    let gateways_only = refresh || json;
    let has_prefer = prefer.is_some();

    // The browser may pass the link as a bare argument.
    if callback.is_none()
        && positionals.len() == 1
        && crate::callback::is_callback_link(&positionals[0])
    {
        callback = positionals.pop();
    }
    if let Some(link) = callback {
        if !positionals.is_empty() || auth_only || gateways_only || has_prefer {
            return Err("--callback takes no other arguments".into());
        }
        return Ok(Command::Callback(link));
    }

    let mut words = positionals.into_iter();
    let command = match words.next().as_deref() {
        None => return Ok(Command::Window),
        Some("tray") => Command::Tray,
        Some("window") => Command::Window,
        Some("auth") => {
            if gateways_only {
                return Err("--refresh and --json are for `gateways`".into());
            }
            Command::Auth(AuthArgs {
                target: target("auth", &mut words)?,
                emit: emit.unwrap_or(Emit::Openconnect),
                user,
                gateway,
                prefer,
                realm,
                paste,
                browser: !no_browser,
                embedded,
            })
        }
        Some("connect") => {
            if gateways_only || emit.is_some() {
                return Err("--refresh, --json and --emit do not apply to `connect`".into());
            }
            Command::Connect(AuthArgs {
                target: target("connect", &mut words)?,
                emit: Emit::Openconnect,
                user,
                gateway,
                prefer,
                realm,
                paste,
                browser: !no_browser,
                embedded,
            })
        }
        Some("disconnect") => Command::Disconnect,
        Some("status") => Command::Status,
        Some("gateways") => {
            if auth_only {
                return Err("that option is for `auth`".into());
            }
            Command::Gateways(GatewaysArgs {
                target: target("gateways", &mut words)?,
                refresh,
                json,
                prefer,
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
    let takes_options = matches!(
        command,
        Command::Auth(_) | Command::Connect(_) | Command::Gateways(_)
    );
    if !takes_options && (auth_only || gateways_only || has_prefer) {
        return Err("those options only work with `auth` or `gateways`".into());
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
            prefer: None,
            realm: None,
            paste: false,
            browser: true,
            embedded: false,
        }
    }

    #[test]
    fn no_arguments_opens_the_window() {
        assert_eq!(p(&[]), Ok(Command::Window));
        assert_eq!(p(&["tray"]), Ok(Command::Tray));
        assert_eq!(p(&["--help"]), Ok(Command::Help));
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
            p(&["auth", "work", "--prefer", "West"]),
            Ok(Command::Auth(AuthArgs {
                prefer: Some("West".into()),
                ..auth(AuthTarget::Profile("work".into()))
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
    fn gateways_variants() {
        assert_eq!(
            p(&[
                "gateways",
                "work",
                "--refresh",
                "--json",
                "--prefer",
                "East"
            ]),
            Ok(Command::Gateways(GatewaysArgs {
                target: AuthTarget::Profile("work".into()),
                refresh: true,
                json: true,
                prefer: Some("East".into()),
            }))
        );
        assert_eq!(
            p(&["gateways", "gp", "vpn.example.com"]),
            Ok(Command::Gateways(GatewaysArgs {
                target: AuthTarget::GlobalProtect("vpn.example.com".into()),
                refresh: false,
                json: false,
                prefer: None,
            }))
        );
        assert!(p(&["gateways", "work", "--paste"]).is_err());
        assert!(p(&["auth", "work", "--refresh"]).is_err());
    }

    #[test]
    fn connect_variants() {
        assert_eq!(
            p(&["connect", "work", "--prefer", "East"]),
            Ok(Command::Connect(AuthArgs {
                prefer: Some("East".into()),
                ..auth(AuthTarget::Profile("work".into()))
            }))
        );
        assert_eq!(p(&["disconnect"]), Ok(Command::Disconnect));
        assert_eq!(p(&["status"]), Ok(Command::Status));
        assert!(p(&["connect", "work", "--emit", "json"]).is_err());
        assert!(p(&["status", "--paste"]).is_err());
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
            &["profiles", "--prefer", "x"],
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
            "--prefer",
            "--realm",
            "--emit",
            "--paste",
            "--no-browser",
            "--refresh",
            "--json",
            "--callback",
            "auth",
            "gateways",
            "connect",
            "disconnect",
            "status",
            "profiles",
            "uri",
        ] {
            assert!(help.contains(flag), "{flag} missing from --help");
        }
    }
}
