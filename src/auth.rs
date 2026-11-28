//! `polytunnel auth`: log in to a GlobalProtect portal or a FortiGate and print the session.

use std::fs;

use polytunnel_core::Secret;
use polytunnel_core::pin::CertFingerprint;
use polytunnel_core::profile::{
    FortinetSslProfile, GlobalProtectProfile, Profile, Profiles, normalize_server,
};
use polytunnel_forti::FortiError;
use polytunnel_forti::login::TokenChallenge;
use polytunnel_gp::ClientInfo;
use polytunnel_gp::flow::{self, LoginOptions, LoginResult};

use crate::cli::{AuthArgs, AuthTarget};
use crate::emit::{self, LoginOutput};
use crate::gateways::GatewayPrefs;
use crate::prompter::{self, CliPrompter, SsoMode};
use crate::{paths, sysinfo};

pub fn run(args: &AuthArgs) -> i32 {
    let result = resolve(args).and_then(|profile| match profile {
        Profile::GlobalProtect(p) => login_gp(&p, args),
        Profile::FortinetSsl(p) => login_fortinet(&p),
        Profile::FortinetIpsec(_) => Err(
            "IPsec has no web login to hand to another client; connect with              'polytunnel connect <profile>' instead"
                .into(),
        ),
    });
    match result {
        Ok(out) => {
            print!("{}", emit::render(args.emit, &out));
            eprintln!("{}", emit::hint(&out));
            0
        }
        Err(message) => {
            eprintln!("polytunnel: {message}");
            1
        }
    }
}

/// The profile to use, with command-line overrides applied.
pub(crate) fn resolve(args: &AuthArgs) -> Result<Profile, String> {
    let mut profile = match &args.target {
        AuthTarget::Profile(name) => load_profile(name)?,
        AuthTarget::GlobalProtect(portal) => Profile::GlobalProtect(GlobalProtectProfile {
            portal: portal.clone(),
            ..Default::default()
        }),
        AuthTarget::Fortinet(server) => Profile::FortinetSsl(FortinetSslProfile {
            server: server.clone(),
            ..Default::default()
        }),
    };
    match &mut profile {
        Profile::GlobalProtect(p) => {
            if args.realm.is_some() {
                return Err("--realm is for Fortinet profiles".into());
            }
            override_with(&mut p.username, &args.user);
            override_with(&mut p.gateway, &args.gateway);
            override_with(&mut p.preferred_gateway, &args.prefer);
        }
        Profile::FortinetSsl(p) => {
            if args.gateway.is_some()
                || args.prefer.is_some()
                || args.paste
                || !args.browser
                || args.embedded
            {
                return Err(
                    "--gateway, --prefer, --paste and --no-browser are for GlobalProtect".into(),
                );
            }
            override_with(&mut p.username, &args.user);
            override_with(&mut p.realm, &args.realm);
        }
        Profile::FortinetIpsec(p) => {
            if args.gateway.is_some()
                || args.prefer.is_some()
                || args.paste
                || !args.browser
                || args.embedded
                || args.realm.is_some()
            {
                return Err("IPsec profiles only take --user".into());
            }
            override_with(&mut p.username, &args.user);
        }
    }
    Ok(profile)
}

fn override_with(slot: &mut Option<String>, value: &Option<String>) {
    if value.is_some() {
        slot.clone_from(value);
    }
}

pub(crate) fn load_profile(name: &str) -> Result<Profile, String> {
    let path = paths::profiles_file().ok_or("cannot find the configuration directory")?;
    let text = fs::read_to_string(&path).map_err(|e| {
        format!(
            "cannot read {} ({e}). Use `polytunnel auth gp <portal>` or \
             `polytunnel auth fortinet <server>`, or create profiles there (see `polytunnel profiles`).",
            path.display()
        )
    })?;
    let profiles = Profiles::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    profiles.get(name).cloned().ok_or_else(|| {
        let names: Vec<&str> = profiles.profiles.keys().map(String::as_str).collect();
        format!(
            "no profile '{name}' in {} (profiles: {})",
            path.display(),
            if names.is_empty() {
                "none".to_string()
            } else {
                names.join(", ")
            }
        )
    })
}

/// A finished GlobalProtect login.
pub(crate) struct GpLogin {
    pub client: ClientInfo,
    pub result: LoginResult,
}

pub(crate) fn gp_login(profile: &GlobalProtectProfile, args: &AuthArgs) -> Result<GpLogin, String> {
    let client = sysinfo::client_info(profile.client_os, profile.client_version.clone());
    let options = LoginOptions {
        portal: profile.portal.clone(),
        username: profile.username.clone(),
        gateway: profile.gateway.clone(),
        default_browser: true,
    };
    let mode = if args.paste {
        SsoMode::Paste
    } else if args.embedded || profile.embedded_login == Some(true) {
        SsoMode::Embedded
    } else {
        SsoMode::Callback
    };
    let prefs = GatewayPrefs {
        preferred: profile.preferred_gateway.clone(),
        policy: profile.gateway_selection.unwrap_or_default(),
        method: profile.probe.unwrap_or_default(),
    };
    let mut prompter = CliPrompter::new(mode, args.browser, prefs);
    let result = flow::login(
        &crate::trace::transport(None),
        &client,
        &options,
        &mut prompter,
    )
    .map_err(|e| e.to_string())?;
    Ok(GpLogin { client, result })
}

fn login_gp(profile: &GlobalProtectProfile, args: &AuthArgs) -> Result<LoginOutput, String> {
    let GpLogin { client, result } = gp_login(profile, args)?;
    Ok(LoginOutput {
        protocol: "gp",
        host: result.session.gateway.clone(),
        os: Some(client.os.openconnect_name()),
        cookie: result.session.cookie_string(),
        username: Some(result.session.user.clone()).filter(|u| !u.is_empty()),
        gateway: Some(result.gateway.label().to_string()),
        region: result.region,
    })
}

/// A finished Fortinet SSL VPN login.
pub(crate) struct FortiLogin {
    pub base: String,
    pub username: String,
    /// The session's cookies (a `Cookie` header value with `SVPNCOOKIE`).
    pub cookie: Secret,
}

/// A Fortinet login error as a message. When the cause is a certificate the system does not
/// trust (a FortiGate's factory certificate, typically), the message names its fingerprint
/// and how to trust it.
pub(crate) fn forti_error(base: &str, pin: Option<CertFingerprint>, error: FortiError) -> String {
    if pin.is_none()
        && matches!(error, FortiError::Http(_))
        && let Some((host, port)) = host_port(base)
        && let Some(fingerprint) = polytunnel_http::untrusted_certificate(&host, port)
    {
        return format!(
            "the system does not trust the server's certificate ({error}).\n\
             Its SHA-256 fingerprint is {}.\n\
             If that is your FortiGate's certificate (FortiClient shows it in its security \
             alert, and your administrator can confirm it), trust it: edit the profile and set \
             Server certificate to {fingerprint}, or add server-cert = \"{fingerprint}\" to the \
             profile in profiles.toml.",
            fingerprint.colon_hex()
        );
    }
    error.to_string()
}

/// The realm to log in to on one of the profile's gateways: the profile's, else one named in
/// that gateway's address (`vpn.example.com/Staff` or `...?realm=Staff`, as openconnect
/// accepts), else none.
fn forti_realm_on(profile: &FortinetSslProfile, server: &str) -> String {
    if let Some(realm) = profile.realm.as_deref().filter(|r| !r.is_empty()) {
        return realm.to_string();
    }
    let server = server.trim();
    let rest = server
        .strip_prefix("https://")
        .or_else(|| server.strip_prefix("http://"))
        .unwrap_or(server);
    let Some((_, path)) = rest.split_once(['/', '?']) else {
        return String::new();
    };
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let from_query = query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == "realm" && !v.is_empty()).then(|| v.to_string())
    });
    from_query
        .or_else(|| {
            path.split('/')
                .find(|s| !s.is_empty())
                .filter(|s| *s != "remote")
                .map(str::to_string)
        })
        .unwrap_or_default()
}

/// `(host, port)` of an `https://host[:port]` base address.
fn host_port(base: &str) -> Option<(String, u16)> {
    let authority = base.strip_prefix("https://")?.split('/').next()?;
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(':') && port.chars().all(|c| c.is_ascii_digit()) => {
            (host, port.parse().ok()?)
        }
        _ => (authority, 443),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then(|| (host.to_string(), port))
}

/// Logs in to the first of the profile's gateways that can be reached, in order (FortiClient's
/// remote gateway list). A gateway that cannot be reached (no connection, no TLS) is skipped;
/// a refused or cancelled login stops there. Returns the gateway's base address and the
/// session's cookies.
pub(crate) fn forti_login_any(
    profile: &FortinetSslProfile,
    username: &str,
    password: &Secret,
    progress: &mut dyn FnMut(String),
    ask_token: &mut dyn FnMut(&TokenChallenge) -> Result<Secret, FortiError>,
) -> Result<(String, Secret), String> {
    let transport = crate::trace::transport(profile.server_cert);
    forti_login_with(profile, progress, &mut |base, realm| {
        polytunnel_forti::login(&transport, base, username, password, realm, ask_token)
    })
}

/// The failover of [`forti_login_any`], with the login step given.
fn forti_login_with(
    profile: &FortinetSslProfile,
    progress: &mut dyn FnMut(String),
    login: &mut dyn FnMut(&str, &str) -> Result<Secret, FortiError>,
) -> Result<(String, Secret), String> {
    let servers = profile.servers();
    let mut unreachable: Vec<String> = Vec::new();
    for (i, server) in servers.iter().enumerate() {
        let base = normalize_server(server).map_err(|e| format!("{server}: {e}"))?;
        let host = base.trim_start_matches("https://").to_string();
        progress(format!("Logging in to {host}..."));
        match login(&base, &forti_realm_on(profile, server)) {
            Ok(cookie) => return Ok((base, cookie)),
            Err(FortiError::Http(e)) if i + 1 < servers.len() => {
                progress(format!(
                    "{host} cannot be reached ({e}); trying the next gateway."
                ));
                unreachable.push(host);
            }
            Err(e) => {
                let message = forti_error(&base, profile.server_cert, e);
                return Err(if unreachable.is_empty() {
                    message
                } else {
                    format!(
                        "{message} (could not reach {} either)",
                        unreachable.join(", ")
                    )
                });
            }
        }
    }
    Err("the profile names no server".into())
}

pub(crate) fn forti_login(profile: &FortinetSslProfile) -> Result<FortiLogin, String> {
    let username = match &profile.username {
        Some(u) => u.clone(),
        None => prompter::ask("Username: ").map_err(|e| e.to_string())?,
    };
    let password = prompter::ask_secret("Password: ").map_err(|e| e.to_string())?;
    let (base, cookie) = forti_login_any(
        profile,
        &username,
        &password,
        &mut |line| eprintln!("{line}"),
        &mut |challenge| {
            if let Some(message) = &challenge.message {
                eprintln!("{message}");
            }
            let hint = match challenge.token_info.as_deref() {
                Some(kind) if kind.contains("push") => {
                    " (approve the push notification, then press Enter)"
                }
                _ => "",
            };
            prompter::ask_secret(&format!("Code{hint}: ")).map_err(|_| FortiError::Cancelled)
        },
    )?;
    Ok(FortiLogin {
        base,
        username,
        cookie,
    })
}

fn login_fortinet(profile: &FortinetSslProfile) -> Result<LoginOutput, String> {
    let FortiLogin {
        base,
        username,
        cookie,
    } = forti_login(profile)?;
    Ok(LoginOutput {
        protocol: "fortinet",
        host: base,
        os: None,
        // openconnect takes the session cookie alone.
        cookie: Secret::new(format!(
            "{}={}",
            polytunnel_forti::login::COOKIE_NAME,
            polytunnel_core::http::CookieJar::from_header(cookie.expose())
                .get(polytunnel_forti::login::COOKIE_NAME)
                .unwrap_or_default()
        )),
        username: Some(username),
        gateway: None,
        region: None,
    })
}

/// `polytunnel profiles`: where the file is and what is in it.
pub fn list_profiles() -> i32 {
    let Some(path) = paths::profiles_file() else {
        eprintln!("polytunnel: cannot find the configuration directory");
        return 1;
    };
    println!("Profiles file: {}", path.display());
    match fs::read_to_string(&path) {
        Ok(text) => match Profiles::parse(&text) {
            Ok(profiles) if profiles.profiles.is_empty() => println!("No profiles yet."),
            Ok(profiles) => {
                for (name, profile) in &profiles.profiles {
                    let target = match profile {
                        Profile::GlobalProtect(p) => &p.portal,
                        Profile::FortinetSsl(p) => &p.server,
                        Profile::FortinetIpsec(p) => &p.server,
                    };
                    println!("  {name:<20} {:<18} {target}", profile.kind());
                }
            }
            Err(e) => {
                eprintln!("polytunnel: {}: {e}", path.display());
                return 1;
            }
        },
        Err(_) => println!(
            "No profiles yet. Example:\n\n\
             [profile.work]\ntype = \"global-protect\"\nportal = \"vpn.example.com\"\n\n\
             [profile.office]\ntype = \"fortinet-ssl\"\nserver = \"vpn.example.net:10443\"\n\
             username = \"me\""
        ),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Emit;

    #[test]
    fn the_realm_can_come_from_the_server_address() {
        let realm = |server: &str, realm: Option<&str>| {
            let profile = FortinetSslProfile {
                server: server.into(),
                realm: realm.map(str::to_string),
                ..Default::default()
            };
            forti_realm_on(&profile, &profile.server)
        };
        assert_eq!(realm("vpn.example.net:10443", None), "");
        assert_eq!(realm("vpn.example.net:10443/Staff", None), "Staff");
        assert_eq!(realm("https://vpn.example.net/?realm=Lab", None), "Lab");
        assert_eq!(realm("vpn.example.net/remote/login?realm=Ops", None), "Ops");
        assert_eq!(realm("vpn.example.net/Staff", Some("Admins")), "Admins");
    }

    #[test]
    fn fortinet_gateways_are_tried_in_order_until_one_answers() {
        let profile = FortinetSslProfile {
            server: "fw.example.net:10443".into(),
            backup_servers: vec!["fw-backup.example.net:10443/Staff".into()],
            ..Default::default()
        };
        let mut tried = Vec::new();
        let mut lines = Vec::new();
        let result = forti_login_with(&profile, &mut |l| lines.push(l), &mut |base, realm| {
            tried.push((base.to_string(), realm.to_string()));
            if base.contains("backup") {
                Ok(Secret::new("SVPNCOOKIE=abc"))
            } else {
                Err(FortiError::Http("connection refused".into()))
            }
        });
        let (base, cookie) = result.unwrap();
        assert_eq!(base, "https://fw-backup.example.net:10443");
        assert_eq!(cookie.expose(), "SVPNCOOKIE=abc");
        // Each gateway gets its own realm from its address.
        assert_eq!(
            tried,
            [
                ("https://fw.example.net:10443".into(), String::new()),
                ("https://fw-backup.example.net:10443".into(), "Staff".into()),
            ]
        );
        assert!(lines.iter().any(|l| l.contains("trying the next gateway")));
    }

    #[test]
    fn a_refused_fortinet_login_does_not_try_the_other_gateways() {
        let profile = FortinetSslProfile {
            server: "fw.example.net".into(),
            backup_servers: vec!["fw-backup.example.net".into()],
            ..Default::default()
        };
        let mut tried = 0;
        let result = forti_login_with(&profile, &mut |_| {}, &mut |_, _| {
            tried += 1;
            Err(FortiError::AuthFailed("wrong password".into()))
        });
        assert_eq!(tried, 1);
        assert!(result.unwrap_err().contains("wrong password"));
        // When every gateway is unreachable, the error says so for each.
        let result = forti_login_with(&profile, &mut |_| {}, &mut |_, _| {
            Err(FortiError::Http("timed out".into()))
        });
        let message = result.unwrap_err();
        assert!(message.contains("timed out") && message.contains("fw.example.net"));
    }

    #[test]
    fn host_and_port_of_base_addresses() {
        let hp = |b: &str| host_port(b);
        assert_eq!(
            hp("https://vpn.example.net:10443"),
            Some(("vpn.example.net".into(), 10443))
        );
        assert_eq!(hp("https://203.0.113.7"), Some(("203.0.113.7".into(), 443)));
        assert_eq!(
            hp("https://[2001:db8::1]:8443/x"),
            Some(("2001:db8::1".into(), 8443))
        );
        assert_eq!(
            hp("https://[2001:db8::1]"),
            Some(("2001:db8::1".into(), 443))
        );
        assert_eq!(hp("http://vpn.example.net"), None);
        assert_eq!(hp("https://"), None);
    }

    fn args(target: AuthTarget) -> AuthArgs {
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
    fn overrides_apply_and_mismatched_flags_are_rejected() {
        let mut a = args(AuthTarget::GlobalProtect("vpn.example.com".into()));
        a.user = Some("me".into());
        a.gateway = Some("East".into());
        match resolve(&a).unwrap() {
            Profile::GlobalProtect(p) => {
                assert_eq!(p.username.as_deref(), Some("me"));
                assert_eq!(p.gateway.as_deref(), Some("East"));
            }
            other => panic!("{other:?}"),
        }
        a.realm = Some("r".into());
        assert!(resolve(&a).is_err());

        let mut f = args(AuthTarget::Fortinet("vpn.example.net:10443".into()));
        f.realm = Some("staff".into());
        assert!(
            matches!(resolve(&f).unwrap(), Profile::FortinetSsl(p) if p.realm.as_deref() == Some("staff"))
        );
        f.paste = true;
        assert!(resolve(&f).is_err());
    }
}
