//! `polytunnel auth`: log in to a GlobalProtect portal or a FortiGate and print the session.

use std::fs;

use polytunnel_core::Secret;
use polytunnel_core::profile::{
    FortinetSslProfile, GlobalProtectProfile, Profile, Profiles, normalize_server,
};
use polytunnel_forti::FortiError;
use polytunnel_gp::ClientInfo;
use polytunnel_gp::flow::{self, LoginOptions, LoginResult};

use crate::cli::{AuthArgs, AuthTarget};
use crate::emit::{self, LoginOutput};
use crate::gateways::GatewayPrefs;
use crate::prompter::{self, CliPrompter, SsoMode};
use crate::{paths, sysinfo};
use polytunnel_http::UreqTransport;

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
    let result = flow::login(&UreqTransport::new(), &client, &options, &mut prompter)
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
    /// The `SVPNCOOKIE` value.
    pub cookie: Secret,
}

pub(crate) fn forti_login(profile: &FortinetSslProfile) -> Result<FortiLogin, String> {
    let base = normalize_server(&profile.server).map_err(|e| e.to_string())?;
    let username = match &profile.username {
        Some(u) => u.clone(),
        None => prompter::ask("Username: ").map_err(|e| e.to_string())?,
    };
    let password = prompter::ask_secret("Password: ").map_err(|e| e.to_string())?;
    let realm = profile.realm.clone().unwrap_or_default();
    eprintln!("Logging in to {}...", base.trim_start_matches("https://"));
    let cookie = polytunnel_forti::login(
        &UreqTransport::new(),
        &base,
        &username,
        &password,
        &realm,
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
    )
    .map_err(|e| e.to_string())?;
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
        cookie: Secret::new(format!(
            "{}={}",
            polytunnel_forti::login::COOKIE_NAME,
            cookie.expose()
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
