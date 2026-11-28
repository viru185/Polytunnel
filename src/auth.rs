//! `polytunnel auth`: log in to a GlobalProtect portal or a FortiGate and print the session.

use std::fs;
use std::io::{self, IsTerminal};

use polytunnel_core::Secret;
use polytunnel_core::pin::CertFingerprint;
use polytunnel_core::profile::{
    FortinetSslProfile, GlobalProtectProfile, Profile, Profiles, gateway_key, normalize_server,
};
use polytunnel_forti::FortiError;
use polytunnel_forti::login::TokenChallenge;
use polytunnel_gp::ClientInfo;
use polytunnel_gp::flow::{self, LoginOptions, LoginResult};
use polytunnel_http::CertInfo;
use polytunnel_http::x509::Validity;

use crate::cli::{AuthArgs, AuthTarget};
use crate::connect::CANCELLED;
use crate::emit::{self, LoginOutput};
use crate::gateways::GatewayPrefs;
use crate::prompter::{self, CliPrompter, SsoMode};
use crate::{paths, profiles_file, sysinfo};

pub fn run(args: &AuthArgs) -> i32 {
    let result = resolve(args).and_then(|profile| match profile {
        Profile::GlobalProtect(p) => login_gp(&p, args),
        Profile::FortinetSsl(p) => login_fortinet(&p, profile_name(args)),
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

/// The name of the profile `args` use, when they name one from the profiles file.
pub(crate) fn profile_name(args: &AuthArgs) -> Option<&str> {
    match &args.target {
        AuthTarget::Profile(name) => Some(name),
        AuthTarget::GlobalProtect(_) | AuthTarget::Fortinet(_) => None,
    }
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
    /// The certificate the gateway was trusted by, for the service (which talks to the same
    /// gateway); `None`: the system's trust.
    pub pin: Option<CertFingerprint>,
}

/// What the user decided about a gateway certificate the system does not trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trust {
    /// For this login only.
    Once,
    /// And saved in the profile, for this gateway.
    Always,
    /// No login.
    Cancel,
}

/// A login on one of a profile's gateways.
pub(crate) struct FortiSession {
    /// `https://host[:port]`
    pub base: String,
    pub cookie: Secret,
    /// The certificate the gateway was trusted by (saved, or trusted just now); `None`: the
    /// system's trust.
    pub pin: Option<CertFingerprint>,
}

/// What [`forti_login_any`] ended with.
pub(crate) struct FortiOutcome {
    pub result: Result<FortiSession, String>,
    /// The certificates the user chose to always trust, as (gateway `host:port`,
    /// fingerprint), to save in the profile. Reported whatever the login did next: the choice
    /// was about the certificate.
    pub always: Vec<(String, CertFingerprint)>,
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

/// The network side of a Fortinet login, replaced in tests.
trait FortiNet {
    /// Logs in to `base` with `realm`, trusting exactly `pin` when given, else the system.
    fn login(
        &mut self,
        base: &str,
        realm: &str,
        pin: Option<CertFingerprint>,
    ) -> Result<Secret, FortiError>;

    /// After a network error: the certificate `host:port` presents, if it is what stood in
    /// the way. `pinned`: whatever it is (a saved one may no longer match); otherwise only a
    /// certificate the system does not trust.
    fn certificate(&mut self, host: &str, port: u16, pinned: bool) -> Option<CertInfo>;
}

struct Network<'a> {
    username: &'a str,
    password: &'a Secret,
    ask_token: &'a mut dyn FnMut(&TokenChallenge) -> Result<Secret, FortiError>,
}

impl FortiNet for Network<'_> {
    fn login(
        &mut self,
        base: &str,
        realm: &str,
        pin: Option<CertFingerprint>,
    ) -> Result<Secret, FortiError> {
        polytunnel_forti::login(
            &crate::trace::transport(pin),
            base,
            self.username,
            self.password,
            realm,
            &mut *self.ask_token,
        )
    }

    fn certificate(&mut self, host: &str, port: u16, pinned: bool) -> Option<CertInfo> {
        if pinned {
            polytunnel_http::server_certificate(host, port)
        } else {
            polytunnel_http::untrusted_certificate_info(host, port)
        }
    }
}

/// Logs in to the first of the profile's gateways that can be reached, in order (FortiClient's
/// remote gateway list). A gateway that cannot be reached (no connection, no TLS) is skipped;
/// a refused or cancelled login stops there.
///
/// A gateway with a saved certificate (its `trusted-certs` entry, else `server-cert`) is
/// trusted by exactly that one, any other by the system. When a gateway presents a certificate
/// that is neither, `on_untrusted` decides (with the gateway's `host:port`, the certificate,
/// and the different one saved before, if any): trusting it logs in again trusting exactly
/// it; cancelling stops without trying the other gateways.
pub(crate) fn forti_login_any(
    profile: &FortinetSslProfile,
    username: &str,
    password: &Secret,
    progress: &mut dyn FnMut(String),
    on_untrusted: &mut dyn FnMut(&str, &CertInfo, Option<CertFingerprint>) -> Trust,
    ask_token: &mut dyn FnMut(&TokenChallenge) -> Result<Secret, FortiError>,
) -> FortiOutcome {
    let mut network = Network {
        username,
        password,
        ask_token,
    };
    forti_login_with(profile, progress, on_untrusted, &mut network)
}

/// The failover and trust decisions of [`forti_login_any`], with the network given.
fn forti_login_with(
    profile: &FortinetSslProfile,
    progress: &mut dyn FnMut(String),
    on_untrusted: &mut dyn FnMut(&str, &CertInfo, Option<CertFingerprint>) -> Trust,
    net: &mut dyn FortiNet,
) -> FortiOutcome {
    let mut always = Vec::new();
    let result = try_gateways(profile, progress, on_untrusted, net, &mut always);
    FortiOutcome { result, always }
}

fn try_gateways(
    profile: &FortinetSslProfile,
    progress: &mut dyn FnMut(String),
    on_untrusted: &mut dyn FnMut(&str, &CertInfo, Option<CertFingerprint>) -> Trust,
    net: &mut dyn FortiNet,
    always: &mut Vec<(String, CertFingerprint)>,
) -> Result<FortiSession, String> {
    let servers = profile.servers();
    let mut unreachable: Vec<String> = Vec::new();
    let with_unreachable = |message: String, unreachable: &[String]| {
        if unreachable.is_empty() {
            message
        } else {
            format!(
                "{message} (could not reach {} either)",
                unreachable.join(", ")
            )
        }
    };
    for (i, server) in servers.iter().enumerate() {
        let base = normalize_server(server).map_err(|e| format!("{server}: {e}"))?;
        let gateway = gateway_key(server).map_err(|e| format!("{server}: {e}"))?;
        let host = base.trim_start_matches("https://").to_string();
        let realm = forti_realm_on(profile, server);
        let saved = profile.trusted_cert(&gateway);
        let mut pin = saved;
        let mut asked = false;
        progress(format!("Logging in to {host}..."));
        let error = loop {
            match net.login(&base, &realm, pin) {
                Ok(cookie) => return Ok(FortiSession { base, cookie, pin }),
                Err(FortiError::Http(e)) if !asked => {
                    // Reachable, with a certificate that is not trusted (or not the saved one)?
                    let presented = host_port(&base)
                        .and_then(|(h, port)| net.certificate(&h, port, saved.is_some()))
                        .filter(|info| Some(info.fingerprint) != saved);
                    let Some(info) = presented else {
                        break e;
                    };
                    asked = true;
                    match on_untrusted(&gateway, &info, saved) {
                        Trust::Cancel => return Err(CANCELLED.into()),
                        Trust::Once => {}
                        Trust::Always => always.push((gateway.clone(), info.fingerprint)),
                    }
                    pin = Some(info.fingerprint);
                    progress(format!(
                        "Logging in to {host}, trusting the certificate you accepted..."
                    ));
                }
                Err(FortiError::Http(e)) => break e,
                Err(e) => return Err(with_unreachable(e.to_string(), &unreachable)),
            }
        };
        if i + 1 < servers.len() {
            progress(format!(
                "{host} cannot be reached ({error}); trying the next gateway."
            ));
            unreachable.push(host);
        } else {
            return Err(with_unreachable(
                FortiError::Http(error).to_string(),
                &unreachable,
            ));
        }
    }
    Err("the profile names no server".into())
}

/// "YYYY-MM-DD to YYYY-MM-DD", and a warning when the certificate is not valid today.
pub(crate) fn certificate_dates(info: &CertInfo) -> (String, Option<&'static str>) {
    let day = |d: &Option<String>| d.clone().unwrap_or_else(|| "?".into());
    let dates = format!("{} to {}", day(&info.not_before), day(&info.not_after));
    let warning = match info.validity() {
        Validity::Expired => Some("Expired"),
        Validity::NotYetValid => Some("Not valid yet"),
        Validity::Valid | Validity::Unknown => None,
    };
    (dates, warning)
}

/// Who issued a certificate, in words.
pub(crate) fn certificate_issuer(info: &CertInfo) -> String {
    let issuer = info.issuer.summary();
    match (info.self_signed, issuer.is_empty()) {
        (true, true) => "Itself (self-signed)".into(),
        (true, false) => format!("{issuer} (self-signed)"),
        (false, true) => "Not named".into(),
        (false, false) => issuer,
    }
}

/// The certificate question's details, for the terminal. `previous`: the certificate
/// trusted before, when this one replaces it.
fn describe_certificate(
    gateway: &str,
    info: &CertInfo,
    previous: Option<CertFingerprint>,
) -> String {
    let mut text = if previous.is_some() {
        format!(
            "WARNING: the certificate of {gateway} has changed: it is not the one this profile \
             trusts.\nThat happens when the certificate is replaced, but it can also mean \
             someone is intercepting the connection.\n"
        )
    } else {
        format!("The certificate of {gateway} is not trusted by this computer.\n")
    };
    let mut row = |label: &str, value: &str| text.push_str(&format!("  {label:<16}{value}\n"));
    let subject = info.subject.summary();
    row(
        "Issued to:",
        if subject.is_empty() {
            "Not named"
        } else {
            &subject
        },
    );
    if !info.dns_names.is_empty() {
        row("Names:", &info.dns_names.join(", "));
    }
    row("Issued by:", &certificate_issuer(info));
    let (dates, warning) = certificate_dates(info);
    match warning {
        Some(warning) => row("Valid:", &format!("{dates} ({})", warning.to_lowercase())),
        None => row("Valid:", &dates),
    }
    if let Some(previous) = previous {
        row("Trusted before:", &previous.colon_hex());
    }
    row("SHA-256:", &info.fingerprint.colon_hex());
    text.push_str("Compare the fingerprint with the one your administrator gives you.\n");
    text
}

/// Asks on the terminal whether to trust a gateway's certificate. `saved_as`: the profile's
/// name, when it comes from the profiles file (only then can it be trusted always). Without
/// a terminal to ask, or at the end of input, the answer is no and `refused` says how to
/// trust the certificate in the profiles file instead.
fn ask_trust(
    gateway: &str,
    info: &CertInfo,
    previous: Option<CertFingerprint>,
    saved_as: Option<&str>,
    refused: &mut Option<String>,
) -> Trust {
    let unanswered = || untrusted_without_terminal(gateway, info, previous.is_some(), saved_as);
    if !io::stdin().is_terminal() {
        *refused = Some(unanswered());
        return Trust::Cancel;
    }
    eprint!("{}", describe_certificate(gateway, info, previous));
    let question = if saved_as.is_some() {
        "Trust this certificate? [o]nce / [a]lways / [N]o: "
    } else {
        "Trust this certificate? [o]nce / [N]o: "
    };
    match prompter::ask(question) {
        Ok(answer) => trust_answer(&answer, saved_as.is_some()),
        Err(_) => {
            *refused = Some(unanswered());
            Trust::Cancel
        }
    }
}

/// The error when nobody could be asked about a certificate: how to trust it in the file.
fn untrusted_without_terminal(
    gateway: &str,
    info: &CertInfo,
    changed: bool,
    saved_as: Option<&str>,
) -> String {
    format!(
        "the certificate of {gateway} {} and there is no terminal to ask. To trust it, add \
         \"{gateway}\" = \"{}\" under [profile.{}.trusted-certs] in profiles.toml.",
        if changed {
            "has changed"
        } else {
            "is not trusted"
        },
        info.fingerprint,
        saved_as.unwrap_or("<name>")
    )
}

/// The terminal answer to the certificate question; anything else is no.
fn trust_answer(answer: &str, can_save: bool) -> Trust {
    match answer.trim().to_ascii_lowercase().as_str() {
        "o" | "once" => Trust::Once,
        "a" | "always" if can_save => Trust::Always,
        _ => Trust::Cancel,
    }
}

/// Logs in on the terminal. `saved_as`: the profile's name, when it comes from the profiles
/// file (a certificate "always" trusted is saved there).
pub(crate) fn forti_login(
    profile: &FortinetSslProfile,
    saved_as: Option<&str>,
) -> Result<FortiLogin, String> {
    let username = match &profile.username {
        Some(u) => u.clone(),
        None => prompter::ask("Username: ").map_err(|e| e.to_string())?,
    };
    let password = prompter::ask_secret("Password: ").map_err(|e| e.to_string())?;
    let mut refused = None;
    let outcome = forti_login_any(
        profile,
        &username,
        &password,
        &mut |line| eprintln!("{line}"),
        &mut |gateway, info, previous| ask_trust(gateway, info, previous, saved_as, &mut refused),
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
    );
    if let Some(name) = saved_as {
        for (gateway, pin) in &outcome.always {
            match profiles_file::save_trusted_certificate(name, gateway, *pin) {
                Ok(()) => eprintln!("Saved: '{name}' always trusts this certificate on {gateway}."),
                Err(e) => eprintln!("polytunnel: could not save the certificate: {e}"),
            }
        }
    }
    let session = outcome.result.map_err(|e| match refused {
        Some(message) if e == CANCELLED => message,
        _ => e,
    })?;
    Ok(FortiLogin {
        base: session.base,
        username,
        cookie: session.cookie,
        pin: session.pin,
    })
}

fn login_fortinet(
    profile: &FortinetSslProfile,
    saved_as: Option<&str>,
) -> Result<LoginOutput, String> {
    let FortiLogin {
        base,
        username,
        cookie,
        ..
    } = forti_login(profile, saved_as)?;
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
    use polytunnel_http::x509::CertName;

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

    /// One gateway of [`FakeNet`].
    #[derive(Clone)]
    enum Gate {
        /// Nothing answers.
        Down,
        /// A certificate the system trusts, with this fingerprint.
        Trusted(u8),
        /// A certificate the system does not trust.
        Untrusted(u8),
        /// TLS works with this (untrusted) certificate, then the connection drops.
        Drops(u8),
        /// A trusted certificate, and the password is refused.
        Refuses,
    }

    fn cert(byte: u8) -> CertInfo {
        CertInfo {
            fingerprint: CertFingerprint::from_digest([byte; 32]),
            subject: CertName {
                common_name: Some("FGT-TEST".into()),
                organization: Some("Example Org".into()),
                organizational_unit: None,
            },
            issuer: CertName {
                common_name: Some("FGT-TEST".into()),
                ..Default::default()
            },
            not_before: Some("2024-01-01".into()),
            not_after: Some("2999-12-31".into()),
            dns_names: vec!["fw.example.net".into()],
            self_signed: true,
        }
    }

    fn pin(byte: u8) -> CertFingerprint {
        CertFingerprint::from_digest([byte; 32])
    }

    /// Gateways by host name, answering the way the real network does: a pinned login works
    /// only with exactly that certificate, an unpinned one only with a certificate the system
    /// trusts.
    struct FakeNet {
        gates: Vec<(&'static str, Gate)>,
        /// (base, realm, pin) of every login.
        tried: Vec<(String, String, Option<CertFingerprint>)>,
    }

    impl FakeNet {
        fn new(gates: &[(&'static str, Gate)]) -> Self {
            FakeNet {
                gates: gates.to_vec(),
                tried: Vec::new(),
            }
        }

        fn gate(&self, host: &str) -> Gate {
            self.gates
                .iter()
                .find(|(h, _)| *h == host)
                .map_or(Gate::Down, |(_, g)| g.clone())
        }
    }

    impl FortiNet for FakeNet {
        fn login(
            &mut self,
            base: &str,
            realm: &str,
            pinned: Option<CertFingerprint>,
        ) -> Result<Secret, FortiError> {
            self.tried
                .push((base.to_string(), realm.to_string(), pinned));
            let (host, _) = host_port(base).unwrap();
            let tls = |presented: CertFingerprint, system: bool| match pinned {
                Some(p) if p == presented => Ok(()),
                Some(_) => Err(FortiError::Http("not the trusted certificate".into())),
                None if system => Ok(()),
                None => Err(FortiError::Http("certificate not trusted".into())),
            };
            match self.gate(&host) {
                Gate::Down => Err(FortiError::Http("connection refused".into())),
                Gate::Trusted(b) => tls(pin(b), true).map(|()| Secret::new("SVPNCOOKIE=ok")),
                Gate::Untrusted(b) => tls(pin(b), false).map(|()| Secret::new("SVPNCOOKIE=ok")),
                Gate::Drops(b) => {
                    tls(pin(b), false)?;
                    Err(FortiError::Http("connection reset".into()))
                }
                Gate::Refuses => Err(FortiError::AuthFailed("wrong password".into())),
            }
        }

        fn certificate(&mut self, host: &str, _port: u16, pinned: bool) -> Option<CertInfo> {
            match self.gate(host) {
                Gate::Down => None,
                Gate::Trusted(b) => pinned.then(|| cert(b)),
                Gate::Untrusted(b) | Gate::Drops(b) => Some(cert(b)),
                Gate::Refuses => None,
            }
        }
    }

    /// What a login did: the outcome, the certificate questions (gateway, fingerprint, the
    /// one trusted before) and the progress lines.
    struct Run {
        outcome: FortiOutcome,
        asked: Vec<(String, CertFingerprint, Option<CertFingerprint>)>,
        lines: Vec<String>,
    }

    fn run(profile: &FortinetSslProfile, net: &mut FakeNet, answer: Trust) -> Run {
        let mut asked = Vec::new();
        let mut lines = Vec::new();
        let outcome = forti_login_with(
            profile,
            &mut |l| lines.push(l),
            &mut |gateway, info, previous| {
                asked.push((gateway.to_string(), info.fingerprint, previous));
                answer
            },
            net,
        );
        Run {
            outcome,
            asked,
            lines,
        }
    }

    fn office() -> FortinetSslProfile {
        FortinetSslProfile {
            server: "fw.example.net:10443".into(),
            backup_servers: vec!["fw-backup.example.net:10443/Staff".into()],
            ..Default::default()
        }
    }

    const MAIN: &str = "https://fw.example.net:10443";
    const BACKUP: &str = "https://fw-backup.example.net:10443";

    #[test]
    fn fortinet_gateways_are_tried_in_order_until_one_answers() {
        let mut net = FakeNet::new(&[
            ("fw.example.net", Gate::Down),
            ("fw-backup.example.net", Gate::Trusted(9)),
        ]);
        let run = run(&office(), &mut net, Trust::Cancel);
        let session = run.outcome.result.unwrap();
        assert_eq!(session.base, BACKUP);
        assert_eq!(session.cookie.expose(), "SVPNCOOKIE=ok");
        assert_eq!(session.pin, None, "the system's trust");
        // Each gateway gets its own realm from its address.
        assert_eq!(
            net.tried,
            [
                (MAIN.into(), String::new(), None),
                (BACKUP.into(), "Staff".into(), None),
            ]
        );
        assert!(
            run.lines
                .iter()
                .any(|l| l.contains("trying the next gateway"))
        );
        assert!(run.asked.is_empty());
    }

    #[test]
    fn a_refused_fortinet_login_does_not_try_the_other_gateways() {
        let mut net = FakeNet::new(&[
            ("fw.example.net", Gate::Refuses),
            ("fw-backup.example.net", Gate::Trusted(9)),
        ]);
        let run = run(&office(), &mut net, Trust::Cancel);
        assert_eq!(net.tried.len(), 1);
        assert!(run.outcome.result.err().unwrap().contains("wrong password"));
        // When every gateway is unreachable, the error says so for each.
        let mut net = FakeNet::new(&[]);
        let message = run_err(&office(), &mut net);
        assert!(message.contains("connection refused") && message.contains("fw.example.net"));
    }

    fn run_err(profile: &FortinetSslProfile, net: &mut FakeNet) -> String {
        run(profile, net, Trust::Cancel)
            .outcome
            .result
            .err()
            .unwrap()
    }

    #[test]
    fn an_unknown_certificate_is_shown_and_can_be_trusted_once() {
        let mut net = FakeNet::new(&[("fw.example.net", Gate::Untrusted(1))]);
        let run = run(&office(), &mut net, Trust::Once);
        assert_eq!(
            run.asked,
            [("fw.example.net:10443".to_string(), pin(1), None)]
        );
        let session = run.outcome.result.unwrap();
        assert_eq!(session.base, MAIN);
        // The service is handed the certificate the login trusted.
        assert_eq!(session.pin, Some(pin(1)));
        assert_eq!(
            net.tried,
            [
                (MAIN.into(), String::new(), None),
                (MAIN.into(), String::new(), Some(pin(1))),
            ]
        );
        // Once: nothing to save.
        assert!(run.outcome.always.is_empty());
    }

    #[test]
    fn always_trust_is_reported_and_then_used_without_asking() {
        let mut net = FakeNet::new(&[("fw.example.net", Gate::Untrusted(1))]);
        let first = run(&office(), &mut net, Trust::Always);
        assert_eq!(first.asked.len(), 1);
        assert_eq!(first.outcome.result.unwrap().pin, Some(pin(1)));
        assert_eq!(
            first.outcome.always,
            [("fw.example.net:10443".to_string(), pin(1))]
        );

        // Saved the way the window and the command line save it, the next login uses it
        // straight away.
        let mut profiles = Profiles::default();
        profiles
            .profiles
            .insert("office".into(), Profile::FortinetSsl(office()));
        for (gateway, fingerprint) in &first.outcome.always {
            profiles_file::trust_certificate(&mut profiles, "office", gateway, *fingerprint)
                .unwrap();
        }
        let Some(Profile::FortinetSsl(saved)) = profiles.get("office") else {
            panic!("office");
        };
        let mut net = FakeNet::new(&[("fw.example.net", Gate::Untrusted(1))]);
        let again = run(saved, &mut net, Trust::Cancel);
        assert!(again.asked.is_empty());
        assert_eq!(again.outcome.result.unwrap().pin, Some(pin(1)));
        assert_eq!(net.tried, [(MAIN.into(), String::new(), Some(pin(1)))]);
    }

    #[test]
    fn cancelling_stops_without_trying_the_backup_gateway() {
        let mut net = FakeNet::new(&[
            ("fw.example.net", Gate::Untrusted(1)),
            ("fw-backup.example.net", Gate::Trusted(9)),
        ]);
        let run = run(&office(), &mut net, Trust::Cancel);
        assert_eq!(run.asked.len(), 1);
        assert_eq!(run.outcome.result.err().as_deref(), Some(CANCELLED));
        assert_eq!(net.tried, [(MAIN.into(), String::new(), None)]);
        assert!(run.outcome.always.is_empty());
    }

    #[test]
    fn a_changed_certificate_is_shown_as_changed() {
        // Saved for the gateway itself.
        let mut profile = office();
        profile
            .trusted_certs
            .insert("fw.example.net:10443".into(), pin(1));
        let mut net = FakeNet::new(&[("fw.example.net", Gate::Untrusted(2))]);
        let run_once = run(&profile, &mut net, Trust::Once);
        assert_eq!(
            run_once.asked,
            [("fw.example.net:10443".to_string(), pin(2), Some(pin(1)))]
        );
        assert_eq!(run_once.outcome.result.unwrap().pin, Some(pin(2)));
        assert_eq!(
            net.tried,
            [
                (MAIN.into(), String::new(), Some(pin(1))),
                (MAIN.into(), String::new(), Some(pin(2))),
            ]
        );

        // Saved as server-cert (every gateway), and the new certificate is one the system
        // trusts: still a change to confirm.
        let profile = FortinetSslProfile {
            server_cert: Some(pin(1)),
            ..office()
        };
        let mut net = FakeNet::new(&[("fw.example.net", Gate::Trusted(3))]);
        let changed = run(&profile, &mut net, Trust::Always);
        assert_eq!(
            changed.asked,
            [("fw.example.net:10443".to_string(), pin(3), Some(pin(1)))]
        );
        assert_eq!(
            changed.outcome.always,
            [("fw.example.net:10443".to_string(), pin(3))]
        );
    }

    #[test]
    fn an_unreachable_gateway_still_fails_over() {
        let mut net = FakeNet::new(&[
            ("fw.example.net", Gate::Down),
            ("fw-backup.example.net", Gate::Untrusted(5)),
        ]);
        let run = run(&office(), &mut net, Trust::Once);
        // Only the gateway that answered is asked about.
        assert_eq!(
            run.asked,
            [("fw-backup.example.net:10443".to_string(), pin(5), None)]
        );
        let session = run.outcome.result.unwrap();
        assert_eq!((session.base.as_str(), session.pin), (BACKUP, Some(pin(5))));
        assert!(
            run.lines
                .iter()
                .any(|l| l.contains("trying the next gateway"))
        );
    }

    #[test]
    fn a_dropped_connection_is_not_a_certificate_question() {
        // The saved certificate is still the one presented: not asked again.
        let mut profile = office();
        profile
            .trusted_certs
            .insert("fw.example.net:10443".into(), pin(4));
        let mut net = FakeNet::new(&[
            ("fw.example.net", Gate::Drops(4)),
            ("fw-backup.example.net", Gate::Trusted(9)),
        ]);
        let first = run(&profile, &mut net, Trust::Cancel);
        assert!(first.asked.is_empty());
        assert_eq!(first.outcome.result.unwrap().base, BACKUP);

        // Trusted just now, then the connection drops: asked once, then the next gateway.
        let mut net = FakeNet::new(&[
            ("fw.example.net", Gate::Drops(4)),
            ("fw-backup.example.net", Gate::Trusted(9)),
        ]);
        let second = run(&office(), &mut net, Trust::Once);
        assert_eq!(second.asked.len(), 1);
        assert_eq!(second.outcome.result.unwrap().base, BACKUP);
        assert_eq!(net.tried.len(), 3);
    }

    #[test]
    fn the_terminal_question_and_its_answers() {
        assert_eq!(trust_answer("o", true), Trust::Once);
        assert_eq!(trust_answer(" Once ", false), Trust::Once);
        assert_eq!(trust_answer("a", true), Trust::Always);
        assert_eq!(trust_answer("ALWAYS", true), Trust::Always);
        // Always only where it can be saved; anything else (Enter too) is no.
        assert_eq!(trust_answer("a", false), Trust::Cancel);
        for no in ["", "n", "no", "yes", "x"] {
            assert_eq!(trust_answer(no, true), Trust::Cancel, "{no:?}");
        }

        let info = cert(7);
        let text = describe_certificate("fw.example.net:10443", &info, None);
        for part in [
            "fw.example.net:10443",
            "FGT-TEST, Example Org",
            "self-signed",
            "2024-01-01 to 2999-12-31",
            &info.fingerprint.colon_hex(),
        ] {
            assert!(text.contains(part), "{part}: {text}");
        }
        assert!(!text.contains("WARNING") && !text.contains("Trusted before:"));
        let changed = describe_certificate("fw.example.net:10443", &info, Some(pin(8)));
        assert!(changed.starts_with("WARNING") && changed.contains("intercepting"));
        assert!(changed.contains(&format!("Trusted before: {}", pin(8).colon_hex())));

        let refused =
            untrusted_without_terminal("fw.example.net:10443", &info, false, Some("office"));
        assert!(
            refused.contains("[profile.office.trusted-certs]"),
            "{refused}"
        );
        assert!(refused.contains(&format!(
            "\"fw.example.net:10443\" = \"{}\"",
            info.fingerprint
        )));
        let ad_hoc = untrusted_without_terminal("fw.example.net:10443", &info, true, None);
        assert!(ad_hoc.contains("has changed") && ad_hoc.contains("trusted-certs"));
    }

    #[test]
    fn certificate_dates_warn_outside_the_validity_period() {
        let mut info = cert(1);
        assert_eq!(
            certificate_dates(&info),
            ("2024-01-01 to 2999-12-31".to_string(), None)
        );
        info.not_after = Some("2001-01-01".into());
        assert_eq!(certificate_dates(&info).1, Some("Expired"));
        info.not_before = Some("2998-01-01".into());
        info.not_after = Some("2999-01-01".into());
        assert_eq!(certificate_dates(&info).1, Some("Not valid yet"));
        info.not_before = None;
        info.not_after = None;
        assert_eq!(certificate_dates(&info), ("? to ?".to_string(), None));
        assert_eq!(certificate_issuer(&cert(1)), "FGT-TEST (self-signed)");
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
