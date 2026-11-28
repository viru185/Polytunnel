//! `polytunnel connect | disconnect | status`: log in here, let the service run the tunnel.

use std::io::{BufReader, BufWriter};
use std::thread;
use std::time::{Duration, Instant};

use interprocess::local_socket::{Stream, prelude::*};
use polytunnel_core::Secret;
use polytunnel_core::ipc::{
    self, ClientFacts, Connect, FortiConnect, GpConnect, KillSwitchMode, KillSwitchSettings,
    PROTOCOL_VERSION, Prompt, Request, Response, Status,
};
use polytunnel_core::profile::Profile;
use polytunnel_gp::ClientInfo;
use polytunnel_gp::login::GatewaySession;

use crate::auth::{self, FortiLogin, GpLogin};
use crate::cli::AuthArgs;
use crate::{ipsec, prompter};

/// A safety limit on waiting for the service to bring a tunnel up; the service has its own
/// limits for every step, so this only matters if it stops answering sensibly.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(300);

/// What a connection that was stopped before it came up ends with.
pub const CANCELLED: &str = "cancelled";

/// What `on_prompt` answers when the service no longer waits for the answer: the wait goes on
/// (the next status says what happened) and nothing is disconnected.
pub const PROMPT_GONE: &str = "prompt-gone";

/// The service answered with something this program does not expect (a mismatched version):
/// said plainly, with the details kept out of the user's way.
fn unexpected(_other: &Response) -> String {
    "the Polytunnel service gave an unexpected answer (is it the same version as the app?)".into()
}

fn connect_stream() -> Result<Stream, String> {
    let not_running = |e: std::io::Error| {
        format!(
            "cannot reach the Polytunnel service ({e}). Is it installed and running? \
             Install it with `polytunnel-daemon install` as administrator/root."
        )
    };
    #[cfg(windows)]
    let name = {
        use interprocess::local_socket::GenericNamespaced;
        ipc::PIPE_NAME
            .to_ns_name::<GenericNamespaced>()
            .map_err(|e| e.to_string())?
    };
    #[cfg(not(windows))]
    let name = {
        use interprocess::local_socket::GenericFilePath;
        ipc::SOCKET_PATH
            .to_fs_name::<GenericFilePath>()
            .map_err(|e| e.to_string())?
    };
    Stream::connect(name).map_err(not_running)
}

/// One request/response exchange with the service (after the version handshake).
pub fn request(request: &Request) -> Result<Response, String> {
    let stream = connect_stream()?;
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);
    let io = |e: std::io::Error| format!("talking to the service: {e}");
    ipc::write_frame(
        &mut writer,
        &Request::Hello {
            version: PROTOCOL_VERSION,
        },
    )
    .map_err(io)?;
    match ipc::read_frame(&mut reader).map_err(io)? {
        Response::Hello { .. } => {}
        Response::Error { message } => return Err(message),
        other => return Err(unexpected(&other)),
    }
    ipc::write_frame(&mut writer, request).map_err(io)?;
    ipc::read_frame(&mut reader).map_err(io)
}

/// What a failed exchange with the service means for people, in one short sentence.
pub fn service_problem(error: &str) -> String {
    if error.contains("protocol version") {
        "Polytunnel was updated. Quit it from the tray and open it again.".into()
    } else if error.contains("cannot reach the Polytunnel service") {
        "The Polytunnel service isn't running. Restart the computer, or reinstall Polytunnel."
            .into()
    } else {
        "Polytunnel can't talk to its service right now.".into()
    }
}

pub fn status() -> Result<Status, String> {
    match request(&Request::Status {})? {
        Response::Status { status } => Ok(status),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// How a transport is named to people: `esp` → "ESP", `esp-tcp` → "ESP over TCP", and the
/// Fortinet SSL tunnel (PPP inside TLS) → "TLS".
pub fn transport_name(transport: &str) -> String {
    match transport {
        "esp" => "ESP".into(),
        "esp-tcp" => "ESP over TCP".into(),
        "tls" | "ppp" => "TLS".into(),
        other => other.to_uppercase(),
    }
}

pub fn describe(status: &Status) -> String {
    match status {
        Status::Idle {} => "Not connected.".into(),
        Status::Connecting { profile } => format!("Connecting ({profile})..."),
        Status::NeedsInput { profile, .. } => {
            format!("Connecting ({profile}): waiting for your sign-in input...")
        }
        Status::Connected {
            profile,
            server,
            addresses,
            transport,
            notice,
            ..
        } => {
            let connected = format!(
                "Connected to {server} ({profile}) over {}, address {}.",
                transport_name(transport),
                addresses.join(", ")
            );
            match notice {
                Some(notice) => {
                    format!("{connected} The server restricted the connection: {notice}")
                }
                None => connected,
            }
        }
        Status::Reconnecting {
            profile,
            server,
            attempt,
            ..
        } => format!(
            "The connection to {server} ({profile}) dropped; reconnecting (try {attempt})..."
        ),
        Status::Disconnecting { profile } => format!("Disconnecting ({profile})..."),
        Status::Failed {
            profile, message, ..
        } => format!("Connection failed ({profile}): {message}"),
    }
}

fn label(args: &AuthArgs) -> String {
    match &args.target {
        crate::cli::AuthTarget::Profile(name) => name.clone(),
        crate::cli::AuthTarget::GlobalProtect(a) | crate::cli::AuthTarget::Fortinet(a) => a.clone(),
    }
}

/// The service request for a finished GlobalProtect login. `app_version` is what the tunnel
/// configuration request announces (see `polytunnel_gp::client::announced_version`).
pub fn gp_connect(
    profile: String,
    client: ClientInfo,
    session: GatewaySession,
    app_version: Option<String>,
) -> Connect {
    Connect::GlobalProtect(Box::new(GpConnect {
        profile,
        gateway: session.gateway,
        authcookie: session.authcookie,
        user: session.user,
        portal: session.portal,
        domain: session.domain,
        preferred_ip: session.preferred_ip,
        preferred_ipv6: session.preferred_ipv6,
        client: ClientFacts {
            os: client.os,
            os_version: client.os_version,
            computer: client.computer,
            host_id: client.host_id,
            app_version,
        },
        allow_esp: true,
    }))
}

/// The service request for a finished Fortinet login.
pub fn forti_connect(
    profile: String,
    server: String,
    cookie: Secret,
    server_cert: Option<polytunnel_core::pin::CertFingerprint>,
) -> Connect {
    Connect::FortinetSsl(FortiConnect {
        profile,
        server,
        cookie,
        server_cert,
    })
}

/// Builds the service request from a finished login.
fn connect_request(args: &AuthArgs) -> Result<Connect, String> {
    let profile = label(args);
    Ok(match auth::resolve(args)? {
        Profile::GlobalProtect(p) => {
            let GpLogin { client, result } = auth::gp_login(&p, args)?;
            let version = polytunnel_gp::client::announced_version(
                p.client_version.as_deref(),
                result.config.version.as_deref(),
            );
            gp_connect(profile, client, result.session, version)
        }
        Profile::FortinetSsl(p) => {
            let FortiLogin {
                base, cookie, pin, ..
            } = auth::forti_login(&p, auth::profile_name(args))?;
            forti_connect(profile, base, cookie, pin)
        }
        Profile::FortinetIpsec(p) => {
            let io = |e: std::io::Error| e.to_string();
            let server = ipsec::server_host(&p)?;
            eprintln!("IPsec tunnel to {server}");
            let psk = if ipsec::needs_psk(&p) {
                prompter::ask_secret("Pre-shared key: ").map_err(io)?
            } else {
                Secret::new("")
            };
            let xauth = if ipsec::needs_login(&p) {
                let username = match &p.username {
                    Some(u) => u.clone(),
                    None => prompter::ask("Username: ").map_err(io)?,
                };
                Some((username, prompter::ask_secret("Password: ").map_err(io)?))
            } else {
                None
            };
            ipsec::connect_request(profile, &p, ipsec::Secrets { psk, xauth })?
        }
    })
}

/// Answers a service prompt on the terminal.
fn ask_on_terminal(prompt: &Prompt) -> Result<Vec<Secret>, String> {
    if let Some(message) = &prompt.message {
        eprintln!("{message}");
    }
    prompt
        .fields
        .iter()
        .map(|f| {
            let label = format!("{}: ", f.label);
            if f.secret {
                prompter::ask_secret(&label)
            } else {
                prompter::ask(&label).map(Secret::new)
            }
            .map_err(|e| e.to_string())
        })
        .collect()
}

/// Sends the user's answer to a service prompt.
pub fn answer(id: u32, values: Vec<Secret>) -> Result<(), String> {
    match request(&Request::Answer { id, values })? {
        Response::Accepted {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Hands `connect` to the service.
pub fn send_connect(connect: Connect) -> Result<(), String> {
    let trace = crate::trace::enabled();
    match request(&Request::Connect { connect, trace })? {
        Response::Accepted {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Polls the service until the tunnel is up or has failed, answering its prompts (one-time
/// codes during IPsec sign-in) with `on_prompt`. `cancelled` is asked every round: when it
/// says so, or a prompt is cancelled, the connection is stopped. A connection that went back
/// to idle (disconnected elsewhere) ends as [`CANCELLED`]; a failure ends with the service's
/// message.
pub fn wait_connected(
    cancelled: &dyn Fn() -> bool,
    on_status: &mut dyn FnMut(&Status),
    on_prompt: &mut dyn FnMut(&Prompt) -> Result<Vec<Secret>, String>,
) -> Result<Status, String> {
    let mut deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut answered = None;
    loop {
        if cancelled() {
            let _ = disconnect();
            return Err(CANCELLED.into());
        }
        let s = status()?;
        on_status(&s);
        match &s {
            Status::Connected { .. } => return Ok(s),
            Status::Failed { message, .. } => return Err(message.clone()),
            Status::Idle {} | Status::Disconnecting { .. } => return Err(CANCELLED.into()),
            Status::NeedsInput { prompt, .. } if answered != Some(prompt.id) => {
                let values = match on_prompt(prompt) {
                    Ok(values) => values,
                    Err(e) if e == PROMPT_GONE => continue,
                    Err(e) => {
                        let _ = disconnect();
                        return Err(e);
                    }
                };
                answer(prompt.id, values)?;
                answered = Some(prompt.id);
                // Time spent typing does not count against the connection.
                deadline = Instant::now() + CONNECT_TIMEOUT;
            }
            _ if Instant::now() < deadline => thread::sleep(Duration::from_millis(500)),
            _ => {
                return Err(format!(
                    "still not connected after {CONNECT_TIMEOUT:?}: {}",
                    describe(&s)
                ));
            }
        }
    }
}

/// `polytunnel connect`.
pub fn run_connect(args: &AuthArgs) -> i32 {
    // Fail early (before a browser login) if the service is not there.
    if let Err(e) = status() {
        eprintln!("polytunnel: {e}");
        return 1;
    }
    let connect = match connect_request(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("polytunnel: {e}");
            return 1;
        }
    };
    if let Err(e) = send_connect(connect) {
        eprintln!("polytunnel: {e}");
        return 1;
    }
    eprintln!("Bringing the tunnel up...");
    match wait_connected(&|| false, &mut |_| {}, &mut ask_on_terminal) {
        Ok(s) => {
            println!("{}", describe(&s));
            0
        }
        Err(e) if e == CANCELLED => {
            eprintln!("polytunnel: the connection was stopped before it came up");
            1
        }
        Err(e) => {
            eprintln!("polytunnel: could not connect: {e}");
            1
        }
    }
}

/// `polytunnel disconnect`.
pub fn run_disconnect() -> i32 {
    match disconnect() {
        Ok(()) => {
            println!("Disconnected.");
            0
        }
        Err(message) => {
            eprintln!("polytunnel: {message}");
            1
        }
    }
}

/// Asks the service to end the connection.
pub fn disconnect() -> Result<(), String> {
    match request(&Request::Disconnect {})? {
        Response::Accepted {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// Reads the kill switch, changing it first when `set` is given.
pub fn killswitch(
    set: Option<KillSwitchSettings>,
) -> Result<(KillSwitchSettings, bool, Option<String>), String> {
    match request(&Request::KillSwitch { set })? {
        Response::KillSwitch {
            settings,
            active,
            problem,
        } => Ok((settings, active, problem)),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

pub fn describe_killswitch(
    settings: &KillSwitchSettings,
    active: bool,
    problem: Option<&str>,
) -> String {
    let mode = match settings.mode {
        KillSwitchMode::Off => return "Kill switch: off.".into(),
        KillSwitchMode::Connected => "on while connected",
        KillSwitchMode::Always => "always on (lockdown)",
    };
    let lan = if settings.allow_lan {
        ", local network allowed"
    } else {
        ""
    };
    match problem {
        Some(p) => format!("Kill switch: {mode}{lan}, but it could not be applied: {p}"),
        None if active => format!("Kill switch: {mode}{lan}; blocking traffic outside the tunnel."),
        None => format!("Kill switch: {mode}{lan}; nothing to block right now."),
    }
}

/// `polytunnel killswitch [mode] [--allow-lan|--block-lan]`.
pub fn run_killswitch(mode: Option<KillSwitchMode>, allow_lan: Option<bool>) -> i32 {
    let result = killswitch(None).and_then(|(current, active, problem)| {
        if mode.is_none() && allow_lan.is_none() {
            return Ok((current, active, problem));
        }
        killswitch(Some(KillSwitchSettings {
            mode: mode.unwrap_or(current.mode),
            allow_lan: allow_lan.unwrap_or(current.allow_lan),
        }))
    });
    match result {
        Ok((settings, active, problem)) => {
            println!(
                "{}",
                describe_killswitch(&settings, active, problem.as_deref())
            );
            0
        }
        Err(e) => {
            eprintln!("polytunnel: {e}");
            1
        }
    }
}

/// What the service found about updates: (current, latest, installing, message).
pub type UpdateInfo = (String, Option<String>, bool, String);

/// Asks the service to look for a newer release, and to install it when `install`.
pub fn update(install: bool) -> Result<UpdateInfo, String> {
    match request(&Request::Update { install })? {
        Response::Update {
            current,
            latest,
            installing,
            message,
        } => Ok((current, latest, installing, message)),
        Response::Error { message } => Err(message),
        other => Err(unexpected(&other)),
    }
}

/// `polytunnel update [--install]`.
pub fn run_update(install: bool) -> i32 {
    match update(install) {
        Ok((_, latest, _, message)) => {
            println!("{message}");
            if latest.is_some() { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("polytunnel: {e}");
            1
        }
    }
}

/// `polytunnel status`.
pub fn run_status() -> i32 {
    match status() {
        Ok(s) => {
            println!("{}", describe(&s));
            0
        }
        Err(e) => {
            eprintln!("polytunnel: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_switch_reads_well() {
        let mut s = KillSwitchSettings::default();
        assert_eq!(describe_killswitch(&s, false, None), "Kill switch: off.");
        s.mode = KillSwitchMode::Connected;
        assert!(describe_killswitch(&s, true, None).contains("blocking"));
        s.allow_lan = true;
        s.mode = KillSwitchMode::Always;
        let text = describe_killswitch(&s, false, Some("access denied"));
        assert!(
            text.contains("lockdown")
                && text.contains("local network")
                && text.contains("access denied")
        );
    }

    #[test]
    fn statuses_read_well() {
        assert_eq!(describe(&Status::Idle {}), "Not connected.");
        assert_eq!(
            describe(&Status::Connected {
                profile: "work".into(),
                server: "gw.example.com".into(),
                addresses: vec!["10.20.30.40".into()],
                transport: "esp".into(),
                since_unix: 0,
                notice: None,
                gateway: None,
                bytes_in: 0,
                bytes_out: 0,
            }),
            "Connected to gw.example.com (work) over ESP, address 10.20.30.40."
        );
        assert_eq!(
            describe(&Status::Connected {
                profile: "work".into(),
                server: "gw.example.com".into(),
                addresses: vec!["10.20.30.40".into()],
                transport: "ppp".into(),
                since_unix: 0,
                notice: Some("VPN Access Denied".into()),
                gateway: None,
                bytes_in: 0,
                bytes_out: 0,
            }),
            "Connected to gw.example.com (work) over TLS, address 10.20.30.40. The server \
             restricted the connection: VPN Access Denied"
        );
        assert_eq!(transport_name("esp-tcp"), "ESP over TCP");
        assert!(
            describe(&Status::Reconnecting {
                profile: "work".into(),
                server: "gw.example.com".into(),
                attempt: 2,
                since_unix: 0,
            })
            .contains("reconnecting (try 2)")
        );
    }
}
