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

/// How long to wait for the service to bring a tunnel up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(90);

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
        other => return Err(format!("unexpected answer from the service: {other:?}")),
    }
    ipc::write_frame(&mut writer, request).map_err(io)?;
    ipc::read_frame(&mut reader).map_err(io)
}

pub fn status() -> Result<Status, String> {
    match request(&Request::Status {})? {
        Response::Status { status } => Ok(status),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected answer from the service: {other:?}")),
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
            ..
        } => format!(
            "Connected to {server} ({profile}) over {}, address {}.",
            transport.to_uppercase(),
            addresses.join(", ")
        ),
        Status::Disconnecting { profile } => format!("Disconnecting ({profile})..."),
        Status::Failed { profile, message } => format!("Connection failed ({profile}): {message}"),
    }
}

fn label(args: &AuthArgs) -> String {
    match &args.target {
        crate::cli::AuthTarget::Profile(name) => name.clone(),
        crate::cli::AuthTarget::GlobalProtect(a) | crate::cli::AuthTarget::Fortinet(a) => a.clone(),
    }
}

/// The service request for a finished GlobalProtect login.
pub fn gp_connect(profile: String, client: ClientInfo, session: GatewaySession) -> Connect {
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
            app_version: client.app_version,
        },
        allow_esp: true,
    }))
}

/// The service request for a finished Fortinet login.
pub fn forti_connect(profile: String, server: String, cookie: Secret) -> Connect {
    Connect::FortinetSsl(FortiConnect {
        profile,
        server,
        cookie,
    })
}

/// Builds the service request from a finished login.
fn connect_request(args: &AuthArgs) -> Result<Connect, String> {
    let profile = label(args);
    Ok(match auth::resolve(args)? {
        Profile::GlobalProtect(p) => {
            let GpLogin { client, result } = auth::gp_login(&p, args)?;
            gp_connect(profile, client, result.session)
        }
        Profile::FortinetSsl(p) => {
            let FortiLogin { base, cookie, .. } = auth::forti_login(&p)?;
            forti_connect(profile, base, cookie)
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
        other => Err(format!("unexpected answer from the service: {other:?}")),
    }
}

/// Hands `connect` to the service.
pub fn send_connect(connect: Connect) -> Result<(), String> {
    match request(&Request::Connect { connect })? {
        Response::Accepted {} => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected answer from the service: {other:?}")),
    }
}

/// Polls the service until the tunnel is up or has failed, answering its prompts (one-time
/// codes during IPsec sign-in) with `on_prompt`. Cancelling a prompt disconnects.
pub fn wait_connected(
    on_status: &mut dyn FnMut(&Status),
    on_prompt: &mut dyn FnMut(&Prompt) -> Result<Vec<Secret>, String>,
) -> Result<Status, String> {
    let mut deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut answered = None;
    loop {
        let s = status()?;
        on_status(&s);
        match &s {
            Status::Connected { .. } => return Ok(s),
            Status::Failed { .. } => return Err(describe(&s)),
            Status::NeedsInput { prompt, .. } if answered != Some(prompt.id) => {
                let values = match on_prompt(prompt) {
                    Ok(values) => values,
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
    match wait_connected(&mut |_| {}, &mut ask_on_terminal) {
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
        other => Err(format!("unexpected answer from the service: {other:?}")),
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
        other => Err(format!("unexpected answer from the service: {other:?}")),
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
        other => Err(format!("unexpected answer from the service: {other:?}")),
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
            }),
            "Connected to gw.example.com (work) over ESP, address 10.20.30.40."
        );
    }
}
