//! `polytunnel connect | disconnect | status`: log in here, let the service run the tunnel.

use std::io::{BufReader, BufWriter};
use std::thread;
use std::time::{Duration, Instant};

use interprocess::local_socket::{Stream, prelude::*};
use polytunnel_core::ipc::{
    self, ClientFacts, Connect, FortiConnect, GpConnect, PROTOCOL_VERSION, Request, Response,
    Status,
};
use polytunnel_core::profile::Profile;

use crate::auth::{self, FortiLogin, GpLogin};
use crate::cli::AuthArgs;

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

fn status() -> Result<Status, String> {
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

/// Builds the service request from a finished login.
fn connect_request(args: &AuthArgs) -> Result<Connect, String> {
    let profile = label(args);
    Ok(match auth::resolve(args)? {
        Profile::GlobalProtect(p) => {
            let GpLogin { client, result } = auth::gp_login(&p, args)?;
            let s = result.session;
            Connect::GlobalProtect(Box::new(GpConnect {
                profile,
                gateway: s.gateway,
                authcookie: s.authcookie,
                user: s.user,
                portal: s.portal,
                domain: s.domain,
                preferred_ip: s.preferred_ip,
                preferred_ipv6: s.preferred_ipv6,
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
        Profile::FortinetSsl(p) => {
            let FortiLogin { base, cookie, .. } = auth::forti_login(&p)?;
            Connect::FortinetSsl(FortiConnect {
                profile,
                server: base,
                cookie,
            })
        }
    })
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
    match request(&Request::Connect { connect }) {
        Ok(Response::Accepted {}) => {}
        Ok(Response::Error { message }) => {
            eprintln!("polytunnel: {message}");
            return 1;
        }
        Ok(other) => {
            eprintln!("polytunnel: unexpected answer from the service: {other:?}");
            return 1;
        }
        Err(e) => {
            eprintln!("polytunnel: {e}");
            return 1;
        }
    }
    eprintln!("Bringing the tunnel up...");
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match status() {
            Ok(s @ Status::Connected { .. }) => {
                println!("{}", describe(&s));
                return 0;
            }
            Ok(s @ Status::Failed { .. }) => {
                eprintln!("polytunnel: {}", describe(&s));
                return 1;
            }
            Ok(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(500)),
            Ok(s) => {
                eprintln!(
                    "polytunnel: still not connected after {CONNECT_TIMEOUT:?}: {}",
                    describe(&s)
                );
                return 1;
            }
            Err(e) => {
                eprintln!("polytunnel: {e}");
                return 1;
            }
        }
    }
}

/// `polytunnel disconnect`.
pub fn run_disconnect() -> i32 {
    match request(&Request::Disconnect {}) {
        Ok(Response::Accepted {}) => {
            println!("Disconnected.");
            0
        }
        Ok(Response::Error { message }) | Err(message) => {
            eprintln!("polytunnel: {message}");
            1
        }
        Ok(other) => {
            eprintln!("polytunnel: unexpected answer from the service: {other:?}");
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
