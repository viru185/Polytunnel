//! The protocol between the user-side app and the privileged daemon (version 1).
//!
//! Frames are a 4-byte big-endian length followed by that many bytes of JSON, at most
//! [`MAX_FRAME`]. Every message is a typed enum with `deny_unknown_fields`; the daemon
//! validates connect requests before acting on them and never receives paths, command lines
//! or anything else it could be tricked into running.

use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::Secret;
use crate::profile::{ClientOs, normalize_server, valid_host};

pub const PROTOCOL_VERSION: u32 = 1;

/// Largest frame accepted in either direction.
pub const MAX_FRAME: usize = 64 * 1024;

/// Windows named pipe: `\\.\pipe\polytunnel`.
pub const PIPE_NAME: &str = "polytunnel";

/// Unix socket path.
#[cfg(target_os = "macos")]
pub const SOCKET_PATH: &str = "/var/run/polytunnel.sock";
#[cfg(not(target_os = "macos"))]
pub const SOCKET_PATH: &str = "/run/polytunnel/daemon.sock";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Hello { version: u32 },
    // Empty struct variants (not unit variants) so unknown fields are rejected too.
    Status {},
    Connect { connect: Connect },
    Disconnect {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Connect {
    GlobalProtect(Box<GpConnect>),
    FortinetSsl(FortiConnect),
}

/// Facts about the client the gateway expects with every request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientFacts {
    pub os: ClientOs,
    pub os_version: String,
    pub computer: String,
    pub host_id: String,
    pub app_version: Option<String>,
}

/// A logged-in GlobalProtect gateway session to bring up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpConnect {
    /// Profile name or label, for status display.
    pub profile: String,
    /// `https://host[:port]` of the gateway.
    pub gateway: String,
    pub authcookie: Secret,
    pub user: String,
    pub portal: String,
    pub domain: String,
    pub preferred_ip: Option<String>,
    pub preferred_ipv6: Option<String>,
    pub client: ClientFacts,
    /// Try ESP (UDP) before falling back to the TLS tunnel.
    pub allow_esp: bool,
}

/// A logged-in FortiGate SSL VPN session to bring up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FortiConnect {
    pub profile: String,
    /// `https://host[:port]` of the FortiGate.
    pub server: String,
    /// The `SVPNCOOKIE` value.
    pub cookie: Secret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Response {
    Hello {
        version: u32,
        daemon_version: String,
    },
    Status {
        status: Status,
    },
    Accepted {},
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Status {
    Idle {},
    Connecting {
        profile: String,
    },
    Connected {
        profile: String,
        server: String,
        addresses: Vec<String>,
        /// `tls`, `esp` or `ppp`.
        transport: String,
        since_unix: u64,
    },
    Disconnecting {
        profile: String,
    },
    Failed {
        profile: String,
        message: String,
    },
}

/// Writes one frame.
pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, message: &T) -> io::Result<()> {
    let body = serde_json::to_vec(message).map_err(io::Error::other)?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    writer.write_all(&(body.len() as u32).to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}

/// Reads one frame; oversized or malformed frames are errors.
pub fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> io::Result<T> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Printable ASCII only: no control characters, line breaks or spaces at the ends.
fn printable(value: &str, max: usize) -> bool {
    value.len() <= max && value.bytes().all(|b| (0x20..0x7f).contains(&b))
}

fn check(ok: bool, what: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(format!("invalid {what}"))
    }
}

/// A `https://host[:port]` that is already in normalized form.
fn check_server(server: &str, what: &str) -> Result<(), String> {
    let normalized = normalize_server(server).map_err(|e| format!("invalid {what}: {e}"))?;
    check(normalized == server, what)?;
    let host = server
        .trim_start_matches("https://")
        .trim_start_matches('[')
        .split([']', ':'])
        .next()
        .unwrap_or_default();
    check(
        valid_host(host) || host.parse::<std::net::IpAddr>().is_ok(),
        what,
    )
}

impl Connect {
    /// Rejects anything the daemon must not act on.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Connect::GlobalProtect(gp) => {
                check(printable(&gp.profile, 128), "profile name")?;
                check_server(&gp.gateway, "gateway")?;
                check(
                    !gp.authcookie.is_empty() && printable(gp.authcookie.expose(), 4096),
                    "authcookie",
                )?;
                for (value, what) in [
                    (&gp.user, "user"),
                    (&gp.portal, "portal"),
                    (&gp.domain, "domain"),
                    (&gp.client.os_version, "OS version"),
                    (&gp.client.computer, "computer name"),
                    (&gp.client.host_id, "host id"),
                ] {
                    check(printable(value, 256), what)?;
                }
                for ip in [&gp.preferred_ip, &gp.preferred_ipv6].into_iter().flatten() {
                    check(ip.parse::<std::net::IpAddr>().is_ok(), "preferred address")?;
                }
                if let Some(v) = &gp.client.app_version {
                    check(printable(v, 32), "app version")?;
                }
                Ok(())
            }
            Connect::FortinetSsl(forti) => {
                check(printable(&forti.profile, 128), "profile name")?;
                check_server(&forti.server, "server")?;
                check(
                    !forti.cookie.is_empty() && printable(forti.cookie.expose(), 4096),
                    "cookie",
                )
            }
        }
    }

    pub fn profile(&self) -> &str {
        match self {
            Connect::GlobalProtect(gp) => &gp.profile,
            Connect::FortinetSsl(f) => &f.profile,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn gp() -> GpConnect {
        GpConnect {
            profile: "work".into(),
            gateway: "https://gw.example.com".into(),
            authcookie: Secret::new("FAKE0123"),
            user: "user@example.com".into(),
            portal: "portal".into(),
            domain: "example.com".into(),
            preferred_ip: Some("10.0.0.5".into()),
            preferred_ipv6: None,
            client: ClientFacts {
                os: ClientOs::Windows,
                os_version: "Microsoft Windows 11 Pro , 64-bit".into(),
                computer: "WORKSTATION-1".into(),
                host_id: "00000000-0000-4000-8000-000000000001".into(),
                app_version: None,
            },
            allow_esp: true,
        }
    }

    #[test]
    fn frames_round_trip() {
        let request = Request::Connect {
            connect: Connect::GlobalProtect(Box::new(gp())),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &request).unwrap();
        assert_eq!(
            u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize,
            buf.len() - 4
        );
        let back: Request = read_frame(&mut Cursor::new(buf)).unwrap();
        assert_eq!(back, request);
    }

    #[test]
    fn oversized_unknown_and_truncated_frames_are_rejected() {
        let mut huge = (MAX_FRAME as u32 + 1).to_be_bytes().to_vec();
        huge.extend(vec![b' '; 16]);
        assert!(read_frame::<_, Request>(&mut Cursor::new(huge)).is_err());

        let body = br#"{"type":"status","extra":1}"#;
        let mut framed = (body.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(body);
        assert!(read_frame::<_, Request>(&mut Cursor::new(framed)).is_err());

        let mut short = 10u32.to_be_bytes().to_vec();
        short.extend_from_slice(b"{}");
        assert!(read_frame::<_, Request>(&mut Cursor::new(short)).is_err());
    }

    #[test]
    fn connect_requests_are_validated() {
        assert_eq!(Connect::GlobalProtect(Box::new(gp())).validate(), Ok(()));
        let bad = |edit: fn(&mut GpConnect)| {
            let mut c = gp();
            edit(&mut c);
            Connect::GlobalProtect(Box::new(c)).validate().is_err()
        };
        assert!(bad(|c| c.gateway = "-oProxyCommand".into()));
        assert!(bad(|c| c.gateway = "https://gw.example.com/path".into()));
        assert!(bad(|c| c.gateway = "http://gw.example.com".into()));
        assert!(bad(|c| c.authcookie = Secret::new("a\r\nInjected: 1")));
        assert!(bad(|c| c.authcookie = Secret::new("")));
        assert!(bad(|c| c.authcookie = Secret::new("x".repeat(5000))));
        assert!(bad(|c| c.user = "line\nbreak".into()));
        assert!(bad(|c| c.preferred_ip = Some("not-an-ip".into())));
        let forti = Connect::FortinetSsl(FortiConnect {
            profile: "office".into(),
            server: "https://vpn.example.net:10443".into(),
            cookie: Secret::new("FAKE+cookie=="),
        });
        assert_eq!(forti.validate(), Ok(()));
    }

    #[test]
    fn status_serializes_with_a_state_tag() {
        let json = serde_json::to_string(&Response::Status {
            status: Status::Connecting {
                profile: "work".into(),
            },
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"type":"status","status":{"state":"connecting","profile":"work"}}"#
        );
    }
}
