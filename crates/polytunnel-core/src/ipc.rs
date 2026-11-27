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
use crate::profile::{
    ClientOs, LocalIdType, ModeConfigStyle, normalize_server, parse_ipv4_network, valid_host,
};

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
    Hello {
        version: u32,
    },
    // Empty struct variants (not unit variants) so unknown fields are rejected too.
    Status {},
    Connect {
        connect: Connect,
    },
    Disconnect {},
    /// Answers a [`Status::NeedsInput`] prompt (one value per field).
    Answer {
        id: u32,
        values: Vec<Secret>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Connect {
    GlobalProtect(Box<GpConnect>),
    FortinetSsl(FortiConnect),
    FortinetIpsec(Box<IpsecConnect>),
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

/// A FortiGate dial-up IPsec tunnel to negotiate (the daemon runs IKE itself).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpsecConnect {
    pub profile: String,
    /// Host name or IPv4 address of the FortiGate.
    pub server: String,
    pub psk: Secret,
    /// Username and password for XAuth; `None` when the tunnel does not use XAuth.
    pub xauth: Option<XauthLogin>,
    pub local_id: Option<String>,
    pub local_id_type: LocalIdType,
    /// Phase-1 proposals, `aes256-sha256-modp2048` style.
    pub ike_proposals: Vec<String>,
    /// Phase-2 proposals, `aes256-sha256` or `aes256gcm16` style.
    pub esp_proposals: Vec<String>,
    pub pfs_group: Option<u16>,
    pub ike_lifetime: u32,
    pub esp_lifetime: u32,
    pub esp_lifetime_kb: Option<u32>,
    pub mode_config: ModeConfigStyle,
    /// `a.b.c.d/len`; `None` for everything.
    pub remote_network: Option<String>,
    /// Seconds; 0 is off.
    pub dpd: u32,
    /// Seconds; 0 is off.
    pub nat_keepalive: u32,
    /// Sent to the gateway as the application version.
    pub client_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XauthLogin {
    pub username: String,
    pub password: Secret,
}

/// Something the daemon needs from the user while connecting (a one-time code, ...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prompt {
    pub id: u32,
    pub message: Option<String>,
    pub fields: Vec<PromptField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptField {
    pub label: String,
    /// Typed without echo.
    pub secret: bool,
}

/// DH groups Polytunnel's IKE supports.
pub const IKE_GROUPS: [u16; 7] = [2, 5, 14, 15, 16, 19, 20];

/// The proposal-string name of an IKE group: 14 is `modp2048`.
pub fn ike_group_name(id: u16) -> Option<&'static str> {
    Some(match id {
        2 => "modp1024",
        5 => "modp1536",
        14 => "modp2048",
        15 => "modp3072",
        16 => "modp4096",
        19 => "ecp256",
        20 => "ecp384",
        _ => return None,
    })
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
    /// Connecting, and waiting for the user: answer with [`Request::Answer`].
    NeedsInput {
        profile: String,
        prompt: Prompt,
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

/// Printable ASCII only: no control characters or line breaks.
fn printable(value: &str, max: usize) -> bool {
    value.len() <= max && value.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// Any text without control characters (passwords and codes may be non-ASCII).
fn no_controls(value: &str, max: usize) -> bool {
    value.len() <= max && !value.chars().any(char::is_control)
}

/// Checks the values of a [`Request::Answer`].
pub fn validate_answer(values: &[Secret]) -> Result<(), String> {
    check(
        values.len() <= 8 && values.iter().all(|v| no_controls(v.expose(), 256)),
        "answer",
    )
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
            Connect::FortinetIpsec(c) => c.validate(),
        }
    }

    pub fn profile(&self) -> &str {
        match self {
            Connect::GlobalProtect(gp) => &gp.profile,
            Connect::FortinetSsl(f) => &f.profile,
            Connect::FortinetIpsec(c) => &c.profile,
        }
    }
}

impl IpsecConnect {
    fn validate(&self) -> Result<(), String> {
        check(printable(&self.profile, 128), "profile name")?;
        check(valid_host(&self.server), "server")?;
        check(
            !self.psk.is_empty() && no_controls(self.psk.expose(), 256),
            "pre-shared key",
        )?;
        if let Some(x) = &self.xauth {
            check(printable(&x.username, 256), "username")?;
            check(no_controls(x.password.expose(), 256), "password")?;
        }
        if let Some(id) = &self.local_id {
            check(!id.is_empty() && printable(id, 256), "local ID")?;
            if self.local_id_type == LocalIdType::Ipv4 {
                check(id.parse::<std::net::Ipv4Addr>().is_ok(), "local ID")?;
            }
        }
        let proposal = |p: &String| {
            !p.is_empty()
                && p.len() <= 40
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        for (list, what) in [
            (&self.ike_proposals, "IKE proposals"),
            (&self.esp_proposals, "ESP proposals"),
        ] {
            check(
                !list.is_empty() && list.len() <= 16 && list.iter().all(proposal),
                what,
            )?;
        }
        if let Some(g) = self.pfs_group {
            check(IKE_GROUPS.contains(&g), "PFS group")?;
        }
        check((120..=172_800).contains(&self.ike_lifetime), "IKE lifetime")?;
        check((60..=172_800).contains(&self.esp_lifetime), "ESP lifetime")?;
        if let Some(kb) = self.esp_lifetime_kb {
            check(kb >= 1024, "ESP lifetime (KB)")?;
        }
        if let Some(net) = &self.remote_network {
            check(parse_ipv4_network(net).is_some(), "remote network")?;
        }
        check(
            self.dpd == 0 || (5..=3600).contains(&self.dpd),
            "DPD interval",
        )?;
        check(self.nat_keepalive <= 300, "NAT keepalive")?;
        check(printable(&self.client_version, 64), "client version")
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

    fn ipsec() -> IpsecConnect {
        IpsecConnect {
            profile: "office".into(),
            server: "vpn.example.net".into(),
            psk: Secret::new(["shared", "key"].join("-")),
            xauth: Some(XauthLogin {
                username: "user".into(),
                password: Secret::new(["p", "\u{e4}", "ss"].concat()),
            }),
            local_id: Some("laptop".into()),
            local_id_type: LocalIdType::Fqdn,
            ike_proposals: vec!["aes256-sha256-modp2048".into()],
            esp_proposals: vec!["aes256-sha256".into(), "aes128gcm16".into()],
            pfs_group: Some(14),
            ike_lifetime: 86_400,
            esp_lifetime: 43_200,
            esp_lifetime_kb: None,
            mode_config: ModeConfigStyle::Pull,
            remote_network: None,
            dpd: 20,
            nat_keepalive: 5,
            client_version: "Polytunnel 0.1.0".into(),
        }
    }

    #[test]
    fn ipsec_requests_are_validated() {
        let ok = |c: IpsecConnect| Connect::FortinetIpsec(Box::new(c)).validate();
        assert_eq!(ok(ipsec()), Ok(()));
        let bad = |edit: fn(&mut IpsecConnect)| {
            let mut c = ipsec();
            edit(&mut c);
            ok(c).is_err()
        };
        assert!(bad(|c| c.server = "https://vpn.example.net".into()));
        assert!(bad(|c| c.server = "-o".into()));
        assert!(bad(|c| c.psk = Secret::new("")));
        assert!(bad(|c| c.psk = Secret::new("line\nbreak")));
        assert!(bad(|c| c.ike_proposals = vec!["aes256; rm".into()]));
        assert!(bad(|c| c.esp_proposals.clear()));
        assert!(bad(|c| c.pfs_group = Some(1)));
        assert!(bad(|c| c.ike_lifetime = 10));
        assert!(bad(|c| c.remote_network = Some("10.0.0.0".into())));
        assert!(bad(|c| c.dpd = 2));
        assert!(bad(|c| c.local_id_type = LocalIdType::Ipv4));
        assert_eq!(validate_answer(&[Secret::new("123456")]), Ok(()));
        assert!(validate_answer(&[Secret::new("12\r\n")]).is_err());
    }

    #[test]
    fn prompts_round_trip() {
        let status = Status::NeedsInput {
            profile: "office".into(),
            prompt: Prompt {
                id: 3,
                message: Some("Enter your token code".into()),
                fields: vec![PromptField {
                    label: "Passcode".into(),
                    secret: true,
                }],
            },
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.starts_with(r#"{"state":"needs-input""#), "{json}");
        assert_eq!(serde_json::from_str::<Status>(&json).unwrap(), status);
        let answer = Request::Answer {
            id: 3,
            values: vec![Secret::new("246810")],
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &answer).unwrap();
        assert_eq!(
            read_frame::<_, Request>(&mut Cursor::new(buf)).unwrap(),
            answer
        );
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
