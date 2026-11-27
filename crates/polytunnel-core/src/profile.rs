//! Connection profiles, stored in `profiles.toml` in the user's config directory.
//!
//! ```toml
//! [profile.work]
//! type = "global-protect"
//! portal = "vpn.example.com"
//!
//! [profile.office]
//! type = "fortinet-ssl"
//! server = "vpn.example.net:10443"
//! username = "user"
//!
//! [profile.office-ipsec]
//! type = "fortinet-ipsec"
//! server = "vpn.example.net"
//! dh-group = 14
//! ```
//!
//! Secrets are never stored here: they live in the operating system's keyring.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// The operating system reported to a VPN server. Polytunnel reports the real one unless a
/// profile explicitly overrides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientOs {
    Windows,
    Mac,
    Linux,
}

impl ClientOs {
    /// The OS this binary runs on.
    pub fn current() -> Self {
        if cfg!(windows) {
            ClientOs::Windows
        } else if cfg!(target_os = "macos") {
            ClientOs::Mac
        } else {
            ClientOs::Linux
        }
    }

    /// The value GlobalProtect expects in `clientos`.
    pub fn gp_name(self) -> &'static str {
        match self {
            ClientOs::Windows => "Windows",
            ClientOs::Mac => "Mac",
            ClientOs::Linux => "Linux",
        }
    }

    /// The matching openconnect `--os` value.
    pub fn openconnect_name(self) -> &'static str {
        match self {
            ClientOs::Windows => "win",
            ClientOs::Mac => "mac-intel",
            ClientOs::Linux => "linux",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Profile {
    GlobalProtect(GlobalProtectProfile),
    FortinetSsl(FortinetSslProfile),
    FortinetIpsec(FortinetIpsecProfile),
}

impl Profile {
    pub fn kind(&self) -> &'static str {
        match self {
            Profile::GlobalProtect(_) => "GlobalProtect",
            Profile::FortinetSsl(_) => "Fortinet SSL VPN",
            Profile::FortinetIpsec(_) => "Fortinet IPsec",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct GlobalProtectProfile {
    /// Portal address: `vpn.example.com`, `vpn.example.com:8443` or an `https://` URL.
    pub portal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Gateway to use (name or address). Empty: pick the best one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// Override the reported OS (default: the real one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_os: Option<ClientOs>,
    /// Report this GlobalProtect app version (`clientgpversion`). Unset by default: some
    /// portals require it, but sending it means claiming to be that app version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
    /// Gateway to prefer when it answers; otherwise the best one is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_gateway: Option<String>,
    /// How priority and speed are combined when picking the best gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_selection: Option<GatewayPolicy>,
    /// How gateway response times are measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<ProbeMethod>,
    /// Sign in in Polytunnel's own login window instead of the default browser.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedded_login: Option<bool>,
}

/// How priority and speed are combined when picking the best GlobalProtect gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayPolicy {
    /// Highest/High/Medium compete on speed; Low/Lowest only as a fallback (the documented
    /// behaviour of current GlobalProtect apps).
    #[default]
    Pools,
    /// Strictly by priority, then by speed.
    StrictTiers,
}

/// How gateway response times are measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeMethod {
    /// TLS handshake time (the GlobalProtect default).
    #[default]
    Tls,
    /// TCP handshake time.
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FortinetSslProfile {
    /// Server address: `vpn.example.com`, `vpn.example.com:10443` or an `https://` URL.
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
}

/// A FortiGate dial-up IPsec tunnel (IKEv1 aggressive mode, pre-shared key, XAuth,
/// mode-config), as FortiClient configures it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FortinetIpsecProfile {
    /// The FortiGate's host name or IPv4 address (IKE uses UDP 500 and 4500).
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// FortiClient's "Local ID" (the FortiGate's peer ID). Unset: our IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_id_type: Option<LocalIdType>,
    /// Diffie-Hellman group for phase 1: 2, 5, 14 (default), 15, 16, 19 or 20.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dh_group: Option<u16>,
    /// Phase-1 proposals such as `aes256-sha256` (default: FortiGate's dial-up set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ike_proposals: Option<Vec<String>>,
    /// Phase-2 proposals such as `aes256-sha256` or `aes256gcm16`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_proposals: Option<Vec<String>>,
    /// PFS group for phase 2; 0 turns PFS off. Default: the phase-1 group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pfs_group: Option<u16>,
    /// Phase-1 lifetime in seconds (default 86400).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ike_lifetime: Option<u32>,
    /// Phase-2 lifetime in seconds (default 43200).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_lifetime: Option<u32>,
    /// Also limit each phase-2 SA by traffic, in kilobytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_lifetime_kb: Option<u32>,
    /// XAuth username and password after phase 1 (default: on).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xauth: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_config: Option<ModeConfigStyle>,
    /// The remote side of the phase-2 selector, `a.b.c.d/len` (default `0.0.0.0/0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_network: Option<String>,
    /// Dead-peer detection after this many idle seconds; 0 turns it off (default 20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpd: Option<u32>,
    /// NAT keepalive interval in seconds; 0 turns it off (default 5, like FortiClient).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat_keepalive: Option<u32>,
    /// 1 (default: aggressive mode with XAuth) or 2 (IKEv2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ike_version: Option<u8>,
    /// IKEv2: sign in with EAP (`mschapv2`) instead of the pre-shared key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eap: Option<EapMethodName>,
    /// IKEv2: how the gateway proves itself, `psk` (default) or `certificate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_auth: Option<ServerAuthStyle>,
    /// IKEv2 with a certificate: a PEM file with a CA to trust besides the system's roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
    /// The name the gateway's certificate must carry (default: the server).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_id: Option<String>,
    /// IKEv2: `udp` (default) or `tcp` (RFC 9329; FortiOS "transport tcp").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<IpsecTransport>,
    /// The gateway's TCP port for `transport = "tcp"` (default 443).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_port: Option<u16>,
}

/// EAP methods for IKEv2 sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EapMethodName {
    Mschapv2,
    /// EAP-TTLS with PAP inside.
    TtlsPap,
}

/// How an IKEv2 gateway authenticates itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServerAuthStyle {
    #[default]
    Psk,
    Certificate,
}

/// How IKE and ESP reach the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpsecTransport {
    #[default]
    Udp,
    Tcp,
}

/// How the local ID is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalIdType {
    #[default]
    Fqdn,
    UserFqdn,
    KeyId,
    Ipv4,
}

/// Whether the client asks for its settings (pull) or the gateway sends them (push).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModeConfigStyle {
    #[default]
    Pull,
    Push,
}

/// `a.b.c.d/len` as an IPv4 network.
pub fn parse_ipv4_network(text: &str) -> Option<(std::net::Ipv4Addr, u8)> {
    let (addr, len) = text.trim().split_once('/')?;
    let addr: std::net::Ipv4Addr = addr.parse().ok()?;
    let len: u8 = len.parse().ok().filter(|l| *l <= 32)?;
    Some((addr, len))
}

/// The whole `profiles.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profiles {
    #[serde(default, rename = "profile")]
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError(pub String);

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProfileError {}

impl Profiles {
    pub fn parse(text: &str) -> Result<Self, ProfileError> {
        toml::from_str(text).map_err(|e| ProfileError(e.to_string()))
    }

    pub fn to_toml(&self) -> String {
        toml::to_string(self).unwrap_or_default()
    }

    pub fn get(&self, name: &str) -> Option<&Profile> {
        self.profiles.get(name)
    }
}

/// Turns `host`, `host:port` or `https://host[:port][/...]` into `https://host[:port]`.
/// Rejects other schemes, credentials in the URL and anything that is not a plain host.
pub fn normalize_server(input: &str) -> Result<String, ProfileError> {
    let trimmed = input.trim();
    let rest = match trimmed.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => rest,
        Some((scheme, _)) => {
            return Err(ProfileError(format!(
                "only https:// servers are supported, not {scheme}://"
            )));
        }
        None => trimmed,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err(ProfileError("server must not contain a username".into()));
    }
    let (host, port) = split_host_port(authority)?;
    if !valid_host(host) {
        return Err(ProfileError(format!("'{host}' is not a valid host name")));
    }
    let host = if host.contains(':') {
        format!("[{host}]") // IPv6 literal
    } else {
        host.to_ascii_lowercase()
    };
    Ok(match port {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    })
}

fn split_host_port(authority: &str) -> Result<(&str, Option<u16>), ProfileError> {
    if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6
            .split_once(']')
            .ok_or_else(|| ProfileError("unclosed '[' in server address".into()))?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(parse_port(p)?),
            None if after.is_empty() => None,
            None => return Err(ProfileError("bad server address".into())),
        };
        return Ok((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Ok((host, Some(parse_port(port)?))),
        None => Ok((authority, None)),
    }
}

fn parse_port(port: &str) -> Result<u16, ProfileError> {
    port.parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| ProfileError(format!("'{port}' is not a valid port")))
}

/// DNS names (letters, digits, `-`, `.`) or IP literals; at most 253 characters, no leading
/// `-` (so a host can never be mistaken for a command-line option).
pub fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.starts_with('-') {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_profile_types() {
        let text = r#"
[profile.work]
type = "global-protect"
portal = "vpn.example.com"
client-os = "windows"

[profile.office]
type = "fortinet-ssl"
server = "vpn.example.net:10443"
username = "user"
"#;
        let profiles = Profiles::parse(text).unwrap();
        assert_eq!(
            profiles.get("work"),
            Some(&Profile::GlobalProtect(GlobalProtectProfile {
                portal: "vpn.example.com".into(),
                client_os: Some(ClientOs::Windows),
                ..Default::default()
            }))
        );
        assert_eq!(
            profiles.get("office").map(Profile::kind),
            Some("Fortinet SSL VPN")
        );
        assert_eq!(Profiles::parse(&profiles.to_toml()).unwrap(), profiles);
    }

    #[test]
    fn parses_ipsec_profiles() {
        let text = r#"
[profile.ipsec]
type = "fortinet-ipsec"
server = "vpn.example.net"
username = "user"
local-id = "laptop"
local-id-type = "key-id"
dh-group = 5
esp-proposals = ["aes128-sha1"]
pfs-group = 0
mode-config = "push"
remote-network = "198.51.100.0/24"
nat-keepalive = 5
"#;
        let profiles = Profiles::parse(text).unwrap();
        let Some(Profile::FortinetIpsec(p)) = profiles.get("ipsec") else {
            panic!("not an IPsec profile");
        };
        assert_eq!(p.local_id_type, Some(LocalIdType::KeyId));
        assert_eq!(p.dh_group, Some(5));
        assert_eq!(p.mode_config, Some(ModeConfigStyle::Push));
        assert_eq!(p.pfs_group, Some(0));
        assert_eq!(
            parse_ipv4_network(p.remote_network.as_deref().unwrap()),
            Some(("198.51.100.0".parse().unwrap(), 24))
        );
        assert_eq!(Profiles::parse(&profiles.to_toml()).unwrap(), profiles);
        assert_eq!(parse_ipv4_network("10.0.0.0/33"), None);
        assert_eq!(parse_ipv4_network("10.0.0.0"), None);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let text =
            "[profile.x]\ntype = \"global-protect\"\nportal = \"a.example.com\"\npasword = \"x\"\n";
        assert!(Profiles::parse(text).is_err());
    }

    #[test]
    fn servers_are_normalized() {
        assert_eq!(
            normalize_server("vpn.example.com").unwrap(),
            "https://vpn.example.com"
        );
        assert_eq!(
            normalize_server("https://vpn.example.com:8443/global-protect/").unwrap(),
            "https://vpn.example.com:8443"
        );
        assert_eq!(
            normalize_server("[2001:db8::1]:443").unwrap(),
            "https://[2001:db8::1]:443"
        );
        assert_eq!(
            normalize_server("VPN.Example.COM").unwrap(),
            "https://vpn.example.com"
        );
        for bad in [
            "http://vpn.example.com",
            "user@vpn.example.com",
            "-oProxyCommand",
            "vpn.example.com:0",
            "vpn.example.com:99999",
            "bad host.example.com",
            "",
        ] {
            assert!(normalize_server(bad).is_err(), "{bad}");
        }
    }
}
