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
}

impl Profile {
    pub fn kind(&self) -> &'static str {
        match self {
            Profile::GlobalProtect(_) => "GlobalProtect",
            Profile::FortinetSsl(_) => "Fortinet SSL VPN",
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
