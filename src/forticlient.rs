//! Importing connection profiles from an installed FortiClient (Windows).
//!
//! Only non-secret settings are read: the tunnel name and server address (SSL VPN) and the
//! gateway and IKE settings (IPsec). FortiClient stores passwords and pre-shared keys
//! encrypted; Polytunnel never reads them. The user types them once and they go to the
//! operating system's keyring.

use polytunnel_core::profile::FortinetSslProfile;

/// An SSL VPN tunnel as configured in FortiClient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedSsl {
    pub name: String,
    pub profile: FortinetSslProfile,
}

/// The first `host:port` of FortiClient's `Server` value (`a:10443;b:10443`).
pub fn first_server(value: &str) -> Option<String> {
    value
        .split(';')
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_string)
}

/// A FortiClient tunnel name made safe as a profile name.
pub fn profile_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    if trimmed.is_empty() {
        "fortinet".into()
    } else {
        trimmed.to_string()
    }
}

#[cfg(windows)]
pub fn ssl_tunnels() -> Vec<ImportedSsl> {
    use crate::win::{Hive, reg_get_string, reg_subkeys};

    const BASE: &str = r"SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels";
    reg_subkeys(Hive::LocalMachine, BASE)
        .into_iter()
        .filter_map(|tunnel| {
            let server = reg_get_string(Hive::LocalMachine, &format!(r"{BASE}\{tunnel}"), "Server")
                .as_deref()
                .and_then(first_server)?;
            Some(ImportedSsl {
                name: profile_name(&tunnel),
                profile: FortinetSslProfile {
                    server,
                    username: None,
                    realm: None,
                },
            })
        })
        .collect()
}

#[cfg(not(windows))]
pub fn ssl_tunnels() -> Vec<ImportedSsl> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers_and_names() {
        assert_eq!(
            first_server(" 192.0.2.10:10443;198.51.100.10:10443").as_deref(),
            Some("192.0.2.10:10443")
        );
        assert_eq!(first_server(";;"), None);
        assert_eq!(profile_name("OFFICE VPN (main)"), "office-vpn--main");
        assert_eq!(profile_name("***"), "fortinet");
    }
}
