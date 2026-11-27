//! Fortinet IPsec profiles: the request the service negotiates (IKE runs in the service, so
//! there is no separate login step here, only the secrets).

use polytunnel_core::Secret;
use polytunnel_core::ipc::{Connect, IpsecConnect, XauthLogin, ike_group_name};
use polytunnel_core::profile::{FortinetIpsecProfile, parse_ipv4_network, valid_host};

pub const DEFAULT_DH_GROUP: u16 = 14;
pub const DEFAULT_IKE_LIFETIME: u32 = 86_400;
pub const DEFAULT_ESP_LIFETIME: u32 = 43_200;
pub const DEFAULT_DPD: u32 = 20;
pub const DEFAULT_NAT_KEEPALIVE: u32 = 5;

/// FortiGate's dial-up proposals (cipher-hash; the group is added from `dh-group`).
const DEFAULT_IKE: [&str; 4] = [
    "aes256-sha256",
    "aes128-sha256",
    "aes256-sha1",
    "aes128-sha1",
];
const DEFAULT_ESP: [&str; 6] = [
    "aes256-sha256",
    "aes128-sha256",
    "aes256-sha1",
    "aes128-sha1",
    "aes256gcm16",
    "aes128gcm16",
];

/// What the user types for an IPsec connection.
pub struct Secrets {
    pub psk: Secret,
    /// Username and password, when the tunnel uses XAuth.
    pub xauth: Option<(String, Secret)>,
}

/// Whether the profile signs in with XAuth (username and password).
pub fn uses_xauth(p: &FortinetIpsecProfile) -> bool {
    p.xauth.unwrap_or(true)
}

/// The gateway's host name or address, from what the user typed.
pub fn server_host(p: &FortinetIpsecProfile) -> Result<String, String> {
    let host = p.server.trim();
    if valid_host(host) {
        Ok(host.to_ascii_lowercase())
    } else {
        Err(format!(
            "'{}' is not a host name or IPv4 address (IPsec servers have no scheme or port)",
            p.server
        ))
    }
}

/// The service request for an IPsec profile.
pub fn connect_request(
    name: String,
    p: &FortinetIpsecProfile,
    secrets: Secrets,
) -> Result<Connect, String> {
    let server = server_host(p)?;
    let group = p.dh_group.unwrap_or(DEFAULT_DH_GROUP);
    let group_name =
        ike_group_name(group).ok_or_else(|| format!("DH group {group} is not supported"))?;
    let ike_proposals = match &p.ike_proposals {
        Some(list) => list.clone(),
        None => DEFAULT_IKE.iter().map(|s| s.to_string()).collect(),
    }
    .into_iter()
    .map(|s| {
        let s = s.trim().to_ascii_lowercase();
        // Accept a full `cipher-hash-group` too, as long as the group matches.
        match s.matches('-').count() {
            1 => Ok(format!("{s}-{group_name}")),
            2 if s.ends_with(group_name) => Ok(s),
            _ => Err(format!(
                "IKE proposal '{s}' must be cipher-hash (the group comes from dh-group)"
            )),
        }
    })
    .collect::<Result<Vec<_>, _>>()?;
    let esp_proposals = match &p.esp_proposals {
        Some(list) => list.iter().map(|s| s.trim().to_ascii_lowercase()).collect(),
        None => DEFAULT_ESP.iter().map(|s| s.to_string()).collect(),
    };
    let pfs_group = match p.pfs_group {
        Some(0) => None,
        Some(g) => Some(g),
        None => Some(group),
    };
    if let Some(net) = &p.remote_network
        && parse_ipv4_network(net).is_none()
    {
        return Err(format!("remote-network '{net}' is not a.b.c.d/len"));
    }
    let xauth = match (uses_xauth(p), secrets.xauth) {
        (true, Some((username, password))) => Some(XauthLogin { username, password }),
        (true, None) => return Err("this profile needs a username and password".into()),
        (false, _) => None,
    };
    let request = IpsecConnect {
        profile: name,
        server,
        psk: secrets.psk,
        xauth,
        local_id: p.local_id.clone().filter(|s| !s.trim().is_empty()),
        local_id_type: p.local_id_type.unwrap_or_default(),
        ike_proposals,
        esp_proposals,
        pfs_group,
        ike_lifetime: p.ike_lifetime.unwrap_or(DEFAULT_IKE_LIFETIME),
        esp_lifetime: p.esp_lifetime.unwrap_or(DEFAULT_ESP_LIFETIME),
        esp_lifetime_kb: p.esp_lifetime_kb,
        mode_config: p.mode_config.unwrap_or_default(),
        remote_network: p.remote_network.clone(),
        dpd: p.dpd.unwrap_or(DEFAULT_DPD),
        nat_keepalive: p.nat_keepalive.unwrap_or(DEFAULT_NAT_KEEPALIVE),
        client_version: format!("Polytunnel {}", polytunnel_core::VERSION),
    };
    let connect = Connect::FortinetIpsec(Box::new(request));
    connect.validate()?;
    Ok(connect)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets() -> Secrets {
        Secrets {
            psk: Secret::new(["shared", "key"].join("-")),
            xauth: Some(("user".into(), Secret::new(["pass", "word"].concat()))),
        }
    }

    #[test]
    fn defaults_follow_fortigate_dial_up() {
        let p = FortinetIpsecProfile {
            server: " VPN.example.net ".into(),
            ..Default::default()
        };
        let Connect::FortinetIpsec(c) = connect_request("office".into(), &p, secrets()).unwrap()
        else {
            panic!("not IPsec");
        };
        assert_eq!(c.server, "vpn.example.net");
        assert_eq!(c.ike_proposals[0], "aes256-sha256-modp2048");
        assert_eq!(c.ike_proposals.len(), 4);
        assert_eq!(c.esp_proposals.len(), 6);
        assert_eq!(c.pfs_group, Some(14));
        assert_eq!((c.ike_lifetime, c.esp_lifetime), (86_400, 43_200));
        assert_eq!((c.dpd, c.nat_keepalive), (20, 5));
        assert!(c.xauth.is_some());
    }

    #[test]
    fn profile_settings_and_mistakes() {
        let p = FortinetIpsecProfile {
            server: "203.0.113.7".into(),
            dh_group: Some(5),
            ike_proposals: Some(vec!["aes128-sha1".into(), "aes128-sha1-modp1536".into()]),
            pfs_group: Some(0),
            xauth: Some(false),
            ..Default::default()
        };
        let Connect::FortinetIpsec(c) = connect_request("x".into(), &p, secrets()).unwrap() else {
            panic!("not IPsec");
        };
        assert_eq!(c.ike_proposals, vec!["aes128-sha1-modp1536"; 2]);
        assert_eq!(c.pfs_group, None);
        assert!(c.xauth.is_none());

        let wrong_group = FortinetIpsecProfile {
            ike_proposals: Some(vec!["aes128-sha1-modp2048".into()]),
            ..p.clone()
        };
        assert!(connect_request("x".into(), &wrong_group, secrets()).is_err());
        for bad in [
            FortinetIpsecProfile {
                server: "https://vpn.example.net".into(),
                ..Default::default()
            },
            FortinetIpsecProfile {
                server: "vpn.example.net".into(),
                dh_group: Some(1),
                ..Default::default()
            },
            FortinetIpsecProfile {
                server: "vpn.example.net".into(),
                remote_network: Some("10.0.0.0".into()),
                ..Default::default()
            },
        ] {
            assert!(
                connect_request("x".into(), &bad, secrets()).is_err(),
                "{bad:?}"
            );
        }
        let no_login = Secrets {
            psk: Secret::new("k"),
            xauth: None,
        };
        let xauth_profile = FortinetIpsecProfile {
            server: "vpn.example.net".into(),
            ..Default::default()
        };
        assert!(connect_request("x".into(), &xauth_profile, no_login).is_err());
    }
}
