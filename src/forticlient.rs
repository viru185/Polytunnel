//! Importing connection profiles from an installed FortiClient (Windows).
//!
//! Only non-secret settings are read: the tunnel name and server address (SSL VPN) and the
//! gateway and IKE settings (IPsec). FortiClient stores passwords and pre-shared keys
//! encrypted; Polytunnel never reads them. The user types them when connecting.

use std::net::Ipv4Addr;

use polytunnel_core::profile::{FortinetIpsecProfile, FortinetSslProfile, valid_host};

use crate::ipsec::{
    DEFAULT_DH_GROUP, DEFAULT_ESP_LIFETIME, DEFAULT_IKE_LIFETIME, DEFAULT_NAT_KEEPALIVE,
};

/// An SSL VPN tunnel as configured in FortiClient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedSsl {
    pub name: String,
    pub profile: FortinetSslProfile,
}

/// An IPsec tunnel as configured in FortiClient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedIpsec {
    pub name: String,
    pub profile: FortinetIpsecProfile,
}

/// The IPsec tunnels Polytunnel can use, and why the others were left out.
#[derive(Debug, Default)]
pub struct IpsecImport {
    pub tunnels: Vec<ImportedIpsec>,
    pub skipped: Vec<String>,
}

/// Every `host:port` of FortiClient's `Server` value (`a:10443;b:10443`), in order.
pub fn servers(value: &str) -> Vec<String> {
    value
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
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

/// The non-secret registry values of one FortiClient IPsec tunnel (`P1` and `P2` keys).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpsecValues {
    pub remote_gw: Option<String>,
    pub user: Option<String>,
    pub local_id: Option<String>,
    pub ike_version: Option<u32>,
    pub aggressive: Option<u32>,
    pub auth_method: Option<u32>,
    pub xauth: Option<u32>,
    pub mode_config: Option<u32>,
    pub p1_dh_groups: Option<u32>,
    pub p1_key_life: Option<u32>,
    pub dpd: Option<u32>,
    pub nat_alive_freq: Option<u32>,
    pub p2_dh_groups: Option<u32>,
    pub p2_key_life_type: Option<u32>,
    pub p2_key_life_sec: Option<u32>,
    pub p2_key_life_kb: Option<u32>,
    pub remote_ip: Option<String>,
    pub remote_mask: Option<String>,
}

/// FortiClient keeps its DH group choices as a bit set, in the order its settings list them
/// (bit 0 is group 1, bit 3 is group 14, ...). The import shows the group it picked so it can
/// be checked.
const DH_ORDER: [u16; 11] = [1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21];

/// The first group in FortiClient's bit set that Polytunnel supports.
pub fn dh_group_from_mask(mask: u32) -> Option<u16> {
    DH_ORDER
        .iter()
        .enumerate()
        .filter(|(bit, _)| mask & (1 << bit) != 0)
        .map(|(_, group)| *group)
        .find(|g| polytunnel_core::ipc::ike_group_name(*g).is_some())
}

/// Turns one tunnel's values into a profile, or says why it cannot be used.
pub fn ipsec_profile(v: &IpsecValues) -> Result<FortinetIpsecProfile, String> {
    let version = v.ike_version.unwrap_or(1);
    if !matches!(version, 1 | 2) {
        return Err(format!("uses IKE version {version}"));
    }
    if version == 1 && v.aggressive.unwrap_or(1) == 0 {
        return Err("uses main mode; Polytunnel supports aggressive mode".into());
    }
    if v.auth_method.unwrap_or(1) != 1 {
        return Err("signs in with a certificate; Polytunnel supports pre-shared keys".into());
    }
    if v.mode_config.unwrap_or(1) == 0 {
        return Err("has a fixed address instead of mode-config, which Polytunnel needs".into());
    }
    let mut gateways = v
        .remote_gw
        .as_deref()
        .map(servers)
        .unwrap_or_default()
        .into_iter()
        .filter(|s| valid_host(s));
    let server = gateways.next().ok_or("has no usable remote gateway")?;
    let backup_servers: Vec<String> = gateways.collect();
    let group = match v.p1_dh_groups {
        Some(mask) => {
            dh_group_from_mask(mask).ok_or("uses DH groups Polytunnel does not support")?
        }
        None => DEFAULT_DH_GROUP,
    };
    let pfs_group = match v.p2_dh_groups {
        Some(0) => Some(0),
        Some(mask) => match dh_group_from_mask(mask) {
            Some(g) if g == group => None,
            Some(g) => Some(g),
            None => return Err("uses a PFS group Polytunnel does not support".into()),
        },
        None => None,
    };
    let text = |s: &Option<String>| {
        s.clone()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let differs = |value: Option<u32>, default: u32| value.filter(|v| *v != default);
    Ok(FortinetIpsecProfile {
        server,
        backup_servers,
        username: text(&v.user),
        local_id: text(&v.local_id),
        dh_group: (group != DEFAULT_DH_GROUP).then_some(group),
        pfs_group,
        ike_lifetime: differs(v.p1_key_life, DEFAULT_IKE_LIFETIME),
        esp_lifetime: differs(v.p2_key_life_sec, DEFAULT_ESP_LIFETIME),
        esp_lifetime_kb: v.p2_key_life_type.filter(|t| *t != 0).and(v.p2_key_life_kb),
        xauth: (version == 1 && v.xauth == Some(0)).then_some(false),
        ike_version: (version == 2).then_some(2),
        dpd: (v.dpd == Some(0)).then_some(0),
        nat_keepalive: differs(v.nat_alive_freq, DEFAULT_NAT_KEEPALIVE),
        remote_network: remote_network(v.remote_ip.as_deref(), v.remote_mask.as_deref()),
        ..Default::default()
    })
}

/// FortiClient's phase-2 destination (`DIP`/`DMASK`) as `a.b.c.d/len`; `None` for everything.
fn remote_network(ip: Option<&str>, mask: Option<&str>) -> Option<String> {
    let ip: Ipv4Addr = ip?.trim().parse().ok()?;
    let mask = u32::from(mask?.trim().parse::<Ipv4Addr>().ok()?);
    if mask.leading_ones() + mask.trailing_zeros() != 32 || mask == 0 {
        return None;
    }
    let len = mask.leading_ones();
    let net = Ipv4Addr::from(u32::from(ip) & mask);
    Some(format!("{net}/{len}"))
}

#[cfg(windows)]
pub fn ssl_tunnels() -> Vec<ImportedSsl> {
    use crate::win::{Hive, reg_get_string, reg_subkeys};

    const BASE: &str = r"SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels";
    reg_subkeys(Hive::LocalMachine, BASE)
        .into_iter()
        .filter_map(|tunnel| {
            let mut gateways = servers(&reg_get_string(
                Hive::LocalMachine,
                &format!(r"{BASE}\{tunnel}"),
                "Server",
            )?)
            .into_iter();
            let server = gateways.next()?;
            Some(ImportedSsl {
                name: profile_name(&tunnel),
                profile: FortinetSslProfile {
                    server,
                    backup_servers: gateways.collect(),
                    ..Default::default()
                },
            })
        })
        .collect()
}

#[cfg(windows)]
pub fn ipsec_tunnels() -> IpsecImport {
    use crate::win::{Hive, reg_get_dword, reg_get_string, reg_subkeys};

    const BASE: &str = r"SOFTWARE\Fortinet\FortiClient\IPSec\Tunnels";
    let mut out = IpsecImport::default();
    for tunnel in reg_subkeys(Hive::LocalMachine, BASE) {
        let p1 = format!(r"{BASE}\{tunnel}\P1");
        let p2 = format!(r"{BASE}\{tunnel}\P2");
        let s = |key: &str, name: &str| reg_get_string(Hive::LocalMachine, key, name);
        let d = |key: &str, name: &str| reg_get_dword(Hive::LocalMachine, key, name);
        // Never AuthKey (the encrypted pre-shared key) or any password.
        let values = IpsecValues {
            remote_gw: s(&p1, "RemoteGW"),
            user: s(&p1, "User"),
            local_id: s(&p1, "LocalID"),
            ike_version: d(&p1, "ikeversion"),
            aggressive: d(&p1, "Aggressive"),
            auth_method: d(&p1, "AuthMethod"),
            xauth: d(&p1, "XAuth"),
            mode_config: d(&p1, "Modecfg"),
            p1_dh_groups: d(&p1, "DHGroup"),
            p1_key_life: d(&p1, "KeyLife"),
            dpd: d(&p1, "DPD"),
            nat_alive_freq: d(&p1, "NatAliveFreq"),
            p2_dh_groups: d(&p2, "DHGroup"),
            p2_key_life_type: d(&p2, "KeyLifeType"),
            p2_key_life_sec: d(&p2, "KeyLifeSec"),
            p2_key_life_kb: d(&p2, "KeyLifeKB"),
            remote_ip: s(&p2, "DIP"),
            remote_mask: s(&p2, "DMASK"),
        };
        match ipsec_profile(&values) {
            Ok(profile) => out.tunnels.push(ImportedIpsec {
                name: profile_name(&tunnel),
                profile,
            }),
            Err(why) => out.skipped.push(format!(
                "Skipped the FortiClient IPsec tunnel '{tunnel}': it {why}."
            )),
        }
    }
    out
}

#[cfg(not(windows))]
pub fn ssl_tunnels() -> Vec<ImportedSsl> {
    Vec::new()
}

#[cfg(not(windows))]
pub fn ipsec_tunnels() -> IpsecImport {
    IpsecImport::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers_and_names() {
        assert_eq!(
            servers(" 192.0.2.10:10443;198.51.100.10:10443"),
            ["192.0.2.10:10443", "198.51.100.10:10443"]
        );
        assert!(servers(";;").is_empty());
        assert_eq!(profile_name("OFFICE VPN (main)"), "office-vpn--main");
        assert_eq!(profile_name("***"), "fortinet");
    }

    fn typical() -> IpsecValues {
        // A FortiClient dial-up tunnel: IKEv1 aggressive, pre-shared key, XAuth, mode-config,
        // DH group 14 in both phases, DPD on, NAT keepalive every 5 s.
        IpsecValues {
            remote_gw: Some("vpn.example.net".into()),
            user: Some(String::new()),
            local_id: Some(String::new()),
            ike_version: Some(1),
            aggressive: Some(1),
            auth_method: Some(1),
            xauth: Some(1),
            mode_config: Some(1),
            p1_dh_groups: Some(8),
            p1_key_life: Some(86_400),
            dpd: Some(1),
            nat_alive_freq: Some(5),
            p2_dh_groups: Some(8),
            p2_key_life_type: Some(0),
            p2_key_life_sec: Some(43_200),
            p2_key_life_kb: Some(5120),
            remote_ip: Some("0.0.0.0".into()),
            remote_mask: Some("0.0.0.0".into()),
        }
    }

    #[test]
    fn a_typical_tunnel_imports_with_defaults_only() {
        assert_eq!(
            ipsec_profile(&typical()),
            Ok(FortinetIpsecProfile {
                server: "vpn.example.net".into(),
                ..Default::default()
            })
        );
    }

    #[test]
    fn every_remote_gateway_is_imported_in_order() {
        let v = IpsecValues {
            remote_gw: Some("vpn.example.net; 198.51.100.10 ;not a host".into()),
            ..typical()
        };
        let p = ipsec_profile(&v).unwrap();
        assert_eq!(p.server, "vpn.example.net");
        assert_eq!(p.backup_servers, ["198.51.100.10"]);
    }

    #[test]
    fn non_default_settings_are_kept() {
        let v = IpsecValues {
            user: Some("me".into()),
            local_id: Some("laptop".into()),
            p1_dh_groups: Some(4),     // group 5
            p2_dh_groups: Some(0),     // no PFS
            p2_key_life_type: Some(2), // seconds and kilobytes
            xauth: Some(0),
            dpd: Some(0),
            nat_alive_freq: Some(10),
            remote_ip: Some("198.51.100.0".into()),
            remote_mask: Some("255.255.255.0".into()),
            ..typical()
        };
        let p = ipsec_profile(&v).unwrap();
        assert_eq!(p.username.as_deref(), Some("me"));
        assert_eq!(p.local_id.as_deref(), Some("laptop"));
        assert_eq!(p.dh_group, Some(5));
        assert_eq!(p.pfs_group, Some(0));
        assert_eq!(p.esp_lifetime_kb, Some(5120));
        assert_eq!(p.xauth, Some(false));
        assert_eq!(p.dpd, Some(0));
        assert_eq!(p.nat_keepalive, Some(10));
        assert_eq!(p.remote_network.as_deref(), Some("198.51.100.0/24"));
    }

    #[test]
    fn unusable_tunnels_say_why() {
        for (v, why) in [
            (
                IpsecValues {
                    ike_version: Some(3),
                    ..typical()
                },
                "IKE version",
            ),
            (
                IpsecValues {
                    aggressive: Some(0),
                    ..typical()
                },
                "main mode",
            ),
            (
                IpsecValues {
                    auth_method: Some(2),
                    ..typical()
                },
                "certificate",
            ),
            (
                IpsecValues {
                    mode_config: Some(0),
                    ..typical()
                },
                "mode-config",
            ),
            (
                IpsecValues {
                    remote_gw: None,
                    ..typical()
                },
                "gateway",
            ),
            (
                IpsecValues {
                    p1_dh_groups: Some(1),
                    ..typical()
                },
                "DH groups",
            ),
        ] {
            let err = ipsec_profile(&v).unwrap_err();
            assert!(err.contains(why), "{err}");
        }
    }

    #[test]
    fn ikev2_tunnels_import_as_ikev2() {
        let p = ipsec_profile(&IpsecValues {
            ike_version: Some(2),
            aggressive: Some(0),
            ..typical()
        })
        .unwrap();
        assert_eq!(p.ike_version, Some(2));
    }

    #[test]
    fn dh_bit_sets() {
        assert_eq!(dh_group_from_mask(8), Some(14));
        assert_eq!(dh_group_from_mask(4), Some(5));
        assert_eq!(
            dh_group_from_mask(1 | 8),
            Some(14),
            "group 1 is not supported"
        );
        assert_eq!(dh_group_from_mask(1 << 8), Some(19));
        assert_eq!(dh_group_from_mask(1), None);
    }
}
