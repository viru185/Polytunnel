//! What to change in the system's network configuration for a tunnel.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::prefix::Prefix;

/// A tunnel's network settings, as received from the VPN server.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Addresses assigned to the tunnel interface (with their prefix length).
    pub addresses: Vec<Prefix>,
    pub mtu: u16,
    /// Networks to send through the tunnel. Empty: everything (full tunnel).
    pub routes: Vec<Prefix>,
    /// Networks that must stay outside the tunnel.
    pub exclude_routes: Vec<Prefix>,
    pub dns_servers: Vec<IpAddr>,
    /// DNS domains served by the tunnel's DNS servers (split DNS when routes are given).
    pub dns_domains: Vec<String>,
    /// The VPN server's addresses: always reached outside the tunnel.
    pub servers: Vec<IpAddr>,
}

impl TunnelConfig {
    pub fn is_full_tunnel(&self) -> bool {
        self.routes.is_empty() || self.routes.iter().any(Prefix::is_default)
    }

    pub fn has_ipv6(&self) -> bool {
        self.addresses.iter().any(|a| !a.is_ipv4())
    }
}

/// Where a route sends traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum Via {
    /// Into the tunnel interface.
    Tunnel { if_index: u32 },
    /// Through the physical network's gateway (outside the tunnel).
    Gateway {
        gateway: Option<IpAddr>,
        if_index: u32,
    },
}

impl Via {
    /// The interface the route uses.
    pub fn if_index(&self) -> u32 {
        match *self {
            Via::Tunnel { if_index } | Via::Gateway { if_index, .. } => if_index,
        }
    }
}

/// One reversible change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "change")]
pub enum Change {
    Route {
        prefix: Prefix,
        via: Via,
    },
    /// Send DNS queries for `domains` (`"."`: all queries) to `servers` over the tunnel, and
    /// complete short names with the `search` domains.
    Dns {
        if_index: u32,
        servers: Vec<IpAddr>,
        domains: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        search: Vec<String>,
    },
}

/// What the system looked like before the tunnel: how each VPN server and the default
/// route are reached.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Context {
    pub tunnel_if: u32,
    /// `(server, gateway, interface)` for each VPN server address.
    pub server_routes: Vec<(IpAddr, Option<IpAddr>, u32)>,
    /// The physical default route (for networks excluded from the tunnel).
    pub default_v4: Option<(Option<IpAddr>, u32)>,
    pub default_v6: Option<(Option<IpAddr>, u32)>,
}

fn halves(v6: bool) -> [Prefix; 2] {
    let parse = |s: &str| s.parse::<Prefix>().expect("constant prefix");
    if v6 {
        [parse("::/1"), parse("8000::/1")]
    } else {
        [parse("0.0.0.0/1"), parse("128.0.0.0/1")]
    }
}

/// The changes for `config`, in the order they must be made (revert in reverse).
///
/// * VPN servers get host routes via their current gateway, so the tunnel's own traffic
///   never loops into the tunnel.
/// * A full tunnel uses the two half-default routes, which win over the existing default
///   route without replacing it.
/// * IPv6 always goes into the tunnel in full-tunnel mode, even when the tunnel has no IPv6
///   address: the tunnel drops it, so it cannot leak around the VPN.
/// * Excluded networks get routes via the physical default gateway.
/// * DNS: split DNS for the tunnel's domains, or all queries in full-tunnel mode.
pub fn plan(config: &TunnelConfig, ctx: &Context) -> Vec<Change> {
    let tunnel = Via::Tunnel {
        if_index: ctx.tunnel_if,
    };
    let mut changes = Vec::new();

    let mut servers: Vec<IpAddr> = config.servers.clone();
    servers.sort();
    servers.dedup();
    for server in servers {
        if let Some((_, gateway, if_index)) =
            ctx.server_routes.iter().find(|(s, _, _)| *s == server)
        {
            changes.push(Change::Route {
                prefix: Prefix::host(server),
                via: Via::Gateway {
                    gateway: *gateway,
                    if_index: *if_index,
                },
            });
        }
    }

    if config.is_full_tunnel() {
        for prefix in halves(false).into_iter().chain(halves(true)) {
            changes.push(Change::Route {
                prefix,
                via: tunnel,
            });
        }
    } else {
        let mut routes = config.routes.clone();
        routes.sort();
        routes.dedup();
        for prefix in routes {
            changes.push(Change::Route {
                prefix,
                via: tunnel,
            });
        }
    }

    for prefix in &config.exclude_routes {
        let default = if prefix.is_ipv4() {
            ctx.default_v4
        } else {
            ctx.default_v6
        };
        if let Some((gateway, if_index)) = default {
            changes.push(Change::Route {
                prefix: *prefix,
                via: Via::Gateway { gateway, if_index },
            });
        }
    }

    if !config.dns_servers.is_empty() {
        let mut search: Vec<String> = Vec::new();
        for domain in &config.dns_domains {
            let domain = domain.trim().trim_matches('.').to_ascii_lowercase();
            if domain != "." && valid_domain(&domain) && !search.contains(&domain) {
                search.push(domain);
            }
        }
        let domains = if config.is_full_tunnel() || config.dns_domains.is_empty() {
            vec![".".to_string()]
        } else {
            search.clone()
        };
        if !domains.is_empty() {
            changes.push(Change::Dns {
                if_index: ctx.tunnel_if,
                servers: config.dns_servers.clone(),
                domains,
                search,
            });
        }
    }
    changes
}

/// `"."` or a DNS name (letters, digits, `-`, `.`); never anything a command could misread.
pub fn valid_domain(domain: &str) -> bool {
    domain == "."
        || (!domain.is_empty()
            && domain.len() <= 253
            && !domain.starts_with('-')
            && domain.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ctx() -> Context {
        Context {
            tunnel_if: 42,
            server_routes: vec![(ip("203.0.113.10"), Some(ip("192.168.1.1")), 7)],
            default_v4: Some((Some(ip("192.168.1.1")), 7)),
            default_v6: None,
        }
    }

    #[test]
    fn full_tunnel_with_dns_and_leak_protection() {
        let config = TunnelConfig {
            addresses: vec![p("10.8.0.5/32")],
            mtu: 1400,
            dns_servers: vec![ip("10.0.0.53")],
            dns_domains: vec!["corp.example.com".into()],
            servers: vec![ip("203.0.113.10"), ip("203.0.113.10")],
            ..Default::default()
        };
        let changes = plan(&config, &ctx());
        let tunnel = Via::Tunnel { if_index: 42 };
        assert_eq!(
            changes,
            vec![
                Change::Route {
                    prefix: p("203.0.113.10/32"),
                    via: Via::Gateway {
                        gateway: Some(ip("192.168.1.1")),
                        if_index: 7
                    }
                },
                Change::Route {
                    prefix: p("0.0.0.0/1"),
                    via: tunnel
                },
                Change::Route {
                    prefix: p("128.0.0.0/1"),
                    via: tunnel
                },
                Change::Route {
                    prefix: p("::/1"),
                    via: tunnel
                },
                Change::Route {
                    prefix: p("8000::/1"),
                    via: tunnel
                },
                Change::Dns {
                    if_index: 42,
                    servers: vec![ip("10.0.0.53")],
                    domains: vec![".".into()],
                    search: vec!["corp.example.com".into()]
                },
            ]
        );
    }

    #[test]
    fn split_tunnel_with_split_dns_and_excludes() {
        let config = TunnelConfig {
            routes: vec![p("10.0.0.0/8"), p("192.0.2.0/24"), p("10.0.0.0/8")],
            exclude_routes: vec![p("10.99.0.0/16"), p("2001:db8::/32")],
            dns_servers: vec![ip("10.0.0.53")],
            dns_domains: vec![
                ".Corp.Example.com.".into(),
                "bad domain".into(),
                "-x".into(),
            ],
            servers: vec![ip("203.0.113.10")],
            ..Default::default()
        };
        let changes = plan(&config, &ctx());
        let routes: Vec<String> = changes
            .iter()
            .filter_map(|c| match c {
                Change::Route { prefix, .. } => Some(prefix.to_string()),
                _ => None,
            })
            .collect();
        // The IPv6 exclude is skipped: there is no IPv6 default route to send it to.
        assert_eq!(
            routes,
            [
                "203.0.113.10/32",
                "10.0.0.0/8",
                "192.0.2.0/24",
                "10.99.0.0/16"
            ]
        );
        assert_eq!(
            changes.last(),
            Some(&Change::Dns {
                if_index: 42,
                servers: vec![ip("10.0.0.53")],
                domains: vec!["corp.example.com".into()],
                search: vec!["corp.example.com".into()]
            })
        );
    }

    #[test]
    fn journals_from_before_search_domains_still_load() {
        let old = r#"{"change":"dns","if_index":3,"servers":["10.0.0.53"],"domains":["."]}"#;
        let change: Change = serde_json::from_str(old).unwrap();
        assert_eq!(
            change,
            Change::Dns {
                if_index: 3,
                servers: vec![ip("10.0.0.53")],
                domains: vec![".".into()],
                search: Vec::new()
            }
        );
    }

    #[test]
    fn a_default_route_in_the_list_means_full_tunnel() {
        let config = TunnelConfig {
            routes: vec![p("0.0.0.0/0")],
            ..Default::default()
        };
        assert!(config.is_full_tunnel());
        assert!(plan(&config, &Context::default()).iter().any(
            |c| matches!(c, Change::Route { prefix, .. } if prefix.to_string() == "128.0.0.0/1")
        ));
    }

    #[test]
    fn domains_are_validated() {
        assert!(valid_domain("."));
        assert!(valid_domain("corp.example.com"));
        for bad in [
            "",
            "-a.example.com",
            "a..example.com",
            "a b",
            "a;rm",
            &"a".repeat(64),
        ] {
            assert!(!valid_domain(bad), "{bad}");
        }
    }

    #[test]
    fn changes_serialize_for_the_journal() {
        let change = Change::Route {
            prefix: p("192.0.2.0/24"),
            via: Via::Tunnel { if_index: 3 },
        };
        let json = serde_json::to_string(&change).unwrap();
        assert_eq!(
            json,
            r#"{"change":"route","prefix":"192.0.2.0/24","via":{"kind":"tunnel","if_index":3}}"#
        );
        assert_eq!(serde_json::from_str::<Change>(&json).unwrap(), change);
    }
}
