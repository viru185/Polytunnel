//! Argument lists for the Linux and macOS network tools, built from typed values only.
//! Kept platform-independent so they can be tested everywhere.

use std::net::IpAddr;

use crate::plan::{Via, valid_domain};
use crate::prefix::Prefix;

fn family(prefix: &Prefix) -> &'static str {
    if prefix.is_ipv4() { "-4" } else { "-6" }
}

/// `ip route add|del ...` (`if_name`: the route's interface).
pub fn linux_route(
    add: bool,
    prefix: &Prefix,
    gateway: Option<IpAddr>,
    if_name: &str,
) -> Vec<String> {
    let mut args = vec![
        family(prefix).to_string(),
        "route".into(),
        if add { "add" } else { "del" }.into(),
        prefix.to_string(),
    ];
    if let Some(gateway) = gateway {
        args.push("via".into());
        args.push(gateway.to_string());
    }
    args.push("dev".into());
    args.push(if_name.to_string());
    args
}

/// The `resolvectl` invocations that route `domains` to `servers` over `if_name`.
pub fn linux_dns(if_name: &str, servers: &[IpAddr], domains: &[String]) -> Vec<Vec<String>> {
    let mut dns = vec!["dns".to_string(), if_name.to_string()];
    dns.extend(servers.iter().map(IpAddr::to_string));
    let mut domain = vec!["domain".to_string(), if_name.to_string()];
    domain.extend(domains.iter().filter(|d| valid_domain(d)).map(|d| {
        if d == "." {
            "~.".to_string()
        } else {
            format!("~{d}")
        }
    }));
    let all = domains.iter().any(|d| d == ".");
    vec![
        dns,
        domain,
        vec![
            "default-route".into(),
            if_name.to_string(),
            if all { "true" } else { "false" }.into(),
        ],
    ]
}

/// `route -n add|delete ...` on macOS.
pub fn macos_route(add: bool, prefix: &Prefix, via: &Via, if_name: &str) -> Vec<String> {
    let host = prefix.prefix_len() == if prefix.is_ipv4() { 32 } else { 128 };
    let mut args = vec![
        "-n".to_string(),
        if add { "add" } else { "delete" }.into(),
        if prefix.is_ipv4() { "-inet" } else { "-inet6" }.into(),
    ];
    if host {
        args.push("-host".into());
        args.push(prefix.addr().to_string());
    } else {
        args.push("-net".into());
        args.push(prefix.to_string());
    }
    match via {
        Via::Gateway {
            gateway: Some(gateway),
            ..
        } => args.push(gateway.to_string()),
        _ => {
            args.push("-interface".into());
            args.push(if_name.to_string());
        }
    }
    args
}

/// The `scutil` script that adds (or removes) a DNS resolver for `domains`.
pub fn macos_dns_script(key: &str, servers: &[IpAddr], domains: &[String]) -> String {
    let servers: Vec<String> = servers.iter().map(IpAddr::to_string).collect();
    let domains: Vec<&str> = domains
        .iter()
        .filter(|d| valid_domain(d) && *d != ".")
        .map(String::as_str)
        .collect();
    let mut script = format!("d.init\nd.add ServerAddresses * {}\n", servers.join(" "));
    if !domains.is_empty() {
        script.push_str(&format!(
            "d.add SupplementalMatchDomains * {}\n",
            domains.join(" ")
        ));
    }
    script.push_str(&format!("set State:/Network/Service/{key}/DNS\nquit\n"));
    script
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn linux_commands() {
        assert_eq!(
            linux_route(true, &p("192.0.2.0/24"), None, "tun0"),
            ["-4", "route", "add", "192.0.2.0/24", "dev", "tun0"]
        );
        assert_eq!(
            linux_route(
                false,
                &p("203.0.113.10/32"),
                Some("192.168.1.1".parse().unwrap()),
                "eth0"
            ),
            [
                "-4",
                "route",
                "del",
                "203.0.113.10/32",
                "via",
                "192.168.1.1",
                "dev",
                "eth0"
            ]
        );
        assert_eq!(linux_route(true, &p("::/1"), None, "tun0")[0], "-6");
        let dns = linux_dns(
            "tun0",
            &["10.0.0.53".parse().unwrap()],
            &["corp.example.com".into(), "bad;x".into()],
        );
        assert_eq!(dns[0], ["dns", "tun0", "10.0.0.53"]);
        assert_eq!(dns[1], ["domain", "tun0", "~corp.example.com"]);
        assert_eq!(dns[2], ["default-route", "tun0", "false"]);
        let all = linux_dns("tun0", &[], &[".".into()]);
        assert_eq!(all[1], ["domain", "tun0", "~."]);
        assert_eq!(all[2][2], "true");
    }

    #[test]
    fn macos_commands() {
        let tunnel = Via::Tunnel { if_index: 9 };
        assert_eq!(
            macos_route(true, &p("10.0.0.0/8"), &tunnel, "utun4"),
            [
                "-n",
                "add",
                "-inet",
                "-net",
                "10.0.0.0/8",
                "-interface",
                "utun4"
            ]
        );
        let gw = Via::Gateway {
            gateway: Some("192.168.1.1".parse().unwrap()),
            if_index: 4,
        };
        assert_eq!(
            macos_route(false, &p("203.0.113.10/32"), &gw, "en0"),
            [
                "-n",
                "delete",
                "-inet",
                "-host",
                "203.0.113.10",
                "192.168.1.1"
            ]
        );
        let script = macos_dns_script(
            "Polytunnel-9",
            &["10.0.0.53".parse().unwrap()],
            &["corp.example.com".into(), ".".into()],
        );
        assert_eq!(
            script,
            "d.init\nd.add ServerAddresses * 10.0.0.53\n\
             d.add SupplementalMatchDomains * corp.example.com\n\
             set State:/Network/Service/Polytunnel-9/DNS\nquit\n"
        );
    }
}
