//! End-to-end: create a TUN device, route a network and a DNS domain into it, check the
//! system uses them, then roll everything back.
//!
//! Needs administrator/root rights (and `POLYTUNNEL_WINTUN_DLL` on Windows), so it is
//! ignored by default. CI runs it with `--ignored` on Windows and Linux runners.

use std::net::IpAddr;

use polytunnel_net::journal::Journal;
use polytunnel_net::plan::{Context, TunnelConfig, plan};
use polytunnel_net::system;
use polytunnel_net::tun::{self, TunOptions};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
#[ignore = "needs administrator/root rights"]
fn tun_routes_and_dns_round_trip() {
    let device = tun::open(&TunOptions {
        name: "ptest0".into(),
        guid: Some(tun::stable_guid("polytunnel-integration-test")),
        addresses: vec!["198.51.100.2/24".parse().unwrap()],
        mtu: 1400,
        wintun_dll: std::env::var_os("POLYTUNNEL_WINTUN_DLL").map(Into::into),
    })
    .expect("create the TUN device");
    let tunnel_if = device.if_index().expect("interface index");

    let mut sys = system::native();
    let before = sys.route_to(ip("203.0.113.5")).expect("route before");
    assert_ne!(before.1, tunnel_if);

    let config = TunnelConfig {
        addresses: vec!["198.51.100.2/24".parse().unwrap()],
        mtu: 1400,
        routes: vec!["203.0.113.0/24".parse().unwrap()],
        dns_servers: vec![ip("198.51.100.53")],
        dns_domains: vec!["polytunnel.test".into()],
        ..Default::default()
    };
    let ctx = Context {
        tunnel_if,
        ..Default::default()
    };
    let journal_path = std::env::temp_dir().join(format!(
        "polytunnel-net-it-{}/journal.json",
        std::process::id()
    ));
    let mut journal = Journal::open(&journal_path).unwrap();
    journal
        .apply_all(sys.as_mut(), plan(&config, &ctx))
        .expect("apply the plan");
    assert_eq!(journal.entries().len(), 2, "one route and one DNS rule");

    let during = sys.route_to(ip("203.0.113.5")).expect("route during");
    assert_eq!(
        during.1, tunnel_if,
        "203.0.113.0/24 must go into the tunnel"
    );

    journal.rollback(sys.as_mut()).expect("roll back");
    assert!(journal.entries().is_empty());
    let after = sys.route_to(ip("203.0.113.5")).expect("route after");
    assert_ne!(after.1, tunnel_if, "the route must be gone");
    drop(device);
}
