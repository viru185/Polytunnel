//! End-to-end: create a TUN device, route a network and a DNS domain into it, check the
//! system uses them, then roll everything back.
//!
//! Needs administrator/root rights (and `POLYTUNNEL_WINTUN_DLL` on Windows), so it is
//! ignored by default. CI runs it with `--ignored` on Windows and Linux runners.

use std::net::IpAddr;

use polytunnel_net::journal::Journal;
use polytunnel_net::plan::{Context, TunnelConfig, plan};
use polytunnel_net::system::{self, System};
use polytunnel_net::tun::{self, SyncDevice, TunOptions};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A TUN device with a route (203.0.113.0/24) and a DNS rule applied into it.
struct Tunnel {
    device: SyncDevice,
    if_index: u32,
    sys: Box<dyn System>,
    journal: Journal,
}

fn tunnel_with_changes(name: &str) -> Tunnel {
    let device = tun::open(&TunOptions {
        name: name.into(),
        guid: Some(tun::stable_guid(&format!("polytunnel-integration-{name}"))),
        addresses: vec!["198.51.100.2/24".parse().unwrap()],
        mtu: 1400,
        wintun_dll: std::env::var_os("POLYTUNNEL_WINTUN_DLL").map(Into::into),
    })
    .expect("create the TUN device");
    let if_index = device.if_index().expect("interface index");

    let mut sys = system::native();
    let before = sys.route_to(ip("203.0.113.5")).expect("route before");
    assert_ne!(before.1, if_index);

    let config = TunnelConfig {
        addresses: vec!["198.51.100.2/24".parse().unwrap()],
        mtu: 1400,
        routes: vec!["203.0.113.0/24".parse().unwrap()],
        dns_servers: vec![ip("198.51.100.53")],
        dns_domains: vec!["polytunnel.test".into()],
        ..Default::default()
    };
    let ctx = Context {
        tunnel_if: if_index,
        ..Default::default()
    };
    let journal_path = std::env::temp_dir().join(format!(
        "polytunnel-net-it-{}-{name}/journal.json",
        std::process::id()
    ));
    let mut journal = Journal::open(&journal_path).unwrap();
    journal
        .apply_all(sys.as_mut(), plan(&config, &ctx))
        .expect("apply the plan");
    assert_eq!(journal.entries().len(), 2, "one route and one DNS rule");

    let during = sys.route_to(ip("203.0.113.5")).expect("route during");
    assert_eq!(during.1, if_index, "203.0.113.0/24 must go into the tunnel");
    Tunnel {
        device,
        if_index,
        sys,
        journal,
    }
}

#[test]
#[ignore = "needs administrator/root rights"]
fn tun_routes_and_dns_round_trip() {
    let mut t = tunnel_with_changes("ptest0");
    t.journal.rollback(t.sys.as_mut()).expect("roll back");
    assert!(t.journal.entries().is_empty());
    let after = t.sys.route_to(ip("203.0.113.5")).expect("route after");
    assert_ne!(after.1, t.if_index, "the route must be gone");
    drop(t.device);
}

/// The daemon closes the tunnel before it rolls back, and the system removes the tunnel's
/// routes with it: that rollback must succeed and leave nothing in the journal.
#[test]
#[ignore = "needs administrator/root rights"]
fn rollback_after_the_tunnel_is_gone() {
    let Tunnel {
        device,
        if_index,
        mut sys,
        mut journal,
    } = tunnel_with_changes("ptest1");
    drop(device);
    journal
        .rollback(sys.as_mut())
        .expect("nothing left to undo is not an error");
    assert!(journal.entries().is_empty(), "{:?}", journal.entries());
    let after = sys.route_to(ip("203.0.113.5")).expect("route after");
    assert_ne!(after.1, if_index, "the route must be gone");
}
