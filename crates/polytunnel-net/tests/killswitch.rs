//! The kill switch on a real system (Windows: administrator; Linux: root with nftables).
//! Run with `--ignored`; CI runs it in the network integration job.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use polytunnel_net::killswitch::{self, Rules};

fn reachable(addr: &SocketAddr) -> bool {
    TcpStream::connect_timeout(addr, Duration::from_secs(4)).is_ok()
}

#[test]
#[ignore = "changes the system firewall; needs administrator or root"]
fn blocks_all_but_allowed_servers_and_lifts() {
    let addr = ("example.com", 443)
        .to_socket_addrs()
        .unwrap()
        .find(SocketAddr::is_ipv4)
        .expect("an IPv4 address");
    assert!(reachable(&addr), "the network works beforehand");
    let mut ks = killswitch::native(false);
    ks.apply(&Rules::default()).unwrap();
    assert!(!reachable(&addr), "blocked while the kill switch is on");
    ks.apply(&Rules {
        servers: vec![addr.ip()],
        ..Rules::default()
    })
    .unwrap();
    assert!(reachable(&addr), "a VPN server stays reachable");
    ks.apply(&Rules::default()).unwrap();
    drop(ks); // the rules go with it
    assert!(reachable(&addr), "lifted");
}
