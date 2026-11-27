//! Fortinet IPsec against independent implementations standing in for a FortiGate:
//! - `ikev1_*`: strongSwan, IKEv1 aggressive mode, pre-shared key and XAuth, mode-config,
//!   DPD, short phase-2 lifetimes;
//! - `ikev2_*`: strongSwan, IKEv2 with a pre-shared key, or with an ECDSA gateway
//!   certificate and EAP-MSCHAPv2;
//! - `tcp_*`: libreswan, IKEv2 with IKE and ESP over TCP (RFC 9329).
//!
//! Needs root (TUN, routes) and a responder; `.github/workflows/interop.yml` sets both up and
//! passes the details in `POLYTUNNEL_INTEROP_*`. Run with `--ignored --test-threads=1` and a
//! name filter for the responder at hand.

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use polytunnel_core::Secret;
use polytunnel_core::ipc::{IpsecConnect, Status, XauthLogin};
use polytunnel_core::profile::{
    EapMethodName, IpsecTransport, LocalIdType, ModeConfigStyle, ServerAuthStyle,
};
use polytunnel_daemon::ipsec;
use tokio::sync::{mpsc, watch};

fn env(name: &str) -> String {
    std::env::var(format!("POLYTUNNEL_INTEROP_{name}"))
        .unwrap_or_else(|_| panic!("POLYTUNNEL_INTEROP_{name} is not set"))
}

fn wrong(s: String) -> String {
    format!("{s}-wrong")
}

/// IKEv1 aggressive mode with XAuth, as `client.test`.
fn ikev1(psk: String, password: String, esp_lifetime: u32) -> IpsecConnect {
    IpsecConnect {
        profile: "interop".into(),
        server: env("GATEWAY"),
        psk: Secret::new(psk),
        xauth: Some(XauthLogin {
            username: env("USER"),
            password: Secret::new(password),
        }),
        local_id: Some("client.test".into()),
        local_id_type: LocalIdType::Fqdn,
        ike_proposals: vec!["aes256-sha256-modp2048".into()],
        esp_proposals: vec!["aes256-sha256".into()],
        pfs_group: Some(14),
        ike_lifetime: 3600,
        esp_lifetime,
        esp_lifetime_kb: None,
        mode_config: ModeConfigStyle::Pull,
        remote_network: Some(env("NETWORK")),
        dpd: 10,
        nat_keepalive: 5,
        client_version: "Polytunnel interop".into(),
        ike_version: 1,
        eap: None,
        server_auth: ServerAuthStyle::Psk,
        ca_pem: None,
        remote_id: None,
        transport: IpsecTransport::Udp,
        tcp_port: 443,
    }
}

/// IKEv2 with a pre-shared key both ways, as `id`.
fn ikev2_psk(id: &str, psk: String, esp_lifetime: u32) -> IpsecConnect {
    IpsecConnect {
        xauth: None,
        local_id: Some(id.into()),
        ike_version: 2,
        ..ikev1(psk, String::new(), esp_lifetime)
    }
}

/// IKEv2 with EAP-MSCHAPv2 to a gateway with a certificate.
fn ikev2_eap(password: String) -> IpsecConnect {
    let ca = std::fs::read_to_string(env("CA_FILE")).expect("the CA certificate");
    IpsecConnect {
        psk: Secret::new(""),
        xauth: Some(XauthLogin {
            username: env("USER"),
            password: Secret::new(password),
        }),
        local_id: Some("client-eap.test".into()),
        ike_version: 2,
        eap: Some(EapMethodName::Mschapv2),
        server_auth: ServerAuthStyle::Certificate,
        ca_pem: Some(ca),
        remote_id: Some("gateway.test".into()),
        ..ikev1(String::new(), String::new(), 3600)
    }
}

/// A running connection in the daemon's IPsec engine.
struct Connection {
    runtime: tokio::runtime::Runtime,
    status: Arc<Mutex<Status>>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    _answers: mpsc::Sender<ipsec::Answer>,
}

impl Connection {
    fn start(request: IpsecConnect) -> Self {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let status = Arc::new(Mutex::new(Status::Connecting {
            profile: "interop".into(),
        }));
        let (stop, stop_rx) = watch::channel(false);
        let (answers, answers_rx) = mpsc::channel(1);
        let task = runtime.spawn(ipsec::run(request, status.clone(), stop_rx, answers_rx));
        Self {
            runtime,
            status,
            stop,
            task,
            _answers: answers,
        }
    }

    fn status(&self) -> Status {
        self.status.lock().unwrap().clone()
    }

    /// Waits until connected or failed.
    fn settle(&self) -> Status {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let s = self.status();
            match s {
                Status::Connected { .. } | Status::Failed { .. } | Status::Idle {} => return s,
                _ if Instant::now() > deadline => panic!("still {s:?} after 60 s"),
                _ => std::thread::sleep(Duration::from_millis(250)),
            }
        }
    }

    fn disconnect(self) -> Status {
        let Connection {
            runtime,
            status,
            stop,
            task,
            ..
        } = self;
        let _ = stop.send(true);
        runtime
            .block_on(async { tokio::time::timeout(Duration::from_secs(20), task).await })
            .expect("the engine stops")
            .unwrap();
        status.lock().unwrap().clone()
    }
}

fn ping(target: &str) -> bool {
    Command::new("ping")
        .args(["-c", "3", "-W", "3", target])
        .status()
        .is_ok_and(|s| s.success())
}

/// Connects, pings, optionally outlives the first ESP SA (`rekey_after`), disconnects.
fn round_trip(request: IpsecConnect, transport: &str, rekey_after: Option<Duration>) {
    let c = Connection::start(request);
    let s = c.settle();
    let Status::Connected {
        addresses,
        transport: used,
        ..
    } = &s
    else {
        panic!("not connected: {s:?}");
    };
    println!("connected with {addresses:?} over {used}");
    assert_eq!(used, transport);
    assert!(ping(&env("PING")), "ping through the tunnel");
    if let Some(wait) = rekey_after {
        std::thread::sleep(wait);
        assert!(
            matches!(c.status(), Status::Connected { .. }),
            "{:?}",
            c.status()
        );
        assert!(ping(&env("PING")), "ping after the rekey");
    }
    assert_eq!(c.disconnect(), Status::Idle {});
}

fn fails_with(request: IpsecConnect, words: &str) {
    let c = Connection::start(request);
    match c.settle() {
        Status::Failed { message, .. } => assert!(message.contains(words), "{message}"),
        other => panic!("expected a failure, got {other:?}"),
    }
}

const REKEY_WAIT: Duration = Duration::from_secs(75);

#[test]
#[ignore = "needs root and a strongSwan responder (see interop.yml)"]
fn ikev1_connects_pings_rekeys_and_disconnects() {
    round_trip(
        ikev1(env("PSK"), env("PASSWORD"), 60),
        "esp",
        Some(REKEY_WAIT),
    );
}

#[test]
#[ignore = "needs root and a strongSwan responder (see interop.yml)"]
fn ikev1_wrong_pre_shared_key_is_reported() {
    fails_with(
        ikev1(wrong(env("PSK")), env("PASSWORD"), 3600),
        "pre-shared key",
    );
}

#[test]
#[ignore = "needs root and a strongSwan responder (see interop.yml)"]
fn ikev1_wrong_password_is_reported() {
    fails_with(ikev1(env("PSK"), wrong(env("PASSWORD")), 3600), "password");
}

#[test]
#[ignore = "needs root and a strongSwan responder (see interop.yml)"]
fn ikev2_psk_connects_pings_rekeys_and_disconnects() {
    round_trip(
        ikev2_psk("client-psk.test", env("PSK"), 60),
        "esp",
        Some(REKEY_WAIT),
    );
}

#[test]
#[ignore = "needs root and a strongSwan responder (see interop.yml)"]
fn ikev2_eap_with_a_gateway_certificate_connects() {
    round_trip(ikev2_eap(env("PASSWORD")), "esp", None);
}

#[test]
#[ignore = "needs root and a strongSwan responder (see interop.yml)"]
fn ikev2_eap_wrong_password_is_reported() {
    fails_with(ikev2_eap(wrong(env("PASSWORD"))), "password");
}

#[test]
#[ignore = "needs root and a libreswan responder (see interop.yml)"]
fn tcp_ikev2_psk_connects_and_pings() {
    let port: u16 = env("TCP_PORT").parse().unwrap();
    let request = IpsecConnect {
        transport: IpsecTransport::Tcp,
        tcp_port: port,
        dpd: 0,
        nat_keepalive: 0,
        ..ikev2_psk("client-tcp.test", env("PSK"), 3600)
    };
    round_trip(request, "esp-tcp", None);
}
