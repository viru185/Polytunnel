//! Fortinet IPsec against strongSwan standing in for a FortiGate dial-up gateway (IKEv1
//! aggressive mode, pre-shared key and XAuth, mode-config, DPD, short phase-2 lifetimes).
//!
//! Needs root (TUN, routes) and a responder; `.github/workflows/interop.yml` sets both up and
//! passes the details in `POLYTUNNEL_INTEROP_*`. Run with `--ignored --test-threads=1`.

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use polytunnel_core::Secret;
use polytunnel_core::ipc::{IpsecConnect, Status, XauthLogin};
use polytunnel_core::profile::{IpsecTransport, LocalIdType, ModeConfigStyle, ServerAuthStyle};
use polytunnel_daemon::ipsec;
use tokio::sync::{mpsc, watch};

fn env(name: &str) -> String {
    std::env::var(format!("POLYTUNNEL_INTEROP_{name}"))
        .unwrap_or_else(|_| panic!("POLYTUNNEL_INTEROP_{name} is not set"))
}

fn request(psk: String, password: String, esp_lifetime: u32) -> IpsecConnect {
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

#[test]
#[ignore = "needs root and a strongSwan responder (see interop.yml)"]
fn connects_pings_rekeys_and_disconnects() {
    let lifetime = 60;
    let c = Connection::start(request(env("PSK"), env("PASSWORD"), lifetime));
    let s = c.settle();
    let Status::Connected {
        addresses,
        transport,
        ..
    } = &s
    else {
        panic!("not connected: {s:?}");
    };
    println!("connected with {addresses:?} over {transport}");
    assert_eq!(transport, "esp");
    assert!(ping(&env("PING")), "ping through the tunnel");

    // Outlive the first ESP SA (60 s): the engine must have rekeyed, and retired the old SA.
    std::thread::sleep(Duration::from_secs(u64::from(lifetime) + 15));
    assert!(
        matches!(c.status(), Status::Connected { .. }),
        "{:?}",
        c.status()
    );
    assert!(ping(&env("PING")), "ping after the rekey");

    assert_eq!(c.disconnect(), Status::Idle {});
}

#[test]
#[ignore = "needs root and a strongSwan responder (see interop.yml)"]
fn a_wrong_pre_shared_key_is_reported() {
    let c = Connection::start(request(
        format!("{}-wrong", env("PSK")),
        env("PASSWORD"),
        3600,
    ));
    match c.settle() {
        Status::Failed { message, .. } => {
            assert!(message.contains("pre-shared key"), "{message}");
        }
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[test]
#[ignore = "needs root and a strongSwan responder (see interop.yml)"]
fn a_wrong_password_is_reported() {
    let c = Connection::start(request(
        env("PSK"),
        format!("{}-wrong", env("PASSWORD")),
        3600,
    ));
    match c.settle() {
        Status::Failed { message, .. } => assert!(message.contains("password"), "{message}"),
        other => panic!("expected a failure, got {other:?}"),
    }
}
