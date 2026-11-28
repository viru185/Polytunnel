//! Pieces shared by the tunnel engines: status, timeouts, and bringing the network up.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use polytunnel_core::ipc::Status;
use polytunnel_net::TunnelConfig;
use polytunnel_net::journal::Journal;
use polytunnel_net::plan::{Context, plan};
use polytunnel_net::system::System;
use polytunnel_net::tun::{self, SyncDevice, TunOptions};

use tokio::sync::watch;

use crate::paths;

/// Bytes moved through the tunnel, counted by the packet pump.
#[derive(Debug, Default)]
pub struct Counters {
    /// From the tunnel to the system.
    pub bytes_in: AtomicU64,
    /// From the system into the tunnel.
    pub bytes_out: AtomicU64,
}

struct Board {
    status: Status,
    /// The run allowed to write; 0 while none has started.
    generation: u64,
    counters: Option<Arc<Counters>>,
}

/// The service's one status, and a connection's handle on it.
///
/// Each connection gets its own handle with a new generation, and writes through it only while
/// it is the current one. A connection that is being replaced, or was given up on, can no
/// longer overwrite its successor's status (or switch off its kill switch).
#[derive(Clone)]
pub struct StatusCell {
    board: Arc<Mutex<Board>>,
    generation: u64,
}

impl StatusCell {
    /// The board itself (for the manager), idle.
    pub fn new() -> StatusCell {
        StatusCell {
            board: Arc::new(Mutex::new(Board {
                status: Status::Idle {},
                generation: 0,
                counters: None,
            })),
            generation: 0,
        }
    }

    fn board(&self) -> std::sync::MutexGuard<'_, Board> {
        self.board.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A handle for a new connection: from now on only it may write.
    pub fn next_run(&self) -> StatusCell {
        let mut board = self.board();
        board.generation += 1;
        board.counters = None;
        StatusCell {
            board: self.board.clone(),
            generation: board.generation,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Is this handle's connection still the current one?
    pub fn is_current(&self) -> bool {
        self.board().generation == self.generation
    }

    /// The status, with the live byte counts when connected.
    pub fn get(&self) -> Status {
        let board = self.board();
        let mut status = board.status.clone();
        if let (
            Status::Connected {
                bytes_in,
                bytes_out,
                ..
            },
            Some(counters),
        ) = (&mut status, &board.counters)
        {
            *bytes_in = counters.bytes_in.load(Ordering::Relaxed);
            *bytes_out = counters.bytes_out.load(Ordering::Relaxed);
        }
        status
    }

    /// Changes the status if this handle's connection is still the current one.
    pub fn update(&self, f: impl FnOnce(&mut Status)) -> bool {
        let mut board = self.board();
        if board.generation != self.generation {
            return false;
        }
        f(&mut board.status);
        true
    }

    /// The pump's counters for the status (current connection only).
    pub fn set_counters(&self, counters: Arc<Counters>) {
        let mut board = self.board();
        if board.generation == self.generation {
            board.counters = Some(counters);
        }
    }

    /// The manager's write: applies whatever connection is current.
    pub fn force(&self, value: Status) {
        self.board().status = value;
    }
}

impl Default for StatusCell {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs a setup step, unless a stop is asked for first: `None` then.
pub async fn until_stopped<T>(
    stop: &mut watch::Receiver<bool>,
    step: impl Future<Output = T>,
) -> Option<T> {
    if *stop.borrow() {
        return None;
    }
    tokio::select! {
        value = step => Some(value),
        // A closed channel means the manager is gone: stop too.
        _ = stop.wait_for(|stopped| *stopped) => None,
    }
}

/// The `Connected` status for a (re)connection: keeps when the connection first came up and
/// the server's latest notice from an earlier `Connected` or `Reconnecting` status.
pub fn connected_status(
    status: &StatusCell,
    profile: &str,
    server: &str,
    gateway: Option<String>,
    addresses: Vec<String>,
    transport: &str,
    notice: Option<String>,
) -> Status {
    let (since_unix, notice) = match status.get() {
        Status::Connected {
            since_unix,
            notice: current,
            ..
        } => (since_unix, current.or(notice)),
        Status::Reconnecting { since_unix, .. } => (since_unix, notice),
        _ => (now_unix(), notice),
    };
    Status::Connected {
        profile: profile.to_string(),
        server: server.to_string(),
        addresses,
        transport: transport.to_string(),
        since_unix,
        notice,
        gateway,
        bytes_in: 0,
        bytes_out: 0,
    }
}

/// The `Failed` status, stamped now.
pub fn failed(profile: String, message: String) -> Status {
    Status::Failed {
        profile,
        message,
        since_unix: now_unix(),
    }
}

/// Tells the kill switch how the connection's tunnel ended: taken down on purpose (`Ok`), or
/// lost while still wanted, which keeps "while connected" blocking. True when it now holds
/// the block.
pub fn tunnel_ended(status: &StatusCell, result: &Result<(), String>) -> bool {
    match result {
        Ok(()) => {
            crate::killswitch::tunnel_down(status.generation());
            false
        }
        Err(_) => crate::killswitch::tunnel_lost(status.generation()),
    }
}

/// The last status of a connection to `server`: idle when it was stopped, else the failure
/// (saying so when the kill switch keeps blocking).
pub fn conclude(
    status: &StatusCell,
    profile: String,
    server: &str,
    result: Result<(), String>,
    held: bool,
) {
    match result {
        Ok(()) => {
            crate::info!("disconnected from {server}");
            set(status, Status::Idle {});
        }
        Err(message) => {
            crate::warn!("connection to {server} failed: {message}");
            let message = if held {
                format!(
                    "{message}. The kill switch keeps blocking internet traffic until you \
                     disconnect."
                )
            } else {
                message
            };
            set(status, failed(profile, message));
        }
    }
}

/// Upper bound for each setup step (connect, handshake, first answer).
pub const STEP_TIMEOUT: Duration = Duration::from_secs(15);

/// How a transport loop ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    Stopped,
    Lost(String),
}

/// Sets the status if `status`'s connection is still the current one.
pub fn set(status: &StatusCell, value: Status) {
    status.update(|s| *s = value);
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Runs blocking work (HTTP requests) off the async workers.
pub async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())?
}

/// `https://host[:port]` -> (host for SNI and `Host:`, port).
pub fn host_port(base: &str) -> (String, u16) {
    let authority = base.trim_start_matches("https://");
    if let Some(v6) = authority.strip_prefix('[')
        && let Some((host, rest)) = v6.split_once(']')
    {
        let port = rest.trim_start_matches(':').parse().unwrap_or(443);
        return (host.to_string(), port);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse().unwrap_or(443)),
        None => (authority.to_string(), 443),
    }
}

/// Creates the TUN device for `profile` and applies the network plan (journaled). The VPN
/// servers in `config.servers` keep their current routes, so tunnel traffic never loops.
pub fn bring_up(
    profile: &str,
    config: &TunnelConfig,
    journal: &mut Journal,
    system: &mut dyn System,
    status: &StatusCell,
) -> Result<Arc<SyncDevice>, String> {
    let device = Arc::new(
        tun::open(&TunOptions {
            name: "Polytunnel".into(),
            guid: Some(tun::stable_guid(profile)),
            addresses: config.addresses.clone(),
            mtu: config.mtu,
            wintun_dll: paths::wintun_dll(),
        })
        .map_err(|e| format!("cannot create the tunnel interface: {e}"))?,
    );
    let tunnel_if = device.if_index().map_err(|e| e.to_string())?;
    let server_routes = config
        .servers
        .iter()
        .filter_map(|server| {
            system
                .route_to(*server)
                .ok()
                .map(|(gateway, index)| (*server, gateway, index))
        })
        .collect();
    // Documentation addresses: whatever route they take is the physical default route.
    let context = Context {
        tunnel_if,
        server_routes,
        default_v4: system
            .route_to("203.0.113.1".parse().expect("constant"))
            .ok(),
        default_v6: system
            .route_to("2001:db8::1".parse().expect("constant"))
            .ok(),
    };
    journal
        .apply_all(system, plan(config, &context))
        .map_err(|e| format!("cannot configure the network: {e}"))?;
    crate::killswitch::tunnel_up(status.generation(), tunnel_if, config.servers.clone());
    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connected(status: &StatusCell, notice: Option<&str>) -> Status {
        connected_status(
            status,
            "work",
            "gw.example.com",
            Some("203.0.113.5".into()),
            vec!["10.0.0.2".into()],
            "esp",
            notice.map(str::to_string),
        )
    }

    #[test]
    fn an_old_connection_cannot_overwrite_a_new_one() {
        let board = StatusCell::new();
        let old = board.next_run();
        set(
            &old,
            Status::Connecting {
                profile: "a".into(),
            },
        );
        let new = board.next_run();
        set(
            &new,
            Status::Connecting {
                profile: "b".into(),
            },
        );
        // The old run finishing late changes nothing.
        set(&old, Status::Idle {});
        assert!(!old.update(|s| *s = Status::Idle {}));
        assert!(!old.is_current() && new.is_current());
        assert_eq!(
            board.get(),
            Status::Connecting {
                profile: "b".into()
            }
        );
        // The manager can always write.
        board.force(Status::Idle {});
        assert_eq!(new.get(), Status::Idle {});
    }

    #[test]
    fn the_status_carries_the_live_byte_counts() {
        let run = StatusCell::new().next_run();
        set(&run, connected(&run, None));
        let counters = Arc::new(Counters::default());
        run.set_counters(counters.clone());
        counters.bytes_in.store(1500, Ordering::Relaxed);
        counters.bytes_out.store(300, Ordering::Relaxed);
        let Status::Connected {
            bytes_in,
            bytes_out,
            gateway,
            ..
        } = run.get()
        else {
            panic!("connected")
        };
        assert_eq!((bytes_in, bytes_out), (1500, 300));
        assert_eq!(gateway.as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn a_reconnect_keeps_the_start_time_and_the_latest_notice() {
        let run = StatusCell::new().next_run();
        set(
            &run,
            Status::Connecting {
                profile: "work".into(),
            },
        );
        let first = connected(&run, Some("first verdict"));
        set(&run, first);
        // The hourly check updated the verdict; then the tunnel came back.
        run.update(|s| {
            if let Status::Connected {
                notice, since_unix, ..
            } = s
            {
                *notice = Some("latest verdict".into());
                *since_unix = 1000;
            }
        });
        let Status::Connected {
            notice, since_unix, ..
        } = connected(&run, Some("first verdict"))
        else {
            panic!("connected")
        };
        assert_eq!(
            (notice.as_deref(), since_unix),
            (Some("latest verdict"), 1000)
        );
        // Reconnecting keeps the start time too.
        set(
            &run,
            Status::Reconnecting {
                profile: "work".into(),
                server: "gw.example.com".into(),
                attempt: 1,
                since_unix: 1000,
            },
        );
        let Status::Connected { since_unix, .. } = connected(&run, None) else {
            panic!("connected")
        };
        assert_eq!(since_unix, 1000);
    }

    #[tokio::test]
    async fn a_stop_interrupts_a_setup_step() {
        let (stop, mut stop_rx) = watch::channel(false);
        let quick = until_stopped(&mut stop_rx, async { 7 }).await;
        assert_eq!(quick, Some(7));
        stop.send(true).unwrap();
        let slow = until_stopped(&mut stop_rx, std::future::pending::<u8>()).await;
        assert_eq!(slow, None);
        // A closed channel stops too.
        let (stop, mut stop_rx) = watch::channel(false);
        drop(stop);
        let orphan = until_stopped(&mut stop_rx, std::future::pending::<u8>()).await;
        assert_eq!(orphan, None);
    }

    #[test]
    fn host_and_port() {
        assert_eq!(
            host_port("https://gw.example.com"),
            ("gw.example.com".into(), 443)
        );
        assert_eq!(
            host_port("https://gw.example.com:8443"),
            ("gw.example.com".into(), 8443)
        );
        assert_eq!(
            host_port("https://[2001:db8::1]:4443"),
            ("2001:db8::1".into(), 4443)
        );
    }
}
