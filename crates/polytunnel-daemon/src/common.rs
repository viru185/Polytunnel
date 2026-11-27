//! Pieces shared by the tunnel engines: status, timeouts, and bringing the network up.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use polytunnel_core::ipc::Status;
use polytunnel_net::TunnelConfig;
use polytunnel_net::journal::Journal;
use polytunnel_net::plan::{Context, plan};
use polytunnel_net::system::System;
use polytunnel_net::tun::{self, SyncDevice, TunOptions};

use crate::paths;

pub type StatusCell = Arc<Mutex<Status>>;

/// Upper bound for each setup step (connect, handshake, first answer).
pub const STEP_TIMEOUT: Duration = Duration::from_secs(15);

/// How a transport loop ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    Stopped,
    Lost(String),
}

pub fn set(status: &StatusCell, value: Status) {
    *status.lock().unwrap_or_else(|e| e.into_inner()) = value;
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
    crate::killswitch::tunnel_up(tunnel_if, config.servers.clone());
    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::*;

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
