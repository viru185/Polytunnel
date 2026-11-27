//! The Fortinet IPsec engine: IKEv1 (`polytunnel-ike`) and ESP in UDP port 4500.
//!
//! 1. Resolve the FortiGate and open one ephemeral UDP socket for IKE and ESP.
//! 2. Run IKE: aggressive mode, XAuth (extra rounds, such as one-time codes, are asked of
//!    the user through the app), mode-config, quick mode.
//! 3. Create the TUN device with the assigned address and apply the network plan.
//! 4. Carry packets in ESP, keep the NAT mapping open, answer DPD and rekey.
//! 5. On disconnect: delete the SAs at the gateway and roll the network changes back.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use polytunnel_core::Secret;
use polytunnel_core::ipc::{IpsecConnect, Prompt, PromptField, Status};
use polytunnel_core::profile::{LocalIdType, ModeConfigStyle, parse_ipv4_network};
use polytunnel_esp::udp::{self, Datagram};
use polytunnel_esp::{InboundSa, OutboundSa};
use polytunnel_ike::dh::Group;
use polytunnel_ike::v1::{
    self, Credentials, EspProposal, Identity, IkeProposal, Initiator, ModeConfig, ModeConfigMode,
    Output,
};
use polytunnel_net::journal::Journal;
use polytunnel_net::system::System;
use polytunnel_net::{Prefix, TunnelConfig};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::common::{STEP_TIMEOUT, StatusCell, bring_up, now_unix, set};
use crate::packets::{self, Pump};
use crate::{info, paths, warn};

/// ESP in UDP adds up to about 90 bytes to each packet.
const MTU: u16 = 1400;
const TICK: Duration = Duration::from_millis(500);
/// How long a prompt may wait for the user before the attempt is abandoned.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(180);
const IKE_PORT: u16 = 500;

/// A prompt's ID and the user's values.
pub type Answer = (u32, Vec<Secret>);

/// Runs one IPsec connection until it is stopped or fails. Always cleans up.
pub async fn run(
    c: IpsecConnect,
    status: StatusCell,
    mut stop: watch::Receiver<bool>,
    mut answers: mpsc::Receiver<Answer>,
) {
    let profile = c.profile.clone();
    let mut system = polytunnel_net::system::native();
    let mut journal = match Journal::open(paths::journal_file()) {
        Ok(j) => j,
        Err(e) => {
            set(
                &status,
                Status::Failed {
                    profile,
                    message: format!("network journal: {e}"),
                },
            );
            return;
        }
    };
    let result = connect_and_run(
        &c,
        &status,
        &mut stop,
        &mut answers,
        &mut journal,
        system.as_mut(),
    )
    .await;
    if let Err(e) = journal.rollback(system.as_mut()) {
        warn!("could not undo every network change: {e}");
    }
    match result {
        Ok(()) => {
            info!("disconnected from {}", c.server);
            set(&status, Status::Idle {});
        }
        Err(message) => {
            warn!("connection to {} failed: {message}", c.server);
            set(&status, Status::Failed { profile, message });
        }
    }
}

/// The IKE settings for a connect request.
pub fn ike_config(
    c: &IpsecConnect,
    local: SocketAddr,
    remote: SocketAddr,
) -> Result<v1::Config, String> {
    let ike = c
        .ike_proposals
        .iter()
        .map(|p| IkeProposal::parse(p).ok_or_else(|| format!("unknown IKE proposal '{p}'")))
        .collect::<Result<Vec<_>, _>>()?;
    let esp = c
        .esp_proposals
        .iter()
        .map(|p| EspProposal::parse(p).ok_or_else(|| format!("unknown ESP proposal '{p}'")))
        .collect::<Result<Vec<_>, _>>()?;
    let pfs = c
        .pfs_group
        .map(|g| Group::from_id(g).ok_or_else(|| format!("unsupported PFS group {g}")))
        .transpose()?;
    let local_id = match &c.local_id {
        None => None,
        Some(v) => Some(match c.local_id_type {
            LocalIdType::Fqdn => Identity::Fqdn(v.clone()),
            LocalIdType::UserFqdn => Identity::UserFqdn(v.clone()),
            LocalIdType::KeyId => Identity::KeyId(v.as_bytes().to_vec()),
            LocalIdType::Ipv4 => Identity::Ipv4(
                v.parse()
                    .map_err(|_| "the local ID is not an IPv4 address".to_string())?,
            ),
        }),
    };
    let remote_network = match &c.remote_network {
        Some(n) => parse_ipv4_network(n).ok_or("invalid remote network")?,
        None => (Ipv4Addr::UNSPECIFIED, 0),
    };
    let config = v1::Config {
        psk: Zeroizing::new(c.psk.expose().as_bytes().to_vec()),
        local_id,
        ike,
        ike_lifetime: Duration::from_secs(c.ike_lifetime.into()),
        esp,
        pfs,
        esp_lifetime: Duration::from_secs(c.esp_lifetime.into()),
        esp_lifetime_kb: c.esp_lifetime_kb,
        xauth: c.xauth.as_ref().map(|x| Credentials {
            username: x.username.clone(),
            password: Zeroizing::new(x.password.expose().to_string()),
        }),
        mode_config: match c.mode_config {
            ModeConfigStyle::Pull => ModeConfigMode::Pull,
            ModeConfigStyle::Push => ModeConfigMode::Push,
        },
        remote_network,
        dpd: (c.dpd > 0).then(|| Duration::from_secs(c.dpd.into())),
        local,
        remote,
        client_version: c.client_version.clone(),
    };
    config.validate()?;
    Ok(config)
}

/// The network plan input from mode-config.
pub fn tunnel_config(
    mc: &ModeConfig,
    gateway: IpAddr,
    remote_network: (Ipv4Addr, u8),
) -> Result<TunnelConfig, String> {
    let address = mc.address.ok_or("the gateway assigned no address")?;
    let mut routes: Vec<Prefix> = mc
        .split_include
        .iter()
        .filter_map(|(net, len)| Prefix::new(IpAddr::V4(*net), *len))
        .collect();
    if routes.is_empty() && remote_network.1 > 0 {
        routes.extend(Prefix::new(IpAddr::V4(remote_network.0), remote_network.1));
    }
    let mut dns_domains = mc.split_dns.clone();
    if let Some(d) = &mc.default_domain
        && !dns_domains.contains(d)
    {
        dns_domains.push(d.clone());
    }
    dns_domains.retain(|d| polytunnel_net::plan::valid_domain(d));
    Ok(TunnelConfig {
        addresses: vec![Prefix::host(IpAddr::V4(address))],
        mtu: MTU,
        routes,
        exclude_routes: Vec::new(),
        dns_servers: mc.dns.iter().map(|d| IpAddr::V4(*d)).collect(),
        dns_domains,
        servers: vec![gateway],
    })
}

async fn resolve(server: &str) -> Result<Ipv4Addr, String> {
    let addrs = timeout(STEP_TIMEOUT, tokio::net::lookup_host((server, IKE_PORT)))
        .await
        .map_err(|_| "resolving the server timed out".to_string())?
        .map_err(|e| format!("cannot resolve the server: {e}"))?;
    for addr in addrs {
        if let IpAddr::V4(v4) = addr.ip() {
            return Ok(v4);
        }
    }
    Err("the server has no IPv4 address".into())
}

/// The local address the system would use towards `gateway` (connecting a UDP socket sends
/// nothing).
fn local_ip_towards(gateway: Ipv4Addr) -> Ipv4Addr {
    std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|s| {
            s.connect((gateway, IKE_PORT))?;
            s.local_addr()
        })
        .ok()
        .and_then(|a| match a.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

/// One connection's moving parts.
struct Tunnel<'a> {
    c: &'a IpsecConnect,
    status: &'a StatusCell,
    socket: UdpSocket,
    gateway: Ipv4Addr,
    remote_network: (Ipv4Addr, u8),
    ike: Initiator,
    inbound: Vec<InboundSa>,
    outbound: Option<OutboundSa>,
    mode_config: Option<ModeConfig>,
    prompt: Option<(u32, Instant)>,
    prompt_seq: u32,
    /// Whether IKE moved to port 4500 (from then on, keepalives keep the NAT mapping open).
    natt_up: bool,
    from_system: Option<mpsc::Receiver<Vec<u8>>>,
    to_system: Option<mpsc::Sender<Vec<u8>>>,
    pump: Option<Pump>,
}

impl Tunnel<'_> {
    fn ike_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.gateway), IKE_PORT)
    }

    fn natt_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.gateway), udp::NAT_T_PORT)
    }

    async fn send_ike(&mut self, natt: bool, message: &[u8]) {
        let sent = if natt {
            self.natt_up = true;
            self.socket
                .send_to(&udp::ike_datagram(message), self.natt_addr())
                .await
        } else {
            self.socket.send_to(message, self.ike_addr()).await
        };
        if let Err(e) = sent {
            warn!("cannot send to the gateway: {e}");
        }
    }

    /// Carries out what IKE asked for. `Some`: the session is over.
    async fn carry_out(
        &mut self,
        outs: Vec<Output>,
        journal: &mut Journal,
        system: &mut dyn System,
    ) -> Option<Result<(), String>> {
        for out in outs {
            match out {
                Output::Send { natt, message } => self.send_ike(natt, &message).await,
                Output::Prompt(p) => {
                    self.prompt_seq += 1;
                    self.prompt = Some((self.prompt_seq, Instant::now()));
                    info!("the gateway asks for more sign-in input");
                    set(
                        self.status,
                        Status::NeedsInput {
                            profile: self.c.profile.clone(),
                            prompt: Prompt {
                                id: self.prompt_seq,
                                message: p.message,
                                fields: p
                                    .fields
                                    .iter()
                                    .map(|f| PromptField {
                                        label: f.label().into(),
                                        secret: f.secret(),
                                    })
                                    .collect(),
                            },
                        },
                    );
                }
                Output::Configured(mc) => {
                    info!(
                        "mode-config: address {}, {} DNS server(s), {} split network(s)",
                        mc.address.map_or("none".into(), |a| a.to_string()),
                        mc.dns.len(),
                        mc.split_include.len()
                    );
                    self.mode_config = Some(mc);
                }
                Output::ChildSa(sa) => {
                    info!(
                        "IPsec SA up: {} for {} s",
                        sa.proposal,
                        sa.lifetime.as_secs()
                    );
                    self.inbound
                        .push(InboundSa::new(sa.inbound_spi, sa.inbound, 128));
                    self.outbound = Some(OutboundSa::new(sa.outbound_spi, sa.outbound));
                    if self.pump.is_none()
                        && let Err(e) = self.bring_up(journal, system)
                    {
                        return Some(Err(e));
                    }
                }
                Output::Retire { inbound_spi } => {
                    self.inbound.retain(|sa| sa.spi() != inbound_spi);
                }
                Output::Closed { reason, .. } => return Some(Err(reason)),
            }
        }
        None
    }

    fn bring_up(&mut self, journal: &mut Journal, system: &mut dyn System) -> Result<(), String> {
        let mc = self
            .mode_config
            .as_ref()
            .ok_or("the IPsec SA came up before mode-config")?;
        let config = tunnel_config(mc, IpAddr::V4(self.gateway), self.remote_network)?;
        let device = bring_up(&self.c.profile, &config, journal, system)?;
        let (pump, channels) = Pump::start(device, config.mtu).map_err(|e| e.to_string())?;
        self.from_system = Some(channels.from_system);
        self.to_system = Some(channels.to_system);
        self.pump = Some(pump);
        set(
            self.status,
            Status::Connected {
                profile: self.c.profile.clone(),
                server: self.c.server.clone(),
                addresses: config
                    .addresses
                    .iter()
                    .map(|a| a.addr().to_string())
                    .collect(),
                transport: "esp".into(),
                since_unix: now_unix(),
            },
        );
        info!("connected to {} over IPsec", self.c.server);
        Ok(())
    }

    async fn on_esp(&mut self, packet: &[u8]) {
        let Some(spi) = packet.get(..4) else {
            return;
        };
        let Some(sa) = self
            .inbound
            .iter_mut()
            .find(|sa| sa.spi().to_be_bytes() == spi)
        else {
            return;
        };
        match sa.open(packet) {
            Ok((_, inner)) => {
                self.ike.note_alive(Instant::now());
                if let Some(tx) = &self.to_system {
                    let _ = tx.send(inner).await;
                }
            }
            Err(e) => warn!("dropped an ESP packet: {e}"),
        }
    }

    async fn on_packet(&mut self, packet: &[u8]) {
        let Some(sa) = &mut self.outbound else {
            return;
        };
        match sa.seal(packets::next_header(packet), packet) {
            Ok(sealed) => {
                let to = self.natt_addr();
                if let Err(e) = self.socket.send_to(&sealed, to).await {
                    warn!("cannot send to the gateway: {e}");
                }
            }
            Err(e) => warn!("cannot encrypt a packet: {e}"),
        }
    }

    fn stop_pump(&mut self) {
        self.from_system = None;
        self.to_system = None;
        if let Some(pump) = self.pump.take() {
            pump.stop();
        }
    }
}

async fn connect_and_run(
    c: &IpsecConnect,
    status: &StatusCell,
    stop: &mut watch::Receiver<bool>,
    answers: &mut mpsc::Receiver<Answer>,
    journal: &mut Journal,
    system: &mut dyn System,
) -> Result<(), String> {
    info!("connecting to {} (IPsec)", c.server);
    let gateway = resolve(&c.server).await?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|e| format!("cannot open a UDP socket: {e}"))?;
    let port = socket.local_addr().map_err(|e| e.to_string())?.port();
    let local = SocketAddr::new(IpAddr::V4(local_ip_towards(gateway)), port);
    let remote = SocketAddr::new(IpAddr::V4(gateway), IKE_PORT);
    let config = ike_config(c, local, remote)?;
    let remote_network = config.remote_network;
    let mut tunnel = Tunnel {
        c,
        status,
        socket,
        gateway,
        remote_network,
        ike: Initiator::new(config, Instant::now())?,
        inbound: Vec::new(),
        outbound: None,
        mode_config: None,
        prompt: None,
        prompt_seq: 0,
        natt_up: false,
        from_system: None,
        to_system: None,
        pump: None,
    };
    let mut outs = tunnel.ike.start(Instant::now());
    let mut tick = tokio::time::interval(TICK);
    let keepalive_every = Duration::from_secs(u64::from(c.nat_keepalive.max(1)));
    let mut keepalive = tokio::time::interval(keepalive_every);
    let mut buf = vec![0u8; 65_536];
    let mut answers_open = true;
    let result = loop {
        if let Some(end) = tunnel
            .carry_out(std::mem::take(&mut outs), journal, system)
            .await
        {
            break end;
        }
        if *stop.borrow() {
            break Ok(());
        }
        let from_system = tunnel.from_system.as_mut();
        tokio::select! {
            changed = stop.changed() => if changed.is_err() || *stop.borrow() {
                break Ok(());
            },
            received = tunnel.socket.recv_from(&mut buf) => match received {
                Ok((n, from)) if from.ip() == IpAddr::V4(gateway) => {
                    let now = Instant::now();
                    if from.port() == udp::NAT_T_PORT {
                        match udp::classify(&buf[..n]) {
                            Datagram::Ike(message) => outs = tunnel.ike.receive(now, message),
                            Datagram::Esp(packet) => tunnel.on_esp(packet).await,
                            Datagram::Keepalive | Datagram::Invalid => {}
                        }
                    } else {
                        outs = tunnel.ike.receive(now, &buf[..n]);
                    }
                }
                Ok(_) => {}
                // Windows reports an earlier ICMP "port unreachable" on the next receive.
                Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
                Err(e) => break Err(format!("the UDP socket failed: {e}")),
            },
            packet = async {
                match from_system {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => match packet {
                Some(packet) => tunnel.on_packet(&packet).await,
                None => break Ok(()),
            },
            answer = answers.recv(), if answers_open => match answer {
                Some((id, values)) if tunnel.prompt.is_some_and(|(p, _)| p == id) => {
                    tunnel.prompt = None;
                    set(status, Status::Connecting { profile: c.profile.clone() });
                    outs = tunnel.ike.answer(
                        values.iter().map(|v| Zeroizing::new(v.expose().to_string())).collect(),
                    );
                }
                Some(_) => {}
                None => answers_open = false,
            },
            _ = tick.tick() => {
                if tunnel.prompt.is_some_and(|(_, since)| since.elapsed() > PROMPT_TIMEOUT) {
                    break Err("nobody answered the sign-in prompt".into());
                }
                outs = tunnel.ike.poll(Instant::now());
            },
            _ = keepalive.tick(), if c.nat_keepalive > 0 && tunnel.natt_up => {
                let to = tunnel.natt_addr();
                let _ = tunnel.socket.send_to(&udp::NAT_KEEPALIVE, to).await;
            },
        }
    };
    // Tell the gateway (best effort), then take the interface down.
    if !tunnel.ike.is_closed() {
        for out in tunnel.ike.close() {
            if let Output::Send { natt, message } = out {
                tunnel.send_ike(natt, &message).await;
            }
        }
    }
    tunnel.stop_pump();
    result
}

#[cfg(test)]
mod tests {
    use polytunnel_core::ipc::XauthLogin;

    use super::*;

    fn request() -> IpsecConnect {
        IpsecConnect {
            profile: "office".into(),
            server: "vpn.example.net".into(),
            psk: Secret::new(["shared", "key"].join("-")),
            xauth: Some(XauthLogin {
                username: "user".into(),
                password: Secret::new(["pass", "word"].concat()),
            }),
            local_id: Some("laptop".into()),
            local_id_type: LocalIdType::KeyId,
            ike_proposals: vec![
                "aes256-sha256-modp2048".into(),
                "aes128-sha1-modp2048".into(),
            ],
            esp_proposals: vec!["aes256-sha256".into(), "aes128gcm16".into()],
            pfs_group: Some(14),
            ike_lifetime: 86_400,
            esp_lifetime: 43_200,
            esp_lifetime_kb: Some(5120),
            mode_config: ModeConfigStyle::Pull,
            remote_network: Some("198.51.100.0/24".into()),
            dpd: 20,
            nat_keepalive: 5,
            client_version: "Polytunnel test".into(),
        }
    }

    #[test]
    fn requests_become_ike_settings() {
        let local: SocketAddr = "192.0.2.5:40000".parse().unwrap();
        let remote: SocketAddr = "203.0.113.1:500".parse().unwrap();
        let config = ike_config(&request(), local, remote).unwrap();
        assert_eq!(config.ike.len(), 2);
        assert_eq!(config.pfs, Some(Group::Modp2048));
        assert_eq!(config.local_id, Some(Identity::KeyId(b"laptop".to_vec())));
        assert_eq!(config.remote_network, ("198.51.100.0".parse().unwrap(), 24));
        assert_eq!(config.dpd, Some(Duration::from_secs(20)));
        assert_eq!(config.esp_lifetime_kb, Some(5120));

        let mut bad = request();
        bad.ike_proposals = vec!["aes256-sha256".into()];
        assert!(ike_config(&bad, local, remote).is_err(), "group missing");
        let mut mixed = request();
        mixed.ike_proposals = vec![
            "aes256-sha256-modp2048".into(),
            "aes256-sha256-modp1536".into(),
        ];
        assert!(ike_config(&mixed, local, remote).is_err(), "one group only");
    }

    #[test]
    fn mode_config_becomes_a_network_plan() {
        let gateway: IpAddr = "203.0.113.1".parse().unwrap();
        let mut mc = ModeConfig {
            address: Some("198.51.100.77".parse().unwrap()),
            dns: vec!["198.51.100.53".parse().unwrap()],
            default_domain: Some("corp.example.com".into()),
            split_dns: vec!["example.net".into(), "bad domain".into()],
            ..ModeConfig::default()
        };
        let full = tunnel_config(&mc, gateway, (Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        assert!(full.is_full_tunnel());
        assert_eq!(full.servers, vec![gateway]);
        assert_eq!(full.dns_domains, vec!["example.net", "corp.example.com"]);
        let selector = tunnel_config(&mc, gateway, ("198.51.100.0".parse().unwrap(), 24)).unwrap();
        assert_eq!(
            selector.routes,
            vec![Prefix::new("198.51.100.0".parse().unwrap(), 24).unwrap()]
        );
        mc.split_include = vec![("192.0.2.0".parse().unwrap(), 24)];
        let split = tunnel_config(&mc, gateway, (Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        assert!(!split.is_full_tunnel());
        assert_eq!(
            split.addresses,
            vec![Prefix::host("198.51.100.77".parse().unwrap())]
        );
        mc.address = None;
        assert!(tunnel_config(&mc, gateway, (Ipv4Addr::UNSPECIFIED, 0)).is_err());
    }
}
