//! The Fortinet IPsec engine: IKEv1 or IKEv2 (`polytunnel-ike`) with ESP in UDP port 4500,
//! or IKEv2 with IKE and ESP in one TCP connection (RFC 9329).
//!
//! 1. Resolve the FortiGate and open the link: one ephemeral UDP socket for IKE and ESP, or a
//!    TCP connection that starts with `IKETCP`.
//! 2. Run IKE: IKEv1 aggressive mode, XAuth (extra rounds, such as one-time codes, are asked
//!    of the user through the app), mode-config, quick mode; or IKEv2 with a pre-shared key or
//!    EAP and the configuration payload.
//! 3. Create the TUN device with the assigned address and apply the network plan.
//! 4. Carry packets in ESP, keep the NAT mapping open, answer liveness checks and rekey.
//! 5. On disconnect: delete the SAs at the gateway and roll the network changes back.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use polytunnel_core::Secret;
use polytunnel_core::ipc::{IpsecConnect, Prompt, PromptField, Status};
use polytunnel_core::profile::{
    EapMethodName, IpsecTransport, LocalIdType, ModeConfigStyle, ServerAuthStyle,
    parse_ipv4_network,
};
use polytunnel_esp::udp::{self, Datagram};
use polytunnel_esp::{InboundSa, OutboundSa};
use polytunnel_ike::dh::Group;
use polytunnel_ike::eap::EapMethod;
use polytunnel_ike::tcp::{self, Frame};
use polytunnel_ike::v1::{
    self, Credentials, EspProposal, Identity, IkeProposal, ModeConfig, ModeConfigMode,
};
use polytunnel_ike::v2::{self, ClientAuth, IkeSuite, ServerAuth, Trust};
use polytunnel_ike::{Output, Session};
use polytunnel_net::journal::Journal;
use polytunnel_net::system::System;
use polytunnel_net::{Prefix, TunnelConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::common::{
    STEP_TIMEOUT, StatusCell, blocking, bring_up, conclude, connected_status, failed, set,
    tunnel_ended, until_stopped,
};
use crate::packets::{self, Pump};
use crate::{info, paths, warn};

/// ESP in UDP adds up to about 90 bytes to each packet; TCP framing a little more.
const MTU: u16 = 1400;
const TICK: Duration = Duration::from_millis(500);
/// How long a prompt may wait for the user before the attempt is abandoned.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(180);
/// Sends that keep failing this long mean the network is gone.
const SEND_FAILING_FOR: Duration = Duration::from_secs(30);
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
            warn!("cannot open the network journal: {e}");
            set(
                &status,
                failed(
                    profile,
                    "Polytunnel could not prepare the network settings. Restart the computer                      and try again."
                        .into(),
                ),
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
    let held = tunnel_ended(&status, &result);
    if let Err(e) = journal.rollback(system.as_mut()) {
        warn!("could not undo every network change: {e}");
    }
    conclude(&status, profile, &c.server, result, held);
}

fn proposals<T>(
    list: &[String],
    parse: fn(&str) -> Option<T>,
    what: &str,
) -> Result<Vec<T>, String> {
    list.iter()
        .map(|p| parse(p).ok_or_else(|| format!("unknown {what} proposal '{p}'")))
        .collect()
}

fn local_identity(c: &IpsecConnect) -> Result<Option<Identity>, String> {
    let Some(v) = &c.local_id else {
        return Ok(None);
    };
    Ok(Some(match c.local_id_type {
        LocalIdType::Fqdn => Identity::Fqdn(v.clone()),
        LocalIdType::UserFqdn => Identity::UserFqdn(v.clone()),
        LocalIdType::KeyId => Identity::KeyId(v.as_bytes().to_vec()),
        LocalIdType::Ipv4 => Identity::Ipv4(
            v.parse()
                .map_err(|_| "the local ID is not an IPv4 address".to_string())?,
        ),
    }))
}

fn remote_network(c: &IpsecConnect) -> Result<(Ipv4Addr, u8), String> {
    match &c.remote_network {
        Some(n) => parse_ipv4_network(n).ok_or_else(|| "invalid remote network".to_string()),
        None => Ok((Ipv4Addr::UNSPECIFIED, 0)),
    }
}

fn pfs(c: &IpsecConnect) -> Result<Option<Group>, String> {
    c.pfs_group
        .map(|g| Group::from_id(g).ok_or_else(|| format!("unsupported PFS group {g}")))
        .transpose()
}

/// The IKEv1 settings for a connect request.
pub fn ike_config(
    c: &IpsecConnect,
    local: SocketAddr,
    remote: SocketAddr,
) -> Result<v1::Config, String> {
    let config = v1::Config {
        psk: Zeroizing::new(c.psk.expose().as_bytes().to_vec()),
        local_id: local_identity(c)?,
        ike: proposals(&c.ike_proposals, IkeProposal::parse, "IKE")?,
        ike_lifetime: Duration::from_secs(c.ike_lifetime.into()),
        esp: proposals(&c.esp_proposals, EspProposal::parse, "ESP")?,
        pfs: pfs(c)?,
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
        remote_network: remote_network(c)?,
        dpd: (c.dpd > 0).then(|| Duration::from_secs(c.dpd.into())),
        local,
        remote,
        client_version: c.client_version.clone(),
    };
    config.validate()?;
    Ok(config)
}

/// The IKEv2 settings for a connect request. Loading the system's trusted roots can take a
/// moment, so this blocks.
pub fn ike2_config(
    c: &IpsecConnect,
    local: SocketAddr,
    remote: SocketAddr,
) -> Result<v2::Config, String> {
    let psk = || Zeroizing::new(c.psk.expose().as_bytes().to_vec());
    // The gateway's (and an EAP-TTLS server's) certificate: system roots plus the profile's
    // CA, issued for remote-id or the server name.
    let trust = || {
        let name = c.remote_id.clone().unwrap_or_else(|| c.server.clone());
        let pem = c.ca_pem.as_deref().unwrap_or_default();
        Trust::new(pem.as_bytes(), true, name)
    };
    let client_auth = match (c.eap, &c.xauth) {
        (Some(method), Some(login)) => ClientAuth::Eap {
            method: match method {
                EapMethodName::Mschapv2 => EapMethod::MsChapV2,
                EapMethodName::TtlsPap => EapMethod::TtlsPap,
            },
            username: login.username.clone(),
            password: Zeroizing::new(login.password.expose().to_string()),
            trust: match method {
                EapMethodName::TtlsPap => Some(trust()?),
                EapMethodName::Mschapv2 => None,
            },
        },
        (Some(_), None) => return Err("EAP needs a username and password".into()),
        (None, _) => ClientAuth::Psk(psk()),
    };
    let server_auth = match c.server_auth {
        ServerAuthStyle::Psk => ServerAuth::Psk(psk()),
        ServerAuthStyle::Certificate => ServerAuth::Certificate(trust()?),
    };
    let config = v2::Config {
        ike: proposals(&c.ike_proposals, IkeSuite::parse, "IKE")?,
        esp: proposals(&c.esp_proposals, EspProposal::parse, "ESP")?,
        pfs: pfs(c)?,
        ike_lifetime: Duration::from_secs(c.ike_lifetime.into()),
        esp_lifetime: Duration::from_secs(c.esp_lifetime.into()),
        local_id: local_identity(c)?,
        client_auth,
        server_auth,
        remote_network: remote_network(c)?,
        dpd: (c.dpd > 0).then(|| Duration::from_secs(c.dpd.into())),
        local,
        remote,
        reliable: c.transport == IpsecTransport::Tcp,
    };
    config.validate()?;
    Ok(config)
}

/// The network plan input from mode-config (or the IKEv2 configuration payload).
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

/// How IKE and ESP reach the gateway.
enum Link {
    Udp {
        socket: UdpSocket,
        gateway: Ipv4Addr,
        /// Whether IKE moved to port 4500 (then keepalives keep the NAT mapping open).
        natt_up: bool,
    },
    Tcp {
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
        decoder: tcp::Decoder,
    },
}

/// Something that came from the gateway.
enum Incoming {
    Ike(Vec<u8>),
    Esp(Vec<u8>),
    Nothing,
}

impl Link {
    async fn udp(gateway: Ipv4Addr) -> Result<(Self, SocketAddr), String> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|e| format!("cannot open a UDP socket: {e}"))?;
        let port = socket.local_addr().map_err(|e| e.to_string())?.port();
        let local = SocketAddr::new(IpAddr::V4(local_ip_towards(gateway)), port);
        Ok((
            Link::Udp {
                socket,
                gateway,
                natt_up: false,
            },
            local,
        ))
    }

    async fn tcp(gateway: Ipv4Addr, port: u16) -> Result<(Self, SocketAddr), String> {
        let mut stream = timeout(STEP_TIMEOUT, TcpStream::connect((gateway, port)))
            .await
            .map_err(|_| "connecting to the gateway over TCP timed out".to_string())?
            .map_err(|e| format!("cannot connect to the gateway over TCP: {e}"))?;
        let _ = stream.set_nodelay(true);
        let local = stream.local_addr().map_err(|e| e.to_string())?;
        stream
            .write_all(tcp::PREFIX)
            .await
            .map_err(|e| e.to_string())?;
        let (reader, writer) = stream.into_split();
        Ok((
            Link::Tcp {
                reader,
                writer,
                decoder: tcp::Decoder::default(),
            },
            local,
        ))
    }

    /// Sends an IKE message; false when it could not be sent.
    async fn send_ike(&mut self, natt: bool, message: &[u8]) -> bool {
        let sent = match self {
            Link::Udp {
                socket,
                gateway,
                natt_up,
            } => {
                if natt {
                    *natt_up = true;
                    socket
                        .send_to(&udp::ike_datagram(message), (*gateway, udp::NAT_T_PORT))
                        .await
                        .map(|_| ())
                } else {
                    socket
                        .send_to(message, (*gateway, IKE_PORT))
                        .await
                        .map(|_| ())
                }
            }
            Link::Tcp { writer, .. } => writer.write_all(&tcp::frame_ike(message)).await,
        };
        if let Err(e) = &sent {
            warn!("cannot send to the gateway: {e}");
        }
        sent.is_ok()
    }

    /// Sends an ESP packet; false when it could not be sent.
    async fn send_esp(&mut self, packet: &[u8]) -> bool {
        let sent = match self {
            Link::Udp {
                socket, gateway, ..
            } => socket
                .send_to(packet, (*gateway, udp::NAT_T_PORT))
                .await
                .map(|_| ()),
            Link::Tcp { writer, .. } => writer.write_all(&tcp::frame_esp(packet)).await,
        };
        if let Err(e) = &sent {
            warn!("cannot send to the gateway: {e}");
        }
        sent.is_ok()
    }

    async fn keepalive(&mut self) {
        if let Link::Udp {
            socket,
            gateway,
            natt_up: true,
        } = self
        {
            let _ = socket
                .send_to(&udp::NAT_KEEPALIVE, (*gateway, udp::NAT_T_PORT))
                .await;
        }
    }

    /// Waits for the next message from the gateway. Cancel-safe.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<Incoming, String> {
        match self {
            Link::Udp {
                socket, gateway, ..
            } => match socket.recv_from(buf).await {
                Ok((n, from)) if from.ip() == IpAddr::V4(*gateway) => {
                    if from.port() == udp::NAT_T_PORT {
                        Ok(match udp::classify(&buf[..n]) {
                            Datagram::Ike(m) => Incoming::Ike(m.to_vec()),
                            Datagram::Esp(p) => Incoming::Esp(p.to_vec()),
                            Datagram::Keepalive | Datagram::Invalid => Incoming::Nothing,
                        })
                    } else {
                        Ok(Incoming::Ike(buf[..n].to_vec()))
                    }
                }
                Ok(_) => Ok(Incoming::Nothing),
                // Windows reports an earlier ICMP "port unreachable" on the next receive.
                Err(e) if e.kind() == ErrorKind::ConnectionReset => Ok(Incoming::Nothing),
                Err(e) => Err(format!("the UDP socket failed: {e}")),
            },
            Link::Tcp {
                reader, decoder, ..
            } => loop {
                match decoder.next().map_err(|e| e.to_string())? {
                    Some(Frame::Ike(m)) => return Ok(Incoming::Ike(m)),
                    Some(Frame::Esp(p)) => return Ok(Incoming::Esp(p)),
                    None => {}
                }
                let n = reader
                    .read(buf)
                    .await
                    .map_err(|e| format!("the TCP connection failed: {e}"))?;
                if n == 0 {
                    return Err("the gateway closed the TCP connection".into());
                }
                decoder.push(&buf[..n]);
            },
        }
    }
}

/// One connection's moving parts.
struct Tunnel<'a> {
    c: &'a IpsecConnect,
    status: &'a StatusCell,
    gateway: Ipv4Addr,
    link: Link,
    remote_network: (Ipv4Addr, u8),
    ike: Box<dyn Session>,
    inbound: Vec<InboundSa>,
    outbound: Option<OutboundSa>,
    mode_config: Option<ModeConfig>,
    prompt: Option<(u32, Instant)>,
    prompt_seq: u32,
    from_system: Option<mpsc::Receiver<Vec<u8>>>,
    to_system: Option<mpsc::Sender<Vec<u8>>>,
    pump: Option<Pump>,
    /// Since when nothing could be sent to the gateway (the network went away).
    failing_since: Option<Instant>,
}

impl Tunnel<'_> {
    /// Notes whether a send worked.
    fn sent(&mut self, ok: bool) {
        if ok {
            self.failing_since = None;
        } else {
            self.failing_since.get_or_insert_with(Instant::now);
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
                Output::Send { natt, message } => {
                    let ok = self.link.send_ike(natt, &message).await;
                    self.sent(ok);
                }
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
                        "configuration: address {}, {} DNS server(s), {} split network(s)",
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
            .ok_or("the IPsec SA came up before the address was assigned")?;
        let config = tunnel_config(mc, IpAddr::V4(self.gateway), self.remote_network)?;
        let device = bring_up(&self.c.profile, &config, journal, system, self.status)?;
        let (pump, channels) = Pump::start(device, config.mtu).map_err(|e| e.to_string())?;
        self.status.set_counters(pump.counters());
        self.from_system = Some(channels.from_system);
        self.to_system = Some(channels.to_system);
        self.pump = Some(pump);
        let transport = match self.link {
            Link::Udp { .. } => "esp",
            Link::Tcp { .. } => "esp-tcp",
        };
        set(
            self.status,
            connected_status(
                self.status,
                &self.c.profile,
                &self.c.server,
                Some(self.gateway.to_string()),
                config
                    .addresses
                    .iter()
                    .map(|a| a.addr().to_string())
                    .collect(),
                transport,
                None,
            ),
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
                let ok = self.link.send_esp(&sealed).await;
                self.sent(ok);
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

/// Connects to the first of the request's gateways that answers, in order (FortiClient's
/// remote gateway list). A gateway that cannot be resolved or reached, or never answers IKE,
/// is skipped; one that answered and then refused stops there.
async fn connect_and_run(
    c: &IpsecConnect,
    status: &StatusCell,
    stop: &mut watch::Receiver<bool>,
    answers: &mut mpsc::Receiver<Answer>,
    journal: &mut Journal,
    system: &mut dyn System,
) -> Result<(), String> {
    let servers = c.servers();
    let mut silent: Vec<String> = Vec::new();
    for (i, server) in servers.iter().enumerate() {
        let mut one = c.clone();
        one.server.clone_from(server);
        match connect_to(&one, status, stop, answers, journal, system).await {
            Ok(()) => return Ok(()),
            Err((e, false)) if i + 1 < servers.len() => {
                warn!("{server} did not answer ({e}); trying the next gateway");
                silent.push(server.clone());
            }
            Err((e, _)) if silent.is_empty() => return Err(e),
            Err((e, _)) => {
                return Err(format!("{e} (no answer from {} either)", silent.join(", ")));
            }
        }
    }
    Err("the profile names no gateway".into())
}

/// One gateway. `Err((message, answered))`: `answered` is false when the gateway never
/// answered (another one may be tried).
async fn connect_to(
    c: &IpsecConnect,
    status: &StatusCell,
    stop: &mut watch::Receiver<bool>,
    answers: &mut mpsc::Receiver<Answer>,
    journal: &mut Journal,
    system: &mut dyn System,
) -> Result<(), (String, bool)> {
    let unanswered = |e: String| (e, false);
    let answered = |e: String| (e, true);
    let over_tcp = c.transport == IpsecTransport::Tcp;
    info!(
        "connecting to {} (IKEv{} over {})",
        c.server,
        c.ike_version,
        if over_tcp { "TCP" } else { "UDP" }
    );
    let gateway = match until_stopped(stop, resolve(&c.server)).await {
        Some(gateway) => gateway.map_err(unanswered)?,
        None => return Ok(()),
    };
    let link = async {
        if over_tcp {
            Link::tcp(gateway, c.tcp_port).await
        } else {
            Link::udp(gateway).await
        }
    };
    let (link, local) = match until_stopped(stop, link).await {
        Some(link) => link.map_err(unanswered)?,
        None => return Ok(()),
    };
    let remote = SocketAddr::new(
        IpAddr::V4(gateway),
        if over_tcp { c.tcp_port } else { IKE_PORT },
    );
    // Problems with the request itself are not the gateway's: no other gateway is tried.
    let remote_network = remote_network(c).map_err(answered)?;
    let ike: Box<dyn Session> = if c.ike_version == 2 {
        let request = c.clone();
        let config = blocking(move || ike2_config(&request, local, remote))
            .await
            .map_err(answered)?;
        Box::new(v2::Initiator::new(config, Instant::now()).map_err(answered)?)
    } else {
        Box::new(
            v1::Initiator::new(
                ike_config(c, local, remote).map_err(answered)?,
                Instant::now(),
            )
            .map_err(answered)?,
        )
    };
    let mut tunnel = Tunnel {
        c,
        status,
        gateway,
        link,
        remote_network,
        ike,
        inbound: Vec::new(),
        outbound: None,
        mode_config: None,
        prompt: None,
        prompt_seq: 0,
        from_system: None,
        to_system: None,
        pump: None,
        failing_since: None,
    };
    let mut outs = tunnel.ike.start(Instant::now());
    let mut tick = tokio::time::interval(TICK);
    let keepalive_every = Duration::from_secs(u64::from(c.nat_keepalive.max(1)));
    let mut keepalive = tokio::time::interval(keepalive_every);
    let mut buf = vec![0u8; 65_536];
    let mut answers_open = true;
    // Whether the gateway has answered at all (before that, another gateway may be tried).
    let mut heard = false;
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
            received = tunnel.link.recv(&mut buf) => match received {
                Ok(Incoming::Ike(message)) => {
                    heard = true;
                    outs = tunnel.ike.receive(Instant::now(), &message);
                }
                Ok(Incoming::Esp(packet)) => tunnel.on_esp(&packet).await,
                Ok(Incoming::Nothing) => {}
                Err(e) => break Err(e),
            },
            packet = async {
                match from_system {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => match packet {
                Some(packet) => tunnel.on_packet(&packet).await,
                None => break Err(packets::INTERFACE_STOPPED.into()),
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
                // Without dead-peer detection nothing else would notice the network going.
                if tunnel.failing_since.is_some_and(|since| since.elapsed() > SEND_FAILING_FOR) {
                    break Err("nothing can be sent to the gateway any more".into());
                }
                outs = tunnel.ike.poll(Instant::now());
            },
            _ = keepalive.tick(), if c.nat_keepalive > 0 => tunnel.link.keepalive().await,
        }
    };
    // Tell the gateway (best effort), then take the interface down.
    if !tunnel.ike.is_closed() {
        for out in tunnel.ike.close() {
            if let Output::Send { natt, message } = out {
                let _ = tunnel.link.send_ike(natt, &message).await;
            }
        }
    }
    tunnel.stop_pump();
    result.map_err(|e| (e, heard))
}

#[cfg(test)]
mod tests {
    use polytunnel_core::ipc::XauthLogin;

    use super::*;

    fn request() -> IpsecConnect {
        IpsecConnect {
            profile: "office".into(),
            server: "vpn.example.net".into(),
            backup_servers: Vec::new(),
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
            ike_version: 1,
            eap: None,
            server_auth: ServerAuthStyle::Psk,
            ca_pem: None,
            remote_id: None,
            transport: IpsecTransport::Udp,
            tcp_port: 443,
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
    fn ikev2_requests_become_ikev2_settings() {
        let local: SocketAddr = "192.0.2.5:40000".parse().unwrap();
        let remote: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let mut c = request();
        c.ike_version = 2;
        c.transport = IpsecTransport::Tcp;
        c.eap = Some(EapMethodName::Mschapv2);
        let config = ike2_config(&c, local, remote).unwrap();
        assert!(config.reliable);
        assert!(matches!(config.client_auth, ClientAuth::Eap { .. }));
        assert!(matches!(config.server_auth, ServerAuth::Psk(_)));
        c.eap = None;
        c.transport = IpsecTransport::Udp;
        let config = ike2_config(&c, local, remote).unwrap();
        assert!(matches!(config.client_auth, ClientAuth::Psk(_)));
        assert!(!config.reliable);
        c.xauth = None;
        c.eap = Some(EapMethodName::Mschapv2);
        assert!(ike2_config(&c, local, remote).is_err());
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
