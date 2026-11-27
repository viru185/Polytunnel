//! The Fortinet SSL VPN tunnel engine: PPP over TLS.
//!
//! 1. Fetch the tunnel configuration (`/remote/fortisslvpn_xml`).
//! 2. Open the TLS tunnel (`/remote/sslvpn-tunnel`) and negotiate PPP (LCP, then IPCP for
//!    the address and DNS servers).
//! 3. Create the TUN device and apply the network plan (journaled).
//! 4. Forward packets, answer and send LCP echoes, until stopped or the link drops.
//! 5. On disconnect: PPP terminate, log out, roll the network changes back.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use polytunnel_core::Secret;
use polytunnel_core::http::Transport;
use polytunnel_core::ipc::{FortiConnect, Status};
use polytunnel_core::pin::CertFingerprint;
use polytunnel_forti::ppp::{Event, IpConfig, Ppp};
use polytunnel_forti::tunnel::{self, TunnelSettings, frame};
use polytunnel_http::UreqTransport;
use polytunnel_net::journal::Journal;
use polytunnel_net::system::System;
use polytunnel_net::{Prefix, TunnelConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::timeout;

use crate::common::{
    Ended, STEP_TIMEOUT, StatusCell, blocking, bring_up, host_port, now_unix, set,
};
use crate::packets::{Channels, Pump};
use crate::{info, paths, warn};

const ECHO_INTERVAL: Duration = Duration::from_secs(10);
const DEAD_AFTER: Duration = Duration::from_secs(60);
const RETRANSMIT: Duration = Duration::from_secs(3);
const MRU: u16 = 1354;

/// Runs one Fortinet connection until it is stopped or fails. Always cleans up.
pub async fn run(c: FortiConnect, status: StatusCell, mut stop: watch::Receiver<bool>) {
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
    let result = connect_and_run(&c, &status, &mut stop, &mut journal, system.as_mut()).await;
    crate::killswitch::tunnel_down();
    if let Err(e) = journal.rollback(system.as_mut()) {
        warn!("could not undo every network change: {e}");
    }
    let (server, cookie, pin) = (c.server.clone(), c.cookie.clone(), c.server_cert);
    let _ = blocking(move || {
        UreqTransport::with_server_cert(pin)
            .send(&tunnel::logout_request(&server, &cookie))
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await;
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

/// The network plan input from the XML configuration and the PPP result.
pub fn tunnel_config(
    settings: &TunnelSettings,
    ip: &IpConfig,
    servers: Vec<IpAddr>,
) -> TunnelConfig {
    let prefixes = |list: &[(std::net::Ipv4Addr, std::net::Ipv4Addr)]| -> Vec<Prefix> {
        list.iter()
            .filter_map(|(net, mask)| Prefix::from_netmask(*net, *mask))
            .collect()
    };
    let mut dns_servers: Vec<IpAddr> = ip.dns.iter().map(|d| IpAddr::V4(*d)).collect();
    if dns_servers.is_empty() {
        dns_servers = settings.dns_servers.clone();
    }
    TunnelConfig {
        addresses: vec![Prefix::host(IpAddr::V4(ip.address))],
        mtu: MRU,
        routes: prefixes(&settings.routes),
        exclude_routes: prefixes(&settings.exclude_routes),
        dns_servers,
        dns_domains: settings.dns_suffixes.clone(),
        servers,
    }
}

async fn connect_and_run(
    c: &FortiConnect,
    status: &StatusCell,
    stop: &mut watch::Receiver<bool>,
    journal: &mut Journal,
    system: &mut dyn System,
) -> Result<(), String> {
    info!("connecting to {}", c.server);
    let settings = {
        let (server, cookie, pin) = (c.server.clone(), c.cookie.clone(), c.server_cert);
        blocking(move || {
            let response = UreqTransport::with_server_cert(pin)
                .send(&tunnel::config_request(&server, &cookie))
                .map_err(|e| e.to_string())?;
            tunnel::parse_config(&response).map_err(|e| e.to_string())
        })
        .await?
    };

    let (host, port) = host_port(&c.server);
    let addrs: Vec<SocketAddr> =
        timeout(STEP_TIMEOUT, tokio::net::lookup_host((host.clone(), port)))
            .await
            .map_err(|_| "resolving the server timed out".to_string())?
            .map_err(|e| format!("cannot resolve the server: {e}"))?
            .collect();
    let addr = *addrs.first().ok_or("the server has no address")?;

    let stream = open_tunnel(&host, port, addr, &c.cookie, c.server_cert.as_ref()).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut decoder = frame::Decoder::default();
    let magic = {
        let mut bytes = [0u8; 4];
        let _ = getrandom::fill(&mut bytes);
        // Never zero (PPP reserves it), even if the OS gave no randomness.
        (u32::from_be_bytes(bytes) ^ now_unix() as u32) | 1
    };
    let mut ppp = Ppp::new(magic, MRU, settings.address);
    let ip = negotiate(&mut ppp, &mut reader, &mut writer, &mut decoder).await?;
    info!("PPP is up with address {}", ip.address);

    let config = tunnel_config(&settings, &ip, addrs.iter().map(SocketAddr::ip).collect());
    let device = bring_up(&c.profile, &config, journal, system)?;
    let (pump, mut channels) =
        Pump::start(device.clone(), config.mtu).map_err(|e| e.to_string())?;
    set(
        status,
        Status::Connected {
            profile: c.profile.clone(),
            server: host.clone(),
            addresses: vec![ip.address.to_string()],
            transport: "ppp".into(),
            since_unix: now_unix(),
        },
    );
    let ended = ppp_loop(&mut ppp, reader, &mut writer, decoder, &mut channels, stop).await;
    let _ = writer.write_all(&frame::encode(&ppp.terminate())).await;
    drop(channels);
    pump.stop();
    match ended {
        Ended::Stopped => Ok(()),
        Ended::Lost(e) => Err(format!("the tunnel was lost: {e}")),
    }
}

async fn open_tunnel(
    host: &str,
    port: u16,
    addr: SocketAddr,
    cookie: &Secret,
    pin: Option<&CertFingerprint>,
) -> Result<tokio_native_tls::TlsStream<TcpStream>, String> {
    let tcp = timeout(STEP_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| "connecting to the server timed out".to_string())?
        .map_err(|e| format!("cannot connect to the server: {e}"))?;
    let connector = polytunnel_http::tls_connector(pin)?;
    let mut tls = timeout(
        STEP_TIMEOUT,
        tokio_native_tls::TlsConnector::from(connector).connect(host, tcp),
    )
    .await
    .map_err(|_| "the TLS handshake timed out".to_string())?
    .map_err(|e| format!("TLS: {e}"))?;
    // With a pinned certificate, nothing is sent before it is checked.
    if let Some(pin) = pin {
        polytunnel_http::check_pin(tls.get_ref(), pin)?;
    }
    let host_header = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    tls.write_all(&tunnel::tunnel_request(&host_header, cookie))
        .await
        .map_err(|e| e.to_string())?;
    Ok(tls)
}

async fn send_events<W: AsyncWrite>(
    writer: &mut WriteHalf<W>,
    events: &[Event],
) -> Result<(), String> {
    for event in events {
        if let Event::Send(packet) = event {
            writer
                .write_all(&frame::encode(packet))
                .await
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Runs LCP and IPCP until the link is up (or the step times out).
pub async fn negotiate<S: AsyncRead + AsyncWrite>(
    ppp: &mut Ppp,
    reader: &mut ReadHalf<S>,
    writer: &mut WriteHalf<S>,
    decoder: &mut frame::Decoder,
) -> Result<IpConfig, String> {
    send_events(writer, &ppp.start()).await?;
    let deadline = Instant::now() + STEP_TIMEOUT + STEP_TIMEOUT;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())
            .ok_or("the server did not complete PPP negotiation")?;
        match timeout(left.min(RETRANSMIT), reader.read(&mut buf)).await {
            Err(_) => send_events(writer, &ppp.retransmit()).await?,
            Ok(Ok(0)) => {
                return Err(
                    "the server closed the tunnel (is the session cookie still valid?)".into(),
                );
            }
            Ok(Ok(n)) => {
                decoder.feed(&buf[..n]);
                while let Some(packet) = decoder.next_packet().map_err(|e| e.to_string())? {
                    let events = ppp.receive(&packet).map_err(|e| e.to_string())?;
                    send_events(writer, &events).await?;
                    for event in events {
                        match event {
                            Event::Up(ip) => return Ok(ip),
                            Event::Down(reason) => return Err(reason),
                            _ => {}
                        }
                    }
                }
            }
            Ok(Err(e)) => return Err(e.to_string()),
        }
    }
}

/// Forwards packets over the established PPP link until stopped or broken.
pub async fn ppp_loop<S: AsyncRead + AsyncWrite>(
    ppp: &mut Ppp,
    mut reader: ReadHalf<S>,
    writer: &mut WriteHalf<S>,
    mut decoder: frame::Decoder,
    channels: &mut Channels,
    stop: &mut watch::Receiver<bool>,
) -> Ended {
    let mut buf = vec![0u8; 32 * 1024];
    let mut echo = tokio::time::interval(ECHO_INTERVAL);
    echo.tick().await;
    let mut last_rx = Instant::now();
    loop {
        if *stop.borrow() {
            return Ended::Stopped;
        }
        tokio::select! {
            changed = stop.changed() => if changed.is_err() || *stop.borrow() {
                return Ended::Stopped;
            },
            packet = channels.from_system.recv() => match packet {
                Some(packet) => if let Err(e) = writer.write_all(&frame::encode(&ppp.encode_ip(&packet))).await {
                    return Ended::Lost(e.to_string());
                },
                None => return Ended::Stopped,
            },
            read = reader.read(&mut buf) => match read {
                Ok(0) => return Ended::Lost("the server closed the tunnel".into()),
                Ok(n) => {
                    last_rx = Instant::now();
                    decoder.feed(&buf[..n]);
                    loop {
                        let packet = match decoder.next_packet() {
                            Ok(Some(p)) => p,
                            Ok(None) => break,
                            Err(e) => return Ended::Lost(e.to_string()),
                        };
                        let events = match ppp.receive(&packet) {
                            Ok(events) => events,
                            Err(e) => {
                                warn!("dropped a PPP packet: {e}");
                                continue;
                            }
                        };
                        for event in events {
                            match event {
                                Event::Send(p) => if let Err(e) = writer.write_all(&frame::encode(&p)).await {
                                    return Ended::Lost(e.to_string());
                                },
                                Event::Deliver(ip) => if channels.to_system.send(ip).await.is_err() {
                                    return Ended::Stopped;
                                },
                                Event::Down(reason) => return Ended::Lost(reason),
                                Event::Up(_) => {}
                            }
                        }
                    }
                }
                Err(e) => return Ended::Lost(e.to_string()),
            },
            _ = echo.tick() => {
                if last_rx.elapsed() > DEAD_AFTER {
                    return Ended::Lost("the server stopped answering".into());
                }
                if let Err(e) = writer.write_all(&frame::encode(&ppp.echo_request())).await {
                    return Ended::Lost(e.to_string());
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::io::DuplexStream;
    use tokio::sync::mpsc;

    use super::*;

    fn ppp_packet(protocol: u16, code: u8, id: u8, data: &[u8]) -> Vec<u8> {
        let mut out = protocol.to_be_bytes().to_vec();
        out.push(code);
        out.push(id);
        out.extend_from_slice(&((4 + data.len()) as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// A scripted FortiGate: acks LCP, naks IPCP with an address, then echoes IP packets.
    async fn fake_fortigate(mut server: DuplexStream) {
        let mut decoder = frame::Decoder::default();
        let mut buf = vec![0u8; 4096];
        let address = [10, 212, 134, 200];
        loop {
            let Ok(n) = server.read(&mut buf).await else {
                return;
            };
            if n == 0 {
                return;
            }
            decoder.feed(&buf[..n]);
            while let Ok(Some(p)) = decoder.next_packet() {
                let protocol = u16::from_be_bytes([p[0], p[1]]);
                let (code, id) = (p[2], p[3]);
                let reply: Vec<Vec<u8>> = match (protocol, code) {
                    (0xc021, 1) => vec![
                        ppp_packet(0xc021, 2, id, &p[6..]),
                        ppp_packet(0xc021, 1, 50, &[]),
                    ],
                    (0x8021, 1) if p[8..12] == address => {
                        vec![
                            ppp_packet(0x8021, 2, id, &p[6..]),
                            ppp_packet(0x8021, 1, 60, &[3, 6, 169, 254, 2, 1]),
                        ]
                    }
                    (0x8021, 1) => {
                        let mut nak = vec![3, 6];
                        nak.extend_from_slice(&address);
                        nak.extend_from_slice(&[129, 6, 10, 0, 0, 53, 131, 6, 10, 0, 0, 54]);
                        vec![ppp_packet(0x8021, 3, id, &nak)]
                    }
                    (0x0021, _) => vec![p.clone()], // echo IP packets back
                    _ => vec![],
                };
                for r in reply {
                    if server.write_all(&frame::encode(&r)).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn negotiates_and_forwards_against_a_fake_fortigate() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(fake_fortigate(server));
        let (mut reader, mut writer) = tokio::io::split(client);
        let mut decoder = frame::Decoder::default();
        let mut ppp = Ppp::new(0x1234_5679, MRU, None);
        let ip = negotiate(&mut ppp, &mut reader, &mut writer, &mut decoder)
            .await
            .unwrap();
        assert_eq!(ip.address, Ipv4Addr::new(10, 212, 134, 200));
        assert_eq!(
            ip.dns,
            vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)]
        );

        let (out_tx, out_rx) = mpsc::channel(8);
        let (in_tx, mut in_rx) = mpsc::channel(8);
        let mut channels = Channels {
            from_system: out_rx,
            to_system: in_tx,
        };
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            ppp_loop(
                &mut ppp,
                reader,
                &mut writer,
                decoder,
                &mut channels,
                &mut stop_rx,
            )
            .await
        });
        let packet = vec![0x45, 0, 0, 20, 1, 2, 3, 4];
        out_tx.send(packet.clone()).await.unwrap();
        assert_eq!(in_rx.recv().await.unwrap(), packet);
        stop_tx.send(true).unwrap();
        assert_eq!(task.await.unwrap(), Ended::Stopped);
    }

    #[test]
    fn config_from_xml_and_ipcp() {
        let settings = TunnelSettings {
            address: Some(Ipv4Addr::new(10, 212, 134, 200)),
            dns_servers: vec!["10.0.0.99".parse().unwrap()],
            dns_suffixes: vec!["corp.example.com".into()],
            routes: vec![(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 0, 0, 0))],
            exclude_routes: vec![],
            idle_timeout_secs: None,
        };
        let ip = IpConfig {
            address: Ipv4Addr::new(10, 212, 134, 200),
            dns: vec![Ipv4Addr::new(10, 0, 0, 53)],
        };
        let config = tunnel_config(&settings, &ip, vec!["203.0.113.10".parse().unwrap()]);
        assert_eq!(config.addresses, vec!["10.212.134.200/32".parse().unwrap()]);
        assert_eq!(config.routes, vec!["10.0.0.0/8".parse().unwrap()]);
        // DNS from IPCP wins over the XML.
        assert_eq!(
            config.dns_servers,
            vec!["10.0.0.53".parse::<IpAddr>().unwrap()]
        );
        let no_ipcp_dns = tunnel_config(&settings, &IpConfig { dns: vec![], ..ip }, vec![]);
        assert_eq!(
            no_ipcp_dns.dns_servers,
            vec!["10.0.0.99".parse::<IpAddr>().unwrap()]
        );
    }
}
