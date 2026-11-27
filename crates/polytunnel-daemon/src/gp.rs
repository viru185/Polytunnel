//! The GlobalProtect tunnel engine.
//!
//! 1. Fetch the tunnel configuration (addresses, routes, DNS, ESP keys).
//! 2. Create the TUN device and apply the network plan (journaled).
//! 3. Send an honest HIP report if the gateway asks for one.
//! 4. Try ESP over UDP (checked with an ICMP probe); otherwise, or if ESP stops working,
//!    use the TLS tunnel, reconnecting a few times if it drops.
//! 5. On disconnect: log out, remove the device, roll the network changes back.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use polytunnel_core::http::Transport;
use polytunnel_core::ipc::{GpConnect, Status};
use polytunnel_esp::{Cipher, InboundSa, Integrity, Keys, OutboundSa};
use polytunnel_gp::login::GatewaySession;
use polytunnel_gp::tunnel::{self, EspHmac, EspSettings, TunnelSettings, frame};
use polytunnel_gp::{ClientInfo, hip};
use polytunnel_http::UreqTransport;
use polytunnel_net::journal::Journal;
use polytunnel_net::system::System;
use polytunnel_net::{Prefix, TunnelConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::time::timeout;

use crate::common::{
    Ended, STEP_TIMEOUT, StatusCell, blocking, bring_up, host_port, now_unix, set,
};
use crate::packets::{self, Channels, Pump};
use crate::{info, paths, warn};

const TLS_KEEPALIVE: Duration = Duration::from_secs(30);
const ESP_KEEPALIVE: Duration = Duration::from_secs(10);
const ESP_DEAD_AFTER: Duration = Duration::from_secs(45);
const TLS_RECONNECTS: usize = 3;
const PROBE_ID: u16 = 0x7054;
const PROBE_PAYLOAD: &[u8] = b"polytunnel esp probe";

/// `MM/DD/YYYY HH:MM:SS` in UTC (for HIP reports).
fn hip_time() -> String {
    let secs = now_unix() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{month:02}/{day:02}/{year:04} {:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn client_and_session(c: &GpConnect) -> (ClientInfo, GatewaySession) {
    let client = ClientInfo {
        os: c.client.os,
        os_version: c.client.os_version.clone(),
        computer: c.client.computer.clone(),
        host_id: c.client.host_id.clone(),
        app_version: c.client.app_version.clone(),
    };
    let session = GatewaySession {
        gateway: c.gateway.clone(),
        authcookie: c.authcookie.clone(),
        portal: c.portal.clone(),
        user: c.user.clone(),
        domain: c.domain.clone(),
        computer: c.client.computer.clone(),
        preferred_ip: c.preferred_ip.clone(),
        preferred_ipv6: c.preferred_ipv6.clone(),
    };
    (client, session)
}

/// The network plan input for the gateway's settings.
pub fn tunnel_config(settings: &TunnelSettings, servers: Vec<IpAddr>) -> TunnelConfig {
    // The interface gets the assigned addresses themselves (host prefixes); what is
    // reachable through the tunnel is decided by the routes.
    let mut addresses = Vec::new();
    if let Some((ip, _)) = settings.address_v4 {
        addresses.push(Prefix::host(IpAddr::V4(ip)));
    }
    if let Some((ip, _)) = settings.address_v6 {
        addresses.push(Prefix::host(IpAddr::V6(ip)));
    }
    let parse =
        |list: &[String]| -> Vec<Prefix> { list.iter().filter_map(|r| r.parse().ok()).collect() };
    TunnelConfig {
        addresses,
        mtu: settings.mtu.unwrap_or(1400),
        routes: parse(&settings.routes),
        exclude_routes: parse(&settings.exclude_routes),
        dns_servers: settings.dns_servers.clone(),
        dns_domains: settings.dns_suffixes.clone(),
        servers,
    }
}

/// Runs one GlobalProtect connection until it is stopped or fails. Always cleans up.
pub async fn run(c: GpConnect, status: StatusCell, mut stop: watch::Receiver<bool>) {
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
    match result {
        Ok(()) => {
            info!("disconnected from {}", c.gateway);
            set(&status, Status::Idle {});
        }
        Err(message) => {
            warn!("connection to {} failed: {message}", c.gateway);
            set(&status, Status::Failed { profile, message });
        }
    }
}

async fn connect_and_run(
    c: &GpConnect,
    status: &StatusCell,
    stop: &mut watch::Receiver<bool>,
    journal: &mut Journal,
    system: &mut dyn System,
) -> Result<(), String> {
    let (client, session) = client_and_session(c);
    info!("connecting to {}", c.gateway);

    let settings = {
        let (client, session) = (client.clone(), session.clone());
        blocking(move || {
            let response = UreqTransport::new()
                .send(&tunnel::getconfig_request(&client, &session))
                .map_err(|e| e.to_string())?;
            tunnel::parse_getconfig(&response).map_err(|e| e.to_string())
        })
        .await?
    };

    let (host, port) = host_port(&session.gateway);
    let gateway_addrs: Vec<SocketAddr> =
        timeout(STEP_TIMEOUT, tokio::net::lookup_host((host.clone(), port)))
            .await
            .map_err(|_| "resolving the gateway timed out".to_string())?
            .map_err(|e| format!("cannot resolve the gateway: {e}"))?
            .collect();
    let gateway_addr = *gateway_addrs.first().ok_or("the gateway has no address")?;
    let mut servers: Vec<IpAddr> = gateway_addrs.iter().map(SocketAddr::ip).collect();
    servers.extend(settings.gateway_address);

    let config = tunnel_config(&settings, servers.clone());
    let device = bring_up(&c.profile, &config, journal, system)?;

    if let Some((ip, _)) = settings.address_v4 {
        let (client, session) = (client.clone(), session.clone());
        let hip = blocking(move || hip_exchange(&client, &session, &ip.to_string())).await;
        if let Err(e) = hip {
            warn!("HIP report: {e}");
        }
    }

    let (pump, mut channels) =
        Pump::start(device.clone(), config.mtu).map_err(|e| e.to_string())?;
    let addresses: Vec<String> = config
        .addresses
        .iter()
        .map(|a| a.addr().to_string())
        .collect();
    let result = transports(
        c,
        &settings,
        &session,
        &host,
        gateway_addr,
        &mut channels,
        stop,
        status,
        &addresses,
    )
    .await;
    drop(channels);
    pump.stop();

    let (client, session) = (client.clone(), session.clone());
    let _ = blocking(move || {
        UreqTransport::new()
            .send(&tunnel::logout_request(&client, &session))
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await;
    result
}

fn hip_exchange(client: &ClientInfo, session: &GatewaySession, ip: &str) -> Result<(), String> {
    let (report, md5) = hip::report(client, session, ip, &hip_time());
    let http = UreqTransport::new();
    let needed = hip::parse_check(
        &http
            .send(&hip::check_request(session, ip, &md5))
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if needed {
        info!("submitting the HIP report (host information only)");
        hip::parse_submit(
            &http
                .send(&hip::submit_request(session, ip, &report))
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn transports(
    c: &GpConnect,
    settings: &TunnelSettings,
    session: &GatewaySession,
    host: &str,
    gateway_addr: SocketAddr,
    channels: &mut Channels,
    stop: &mut watch::Receiver<bool>,
    status: &StatusCell,
    addresses: &[String],
) -> Result<(), String> {
    let connected = |transport: &str| Status::Connected {
        profile: c.profile.clone(),
        server: host.to_string(),
        addresses: addresses.to_vec(),
        transport: transport.to_string(),
        since_unix: now_unix(),
    };

    if c.allow_esp
        && let (Some(esp), Some((tunnel_ip, _))) = (&settings.esp, settings.address_v4)
    {
        let probe_to = match settings.gateway_address {
            Some(IpAddr::V4(v4)) => Some(v4),
            _ => match gateway_addr.ip() {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            },
        };
        if let Some(probe_to) = probe_to {
            match start_esp(esp, gateway_addr.ip(), tunnel_ip, probe_to).await {
                Ok((socket, out, inb)) => {
                    info!("ESP is working; using UDP");
                    set(status, connected("esp"));
                    match esp_loop(socket, out, inb, channels, stop, (tunnel_ip, probe_to)).await {
                        Ended::Stopped => return Ok(()),
                        Ended::Lost(e) => warn!("ESP stopped ({e}); switching to the TLS tunnel"),
                    }
                }
                Err(e) => info!("ESP not available ({e}); using the TLS tunnel"),
            }
        }
    }

    let mut last_error = String::new();
    for attempt in 0..=TLS_RECONNECTS {
        if *stop.borrow() {
            return Ok(());
        }
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(2 * attempt as u64)).await;
        }
        let stream = match open_tls(host, gateway_addr, session, &settings.tunnel_path).await {
            Ok(stream) => stream,
            Err(e) if attempt == 0 => return Err(e),
            Err(e) => {
                last_error = e;
                continue;
            }
        };
        set(status, connected("tls"));
        match tls_loop(stream, channels, stop).await {
            Ended::Stopped => return Ok(()),
            Ended::Lost(e) => {
                warn!("the TLS tunnel dropped: {e}");
                last_error = e;
            }
        }
    }
    Err(format!("the tunnel was lost: {last_error}"))
}

async fn open_tls(
    host: &str,
    addr: SocketAddr,
    session: &GatewaySession,
    path: &str,
) -> Result<tokio_native_tls::TlsStream<TcpStream>, String> {
    let tcp = timeout(STEP_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| "connecting to the gateway timed out".to_string())?
        .map_err(|e| format!("cannot connect to the gateway: {e}"))?;
    let connector = native_tls::TlsConnector::new().map_err(|e| e.to_string())?;
    let mut tls = timeout(
        STEP_TIMEOUT,
        tokio_native_tls::TlsConnector::from(connector).connect(host, tcp),
    )
    .await
    .map_err(|_| "the TLS handshake timed out".to_string())?
    .map_err(|e| format!("TLS: {e}"))?;
    tls.write_all(&tunnel::tunnel_request(session, path))
        .await
        .map_err(|e| e.to_string())?;
    let mut start = [0u8; tunnel::START_TUNNEL.len()];
    timeout(STEP_TIMEOUT, tls.read_exact(&mut start))
        .await
        .map_err(|_| "the gateway did not start the tunnel".to_string())?
        .map_err(|e| e.to_string())?;
    if start != tunnel::START_TUNNEL {
        let text = String::from_utf8_lossy(&start).into_owned();
        return Err(format!("the gateway refused the tunnel ({})", text.trim()));
    }
    Ok(tls)
}

/// Exchanges framed packets over an established TLS tunnel until stopped or broken.
pub async fn tls_loop<S: AsyncRead + AsyncWrite>(
    stream: S,
    channels: &mut Channels,
    stop: &mut watch::Receiver<bool>,
) -> Ended {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut decoder = frame::Decoder::default();
    let mut buf = vec![0u8; 32 * 1024];
    let mut keepalive = tokio::time::interval(TLS_KEEPALIVE);
    keepalive.tick().await;
    loop {
        if *stop.borrow() {
            return Ended::Stopped;
        }
        tokio::select! {
            changed = stop.changed() => if changed.is_err() || *stop.borrow() {
                return Ended::Stopped;
            },
            packet = channels.from_system.recv() => match packet {
                Some(packet) => if let Err(e) = writer.write_all(&frame::encode_packet(&packet)).await {
                    return Ended::Lost(e.to_string());
                },
                None => return Ended::Stopped,
            },
            read = reader.read(&mut buf) => match read {
                Ok(0) => return Ended::Lost("the gateway closed the tunnel".into()),
                Ok(n) => {
                    decoder.feed(&buf[..n]);
                    loop {
                        match decoder.next_frame() {
                            Ok(Some(frame::Frame::Packet(packet))) => {
                                if channels.to_system.send(packet).await.is_err() {
                                    return Ended::Stopped;
                                }
                            }
                            Ok(Some(frame::Frame::Keepalive)) => {}
                            Ok(None) => break,
                            Err(e) => return Ended::Lost(e.to_string()),
                        }
                    }
                }
                Err(e) => return Ended::Lost(e.to_string()),
            },
            _ = keepalive.tick() => if let Err(e) = writer.write_all(&frame::encode_keepalive()).await {
                return Ended::Lost(e.to_string());
            },
        }
    }
}

fn esp_sas(esp: &EspSettings) -> Result<(OutboundSa, InboundSa), String> {
    let integrity = match esp.hmac {
        EspHmac::Sha1 => Integrity::HmacSha1_96,
        EspHmac::Sha256 => Integrity::HmacSha256_128,
    };
    let keys = |enc, auth| {
        Keys::new(
            Cipher::AesCbc(EspSettings::key_bytes(enc)),
            integrity,
            EspSettings::key_bytes(auth),
        )
        .map_err(|e| e.to_string())
    };
    Ok((
        OutboundSa::new(esp.c2s_spi, keys(&esp.c2s_enc_key, &esp.c2s_auth_key)?),
        InboundSa::new(esp.s2c_spi, keys(&esp.s2c_enc_key, &esp.s2c_auth_key)?, 128),
    ))
}

async fn start_esp(
    esp: &EspSettings,
    gateway: IpAddr,
    tunnel_ip: Ipv4Addr,
    probe_to: Ipv4Addr,
) -> Result<(UdpSocket, OutboundSa, InboundSa), String> {
    let (mut out, mut inb) = esp_sas(esp)?;
    let bind = if gateway.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    socket
        .connect((gateway, esp.udp_port))
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 2048];
    for seq in 1..=3u16 {
        let ping = packets::echo_request(tunnel_ip, probe_to, PROBE_ID, seq, PROBE_PAYLOAD);
        let sealed = out
            .seal(polytunnel_esp::NEXT_HEADER_IPV4, &ping)
            .map_err(|e| e.to_string())?;
        socket.send(&sealed).await.map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(1);
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match timeout(left, socket.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    if inb.open(&buf[..n]).is_ok() {
                        return Ok((socket, out, inb));
                    }
                }
                Ok(Err(e)) => return Err(e.to_string()),
                Err(_) => break,
            }
        }
    }
    Err("no answer to the ESP probe".into())
}

/// Exchanges ESP packets until stopped, or until the gateway stops answering.
pub async fn esp_loop(
    socket: UdpSocket,
    mut out: OutboundSa,
    mut inb: InboundSa,
    channels: &mut Channels,
    stop: &mut watch::Receiver<bool>,
    (tunnel_ip, probe_to): (Ipv4Addr, Ipv4Addr),
) -> Ended {
    let mut buf = vec![0u8; 65_536];
    let mut keepalive = tokio::time::interval(ESP_KEEPALIVE);
    keepalive.tick().await;
    let mut last_rx = Instant::now();
    let mut probe_seq: u16 = 100;
    loop {
        if *stop.borrow() {
            return Ended::Stopped;
        }
        tokio::select! {
            changed = stop.changed() => if changed.is_err() || *stop.borrow() {
                return Ended::Stopped;
            },
            packet = channels.from_system.recv() => match packet {
                Some(packet) => match out.seal(packets::next_header(&packet), &packet) {
                    Ok(sealed) => if let Err(e) = socket.send(&sealed).await {
                        return Ended::Lost(e.to_string());
                    },
                    Err(e) => return Ended::Lost(e.to_string()),
                },
                None => return Ended::Stopped,
            },
            received = socket.recv(&mut buf) => match received {
                Ok(n) => match inb.open(&buf[..n]) {
                    Ok((_, packet)) => {
                        last_rx = Instant::now();
                        if packets::is_echo_reply(&packet, probe_to, PROBE_ID) {
                            continue;
                        }
                        if channels.to_system.send(packet).await.is_err() {
                            return Ended::Stopped;
                        }
                    }
                    Err(e) => warn!("dropped an ESP packet: {e}"),
                },
                Err(e) => return Ended::Lost(e.to_string()),
            },
            _ = keepalive.tick() => {
                if last_rx.elapsed() > ESP_DEAD_AFTER {
                    return Ended::Lost("the gateway stopped answering over ESP".into());
                }
                probe_seq = probe_seq.wrapping_add(1);
                let ping = packets::echo_request(tunnel_ip, probe_to, PROBE_ID, probe_seq, PROBE_PAYLOAD);
                if let Ok(sealed) = out.seal(polytunnel_esp::NEXT_HEADER_IPV4, &ping) {
                    let _ = socket.send(&sealed).await;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use polytunnel_core::Secret;
    use polytunnel_gp::tunnel::EspCipher;
    use tokio::sync::mpsc;

    use super::*;

    fn channels() -> (Channels, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let (out_tx, out_rx) = mpsc::channel(16);
        let (in_tx, in_rx) = mpsc::channel(16);
        (
            Channels {
                from_system: out_rx,
                to_system: in_tx,
            },
            out_tx,
            in_rx,
        )
    }

    #[tokio::test]
    async fn tls_loop_carries_packets_both_ways_and_stops() {
        let (client_side, mut gateway_side) = tokio::io::duplex(64 * 1024);
        let (mut ch, system_out, mut system_in) = channels();
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let task = tokio::spawn(async move { tls_loop(client_side, &mut ch, &mut stop_rx).await });

        // System -> gateway.
        system_out.send(vec![0x45, 1, 2, 3]).await.unwrap();
        let mut header = [0u8; frame::HEADER_LEN + 4];
        gateway_side.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..4], &frame::MAGIC);
        assert_eq!(&header[frame::HEADER_LEN..], &[0x45, 1, 2, 3]);

        // Gateway -> system, split across writes, with a keepalive in between.
        let mut bytes = frame::encode_keepalive().to_vec();
        bytes.extend(frame::encode_packet(&[0x45, 9, 9]));
        gateway_side.write_all(&bytes[..10]).await.unwrap();
        gateway_side.write_all(&bytes[10..]).await.unwrap();
        assert_eq!(system_in.recv().await.unwrap(), vec![0x45, 9, 9]);

        stop_tx.send(true).unwrap();
        assert_eq!(task.await.unwrap(), Ended::Stopped);
    }

    #[tokio::test]
    async fn tls_loop_reports_a_closed_tunnel() {
        let (client_side, gateway_side) = tokio::io::duplex(1024);
        let (mut ch, _out, _in) = channels();
        let (_stop_tx, mut stop_rx) = watch::channel(false);
        drop(gateway_side);
        assert!(matches!(
            tls_loop(client_side, &mut ch, &mut stop_rx).await,
            Ended::Lost(_)
        ));
    }

    fn esp_settings() -> EspSettings {
        EspSettings {
            udp_port: 0,
            cipher: EspCipher::Aes128Cbc,
            hmac: EspHmac::Sha1,
            c2s_spi: 0x1000,
            s2c_spi: 0x2000,
            c2s_enc_key: Secret::new("000102030405060708090a0b0c0d0e0f"),
            c2s_auth_key: Secret::new("101112131415161718191a1b1c1d1e1f20212223"),
            s2c_enc_key: Secret::new("202122232425262728292a2b2c2d2e2f"),
            s2c_auth_key: Secret::new("303132333435363738393a3b3c3d3e3f40414243"),
        }
    }

    /// A fake gateway on loopback with the mirrored SAs: answers the probe, echoes packets.
    #[tokio::test]
    async fn esp_probe_and_loop_against_a_fake_gateway() {
        let gateway = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut esp = esp_settings();
        esp.udp_port = gateway.local_addr().unwrap().port();
        let (client_out, client_in) = esp_sas(&esp).unwrap();
        let _ = (client_out, client_in);
        // Gateway side: inbound with c2s keys, outbound with s2c keys.
        let mirrored = EspSettings {
            c2s_spi: esp.s2c_spi,
            s2c_spi: esp.c2s_spi,
            c2s_enc_key: esp.s2c_enc_key.clone(),
            c2s_auth_key: esp.s2c_auth_key.clone(),
            s2c_enc_key: esp.c2s_enc_key.clone(),
            s2c_auth_key: esp.c2s_auth_key.clone(),
            ..esp.clone()
        };
        let (mut gw_out, mut gw_in) = esp_sas(&mirrored).unwrap();
        let tunnel_ip = Ipv4Addr::new(10, 20, 30, 40);
        let probe_to = Ipv4Addr::new(198, 51, 100, 1);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, from)) = gateway.recv_from(&mut buf).await else {
                    return;
                };
                let Ok((nh, mut packet)) = gw_in.open(&buf[..n]) else {
                    continue;
                };
                if packet.len() >= 28 && packet[9] == 1 && packet[20] == 8 {
                    // Echo request -> reply from probe_to.
                    let (src, dst) = (packet[12..16].to_vec(), packet[16..20].to_vec());
                    packet[12..16].copy_from_slice(&dst);
                    packet[16..20].copy_from_slice(&src);
                    packet[20] = 0;
                }
                let sealed = gw_out.seal(nh, &packet).unwrap();
                gateway.send_to(&sealed, from).await.unwrap();
            }
        });

        let (socket, out, inb) = start_esp(&esp, "127.0.0.1".parse().unwrap(), tunnel_ip, probe_to)
            .await
            .expect("probe answered");
        let (mut ch, system_out, mut system_in) = channels();
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            esp_loop(
                socket,
                out,
                inb,
                &mut ch,
                &mut stop_rx,
                (tunnel_ip, probe_to),
            )
            .await
        });
        let packet = vec![
            0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17, 0, 0, 10, 20, 30, 40, 198, 51, 100, 9, 1, 2, 3, 4,
        ];
        system_out.send(packet.clone()).await.unwrap();
        assert_eq!(
            system_in.recv().await.unwrap(),
            packet,
            "echoed back through ESP"
        );
        stop_tx.send(true).unwrap();
        assert_eq!(task.await.unwrap(), Ended::Stopped);
    }

    #[test]
    fn config_and_helpers() {
        let settings = TunnelSettings {
            address_v4: Some((
                Ipv4Addr::new(10, 20, 30, 40),
                Ipv4Addr::new(255, 255, 255, 255),
            )),
            routes: vec!["10.0.0.0/8".into(), "garbage".into()],
            dns_servers: vec!["10.0.0.53".parse().unwrap()],
            dns_suffixes: vec!["corp.example.com".into()],
            mtu: Some(1300),
            ..Default::default()
        };
        let config = tunnel_config(&settings, vec!["203.0.113.10".parse().unwrap()]);
        assert_eq!(config.addresses, vec!["10.20.30.40/32".parse().unwrap()]);
        assert_eq!(config.routes, vec!["10.0.0.0/8".parse().unwrap()]);
        assert_eq!(config.mtu, 1300);
        let t = hip_time();
        assert_eq!(t.len(), 19, "{t}");
        assert_eq!(&t[2..3], "/");
    }
}
