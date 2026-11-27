//! Measures how fast each gateway answers, all in parallel, the way GlobalProtect does:
//! the TLS handshake time (default) or the TCP handshake time.
//!
//! Probe sockets can be bound to a given network interface so that, while a full tunnel is
//! up, the measurement goes over the physical network instead of through the tunnel.

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use polytunnel_core::profile::ProbeMethod;
use polytunnel_gp::portal::Gateway;
use polytunnel_gp::rank::Probe;
use socket2::{Domain, Protocol, Socket, Type};

/// Probes every gateway at once; each gets at most `timeout`. `interface`: index of the
/// network interface to send probes from (`None`: let the OS route them).
pub fn probe_all(
    gateways: &[Gateway],
    method: ProbeMethod,
    timeout: Duration,
    interface: Option<u32>,
) -> Vec<Probe> {
    let (tx, rx) = mpsc::channel();
    for (index, gateway) in gateways.iter().enumerate() {
        let tx = tx.clone();
        let address = gateway.address.clone();
        let spawned = thread::Builder::new()
            .name("gateway-probe".into())
            .spawn(move || {
                let probe = match measure(&address, method, timeout, interface) {
                    Ok(elapsed) => Probe::Answered(elapsed),
                    Err(_) => Probe::Failed,
                };
                let _ = tx.send((index, probe));
            });
        if spawned.is_err() {
            continue;
        }
    }
    drop(tx);
    let mut probes = vec![Probe::Failed; gateways.len()];
    // Name resolution has no timeout of its own: give up on stragglers.
    let deadline = Instant::now() + timeout + Duration::from_secs(1);
    while let Ok((index, probe)) =
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
    {
        probes[index] = probe;
    }
    probes
}

/// The handshake time to `address` (`https://host[:port]`).
pub fn measure(
    address: &str,
    method: ProbeMethod,
    timeout: Duration,
    interface: Option<u32>,
) -> io::Result<Duration> {
    let (host, port) = split_address(address)?;
    let target = (host.as_str(), port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address for host"))?;
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if let Some(index) = interface {
        bind_interface(&socket, index, target.is_ipv6())?;
    }

    let started = Instant::now();
    socket.connect_timeout(&target.into(), timeout)?;
    let tcp = started.elapsed();
    if method == ProbeMethod::Tcp {
        return Ok(tcp);
    }

    let stream: TcpStream = socket.into();
    let left = timeout.saturating_sub(tcp).max(Duration::from_millis(100));
    stream.set_read_timeout(Some(left))?;
    stream.set_write_timeout(Some(left))?;
    let connector = native_tls::TlsConnector::new().map_err(io::Error::other)?;
    let started = Instant::now();
    let tls = connector
        .connect(&host, stream)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let elapsed = started.elapsed();
    drop(tls);
    Ok(elapsed)
}

/// `https://host[:port]` -> (host without brackets, port).
fn split_address(address: &str) -> io::Result<(String, u16)> {
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, "bad gateway address");
    let authority = address.strip_prefix("https://").unwrap_or(address);
    let authority = authority.split('/').next().unwrap_or_default();
    if let Some(v6) = authority.strip_prefix('[') {
        let (host, rest) = v6.split_once(']').ok_or_else(bad)?;
        let port = match rest.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| bad())?,
            None => 443,
        };
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Ok((host.to_string(), port.parse().map_err(|_| bad())?)),
        None if !authority.is_empty() => Ok((authority.to_string(), 443)),
        None => Err(bad()),
    }
}

#[cfg(windows)]
fn bind_interface(socket: &Socket, index: u32, ipv6: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET_ERROR, setsockopt,
    };
    // IPv4 expects the index in network byte order, IPv6 in host order.
    let (level, name, value) = if ipv6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    } else {
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    };
    // SAFETY: `value` is a live u32 and we pass its exact size; the socket handle is valid.
    let rc = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            name,
            (&value as *const u32).cast(),
            size_of::<u32>() as i32,
        )
    };
    if rc == SOCKET_ERROR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn bind_interface(socket: &Socket, index: u32, ipv6: bool) -> io::Result<()> {
    let index = std::num::NonZeroU32::new(index)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "interface index 0"))?;
    if ipv6 {
        socket.bind_device_by_index_v6(Some(index))
    } else {
        socket.bind_device_by_index_v4(Some(index))
    }
}

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos"
)))]
fn bind_interface(_socket: &Socket, _index: u32, _ipv6: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "binding probes to an interface is not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn splits_addresses() {
        assert_eq!(
            split_address("https://gw.example.com").unwrap(),
            ("gw.example.com".into(), 443)
        );
        assert_eq!(
            split_address("https://gw.example.com:8443").unwrap(),
            ("gw.example.com".into(), 8443)
        );
        assert_eq!(
            split_address("https://[2001:db8::1]:4443").unwrap(),
            ("2001:db8::1".into(), 4443)
        );
        assert!(split_address("https://").is_err());
        assert!(split_address("https://gw.example.com:x").is_err());
    }

    #[test]
    fn tcp_probe_measures_a_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let address = format!("https://127.0.0.1:{port}");
        let elapsed = measure(&address, ProbeMethod::Tcp, Duration::from_secs(2), None).unwrap();
        assert!(elapsed < Duration::from_secs(2));
    }

    #[test]
    fn closed_ports_and_non_tls_servers_fail() {
        // A port that was just closed: connection refused.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let closed = format!("https://127.0.0.1:{port}");
        assert!(measure(&closed, ProbeMethod::Tcp, Duration::from_secs(2), None).is_err());

        // A listener that accepts and hangs up: the TLS handshake fails.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().take(1) {
                drop(stream);
            }
        });
        let plain = format!("https://127.0.0.1:{port}");
        assert!(measure(&plain, ProbeMethod::Tls, Duration::from_secs(2), None).is_err());
    }

    #[test]
    fn probe_all_keeps_the_order() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let closed_port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let gateways = [
            Gateway {
                address: format!("https://127.0.0.1:{closed_port}"),
                ..Gateway::default()
            },
            Gateway {
                address: format!("https://127.0.0.1:{port}"),
                ..Gateway::default()
            },
        ];
        let probes = probe_all(&gateways, ProbeMethod::Tcp, Duration::from_secs(2), None);
        assert_eq!(probes[0], Probe::Failed);
        assert!(matches!(probes[1], Probe::Answered(_)));
    }
}
