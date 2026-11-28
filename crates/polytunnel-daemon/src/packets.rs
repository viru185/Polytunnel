//! Moving packets between the TUN device and the tunnel engines, plus small IP helpers.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread::{self, JoinHandle};

use polytunnel_net::tun::{InterruptEvent, SyncDevice};
use tokio::sync::mpsc;

use crate::common::Counters;

/// Why a connection ends when the tunnel interface's packet threads stop (the interface
/// failed or was removed): a failure, never a stop the user asked for.
pub const INTERFACE_STOPPED: &str = "the tunnel interface stopped working";

/// Packets from the system (to send through the tunnel) and to the system (received).
pub struct Channels {
    pub from_system: mpsc::Receiver<Vec<u8>>,
    pub to_system: mpsc::Sender<Vec<u8>>,
}

/// Two threads bridging the (blocking) TUN device and the async engines.
pub struct Pump {
    interrupt: Arc<InterruptEvent>,
    threads: Vec<JoinHandle<()>>,
    counters: Arc<Counters>,
}

impl Pump {
    pub fn start(device: Arc<SyncDevice>, mtu: u16) -> std::io::Result<(Pump, Channels)> {
        let interrupt = Arc::new(InterruptEvent::new()?);
        let counters = Arc::new(Counters::default());
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(256);
        let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(256);
        let reader = {
            let (device, interrupt, counters) =
                (device.clone(), interrupt.clone(), counters.clone());
            thread::spawn(move || {
                let mut buf = vec![0u8; usize::from(mtu) + 64];
                read_packets(&device, &interrupt, &mut buf, |packet| {
                    counters
                        .bytes_out
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);
                    out_tx.blocking_send(packet.to_vec()).is_ok()
                });
            })
        };
        let writer = {
            let (device, counters) = (device.clone(), counters.clone());
            thread::spawn(move || {
                while let Some(packet) = in_rx.blocking_recv() {
                    if device.send(&packet).is_err() {
                        break;
                    }
                    counters
                        .bytes_in
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);
                }
            })
        };
        Ok((
            Pump {
                interrupt,
                threads: vec![reader, writer],
                counters,
            },
            Channels {
                from_system: out_rx,
                to_system: in_tx,
            },
        ))
    }

    /// Bytes moved so far, for the status.
    pub fn counters(&self) -> Arc<Counters> {
        self.counters.clone()
    }

    /// Unblocks and joins the threads (the writer ends when its channel closes).
    pub fn stop(self) {
        let _ = self.interrupt.trigger();
        for t in self.threads {
            let _ = t.join();
        }
    }
}

/// Reads packets from the device and hands each to `deliver` (which returns false to stop),
/// until the device fails or `interrupt` is triggered.
///
/// On Windows the Wintun ring has to be emptied, until it reports no more packets, before
/// waiting on its read event. The event is signalled once for a whole batch, so waiting first
/// (as `recv_intr` does) leaves the rest of a batch in the ring until more packets arrive:
/// every packet then waits for later ones, and a new connection's first packet waits for its
/// own retransmission.
#[cfg(windows)]
fn read_packets(
    device: &SyncDevice,
    interrupt: &InterruptEvent,
    buf: &mut [u8],
    mut deliver: impl FnMut(&[u8]) -> bool,
) {
    while !interrupt.is_trigger() {
        match device.try_recv(buf) {
            Ok(0) => {}
            Ok(n) => {
                if !deliver(&buf[..n]) {
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if device.wait_readable_intr(interrupt).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// Other systems: the descriptor is polled level-triggered, so waiting first loses nothing.
#[cfg(not(windows))]
fn read_packets(
    device: &SyncDevice,
    interrupt: &InterruptEvent,
    buf: &mut [u8],
    mut deliver: impl FnMut(&[u8]) -> bool,
) {
    while let Ok(n) = device.recv_intr(buf, interrupt) {
        if n > 0 && !deliver(&buf[..n]) {
            return;
        }
    }
}

/// The IP version of a packet: the ESP next-header value for it.
pub fn next_header(packet: &[u8]) -> u8 {
    match packet.first().map(|b| b >> 4) {
        Some(6) => polytunnel_esp::NEXT_HEADER_IPV6,
        _ => polytunnel_esp::NEXT_HEADER_IPV4,
    }
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An ICMP echo request (IPv4) used to check that ESP traffic flows.
pub fn echo_request(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0];
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let c = checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());

    let total = (20 + icmp.len()) as u16;
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&id.to_be_bytes()); // identification
    ip.extend_from_slice(&[0x40, 0, 64, 1, 0, 0]); // don't fragment, TTL 64, ICMP, checksum
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let c = checksum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

/// Is `packet` an ICMP echo reply from `from` with identifier `id`?
pub fn is_echo_reply(packet: &[u8], from: Ipv4Addr, id: u16) -> bool {
    packet.len() >= 28
        && packet[0] >> 4 == 4
        && packet[9] == 1
        && packet[12..16] == from.octets()
        && {
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            packet.len() >= ihl + 8
                && packet[ihl] == 0
                && packet[ihl + 4..ihl + 6] == id.to_be_bytes()
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_request_has_valid_checksums() {
        let src = Ipv4Addr::new(10, 20, 30, 40);
        let dst = Ipv4Addr::new(198, 51, 100, 1);
        let p = echo_request(src, dst, 0x1234, 1, b"polytunnel");
        assert_eq!(p.len(), 20 + 8 + 10);
        assert_eq!(checksum(&p[..20]), 0, "IPv4 header checksum");
        assert_eq!(checksum(&p[20..]), 0, "ICMP checksum");
        assert_eq!(next_header(&p), polytunnel_esp::NEXT_HEADER_IPV4);

        // Turn it into the reply the gateway would send.
        let mut reply = p.clone();
        reply[12..16].copy_from_slice(&dst.octets());
        reply[16..20].copy_from_slice(&src.octets());
        reply[20] = 0;
        assert!(is_echo_reply(&reply, dst, 0x1234));
        assert!(!is_echo_reply(&reply, dst, 0x9999));
        assert!(!is_echo_reply(&p, dst, 0x1234));
    }
}
