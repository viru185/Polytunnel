//! A minimal PPP client (RFC 1661 LCP, RFC 1332 IPCP, RFC 1877 DNS) for the FortiGate SSL VPN
//! tunnel. Sans I/O: feed it PPP packets, it returns [`Event`]s (packets to send, IP packets
//! to deliver, link up/down).
//!
//! * Every packet we send starts with the address/control field `FF 03` and a two-byte
//!   protocol, as openconnect sends them; received packets may have either form.
//! * LCP: we ask for our MRU and a magic number; we accept the peer's MRU, ACCM, magic number,
//!   protocol-field and address/control-field compression, and reject anything else. The
//!   link's MTU is the smaller of the two MRUs.
//! * IPCP: we ask for an address, and for two DNS servers only when the tunnel configuration
//!   named none (`0.0.0.0` until the peer suggests real ones in a Configure-Nak). The peer's
//!   IPCP request is answered even if it arrives before LCP is open; the link is up once both
//!   sides have acknowledged.
//! * Echo requests are answered; unknown protocols (e.g. IPv6CP) get a Protocol-Reject.

use std::net::Ipv4Addr;

use crate::login::FortiError;

pub const PROTO_LCP: u16 = 0xc021;
pub const PROTO_IPCP: u16 = 0x8021;
pub const PROTO_IPV4: u16 = 0x0021;
pub const PROTO_IPV6: u16 = 0x0057;

const CONF_REQ: u8 = 1;
const CONF_ACK: u8 = 2;
const CONF_NAK: u8 = 3;
const CONF_REJ: u8 = 4;
const TERM_REQ: u8 = 5;
const TERM_ACK: u8 = 6;
const PROTO_REJ: u8 = 8;
const ECHO_REQ: u8 = 9;
const ECHO_REP: u8 = 10;

const LCP_MRU: u8 = 1;
const LCP_ACCM: u8 = 2;
const LCP_MAGIC: u8 = 5;
const LCP_PFC: u8 = 7;
const LCP_ACFC: u8 = 8;

const IPCP_ADDRESS: u8 = 3;
const IPCP_DNS1: u8 = 129;
const IPCP_DNS2: u8 = 131;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpConfig {
    pub address: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    /// The link's MTU: our MRU, or the peer's if smaller.
    pub mtu: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A PPP packet (protocol field included) to send to the peer.
    Send(Vec<u8>),
    /// An IP packet received over the link.
    Deliver(Vec<u8>),
    Up(IpConfig),
    Down(String),
}

#[derive(Debug, Default)]
struct Negotiation {
    /// Id of our latest Configure-Request.
    request_id: u8,
    /// The peer acknowledged our request.
    acked_by_peer: bool,
    /// We acknowledged the peer's request.
    acked_peer: bool,
}

impl Negotiation {
    fn open(&self) -> bool {
        self.acked_by_peer && self.acked_peer
    }
}

pub struct Ppp {
    magic: u32,
    mru: u16,
    /// The MRU the peer asked for.
    peer_mru: Option<u16>,
    next_id: u8,
    send_mru: bool,
    send_magic: bool,
    lcp: Negotiation,
    ipcp: Negotiation,
    ipcp_started: bool,
    address: Ipv4Addr,
    dns1: Option<Ipv4Addr>,
    dns2: Option<Ipv4Addr>,
    up: bool,
}

/// The address/control field every packet we send starts with.
const ADDRESS_CONTROL: [u8; 2] = [0xff, 0x03];

fn packet(protocol: u16, code: u8, id: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + data.len());
    out.extend_from_slice(&ADDRESS_CONTROL);
    out.extend_from_slice(&protocol.to_be_bytes());
    out.push(code);
    out.push(id);
    out.extend_from_slice(&((4 + data.len()) as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// `(type, value)` pairs of a configuration packet.
fn options(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, FortiError> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        if rest.len() < 2 || usize::from(rest[1]) < 2 || usize::from(rest[1]) > rest.len() {
            return Err(FortiError::BadResponse("malformed PPP option".into()));
        }
        let len = usize::from(rest[1]);
        out.push((rest[0], rest[2..len].to_vec()));
        rest = &rest[len..];
    }
    Ok(out)
}

fn encode_options(options: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (kind, value) in options {
        out.push(*kind);
        out.push((value.len() + 2) as u8);
        out.extend_from_slice(value);
    }
    out
}

fn ip_of(value: &[u8]) -> Option<Ipv4Addr> {
    <[u8; 4]>::try_from(value).ok().map(Ipv4Addr::from)
}

impl Ppp {
    /// `address_hint`: the address from the tunnel configuration, if known. `ask_dns`: ask
    /// the peer for DNS servers (when the tunnel configuration named none).
    pub fn new(magic: u32, mru: u16, address_hint: Option<Ipv4Addr>, ask_dns: bool) -> Self {
        let dns = ask_dns.then_some(Ipv4Addr::UNSPECIFIED);
        Ppp {
            magic,
            mru,
            peer_mru: None,
            next_id: 0,
            send_mru: true,
            send_magic: true,
            lcp: Negotiation::default(),
            ipcp: Negotiation::default(),
            ipcp_started: false,
            address: address_hint.unwrap_or(Ipv4Addr::UNSPECIFIED),
            dns1: dns,
            dns2: dns,
            up: false,
        }
    }

    pub fn is_up(&self) -> bool {
        self.up
    }

    fn id(&mut self) -> u8 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }

    fn lcp_request(&mut self) -> Event {
        let mut opts = Vec::new();
        if self.send_mru {
            opts.push((LCP_MRU, self.mru.to_be_bytes().to_vec()));
        }
        if self.send_magic {
            opts.push((LCP_MAGIC, self.magic.to_be_bytes().to_vec()));
        }
        let id = self.id();
        self.lcp.request_id = id;
        Event::Send(packet(PROTO_LCP, CONF_REQ, id, &encode_options(&opts)))
    }

    fn ipcp_request(&mut self) -> Event {
        let mut opts = vec![(IPCP_ADDRESS, self.address.octets().to_vec())];
        if let Some(dns) = self.dns1 {
            opts.push((IPCP_DNS1, dns.octets().to_vec()));
        }
        if let Some(dns) = self.dns2 {
            opts.push((IPCP_DNS2, dns.octets().to_vec()));
        }
        let id = self.id();
        self.ipcp.request_id = id;
        self.ipcp_started = true;
        Event::Send(packet(PROTO_IPCP, CONF_REQ, id, &encode_options(&opts)))
    }

    /// Starts negotiation.
    pub fn start(&mut self) -> Vec<Event> {
        vec![self.lcp_request()]
    }

    /// Resends whatever request is still unanswered (call on a timer until [`Ppp::is_up`]).
    pub fn retransmit(&mut self) -> Vec<Event> {
        if !self.lcp.acked_by_peer {
            vec![self.lcp_request()]
        } else if self.lcp.open() && !self.ipcp.acked_by_peer {
            vec![self.ipcp_request()]
        } else {
            Vec::new()
        }
    }

    /// Wraps an IP packet for sending.
    pub fn encode_ip(&self, ip: &[u8]) -> Vec<u8> {
        let protocol = if ip.first().map(|b| b >> 4) == Some(6) {
            PROTO_IPV6
        } else {
            PROTO_IPV4
        };
        let mut out = ADDRESS_CONTROL.to_vec();
        out.extend_from_slice(&protocol.to_be_bytes());
        out.extend_from_slice(ip);
        out
    }

    pub fn echo_request(&mut self) -> Vec<u8> {
        let id = self.id();
        packet(PROTO_LCP, ECHO_REQ, id, &self.magic.to_be_bytes())
    }

    pub fn terminate(&mut self) -> Vec<u8> {
        let id = self.id();
        packet(PROTO_LCP, TERM_REQ, id, b"Polytunnel disconnecting")
    }

    /// Handles one PPP packet from the peer.
    pub fn receive(&mut self, raw: &[u8]) -> Result<Vec<Event>, FortiError> {
        // Address/control field (FF 03) may or may not be present; the protocol field may
        // be compressed to one byte (odd value).
        let raw = raw.strip_prefix(&[0xff, 0x03]).unwrap_or(raw);
        let (protocol, body) = match raw {
            [first, rest @ ..] if first & 1 == 1 => (u16::from(*first), rest),
            [hi, lo, rest @ ..] => (u16::from_be_bytes([*hi, *lo]), rest),
            _ => return Err(FortiError::BadResponse("short PPP packet".into())),
        };
        match protocol {
            PROTO_IPV4 | PROTO_IPV6 => Ok(if self.up {
                vec![Event::Deliver(body.to_vec())]
            } else {
                Vec::new()
            }),
            PROTO_LCP => self.lcp(body),
            PROTO_IPCP => self.ipcp(body),
            other => {
                // Protocol-Reject: the rejected protocol, then as much of the packet as fits.
                let mut data = other.to_be_bytes().to_vec();
                data.extend_from_slice(&body[..body.len().min(usize::from(self.mru) - 8)]);
                let id = self.id();
                Ok(if self.lcp.open() {
                    vec![Event::Send(packet(PROTO_LCP, PROTO_REJ, id, &data))]
                } else {
                    Vec::new()
                })
            }
        }
    }

    fn header(body: &[u8]) -> Result<(u8, u8, &[u8]), FortiError> {
        if body.len() < 4 {
            return Err(FortiError::BadResponse("short control packet".into()));
        }
        let len = usize::from(u16::from_be_bytes([body[2], body[3]]));
        if len < 4 || len > body.len() {
            return Err(FortiError::BadResponse("bad control packet length".into()));
        }
        Ok((body[0], body[1], &body[4..len]))
    }

    fn lcp(&mut self, body: &[u8]) -> Result<Vec<Event>, FortiError> {
        let (code, id, data) = Self::header(body)?;
        let mut events = Vec::new();
        match code {
            CONF_REQ => {
                let opts = options(data)?;
                let rejected: Vec<(u8, Vec<u8>)> = opts
                    .iter()
                    .filter(|(kind, value)| {
                        !matches!(
                            (*kind, value.len()),
                            (LCP_MRU, 2)
                                | (LCP_ACCM, 4)
                                | (LCP_MAGIC, 4)
                                | (LCP_PFC, 0)
                                | (LCP_ACFC, 0)
                        )
                    })
                    .cloned()
                    .collect();
                if rejected.is_empty() {
                    events.push(Event::Send(packet(PROTO_LCP, CONF_ACK, id, data)));
                    self.lcp.acked_peer = true;
                    self.peer_mru = opts
                        .iter()
                        .find(|(kind, _)| *kind == LCP_MRU)
                        .map(|(_, v)| u16::from_be_bytes([v[0], v[1]]));
                } else {
                    events.push(Event::Send(packet(
                        PROTO_LCP,
                        CONF_REJ,
                        id,
                        &encode_options(&rejected),
                    )));
                }
            }
            // Any Configure-Ack counts, as in openconnect (some servers reuse ids).
            CONF_ACK => self.lcp.acked_by_peer = true,
            CONF_NAK if id == self.lcp.request_id => {
                for (kind, value) in options(data)? {
                    if kind == LCP_MRU && value.len() == 2 {
                        self.mru = u16::from_be_bytes([value[0], value[1]]).clamp(576, 1500);
                    }
                }
                events.push(self.lcp_request());
            }
            CONF_REJ if id == self.lcp.request_id => {
                for (kind, _) in options(data)? {
                    match kind {
                        LCP_MRU => self.send_mru = false,
                        LCP_MAGIC => self.send_magic = false,
                        _ => {}
                    }
                }
                events.push(self.lcp_request());
            }
            TERM_REQ => {
                events.push(Event::Send(packet(PROTO_LCP, TERM_ACK, id, &[])));
                self.up = false;
                events.push(Event::Down("the server closed the PPP link".into()));
            }
            TERM_ACK => {
                self.up = false;
                events.push(Event::Down("PPP link closed".into()));
            }
            ECHO_REQ if self.lcp.open() => {
                let mut reply = self.magic.to_be_bytes().to_vec();
                reply.extend_from_slice(data.get(4..).unwrap_or_default());
                events.push(Event::Send(packet(PROTO_LCP, ECHO_REP, id, &reply)));
            }
            PROTO_REJ if data.get(..2) == Some(&PROTO_IPCP.to_be_bytes()[..]) => {
                events.push(Event::Down("the server rejected IPCP".into()));
            }
            _ => {} // echo replies, discards, stale or unrelated packets
        }
        if self.lcp.open() && !self.ipcp_started {
            events.push(self.ipcp_request());
        }
        Ok(events)
    }

    fn ipcp(&mut self, body: &[u8]) -> Result<Vec<Event>, FortiError> {
        let (code, id, data) = Self::header(body)?;
        // Before LCP is open only the peer's own request is answered (openconnect does too).
        if !self.lcp.open() && code != CONF_REQ {
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        match code {
            CONF_REQ => {
                let opts = options(data)?;
                let rejected: Vec<(u8, Vec<u8>)> = opts
                    .iter()
                    .filter(|(kind, value)| !(*kind == IPCP_ADDRESS && value.len() == 4))
                    .cloned()
                    .collect();
                if rejected.is_empty() {
                    events.push(Event::Send(packet(PROTO_IPCP, CONF_ACK, id, data)));
                    self.ipcp.acked_peer = true;
                } else {
                    events.push(Event::Send(packet(
                        PROTO_IPCP,
                        CONF_REJ,
                        id,
                        &encode_options(&rejected),
                    )));
                }
            }
            CONF_ACK => self.ipcp.acked_by_peer = true,
            CONF_NAK if id == self.ipcp.request_id => {
                for (kind, value) in options(data)? {
                    match (kind, ip_of(&value)) {
                        (IPCP_ADDRESS, Some(ip)) => self.address = ip,
                        (IPCP_DNS1, Some(ip)) => self.dns1 = Some(ip),
                        (IPCP_DNS2, Some(ip)) => self.dns2 = Some(ip),
                        _ => {}
                    }
                }
                events.push(self.ipcp_request());
            }
            CONF_REJ if id == self.ipcp.request_id => {
                for (kind, _) in options(data)? {
                    match kind {
                        IPCP_DNS1 => self.dns1 = None,
                        IPCP_DNS2 => self.dns2 = None,
                        _ => {}
                    }
                }
                events.push(self.ipcp_request());
            }
            TERM_REQ => events.push(Event::Send(packet(PROTO_IPCP, TERM_ACK, id, &[]))),
            _ => {}
        }
        if self.ipcp.open() && !self.up {
            if self.address.is_unspecified() {
                return Err(FortiError::BadResponse(
                    "the server assigned no address".into(),
                ));
            }
            self.up = true;
            let dns = [self.dns1, self.dns2]
                .into_iter()
                .flatten()
                .filter(|d| !d.is_unspecified())
                .collect();
            events.push(Event::Up(IpConfig {
                address: self.address,
                dns,
                mtu: self.peer_mru.map_or(self.mru, |p| p.clamp(576, self.mru)),
            }));
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The packets sent, without their FF 03 prefix (checked here).
    fn sent(events: &[Event]) -> Vec<Vec<u8>> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Send(p) => {
                    assert_eq!(p[..2], ADDRESS_CONTROL, "every packet starts with FF 03");
                    Some(p[2..].to_vec())
                }
                _ => None,
            })
            .collect()
    }

    fn opts(list: &[(u8, &[u8])]) -> Vec<u8> {
        encode_options(
            &list
                .iter()
                .map(|(k, v)| (*k, v.to_vec()))
                .collect::<Vec<_>>(),
        )
    }

    /// The whole negotiation against a scripted FortiGate.
    #[test]
    fn negotiates_lcp_and_ipcp_then_carries_ip() {
        let mut ppp = Ppp::new(0x11223344, 1354, None, true);
        let start = sent(&ppp.start());
        assert_eq!(&start[0][..3], &[0xc0, 0x21, CONF_REQ]);
        let our_lcp_id = start[0][3];

        // The server's own LCP request (MRU + magic): acknowledged.
        let server_req = packet(
            PROTO_LCP,
            CONF_REQ,
            7,
            &opts(&[(LCP_MRU, &[5, 0x4a]), (LCP_MAGIC, &[9, 9, 9, 9])]),
        );
        let ev = ppp.receive(&server_req).unwrap();
        assert_eq!(sent(&ev)[0][..4], [0xc0, 0x21, CONF_ACK, 7]);

        // The server acknowledges ours: LCP open, IPCP starts with 0.0.0.0 placeholders.
        let ev = ppp
            .receive(&packet(PROTO_LCP, CONF_ACK, our_lcp_id, &[]))
            .unwrap();
        let ipcp_req = &sent(&ev)[0];
        assert_eq!(&ipcp_req[..3], &[0x80, 0x21, CONF_REQ]);
        let ipcp_id = ipcp_req[3];

        // The server's IPCP request (its address): acknowledged.
        let ev = ppp
            .receive(&packet(
                PROTO_IPCP,
                CONF_REQ,
                3,
                &opts(&[(IPCP_ADDRESS, &[169, 254, 2, 1])]),
            ))
            .unwrap();
        assert_eq!(sent(&ev)[0][..4], [0x80, 0x21, CONF_ACK, 3]);

        // Nak with the real address and DNS servers; we ask again with them.
        let nak = opts(&[
            (IPCP_ADDRESS, &[10, 212, 134, 200]),
            (IPCP_DNS1, &[10, 0, 0, 53]),
            (IPCP_DNS2, &[10, 0, 0, 54]),
        ]);
        let ev = ppp
            .receive(&packet(PROTO_IPCP, CONF_NAK, ipcp_id, &nak))
            .unwrap();
        let retry = &sent(&ev)[0];
        assert_eq!(&retry[6..], &nak[..]);
        let retry_id = retry[3];

        let ev = ppp
            .receive(&packet(PROTO_IPCP, CONF_ACK, retry_id, &nak))
            .unwrap();
        assert_eq!(
            ev,
            vec![Event::Up(IpConfig {
                address: Ipv4Addr::new(10, 212, 134, 200),
                dns: vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)],
                mtu: 1354,
            })]
        );
        assert!(ppp.is_up());

        // Data in both directions.
        let ip = vec![0x45, 0, 0, 20];
        assert_eq!(ppp.encode_ip(&ip)[..4], [0xff, 0x03, 0x00, 0x21]);
        let mut incoming = vec![0x00, 0x21];
        incoming.extend_from_slice(&ip);
        assert_eq!(
            ppp.receive(&incoming).unwrap(),
            vec![Event::Deliver(ip.clone())]
        );
        // Compressed protocol field and address/control prefix are understood too.
        let mut compressed = vec![0xff, 0x03, 0x21];
        compressed.extend_from_slice(&ip);
        assert_eq!(ppp.receive(&compressed).unwrap(), vec![Event::Deliver(ip)]);
    }

    fn opened() -> Ppp {
        let mut ppp = Ppp::new(1, 1354, Some(Ipv4Addr::new(10, 0, 0, 5)), true);
        let id = sent(&ppp.start())[0][3];
        ppp.receive(&packet(PROTO_LCP, CONF_REQ, 1, &[])).unwrap();
        ppp.receive(&packet(PROTO_LCP, CONF_ACK, id, &[])).unwrap();
        ppp
    }

    #[test]
    fn echo_unknown_protocols_and_termination() {
        let mut ppp = opened();
        let ev = ppp
            .receive(&packet(PROTO_LCP, ECHO_REQ, 42, &[0, 0, 0, 9, 0xaa]))
            .unwrap();
        let reply = &sent(&ev)[0];
        assert_eq!(&reply[..4], &[0xc0, 0x21, ECHO_REP, 42]);
        assert_eq!(&reply[6..], &[0, 0, 0, 1, 0xaa]);

        let ev = ppp
            .receive(&packet(
                0x8057,
                CONF_REQ,
                1,
                &[1, 10, 0, 0, 0, 0, 0, 0, 0, 1],
            ))
            .unwrap();
        let reject = &sent(&ev)[0];
        assert_eq!(&reject[..3], &[0xc0, 0x21, PROTO_REJ]);
        assert_eq!(&reject[6..8], &[0x80, 0x57]);

        let ev = ppp.receive(&packet(PROTO_LCP, TERM_REQ, 5, &[])).unwrap();
        assert_eq!(sent(&ev)[0][..4], [0xc0, 0x21, TERM_ACK, 5]);
        assert!(ev.iter().any(|e| matches!(e, Event::Down(_))));
    }

    #[test]
    fn unsupported_options_are_rejected_and_rejections_honoured() {
        let mut ppp = Ppp::new(1, 1354, None, true);
        let id = sent(&ppp.start())[0][3];
        // Authentication protocol (3) is not something we do: Configure-Reject.
        let ev = ppp
            .receive(&packet(
                PROTO_LCP,
                CONF_REQ,
                2,
                &opts(&[(3, &[0xc0, 0x23])]),
            ))
            .unwrap();
        assert_eq!(sent(&ev)[0][2], CONF_REJ);
        // The server rejects our magic number: the next request leaves it out.
        let ev = ppp
            .receive(&packet(
                PROTO_LCP,
                CONF_REJ,
                id,
                &opts(&[(LCP_MAGIC, &[0, 0, 0, 1])]),
            ))
            .unwrap();
        let retry = &sent(&ev)[0];
        assert_eq!(&retry[6..], &opts(&[(LCP_MRU, &1354u16.to_be_bytes())])[..]);
    }

    #[test]
    fn malformed_packets_are_errors() {
        let mut ppp = Ppp::new(1, 1354, None, true);
        assert!(ppp.receive(&[0xc0]).is_err());
        assert!(ppp.receive(&[0xc0, 0x21, 1, 1, 0, 99]).is_err());
        assert!(ppp.receive(&[0xc0, 0x21, 1, 1, 0, 6, 1, 9]).is_err());
        // IP before the link is up is dropped silently.
        assert!(ppp.receive(&[0x00, 0x21, 0x45]).unwrap().is_empty());
    }

    #[test]
    fn early_ipcp_smaller_peer_mru_and_configured_dns() {
        // DNS came with the tunnel configuration: IPCP asks for the address only.
        let mut ppp = Ppp::new(1, 1354, Some(Ipv4Addr::new(10, 0, 0, 5)), false);
        let id = sent(&ppp.start())[0][3];
        // The server's IPCP request before LCP is open is answered.
        let ev = ppp
            .receive(&packet(
                PROTO_IPCP,
                CONF_REQ,
                4,
                &opts(&[(IPCP_ADDRESS, &[192, 0, 2, 1])]),
            ))
            .unwrap();
        assert_eq!(sent(&ev)[0][..4], [0x80, 0x21, CONF_ACK, 4]);
        // The server wants a smaller MRU.
        ppp.receive(&packet(
            PROTO_LCP,
            CONF_REQ,
            1,
            &opts(&[(LCP_MRU, &1300u16.to_be_bytes())]),
        ))
        .unwrap();
        let ev = ppp.receive(&packet(PROTO_LCP, CONF_ACK, id, &[])).unwrap();
        let request = &sent(&ev)[0];
        assert_eq!(&request[6..], &opts(&[(IPCP_ADDRESS, &[10, 0, 0, 5])])[..]);
        // An Ack with another id still counts.
        let ev = ppp
            .receive(&packet(
                PROTO_IPCP,
                CONF_ACK,
                request[3].wrapping_add(9),
                &[],
            ))
            .unwrap();
        assert_eq!(
            ev,
            vec![Event::Up(IpConfig {
                address: Ipv4Addr::new(10, 0, 0, 5),
                dns: Vec::new(),
                mtu: 1300,
            })]
        );
    }
}
