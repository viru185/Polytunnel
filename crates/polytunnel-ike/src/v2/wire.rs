//! IKEv2 messages on the wire ([RFC 7296] section 3), plus fragmentation ([RFC 7383]).
//!
//! [RFC 7296]: https://www.rfc-editor.org/rfc/rfc7296
//! [RFC 7383]: https://www.rfc-editor.org/rfc/rfc7383

use std::net::Ipv4Addr;

pub use crate::v1::wire::WireError;

pub const HEADER_LEN: usize = 28;
/// IKE version 2.0.
pub const VERSION: u8 = 0x20;

pub mod exchange {
    pub const IKE_SA_INIT: u8 = 34;
    pub const IKE_AUTH: u8 = 35;
    pub const CREATE_CHILD_SA: u8 = 36;
    pub const INFORMATIONAL: u8 = 37;
}

pub mod flag {
    pub const INITIATOR: u8 = 0x08;
    pub const RESPONSE: u8 = 0x20;
}

pub mod payload {
    pub const NONE: u8 = 0;
    pub const SA: u8 = 33;
    pub const KE: u8 = 34;
    pub const IDI: u8 = 35;
    pub const IDR: u8 = 36;
    pub const CERT: u8 = 37;
    pub const CERTREQ: u8 = 38;
    pub const AUTH: u8 = 39;
    pub const NONCE: u8 = 40;
    pub const NOTIFY: u8 = 41;
    pub const DELETE: u8 = 42;
    pub const VENDOR: u8 = 43;
    pub const TSI: u8 = 44;
    pub const TSR: u8 = 45;
    /// Encrypted and authenticated.
    pub const SK: u8 = 46;
    pub const CP: u8 = 47;
    pub const EAP: u8 = 48;
    /// Encrypted fragment (RFC 7383).
    pub const SKF: u8 = 53;
}

pub mod notify {
    pub const UNSUPPORTED_CRITICAL_PAYLOAD: u16 = 1;
    pub const INVALID_SYNTAX: u16 = 7;
    pub const NO_PROPOSAL_CHOSEN: u16 = 14;
    pub const INVALID_KE_PAYLOAD: u16 = 17;
    pub const AUTHENTICATION_FAILED: u16 = 24;
    pub const SINGLE_PAIR_REQUIRED: u16 = 34;
    pub const NO_ADDITIONAL_SAS: u16 = 35;
    pub const INTERNAL_ADDRESS_FAILURE: u16 = 36;
    pub const FAILED_CP_REQUIRED: u16 = 37;
    pub const TS_UNACCEPTABLE: u16 = 38;
    pub const TEMPORARY_FAILURE: u16 = 43;
    pub const CHILD_SA_NOT_FOUND: u16 = 44;
    /// Below this, a notification reports an error.
    pub const ERROR_MAX: u16 = 16383;
    pub const INITIAL_CONTACT: u16 = 16384;
    pub const NAT_DETECTION_SOURCE_IP: u16 = 16388;
    pub const NAT_DETECTION_DESTINATION_IP: u16 = 16389;
    pub const COOKIE: u16 = 16390;
    pub const USE_TRANSPORT_MODE: u16 = 16391;
    pub const REKEY_SA: u16 = 16393;
    pub const EAP_ONLY_AUTHENTICATION: u16 = 16417;
    pub const FRAGMENTATION_SUPPORTED: u16 = 16430;
    pub const SIGNATURE_HASH_ALGORITHMS: u16 = 16431;
}

pub mod protocol {
    pub const IKE: u8 = 1;
    pub const ESP: u8 = 3;
}

pub mod id_type {
    pub const IPV4_ADDR: u8 = 1;
    pub const FQDN: u8 = 2;
    pub const RFC822_ADDR: u8 = 3;
    pub const DER_ASN1_DN: u8 = 9;
    pub const KEY_ID: u8 = 11;
}

pub mod auth_method {
    pub const RSA: u8 = 1;
    pub const PSK: u8 = 2;
    pub const ECDSA_256: u8 = 9;
    pub const ECDSA_384: u8 = 10;
    pub const ECDSA_521: u8 = 11;
    /// RFC 7427.
    pub const DIGITAL_SIGNATURE: u8 = 14;
}

pub mod transform {
    pub const ENCR: u8 = 1;
    pub const PRF: u8 = 2;
    pub const INTEG: u8 = 3;
    pub const DH: u8 = 4;
    pub const ESN: u8 = 5;

    pub const ENCR_AES_CBC: u16 = 12;
    pub const ENCR_AES_GCM_16: u16 = 20;
    pub const PRF_HMAC_SHA1: u16 = 2;
    pub const PRF_HMAC_SHA2_256: u16 = 5;
    pub const PRF_HMAC_SHA2_384: u16 = 6;
    pub const PRF_HMAC_SHA2_512: u16 = 7;
    pub const AUTH_HMAC_SHA1_96: u16 = 2;
    pub const AUTH_HMAC_SHA2_256_128: u16 = 12;
    pub const AUTH_HMAC_SHA2_384_192: u16 = 13;
    pub const AUTH_HMAC_SHA2_512_256: u16 = 14;
    pub const ESN_NONE: u16 = 0;
    /// The key-length attribute (TV), in bits.
    pub const ATTR_KEY_LENGTH: u16 = 14;
}

pub mod cp {
    pub const REQUEST: u8 = 1;
    pub const REPLY: u8 = 2;
    pub const INTERNAL_IP4_ADDRESS: u16 = 1;
    pub const INTERNAL_IP4_NETMASK: u16 = 2;
    pub const INTERNAL_IP4_DNS: u16 = 3;
    pub const INTERNAL_IP4_SUBNET: u16 = 13;
    /// RFC 8598.
    pub const INTERNAL_DNS_DOMAIN: u16 = 25;
}

/// Certificate encodings.
pub const CERT_X509_SIGNATURE: u8 = 4;
/// Traffic selector type.
pub const TS_IPV4_ADDR_RANGE: u8 = 7;

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn len16(n: usize) -> [u8; 2] {
    u16::try_from(n)
        .expect("IKE payloads are far below 64 KiB")
        .to_be_bytes()
}

// ------------------------------------------------------------------------------ header

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub spi_i: [u8; 8],
    pub spi_r: [u8; 8],
    pub next: u8,
    pub exchange: u8,
    pub flags: u8,
    pub mid: u32,
    pub len: u32,
}

impl Header {
    /// Splits a message into its header and body.
    pub fn parse(data: &[u8]) -> Result<(Header, &[u8]), WireError> {
        if data.len() < HEADER_LEN {
            return Err(WireError("shorter than the header"));
        }
        if data[17] >> 4 != 2 {
            return Err(WireError("not IKE version 2"));
        }
        let len = be32(&data[24..28]);
        let end = usize::try_from(len).map_err(|_| WireError("length"))?;
        if end < HEADER_LEN || end > data.len() {
            return Err(WireError("length field does not match the message"));
        }
        Ok((
            Header {
                spi_i: data[0..8].try_into().expect("8 bytes"),
                spi_r: data[8..16].try_into().expect("8 bytes"),
                next: data[16],
                exchange: data[18],
                flags: data[19],
                mid: be32(&data[20..24]),
                len,
            },
            &data[HEADER_LEN..end],
        ))
    }

    pub fn is_response(&self) -> bool {
        self.flags & flag::RESPONSE != 0
    }

    pub fn encode(&self, body_len: usize) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..8].copy_from_slice(&self.spi_i);
        out[8..16].copy_from_slice(&self.spi_r);
        out[16] = self.next;
        out[17] = VERSION;
        out[18] = self.exchange;
        out[19] = self.flags;
        out[20..24].copy_from_slice(&self.mid.to_be_bytes());
        let total = u32::try_from(HEADER_LEN + body_len).expect("small message");
        out[24..28].copy_from_slice(&total.to_be_bytes());
        out
    }
}

// ------------------------------------------------------------------------------ payloads

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub kind: u8,
    pub body: Vec<u8>,
}

impl Payload {
    pub fn new(kind: u8, body: Vec<u8>) -> Self {
        Self { kind, body }
    }
}

/// Encodes a payload chain whose last payload links to `last_next` (an SK payload's inner
/// first payload, otherwise none).
pub fn encode_chain(payloads: &[Payload]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, p) in payloads.iter().enumerate() {
        out.push(payloads.get(i + 1).map_or(payload::NONE, |n| n.kind));
        out.push(0);
        out.extend_from_slice(&len16(p.body.len() + 4));
        out.extend_from_slice(&p.body);
    }
    out
}

/// Where an encrypted (SK or SKF) payload sits in a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encrypted {
    pub kind: u8,
    /// The first payload inside.
    pub inner_next: u8,
    /// Offset of its generic header from the start of the whole message.
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub payloads: Vec<Payload>,
    /// The SK/SKF payload, which always comes last.
    pub encrypted: Option<Encrypted>,
}

impl Chain {
    /// Parses a payload chain; `base` is the chain's offset in the whole message.
    pub fn parse(first: u8, data: &[u8], base: usize) -> Result<Chain, WireError> {
        let mut payloads = Vec::new();
        let mut kind = first;
        let mut at = 0;
        while kind != payload::NONE {
            if payloads.len() >= 64 {
                return Err(WireError("too many payloads"));
            }
            let head = data
                .get(at..at + 4)
                .ok_or(WireError("truncated payload header"))?;
            let len = usize::from(be16(&head[2..4]));
            if len < 4 || at + len > data.len() {
                return Err(WireError("payload length out of range"));
            }
            if kind == payload::SK || kind == payload::SKF {
                return Ok(Chain {
                    payloads,
                    encrypted: Some(Encrypted {
                        kind,
                        inner_next: head[0],
                        offset: base + at,
                    }),
                });
            }
            payloads.push(Payload::new(kind, data[at + 4..at + len].to_vec()));
            kind = head[0];
            at += len;
        }
        Ok(Chain {
            payloads,
            encrypted: None,
        })
    }

    pub fn find(&self, kind: u8) -> Option<&[u8]> {
        self.payloads
            .iter()
            .find(|p| p.kind == kind)
            .map(|p| p.body.as_slice())
    }

    pub fn all(&self, kind: u8) -> impl Iterator<Item = &[u8]> {
        self.payloads
            .iter()
            .filter(move |p| p.kind == kind)
            .map(|p| p.body.as_slice())
    }

    pub fn notifies(&self) -> impl Iterator<Item = Notify> + '_ {
        self.all(payload::NOTIFY)
            .filter_map(|b| Notify::parse(b).ok())
    }

    pub fn notify(&self, kind: u16) -> Option<Notify> {
        self.notifies().find(|n| n.kind == kind)
    }
}

// ------------------------------------------------------------------------------ SA

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub kind: u8,
    pub id: u16,
    /// Key length in bits, if given.
    pub key_len: Option<u16>,
}

impl Transform {
    pub fn new(kind: u8, id: u16) -> Self {
        Self {
            kind,
            id,
            key_len: None,
        }
    }

    pub fn with_key_len(kind: u8, id: u16, bits: u16) -> Self {
        Self {
            kind,
            id,
            key_len: Some(bits),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub number: u8,
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

impl Proposal {
    /// The transform of a type, if exactly one was chosen.
    pub fn one(&self, kind: u8) -> Option<&Transform> {
        let mut it = self.transforms.iter().filter(|t| t.kind == kind);
        let first = it.next()?;
        it.next().is_none().then_some(first)
    }
}

pub fn encode_sa(proposals: &[Proposal]) -> Vec<u8> {
    let mut out = Vec::new();
    for (pi, p) in proposals.iter().enumerate() {
        let mut body = vec![
            p.number,
            p.protocol,
            u8::try_from(p.spi.len()).expect("short SPI"),
            u8::try_from(p.transforms.len()).expect("few transforms"),
        ];
        body.extend_from_slice(&p.spi);
        for (ti, t) in p.transforms.iter().enumerate() {
            let attrs = t
                .key_len
                .map(|bits| {
                    let mut a = (transform::ATTR_KEY_LENGTH | 0x8000).to_be_bytes().to_vec();
                    a.extend_from_slice(&bits.to_be_bytes());
                    a
                })
                .unwrap_or_default();
            body.push(if ti + 1 < p.transforms.len() { 3 } else { 0 });
            body.push(0);
            body.extend_from_slice(&len16(8 + attrs.len()));
            body.push(t.kind);
            body.push(0);
            body.extend_from_slice(&t.id.to_be_bytes());
            body.extend_from_slice(&attrs);
        }
        out.push(if pi + 1 < proposals.len() { 2 } else { 0 });
        out.push(0);
        out.extend_from_slice(&len16(4 + body.len()));
        out.extend_from_slice(&body);
    }
    out
}

pub fn parse_sa(mut data: &[u8]) -> Result<Vec<Proposal>, WireError> {
    let mut proposals = Vec::new();
    while !data.is_empty() {
        if data.len() < 8 || proposals.len() >= 64 {
            return Err(WireError("truncated proposal"));
        }
        let last = data[0] == 0;
        let len = usize::from(be16(&data[2..4]));
        if len < 8 || len > data.len() {
            return Err(WireError("proposal length out of range"));
        }
        let p = &data[4..len];
        let spi_len = usize::from(p[2]);
        let count = usize::from(p[3]);
        let spi = p
            .get(4..4 + spi_len)
            .ok_or(WireError("truncated SPI"))?
            .to_vec();
        let mut rest = &p[4 + spi_len..];
        let mut transforms = Vec::new();
        for _ in 0..count {
            if rest.len() < 8 {
                return Err(WireError("truncated transform"));
            }
            let tlen = usize::from(be16(&rest[2..4]));
            if tlen < 8 || tlen > rest.len() {
                return Err(WireError("transform length out of range"));
            }
            let mut key_len = None;
            let mut attrs = &rest[8..tlen];
            while attrs.len() >= 4 {
                let kind = be16(attrs);
                if kind & 0x8000 != 0 {
                    if kind & 0x7fff == transform::ATTR_KEY_LENGTH {
                        key_len = Some(be16(&attrs[2..4]));
                    }
                    attrs = &attrs[4..];
                } else {
                    let alen = usize::from(be16(&attrs[2..4]));
                    attrs = attrs.get(4 + alen..).ok_or(WireError("attribute"))?;
                }
            }
            transforms.push(Transform {
                kind: rest[4],
                id: be16(&rest[6..8]),
                key_len,
            });
            rest = &rest[tlen..];
        }
        proposals.push(Proposal {
            number: p[0],
            protocol: p[1],
            spi,
            transforms,
        });
        data = &data[len..];
        if last {
            break;
        }
    }
    Ok(proposals)
}

// ------------------------------------------------------------------------------ small payloads

pub fn encode_ke(group: u16, data: &[u8]) -> Vec<u8> {
    let mut out = group.to_be_bytes().to_vec();
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(data);
    out
}

pub fn parse_ke(data: &[u8]) -> Result<(u16, &[u8]), WireError> {
    if data.len() < 4 {
        return Err(WireError("truncated KE"));
    }
    Ok((be16(data), &data[4..]))
}

/// ID payload body: type, three reserved bytes, data.
pub fn encode_id(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![kind, 0, 0, 0];
    out.extend_from_slice(data);
    out
}

pub fn parse_id(data: &[u8]) -> Result<(u8, &[u8]), WireError> {
    if data.len() < 4 {
        return Err(WireError("truncated ID"));
    }
    Ok((data[0], &data[4..]))
}

pub fn encode_auth(method: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![method, 0, 0, 0];
    out.extend_from_slice(data);
    out
}

pub fn parse_auth(data: &[u8]) -> Result<(u8, &[u8]), WireError> {
    if data.len() < 4 {
        return Err(WireError("truncated AUTH"));
    }
    Ok((data[0], &data[4..]))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notify {
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub kind: u16,
    pub data: Vec<u8>,
}

impl Notify {
    pub fn new(kind: u16, data: Vec<u8>) -> Self {
        Self {
            protocol: 0,
            spi: Vec::new(),
            kind,
            data,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            self.protocol,
            u8::try_from(self.spi.len()).expect("short SPI"),
        ];
        out.extend_from_slice(&self.kind.to_be_bytes());
        out.extend_from_slice(&self.spi);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn parse(data: &[u8]) -> Result<Notify, WireError> {
        if data.len() < 4 {
            return Err(WireError("truncated notification"));
        }
        let spi_len = usize::from(data[1]);
        let spi = data
            .get(4..4 + spi_len)
            .ok_or(WireError("truncated notification SPI"))?;
        Ok(Notify {
            protocol: data[0],
            spi: spi.to_vec(),
            kind: be16(&data[2..4]),
            data: data[4 + spi_len..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delete {
    pub protocol: u8,
    /// ESP SPIs; empty for the IKE SA.
    pub spis: Vec<u32>,
}

impl Delete {
    pub fn encode(&self) -> Vec<u8> {
        let spi_len = if self.protocol == protocol::IKE { 0 } else { 4 };
        let mut out = vec![self.protocol, spi_len];
        out.extend_from_slice(&len16(self.spis.len()));
        for spi in &self.spis {
            out.extend_from_slice(&spi.to_be_bytes());
        }
        out
    }

    pub fn parse(data: &[u8]) -> Result<Delete, WireError> {
        if data.len() < 4 {
            return Err(WireError("truncated delete"));
        }
        let spi_len = usize::from(data[1]);
        let count = usize::from(be16(&data[2..4]));
        let mut spis = Vec::new();
        if spi_len == 4 {
            let rest = &data[4..];
            if rest.len() < 4 * count {
                return Err(WireError("delete SPIs out of range"));
            }
            spis = rest
                .as_chunks::<4>()
                .0
                .iter()
                .take(count)
                .map(|c| be32(c))
                .collect();
        }
        Ok(Delete {
            protocol: data[0],
            spis,
        })
    }
}

/// A traffic selector: an IPv4 range and a protocol (0: any), all ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selector {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
}

impl Selector {
    pub const ANY: Selector = Selector {
        start: Ipv4Addr::UNSPECIFIED,
        end: Ipv4Addr::BROADCAST,
    };

    /// `net/len` as a range.
    pub fn network(net: Ipv4Addr, len: u8) -> Self {
        let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
        let start = u32::from(net) & mask;
        Selector {
            start: Ipv4Addr::from(start),
            end: Ipv4Addr::from(start | !mask),
        }
    }

    pub fn host(addr: Ipv4Addr) -> Self {
        Selector {
            start: addr,
            end: addr,
        }
    }

    /// The range as networks (exact when it is one CIDR block, which is what gateways send).
    pub fn to_network(self) -> Option<(Ipv4Addr, u8)> {
        let (s, e) = (u32::from(self.start), u32::from(self.end));
        let size = e.checked_sub(s)?.checked_add(1);
        match size {
            None => Some((Ipv4Addr::UNSPECIFIED, 0)), // the whole space
            Some(n) if n.is_power_of_two() && s % n == 0 => Some((
                self.start,
                u8::try_from(32 - n.trailing_zeros()).expect("<= 32"),
            )),
            _ => None,
        }
    }
}

pub fn encode_ts(selectors: &[Selector]) -> Vec<u8> {
    let mut out = vec![
        u8::try_from(selectors.len()).expect("few selectors"),
        0,
        0,
        0,
    ];
    for s in selectors {
        out.extend_from_slice(&[TS_IPV4_ADDR_RANGE, 0, 0, 16, 0, 0, 0xff, 0xff]);
        out.extend_from_slice(&s.start.octets());
        out.extend_from_slice(&s.end.octets());
    }
    out
}

/// The IPv4 selectors in a TS payload (others are skipped).
pub fn parse_ts(data: &[u8]) -> Result<Vec<Selector>, WireError> {
    if data.len() < 4 {
        return Err(WireError("truncated TS"));
    }
    let count = usize::from(data[0]);
    let mut rest = &data[4..];
    let mut out = Vec::new();
    for _ in 0..count {
        if rest.len() < 4 {
            return Err(WireError("truncated selector"));
        }
        let len = usize::from(be16(&rest[2..4]));
        if len < 8 || len > rest.len() {
            return Err(WireError("selector length out of range"));
        }
        if rest[0] == TS_IPV4_ADDR_RANGE && len == 16 {
            out.push(Selector {
                start: Ipv4Addr::new(rest[8], rest[9], rest[10], rest[11]),
                end: Ipv4Addr::new(rest[12], rest[13], rest[14], rest[15]),
            });
        }
        rest = &rest[len..];
    }
    Ok(out)
}

/// One configuration attribute: its type and value.
pub type CpAttr = (u16, Vec<u8>);

/// A configuration payload: its type and (attribute type, value) pairs.
pub fn encode_cp(kind: u8, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![kind, 0, 0, 0];
    for (t, v) in attrs {
        out.extend_from_slice(&(t & 0x7fff).to_be_bytes());
        out.extend_from_slice(&len16(v.len()));
        out.extend_from_slice(v);
    }
    out
}

pub fn parse_cp(data: &[u8]) -> Result<(u8, Vec<CpAttr>), WireError> {
    if data.len() < 4 {
        return Err(WireError("truncated CP"));
    }
    let mut rest = &data[4..];
    let mut attrs = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(WireError("truncated CP attribute"));
        }
        let len = usize::from(be16(&rest[2..4]));
        let value = rest
            .get(4..4 + len)
            .ok_or(WireError("CP attribute length out of range"))?;
        attrs.push((be16(rest) & 0x7fff, value.to_vec()));
        rest = &rest[4 + len..];
    }
    Ok((data[0], attrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sa_round_trip_with_key_lengths() {
        let proposals = vec![
            Proposal {
                number: 1,
                protocol: protocol::IKE,
                spi: Vec::new(),
                transforms: vec![
                    Transform::with_key_len(transform::ENCR, transform::ENCR_AES_CBC, 256),
                    Transform::new(transform::PRF, transform::PRF_HMAC_SHA2_256),
                    Transform::new(transform::INTEG, transform::AUTH_HMAC_SHA2_256_128),
                    Transform::new(transform::DH, 14),
                ],
            },
            Proposal {
                number: 2,
                protocol: protocol::ESP,
                spi: vec![1, 2, 3, 4],
                transforms: vec![
                    Transform::with_key_len(transform::ENCR, transform::ENCR_AES_GCM_16, 128),
                    Transform::new(transform::ESN, transform::ESN_NONE),
                ],
            },
        ];
        let raw = encode_sa(&proposals);
        assert_eq!(parse_sa(&raw).unwrap(), proposals);
        assert_eq!(
            proposals[0].one(transform::DH),
            Some(&Transform::new(transform::DH, 14))
        );
        assert!(parse_sa(&raw[..raw.len() - 2]).is_err());
    }

    #[test]
    fn chains_stop_at_the_encrypted_payload() {
        let mut raw = encode_chain(&[Payload::new(payload::NONCE, vec![1; 8])]);
        raw[0] = payload::SK;
        raw.extend_from_slice(&[payload::IDI, 0, 0, 20]);
        raw.extend_from_slice(&[0; 16]);
        let chain = Chain::parse(payload::NONCE, &raw, 28).unwrap();
        assert_eq!(chain.payloads.len(), 1);
        assert_eq!(
            chain.encrypted,
            Some(Encrypted {
                kind: payload::SK,
                inner_next: payload::IDI,
                offset: 28 + 12
            })
        );
    }

    #[test]
    fn selectors_and_networks() {
        let s = Selector::network("198.51.100.77".parse().unwrap(), 24);
        assert_eq!(s.start, Ipv4Addr::new(198, 51, 100, 0));
        assert_eq!(s.end, Ipv4Addr::new(198, 51, 100, 255));
        assert_eq!(s.to_network(), Some((Ipv4Addr::new(198, 51, 100, 0), 24)));
        assert_eq!(Selector::ANY.to_network(), Some((Ipv4Addr::UNSPECIFIED, 0)));
        let odd = Selector {
            start: Ipv4Addr::new(192, 0, 2, 1),
            end: Ipv4Addr::new(192, 0, 2, 5),
        };
        assert_eq!(odd.to_network(), None);
        let raw = encode_ts(&[s, Selector::host(Ipv4Addr::new(192, 0, 2, 9))]);
        assert_eq!(parse_ts(&raw).unwrap().len(), 2);
    }

    #[test]
    fn small_payloads_round_trip() {
        let n = Notify {
            protocol: protocol::ESP,
            spi: vec![9, 9, 9, 9],
            kind: notify::REKEY_SA,
            data: Vec::new(),
        };
        assert_eq!(Notify::parse(&n.encode()).unwrap(), n);
        let d = Delete {
            protocol: protocol::ESP,
            spis: vec![0x1234_5678],
        };
        assert_eq!(Delete::parse(&d.encode()).unwrap(), d);
        let ike = Delete {
            protocol: protocol::IKE,
            spis: Vec::new(),
        };
        assert_eq!(Delete::parse(&ike.encode()).unwrap(), ike);
        let cp = encode_cp(cp::REQUEST, &[(cp::INTERNAL_IP4_ADDRESS, Vec::new())]);
        assert_eq!(
            parse_cp(&cp).unwrap(),
            (cp::REQUEST, vec![(cp::INTERNAL_IP4_ADDRESS, Vec::new())])
        );
        assert_eq!(
            parse_ke(&encode_ke(19, &[7; 64])).unwrap(),
            (19, &[7u8; 64][..])
        );
        assert_eq!(
            parse_id(&encode_id(id_type::FQDN, b"a")).unwrap(),
            (2, &b"a"[..])
        );
    }
}
