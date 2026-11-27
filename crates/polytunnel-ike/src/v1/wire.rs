//! IKEv1 messages on the wire ([RFC 2408] section 3, [RFC 2407] for the IPsec DOI): the
//! header, the payload chain and the payloads Polytunnel uses.
//!
//! [RFC 2408]: https://www.rfc-editor.org/rfc/rfc2408
//! [RFC 2407]: https://www.rfc-editor.org/rfc/rfc2407

use std::fmt;

pub const HEADER_LEN: usize = 28;
/// ISAKMP version 1.0.
pub const VERSION: u8 = 0x10;
/// The IPsec domain of interpretation.
pub const DOI_IPSEC: u32 = 1;
/// SIT_IDENTITY_ONLY.
pub const SITUATION: u32 = 1;

/// Exchange types.
pub mod exchange {
    pub const AGGRESSIVE: u8 = 4;
    pub const INFORMATIONAL: u8 = 5;
    /// Mode-config and XAuth.
    pub const TRANSACTION: u8 = 6;
    pub const QUICK: u8 = 32;
}

/// Header flags.
pub mod flag {
    pub const ENCRYPTED: u8 = 1;
}

/// Payload types.
pub mod payload {
    pub const NONE: u8 = 0;
    pub const SA: u8 = 1;
    pub const PROPOSAL: u8 = 2;
    pub const TRANSFORM: u8 = 3;
    pub const KE: u8 = 4;
    pub const ID: u8 = 5;
    pub const HASH: u8 = 8;
    pub const NONCE: u8 = 10;
    pub const NOTIFY: u8 = 11;
    pub const DELETE: u8 = 12;
    pub const VENDOR: u8 = 13;
    /// Mode-config / XAuth attributes.
    pub const ATTRIBUTES: u8 = 14;
    /// NAT discovery (RFC 3947).
    pub const NAT_D: u8 = 20;
    /// NAT discovery, pre-RFC drafts.
    pub const NAT_D_DRAFT: u8 = 130;
}

/// Protocol IDs.
pub mod protocol {
    pub const ISAKMP: u8 = 1;
    pub const ESP: u8 = 3;
}

/// Identification types (RFC 2407, "Identification Type Values").
pub mod id_type {
    pub const IPV4_ADDR: u8 = 1;
    pub const FQDN: u8 = 2;
    pub const USER_FQDN: u8 = 3;
    pub const IPV4_ADDR_SUBNET: u8 = 4;
    pub const KEY_ID: u8 = 11;
}

/// Notification types.
pub mod notify {
    pub const INVALID_PAYLOAD_TYPE: u16 = 1;
    pub const INVALID_EXCHANGE_TYPE: u16 = 7;
    pub const INVALID_FLAGS: u16 = 8;
    pub const INVALID_MESSAGE_ID: u16 = 9;
    pub const INVALID_SPI: u16 = 11;
    pub const ATTRIBUTES_NOT_SUPPORTED: u16 = 13;
    pub const NO_PROPOSAL_CHOSEN: u16 = 14;
    pub const PAYLOAD_MALFORMED: u16 = 16;
    pub const INVALID_KEY_INFORMATION: u16 = 17;
    pub const INVALID_ID_INFORMATION: u16 = 18;
    pub const INVALID_HASH_INFORMATION: u16 = 23;
    pub const AUTHENTICATION_FAILED: u16 = 24;
    /// Below this, a notification reports an error.
    pub const ERROR_MAX: u16 = 8191;
    pub const RESPONDER_LIFETIME: u16 = 24576;
    pub const INITIAL_CONTACT: u16 = 24578;
    /// Dead-peer detection (RFC 3706).
    pub const R_U_THERE: u16 = 36136;
    pub const R_U_THERE_ACK: u16 = 36137;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireError(pub &'static str);

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed IKE message: {}", self.0)
    }
}

impl std::error::Error for WireError {}

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
    pub cky_i: [u8; 8],
    pub cky_r: [u8; 8],
    /// The first payload's type.
    pub next: u8,
    pub exchange: u8,
    pub flags: u8,
    pub mid: u32,
    /// Length of the whole message, header included.
    pub len: u32,
}

impl Header {
    /// Splits a datagram into its header and body (the payloads, maybe encrypted).
    pub fn parse(data: &[u8]) -> Result<(Header, &[u8]), WireError> {
        if data.len() < HEADER_LEN {
            return Err(WireError("shorter than the header"));
        }
        if data[17] >> 4 != 1 {
            return Err(WireError("not IKE version 1"));
        }
        let len = be32(&data[24..28]);
        let end = usize::try_from(len).map_err(|_| WireError("length"))?;
        if end < HEADER_LEN || end > data.len() {
            return Err(WireError("length field does not match the datagram"));
        }
        let header = Header {
            cky_i: data[0..8].try_into().expect("8 bytes"),
            cky_r: data[8..16].try_into().expect("8 bytes"),
            next: data[16],
            exchange: data[18],
            flags: data[19],
            mid: be32(&data[20..24]),
            len,
        };
        Ok((header, &data[HEADER_LEN..end]))
    }

    pub fn encrypted(&self) -> bool {
        self.flags & flag::ENCRYPTED != 0
    }

    /// The 28 header bytes for a body of `body_len` bytes.
    pub fn encode(&self, body_len: usize) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..8].copy_from_slice(&self.cky_i);
        out[8..16].copy_from_slice(&self.cky_r);
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

// ------------------------------------------------------------------------------ payload chain

/// One payload: its type and body (without the 4-byte generic header).
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

/// Encodes a payload chain (the generic headers link each payload to the next).
pub fn encode_chain(payloads: &[Payload]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, p) in payloads.iter().enumerate() {
        let next = payloads.get(i + 1).map_or(payload::NONE, |n| n.kind);
        out.push(next);
        out.push(0);
        out.extend_from_slice(&len16(p.body.len() + 4));
        out.extend_from_slice(&p.body);
    }
    out
}

/// A parsed payload chain, with where each payload ends (for hashes over raw payloads).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub payloads: Vec<Payload>,
    ends: Vec<usize>,
}

impl Chain {
    /// Parses the chain starting with a payload of type `first`. Bytes after the last payload
    /// (encryption padding) are ignored.
    pub fn parse(first: u8, data: &[u8]) -> Result<Chain, WireError> {
        let mut payloads = Vec::new();
        let mut ends = Vec::new();
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
            payloads.push(Payload::new(kind, data[at + 4..at + len].to_vec()));
            kind = head[0];
            at += len;
            ends.push(at);
        }
        Ok(Chain { payloads, ends })
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

    /// The raw bytes of every payload after the first one (what IKE's HASH payloads cover).
    pub fn after_first<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        match (self.ends.first(), self.ends.last()) {
            (Some(&first), Some(&last)) => &data[first..last],
            _ => &[],
        }
    }
}

/// A whole message: header plus the encoded (unencrypted) payload chain.
pub fn message(header: Header, payloads: &[Payload]) -> Vec<u8> {
    let body = encode_chain(payloads);
    let header = Header {
        next: payloads.first().map_or(payload::NONE, |p| p.kind),
        ..header
    };
    let mut out = header.encode(body.len()).to_vec();
    out.extend_from_slice(&body);
    out
}

// ------------------------------------------------------------------------------ attributes

/// A data attribute: basic (TV, a 16-bit value) or variable (TLV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub kind: u16,
    pub value: Vec<u8>,
    pub basic: bool,
}

impl Attribute {
    pub fn basic(kind: u16, value: u16) -> Self {
        Self {
            kind,
            value: value.to_be_bytes().to_vec(),
            basic: true,
        }
    }

    pub fn variable(kind: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            value: value.into(),
            basic: false,
        }
    }

    /// A number: basic if it fits in 16 bits, else a 4-byte variable attribute.
    pub fn number(kind: u16, value: u32) -> Self {
        match u16::try_from(value) {
            Ok(v) => Self::basic(kind, v),
            Err(_) => Self::variable(kind, value.to_be_bytes().to_vec()),
        }
    }

    /// The value as a number (saturating at `u32::MAX` for longer values).
    pub fn as_u32(&self) -> u32 {
        let significant = self
            .value
            .iter()
            .skip_while(|&&b| b == 0)
            .copied()
            .collect::<Vec<u8>>();
        if significant.len() > 4 {
            return u32::MAX;
        }
        significant
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | u32::from(b))
    }
}

pub fn encode_attributes(attrs: &[Attribute]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in attrs {
        if a.basic {
            out.extend_from_slice(&(a.kind | 0x8000).to_be_bytes());
            let mut v = [0u8; 2];
            let n = a.value.len().min(2);
            v[2 - n..].copy_from_slice(&a.value[a.value.len() - n..]);
            out.extend_from_slice(&v);
        } else {
            out.extend_from_slice(&(a.kind & 0x7fff).to_be_bytes());
            out.extend_from_slice(&len16(a.value.len()));
            out.extend_from_slice(&a.value);
        }
    }
    out
}

pub fn parse_attributes(mut data: &[u8]) -> Result<Vec<Attribute>, WireError> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data.len() < 4 {
            return Err(WireError("truncated attribute"));
        }
        let kind = be16(data);
        if kind & 0x8000 != 0 {
            out.push(Attribute {
                kind: kind & 0x7fff,
                value: data[2..4].to_vec(),
                basic: true,
            });
            data = &data[4..];
        } else {
            let len = usize::from(be16(&data[2..4]));
            let value = data
                .get(4..4 + len)
                .ok_or(WireError("attribute length out of range"))?;
            out.push(Attribute::variable(kind, value.to_vec()));
            data = &data[4 + len..];
        }
    }
    Ok(out)
}

pub fn find_attr(attrs: &[Attribute], kind: u16) -> Option<&Attribute> {
    attrs.iter().find(|a| a.kind == kind)
}

// ------------------------------------------------------------------------------ SA payload

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub number: u8,
    pub id: u8,
    pub attrs: Vec<Attribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub number: u8,
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

/// An SA payload body in the IPsec DOI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sa {
    pub proposals: Vec<Proposal>,
}

impl Sa {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&DOI_IPSEC.to_be_bytes());
        out.extend_from_slice(&SITUATION.to_be_bytes());
        for (pi, p) in self.proposals.iter().enumerate() {
            let mut body = vec![
                p.number,
                p.protocol,
                u8::try_from(p.spi.len()).expect("short SPI"),
                u8::try_from(p.transforms.len()).expect("few transforms"),
            ];
            body.extend_from_slice(&p.spi);
            for (ti, t) in p.transforms.iter().enumerate() {
                let attrs = encode_attributes(&t.attrs);
                let next = if ti + 1 < p.transforms.len() {
                    payload::TRANSFORM
                } else {
                    payload::NONE
                };
                body.push(next);
                body.push(0);
                body.extend_from_slice(&len16(attrs.len() + 8));
                body.extend_from_slice(&[t.number, t.id, 0, 0]);
                body.extend_from_slice(&attrs);
            }
            let next = if pi + 1 < self.proposals.len() {
                payload::PROPOSAL
            } else {
                payload::NONE
            };
            out.push(next);
            out.push(0);
            out.extend_from_slice(&len16(body.len() + 4));
            out.extend_from_slice(&body);
        }
        out
    }

    pub fn parse(data: &[u8]) -> Result<Sa, WireError> {
        if data.len() < 8 {
            return Err(WireError("truncated SA"));
        }
        if be32(data) != DOI_IPSEC {
            return Err(WireError("SA is not in the IPsec DOI"));
        }
        let mut proposals = Vec::new();
        for raw in Chain::parse(payload::PROPOSAL, &data[8..])?.payloads {
            if raw.kind != payload::PROPOSAL {
                return Err(WireError("SA holds something other than proposals"));
            }
            let b = &raw.body;
            if b.len() < 4 {
                return Err(WireError("truncated proposal"));
            }
            let spi_len = usize::from(b[2]);
            let spi = b
                .get(4..4 + spi_len)
                .ok_or(WireError("truncated SPI"))?
                .to_vec();
            let mut transforms = Vec::new();
            if usize::from(b[3]) > 0 {
                for t in Chain::parse(payload::TRANSFORM, &b[4 + spi_len..])?.payloads {
                    if t.body.len() < 4 {
                        return Err(WireError("truncated transform"));
                    }
                    transforms.push(Transform {
                        number: t.body[0],
                        id: t.body[1],
                        attrs: parse_attributes(&t.body[4..])?,
                    });
                }
            }
            proposals.push(Proposal {
                number: b[0],
                protocol: b[1],
                spi,
                transforms,
            });
        }
        Ok(Sa { proposals })
    }
}

// ------------------------------------------------------------------------------ small payloads

/// An identification payload body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Id {
    pub kind: u8,
    pub protocol: u8,
    pub port: u16,
    pub data: Vec<u8>,
}

impl Id {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.kind, self.protocol];
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn parse(data: &[u8]) -> Result<Id, WireError> {
        if data.len() < 4 {
            return Err(WireError("truncated ID"));
        }
        Ok(Id {
            kind: data[0],
            protocol: data[1],
            port: be16(&data[2..4]),
            data: data[4..].to_vec(),
        })
    }
}

/// A notification payload body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notify {
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub kind: u16,
    pub data: Vec<u8>,
}

impl Notify {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = DOI_IPSEC.to_be_bytes().to_vec();
        out.push(self.protocol);
        out.push(u8::try_from(self.spi.len()).expect("short SPI"));
        out.extend_from_slice(&self.kind.to_be_bytes());
        out.extend_from_slice(&self.spi);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn parse(data: &[u8]) -> Result<Notify, WireError> {
        if data.len() < 8 {
            return Err(WireError("truncated notification"));
        }
        let spi_len = usize::from(data[5]);
        let spi = data
            .get(8..8 + spi_len)
            .ok_or(WireError("truncated notification SPI"))?;
        Ok(Notify {
            protocol: data[4],
            spi: spi.to_vec(),
            kind: be16(&data[6..8]),
            data: data[8 + spi_len..].to_vec(),
        })
    }
}

/// A delete payload body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delete {
    pub protocol: u8,
    pub spis: Vec<Vec<u8>>,
}

impl Delete {
    pub fn encode(&self) -> Vec<u8> {
        let spi_len = self.spis.first().map_or(0, Vec::len);
        let mut out = DOI_IPSEC.to_be_bytes().to_vec();
        out.push(self.protocol);
        out.push(u8::try_from(spi_len).expect("short SPI"));
        out.extend_from_slice(&len16(self.spis.len()));
        for spi in &self.spis {
            out.extend_from_slice(spi);
        }
        out
    }

    pub fn parse(data: &[u8]) -> Result<Delete, WireError> {
        if data.len() < 8 {
            return Err(WireError("truncated delete"));
        }
        let spi_len = usize::from(data[5]);
        let count = usize::from(be16(&data[6..8]));
        let spis = &data[8..];
        if spi_len == 0 || spis.len() < spi_len * count {
            return Err(WireError("delete SPIs out of range"));
        }
        Ok(Delete {
            protocol: data[4],
            spis: spis
                .chunks(spi_len)
                .take(count)
                .map(<[u8]>::to_vec)
                .collect(),
        })
    }
}

/// A mode-config / XAuth attribute payload body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cfg {
    pub kind: u8,
    pub id: u16,
    pub attrs: Vec<Attribute>,
}

impl Cfg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.kind, 0];
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&encode_attributes(&self.attrs));
        out
    }

    pub fn parse(data: &[u8]) -> Result<Cfg, WireError> {
        if data.len() < 4 {
            return Err(WireError("truncated attribute payload"));
        }
        Ok(Cfg {
            kind: data[0],
            id: be16(&data[2..4]),
            attrs: parse_attributes(&data[4..])?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip_and_checks() {
        let h = Header {
            cky_i: [1; 8],
            cky_r: [2; 8],
            next: payload::SA,
            exchange: exchange::AGGRESSIVE,
            flags: 0,
            mid: 0x0102_0304,
            len: 0,
        };
        let msg = message(h, &[Payload::new(payload::NONCE, vec![9; 16])]);
        assert_eq!(msg.len(), 28 + 4 + 16);
        let (parsed, body) = Header::parse(&msg).unwrap();
        assert_eq!(parsed.next, payload::NONCE);
        assert_eq!(parsed.mid, 0x0102_0304);
        assert_eq!(parsed.len, 48);
        assert_eq!(body.len(), 20);
        assert!(Header::parse(&msg[..27]).is_err());
        let mut v2 = msg.clone();
        v2[17] = 0x20;
        assert!(Header::parse(&v2).is_err());
        let mut long = msg.clone();
        long[27] = 200;
        assert!(Header::parse(&long).is_err());
        // Trailing bytes beyond the length field are not part of the message.
        let mut extra = msg.clone();
        extra.extend_from_slice(&[0; 8]);
        assert_eq!(Header::parse(&extra).unwrap().1.len(), 20);
    }

    #[test]
    fn chains_parse_and_expose_raw_bytes_after_the_first_payload() {
        let payloads = [
            Payload::new(payload::HASH, vec![0xaa; 20]),
            Payload::new(payload::NONCE, vec![1, 2, 3]),
            Payload::new(payload::VENDOR, vec![4]),
        ];
        let mut raw = encode_chain(&payloads);
        let rest = raw[24..].to_vec();
        raw.extend_from_slice(&[0; 7]); // encryption padding
        let chain = Chain::parse(payload::HASH, &raw).unwrap();
        assert_eq!(chain.payloads, payloads);
        assert_eq!(chain.after_first(&raw), &rest[..]);
        assert_eq!(chain.find(payload::NONCE), Some(&[1u8, 2, 3][..]));
        assert_eq!(chain.all(payload::VENDOR).count(), 1);
        assert!(Chain::parse(payload::HASH, &raw[..10]).is_err());
        let mut bad = encode_chain(&payloads);
        bad[3] = 2; // length below the header size
        assert!(Chain::parse(payload::HASH, &bad).is_err());
    }

    #[test]
    fn attributes_basic_and_variable() {
        let attrs = vec![
            Attribute::basic(1, 7),
            Attribute::number(12, 28800),
            Attribute::number(12, 86400),
            Attribute::variable(16521, b"user".to_vec()),
            Attribute::variable(1, Vec::new()),
        ];
        let raw = encode_attributes(&attrs);
        let back = parse_attributes(&raw).unwrap();
        assert_eq!(back, attrs);
        assert_eq!(back[1].as_u32(), 28800);
        assert_eq!(back[2].as_u32(), 86400);
        assert!(back[2].value.len() == 4 && !back[2].basic);
        assert_eq!(&raw[..4], &[0x80, 0x01, 0x00, 0x07]);
        assert!(parse_attributes(&raw[..raw.len() - 1]).is_err());
        assert_eq!(Attribute::variable(2, vec![0, 0, 0, 0, 0, 1]).as_u32(), 1);
        assert_eq!(
            Attribute::variable(2, vec![1, 0, 0, 0, 0]).as_u32(),
            u32::MAX
        );
    }

    #[test]
    fn sa_round_trip() {
        let sa = Sa {
            proposals: vec![Proposal {
                number: 1,
                protocol: protocol::ESP,
                spi: vec![0xde, 0xad, 0xbe, 0xef],
                transforms: vec![
                    Transform {
                        number: 1,
                        id: 12,
                        attrs: vec![Attribute::basic(4, 3), Attribute::basic(6, 256)],
                    },
                    Transform {
                        number: 2,
                        id: 20,
                        attrs: vec![Attribute::basic(6, 128)],
                    },
                ],
            }],
        };
        let raw = sa.encode();
        assert_eq!(Sa::parse(&raw).unwrap(), sa);
        let mut other_doi = raw.clone();
        other_doi[3] = 2;
        assert!(Sa::parse(&other_doi).is_err());
        assert!(Sa::parse(&raw[..raw.len() - 3]).is_err());
    }

    #[test]
    fn small_payloads_round_trip() {
        let id = Id {
            kind: id_type::FQDN,
            protocol: 17,
            port: 500,
            data: b"client.example.com".to_vec(),
        };
        assert_eq!(Id::parse(&id.encode()).unwrap(), id);
        let n = Notify {
            protocol: protocol::ISAKMP,
            spi: vec![7; 16],
            kind: notify::R_U_THERE,
            data: 5u32.to_be_bytes().to_vec(),
        };
        assert_eq!(Notify::parse(&n.encode()).unwrap(), n);
        let d = Delete {
            protocol: protocol::ESP,
            spis: vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]],
        };
        assert_eq!(Delete::parse(&d.encode()).unwrap(), d);
        assert!(Delete::parse(&d.encode()[..12]).is_err());
        let c = Cfg {
            kind: 1,
            id: 0x1234,
            attrs: vec![Attribute::variable(16521, Vec::new())],
        };
        assert_eq!(Cfg::parse(&c.encode()).unwrap(), c);
    }
}
