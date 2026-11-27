//! The IKEv1 initiator: aggressive mode with a pre-shared key, XAuth, mode-config, quick mode
//! (with PFS), dead-peer detection and rekeying.
//!
//! NAT traversal is always forced: our NAT-D payload describes an address we do not have, so
//! the gateway puts ESP in UDP port 4500 and we never need raw ESP sockets. Our socket is
//! ephemeral, which keeps us clear of the system's own IKE service and of FortiClient.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use polytunnel_esp::{Cipher, Integrity, Keys};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::cfg::{ModeConfig, XauthField, XauthPrompt, attr, cfg_type};
use super::config::{Config, EspCipher, EspProposal, Identity, IkeProposal, ModeConfigMode};
use super::keymat::{Material, Phase1};
use super::wire::{
    self, Attribute, Cfg, Chain, Delete, Header, Id, Notify, Payload, Proposal, Sa, Transform,
    exchange, find_attr, id_type, notify, payload, protocol,
};
use crate::dh::KeyPair;
use crate::prf::HashAlg;

/// Vendor IDs we send.
const VID_XAUTH: [u8; 8] = [0x09, 0x00, 0x26, 0x89, 0xdf, 0xd6, 0xb7, 0x12];
const VID_UNITY: [u8; 16] = [
    0x12, 0xf5, 0xf2, 0x8c, 0x45, 0x71, 0x68, 0xa9, 0x70, 0x2d, 0x9f, 0xe2, 0x74, 0xcc, 0x01, 0x00,
];
const VID_DPD: [u8; 16] = [
    0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01, 0x00,
];
const VID_NATT_RFC: [u8; 16] = [
    0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95, 0x45, 0x2f,
];
const VID_NATT_DRAFT: [u8; 16] = [
    0x90, 0xcb, 0x80, 0x91, 0x3e, 0xbb, 0x69, 0x6e, 0x08, 0x63, 0x81, 0xb5, 0xec, 0x42, 0x7b, 0x1f,
];

/// Phase-1 transform attributes (RFC 2409 appendix A).
mod ike_attr {
    pub const ENCRYPTION: u16 = 1;
    pub const HASH: u16 = 2;
    pub const AUTH: u16 = 3;
    pub const GROUP: u16 = 4;
    pub const LIFE_TYPE: u16 = 11;
    pub const LIFE_DURATION: u16 = 12;
    pub const KEY_LENGTH: u16 = 14;

    pub const ENC_AES_CBC: u16 = 7;
    pub const AUTH_PSK: u16 = 1;
    /// XAUTHInitPreShared.
    pub const AUTH_XAUTH_PSK: u16 = 65001;
    pub const SECONDS: u16 = 1;
    pub const KEY_IKE: u8 = 1;
}

/// Phase-2 (IPsec DOI) transform attributes (RFC 2407 section 4.5).
mod esp_attr {
    pub const LIFE_TYPE: u16 = 1;
    pub const LIFE_DURATION: u16 = 2;
    pub const GROUP: u16 = 3;
    pub const ENCAPSULATION: u16 = 4;
    pub const AUTH: u16 = 5;
    pub const KEY_LENGTH: u16 = 6;

    pub const SECONDS: u16 = 1;
    pub const KILOBYTES: u16 = 2;
    /// UDP-encapsulated tunnel (RFC 3947) and its draft-era value.
    pub const UDP_TUNNEL: u16 = 3;
    pub const UDP_TUNNEL_DRAFT: u16 = 61443;

    pub const ESP_AES_CBC: u8 = 12;
    pub const ESP_AES_GCM_16: u8 = 20;
}

/// Retransmission delays for our requests; after the last one the gateway is declared gone.
const RETRANSMIT: [Duration; 5] = [
    Duration::from_secs(2),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(8),
];
const DPD_RETRY: Duration = Duration::from_secs(5);
const DPD_TRIES: u32 = 5;
/// How long a replaced SA keeps accepting traffic.
const RETIRE_AFTER: Duration = Duration::from_secs(20);
/// Push mode: how long to wait for the gateway's SET before asking.
const PUSH_WAIT: Duration = Duration::from_secs(4);
const NONCE_LEN: usize = 32;

/// What the caller must do.
#[derive(Debug)]
pub enum Output {
    /// Send an IKE message to the gateway: to its NAT-T port (4500, after the four-byte
    /// non-ESP marker) when `natt`, else to the IKE port (500).
    Send { natt: bool, message: Vec<u8> },
    /// The gateway wants more XAuth input; reply with [`Initiator::answer`].
    Prompt(XauthPrompt),
    /// Our address, DNS servers and split networks.
    Configured(ModeConfig),
    /// A pair of ESP SAs is ready (the first, or a rekeyed one): send with it from now on.
    ChildSa(ChildSa),
    /// Stop accepting packets for this inbound SPI.
    Retire { inbound_spi: u32 },
    /// The session is over. `retry`: a fresh connection may well succeed (the gateway went
    /// away or the session expired); otherwise it was refused (wrong key, password, ...).
    Closed { reason: String, retry: bool },
}

/// One ESP SA in each direction.
#[derive(Debug)]
pub struct ChildSa {
    pub inbound_spi: u32,
    pub inbound: Keys,
    pub outbound_spi: u32,
    pub outbound: Keys,
    pub proposal: EspProposal,
    pub lifetime: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    New,
    AggressiveSent,
    /// Phase 1 is up; XAuth is running (or about to).
    Authenticating,
    ModeConfig,
    Quick,
    Established,
    Closed,
}

struct Retransmit {
    message: Vec<u8>,
    natt: bool,
    next: Instant,
    tries: usize,
    what: &'static str,
}

struct PendingXauth {
    mid: u32,
    id: u16,
    xauth_type: Option<u16>,
    fields: Vec<XauthField>,
}

/// Our quick mode in flight.
struct Quick {
    mid: u32,
    spi: u32,
    ni: Vec<u8>,
    dh: Option<KeyPair>,
}

/// The gateway's quick mode in flight (we answered its first message).
struct PeerQuick {
    mid: u32,
    spi: u32,
    peer_spi: u32,
    proposal: EspProposal,
    lifetime: Duration,
    ni: Vec<u8>,
    nr: Vec<u8>,
    gqm: Option<Zeroizing<Vec<u8>>>,
}

struct Child {
    inbound_spi: u32,
    rekey_at: Instant,
}

struct DpdWait {
    seq: u32,
    sent: Instant,
    tries: u32,
}

pub struct Initiator {
    config: Config,
    state: State,
    cky_i: [u8; 8],
    cky_r: [u8; 8],
    // Phase 1.
    dh: Option<KeyPair>,
    ni: Vec<u8>,
    sai_b: Vec<u8>,
    idii_b: Vec<u8>,
    p1: Option<Phase1>,
    /// NAT-D payload type and UDP tunnel mode value, from the NAT-T flavour the gateway speaks.
    nat_d: u8,
    encapsulation: u16,
    peer_dpd: bool,
    last_msg2: Vec<u8>,
    msg3: Vec<u8>,
    ike_expires: Option<Instant>,
    // Exchanges.
    retransmit: Option<Retransmit>,
    /// Requests from the gateway we answered: (message ID, raw request, our reply).
    answered: VecDeque<(u32, Vec<u8>, Vec<u8>)>,
    xauth: Option<PendingXauth>,
    xauth_rounds: u32,
    modecfg: Option<(u32, u16)>,
    push_deadline: Option<Instant>,
    /// Our address from mode-config (the quick-mode selector).
    assigned: Option<Ipv4Addr>,
    quick: Option<Quick>,
    peer_quick: Option<PeerQuick>,
    child: Option<Child>,
    retiring: Vec<(u32, Instant)>,
    dpd_seq: u32,
    dpd_wait: Option<DpdWait>,
    last_heard: Instant,
    out: Vec<Output>,
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("the system random number generator failed");
    b
}

fn random_mid() -> u32 {
    loop {
        let v = u32::from_be_bytes(random());
        if v != 0 {
            return v;
        }
    }
}

fn random_spi() -> u32 {
    loop {
        let v = u32::from_be_bytes(random());
        // SPIs below 256 are reserved.
        if v >= 256 {
            return v;
        }
    }
}

fn hash_id(h: HashAlg) -> u16 {
    match h {
        HashAlg::Md5 => 1,
        HashAlg::Sha1 => 2,
        HashAlg::Sha256 => 4,
        HashAlg::Sha384 => 5,
        HashAlg::Sha512 => 6,
    }
}

fn esp_auth_id(i: Integrity) -> Option<u16> {
    match i {
        Integrity::None => None,
        Integrity::HmacSha1_96 => Some(2),
        Integrity::HmacSha256_128 => Some(5),
        Integrity::HmacSha384_192 => Some(6),
        Integrity::HmacSha512_256 => Some(7),
    }
}

fn secs(d: Duration) -> u32 {
    u32::try_from(d.as_secs()).unwrap_or(u32::MAX)
}

fn bits(key_len: usize) -> u16 {
    u16::try_from(key_len * 8).expect("small key")
}

/// The lifetime in seconds from life type/duration attribute pairs, if any.
fn lifetime_secs(attrs: &[Attribute], life_type: u16, life_duration: u16) -> Option<Duration> {
    let mut seconds = None;
    let mut current_type = 0;
    for a in attrs {
        if a.kind == life_type {
            current_type = a.as_u32();
        } else if a.kind == life_duration && current_type == u32::from(esp_attr::SECONDS) {
            seconds = Some(Duration::from_secs(u64::from(a.as_u32())));
        }
    }
    seconds
}

fn describe_error(kind: u16, phase: &str) -> String {
    match kind {
        notify::NO_PROPOSAL_CHOSEN => format!(
            "the gateway accepted none of the offered {phase} proposals; check the encryption, \
             hash and Diffie-Hellman group settings"
        ),
        notify::INVALID_ID_INFORMATION => {
            "the gateway did not accept our identity; check the profile's local ID (peer ID)".into()
        }
        notify::AUTHENTICATION_FAILED | notify::INVALID_HASH_INFORMATION => {
            "authentication failed; check the pre-shared key".into()
        }
        notify::PAYLOAD_MALFORMED | notify::INVALID_PAYLOAD_TYPE => {
            "the gateway could not parse our message".into()
        }
        notify::INVALID_KEY_INFORMATION => "the gateway rejected our key exchange".into(),
        _ => format!("the gateway reported IKE error {kind}"),
    }
}

impl Initiator {
    pub fn new(config: Config, now: Instant) -> Result<Self, String> {
        config.validate()?;
        let mut cky_i: [u8; 8] = random();
        if cky_i == [0; 8] {
            cky_i[7] = 1;
        }
        Ok(Self {
            config,
            state: State::New,
            cky_i,
            cky_r: [0; 8],
            dh: None,
            ni: Vec::new(),
            sai_b: Vec::new(),
            idii_b: Vec::new(),
            p1: None,
            nat_d: payload::NAT_D,
            encapsulation: esp_attr::UDP_TUNNEL,
            peer_dpd: false,
            last_msg2: Vec::new(),
            msg3: Vec::new(),
            ike_expires: None,
            retransmit: None,
            answered: VecDeque::new(),
            xauth: None,
            xauth_rounds: 0,
            modecfg: None,
            push_deadline: None,
            assigned: None,
            quick: None,
            peer_quick: None,
            child: None,
            retiring: Vec::new(),
            dpd_seq: u32::from_be_bytes(random()) & 0x7fff_ffff,
            dpd_wait: None,
            last_heard: now,
            out: Vec::new(),
        })
    }

    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Sends the first aggressive-mode message.
    pub fn start(&mut self, now: Instant) -> Vec<Output> {
        if self.state == State::New
            && let Err(reason) = self.send_msg1(now)
        {
            self.fail(reason, false);
        }
        self.drain()
    }

    /// Handles a datagram from the gateway (IKE only: the caller strips the non-ESP marker).
    pub fn receive(&mut self, now: Instant, data: &[u8]) -> Vec<Output> {
        if self.state != State::Closed
            && let Err(reason) = self.dispatch(now, data)
        {
            self.fail(reason, false);
        }
        self.drain()
    }

    /// Answers the pending XAuth prompt, one value per requested field.
    pub fn answer(&mut self, values: Vec<Zeroizing<String>>) -> Vec<Output> {
        if let Some(pending) = self.xauth.take() {
            let mut attrs = Vec::new();
            if let Some(t) = pending.xauth_type {
                attrs.push(Attribute::basic(attr::XAUTH_TYPE, t));
            }
            for (field, value) in pending.fields.iter().zip(values.iter()) {
                attrs.push(Attribute::variable(field.attr(), value.as_bytes().to_vec()));
            }
            self.send_cfg_reply(pending.mid, pending.id, cfg_type::REPLY, attrs);
        }
        self.drain()
    }

    /// Note that ESP traffic arrived: the gateway is alive (no DPD needed).
    pub fn note_alive(&mut self, now: Instant) {
        self.last_heard = now;
        self.dpd_wait = None;
    }

    /// Timers: retransmissions, DPD, rekeying, retiring SAs, lifetime. Call about once a second.
    pub fn poll(&mut self, now: Instant) -> Vec<Output> {
        if self.state == State::Closed {
            return self.drain();
        }
        if let Some(r) = &mut self.retransmit
            && now >= r.next
        {
            if r.tries >= RETRANSMIT.len() {
                let what = r.what;
                self.fail(format!("the gateway stopped answering ({what})"), true);
                return self.drain();
            }
            r.next = now + RETRANSMIT[r.tries];
            r.tries += 1;
            let (natt, message) = (r.natt, r.message.clone());
            self.out.push(Output::Send { natt, message });
        }
        if self.push_deadline.is_some_and(|d| now >= d) {
            self.push_deadline = None;
            self.request_mode_config(now);
        }
        if self.ike_expires.is_some_and(|t| now >= t) {
            self.fail("the IKE session reached its lifetime".into(), true);
            return self.drain();
        }
        if self.state == State::Established {
            self.poll_dpd(now);
            if self.state == State::Closed {
                return self.drain();
            }
            if self.quick.is_none()
                && self.peer_quick.is_none()
                && self.child.as_ref().is_some_and(|c| now >= c.rekey_at)
                && let Err(reason) = self.start_quick(now)
            {
                self.fail(reason, true);
            }
        }
        let (due, later): (Vec<_>, Vec<_>) = self.retiring.drain(..).partition(|(_, t)| now >= *t);
        self.retiring = later;
        for (spi, _) in due {
            self.send_delete(protocol::ESP, spi.to_be_bytes().to_vec());
            self.out.push(Output::Retire { inbound_spi: spi });
        }
        self.drain()
    }

    /// Ends the session: deletes the ESP SAs and the ISAKMP SA at the gateway.
    pub fn close(&mut self) -> Vec<Output> {
        if self.state != State::Closed && self.p1.is_some() {
            let mut spis: Vec<u32> = self.retiring.iter().map(|(spi, _)| *spi).collect();
            spis.extend(self.child.as_ref().map(|c| c.inbound_spi));
            for spi in spis {
                self.send_delete(protocol::ESP, spi.to_be_bytes().to_vec());
            }
            let cookies = [self.cky_i, self.cky_r].concat();
            self.send_delete(protocol::ISAKMP, cookies);
        }
        self.state = State::Closed;
        self.retransmit = None;
        self.drain()
    }

    fn drain(&mut self) -> Vec<Output> {
        std::mem::take(&mut self.out)
    }

    fn fail(&mut self, reason: String, retry: bool) {
        self.state = State::Closed;
        self.retransmit = None;
        self.out.push(Output::Closed { reason, retry });
    }

    fn send(&mut self, natt: bool, message: Vec<u8>) {
        self.out.push(Output::Send { natt, message });
    }

    fn send_tracked(&mut self, now: Instant, message: Vec<u8>, what: &'static str) {
        self.retransmit = Some(Retransmit {
            message: message.clone(),
            natt: true,
            next: now + RETRANSMIT[0],
            tries: 1,
            what,
        });
        self.send(true, message);
    }

    fn header(&self, exchange: u8, mid: u32) -> Header {
        Header {
            cky_i: self.cky_i,
            cky_r: self.cky_r,
            next: payload::NONE,
            exchange,
            flags: 0,
            mid,
            len: 0,
        }
    }

    fn p1(&self) -> &Phase1 {
        self.p1.as_ref().expect("phase 1 is up")
    }

    /// An encrypted message whose first payload is HASH = prf(SKEYID_a, M-ID | prefix | rest).
    fn protected(
        &mut self,
        exchange: u8,
        mid: u32,
        prefix: &[&[u8]],
        payloads: &[Payload],
    ) -> Vec<u8> {
        let rest = wire::encode_chain(payloads);
        let mid_b = mid.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![&mid_b];
        parts.extend_from_slice(prefix);
        parts.push(&rest);
        let hash = self.p1().prf_a(&parts);
        let mut chain = vec![payloads.first().map_or(payload::NONE, |p| p.kind), 0];
        chain.extend_from_slice(&u16::try_from(hash.len() + 4).expect("short").to_be_bytes());
        chain.extend_from_slice(&hash);
        chain.extend_from_slice(&rest);
        let header = Header {
            next: payload::HASH,
            ..self.header(exchange, mid)
        };
        self.p1
            .as_mut()
            .expect("phase 1 is up")
            .encrypt(header, &chain)
    }

    /// Whether an encrypted message's HASH = prf(SKEYID_a, M-ID | prefix | rest) holds.
    fn hash_ok(&self, mid: u32, prefix: &[&[u8]], chain: &Chain, plain: &[u8]) -> bool {
        let Some(first) = chain.payloads.first().filter(|p| p.kind == payload::HASH) else {
            return false;
        };
        let mid_b = mid.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![&mid_b];
        parts.extend_from_slice(prefix);
        parts.push(chain.after_first(plain));
        let want = self.p1().prf_a(&parts);
        bool::from(want.ct_eq(&first.body))
    }

    fn remember_answer(&mut self, mid: u32, request: &[u8], reply: Vec<u8>) {
        if self.answered.len() >= 16 {
            self.answered.pop_front();
        }
        self.answered.push_back((mid, request.to_vec(), reply));
    }

    // -------------------------------------------------------------------------- phase 1

    fn ike_sa(&self) -> Sa {
        let auth = if self.config.xauth.is_some() {
            ike_attr::AUTH_XAUTH_PSK
        } else {
            ike_attr::AUTH_PSK
        };
        let transforms = self
            .config
            .ike
            .iter()
            .enumerate()
            .map(|(i, p)| Transform {
                number: u8::try_from(i + 1).expect("few proposals"),
                id: ike_attr::KEY_IKE,
                attrs: vec![
                    Attribute::basic(ike_attr::ENCRYPTION, ike_attr::ENC_AES_CBC),
                    Attribute::basic(ike_attr::KEY_LENGTH, bits(p.key_len)),
                    Attribute::basic(ike_attr::HASH, hash_id(p.hash)),
                    Attribute::basic(ike_attr::AUTH, auth),
                    Attribute::basic(ike_attr::GROUP, p.group.id()),
                    Attribute::basic(ike_attr::LIFE_TYPE, ike_attr::SECONDS),
                    Attribute::number(ike_attr::LIFE_DURATION, secs(self.config.ike_lifetime)),
                ],
            })
            .collect();
        Sa {
            proposals: vec![Proposal {
                number: 1,
                protocol: protocol::ISAKMP,
                spi: Vec::new(),
                transforms,
            }],
        }
    }

    fn local_id(&self) -> Id {
        match (&self.config.local_id, self.config.local.ip()) {
            (Some(id), _) => id.to_id(),
            (None, IpAddr::V4(ip)) => Identity::Ipv4(ip).to_id(),
            (None, IpAddr::V6(_)) => Identity::Ipv4(Ipv4Addr::UNSPECIFIED).to_id(),
        }
    }

    fn send_msg1(&mut self, now: Instant) -> Result<(), String> {
        let group = self.config.ike[0].group;
        let dh = KeyPair::generate(group).map_err(|e| e.to_string())?;
        self.ni = random::<NONCE_LEN>().to_vec();
        self.sai_b = self.ike_sa().encode();
        self.idii_b = self.local_id().encode();
        let mut payloads = vec![
            Payload::new(payload::SA, self.sai_b.clone()),
            Payload::new(payload::KE, dh.public().to_vec()),
            Payload::new(payload::NONCE, self.ni.clone()),
            Payload::new(payload::ID, self.idii_b.clone()),
        ];
        if self.config.xauth.is_some() {
            payloads.push(Payload::new(payload::VENDOR, VID_XAUTH.to_vec()));
        }
        for vid in [VID_UNITY, VID_DPD, VID_NATT_RFC, VID_NATT_DRAFT] {
            payloads.push(Payload::new(payload::VENDOR, vid.to_vec()));
        }
        let msg = wire::message(self.header(exchange::AGGRESSIVE, 0), &payloads);
        self.dh = Some(dh);
        self.state = State::AggressiveSent;
        self.retransmit = Some(Retransmit {
            message: msg.clone(),
            natt: false,
            next: now + RETRANSMIT[0],
            tries: 1,
            what: "IKE phase 1",
        });
        self.send(false, msg);
        Ok(())
    }

    fn dispatch(&mut self, now: Instant, data: &[u8]) -> Result<(), String> {
        let Ok((header, body)) = Header::parse(data) else {
            return Ok(()); // not IKE, or mangled: ignore
        };
        if header.cky_i != self.cky_i {
            return Ok(());
        }
        let raw = &data[..usize::try_from(header.len).unwrap_or(data.len())];
        if !header.encrypted() {
            return match header.exchange {
                exchange::AGGRESSIVE if self.state == State::AggressiveSent => {
                    self.on_msg2(now, &header, body, raw)
                }
                exchange::AGGRESSIVE if raw == self.last_msg2.as_slice() => {
                    // The gateway missed our third message.
                    let msg3 = self.msg3.clone();
                    self.send(true, msg3);
                    Ok(())
                }
                exchange::INFORMATIONAL if self.p1.is_none() => {
                    // Before phase 1 completes, errors come unencrypted.
                    let chain = Chain::parse(header.next, body).map_err(|e| e.to_string())?;
                    for n in chain
                        .all(payload::NOTIFY)
                        .filter_map(|b| Notify::parse(b).ok())
                    {
                        if n.kind <= notify::ERROR_MAX {
                            return Err(describe_error(n.kind, "IKE"));
                        }
                    }
                    Ok(())
                }
                _ => Ok(()),
            };
        }
        if self.p1.is_none() || header.cky_r != self.cky_r {
            return Ok(());
        }
        if let Some((_, _, reply)) = self
            .answered
            .iter()
            .find(|(mid, request, _)| *mid == header.mid && request.as_slice() == raw)
        {
            // A retransmitted request: repeat our answer (none yet while the user types).
            if !reply.is_empty() {
                let reply = reply.clone();
                self.send(true, reply);
            }
            return Ok(());
        }
        let Ok((plain, next_iv)) = self.p1().decrypt(&header, body) else {
            return Ok(());
        };
        let Ok(chain) = Chain::parse(header.next, &plain) else {
            return Ok(());
        };
        match header.exchange {
            exchange::TRANSACTION => {
                if !self.hash_ok(header.mid, &[], &chain, &plain) {
                    return Ok(());
                }
                self.authenticated(now, header.mid, next_iv);
                self.on_transaction(now, header.mid, &chain, raw)
            }
            exchange::INFORMATIONAL => {
                if !self.hash_ok(header.mid, &[], &chain, &plain) {
                    return Ok(());
                }
                self.last_heard = now;
                self.on_informational(now, &chain);
                Ok(())
            }
            exchange::QUICK => self.on_quick(now, &header, &chain, &plain, next_iv, raw),
            _ => Ok(()),
        }
    }

    /// Commits a verified message's IV and notes the gateway is alive.
    fn authenticated(&mut self, now: Instant, mid: u32, next_iv: Vec<u8>) {
        self.p1
            .as_mut()
            .expect("phase 1 is up")
            .set_iv(mid, next_iv);
        self.last_heard = now;
    }

    fn match_ike(&self, sa: &Sa) -> Result<(IkeProposal, Option<Duration>), String> {
        let transform = sa
            .proposals
            .first()
            .and_then(|p| p.transforms.first())
            .ok_or("the gateway chose no IKE proposal")?;
        let get = |kind| find_attr(&transform.attrs, kind).map(Attribute::as_u32);
        let chosen = self.config.ike.iter().find(|p| {
            get(ike_attr::ENCRYPTION) == Some(u32::from(ike_attr::ENC_AES_CBC))
                && get(ike_attr::KEY_LENGTH) == Some(u32::from(bits(p.key_len)))
                && get(ike_attr::HASH) == Some(u32::from(hash_id(p.hash)))
                && get(ike_attr::GROUP) == Some(u32::from(p.group.id()))
        });
        let chosen = chosen.ok_or("the gateway chose an IKE proposal we did not offer")?;
        let lifetime = lifetime_secs(
            &transform.attrs,
            ike_attr::LIFE_TYPE,
            ike_attr::LIFE_DURATION,
        );
        Ok((*chosen, lifetime))
    }

    fn on_msg2(
        &mut self,
        now: Instant,
        header: &Header,
        body: &[u8],
        raw: &[u8],
    ) -> Result<(), String> {
        let chain = Chain::parse(header.next, body).map_err(|e| e.to_string())?;
        for n in chain
            .all(payload::NOTIFY)
            .filter_map(|b| Notify::parse(b).ok())
        {
            if n.kind <= notify::ERROR_MAX {
                return Err(describe_error(n.kind, "IKE"));
            }
        }
        let missing = |what: &str| format!("the gateway's reply has no {what}");
        let sa = Sa::parse(chain.find(payload::SA).ok_or_else(|| missing("SA"))?)
            .map_err(|e| e.to_string())?;
        let (chosen, their_lifetime) = self.match_ike(&sa)?;
        let ke = chain
            .find(payload::KE)
            .ok_or_else(|| missing("key exchange"))?;
        let nr = chain.find(payload::NONCE).ok_or_else(|| missing("nonce"))?;
        let idir = chain.find(payload::ID).ok_or_else(|| missing("identity"))?;
        let hash_r = chain.find(payload::HASH).ok_or_else(|| missing("hash"))?;
        if !(8..=256).contains(&nr.len()) {
            return Err("the gateway's nonce has an invalid length".into());
        }
        let mut natt = None;
        for vid in chain.all(payload::VENDOR) {
            if vid == VID_NATT_RFC {
                natt = Some((payload::NAT_D, esp_attr::UDP_TUNNEL));
            } else if vid == VID_NATT_DRAFT && natt.is_none() {
                natt = Some((payload::NAT_D_DRAFT, esp_attr::UDP_TUNNEL_DRAFT));
            } else if vid.len() >= 14 && vid[..14] == VID_DPD[..14] {
                self.peer_dpd = true;
            }
        }
        let (nat_d, encapsulation) = natt.ok_or(
            "the gateway does not offer NAT traversal, which Polytunnel needs for IPsec over UDP",
        )?;
        self.nat_d = nat_d;
        self.encapsulation = encapsulation;
        self.cky_r = header.cky_r;
        let dh = self.dh.take().expect("sent with msg1");
        let gxy = dh.agree(ke).map_err(|e| e.to_string())?;
        let material = Material {
            psk: &self.config.psk,
            ni_b: &self.ni,
            nr_b: nr,
            gxy: &gxy,
            gxi: dh.public(),
            gxr: ke,
            cky_i: self.cky_i,
            cky_r: self.cky_r,
        };
        let p1 = Phase1::derive(chosen.hash, chosen.key_len, &material);
        if !bool::from(p1.hash_r(&material, &self.sai_b, idir).ct_eq(hash_r)) {
            return Err(
                "the gateway's proof did not verify: the pre-shared key is probably wrong".into(),
            );
        }
        let hash_i = p1.hash_i(&material, &self.sai_b, &self.idii_b);
        let remote = self.config.remote;
        let nat_remote = nat_hash(chosen.hash, self.cky_i, self.cky_r, remote);
        // Forced NAT traversal: describe an address we do not have.
        let fake = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(random::<4>())),
            u16::from_be_bytes(random()),
        );
        let nat_local = nat_hash(chosen.hash, self.cky_i, self.cky_r, fake);
        let msg3 = wire::message(
            self.header(exchange::AGGRESSIVE, 0),
            &[
                Payload::new(payload::HASH, hash_i),
                Payload::new(nat_d, nat_remote),
                Payload::new(nat_d, nat_local),
            ],
        );
        self.p1 = Some(p1);
        self.last_msg2 = raw.to_vec();
        self.msg3 = msg3.clone();
        let lifetime = their_lifetime.map_or(self.config.ike_lifetime, |t| {
            t.min(self.config.ike_lifetime)
        });
        self.ike_expires = Some(now + lifetime);
        self.state = State::Authenticating;
        self.last_heard = now;
        self.retransmit = None;
        self.send(true, msg3.clone());
        // Tell the gateway to drop any session left from a previous run.
        let cookies = [self.cky_i, self.cky_r].concat();
        self.send_informational(&Notify {
            protocol: protocol::ISAKMP,
            spi: cookies,
            kind: notify::INITIAL_CONTACT,
            data: Vec::new(),
        });
        if self.config.xauth.is_some() {
            // Wait for the gateway's XAuth request; repeat message 3 if it does not come.
            self.retransmit = Some(Retransmit {
                message: msg3,
                natt: true,
                next: now + RETRANSMIT[0],
                tries: 1,
                what: "XAuth",
            });
        } else {
            self.after_auth(now);
        }
        Ok(())
    }

    // -------------------------------------------------------------------------- XAuth, mode-config

    fn send_cfg_reply(&mut self, mid: u32, id: u16, kind: u8, attrs: Vec<Attribute>) {
        let cfg = Cfg { kind, id, attrs };
        let msg = self.protected(
            exchange::TRANSACTION,
            mid,
            &[],
            &[Payload::new(payload::ATTRIBUTES, cfg.encode())],
        );
        if let Some(entry) = self.answered.iter_mut().rev().find(|(m, _, _)| *m == mid) {
            entry.2 = msg.clone();
        }
        // Our reply ends this exchange.
        self.p1.as_mut().expect("phase 1 is up").forget(mid);
        self.send(true, msg);
    }

    fn on_transaction(
        &mut self,
        now: Instant,
        mid: u32,
        chain: &Chain,
        raw: &[u8],
    ) -> Result<(), String> {
        let Some(cfg) = chain
            .find(payload::ATTRIBUTES)
            .and_then(|b| Cfg::parse(b).ok())
        else {
            return Ok(());
        };
        match cfg.kind {
            cfg_type::REQUEST => {
                if self.xauth.as_ref().is_some_and(|x| x.mid == mid) {
                    return Ok(()); // still waiting for the user
                }
                if self.state == State::Authenticating
                    && matches!(self.retransmit, Some(Retransmit { what: "XAuth", .. }))
                {
                    self.retransmit = None;
                }
                self.remember_answer(mid, raw, Vec::new());
                let prompt = XauthPrompt::from_request(&cfg.attrs);
                let xauth_type = find_attr(&cfg.attrs, attr::XAUTH_TYPE)
                    .map(|a| u16::try_from(a.as_u32()).unwrap_or(0));
                if prompt.fields.is_empty() {
                    // Not XAuth: answer with nothing.
                    self.send_cfg_reply(mid, cfg.id, cfg_type::REPLY, Vec::new());
                    return Ok(());
                }
                self.xauth_rounds += 1;
                let automatic = self.xauth_rounds == 1
                    && prompt
                        .fields
                        .iter()
                        .all(|f| matches!(f, XauthField::Name | XauthField::Password));
                match (&self.config.xauth, automatic) {
                    (Some(creds), true) => {
                        let mut attrs = Vec::new();
                        if let Some(t) = xauth_type {
                            attrs.push(Attribute::basic(attr::XAUTH_TYPE, t));
                        }
                        for f in &prompt.fields {
                            let value = match f {
                                XauthField::Name => creds.username.as_bytes().to_vec(),
                                _ => creds.password.as_bytes().to_vec(),
                            };
                            attrs.push(Attribute::variable(f.attr(), value));
                        }
                        self.send_cfg_reply(mid, cfg.id, cfg_type::REPLY, attrs);
                    }
                    _ => {
                        self.xauth = Some(PendingXauth {
                            mid,
                            id: cfg.id,
                            xauth_type,
                            fields: prompt.fields.clone(),
                        });
                        self.out.push(Output::Prompt(prompt));
                    }
                }
                Ok(())
            }
            cfg_type::SET => {
                self.remember_answer(mid, raw, Vec::new());
                if let Some(status) = find_attr(&cfg.attrs, attr::XAUTH_STATUS) {
                    let ok = status.as_u32() == 1;
                    self.send_cfg_reply(
                        mid,
                        cfg.id,
                        cfg_type::ACK,
                        vec![Attribute::basic(attr::XAUTH_STATUS, u16::from(ok))],
                    );
                    if !ok {
                        return Err(
                            "the gateway did not accept the username, password or code".into()
                        );
                    }
                    self.retransmit = None;
                    self.xauth = None;
                    self.after_auth(now);
                } else if ModeConfig::present(&cfg.attrs) {
                    let ack = cfg
                        .attrs
                        .iter()
                        .map(|a| Attribute::variable(a.kind, Vec::new()))
                        .collect();
                    self.send_cfg_reply(mid, cfg.id, cfg_type::ACK, ack);
                    self.configured(now, ModeConfig::parse(&cfg.attrs))?;
                } else {
                    self.send_cfg_reply(mid, cfg.id, cfg_type::ACK, Vec::new());
                }
                Ok(())
            }
            cfg_type::REPLY if self.modecfg.is_some_and(|(m, _)| m == mid) => {
                self.retransmit = None;
                self.configured(now, ModeConfig::parse(&cfg.attrs))
            }
            _ => Ok(()),
        }
    }

    /// XAuth succeeded (or was not used): get our address.
    fn after_auth(&mut self, now: Instant) {
        if self.state != State::Authenticating {
            return;
        }
        self.state = State::ModeConfig;
        match self.config.mode_config {
            ModeConfigMode::Pull => self.request_mode_config(now),
            ModeConfigMode::Push => self.push_deadline = Some(now + PUSH_WAIT),
        }
    }

    fn request_mode_config(&mut self, now: Instant) {
        if self.state != State::ModeConfig || self.modecfg.is_some() {
            return;
        }
        let mid = random_mid();
        let id = u16::from_be_bytes(random());
        let cfg = Cfg {
            kind: cfg_type::REQUEST,
            id,
            attrs: ModeConfig::request(&self.config.client_version),
        };
        let msg = self.protected(
            exchange::TRANSACTION,
            mid,
            &[],
            &[Payload::new(payload::ATTRIBUTES, cfg.encode())],
        );
        self.modecfg = Some((mid, id));
        self.send_tracked(now, msg, "mode-config");
    }

    fn configured(&mut self, now: Instant, mc: ModeConfig) -> Result<(), String> {
        if self.state != State::ModeConfig {
            return Ok(()); // a repeated SET: already configured
        }
        if mc.address.is_none() {
            return Err("the gateway assigned no IPv4 address (mode-config)".into());
        }
        self.push_deadline = None;
        // A pull request still pending is answered: the settings are here.
        if let Some((mid, _)) = self.modecfg.take() {
            self.p1.as_mut().expect("phase 1 is up").forget(mid);
        }
        self.out.push(Output::Configured(mc.clone()));
        self.assigned = mc.address;
        self.start_quick(now)
    }

    // -------------------------------------------------------------------------- quick mode

    fn esp_transform(&self, number: usize, p: &EspProposal) -> Transform {
        let mut attrs = vec![
            Attribute::basic(esp_attr::LIFE_TYPE, esp_attr::SECONDS),
            Attribute::number(esp_attr::LIFE_DURATION, secs(self.config.esp_lifetime)),
        ];
        if let Some(kb) = self.config.esp_lifetime_kb {
            attrs.push(Attribute::basic(esp_attr::LIFE_TYPE, esp_attr::KILOBYTES));
            attrs.push(Attribute::number(esp_attr::LIFE_DURATION, kb));
        }
        if let Some(group) = self.config.pfs {
            attrs.push(Attribute::basic(esp_attr::GROUP, group.id()));
        }
        attrs.push(Attribute::basic(
            esp_attr::ENCAPSULATION,
            self.encapsulation,
        ));
        if let Some(auth) = esp_auth_id(p.integrity) {
            attrs.push(Attribute::basic(esp_attr::AUTH, auth));
        }
        attrs.push(Attribute::basic(esp_attr::KEY_LENGTH, bits(p.key_len())));
        let id = match p.cipher {
            EspCipher::AesCbc { .. } => esp_attr::ESP_AES_CBC,
            EspCipher::AesGcm16 { .. } => esp_attr::ESP_AES_GCM_16,
        };
        Transform {
            number: u8::try_from(number).expect("few proposals"),
            id,
            attrs,
        }
    }

    /// Which of our ESP proposals a transform is, if any.
    fn match_esp(&self, t: &Transform) -> Option<EspProposal> {
        let get = |kind| find_attr(&t.attrs, kind).map(Attribute::as_u32);
        let group_ok = match self.config.pfs {
            Some(g) => get(esp_attr::GROUP) == Some(u32::from(g.id())),
            None => get(esp_attr::GROUP).is_none(),
        };
        let encap = get(esp_attr::ENCAPSULATION);
        let encap_ok = encap == Some(u32::from(esp_attr::UDP_TUNNEL))
            || encap == Some(u32::from(esp_attr::UDP_TUNNEL_DRAFT));
        if !group_ok || !encap_ok {
            return None;
        }
        self.config.esp.iter().copied().find(|p| {
            let id_ok = match p.cipher {
                EspCipher::AesCbc { .. } => t.id == esp_attr::ESP_AES_CBC,
                EspCipher::AesGcm16 { .. } => t.id == esp_attr::ESP_AES_GCM_16,
            };
            id_ok
                && get(esp_attr::KEY_LENGTH) == Some(u32::from(bits(p.key_len())))
                && get(esp_attr::AUTH) == esp_auth_id(p.integrity).map(u32::from)
        })
    }

    fn selectors(&self) -> (Id, Id) {
        let ours = Id {
            kind: id_type::IPV4_ADDR,
            protocol: 0,
            port: 0,
            data: self
                .assigned
                .unwrap_or(Ipv4Addr::UNSPECIFIED)
                .octets()
                .to_vec(),
        };
        let (net, len) = self.config.remote_network;
        let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
        let remote = Id {
            kind: id_type::IPV4_ADDR_SUBNET,
            protocol: 0,
            port: 0,
            data: [(u32::from(net) & mask).to_be_bytes(), mask.to_be_bytes()].concat(),
        };
        (ours, remote)
    }

    fn start_quick(&mut self, now: Instant) -> Result<(), String> {
        let mid = random_mid();
        let spi = random_spi();
        let ni = random::<NONCE_LEN>().to_vec();
        let dh = match self.config.pfs {
            Some(g) => Some(KeyPair::generate(g).map_err(|e| e.to_string())?),
            None => None,
        };
        let transforms = self
            .config
            .esp
            .iter()
            .enumerate()
            .map(|(i, p)| self.esp_transform(i + 1, p))
            .collect();
        let sa = Sa {
            proposals: vec![Proposal {
                number: 1,
                protocol: protocol::ESP,
                spi: spi.to_be_bytes().to_vec(),
                transforms,
            }],
        };
        let (idci, idcr) = self.selectors();
        let mut payloads = vec![
            Payload::new(payload::SA, sa.encode()),
            Payload::new(payload::NONCE, ni.clone()),
        ];
        if let Some(dh) = &dh {
            payloads.push(Payload::new(payload::KE, dh.public().to_vec()));
        }
        payloads.push(Payload::new(payload::ID, idci.encode()));
        payloads.push(Payload::new(payload::ID, idcr.encode()));
        let msg = self.protected(exchange::QUICK, mid, &[], &payloads);
        self.quick = Some(Quick { mid, spi, ni, dh });
        if self.state != State::Established {
            self.state = State::Quick;
        }
        self.send_tracked(now, msg, "IPsec SA negotiation");
        Ok(())
    }

    fn on_quick(
        &mut self,
        now: Instant,
        header: &Header,
        chain: &Chain,
        plain: &[u8],
        next_iv: Vec<u8>,
        raw: &[u8],
    ) -> Result<(), String> {
        let mid = header.mid;
        if self.quick.as_ref().is_some_and(|q| q.mid == mid) {
            let ni = self.quick.as_ref().expect("checked").ni.clone();
            if !self.hash_ok(mid, &[&ni], chain, plain) {
                return Ok(());
            }
            self.authenticated(now, mid, next_iv);
            return self.on_quick2(now, mid, chain, raw);
        }
        if let Some(pq) = self.peer_quick.as_ref().filter(|pq| pq.mid == mid) {
            // HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b), alone in the message.
            let want = self.p1().prf_a(&[&[0], &mid.to_be_bytes(), &pq.ni, &pq.nr]);
            let ok = chain
                .payloads
                .first()
                .is_some_and(|p| p.kind == payload::HASH && bool::from(want.ct_eq(&p.body)));
            if !ok {
                return Ok(());
            }
            let pq = self.peer_quick.take().expect("checked");
            self.p1.as_mut().expect("phase 1 is up").forget(mid);
            self.last_heard = now;
            return self.install(
                now,
                (pq.spi, pq.peer_spi),
                pq.proposal,
                pq.lifetime,
                (&pq.ni, &pq.nr),
                pq.gqm.as_deref().map(Vec::as_slice),
            );
        }
        if self.state == State::Established && self.peer_quick.is_none() {
            if !self.hash_ok(mid, &[], chain, plain) {
                return Ok(());
            }
            self.authenticated(now, mid, next_iv);
            self.on_peer_quick1(mid, chain, raw)?;
        }
        Ok(())
    }

    /// The gateway's answer to our quick mode.
    fn on_quick2(
        &mut self,
        now: Instant,
        mid: u32,
        chain: &Chain,
        raw: &[u8],
    ) -> Result<(), String> {
        for n in chain
            .all(payload::NOTIFY)
            .filter_map(|b| Notify::parse(b).ok())
        {
            if n.kind <= notify::ERROR_MAX {
                return Err(describe_error(n.kind, "ESP"));
            }
        }
        let quick = self.quick.take().expect("checked by the caller");
        let sa = chain
            .find(payload::SA)
            .and_then(|b| Sa::parse(b).ok())
            .ok_or("the gateway's quick-mode reply has no valid SA")?;
        let proposal = sa
            .proposals
            .first()
            .filter(|p| p.protocol == protocol::ESP && p.spi.len() == 4)
            .ok_or("the gateway's quick-mode reply has no ESP proposal")?;
        let transform = proposal
            .transforms
            .first()
            .ok_or("the gateway's quick-mode reply has no transform")?;
        let chosen = self
            .match_esp(transform)
            .ok_or("the gateway chose an ESP proposal we did not offer")?;
        let peer_spi = u32::from_be_bytes(proposal.spi[..4].try_into().expect("4 bytes"));
        let mut lifetime = self.config.esp_lifetime;
        if let Some(t) = lifetime_secs(
            &transform.attrs,
            esp_attr::LIFE_TYPE,
            esp_attr::LIFE_DURATION,
        ) {
            lifetime = lifetime.min(t);
        }
        for n in chain
            .all(payload::NOTIFY)
            .filter_map(|b| Notify::parse(b).ok())
        {
            if n.kind == notify::RESPONDER_LIFETIME
                && let Ok(attrs) = wire::parse_attributes(&n.data)
                && let Some(t) = lifetime_secs(&attrs, esp_attr::LIFE_TYPE, esp_attr::LIFE_DURATION)
            {
                lifetime = lifetime.min(t);
            }
        }
        let nr = chain
            .find(payload::NONCE)
            .ok_or("the gateway's quick-mode reply has no nonce")?
            .to_vec();
        let gqm = match &quick.dh {
            Some(dh) => {
                let ke = chain
                    .find(payload::KE)
                    .ok_or("the gateway did not use PFS, which the profile requires")?;
                Some(dh.agree(ke).map_err(|e| e.to_string())?)
            }
            None => None,
        };
        let hash3 = self.p1().prf_a(&[&[0], &mid.to_be_bytes(), &quick.ni, &nr]);
        let header = Header {
            next: payload::HASH,
            ..self.header(exchange::QUICK, mid)
        };
        let qm3 = self.p1.as_mut().expect("phase 1 is up").encrypt(
            header,
            &wire::encode_chain(&[Payload::new(payload::HASH, hash3)]),
        );
        self.p1.as_mut().expect("phase 1 is up").forget(mid);
        self.remember_answer(mid, raw, qm3.clone());
        self.retransmit = None;
        self.send(true, qm3);
        self.install(
            now,
            (quick.spi, peer_spi),
            chosen,
            lifetime,
            (&quick.ni, &nr),
            gqm.as_deref().map(Vec::as_slice),
        )
    }

    /// The gateway starts a quick mode (it rekeys): answer as the responder.
    fn on_peer_quick1(&mut self, mid: u32, chain: &Chain, raw: &[u8]) -> Result<(), String> {
        let Some(sa) = chain.find(payload::SA).and_then(|b| Sa::parse(b).ok()) else {
            return Ok(());
        };
        let Some(ni) = chain.find(payload::NONCE).map(<[u8]>::to_vec) else {
            return Ok(());
        };
        let mut pick = None;
        for p in sa
            .proposals
            .iter()
            .filter(|p| p.protocol == protocol::ESP && p.spi.len() == 4)
        {
            if let Some((t, chosen)) = p
                .transforms
                .iter()
                .find_map(|t| self.match_esp(t).map(|c| (t, c)))
            {
                pick = Some((p, t, chosen));
                break;
            }
        }
        let Some((proposal, transform, chosen)) = pick else {
            self.send_informational(&Notify {
                protocol: protocol::ESP,
                spi: Vec::new(),
                kind: notify::NO_PROPOSAL_CHOSEN,
                data: Vec::new(),
            });
            return Ok(());
        };
        let peer_spi = u32::from_be_bytes(proposal.spi[..4].try_into().expect("4 bytes"));
        let lifetime = lifetime_secs(
            &transform.attrs,
            esp_attr::LIFE_TYPE,
            esp_attr::LIFE_DURATION,
        )
        .map_or(self.config.esp_lifetime, |t| {
            t.min(self.config.esp_lifetime)
        });
        let (dh, gqm) = match (self.config.pfs, chain.find(payload::KE)) {
            (Some(g), Some(ke)) => {
                let dh = KeyPair::generate(g).map_err(|e| e.to_string())?;
                let gqm = dh.agree(ke).map_err(|e| e.to_string())?;
                (Some(dh), Some(gqm))
            }
            (None, None) => (None, None),
            _ => return Ok(()),
        };
        let spi = random_spi();
        let nr = random::<NONCE_LEN>().to_vec();
        let reply_sa = Sa {
            proposals: vec![Proposal {
                number: proposal.number,
                protocol: protocol::ESP,
                spi: spi.to_be_bytes().to_vec(),
                transforms: vec![transform.clone()],
            }],
        };
        let mut payloads = vec![
            Payload::new(payload::SA, reply_sa.encode()),
            Payload::new(payload::NONCE, nr.clone()),
        ];
        if let Some(dh) = &dh {
            payloads.push(Payload::new(payload::KE, dh.public().to_vec()));
        }
        for id in chain.all(payload::ID) {
            payloads.push(Payload::new(payload::ID, id.to_vec()));
        }
        let msg = self.protected(exchange::QUICK, mid, &[&ni], &payloads);
        self.remember_answer(mid, raw, msg.clone());
        self.send(true, msg);
        self.peer_quick = Some(PeerQuick {
            mid,
            spi,
            peer_spi,
            proposal: chosen,
            lifetime,
            ni,
            nr,
            gqm,
        });
        Ok(())
    }

    fn keys(
        &self,
        p: &EspProposal,
        spi: u32,
        nonces: (&[u8], &[u8]),
        gqm: Option<&[u8]>,
    ) -> Result<Keys, String> {
        let km = self.p1().keymat(
            gqm,
            protocol::ESP,
            &spi.to_be_bytes(),
            nonces,
            p.keymat_len(),
        );
        let keys = match p.cipher {
            EspCipher::AesCbc { key_len } => Keys::new(
                Cipher::AesCbc(km[..key_len].to_vec()),
                p.integrity,
                km[key_len..].to_vec(),
            ),
            EspCipher::AesGcm16 { key_len } => Keys::new(
                Cipher::AesGcm16 {
                    key: km[..key_len].to_vec(),
                    salt: km[key_len..key_len + 4].try_into().expect("4 bytes"),
                },
                Integrity::None,
                Vec::new(),
            ),
        };
        keys.map_err(|e| e.to_string())
    }

    /// Derives and announces a new SA pair. `spis`: (ours/inbound, theirs/outbound);
    /// `nonces`: (initiator's, responder's) of that quick mode.
    fn install(
        &mut self,
        now: Instant,
        spis: (u32, u32),
        proposal: EspProposal,
        lifetime: Duration,
        nonces: (&[u8], &[u8]),
        gqm: Option<&[u8]>,
    ) -> Result<(), String> {
        let (inbound_spi, outbound_spi) = spis;
        let inbound = self.keys(&proposal, inbound_spi, nonces, gqm)?;
        let outbound = self.keys(&proposal, outbound_spi, nonces, gqm)?;
        // Rekey with 10% of the lifetime left, minus up to 5% jitter.
        let margin = lifetime / 10 + lifetime / 20 * u32::from(random::<1>()[0]) / 255;
        let child = Child {
            inbound_spi,
            rekey_at: now + lifetime.saturating_sub(margin),
        };
        if let Some(old) = self.child.replace(child) {
            self.retiring.push((old.inbound_spi, now + RETIRE_AFTER));
        }
        self.state = State::Established;
        self.last_heard = now;
        self.out.push(Output::ChildSa(ChildSa {
            inbound_spi,
            inbound,
            outbound_spi,
            outbound,
            proposal,
            lifetime,
        }));
        Ok(())
    }

    // -------------------------------------------------------------------------- informational

    fn send_informational(&mut self, n: &Notify) {
        let mid = random_mid();
        let msg = self.protected(
            exchange::INFORMATIONAL,
            mid,
            &[],
            &[Payload::new(payload::NOTIFY, n.encode())],
        );
        self.p1.as_mut().expect("phase 1 is up").forget(mid);
        self.send(true, msg);
    }

    fn send_delete(&mut self, protocol: u8, spi: Vec<u8>) {
        let mid = random_mid();
        let d = Delete {
            protocol,
            spis: vec![spi],
        };
        let msg = self.protected(
            exchange::INFORMATIONAL,
            mid,
            &[],
            &[Payload::new(payload::DELETE, d.encode())],
        );
        self.p1.as_mut().expect("phase 1 is up").forget(mid);
        self.send(true, msg);
    }

    fn on_informational(&mut self, now: Instant, chain: &Chain) {
        let cookies = [self.cky_i, self.cky_r].concat();
        for n in chain
            .all(payload::NOTIFY)
            .filter_map(|b| Notify::parse(b).ok())
        {
            match n.kind {
                notify::R_U_THERE => {
                    self.send_informational(&Notify {
                        protocol: protocol::ISAKMP,
                        spi: cookies.clone(),
                        kind: notify::R_U_THERE_ACK,
                        data: n.data.clone(),
                    });
                }
                notify::R_U_THERE_ACK => {
                    if let Some(w) = &self.dpd_wait
                        && n.data == w.seq.to_be_bytes()
                    {
                        self.dpd_wait = None;
                    }
                }
                _ => {}
            }
        }
        for d in chain
            .all(payload::DELETE)
            .filter_map(|b| Delete::parse(b).ok())
        {
            if d.protocol == protocol::ISAKMP && d.spis.contains(&cookies) {
                self.fail("the gateway ended the session".into(), true);
                return;
            }
            if d.protocol == protocol::ESP
                && self.state == State::Established
                && self.child.is_some()
                && self.quick.is_none()
            {
                // The gateway dropped an SA: if it was the current one, negotiate a new one.
                // (Its delete names its own inbound SPI, our outbound one, which we do not
                // track per child; a fresh negotiation is harmless if it was an old one.)
                if let Some(child) = &mut self.child {
                    child.rekey_at = now;
                }
            }
        }
    }

    fn poll_dpd(&mut self, now: Instant) {
        let Some(interval) = self.config.dpd.filter(|_| self.peer_dpd) else {
            return;
        };
        let due = match &self.dpd_wait {
            Some(w) if now >= w.sent + DPD_RETRY => {
                if w.tries >= DPD_TRIES {
                    self.fail(
                        "the gateway stopped answering (dead-peer detection)".into(),
                        true,
                    );
                    return;
                }
                Some(w.tries + 1)
            }
            Some(_) => None,
            None if now >= self.last_heard + interval => Some(1),
            None => None,
        };
        if let Some(tries) = due {
            self.dpd_seq = self.dpd_seq.wrapping_add(1);
            let seq = self.dpd_seq;
            self.dpd_wait = Some(DpdWait {
                seq,
                sent: now,
                tries,
            });
            let cookies = [self.cky_i, self.cky_r].concat();
            self.send_informational(&Notify {
                protocol: protocol::ISAKMP,
                spi: cookies,
                kind: notify::R_U_THERE,
                data: seq.to_be_bytes().to_vec(),
            });
        }
    }
}

/// NAT-D = HASH(CKY-I | CKY-R | IP | port) with the phase-1 hash.
pub(crate) fn nat_hash(hash: HashAlg, cky_i: [u8; 8], cky_r: [u8; 8], addr: SocketAddr) -> Vec<u8> {
    let ip = match addr.ip() {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    hash.hash(&[&cky_i, &cky_r, &ip, &addr.port().to_be_bytes()])
}
