//! The IKEv2 initiator ([RFC 7296]): IKE_SA_INIT, IKE_AUTH with a pre-shared key or EAP,
//! the configuration payload, the child SA, CREATE_CHILD_SA rekeys (ours and the gateway's),
//! liveness checks and deletes. Fragmented replies ([RFC 7383]) are reassembled.
//!
//! As with IKEv1, NAT traversal is always forced (our NAT detection hash describes an
//! address we do not have), so ESP travels in UDP 4500 or in the TCP stream (RFC 9329).
//!
//! [RFC 7296]: https://www.rfc-editor.org/rfc/rfc7296
//! [RFC 7383]: https://www.rfc-editor.org/rfc/rfc7383

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use polytunnel_esp::{Cipher, Integrity, Keys};
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

use super::auth::{shared_key_auth, shared_key_ok, signed_octets};
use super::config::{ClientAuth, Config, ServerAuth};
use super::crypto::{IkeKeys, IkeSuite, bits};
use super::wire::{
    self, CERT_X509_SIGNATURE, Chain, Delete, Header, Notify, Payload, Proposal, Selector,
    Transform, auth_method, cp, encode_chain, exchange, flag, id_type, notify, payload, protocol,
    transform,
};
use crate::dh::{Group, KeyPair};
use crate::eap::{EapClient, Step};
use crate::session::{ChildSa, Output, Session};
use crate::v1::cfg::ModeConfig;
use crate::v1::config::{EspCipher, EspProposal, Identity};

const RETRANSMIT: [Duration; 5] = [
    Duration::from_secs(2),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(8),
];
/// Over TCP nothing is retransmitted; an answer must come within this.
const RELIABLE_TIMEOUT: Duration = Duration::from_secs(30);
const RETIRE_AFTER: Duration = Duration::from_secs(20);
const NONCE_LEN: usize = 32;
const MAX_FRAGMENTS: u16 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    New,
    InitSent,
    AuthSent,
    Established,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Init,
    Auth,
    Rekey,
    Liveness,
    Info,
}

impl Kind {
    fn what(self) -> &'static str {
        match self {
            Kind::Init => "IKE_SA_INIT",
            Kind::Auth => "IKE_AUTH",
            Kind::Rekey => "rekeying",
            Kind::Liveness => "liveness check",
            Kind::Info => "informational exchange",
        }
    }
}

struct Pending {
    mid: u32,
    kind: Kind,
    message: Vec<u8>,
    sent: Instant,
    next: Instant,
    tries: usize,
}

struct Queued {
    kind: Kind,
    exchange: u8,
    inner: Vec<Payload>,
}

struct Child {
    inbound: u32,
    outbound: u32,
    rekey_at: Instant,
}

struct Rekey {
    spi: u32,
    ni: Vec<u8>,
    dh: Option<KeyPair>,
}

#[derive(Default)]
struct Fragments {
    mid: u32,
    first_next: u8,
    parts: Vec<Option<Vec<u8>>>,
}

pub struct Initiator {
    config: Config,
    state: State,
    spi_i: [u8; 8],
    spi_r: [u8; 8],
    dh: Option<KeyPair>,
    ni: Vec<u8>,
    nr: Vec<u8>,
    cookie: Option<Vec<u8>>,
    init_request: Vec<u8>,
    init_response: Vec<u8>,
    keys: Option<IkeKeys>,
    idi_body: Vec<u8>,
    idr_body: Vec<u8>,
    child_spi: u32,
    eap: Option<EapClient>,
    server_authenticated: bool,
    msk_auth_sent: bool,
    mid: u32,
    pending: Option<Pending>,
    queue: VecDeque<Queued>,
    fragments: Fragments,
    peer_mid: u32,
    last_response: Option<(u32, Vec<u8>, Vec<u8>)>,
    child: Option<Child>,
    retiring: Vec<(Child, Instant)>,
    rekey: Option<Rekey>,
    ike_expires: Option<Instant>,
    last_heard: Instant,
    out: Vec<Output>,
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("the system random number generator failed");
    b
}

fn random_spi() -> u32 {
    loop {
        let v = u32::from_be_bytes(random());
        if v >= 256 {
            return v;
        }
    }
}

/// NAT detection: SHA-1(SPIi | SPIr | IP | port).
pub(crate) fn nat_hash(spi_i: [u8; 8], spi_r: [u8; 8], addr: SocketAddr) -> Vec<u8> {
    let ip = match addr.ip() {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    Sha1::new()
        .chain_update(spi_i)
        .chain_update(spi_r)
        .chain_update(ip)
        .chain_update(addr.port().to_be_bytes())
        .finalize()
        .to_vec()
}

pub(crate) fn integ_id(i: Integrity) -> Option<u16> {
    match i {
        Integrity::None => None,
        Integrity::HmacSha1_96 => Some(transform::AUTH_HMAC_SHA1_96),
        Integrity::HmacSha256_128 => Some(transform::AUTH_HMAC_SHA2_256_128),
        Integrity::HmacSha384_192 => Some(transform::AUTH_HMAC_SHA2_384_192),
        Integrity::HmacSha512_256 => Some(transform::AUTH_HMAC_SHA2_512_256),
    }
}

/// One ESP proposal per configured combination.
pub(crate) fn esp_proposals(esp: &[EspProposal], spi: u32, group: Option<Group>) -> Vec<Proposal> {
    esp.iter()
        .enumerate()
        .map(|(i, p)| {
            let encr = match p.cipher {
                EspCipher::AesCbc { key_len } => (transform::ENCR_AES_CBC, key_len),
                EspCipher::AesGcm16 { key_len } => (transform::ENCR_AES_GCM_16, key_len),
            };
            let mut transforms = vec![Transform::with_key_len(
                transform::ENCR,
                encr.0,
                bits(encr.1),
            )];
            if let Some(id) = integ_id(p.integrity) {
                transforms.push(Transform::new(transform::INTEG, id));
            }
            if let Some(g) = group {
                transforms.push(Transform::new(transform::DH, g.id()));
            }
            transforms.push(Transform::new(transform::ESN, transform::ESN_NONE));
            Proposal {
                number: u8::try_from(i + 1).expect("few proposals"),
                protocol: protocol::ESP,
                spi: spi.to_be_bytes().to_vec(),
                transforms,
            }
        })
        .collect()
}

/// Which of `esp` an ESP proposal is (with the DH group `group`, if any).
pub(crate) fn match_esp(
    esp: &[EspProposal],
    p: &Proposal,
    group: Option<Group>,
) -> Option<EspProposal> {
    if p.protocol != protocol::ESP || p.spi.len() != 4 {
        return None;
    }
    let encr = p.one(transform::ENCR)?;
    let integ = p.one(transform::INTEG).map(|t| t.id).filter(|id| *id != 0);
    let dh = p.one(transform::DH).map(|t| t.id).filter(|id| *id != 0);
    if dh != group.map(Group::id) {
        return None;
    }
    esp.iter().copied().find(|ours| {
        let (id, key_len) = match ours.cipher {
            EspCipher::AesCbc { key_len } => (transform::ENCR_AES_CBC, key_len),
            EspCipher::AesGcm16 { key_len } => (transform::ENCR_AES_GCM_16, key_len),
        };
        encr.id == id && encr.key_len == Some(bits(key_len)) && integ == integ_id(ours.integrity)
    })
}

/// ESP keys from one direction's share of the keying material.
pub(crate) fn esp_keys(p: &EspProposal, km: &[u8]) -> Result<Keys, String> {
    match p.cipher {
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
    }
    .map_err(|e| e.to_string())
}

fn id_body(id: &Identity) -> Vec<u8> {
    match id {
        Identity::Ipv4(a) => wire::encode_id(id_type::IPV4_ADDR, &a.octets()),
        Identity::Fqdn(s) => wire::encode_id(id_type::FQDN, s.as_bytes()),
        Identity::UserFqdn(s) => wire::encode_id(id_type::RFC822_ADDR, s.as_bytes()),
        Identity::KeyId(k) => wire::encode_id(id_type::KEY_ID, k),
    }
}

fn describe_error(kind: u16) -> String {
    match kind {
        notify::NO_PROPOSAL_CHOSEN => {
            "the gateway accepted none of the offered proposals; check the encryption, hash and Diffie-Hellman settings".into()
        }
        notify::AUTHENTICATION_FAILED => {
            "authentication failed; check the pre-shared key, username and password".into()
        }
        notify::TS_UNACCEPTABLE => {
            "the gateway refused the traffic selectors; check the profile's remote network".into()
        }
        notify::INTERNAL_ADDRESS_FAILURE | notify::FAILED_CP_REQUIRED => {
            "the gateway could not assign an address".into()
        }
        notify::INVALID_SYNTAX => "the gateway could not parse our message".into(),
        notify::TEMPORARY_FAILURE => "the gateway is busy; try again".into(),
        other => format!("the gateway reported IKE error {other}"),
    }
}

/// Mode-config from a CP reply and the gateway's (possibly narrowed) TSr.
fn mode_config(cp_attrs: &[wire::CpAttr], tsr: &[Selector]) -> ModeConfig {
    let mut mc = ModeConfig::default();
    let ipv4 = |v: &[u8]| <[u8; 4]>::try_from(v).ok().map(Ipv4Addr::from);
    let add = |net: Ipv4Addr, len: u8, mc: &mut ModeConfig| {
        if len > 0 && !mc.split_include.contains(&(net, len)) {
            mc.split_include.push((net, len));
        }
    };
    for (kind, value) in cp_attrs {
        match *kind {
            cp::INTERNAL_IP4_ADDRESS if mc.address.is_none() => mc.address = ipv4(value),
            cp::INTERNAL_IP4_NETMASK => mc.netmask = ipv4(value),
            cp::INTERNAL_IP4_DNS => mc.dns.extend(ipv4(value)),
            cp::INTERNAL_IP4_SUBNET if value.len() == 8 => {
                if let (Some(net), Some(mask)) = (ipv4(&value[..4]), ipv4(&value[4..])) {
                    let m = u32::from(mask);
                    if m.leading_ones() + m.trailing_zeros() == 32 {
                        let len = u8::try_from(m.leading_ones()).expect("<= 32");
                        add(Ipv4Addr::from(u32::from(net) & m), len, &mut mc);
                    }
                }
            }
            cp::INTERNAL_DNS_DOMAIN => {
                let d = String::from_utf8_lossy(value).trim().to_string();
                if !d.is_empty() && !mc.split_dns.contains(&d) {
                    mc.split_dns.push(d);
                }
            }
            _ => {}
        }
    }
    for s in tsr {
        if let Some((net, len)) = s.to_network() {
            add(net, len, &mut mc);
        }
    }
    mc
}

impl Initiator {
    pub fn new(config: Config, now: Instant) -> Result<Self, String> {
        config.validate()?;
        let mut spi_i: [u8; 8] = random();
        if spi_i == [0; 8] {
            spi_i[0] = 1;
        }
        let eap = match &config.client_auth {
            ClientAuth::Eap {
                method,
                username,
                password,
                trust,
            } => {
                let client = EapClient::new(*method, username.clone(), password.clone());
                Some(match trust {
                    Some(t) => client.with_trust(t.clone()),
                    None => client,
                })
            }
            ClientAuth::Psk(_) => None,
        };
        Ok(Self {
            config,
            state: State::New,
            spi_i,
            spi_r: [0; 8],
            dh: None,
            ni: random::<NONCE_LEN>().to_vec(),
            nr: Vec::new(),
            cookie: None,
            init_request: Vec::new(),
            init_response: Vec::new(),
            keys: None,
            idi_body: Vec::new(),
            idr_body: Vec::new(),
            child_spi: random_spi(),
            eap,
            server_authenticated: false,
            msk_auth_sent: false,
            mid: 1,
            pending: None,
            queue: VecDeque::new(),
            fragments: Fragments::default(),
            peer_mid: 0,
            last_response: None,
            child: None,
            retiring: Vec::new(),
            rekey: None,
            ike_expires: None,
            last_heard: now,
            out: Vec::new(),
        })
    }

    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    fn drain(&mut self) -> Vec<Output> {
        std::mem::take(&mut self.out)
    }

    fn fail(&mut self, reason: String, retry: bool) {
        if self.state != State::Closed {
            self.state = State::Closed;
            self.pending = None;
            self.out.push(Output::Closed { reason, retry });
        }
    }

    fn send(&mut self, natt: bool, message: Vec<u8>) {
        self.out.push(Output::Send { natt, message });
    }

    fn keys(&self) -> &IkeKeys {
        self.keys.as_ref().expect("keys are derived")
    }

    fn header(&self, exchange: u8, mid: u32, response: bool) -> Header {
        Header {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            next: payload::NONE,
            exchange,
            flags: flag::INITIATOR | if response { flag::RESPONSE } else { 0 },
            mid,
            len: 0,
        }
    }

    // ------------------------------------------------------------------ requests

    fn track(&mut self, now: Instant, mid: u32, kind: Kind, message: Vec<u8>) {
        self.pending = Some(Pending {
            mid,
            kind,
            message,
            sent: now,
            next: now + RETRANSMIT[0],
            tries: 1,
        });
    }

    /// Sends an encrypted request, or queues it while another one is outstanding.
    fn request(&mut self, now: Instant, kind: Kind, exchange: u8, inner: Vec<Payload>) {
        if self.pending.is_some() {
            self.queue.push_back(Queued {
                kind,
                exchange,
                inner,
            });
            return;
        }
        let mid = self.mid;
        self.mid += 1;
        let msg = self
            .keys()
            .encrypt(true, self.header(exchange, mid, false), &inner);
        self.track(now, mid, kind, msg.clone());
        self.send(true, msg);
    }

    fn send_init(&mut self, now: Instant) {
        let dh = self.dh.as_ref().expect("key pair made");
        let group = dh.group();
        let proposals: Vec<Proposal> = self
            .config
            .ike
            .iter()
            .enumerate()
            .map(|(i, s)| s.proposal(u8::try_from(i + 1).expect("few proposals")))
            .collect();
        let fake = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(random::<4>())),
            u16::from_be_bytes(random()),
        );
        let mut payloads = Vec::new();
        if let Some(cookie) = &self.cookie {
            payloads.push(Payload::new(
                payload::NOTIFY,
                Notify::new(notify::COOKIE, cookie.clone()).encode(),
            ));
        }
        payloads.extend([
            Payload::new(payload::SA, wire::encode_sa(&proposals)),
            Payload::new(payload::KE, wire::encode_ke(group.id(), dh.public())),
            Payload::new(payload::NONCE, self.ni.clone()),
            Payload::new(
                payload::NOTIFY,
                Notify::new(
                    notify::NAT_DETECTION_SOURCE_IP,
                    nat_hash(self.spi_i, [0; 8], fake),
                )
                .encode(),
            ),
            Payload::new(
                payload::NOTIFY,
                Notify::new(
                    notify::NAT_DETECTION_DESTINATION_IP,
                    nat_hash(self.spi_i, [0; 8], self.config.remote),
                )
                .encode(),
            ),
            Payload::new(
                payload::NOTIFY,
                Notify::new(notify::FRAGMENTATION_SUPPORTED, Vec::new()).encode(),
            ),
        ]);
        if matches!(self.config.server_auth, ServerAuth::Certificate(_)) {
            // SHA2-256, SHA2-384, SHA2-512 for RFC 7427 signatures.
            payloads.push(Payload::new(
                payload::NOTIFY,
                Notify::new(notify::SIGNATURE_HASH_ALGORITHMS, vec![0, 2, 0, 3, 0, 4]).encode(),
            ));
        }
        let body = encode_chain(&payloads);
        let header = Header {
            next: payloads[0].kind,
            ..self.header(exchange::IKE_SA_INIT, 0, false)
        };
        let mut msg = header.encode(body.len()).to_vec();
        msg.extend_from_slice(&body);
        self.init_request = msg.clone();
        self.state = State::InitSent;
        self.track(now, 0, Kind::Init, msg.clone());
        self.send(false, msg);
    }

    // ------------------------------------------------------------------ dispatch

    fn dispatch(&mut self, now: Instant, data: &[u8]) -> Result<(), String> {
        let Ok((header, body)) = Header::parse(data) else {
            return Ok(());
        };
        if header.spi_i != self.spi_i || header.flags & flag::INITIATOR != 0 {
            return Ok(()); // not ours, or a copy of our own message
        }
        let raw = &data[..usize::try_from(header.len).unwrap_or(data.len())];
        if header.exchange == exchange::IKE_SA_INIT {
            return if header.is_response() && self.state == State::InitSent {
                self.on_init_response(now, &header, body, raw)
            } else {
                Ok(())
            };
        }
        if self.keys.is_none() || header.spi_r != self.spi_r {
            return Ok(());
        }
        if !header.is_response() {
            if header.mid.wrapping_add(1) == self.peer_mid
                && let Some((_, request, response)) = &self.last_response
                && request.as_slice() == raw
            {
                let response = response.clone();
                self.send(true, response);
                return Ok(());
            }
            if header.mid != self.peer_mid {
                return Ok(());
            }
        } else if self.pending.as_ref().is_none_or(|p| p.mid != header.mid) {
            return Ok(());
        }
        let Ok(chain) = Chain::parse(header.next, body, wire::HEADER_LEN) else {
            return Ok(());
        };
        let Some(enc) = chain.encrypted else {
            return Ok(());
        };
        let Ok(plain) = self.keys().decrypt(false, raw, &enc) else {
            return Ok(()); // forged or damaged
        };
        let (first, plain) = if enc.kind == payload::SKF {
            match self.reassemble(&header, raw, enc.offset, enc.inner_next, plain) {
                Some(whole) => whole,
                None => return Ok(()), // more fragments to come
            }
        } else {
            (enc.inner_next, plain)
        };
        let Ok(inner) = Chain::parse(first, &plain, 0) else {
            return Ok(());
        };
        self.last_heard = now;
        if header.is_response() {
            let pending = self.pending.take().expect("checked");
            match pending.kind {
                Kind::Auth => self.on_auth_response(now, &inner)?,
                Kind::Rekey => self.on_rekey_response(now, &inner)?,
                Kind::Init | Kind::Liveness | Kind::Info => {}
            }
            if self.pending.is_none()
                && self.state != State::Closed
                && let Some(q) = self.queue.pop_front()
            {
                self.request(now, q.kind, q.exchange, q.inner);
            }
            Ok(())
        } else {
            self.on_peer_request(now, &header, raw, &inner)
        }
    }

    /// Collects encrypted fragments; returns the whole plaintext once all have arrived.
    fn reassemble(
        &mut self,
        header: &Header,
        raw: &[u8],
        offset: usize,
        inner_next: u8,
        plain: Vec<u8>,
    ) -> Option<(u8, Vec<u8>)> {
        let fields = raw.get(offset + 4..offset + 8)?;
        let number = u16::from_be_bytes([fields[0], fields[1]]);
        let total = u16::from_be_bytes([fields[2], fields[3]]);
        if number == 0 || number > total || total > MAX_FRAGMENTS {
            return None;
        }
        if self.fragments.mid != header.mid || self.fragments.parts.len() != usize::from(total) {
            self.fragments = Fragments {
                mid: header.mid,
                first_next: 0,
                parts: vec![None; usize::from(total)],
            };
        }
        if number == 1 {
            self.fragments.first_next = inner_next;
        }
        self.fragments.parts[usize::from(number - 1)] = Some(plain);
        if self.fragments.parts.iter().any(Option::is_none) {
            return None;
        }
        let whole: Vec<u8> = std::mem::take(&mut self.fragments.parts)
            .into_iter()
            .flatten()
            .flatten()
            .collect();
        let first = self.fragments.first_next;
        self.fragments = Fragments::default();
        Some((first, whole))
    }

    // ------------------------------------------------------------------ IKE_SA_INIT

    fn on_init_response(
        &mut self,
        now: Instant,
        header: &Header,
        body: &[u8],
        raw: &[u8],
    ) -> Result<(), String> {
        let chain = Chain::parse(header.next, body, wire::HEADER_LEN).map_err(|e| e.to_string())?;
        if let Some(n) = chain.notify(notify::COOKIE) {
            if n.data.len() > 64 {
                return Err("the gateway sent an oversized cookie".into());
            }
            self.cookie = Some(n.data);
            self.send_init(now);
            return Ok(());
        }
        if let Some(n) = chain.notify(notify::INVALID_KE_PAYLOAD) {
            let wanted = (n.data.len() == 2).then(|| u16::from_be_bytes([n.data[0], n.data[1]]));
            let group = wanted
                .and_then(Group::from_id)
                .filter(|g| self.config.ike.iter().any(|s| s.group == *g))
                .ok_or("the gateway wants a Diffie-Hellman group the profile does not offer")?;
            if self.dh.as_ref().is_some_and(|d| d.group() == group) {
                return Err("the gateway keeps refusing our Diffie-Hellman group".into());
            }
            self.dh = Some(KeyPair::generate(group).map_err(|e| e.to_string())?);
            self.send_init(now);
            return Ok(());
        }
        if let Some(n) = chain.notifies().find(|n| n.kind <= notify::ERROR_MAX) {
            return Err(describe_error(n.kind));
        }
        let missing = |what: &str| format!("the gateway's IKE_SA_INIT reply has no {what}");
        let chosen = wire::parse_sa(chain.find(payload::SA).ok_or_else(|| missing("SA"))?)
            .map_err(|e| e.to_string())?;
        let chosen = chosen.first().ok_or_else(|| missing("proposal"))?;
        let dh = self.dh.take().expect("sent with the request");
        let suite: IkeSuite = *self
            .config
            .ike
            .iter()
            .find(|s| s.matches(chosen) && s.group == dh.group())
            .ok_or("the gateway chose an IKE proposal we did not offer")?;
        let (group, ke) = wire::parse_ke(
            chain
                .find(payload::KE)
                .ok_or_else(|| missing("key exchange"))?,
        )
        .map_err(|e| e.to_string())?;
        if group != dh.group().id() {
            return Err("the gateway answered with another Diffie-Hellman group".into());
        }
        let nr = chain.find(payload::NONCE).ok_or_else(|| missing("nonce"))?;
        if !(16..=256).contains(&nr.len()) {
            return Err("the gateway's nonce has an invalid length".into());
        }
        let gir = dh.agree(ke).map_err(|e| e.to_string())?;
        self.spi_r = header.spi_r;
        self.nr = nr.to_vec();
        self.init_response = raw.to_vec();
        self.keys = Some(IkeKeys::derive(
            suite,
            (&self.ni, &self.nr),
            &gir,
            (self.spi_i, self.spi_r),
        ));
        self.pending = None;
        self.state = State::AuthSent;
        self.send_auth(now);
        Ok(())
    }

    // ------------------------------------------------------------------ IKE_AUTH

    fn initiator_octets(&self) -> Vec<u8> {
        let keys = self.keys();
        signed_octets(
            &self.init_request,
            &self.nr,
            keys.prf(),
            keys.sk_pi(),
            &self.idi_body,
        )
    }

    fn responder_octets(&self, idr_body: &[u8]) -> Vec<u8> {
        let keys = self.keys();
        signed_octets(
            &self.init_response,
            &self.ni,
            keys.prf(),
            keys.sk_pr(),
            idr_body,
        )
    }

    fn send_auth(&mut self, now: Instant) {
        self.idi_body = match (&self.config.local_id, self.config.local.ip()) {
            (Some(id), _) => id_body(id),
            (None, IpAddr::V4(ip)) => id_body(&Identity::Ipv4(ip)),
            (None, IpAddr::V6(_)) => id_body(&Identity::Ipv4(Ipv4Addr::UNSPECIFIED)),
        };
        let mut inner = vec![Payload::new(payload::IDI, self.idi_body.clone())];
        if let ClientAuth::Psk(psk) = &self.config.client_auth {
            let auth = shared_key_auth(self.keys().prf(), psk, &self.initiator_octets());
            inner.push(Payload::new(
                payload::AUTH,
                wire::encode_auth(auth_method::PSK, &auth),
            ));
        }
        let (net, len) = self.config.remote_network;
        inner.extend([
            Payload::new(
                payload::CP,
                wire::encode_cp(
                    cp::REQUEST,
                    &[
                        (cp::INTERNAL_IP4_ADDRESS, Vec::new()),
                        (cp::INTERNAL_IP4_DNS, Vec::new()),
                        (cp::INTERNAL_DNS_DOMAIN, Vec::new()),
                    ],
                ),
            ),
            Payload::new(
                payload::SA,
                wire::encode_sa(&esp_proposals(&self.config.esp, self.child_spi, None)),
            ),
            Payload::new(payload::TSI, wire::encode_ts(&[Selector::ANY])),
            Payload::new(
                payload::TSR,
                wire::encode_ts(&[Selector::network(net, len)]),
            ),
            Payload::new(
                payload::NOTIFY,
                Notify::new(notify::INITIAL_CONTACT, Vec::new()).encode(),
            ),
        ]);
        self.request(now, Kind::Auth, exchange::IKE_AUTH, inner);
    }

    fn on_auth_response(&mut self, now: Instant, chain: &Chain) -> Result<(), String> {
        if let Some(n) = chain.notifies().find(|n| n.kind <= notify::ERROR_MAX) {
            return Err(describe_error(n.kind));
        }
        let prf = self.keys().prf();
        if !self.server_authenticated {
            let idr = chain
                .find(payload::IDR)
                .ok_or("the gateway did not identify itself")?
                .to_vec();
            let (method, data) = wire::parse_auth(
                chain
                    .find(payload::AUTH)
                    .ok_or("the gateway did not authenticate itself")?,
            )
            .map_err(|e| e.to_string())?;
            let octets = self.responder_octets(&idr);
            match &self.config.server_auth {
                ServerAuth::Psk(psk) => {
                    if method != auth_method::PSK || !shared_key_ok(prf, psk, &octets, data) {
                        return Err("the gateway's proof did not verify: the pre-shared key is probably wrong".into());
                    }
                }
                ServerAuth::Certificate(trust) => {
                    let certs: Vec<Vec<u8>> = chain
                        .all(payload::CERT)
                        .filter(|c| c.first() == Some(&CERT_X509_SIGNATURE))
                        .map(|c| c[1..].to_vec())
                        .collect();
                    trust.verify(&certs, method, data, &octets)?;
                }
            }
            self.server_authenticated = true;
            self.idr_body = idr;
        }
        if self.eap.is_some() && !self.msk_auth_sent {
            let packet = chain
                .find(payload::EAP)
                .ok_or("the gateway did not start EAP")?;
            let step = self.eap.as_mut().expect("checked").handle(packet);
            match step {
                Step::Respond(response) => {
                    self.request(
                        now,
                        Kind::Auth,
                        exchange::IKE_AUTH,
                        vec![Payload::new(payload::EAP, response)],
                    );
                }
                Step::Success => {
                    let msk = self
                        .eap
                        .as_ref()
                        .and_then(EapClient::msk)
                        .expect("set on success")
                        .to_vec();
                    let auth = shared_key_auth(prf, &msk, &self.initiator_octets());
                    self.msk_auth_sent = true;
                    self.request(
                        now,
                        Kind::Auth,
                        exchange::IKE_AUTH,
                        vec![Payload::new(
                            payload::AUTH,
                            wire::encode_auth(auth_method::PSK, &auth),
                        )],
                    );
                }
                Step::Failure(reason) => return Err(reason),
            }
            return Ok(());
        }
        if self.msk_auth_sent {
            let (_, data) = wire::parse_auth(
                chain
                    .find(payload::AUTH)
                    .ok_or("the gateway's final proof is missing")?,
            )
            .map_err(|e| e.to_string())?;
            let msk = self
                .eap
                .as_ref()
                .and_then(EapClient::msk)
                .expect("EAP finished")
                .to_vec();
            if !shared_key_ok(prf, &msk, &self.responder_octets(&self.idr_body), data) {
                return Err("the gateway's EAP proof did not verify".into());
            }
        }
        self.establish(now, chain)
    }

    fn establish(&mut self, now: Instant, chain: &Chain) -> Result<(), String> {
        let attrs = match chain.find(payload::CP) {
            Some(b) => wire::parse_cp(b).map_err(|e| e.to_string())?.1,
            None => Vec::new(),
        };
        let tsr = match chain.find(payload::TSR) {
            Some(b) => wire::parse_ts(b).map_err(|e| e.to_string())?,
            None => Vec::new(),
        };
        let mc = mode_config(&attrs, &tsr);
        if mc.address.is_none() {
            return Err("the gateway assigned no IPv4 address".into());
        }
        let proposals = wire::parse_sa(
            chain
                .find(payload::SA)
                .ok_or("the gateway created no IPsec SA")?,
        )
        .map_err(|e| e.to_string())?;
        let chosen = proposals.first().ok_or("the gateway created no IPsec SA")?;
        let proposal = match_esp(&self.config.esp, chosen, None)
            .ok_or("the gateway chose an ESP proposal we did not offer")?;
        let peer_spi = u32::from_be_bytes(chosen.spi[..4].try_into().expect("4 bytes"));
        let km = self
            .keys()
            .child_keymat(None, &self.ni, &self.nr, 2 * proposal.keymat_len());
        self.out.push(Output::Configured(mc));
        self.state = State::Established;
        self.ike_expires = Some(now + self.config.ike_lifetime);
        let spi = self.child_spi;
        self.install(now, (spi, peer_spi), proposal, &km, true)
    }

    /// Announces a new SA pair. `spis`: (ours, the gateway's); `we_initiated`: whether we
    /// started the exchange (its initiator-to-responder keys come first).
    fn install(
        &mut self,
        now: Instant,
        spis: (u32, u32),
        proposal: EspProposal,
        km: &[u8],
        we_initiated: bool,
    ) -> Result<(), String> {
        let (i2r, r2i) = km.split_at(proposal.keymat_len());
        let (out_km, in_km) = if we_initiated { (i2r, r2i) } else { (r2i, i2r) };
        let lifetime = self.config.esp_lifetime;
        let margin = lifetime / 10 + lifetime / 20 * u32::from(random::<1>()[0]) / 255;
        let child = Child {
            inbound: spis.0,
            outbound: spis.1,
            rekey_at: now + lifetime.saturating_sub(margin),
        };
        if let Some(old) = self.child.replace(child) {
            self.retiring.push((old, now + RETIRE_AFTER));
        }
        self.out.push(Output::ChildSa(ChildSa {
            inbound_spi: spis.0,
            inbound: esp_keys(&proposal, in_km)?,
            outbound_spi: spis.1,
            outbound: esp_keys(&proposal, out_km)?,
            proposal,
            lifetime,
        }));
        Ok(())
    }

    // ------------------------------------------------------------------ rekeying

    fn start_rekey(&mut self, now: Instant) -> Result<(), String> {
        let Some(old) = self.child.as_ref().map(|c| c.inbound) else {
            return Ok(());
        };
        let spi = random_spi();
        let ni = random::<NONCE_LEN>().to_vec();
        let dh = match self.config.pfs {
            Some(g) => Some(KeyPair::generate(g).map_err(|e| e.to_string())?),
            None => None,
        };
        let (net, len) = self.config.remote_network;
        let mut inner = vec![
            Payload::new(
                payload::NOTIFY,
                Notify {
                    protocol: protocol::ESP,
                    spi: old.to_be_bytes().to_vec(),
                    kind: notify::REKEY_SA,
                    data: Vec::new(),
                }
                .encode(),
            ),
            Payload::new(
                payload::SA,
                wire::encode_sa(&esp_proposals(&self.config.esp, spi, self.config.pfs)),
            ),
            Payload::new(payload::NONCE, ni.clone()),
        ];
        if let Some(dh) = &dh {
            inner.push(Payload::new(
                payload::KE,
                wire::encode_ke(dh.group().id(), dh.public()),
            ));
        }
        inner.push(Payload::new(
            payload::TSI,
            wire::encode_ts(&[Selector::ANY]),
        ));
        inner.push(Payload::new(
            payload::TSR,
            wire::encode_ts(&[Selector::network(net, len)]),
        ));
        self.rekey = Some(Rekey { spi, ni, dh });
        self.request(now, Kind::Rekey, exchange::CREATE_CHILD_SA, inner);
        Ok(())
    }

    fn on_rekey_response(&mut self, now: Instant, chain: &Chain) -> Result<(), String> {
        let Some(rekey) = self.rekey.take() else {
            return Ok(());
        };
        if let Some(n) = chain.notifies().find(|n| n.kind <= notify::ERROR_MAX) {
            if n.kind == notify::TEMPORARY_FAILURE || n.kind == notify::NO_ADDITIONAL_SAS {
                // Try again shortly with the SA we have.
                if let Some(c) = &mut self.child {
                    c.rekey_at = now + Duration::from_secs(30);
                }
                return Ok(());
            }
            return Err(describe_error(n.kind));
        }
        let proposals = wire::parse_sa(chain.find(payload::SA).ok_or("the rekey reply has no SA")?)
            .map_err(|e| e.to_string())?;
        let chosen = proposals.first().ok_or("the rekey reply has no SA")?;
        let proposal = match_esp(&self.config.esp, chosen, self.config.pfs)
            .ok_or("the gateway chose a rekey proposal we did not offer")?;
        let peer_spi = u32::from_be_bytes(chosen.spi[..4].try_into().expect("4 bytes"));
        let nr = chain
            .find(payload::NONCE)
            .ok_or("the rekey reply has no nonce")?
            .to_vec();
        let gir = match &rekey.dh {
            Some(dh) => {
                let (_, ke) = wire::parse_ke(
                    chain
                        .find(payload::KE)
                        .ok_or("the rekey reply has no key exchange")?,
                )
                .map_err(|e| e.to_string())?;
                Some(dh.agree(ke).map_err(|e| e.to_string())?)
            }
            None => None,
        };
        let km = self.keys().child_keymat(
            gir.as_deref().map(Vec::as_slice),
            &rekey.ni,
            &nr,
            2 * proposal.keymat_len(),
        );
        self.install(now, (rekey.spi, peer_spi), proposal, &km, true)
    }

    // ------------------------------------------------------------------ the gateway's requests

    fn respond(&mut self, header: &Header, raw: &[u8], inner: &[Payload]) {
        let msg = self
            .keys()
            .encrypt(true, self.header(header.exchange, header.mid, true), inner);
        self.last_response = Some((header.mid, raw.to_vec(), msg.clone()));
        self.peer_mid = header.mid.wrapping_add(1);
        self.send(true, msg);
    }

    fn on_peer_request(
        &mut self,
        now: Instant,
        header: &Header,
        raw: &[u8],
        chain: &Chain,
    ) -> Result<(), String> {
        match header.exchange {
            exchange::INFORMATIONAL => {
                let mut reply = Vec::new();
                let mut ended = None;
                for d in chain
                    .all(payload::DELETE)
                    .filter_map(|b| Delete::parse(b).ok())
                {
                    if d.protocol == protocol::IKE {
                        ended = Some("the gateway ended the session");
                    } else if d.protocol == protocol::ESP {
                        // The gateway names its inbound SPIs: our outbound ones.
                        let mut ours = Vec::new();
                        self.retiring.retain(|(c, _)| {
                            let hit = d.spis.contains(&c.outbound);
                            if hit {
                                ours.push(c.inbound);
                            }
                            !hit
                        });
                        if let Some(c) =
                            self.child.as_ref().filter(|c| d.spis.contains(&c.outbound))
                        {
                            ours.push(c.inbound);
                            self.child = None;
                            ended = Some("the gateway removed the IPsec SA");
                        }
                        for spi in &ours {
                            self.out.push(Output::Retire { inbound_spi: *spi });
                        }
                        if !ours.is_empty() {
                            reply.push(Payload::new(
                                payload::DELETE,
                                Delete {
                                    protocol: protocol::ESP,
                                    spis: ours,
                                }
                                .encode(),
                            ));
                        }
                    }
                }
                self.respond(header, raw, &reply);
                if let Some(reason) = ended {
                    self.fail(reason.into(), true);
                }
                Ok(())
            }
            exchange::CREATE_CHILD_SA => {
                let reply = self.on_peer_create_child(now, chain)?;
                self.respond(header, raw, &reply);
                Ok(())
            }
            _ => {
                self.respond(header, raw, &[]);
                Ok(())
            }
        }
    }

    /// The gateway rekeys a child SA: answer it. IKE SA rekeys are declined (the session is
    /// re-established when the IKE SA ends).
    fn on_peer_create_child(
        &mut self,
        now: Instant,
        chain: &Chain,
    ) -> Result<Vec<Payload>, String> {
        let refuse = |kind| {
            Ok(vec![Payload::new(
                payload::NOTIFY,
                Notify::new(kind, Vec::new()).encode(),
            )])
        };
        let Some(sa) = chain.find(payload::SA).and_then(|b| wire::parse_sa(b).ok()) else {
            return refuse(notify::INVALID_SYNTAX);
        };
        if sa.first().is_some_and(|p| p.protocol == protocol::IKE)
            || chain.notify(notify::REKEY_SA).is_none()
        {
            return refuse(notify::NO_ADDITIONAL_SAS);
        }
        let Some(ni) = chain.find(payload::NONCE).map(<[u8]>::to_vec) else {
            return refuse(notify::INVALID_SYNTAX);
        };
        let ke = chain.find(payload::KE).and_then(|b| wire::parse_ke(b).ok());
        let group = match ke {
            Some((g, _)) => match self.config.pfs.filter(|p| p.id() == g) {
                Some(p) => Some(p),
                None => return refuse(notify::NO_PROPOSAL_CHOSEN),
            },
            None => None,
        };
        let Some((chosen, proposal)) = sa
            .iter()
            .find_map(|p| match_esp(&self.config.esp, p, group).map(|e| (p.clone(), e)))
        else {
            return refuse(notify::NO_PROPOSAL_CHOSEN);
        };
        let peer_spi = u32::from_be_bytes(chosen.spi[..4].try_into().expect("4 bytes"));
        let spi = random_spi();
        let nr = random::<NONCE_LEN>().to_vec();
        let mut reply_dh = None;
        let gir = match (group, ke) {
            (Some(g), Some((_, data))) => {
                let dh = KeyPair::generate(g).map_err(|e| e.to_string())?;
                let gir = dh.agree(data).map_err(|e| e.to_string())?;
                reply_dh = Some(dh);
                Some(gir)
            }
            _ => None,
        };
        let km = self.keys().child_keymat(
            gir.as_deref().map(Vec::as_slice),
            &ni,
            &nr,
            2 * proposal.keymat_len(),
        );
        let mut reply = vec![
            Payload::new(
                payload::SA,
                wire::encode_sa(&[Proposal {
                    spi: spi.to_be_bytes().to_vec(),
                    ..chosen
                }]),
            ),
            Payload::new(payload::NONCE, nr),
        ];
        if let Some(dh) = &reply_dh {
            reply.push(Payload::new(
                payload::KE,
                wire::encode_ke(dh.group().id(), dh.public()),
            ));
        }
        for kind in [payload::TSI, payload::TSR] {
            if let Some(ts) = chain.find(kind) {
                reply.push(Payload::new(kind, ts.to_vec()));
            }
        }
        self.install(now, (spi, peer_spi), proposal, &km, false)?;
        Ok(reply)
    }

    // ------------------------------------------------------------------ timers

    fn poll_timers(&mut self, now: Instant) {
        if let Some(p) = &mut self.pending {
            let gone = if self.config.reliable {
                now.duration_since(p.sent) > RELIABLE_TIMEOUT
            } else if now >= p.next {
                if p.tries >= RETRANSMIT.len() {
                    true
                } else {
                    p.next = now + RETRANSMIT[p.tries];
                    p.tries += 1;
                    let (natt, msg) = (p.kind != Kind::Init, p.message.clone());
                    self.out.push(Output::Send { natt, message: msg });
                    false
                }
            } else {
                false
            };
            if gone {
                let what = p.kind.what();
                self.fail(format!("the gateway stopped answering ({what})"), true);
                return;
            }
        }
        if self.ike_expires.is_some_and(|t| now >= t) {
            self.fail("the IKE session reached its lifetime".into(), true);
            return;
        }
        if self.state != State::Established {
            return;
        }
        let (due, later): (Vec<_>, Vec<_>) = self.retiring.drain(..).partition(|(_, t)| now >= *t);
        self.retiring = later;
        for (child, _) in due {
            self.out.push(Output::Retire {
                inbound_spi: child.inbound,
            });
            self.request(
                now,
                Kind::Info,
                exchange::INFORMATIONAL,
                vec![Payload::new(
                    payload::DELETE,
                    Delete {
                        protocol: protocol::ESP,
                        spis: vec![child.inbound],
                    }
                    .encode(),
                )],
            );
        }
        if self.pending.is_none()
            && self.rekey.is_none()
            && self.child.as_ref().is_some_and(|c| now >= c.rekey_at)
            && let Err(reason) = self.start_rekey(now)
        {
            self.fail(reason, true);
            return;
        }
        if let Some(every) = self.config.dpd
            && self.pending.is_none()
            && now.duration_since(self.last_heard) >= every
        {
            self.request(now, Kind::Liveness, exchange::INFORMATIONAL, Vec::new());
        }
    }
}

impl Session for Initiator {
    fn start(&mut self, now: Instant) -> Vec<Output> {
        if self.state == State::New {
            match KeyPair::generate(self.config.ike[0].group) {
                Ok(dh) => {
                    self.dh = Some(dh);
                    self.send_init(now);
                }
                Err(e) => self.fail(e.to_string(), false),
            }
        }
        self.drain()
    }

    fn receive(&mut self, now: Instant, message: &[u8]) -> Vec<Output> {
        if self.state != State::Closed
            && let Err(reason) = self.dispatch(now, message)
        {
            self.fail(reason, false);
        }
        self.drain()
    }

    fn answer(&mut self, _values: Vec<Zeroizing<String>>) -> Vec<Output> {
        self.drain()
    }

    fn note_alive(&mut self, now: Instant) {
        self.last_heard = now;
    }

    fn poll(&mut self, now: Instant) -> Vec<Output> {
        if self.state != State::Closed {
            self.poll_timers(now);
        }
        self.drain()
    }

    fn close(&mut self) -> Vec<Output> {
        if self.state != State::Closed && self.keys.is_some() && self.spi_r != [0; 8] {
            // Deleting the IKE SA deletes its child SAs too; no answer is awaited.
            let mid = self.mid;
            self.mid += 1;
            let inner = [Payload::new(
                payload::DELETE,
                Delete {
                    protocol: protocol::IKE,
                    spis: Vec::new(),
                }
                .encode(),
            )];
            let msg = self.keys().encrypt(
                true,
                self.header(exchange::INFORMATIONAL, mid, false),
                &inner,
            );
            self.send(true, msg);
        }
        self.state = State::Closed;
        self.pending = None;
        self.drain()
    }

    fn is_closed(&self) -> bool {
        self.state == State::Closed
    }
}
