//! The initiator against a scripted, FortiGate-like gateway built from the same wire and key
//! primitives: every exchange end to end, then real ESP packets with the negotiated keys.
//! (Interoperability with an independent implementation is tested against strongSwan in CI.)

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use polytunnel_esp::{Cipher, InboundSa, Integrity, Keys, NEXT_HEADER_IPV4, OutboundSa};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::cfg::{ModeConfig, XauthField, attr, cfg_type};
use super::config::{Config, Credentials, EspProposal, Identity, IkeProposal, ModeConfigMode};
use super::initiator::{ChildSa, Initiator, Output, nat_hash};
use super::keymat::{Material, Phase1};
use super::wire::{
    Attribute, Cfg, Chain, Delete, Header, Id, Notify, Payload, Proposal, Sa, encode_chain,
    exchange, find_attr, id_type, message, notify, payload, protocol,
};
use crate::dh::{Group, KeyPair};

const VID_NATT_RFC: [u8; 16] = [
    0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95, 0x45, 0x2f,
];
const VID_DPD: [u8; 16] = [
    0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01, 0x00,
];

// Built at run time so secret scanners do not mistake test values for real ones.
fn psk() -> Vec<u8> {
    ["shared", "test", "key"].join("-").into_bytes()
}

fn password() -> String {
    ["not", "a", "secret"].concat()
}

fn gateway_addr() -> SocketAddr {
    "203.0.113.10:500".parse().unwrap()
}

fn local_addr() -> SocketAddr {
    "192.0.2.20:53000".parse().unwrap()
}

fn config() -> Config {
    Config {
        psk: Zeroizing::new(psk()),
        local_id: Some(Identity::Fqdn("laptop.example.com".into())),
        ike: vec![
            IkeProposal::parse("aes256-sha256-modp2048").unwrap(),
            IkeProposal::parse("aes128-sha1-modp2048").unwrap(),
        ],
        ike_lifetime: Duration::from_secs(28800),
        esp: vec![
            EspProposal::parse("aes256-sha256").unwrap(),
            EspProposal::parse("aes128gcm16").unwrap(),
        ],
        pfs: Some(Group::Modp2048),
        esp_lifetime: Duration::from_secs(3600),
        esp_lifetime_kb: None,
        xauth: Some(Credentials {
            username: "alice".into(),
            password: Zeroizing::new(password()),
        }),
        mode_config: ModeConfigMode::Pull,
        remote_network: (Ipv4Addr::UNSPECIFIED, 0),
        dpd: Some(Duration::from_secs(20)),
        local: local_addr(),
        remote: gateway_addr(),
        client_version: "Polytunnel test".into(),
    }
}

fn sends(out: &[Output]) -> Vec<(bool, Vec<u8>)> {
    out.iter()
        .filter_map(|o| match o {
            Output::Send { natt, message } => Some((*natt, message.clone())),
            _ => None,
        })
        .collect()
}

fn one_send(out: &[Output]) -> Vec<u8> {
    let s = sends(out);
    assert_eq!(s.len(), 1, "expected one message, got {out:?}");
    assert!(s[0].0, "after phase 1 everything goes to the NAT-T port");
    s[0].1.clone()
}

fn closed(out: &[Output]) -> Option<(String, bool)> {
    out.iter().find_map(|o| match o {
        Output::Closed { reason, retry } => Some((reason.clone(), *retry)),
        _ => None,
    })
}

/// The gateway side of one connection.
struct Gateway {
    psk: Vec<u8>,
    cky_i: [u8; 8],
    cky_r: [u8; 8],
    p1: Option<Phase1>,
    gxi: Vec<u8>,
    gxr: Vec<u8>,
    ni: Vec<u8>,
    nr: Vec<u8>,
    sai_b: Vec<u8>,
    idii_b: Vec<u8>,
    hash: Option<crate::prf::HashAlg>,
    quick: Option<GatewayQuick>,
    next_mid: u32,
}

/// The gateway's half of a quick mode in flight.
struct GatewayQuick {
    mid: u32,
    ni: Vec<u8>,
    nr: Vec<u8>,
    spi: u32,
    client_spi: u32,
    gqm: Option<Zeroizing<Vec<u8>>>,
}

struct Sent {
    mid: u32,
    msg: Vec<u8>,
}

impl Gateway {
    fn new() -> Self {
        Self {
            psk: psk(),
            cky_i: [0; 8],
            cky_r: [0x5a; 8],
            p1: None,
            gxi: Vec::new(),
            gxr: Vec::new(),
            ni: Vec::new(),
            nr: Vec::new(),
            sai_b: Vec::new(),
            idii_b: Vec::new(),
            hash: None,
            quick: None,
            next_mid: 0x0bad_0000,
        }
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

    fn material(&self) -> Material<'_> {
        Material {
            psk: &self.psk,
            ni_b: &self.ni,
            nr_b: &self.nr,
            gxy: &[],
            gxi: &self.gxi,
            gxr: &self.gxr,
            cky_i: self.cky_i,
            cky_r: self.cky_r,
        }
    }

    /// Aggressive mode, message 1 -> message 2 (choosing the client's first proposal).
    fn on_msg1(&mut self, msg1: &[u8], psk_override: Option<Vec<u8>>) -> Vec<u8> {
        let (h, body) = Header::parse(msg1).unwrap();
        assert_eq!(h.exchange, exchange::AGGRESSIVE);
        assert_eq!(h.cky_r, [0; 8]);
        let chain = Chain::parse(h.next, body).unwrap();
        self.cky_i = h.cky_i;
        self.sai_b = chain.find(payload::SA).unwrap().to_vec();
        let sa = Sa::parse(&self.sai_b).unwrap();
        let first = sa.proposals[0].transforms[0].clone();
        assert_eq!(
            find_attr(&first.attrs, 3).unwrap().as_u32(),
            65001,
            "XAuth pre-shared key method"
        );
        self.gxi = chain.find(payload::KE).unwrap().to_vec();
        self.ni = chain.find(payload::NONCE).unwrap().to_vec();
        self.idii_b = chain.find(payload::ID).unwrap().to_vec();
        let id = Id::parse(&self.idii_b).unwrap();
        assert_eq!(id.kind, id_type::FQDN);
        assert_eq!(id.data, b"laptop.example.com");
        assert!(chain.all(payload::VENDOR).any(|v| v == VID_NATT_RFC));
        let dh = KeyPair::generate(Group::Modp2048).unwrap();
        self.gxr = dh.public().to_vec();
        self.nr = vec![0x42; 24];
        let gxy = dh.agree(&self.gxi).unwrap();
        let hash = crate::prf::HashAlg::Sha256;
        self.hash = Some(hash);
        let idir = Id {
            kind: id_type::IPV4_ADDR,
            protocol: 0,
            port: 0,
            data: vec![203, 0, 113, 10],
        }
        .encode();
        let psk = psk_override.unwrap_or_else(|| self.psk.clone());
        let m = Material {
            psk: &psk,
            gxy: &gxy,
            ..self.material()
        };
        let p1 = Phase1::derive(hash, 32, &m);
        let hash_r = p1.hash_r(&m, &self.sai_b, &idir);
        self.p1 = Some(Phase1::derive(
            hash,
            32,
            &Material {
                gxy: &gxy,
                ..self.material()
            },
        ));
        let chosen = Sa {
            proposals: vec![Proposal {
                number: 1,
                protocol: protocol::ISAKMP,
                spi: Vec::new(),
                transforms: vec![first],
            }],
        };
        message(
            self.header(exchange::AGGRESSIVE, 0),
            &[
                Payload::new(payload::SA, chosen.encode()),
                Payload::new(payload::KE, self.gxr.clone()),
                Payload::new(payload::NONCE, self.nr.clone()),
                Payload::new(payload::ID, idir),
                Payload::new(payload::HASH, hash_r),
                Payload::new(payload::VENDOR, VID_NATT_RFC.to_vec()),
                Payload::new(payload::VENDOR, VID_DPD.to_vec()),
            ],
        )
    }

    /// Message 3: HASH_I must verify, and the client's NAT-D must not match its real address.
    fn on_msg3(&self, msg3: &[u8]) {
        let (h, body) = Header::parse(msg3).unwrap();
        assert!(!h.encrypted());
        let chain = Chain::parse(h.next, body).unwrap();
        let p1 = self.p1.as_ref().unwrap();
        let want = p1.hash_i(&self.material(), &self.sai_b, &self.idii_b);
        assert_eq!(chain.find(payload::HASH).unwrap(), &want[..]);
        let nat_d: Vec<&[u8]> = chain.all(payload::NAT_D).collect();
        assert_eq!(nat_d.len(), 2);
        let hash = self.hash.unwrap();
        assert_eq!(
            nat_d[0],
            &nat_hash(hash, self.cky_i, self.cky_r, gateway_addr())[..]
        );
        assert_ne!(
            nat_d[1],
            &nat_hash(hash, self.cky_i, self.cky_r, local_addr())[..]
        );
    }

    fn protected(
        &mut self,
        exchange: u8,
        mid: u32,
        prefix: &[&[u8]],
        payloads: &[Payload],
    ) -> Vec<u8> {
        let rest = encode_chain(payloads);
        let mid_b = mid.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![&mid_b];
        parts.extend_from_slice(prefix);
        parts.push(&rest);
        let hash = self.p1.as_ref().unwrap().prf_a(&parts);
        let mut all = vec![Payload::new(payload::HASH, hash)];
        all.extend_from_slice(payloads);
        let header = Header {
            next: payload::HASH,
            ..self.header(exchange, mid)
        };
        self.p1
            .as_mut()
            .unwrap()
            .encrypt(header, &encode_chain(&all))
    }

    /// Decrypts a client message, checks HASH(1)-style integrity, and returns its payloads.
    fn open(&mut self, msg: &[u8], prefix: &[&[u8]]) -> (Header, Chain) {
        let (h, body) = Header::parse(msg).unwrap();
        assert!(h.encrypted());
        let p1 = self.p1.as_mut().unwrap();
        let (plain, next) = p1.decrypt(&h, body).unwrap();
        p1.set_iv(h.mid, next);
        let chain = Chain::parse(h.next, &plain).unwrap();
        let mid_b = h.mid.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![&mid_b];
        parts.extend_from_slice(prefix);
        parts.push(chain.after_first(&plain));
        let want = p1.prf_a(&parts);
        assert_eq!(chain.payloads[0].kind, payload::HASH);
        assert!(
            bool::from(want.ct_eq(&chain.payloads[0].body)),
            "HASH(1) verifies"
        );
        (h, chain)
    }

    fn cfg(&mut self, kind: u8, mid: u32, attrs: Vec<Attribute>) -> Sent {
        let cfg = Cfg {
            kind,
            id: 0x0101,
            attrs,
        };
        let msg = self.protected(
            exchange::TRANSACTION,
            mid,
            &[],
            &[Payload::new(payload::ATTRIBUTES, cfg.encode())],
        );
        Sent { mid, msg }
    }

    fn open_cfg(&mut self, msg: &[u8]) -> (u32, Cfg) {
        let (h, chain) = self.open(msg, &[]);
        assert_eq!(h.exchange, exchange::TRANSACTION);
        (
            h.mid,
            Cfg::parse(chain.find(payload::ATTRIBUTES).unwrap()).unwrap(),
        )
    }

    /// Each informational message is its own exchange, with a fresh message ID.
    fn informational(&mut self, payloads: &[Payload]) -> Vec<u8> {
        self.next_mid += 1;
        let mid = self.next_mid;
        let msg = self.protected(exchange::INFORMATIONAL, mid, &[], payloads);
        self.p1.as_mut().unwrap().forget(mid);
        msg
    }

    /// Quick mode message 1 -> 2, choosing the client's first transform.
    fn on_qm1(&mut self, qm1: &[u8]) -> Vec<u8> {
        let (h, chain) = self.open(qm1, &[]);
        assert_eq!(h.exchange, exchange::QUICK);
        let sa = Sa::parse(chain.find(payload::SA).unwrap()).unwrap();
        let p = &sa.proposals[0];
        assert_eq!(p.protocol, protocol::ESP);
        let client_spi = u32::from_be_bytes(p.spi[..4].try_into().unwrap());
        let t = p.transforms[0].clone();
        assert_eq!(
            find_attr(&t.attrs, 4).unwrap().as_u32(),
            3,
            "UDP-encapsulated tunnel"
        );
        let ni = chain.find(payload::NONCE).unwrap().to_vec();
        let ke = chain.find(payload::KE).expect("PFS").to_vec();
        let ids: Vec<Vec<u8>> = chain.all(payload::ID).map(<[u8]>::to_vec).collect();
        assert_eq!(ids.len(), 2);
        assert_eq!(Id::parse(&ids[0]).unwrap().data, vec![10, 212, 134, 200]);
        let remote = Id::parse(&ids[1]).unwrap();
        assert_eq!(
            (remote.kind, remote.data),
            (id_type::IPV4_ADDR_SUBNET, vec![0; 8])
        );
        let dh = KeyPair::generate(Group::Modp2048).unwrap();
        let gqm = dh.agree(&ke).unwrap();
        let nr = vec![0x99; 32];
        let spi: u32 = 0x00c0_ffee;
        let reply = Sa {
            proposals: vec![Proposal {
                number: 1,
                protocol: protocol::ESP,
                spi: spi.to_be_bytes().to_vec(),
                transforms: vec![t],
            }],
        };
        let mut payloads = vec![
            Payload::new(payload::SA, reply.encode()),
            Payload::new(payload::NONCE, nr.clone()),
            Payload::new(payload::KE, dh.public().to_vec()),
        ];
        for id in ids {
            payloads.push(Payload::new(payload::ID, id));
        }
        let msg = self.protected(exchange::QUICK, h.mid, &[&ni], &payloads);
        self.quick = Some(GatewayQuick {
            mid: h.mid,
            ni,
            nr,
            spi,
            client_spi,
            gqm: Some(gqm),
        });
        msg
    }

    /// Quick mode message 3; returns the gateway's (inbound, outbound) ESP SAs.
    fn on_qm3(&mut self, qm3: &[u8]) -> (InboundSa, OutboundSa) {
        let GatewayQuick {
            mid,
            ni,
            nr,
            spi,
            client_spi,
            gqm,
        } = self.quick.take().unwrap();
        let (h, body) = Header::parse(qm3).unwrap();
        assert_eq!(h.mid, mid);
        let p1 = self.p1.as_mut().unwrap();
        let (plain, _) = p1.decrypt(&h, body).unwrap();
        let chain = Chain::parse(h.next, &plain).unwrap();
        let want = p1.prf_a(&[&[0], &mid.to_be_bytes(), &ni, &nr]);
        assert_eq!(chain.payloads.len(), 1);
        assert_eq!(chain.payloads[0].body, want, "HASH(3)");
        let keys = |spi: u32| {
            let km = p1.keymat(
                gqm.as_deref().map(Vec::as_slice),
                protocol::ESP,
                &spi.to_be_bytes(),
                (&ni, &nr),
                64,
            );
            Keys::new(
                Cipher::AesCbc(km[..32].to_vec()),
                Integrity::HmacSha256_128,
                km[32..].to_vec(),
            )
            .unwrap()
        };
        (
            InboundSa::new(spi, keys(spi), 64),
            OutboundSa::new(client_spi, keys(client_spi)),
        )
    }
}

/// Runs the handshake up to the XAuth request; returns the client, gateway and time.
fn through_phase1() -> (Initiator, Gateway, Instant) {
    let now = Instant::now();
    let mut client = Initiator::new(config(), now).unwrap();
    let out = client.start(now);
    let s = sends(&out);
    assert_eq!(s.len(), 1);
    assert!(!s[0].0, "message 1 goes to port 500");
    let mut gw = Gateway::new();
    let msg2 = gw.on_msg1(&s[0].1, None);
    let out = client.receive(now, &msg2);
    let s = sends(&out);
    assert_eq!(s.len(), 2, "message 3 and INITIAL-CONTACT: {out:?}");
    gw.on_msg3(&s[0].1);
    let (_, chain) = gw.open(&s[1].1, &[]);
    let n = Notify::parse(chain.find(payload::NOTIFY).unwrap()).unwrap();
    assert_eq!(n.kind, notify::INITIAL_CONTACT);
    (client, gw, now)
}

#[test]
fn full_connection_with_xauth_code_mode_config_quick_mode_and_esp() {
    let (mut client, mut gw, now) = through_phase1();

    // XAuth round 1: username and password, answered from the profile.
    let req = gw.cfg(
        cfg_type::REQUEST,
        0x1111,
        vec![
            Attribute::basic(attr::XAUTH_TYPE, 0),
            Attribute::variable(attr::XAUTH_USER_NAME, Vec::new()),
            Attribute::variable(attr::XAUTH_USER_PASSWORD, Vec::new()),
        ],
    );
    let out = client.receive(now, &req.msg);
    let (mid, reply) = gw.open_cfg(&one_send(&out));
    assert_eq!(mid, req.mid);
    assert_eq!(reply.kind, cfg_type::REPLY);
    assert_eq!(
        find_attr(&reply.attrs, attr::XAUTH_USER_NAME)
            .unwrap()
            .value,
        b"alice"
    );
    assert_eq!(
        find_attr(&reply.attrs, attr::XAUTH_USER_PASSWORD)
            .unwrap()
            .value,
        password().as_bytes()
    );
    // The gateway repeats its request: the same answer goes out again.
    assert_eq!(sends(&client.receive(now, &req.msg)).len(), 1);

    // XAuth round 2: a one-time code, which needs the user.
    let req = gw.cfg(
        cfg_type::REQUEST,
        0x2222,
        vec![
            Attribute::variable(attr::XAUTH_MESSAGE, b"Enter your token code".to_vec()),
            Attribute::variable(attr::XAUTH_PASSCODE, Vec::new()),
        ],
    );
    let out = client.receive(now, &req.msg);
    let prompt = out
        .iter()
        .find_map(|o| match o {
            Output::Prompt(p) => Some(p.clone()),
            _ => None,
        })
        .expect("a prompt");
    assert_eq!(prompt.fields, vec![XauthField::Passcode]);
    assert_eq!(prompt.message.as_deref(), Some("Enter your token code"));
    assert!(sends(&out).is_empty());
    assert!(client.receive(now, &req.msg).is_empty(), "no second prompt");
    let out = client.answer(vec![Zeroizing::new("246810".into())]);
    let (_, reply) = gw.open_cfg(&one_send(&out));
    assert_eq!(
        find_attr(&reply.attrs, attr::XAUTH_PASSCODE).unwrap().value,
        b"246810"
    );

    // Success: ACK, then our mode-config request.
    let set = gw.cfg(
        cfg_type::SET,
        0x3333,
        vec![Attribute::basic(attr::XAUTH_STATUS, 1)],
    );
    let out = client.receive(now, &set.msg);
    let s = sends(&out);
    assert_eq!(s.len(), 2);
    let (_, ack) = gw.open_cfg(&s[0].1);
    assert_eq!(ack.kind, cfg_type::ACK);
    let (mc_mid, request) = gw.open_cfg(&s[1].1);
    assert_eq!(request.kind, cfg_type::REQUEST);
    assert_eq!(
        find_attr(&request.attrs, attr::APPLICATION_VERSION)
            .unwrap()
            .value,
        b"Polytunnel test"
    );

    let mut split = vec![10, 1, 0, 0, 255, 255, 0, 0];
    split.extend_from_slice(&[0; 6]);
    let reply = gw.cfg(
        cfg_type::REPLY,
        mc_mid,
        vec![
            Attribute::variable(attr::INTERNAL_IP4_ADDRESS, vec![10, 212, 134, 200]),
            Attribute::variable(attr::INTERNAL_IP4_DNS, vec![10, 1, 0, 53]),
            Attribute::variable(attr::UNITY_SPLIT_INCLUDE, split),
        ],
    );
    let out = client.receive(now, &reply.msg);
    let mc = out
        .iter()
        .find_map(|o| match o {
            Output::Configured(mc) => Some(mc.clone()),
            _ => None,
        })
        .expect("configured");
    assert_eq!(
        mc,
        ModeConfig {
            address: Some(Ipv4Addr::new(10, 212, 134, 200)),
            dns: vec![Ipv4Addr::new(10, 1, 0, 53)],
            split_include: vec![(Ipv4Addr::new(10, 1, 0, 0), 16)],
            ..ModeConfig::default()
        }
    );

    // Quick mode with PFS.
    let qm2 = gw.on_qm1(&one_send(&out));
    let out = client.receive(now, &qm2);
    let child: ChildSa = out
        .into_iter()
        .find_map(|o| match o {
            Output::ChildSa(c) => Some(c),
            _ => None,
        })
        .expect("an ESP SA pair");
    assert!(client.is_established());
    assert_eq!(child.outbound_spi, 0x00c0_ffee);
    assert_eq!(child.lifetime, Duration::from_secs(3600));
    // The gateway saw our third quick-mode message.
    let qm3 = {
        // Replay QM2: the client repeats QM3 from its cache.
        let again = client.receive(now, &qm2);
        one_send(&again)
    };
    let (mut gw_in, mut gw_out) = gw.on_qm3(&qm3);

    // ESP both ways with the negotiated keys.
    let mut ours_out = OutboundSa::new(child.outbound_spi, child.outbound);
    let mut ours_in = InboundSa::new(child.inbound_spi, child.inbound, 64);
    let packet = ours_out
        .seal(NEXT_HEADER_IPV4, b"ping from the client")
        .unwrap();
    assert_eq!(
        gw_in.open(&packet).unwrap(),
        (NEXT_HEADER_IPV4, b"ping from the client".to_vec())
    );
    let packet = gw_out.seal(NEXT_HEADER_IPV4, b"pong").unwrap();
    assert_eq!(
        ours_in.open(&packet).unwrap(),
        (NEXT_HEADER_IPV4, b"pong".to_vec())
    );

    // Dead-peer detection from the gateway.
    let cookies = [gw.cky_i, gw.cky_r].concat();
    let rut = gw.informational(&[Payload::new(
        payload::NOTIFY,
        Notify {
            protocol: protocol::ISAKMP,
            spi: cookies.clone(),
            kind: notify::R_U_THERE,
            data: 7u32.to_be_bytes().to_vec(),
        }
        .encode(),
    )]);
    let out = client.receive(now, &rut);
    let (_, chain) = gw.open(&one_send(&out), &[]);
    let ack = Notify::parse(chain.find(payload::NOTIFY).unwrap()).unwrap();
    assert_eq!(
        (ack.kind, ack.data),
        (notify::R_U_THERE_ACK, 7u32.to_be_bytes().to_vec())
    );

    // Our own DPD after 20 s of silence, answered.
    let later = now + Duration::from_secs(21);
    let out = client.poll(later);
    let (_, chain) = gw.open(&one_send(&out), &[]);
    let rut = Notify::parse(chain.find(payload::NOTIFY).unwrap()).unwrap();
    assert_eq!(rut.kind, notify::R_U_THERE);
    let ack = gw.informational(&[Payload::new(
        payload::NOTIFY,
        Notify {
            kind: notify::R_U_THERE_ACK,
            ..rut
        }
        .encode(),
    )]);
    assert!(client.receive(later, &ack).is_empty());
    assert!(
        client.poll(later + Duration::from_secs(6)).is_empty(),
        "answered: no retry"
    );

    // Disconnect: delete the ESP SA, then the ISAKMP SA.
    let out = client.close();
    let s = sends(&out);
    assert_eq!(s.len(), 2);
    let (_, chain) = gw.open(&s[0].1, &[]);
    let d = Delete::parse(chain.find(payload::DELETE).unwrap()).unwrap();
    assert_eq!(d.protocol, protocol::ESP);
    assert_eq!(d.spis, vec![child.inbound_spi.to_be_bytes().to_vec()]);
    let (_, chain) = gw.open(&s[1].1, &[]);
    let d = Delete::parse(chain.find(payload::DELETE).unwrap()).unwrap();
    assert_eq!((d.protocol, d.spis), (protocol::ISAKMP, vec![cookies]));
    assert!(client.is_closed());
}

#[test]
fn wrong_pre_shared_key_is_reported() {
    let now = Instant::now();
    let mut client = Initiator::new(config(), now).unwrap();
    let msg1 = sends(&client.start(now))[0].1.clone();
    let mut gw = Gateway::new();
    let msg2 = gw.on_msg1(&msg1, Some(b"another key".to_vec()));
    let (reason, retry) = closed(&client.receive(now, &msg2)).expect("closed");
    assert!(reason.contains("pre-shared key"), "{reason}");
    assert!(!retry);
}

#[test]
fn refused_proposals_and_xauth_failures_are_explained() {
    let now = Instant::now();
    let mut client = Initiator::new(config(), now).unwrap();
    let msg1 = sends(&client.start(now))[0].1.clone();
    let (h, _) = Header::parse(&msg1).unwrap();
    let refusal = message(
        Header {
            exchange: exchange::INFORMATIONAL,
            ..h
        },
        &[Payload::new(
            payload::NOTIFY,
            Notify {
                protocol: protocol::ISAKMP,
                spi: Vec::new(),
                kind: notify::NO_PROPOSAL_CHOSEN,
                data: Vec::new(),
            }
            .encode(),
        )],
    );
    let (reason, _) = closed(&client.receive(now, &refusal)).expect("closed");
    assert!(reason.contains("Diffie-Hellman group"), "{reason}");

    let (mut client, mut gw, now) = through_phase1();
    let set = gw.cfg(
        cfg_type::SET,
        0x4444,
        vec![Attribute::basic(attr::XAUTH_STATUS, 0)],
    );
    let out = client.receive(now, &set.msg);
    let (_, ack) = gw.open_cfg(&sends(&out)[0].1);
    assert_eq!(ack.kind, cfg_type::ACK);
    let (reason, retry) = closed(&out).expect("closed");
    assert!(reason.contains("password"), "{reason}");
    assert!(!retry);
}

#[test]
fn pushed_mode_config_is_acknowledged_and_used() {
    let (mut client, mut gw, now) = through_phase1();
    // A gateway that skips XAuth status handling order: success, then pushes the settings.
    let set = gw.cfg(
        cfg_type::SET,
        0x5555,
        vec![Attribute::basic(attr::XAUTH_STATUS, 1)],
    );
    let out = client.receive(now, &set.msg);
    assert_eq!(sends(&out).len(), 2, "ACK and the pull request");
    let push = gw.cfg(
        cfg_type::SET,
        0x6666,
        vec![Attribute::variable(
            attr::INTERNAL_IP4_ADDRESS,
            vec![10, 212, 134, 200],
        )],
    );
    let out = client.receive(now, &push.msg);
    let s = sends(&out);
    assert_eq!(s.len(), 2, "ACK and quick mode: {out:?}");
    let (_, ack) = gw.open_cfg(&s[0].1);
    assert_eq!(ack.kind, cfg_type::ACK);
    assert!(out.iter().any(|o| matches!(o, Output::Configured(_))));
}

#[test]
fn silence_is_retransmitted_then_reported() {
    let now = Instant::now();
    let mut client = Initiator::new(config(), now).unwrap();
    let first = sends(&client.start(now))[0].1.clone();
    assert!(client.poll(now + Duration::from_secs(1)).is_empty());
    let mut t = now;
    for delay in [2, 2, 4, 8] {
        t += Duration::from_secs(delay);
        let s = sends(&client.poll(t));
        assert_eq!(
            s,
            vec![(false, first.clone())],
            "retransmission at +{delay}s"
        );
    }
    t += Duration::from_secs(8);
    let (reason, retry) = closed(&client.poll(t)).expect("gave up");
    assert!(reason.contains("stopped answering"), "{reason}");
    assert!(retry);
}

#[test]
fn messages_from_strangers_are_ignored() {
    let (mut client, mut gw, now) = through_phase1();
    // Wrong cookie, garbage, a truncated header.
    let mut other = gw.cfg(cfg_type::REQUEST, 9, vec![]).msg;
    other[0] ^= 0xff;
    assert!(client.receive(now, &other).is_empty());
    assert!(client.receive(now, b"\xff").is_empty());
    assert!(client.receive(now, &[0u8; 20]).is_empty());
    // A message with a bad HASH is dropped without disturbing the session.
    let mut forged = gw.cfg(cfg_type::REQUEST, 10, vec![]).msg;
    let n = forged.len();
    forged[n - 20] ^= 1;
    assert!(client.receive(now, &forged).is_empty());
    assert!(!client.is_closed());
}

/// A small xorshift generator: reproducible "fuzzing" without extra tools.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    /// Flips, overwrites, truncates or extends a valid message.
    fn mutate(&mut self, msg: &[u8]) -> Vec<u8> {
        let mut m = msg.to_vec();
        for _ in 0..1 + self.below(4) {
            match self.below(4) {
                0 if !m.is_empty() => {
                    let i = self.below(m.len());
                    m[i] ^= 1 << self.below(8);
                }
                1 if !m.is_empty() => {
                    let i = self.below(m.len());
                    m[i] = self.next() as u8;
                }
                2 => m.truncate(self.below(m.len() + 1)),
                _ => {
                    let extra = self.below(40);
                    m.extend(self.bytes(extra));
                }
            }
        }
        m
    }
}

#[test]
fn parsers_survive_garbage() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..20_000 {
        let n = rng.below(300);
        let data = rng.bytes(n);
        let first = data.first().copied().unwrap_or(1) % 16;
        let _ = Header::parse(&data);
        let _ = Chain::parse(first, &data);
        let _ = Sa::parse(&data);
        let _ = Id::parse(&data);
        let _ = Notify::parse(&data);
        let _ = Delete::parse(&data);
        let _ = Cfg::parse(&data);
        let _ = ModeConfig::parse(&super::wire::parse_attributes(&data).unwrap_or_default());
    }
}

#[test]
fn the_initiator_survives_mutated_messages_in_every_phase() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    // Before phase 1: mutations of a real message 2.
    for _ in 0..300 {
        let now = Instant::now();
        let mut client = Initiator::new(config(), now).unwrap();
        let msg1 = sends(&client.start(now))[0].1.clone();
        let mut gw = Gateway::new();
        let msg2 = gw.on_msg1(&msg1, None);
        let _ = client.receive(now, &rng.mutate(&msg2));
        let _ = client.poll(now + Duration::from_secs(3));
    }
    // After phase 1: mutated encrypted requests and garbage with the right cookies.
    let (mut client, mut gw, now) = through_phase1();
    let request = gw
        .cfg(
            cfg_type::REQUEST,
            0x7777,
            vec![Attribute::variable(attr::XAUTH_USER_NAME, Vec::new())],
        )
        .msg;
    for i in 0..3000 {
        let message = if i % 3 == 0 {
            let mut m = request[..28].to_vec();
            let n = rng.below(200);
            m.extend(rng.bytes(n));
            let len = u32::try_from(m.len()).unwrap();
            m[24..28].copy_from_slice(&len.to_be_bytes());
            m
        } else {
            rng.mutate(&request)
        };
        // Not panicking is the point; the session may or may not survive the garbage.
        let _ = client.receive(now, &message);
    }
}
