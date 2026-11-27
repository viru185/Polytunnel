//! The IKEv2 initiator against a scripted gateway: every exchange end to end, then ESP
//! packets with the negotiated keys. Interop with strongSwan and libreswan runs in CI.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use polytunnel_esp::{InboundSa, NEXT_HEADER_IPV4, OutboundSa};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair,
};
use zeroize::Zeroizing;

use super::auth::{Trust, shared_key_auth, shared_key_ok, signed_octets};
use super::config::{ClientAuth, Config, ServerAuth};
use super::crypto::{IkeKeys, IkeSuite};
use super::initiator::{Initiator, esp_keys, match_esp, nat_hash};
use super::wire::{
    self, CERT_X509_SIGNATURE, Chain, Delete, Header, Notify, Payload, Proposal, Selector,
    auth_method, cp, encode_chain, exchange, flag, id_type, notify, payload, protocol,
};
use crate::dh::{Group, KeyPair as DhKeyPair};
use crate::eap::{self, EapMethod, mschapv2};
use crate::session::{ChildSa, Output, Session};
use crate::v1::cfg::ModeConfig;
use crate::v1::config::{EspProposal, Identity};

fn psk() -> Vec<u8> {
    ["ikev2", "test", "key"].join("-").into_bytes()
}

fn password() -> String {
    ["not", "a", "secret"].concat()
}

fn gateway_addr() -> SocketAddr {
    "203.0.113.20:500".parse().unwrap()
}

fn config(client: ClientAuth, server: ServerAuth) -> Config {
    Config {
        ike: vec![
            IkeSuite::parse("aes256-sha256-modp2048").unwrap(),
            IkeSuite::parse("aes128gcm16-prfsha256-ecp256").unwrap(),
        ],
        esp: vec![
            EspProposal::parse("aes256-sha256").unwrap(),
            EspProposal::parse("aes128gcm16").unwrap(),
        ],
        pfs: Some(Group::Modp2048),
        ike_lifetime: Duration::from_secs(8 * 3600),
        esp_lifetime: Duration::from_secs(3600),
        local_id: Some(Identity::Fqdn("laptop.example.com".into())),
        client_auth: client,
        server_auth: server,
        remote_network: (Ipv4Addr::UNSPECIFIED, 0),
        dpd: Some(Duration::from_secs(30)),
        local: "192.0.2.30:41000".parse().unwrap(),
        remote: gateway_addr(),
        reliable: false,
    }
}

fn psk_config() -> Config {
    config(
        ClientAuth::Psk(Zeroizing::new(psk())),
        ServerAuth::Psk(Zeroizing::new(psk())),
    )
}

fn sends(out: &[Output]) -> Vec<(bool, Vec<u8>)> {
    out.iter()
        .filter_map(|o| match o {
            Output::Send { natt, message } => Some((*natt, message.clone())),
            _ => None,
        })
        .collect()
}

fn one(out: &[Output]) -> Vec<u8> {
    let s = sends(out);
    assert_eq!(s.len(), 1, "expected one message: {out:?}");
    s[0].1.clone()
}

fn closed(out: &[Output]) -> Option<String> {
    out.iter().find_map(|o| match o {
        Output::Closed { reason, .. } => Some(reason.clone()),
        _ => None,
    })
}

fn child(out: Vec<Output>) -> ChildSa {
    out.into_iter()
        .find_map(|o| match o {
            Output::ChildSa(c) => Some(c),
            _ => None,
        })
        .expect("an SA pair")
}

/// The gateway's certificate and signing key.
struct Signer {
    ca_pem: String,
    leaf: Vec<u8>,
    pkcs8: Vec<u8>,
}

fn signer(name: &str) -> Signer {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca = CertifiedIssuer::self_signed(ca, ca_key).unwrap();
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf = CertificateParams::new(vec![name.to_string()]).unwrap();
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf.signed_by(&key, &ca).unwrap();
    Signer {
        ca_pem: ca.pem(),
        leaf: leaf.der().to_vec(),
        pkcs8: key.serialize_der(),
    }
}

/// The responder side of one connection.
struct Gateway {
    suite: IkeSuite,
    spi_i: [u8; 8],
    spi_r: [u8; 8],
    keys: Option<IkeKeys>,
    ni: Vec<u8>,
    nr: Vec<u8>,
    init_request: Vec<u8>,
    init_response: Vec<u8>,
    idi: Vec<u8>,
    idr: Vec<u8>,
    psk: Vec<u8>,
    mid: u32,
    spi: u32,
    msk: Option<Vec<u8>>,
    mschap: Option<([u8; 16], [u8; 16], [u8; 24])>,
}

impl Gateway {
    fn new(suite: &str) -> Self {
        Self {
            suite: IkeSuite::parse(suite).unwrap(),
            spi_i: [0; 8],
            spi_r: [0x6b; 8],
            keys: None,
            ni: Vec::new(),
            nr: Vec::new(),
            init_request: Vec::new(),
            init_response: Vec::new(),
            idi: Vec::new(),
            idr: wire::encode_id(id_type::FQDN, b"gateway.test"),
            psk: psk(),
            mid: 0,
            spi: 0x00c0_ffee,
            msk: None,
            mschap: None,
        }
    }

    fn keys(&self) -> &IkeKeys {
        self.keys.as_ref().unwrap()
    }

    fn header(&self, exchange: u8, mid: u32, response: bool) -> Header {
        Header {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            next: 0,
            exchange,
            flags: if response { flag::RESPONSE } else { 0 },
            mid,
            len: 0,
        }
    }

    fn plain(&self, header: Header, payloads: &[Payload]) -> Vec<u8> {
        let body = encode_chain(payloads);
        let header = Header {
            next: payloads[0].kind,
            ..header
        };
        [header.encode(body.len()).to_vec(), body].concat()
    }

    /// IKE_SA_INIT request -> response (or a refusal made by `refuse`).
    fn on_init(&mut self, request: &[u8]) -> Vec<u8> {
        let (h, body) = Header::parse(request).unwrap();
        assert_eq!(
            (h.exchange, h.flags),
            (exchange::IKE_SA_INIT, flag::INITIATOR)
        );
        let chain = Chain::parse(h.next, body, 28).unwrap();
        self.spi_i = h.spi_i;
        let proposals = wire::parse_sa(chain.find(payload::SA).unwrap()).unwrap();
        let chosen = proposals
            .iter()
            .find(|p| self.suite.matches(p))
            .expect("our suite offered")
            .clone();
        let (group, ke) = wire::parse_ke(chain.find(payload::KE).unwrap()).unwrap();
        assert_eq!(group, self.suite.group.id(), "KE in the agreed group");
        assert!(chain.notify(notify::NAT_DETECTION_SOURCE_IP).is_some());
        let dst = chain.notify(notify::NAT_DETECTION_DESTINATION_IP).unwrap();
        assert_eq!(dst.data, nat_hash(self.spi_i, [0; 8], gateway_addr()));
        self.ni = chain.find(payload::NONCE).unwrap().to_vec();
        self.nr = vec![0x77; 32];
        let dh = DhKeyPair::generate(self.suite.group).unwrap();
        let gir = dh.agree(ke).unwrap();
        self.keys = Some(IkeKeys::derive(
            self.suite,
            (&self.ni, &self.nr),
            &gir,
            (self.spi_i, self.spi_r),
        ));
        self.init_request = request.to_vec();
        let response = self.plain(
            self.header(exchange::IKE_SA_INIT, 0, true),
            &[
                Payload::new(payload::SA, wire::encode_sa(&[chosen])),
                Payload::new(payload::KE, wire::encode_ke(group, dh.public())),
                Payload::new(payload::NONCE, self.nr.clone()),
            ],
        );
        self.init_response = response.clone();
        response
    }

    /// Decrypts a client message (and checks it is from the initiator).
    fn open(&self, message: &[u8]) -> (Header, Chain) {
        let (h, body) = Header::parse(message).unwrap();
        assert!(h.flags & flag::INITIATOR != 0);
        let enc = Chain::parse(h.next, body, 28).unwrap().encrypted.unwrap();
        let plain = self.keys().decrypt(true, message, &enc).unwrap();
        (h, Chain::parse(enc.inner_next, &plain, 0).unwrap())
    }

    fn respond(&self, mid: u32, exchange: u8, inner: &[Payload]) -> Vec<u8> {
        self.keys()
            .encrypt(false, self.header(exchange, mid, true), inner)
    }

    fn request(&mut self, exchange: u8, inner: &[Payload]) -> Vec<u8> {
        let mid = self.mid;
        self.mid += 1;
        self.keys()
            .encrypt(false, self.header(exchange, mid, false), inner)
    }

    fn responder_octets(&self) -> Vec<u8> {
        signed_octets(
            &self.init_response,
            &self.ni,
            self.suite.prf,
            self.keys().sk_pr(),
            &self.idr,
        )
    }

    fn initiator_octets(&self) -> Vec<u8> {
        signed_octets(
            &self.init_request,
            &self.nr,
            self.suite.prf,
            self.keys().sk_pi(),
            &self.idi,
        )
    }

    /// The final IKE_AUTH reply: address, DNS, narrowed selectors and the child SA.
    fn finish(&self, chain: &Chain, mid: u32, auth: Vec<u8>) -> (Vec<u8>, InboundSa, OutboundSa) {
        let esp = [EspProposal::parse("aes256-sha256").unwrap()];
        let proposals = wire::parse_sa(chain.find(payload::SA).unwrap()).unwrap();
        let (offer, proposal) = proposals
            .iter()
            .find_map(|p| match_esp(&esp, p, None).map(|e| (p.clone(), e)))
            .unwrap();
        let client_spi = u32::from_be_bytes(offer.spi[..4].try_into().unwrap());
        let km = self
            .keys()
            .child_keymat(None, &self.ni, &self.nr, 2 * proposal.keymat_len());
        let (i2r, r2i) = km.split_at(proposal.keymat_len());
        let reply = self.respond(
            mid,
            exchange::IKE_AUTH,
            &[
                Payload::new(payload::IDR, self.idr.clone()),
                Payload::new(payload::AUTH, auth),
                Payload::new(
                    payload::CP,
                    wire::encode_cp(
                        cp::REPLY,
                        &[
                            (cp::INTERNAL_IP4_ADDRESS, vec![198, 51, 100, 77]),
                            (cp::INTERNAL_IP4_DNS, vec![198, 51, 100, 53]),
                            (cp::INTERNAL_DNS_DOMAIN, b"corp.example.com".to_vec()),
                        ],
                    ),
                ),
                Payload::new(
                    payload::SA,
                    wire::encode_sa(&[Proposal {
                        spi: self.spi.to_be_bytes().to_vec(),
                        ..offer
                    }]),
                ),
                Payload::new(
                    payload::TSI,
                    wire::encode_ts(&[Selector::host(Ipv4Addr::new(198, 51, 100, 77))]),
                ),
                Payload::new(
                    payload::TSR,
                    wire::encode_ts(&[Selector::network(Ipv4Addr::new(198, 51, 100, 0), 24)]),
                ),
            ],
        );
        (
            reply,
            InboundSa::new(self.spi, esp_keys(&proposal, i2r).unwrap(), 64),
            OutboundSa::new(client_spi, esp_keys(&proposal, r2i).unwrap()),
        )
    }
}

fn assert_esp(c: ChildSa, gw_in: &mut InboundSa, gw_out: &mut OutboundSa) {
    let mut ours_out = OutboundSa::new(c.outbound_spi, c.outbound);
    let mut ours_in = InboundSa::new(c.inbound_spi, c.inbound, 64);
    let p = ours_out.seal(NEXT_HEADER_IPV4, b"to the gateway").unwrap();
    assert_eq!(gw_in.open(&p).unwrap().1, b"to the gateway");
    let p = gw_out.seal(NEXT_HEADER_IPV4, b"to the client").unwrap();
    assert_eq!(ours_in.open(&p).unwrap().1, b"to the client");
}

/// Runs IKE_SA_INIT; returns the client's IKE_AUTH request.
fn init(client: &mut Initiator, gw: &mut Gateway, now: Instant) -> Vec<u8> {
    let s = sends(&client.start(now));
    assert_eq!(s.len(), 1);
    assert!(!s[0].0, "IKE_SA_INIT goes to port 500");
    let response = gw.on_init(&s[0].1);
    let s = sends(&client.receive(now, &response));
    assert_eq!(s.len(), 1);
    assert!(s[0].0, "IKE_AUTH goes to the NAT-T port");
    s[0].1.clone()
}

#[test]
fn psk_connection_rekeys_liveness_and_close() {
    let now = Instant::now();
    let mut client = Initiator::new(psk_config(), now).unwrap();
    let mut gw = Gateway::new("aes256-sha256-modp2048");
    let auth_request = init(&mut client, &mut gw, now);

    let (h, chain) = gw.open(&auth_request);
    assert_eq!((h.exchange, h.mid), (exchange::IKE_AUTH, 1));
    gw.idi = chain.find(payload::IDI).unwrap().to_vec();
    assert_eq!(
        gw.idi,
        wire::encode_id(id_type::FQDN, b"laptop.example.com")
    );
    let (method, data) = wire::parse_auth(chain.find(payload::AUTH).unwrap()).unwrap();
    assert_eq!(method, auth_method::PSK);
    assert!(shared_key_ok(
        gw.suite.prf,
        &gw.psk,
        &gw.initiator_octets(),
        data
    ));
    assert!(chain.notify(notify::INITIAL_CONTACT).is_some());
    let auth = wire::encode_auth(
        auth_method::PSK,
        &shared_key_auth(gw.suite.prf, &gw.psk, &gw.responder_octets()),
    );
    let (reply, mut gw_in, mut gw_out) = gw.finish(&chain, 1, auth);
    let out = client.receive(now, &reply);
    let mc = out
        .iter()
        .find_map(|o| match o {
            Output::Configured(mc) => Some(mc.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        mc,
        ModeConfig {
            address: Some(Ipv4Addr::new(198, 51, 100, 77)),
            dns: vec![Ipv4Addr::new(198, 51, 100, 53)],
            split_include: vec![(Ipv4Addr::new(198, 51, 100, 0), 24)],
            split_dns: vec!["corp.example.com".into()],
            ..ModeConfig::default()
        }
    );
    let first = child(out);
    assert_eq!(first.outbound_spi, gw.spi);
    let first_inbound = first.inbound_spi;
    assert_esp(first, &mut gw_in, &mut gw_out);
    assert!(client.is_established());

    // The gateway checks liveness; a repeat of its request gets the same answer.
    let ping = gw.request(exchange::INFORMATIONAL, &[]);
    let answer = one(&client.receive(now, &ping));
    let (h, chain) = gw.open(&answer);
    assert!(h.is_response() && chain.payloads.is_empty());
    assert_eq!(one(&client.receive(now, &ping)), answer);

    // Our liveness check after 30 s of silence.
    let t = now + Duration::from_secs(31);
    let check = one(&client.poll(t));
    let (h, chain) = gw.open(&check);
    assert_eq!(
        (h.exchange, h.mid, chain.payloads.len()),
        (exchange::INFORMATIONAL, 2, 0)
    );
    assert!(
        client
            .receive(t, &gw.respond(2, exchange::INFORMATIONAL, &[]))
            .is_empty()
    );

    // Our rekey, with PFS, before the hour is up.
    let t = now + Duration::from_secs(3300);
    let rekey = one(&client.poll(t));
    let (h, chain) = gw.open(&rekey);
    assert_eq!(h.exchange, exchange::CREATE_CHILD_SA);
    let rekey_sa = chain.notify(notify::REKEY_SA).unwrap();
    assert_eq!(rekey_sa.spi, first_inbound.to_be_bytes());
    let esp = [EspProposal::parse("aes256-sha256").unwrap()];
    let proposals = wire::parse_sa(chain.find(payload::SA).unwrap()).unwrap();
    let (offer, proposal) = proposals
        .iter()
        .find_map(|p| match_esp(&esp, p, Some(Group::Modp2048)).map(|e| (p.clone(), e)))
        .unwrap();
    let (_, ke) = wire::parse_ke(chain.find(payload::KE).unwrap()).unwrap();
    let ni = chain.find(payload::NONCE).unwrap().to_vec();
    let dh = DhKeyPair::generate(Group::Modp2048).unwrap();
    let gir = dh.agree(ke).unwrap();
    let nr = vec![0x31; 32];
    let new_spi: u32 = 0x0bad_f00d;
    let km = gw
        .keys()
        .child_keymat(Some(&gir), &ni, &nr, 2 * proposal.keymat_len());
    let (i2r, r2i) = km.split_at(proposal.keymat_len());
    let client_spi = u32::from_be_bytes(offer.spi[..4].try_into().unwrap());
    let reply = gw.respond(
        h.mid,
        exchange::CREATE_CHILD_SA,
        &[
            Payload::new(
                payload::SA,
                wire::encode_sa(&[Proposal {
                    spi: new_spi.to_be_bytes().to_vec(),
                    ..offer
                }]),
            ),
            Payload::new(payload::NONCE, nr),
            Payload::new(payload::KE, wire::encode_ke(14, dh.public())),
            Payload::new(payload::TSI, wire::encode_ts(&[Selector::ANY])),
            Payload::new(payload::TSR, wire::encode_ts(&[Selector::ANY])),
        ],
    );
    let second = child(client.receive(t, &reply));
    assert_eq!(second.outbound_spi, new_spi);
    let mut gw_in = InboundSa::new(new_spi, esp_keys(&proposal, i2r).unwrap(), 64);
    let mut gw_out = OutboundSa::new(client_spi, esp_keys(&proposal, r2i).unwrap());
    assert_esp(second, &mut gw_in, &mut gw_out);

    // The old SA is retired 20 s later and deleted at the gateway.
    let out = client.poll(t + Duration::from_secs(21));
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Retire { inbound_spi } if *inbound_spi == first_inbound))
    );
    let (h, chain) = gw.open(&one(&out));
    let d = Delete::parse(chain.find(payload::DELETE).unwrap()).unwrap();
    assert_eq!((d.protocol, d.spis), (protocol::ESP, vec![first_inbound]));
    let t2 = t + Duration::from_secs(21);
    assert!(
        client
            .receive(t2, &gw.respond(h.mid, exchange::INFORMATIONAL, &[]))
            .is_empty()
    );

    // The gateway rekeys too: we answer as the responder.
    let gw_ni = vec![0x41; 32];
    let gw_dh = DhKeyPair::generate(Group::Modp2048).unwrap();
    let gw_spi: u32 = 0x1234_5678;
    let mut offer = esp_proposal_for(&proposal, gw_spi);
    offer.transforms.insert(
        offer.transforms.len() - 1,
        wire::Transform::new(wire::transform::DH, 14),
    );
    let request = gw.request(
        exchange::CREATE_CHILD_SA,
        &[
            Payload::new(
                payload::NOTIFY,
                Notify {
                    protocol: protocol::ESP,
                    spi: new_spi.to_be_bytes().to_vec(),
                    kind: notify::REKEY_SA,
                    data: Vec::new(),
                }
                .encode(),
            ),
            Payload::new(payload::SA, wire::encode_sa(&[offer])),
            Payload::new(payload::NONCE, gw_ni.clone()),
            Payload::new(payload::KE, wire::encode_ke(14, gw_dh.public())),
            Payload::new(payload::TSI, wire::encode_ts(&[Selector::ANY])),
            Payload::new(payload::TSR, wire::encode_ts(&[Selector::ANY])),
        ],
    );
    let out = client.receive(t2, &request);
    let third_reply = one(&out);
    let third = child(out);
    assert_eq!(third.outbound_spi, gw_spi);
    let (h, chain) = gw.open(&third_reply);
    assert!(h.is_response());
    let client_nr = chain.find(payload::NONCE).unwrap().to_vec();
    let (_, client_ke) = wire::parse_ke(chain.find(payload::KE).unwrap()).unwrap();
    let gir = gw_dh.agree(client_ke).unwrap();
    // The gateway started this exchange: its keys come first.
    let km = gw
        .keys()
        .child_keymat(Some(&gir), &gw_ni, &client_nr, 2 * proposal.keymat_len());
    let (i2r, r2i) = km.split_at(proposal.keymat_len());
    let mut gw_in = InboundSa::new(gw_spi, esp_keys(&proposal, r2i).unwrap(), 64);
    let mut gw_out = OutboundSa::new(third.inbound_spi, esp_keys(&proposal, i2r).unwrap());
    assert_esp(third, &mut gw_in, &mut gw_out);

    // Disconnect: delete the IKE SA.
    let (_, chain) = gw.open(&one(&client.close()));
    let d = Delete::parse(chain.find(payload::DELETE).unwrap()).unwrap();
    assert_eq!(d.protocol, protocol::IKE);
    assert!(client.is_closed());
}

/// An ESP proposal the gateway makes for `p` with SPI `spi` (IKEv2 transforms).
fn esp_proposal_for(p: &EspProposal, spi: u32) -> Proposal {
    super::initiator::esp_proposals(std::slice::from_ref(p), spi, None).remove(0)
}

#[test]
fn eap_mschapv2_with_a_certificate_gateway() {
    let s = signer("gateway.test");
    let trust = Trust::new(s.ca_pem.as_bytes(), false, "gateway.test".into()).unwrap();
    let now = Instant::now();
    let client_auth = ClientAuth::Eap {
        method: EapMethod::MsChapV2,
        username: "alice".into(),
        password: Zeroizing::new(password()),
    };
    let mut client =
        Initiator::new(config(client_auth, ServerAuth::Certificate(trust)), now).unwrap();
    let mut gw = Gateway::new("aes256-sha256-modp2048");
    let request = init(&mut client, &mut gw, now);
    let (h, chain) = gw.open(&request);
    assert!(chain.find(payload::AUTH).is_none(), "EAP: no AUTH yet");
    let auth_chain = chain;
    gw.idi = auth_chain.find(payload::IDI).unwrap().to_vec();

    // The gateway proves itself with its certificate (ECDSA, raw r|s) and starts EAP.
    let rng = SystemRandom::new();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &s.pkcs8, &rng).unwrap();
    let sig = key.sign(&rng, &gw.responder_octets()).unwrap();
    let mut cert = vec![CERT_X509_SIGNATURE];
    cert.extend_from_slice(&s.leaf);
    let reply = gw.respond(
        h.mid,
        exchange::IKE_AUTH,
        &[
            Payload::new(payload::IDR, gw.idr.clone()),
            Payload::new(payload::CERT, cert),
            Payload::new(
                payload::AUTH,
                wire::encode_auth(auth_method::ECDSA_256, sig.as_ref()),
            ),
            Payload::new(payload::EAP, vec![1, 1, 0, 5, eap::kind::IDENTITY]),
        ],
    );
    let (h, chain) = gw.open(&one(&client.receive(now, &reply)));
    assert_eq!(
        chain.find(payload::EAP).unwrap(),
        [&[2, 1, 0, 10, 1][..], b"alice"].concat()
    );

    // MSCHAPv2 challenge.
    let authenticator = [0x24; 16];
    let mut challenge = vec![1, 2, 0, 0, eap::kind::MSCHAPV2, 1, 7, 0, 23, 16];
    challenge.extend_from_slice(&authenticator);
    challenge.extend_from_slice(b"gw");
    challenge[3] = u8::try_from(challenge.len()).unwrap();
    let reply = gw.respond(
        h.mid,
        exchange::IKE_AUTH,
        &[Payload::new(payload::EAP, challenge)],
    );
    let (h, chain) = gw.open(&one(&client.receive(now, &reply)));
    let response = chain.find(payload::EAP).unwrap();
    let peer: [u8; 16] = response[10..26].try_into().unwrap();
    let nt: [u8; 24] = response[34..58].try_into().unwrap();
    assert_eq!(
        nt,
        mschapv2::nt_response(&authenticator, &peer, b"alice", &password())
    );
    gw.mschap = Some((authenticator, peer, nt));

    // MSCHAPv2 success with the authenticator response, then EAP-Success.
    let proof = mschapv2::authenticator_response(&password(), &nt, &peer, &authenticator, b"alice");
    let mut success = vec![1, 3, 0, 0, eap::kind::MSCHAPV2, 3, 7, 0, 46];
    success.extend_from_slice(proof.as_bytes());
    success[3] = u8::try_from(success.len()).unwrap();
    let reply = gw.respond(
        h.mid,
        exchange::IKE_AUTH,
        &[Payload::new(payload::EAP, success)],
    );
    let (h, chain) = gw.open(&one(&client.receive(now, &reply)));
    assert_eq!(
        chain.find(payload::EAP).unwrap(),
        [2, 3, 0, 6, eap::kind::MSCHAPV2, 3]
    );
    let reply = gw.respond(
        h.mid,
        exchange::IKE_AUTH,
        &[Payload::new(payload::EAP, vec![3, 4, 0, 4])],
    );

    // Both sides prove themselves again with the MSK.
    let (h, chain) = gw.open(&one(&client.receive(now, &reply)));
    let msk = mschapv2::msk(&password(), &nt).to_vec();
    let (method, data) = wire::parse_auth(chain.find(payload::AUTH).unwrap()).unwrap();
    assert_eq!(method, auth_method::PSK);
    assert!(shared_key_ok(
        gw.suite.prf,
        &msk,
        &gw.initiator_octets(),
        data
    ));
    gw.msk = Some(msk.clone());
    let auth = wire::encode_auth(
        auth_method::PSK,
        &shared_key_auth(gw.suite.prf, &msk, &gw.responder_octets()),
    );
    let (reply, mut gw_in, mut gw_out) = gw.finish(&auth_chain, h.mid, auth);
    let c = child(client.receive(now, &reply));
    assert_esp(c, &mut gw_in, &mut gw_out);
    assert!(client.is_established());
}

#[test]
fn certificate_checks() {
    let s = signer("gateway.test");
    let octets = b"signed octets".to_vec();
    let rng = SystemRandom::new();
    // RFC 7427: ECDSA with SHA-256, DER signature, behind its AlgorithmIdentifier.
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &s.pkcs8, &rng).unwrap();
    let sig = key.sign(&rng, &octets).unwrap();
    let alg_id = [
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    ];
    let auth = [
        &[u8::try_from(alg_id.len()).unwrap()][..],
        &alg_id,
        sig.as_ref(),
    ]
    .concat();
    let trust = Trust::new(s.ca_pem.as_bytes(), false, "gateway.test".into()).unwrap();
    let leaf = vec![s.leaf.clone()];
    assert_eq!(
        trust.verify(&leaf, auth_method::DIGITAL_SIGNATURE, &auth, &octets),
        Ok(())
    );
    let err = trust
        .verify(
            &leaf,
            auth_method::DIGITAL_SIGNATURE,
            &auth,
            b"other octets",
        )
        .unwrap_err();
    assert!(err.contains("signature"), "{err}");
    let wrong_name = Trust::new(s.ca_pem.as_bytes(), false, "other.test".into()).unwrap();
    let err = wrong_name
        .verify(&leaf, auth_method::DIGITAL_SIGNATURE, &auth, &octets)
        .unwrap_err();
    assert!(err.contains("remote-id"), "{err}");
    let stranger = signer("gateway.test");
    let untrusted = Trust::new(stranger.ca_pem.as_bytes(), false, "gateway.test".into()).unwrap();
    let err = untrusted
        .verify(&leaf, auth_method::DIGITAL_SIGNATURE, &auth, &octets)
        .unwrap_err();
    assert!(err.contains("not trusted"), "{err}");
    assert!(
        trust
            .verify(&[], auth_method::DIGITAL_SIGNATURE, &auth, &octets)
            .is_err()
    );
}

#[test]
fn cookies_and_group_changes_are_followed() {
    let now = Instant::now();
    let mut cfg = psk_config();
    cfg.ike = vec![
        IkeSuite::parse("aes256-sha256-modp2048").unwrap(),
        IkeSuite::parse("aes128gcm16-prfsha256-ecp256").unwrap(),
    ];
    let mut client = Initiator::new(cfg, now).unwrap();
    let first = one(&client.start(now));
    let (h, _) = Header::parse(&first).unwrap();
    let gw = Gateway::new("aes128gcm16-prfsha256-ecp256");
    // A cookie: the request comes back with it first.
    let cookie = gw.plain(
        Header {
            spi_i: h.spi_i,
            spi_r: [0; 8],
            ..gw.header(exchange::IKE_SA_INIT, 0, true)
        },
        &[Payload::new(
            payload::NOTIFY,
            Notify::new(notify::COOKIE, vec![0xc0; 16]).encode(),
        )],
    );
    let again = one(&client.receive(now, &cookie));
    let (h2, body) = Header::parse(&again).unwrap();
    let chain = Chain::parse(h2.next, body, 28).unwrap();
    assert_eq!(chain.payloads[0].kind, payload::NOTIFY);
    assert_eq!(chain.notify(notify::COOKIE).unwrap().data, vec![0xc0; 16]);
    // The gateway wants ECP-256: the client switches its key exchange.
    let invalid_ke = gw.plain(
        Header {
            spi_i: h.spi_i,
            spi_r: [0; 8],
            ..gw.header(exchange::IKE_SA_INIT, 0, true)
        },
        &[Payload::new(
            payload::NOTIFY,
            Notify::new(notify::INVALID_KE_PAYLOAD, 19u16.to_be_bytes().to_vec()).encode(),
        )],
    );
    let third = one(&client.receive(now, &invalid_ke));
    let (h3, body) = Header::parse(&third).unwrap();
    let chain = Chain::parse(h3.next, body, 28).unwrap();
    assert_eq!(
        wire::parse_ke(chain.find(payload::KE).unwrap()).unwrap().0,
        19
    );
    // ... and the exchange completes in that group (with AES-GCM for IKE).
    let mut gw = gw;
    let reply = gw.on_init(&third);
    assert_eq!(sends(&client.receive(now, &reply)).len(), 1);
}

#[test]
fn failures_are_explained() {
    // The gateway's proof made with another key.
    let now = Instant::now();
    let mut client = Initiator::new(psk_config(), now).unwrap();
    let mut gw = Gateway::new("aes256-sha256-modp2048");
    let request = init(&mut client, &mut gw, now);
    let (h, chain) = gw.open(&request);
    gw.idi = chain.find(payload::IDI).unwrap().to_vec();
    let wrong = wire::encode_auth(
        auth_method::PSK,
        &shared_key_auth(gw.suite.prf, b"another key", &gw.responder_octets()),
    );
    let (reply, _, _) = gw.finish(&chain, h.mid, wrong);
    let reason = closed(&client.receive(now, &reply)).unwrap();
    assert!(reason.contains("pre-shared key"), "{reason}");

    // AUTHENTICATION_FAILED from the gateway.
    let mut client = Initiator::new(psk_config(), now).unwrap();
    let mut gw = Gateway::new("aes256-sha256-modp2048");
    let request = init(&mut client, &mut gw, now);
    let (h, _) = gw.open(&request);
    let refusal = gw.respond(
        h.mid,
        exchange::IKE_AUTH,
        &[Payload::new(
            payload::NOTIFY,
            Notify::new(notify::AUTHENTICATION_FAILED, Vec::new()).encode(),
        )],
    );
    let reason = closed(&client.receive(now, &refusal)).unwrap();
    assert!(reason.contains("authentication failed"), "{reason}");

    // Silence: retransmissions, then give up.
    let mut client = Initiator::new(psk_config(), now).unwrap();
    let first = one(&client.start(now));
    let mut t = now;
    for delay in [2, 2, 4, 8] {
        t += Duration::from_secs(delay);
        assert_eq!(sends(&client.poll(t)), vec![(false, first.clone())]);
    }
    t += Duration::from_secs(8);
    assert!(
        closed(&client.poll(t))
            .unwrap()
            .contains("stopped answering")
    );
}

#[test]
fn a_fragmented_reply_is_reassembled() {
    let now = Instant::now();
    let mut client = Initiator::new(psk_config(), now).unwrap();
    let mut gw = Gateway::new("aes256-sha256-modp2048");
    let request = init(&mut client, &mut gw, now);
    let (h, chain) = gw.open(&request);
    gw.idi = chain.find(payload::IDI).unwrap().to_vec();
    let auth = wire::encode_auth(
        auth_method::PSK,
        &shared_key_auth(gw.suite.prf, &gw.psk, &gw.responder_octets()),
    );
    let (whole, _, _) = gw.finish(&chain, h.mid, auth);
    // Recover the reply's payload bytes, then send them as three fragments, last one first.
    let (wh, body) = Header::parse(&whole).unwrap();
    let enc = Chain::parse(wh.next, body, 28).unwrap().encrypted.unwrap();
    let plain = gw.keys().decrypt(false, &whole, &enc).unwrap();
    let third = plain.len() / 3 + 1;
    let parts: Vec<&[u8]> = plain.chunks(third).collect();
    let total = u16::try_from(parts.len()).unwrap();
    let mut frags = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let number = u16::try_from(i + 1).unwrap();
        let first = if number == 1 { enc.inner_next } else { 0 };
        frags.push(gw.keys().encrypt_bytes(
            false,
            gw.header(exchange::IKE_AUTH, h.mid, true),
            first,
            part,
            Some((number, total)),
        ));
    }
    assert!(client.receive(now, &frags[2]).is_empty());
    assert!(client.receive(now, &frags[0]).is_empty());
    let out = client.receive(now, &frags[1]);
    assert!(
        out.iter().any(|o| matches!(o, Output::ChildSa(_))),
        "{out:?}"
    );
}

#[test]
fn garbage_does_not_disturb_the_session() {
    let now = Instant::now();
    let mut client = Initiator::new(psk_config(), now).unwrap();
    let mut gw = Gateway::new("aes256-sha256-modp2048");
    let _ = init(&mut client, &mut gw, now);
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rand = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let valid = gw.respond(
        1,
        exchange::IKE_AUTH,
        &[Payload::new(payload::NONCE, vec![1; 16])],
    );
    for _ in 0..3000 {
        let mut m = valid.clone();
        let i = usize::try_from(rand() % m.len() as u64).unwrap();
        m[i] ^= 1 << (rand() % 8);
        if rand() % 3 == 0 {
            m.truncate(usize::try_from(rand() % m.len() as u64).unwrap());
        }
        let _ = client.receive(now, &m);
    }
    for _ in 0..3000 {
        let n = usize::try_from(rand() % 200).unwrap();
        let junk: Vec<u8> = (0..n).map(|_| rand() as u8).collect();
        let _ = wire::parse_sa(&junk);
        let _ = wire::parse_ts(&junk);
        let _ = wire::parse_cp(&junk);
        let _ = Notify::parse(&junk);
        let _ = Delete::parse(&junk);
        let _ = Chain::parse(junk.first().copied().unwrap_or(0), &junk, 0);
        let _ = client.receive(now, &junk);
    }
}
