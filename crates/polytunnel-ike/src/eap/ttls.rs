//! EAP-TTLS ([RFC 5281]) with PAP inside: TLS 1.2 in memory (rustls), its records carried in
//! EAP messages (fragmented and acknowledged as needed), then the username and password as
//! Diameter AVPs inside the tunnel. The MSK is the TLS "ttls keying material" export.
//!
//! [RFC 5281]: https://www.rfc-editor.org/rfc/rfc5281

use std::io::Write;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use zeroize::Zeroizing;

use crate::v2::auth::Trust;

pub const FLAG_LENGTH: u8 = 0x80;
pub const FLAG_MORE: u8 = 0x40;
pub const FLAG_START: u8 = 0x20;
/// TLS bytes per EAP message.
const FRAGMENT: usize = 1000;
/// Largest TLS message accepted from the server.
const MAX_MESSAGE: usize = 64 * 1024;
const LABEL: &[u8] = b"ttls keying material";

/// AVP codes (RFC 2865 attributes).
const AVP_USER_NAME: u32 = 1;
const AVP_USER_PASSWORD: u32 = 2;
/// The AVP "mandatory" flag.
const AVP_MANDATORY: u8 = 0x40;

pub struct Ttls {
    conn: ClientConnection,
    username: String,
    password: Zeroizing<String>,
    incoming: Vec<u8>,
    outgoing: Vec<u8>,
    out_total: usize,
    sent_first: bool,
    avps_sent: bool,
}

/// One AVP: code, flags, 24-bit length (header included), data, padding to 4 bytes.
fn avp(code: u32, data: &[u8]) -> Vec<u8> {
    let len = 8 + data.len();
    let mut out = code.to_be_bytes().to_vec();
    out.push(AVP_MANDATORY);
    out.extend_from_slice(&u32::try_from(len).expect("small AVP").to_be_bytes()[1..]);
    out.extend_from_slice(data);
    out.resize(out.len() + (4 - len % 4) % 4, 0);
    out
}

impl Ttls {
    pub fn new(
        trust: &Trust,
        username: String,
        password: Zeroizing<String>,
    ) -> Result<Self, String> {
        let roots = RootCertStore {
            roots: trust.anchors().to_vec(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .map_err(|e| format!("TLS: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(trust.name.clone())
            .map_err(|_| format!("'{}' is not a host name or address", trust.name))?;
        let conn =
            ClientConnection::new(Arc::new(config), name).map_err(|e| format!("TLS: {e}"))?;
        Ok(Self {
            conn,
            username,
            password,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            out_total: 0,
            sent_first: false,
            avps_sent: false,
        })
    }

    /// Handles the type data of an EAP-Request/TTLS; returns the type data of the response.
    pub fn handle(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        let flags = *data.first().ok_or("an empty TTLS message")?;
        let mut body = &data[1..];
        if flags & FLAG_LENGTH != 0 {
            body = body.get(4..).ok_or("a truncated TTLS message")?;
        }
        if flags & FLAG_START == 0 {
            // An empty request acknowledges our fragment: send the next one.
            if !self.outgoing.is_empty() && body.is_empty() {
                return Ok(self.next_fragment());
            }
            self.incoming.extend_from_slice(body);
            if self.incoming.len() > MAX_MESSAGE {
                return Err("the EAP server sent an oversized TLS message".into());
            }
            if flags & FLAG_MORE != 0 {
                return Ok(vec![0]); // acknowledge; more is coming
            }
            let mut rd = &self.incoming[..];
            while !rd.is_empty() {
                self.conn
                    .read_tls(&mut rd)
                    .map_err(|e| format!("TLS: {e}"))?;
                self.conn
                    .process_new_packets()
                    .map_err(|e| format!("the EAP server's TLS failed: {e}"))?;
            }
            self.incoming.clear();
        }
        if !self.conn.is_handshaking() && !self.avps_sent {
            let mut password = Zeroizing::new(self.password.as_bytes().to_vec());
            let padded = password.len().div_ceil(16).max(1) * 16;
            password.resize(padded, 0);
            let mut avps = Zeroizing::new(avp(AVP_USER_NAME, self.username.as_bytes()));
            avps.extend_from_slice(&avp(AVP_USER_PASSWORD, &password));
            self.conn
                .writer()
                .write_all(&avps)
                .map_err(|e| format!("TLS: {e}"))?;
            self.avps_sent = true;
        }
        let mut out = Vec::new();
        while self.conn.wants_write() {
            self.conn
                .write_tls(&mut out)
                .map_err(|e| format!("TLS: {e}"))?;
        }
        if out.is_empty() {
            return Ok(vec![0]);
        }
        self.out_total = out.len();
        self.outgoing = out;
        self.sent_first = false;
        Ok(self.next_fragment())
    }

    fn next_fragment(&mut self) -> Vec<u8> {
        let take = self.outgoing.len().min(FRAGMENT);
        let more = take < self.outgoing.len();
        let mut out = Vec::with_capacity(take + 5);
        if more && !self.sent_first {
            out.push(FLAG_LENGTH | FLAG_MORE);
            out.extend_from_slice(&u32::try_from(self.out_total).expect("small").to_be_bytes());
        } else {
            out.push(if more { FLAG_MORE } else { 0 });
        }
        self.sent_first = true;
        out.extend(self.outgoing.drain(..take));
        out
    }

    /// Whether the credentials went out (the method can only succeed after that).
    pub fn finished(&self) -> bool {
        self.avps_sent && self.outgoing.is_empty()
    }

    /// The 64-byte MSK, once the TLS handshake is complete.
    pub fn msk(&self) -> Option<Zeroizing<Vec<u8>>> {
        if self.conn.is_handshaking() {
            return None;
        }
        self.conn
            .export_keying_material(vec![0u8; 64], LABEL, None)
            .ok()
            .map(Zeroizing::new)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use rcgen::{CertificateParams, CertifiedIssuer, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};

    use super::*;

    fn server_and_trust() -> (ServerConnection, Trust) {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca, ca_key).unwrap();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf = CertificateParams::new(vec!["radius.test".to_string()])
            .unwrap()
            .signed_by(&key, &ca)
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        let trust = Trust::new(ca.pem().as_bytes(), false, "radius.test".into()).unwrap();
        (ServerConnection::new(Arc::new(config)).unwrap(), trust)
    }

    /// The TLS bytes of a response (flags and optional length removed).
    fn tls_of(data: &[u8]) -> &[u8] {
        if data[0] & FLAG_LENGTH != 0 {
            &data[5..]
        } else {
            &data[1..]
        }
    }

    /// Splits server TLS bytes into TTLS requests of at most 300 bytes.
    fn requests(tls: &[u8]) -> Vec<Vec<u8>> {
        let chunks: Vec<&[u8]> = tls.chunks(300).collect();
        chunks
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let more = i + 1 < chunks.len();
                let mut r = vec![if more { FLAG_MORE } else { 0 }];
                r.extend_from_slice(c);
                r
            })
            .collect()
    }

    #[test]
    fn pap_over_ttls_with_fragments_and_matching_keys() {
        let (mut server, trust) = server_and_trust();
        let password = ["pass", "phrase"].join(" ");
        let mut client =
            Ttls::new(&trust, "alice".into(), Zeroizing::new(password.clone())).unwrap();
        let mut response = client.handle(&[FLAG_START]).unwrap();
        let mut inner = Vec::new();
        for _ in 0..20 {
            // Collect the client's message, acknowledging its fragments.
            let mut from_client = tls_of(&response).to_vec();
            while response[0] & FLAG_MORE != 0 {
                response = client.handle(&[0]).unwrap();
                from_client.extend_from_slice(tls_of(&response));
            }
            if !from_client.is_empty() {
                server.read_tls(&mut &from_client[..]).unwrap();
                server.process_new_packets().unwrap();
                let _ = server.reader().read_to_end(&mut inner);
            }
            if !inner.is_empty() {
                break;
            }
            let mut to_client = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut to_client).unwrap();
            }
            let reqs = requests(&to_client);
            for (i, r) in reqs.iter().enumerate() {
                response = client.handle(r).unwrap();
                if i + 1 < reqs.len() {
                    assert_eq!(response, vec![0], "fragments are acknowledged");
                }
            }
        }
        // User-Name and User-Password (padded to 16 bytes) as mandatory AVPs.
        let mut want = avp(AVP_USER_NAME, b"alice");
        let mut padded = password.as_bytes().to_vec();
        padded.resize(16, 0);
        want.extend_from_slice(&avp(AVP_USER_PASSWORD, &padded));
        assert_eq!(inner, want);
        assert!(client.finished());
        let server_msk = server
            .export_keying_material(vec![0u8; 64], LABEL, None)
            .unwrap();
        assert_eq!(*client.msk().unwrap(), server_msk);
    }

    #[test]
    fn an_untrusted_server_is_refused() {
        let (mut server, _) = server_and_trust();
        let (_, other) = server_and_trust();
        let mut client = Ttls::new(&other, "alice".into(), Zeroizing::new("pw".into())).unwrap();
        let hello = client.handle(&[FLAG_START]).unwrap();
        server.read_tls(&mut tls_of(&hello)).unwrap();
        server.process_new_packets().unwrap();
        let mut to_client = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut to_client).unwrap();
        }
        let mut result = Ok(Vec::new());
        for r in requests(&to_client) {
            result = client.handle(&r);
            if result.is_err() {
                break;
            }
        }
        assert!(result.is_err(), "the certificate is from another CA");
    }

    #[test]
    fn avps_are_padded() {
        let a = avp(1, b"abc");
        assert_eq!(a.len(), 12);
        assert_eq!(&a[..8], &[0, 0, 0, 1, AVP_MANDATORY, 0, 0, 11]);
    }
}
