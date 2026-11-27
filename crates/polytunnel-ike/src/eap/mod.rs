//! The EAP peer ([RFC 3748]) used inside IKEv2: identity, EAP-MSCHAPv2 and EAP-TTLS.
//!
//! [RFC 3748]: https://www.rfc-editor.org/rfc/rfc3748

pub mod mschapv2;
pub mod ttls;

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub mod code {
    pub const REQUEST: u8 = 1;
    pub const RESPONSE: u8 = 2;
    pub const SUCCESS: u8 = 3;
    pub const FAILURE: u8 = 4;
}

pub mod kind {
    pub const IDENTITY: u8 = 1;
    pub const NAK: u8 = 3;
    pub const TTLS: u8 = 21;
    pub const MSCHAPV2: u8 = 26;
}

mod opcode {
    pub const CHALLENGE: u8 = 1;
    pub const RESPONSE: u8 = 2;
    pub const SUCCESS: u8 = 3;
    pub const FAILURE: u8 = 4;
}

/// The EAP methods Polytunnel speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapMethod {
    MsChapV2,
    /// EAP-TTLS with PAP inside.
    TtlsPap,
}

impl EapMethod {
    pub fn kind(self) -> u8 {
        match self {
            EapMethod::MsChapV2 => kind::MSCHAPV2,
            EapMethod::TtlsPap => kind::TTLS,
        }
    }
}

/// What to do with an EAP request.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Send this EAP response.
    Respond(Vec<u8>),
    /// EAP-Success: the method finished and keys are available.
    Success,
    Failure(String),
}

struct MsChap {
    authenticator: [u8; 16],
    peer: [u8; 16],
    nt_response: [u8; 24],
}

/// The client side of one EAP conversation.
pub struct EapClient {
    method: EapMethod,
    username: String,
    password: Zeroizing<String>,
    mschap: Option<MsChap>,
    msk: Option<Zeroizing<Vec<u8>>>,
    /// Who may run the TTLS server.
    trust: Option<crate::v2::auth::Trust>,
    ttls: Option<ttls::Ttls>,
}

impl fmt::Debug for EapClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EapClient")
            .field("method", &self.method)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

fn packet(code: u8, id: u8, kind: u8, data: &[u8]) -> Vec<u8> {
    let len = u16::try_from(5 + data.len()).expect("small EAP packet");
    let mut out = vec![code, id];
    out.extend_from_slice(&len.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(data);
    out
}

impl EapClient {
    pub fn new(method: EapMethod, username: String, password: Zeroizing<String>) -> Self {
        Self {
            method,
            username,
            password,
            mschap: None,
            msk: None,
            trust: None,
            ttls: None,
        }
    }

    /// The CA certificates and name an EAP-TTLS server must present.
    pub fn with_trust(mut self, trust: crate::v2::auth::Trust) -> Self {
        self.trust = Some(trust);
        self
    }

    /// The master session key, once the method has finished.
    pub fn msk(&self) -> Option<&[u8]> {
        self.msk.as_deref().map(Vec::as_slice)
    }

    /// Handles one EAP packet from the server.
    pub fn handle(&mut self, packet_in: &[u8]) -> Step {
        if packet_in.len() < 4 {
            return Step::Failure("a malformed EAP packet".into());
        }
        let (code, id) = (packet_in[0], packet_in[1]);
        let len = usize::from(u16::from_be_bytes([packet_in[2], packet_in[3]]));
        if len < 4 || len > packet_in.len() {
            return Step::Failure("a malformed EAP packet".into());
        }
        let p = &packet_in[..len];
        match code {
            code::SUCCESS => {
                if self.msk.is_none()
                    && let Some(t) = self.ttls.as_ref().filter(|t| t.finished())
                {
                    self.msk = t.msk();
                }
                if self.msk.is_some() {
                    Step::Success
                } else {
                    Step::Failure("EAP succeeded before authentication finished".into())
                }
            }
            code::FAILURE => Step::Failure(
                "the gateway rejected the sign-in (check the username and password)".into(),
            ),
            code::REQUEST if p.len() >= 5 => {
                let data = &p[5..];
                match p[4] {
                    kind::IDENTITY => Step::Respond(packet(
                        code::RESPONSE,
                        id,
                        kind::IDENTITY,
                        self.username.as_bytes(),
                    )),
                    kind::MSCHAPV2 if self.method == EapMethod::MsChapV2 => self.mschapv2(id, data),
                    kind::TTLS if self.method == EapMethod::TtlsPap => self.ttls(id, data),
                    // Ask for the method we were configured with.
                    _ => {
                        Step::Respond(packet(code::RESPONSE, id, kind::NAK, &[self.method.kind()]))
                    }
                }
            }
            _ => Step::Failure("an unexpected EAP packet".into()),
        }
    }

    fn ttls(&mut self, id: u8, data: &[u8]) -> Step {
        if self.ttls.is_none() {
            let Some(trust) = &self.trust else {
                return Step::Failure("EAP-TTLS needs trusted CA certificates".into());
            };
            match ttls::Ttls::new(trust, self.username.clone(), self.password.clone()) {
                Ok(t) => self.ttls = Some(t),
                Err(e) => return Step::Failure(e),
            }
        }
        match self.ttls.as_mut().expect("just made").handle(data) {
            Ok(response) => Step::Respond(packet(code::RESPONSE, id, kind::TTLS, &response)),
            Err(e) => Step::Failure(e),
        }
    }

    fn mschapv2(&mut self, id: u8, data: &[u8]) -> Step {
        let Some(&op) = data.first() else {
            return Step::Failure("an empty MSCHAPv2 message".into());
        };
        match op {
            opcode::CHALLENGE => {
                // OpCode, MS-CHAPv2-ID, MS-Length, Value-Size (16), Challenge, Name.
                if data.len() < 21 || data[4] != 16 {
                    return Step::Failure("a malformed MSCHAPv2 challenge".into());
                }
                let ms_id = data[1];
                let authenticator: [u8; 16] = data[5..21].try_into().expect("16 bytes");
                let mut peer = [0u8; 16];
                if getrandom::fill(&mut peer).is_err() {
                    return Step::Failure("the system random number generator failed".into());
                }
                let name = self.username.as_bytes();
                let nt_response =
                    mschapv2::nt_response(&authenticator, &peer, name, &self.password);
                let ms_len = u16::try_from(54 + name.len()).expect("short name");
                let mut body = vec![opcode::RESPONSE, ms_id];
                body.extend_from_slice(&ms_len.to_be_bytes());
                body.push(49);
                body.extend_from_slice(&peer);
                body.extend_from_slice(&[0; 8]);
                body.extend_from_slice(&nt_response);
                body.push(0); // flags
                body.extend_from_slice(name);
                self.mschap = Some(MsChap {
                    authenticator,
                    peer,
                    nt_response,
                });
                Step::Respond(packet(code::RESPONSE, id, kind::MSCHAPV2, &body))
            }
            opcode::SUCCESS => {
                let Some(m) = &self.mschap else {
                    return Step::Failure("MSCHAPv2 success without a challenge".into());
                };
                let message = String::from_utf8_lossy(data.get(4..).unwrap_or_default());
                let want = mschapv2::authenticator_response(
                    &self.password,
                    &m.nt_response,
                    &m.peer,
                    &m.authenticator,
                    self.username.as_bytes(),
                );
                let got = message.split_whitespace().next().unwrap_or_default();
                if !bool::from(got.as_bytes().ct_eq(want.as_bytes())) {
                    return Step::Failure(
                        "the gateway's MSCHAPv2 proof did not verify (it may not know the password)"
                            .into(),
                    );
                }
                self.msk = Some(mschapv2::msk(&self.password, &m.nt_response));
                Step::Respond(packet(
                    code::RESPONSE,
                    id,
                    kind::MSCHAPV2,
                    &[opcode::SUCCESS],
                ))
            }
            opcode::FAILURE => {
                let message = String::from_utf8_lossy(data.get(4..).unwrap_or_default());
                Step::Failure(mschap_failure(&message))
            }
            _ => Step::Failure("an unexpected MSCHAPv2 message".into()),
        }
    }
}

/// Explains an MSCHAPv2 failure (`E=691 R=0 C=... V=3 M=...`).
fn mschap_failure(message: &str) -> String {
    let code = message
        .split_whitespace()
        .find_map(|w| w.strip_prefix("E="))
        .unwrap_or_default();
    match code {
        "691" => "the username or password is wrong".into(),
        "646" => "the account may not sign in at this time".into(),
        "647" => "the account is disabled".into(),
        "648" => "the password has expired".into(),
        "649" => "the account has no permission to dial in".into(),
        other => format!("MSCHAPv2 sign-in failed (error {other})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: u8, kind: u8, data: &[u8]) -> Vec<u8> {
        packet(code::REQUEST, id, kind, data)
    }

    #[test]
    fn identity_nak_and_terminal_codes() {
        let mut c = EapClient::new(
            EapMethod::MsChapV2,
            "alice".into(),
            Zeroizing::new("pw".into()),
        );
        let Step::Respond(r) = c.handle(&request(7, kind::IDENTITY, b"")) else {
            panic!("no identity response");
        };
        assert_eq!(r, packet(code::RESPONSE, 7, kind::IDENTITY, b"alice"));
        let Step::Respond(r) = c.handle(&request(8, 4, b"md5 challenge")) else {
            panic!("no NAK");
        };
        assert_eq!(r, packet(code::RESPONSE, 8, kind::NAK, &[kind::MSCHAPV2]));
        assert!(matches!(
            c.handle(&[code::SUCCESS, 9, 0, 4]),
            Step::Failure(_)
        ));
        assert!(matches!(
            c.handle(&[code::FAILURE, 9, 0, 4]),
            Step::Failure(_)
        ));
        assert!(matches!(c.handle(&[1, 2]), Step::Failure(_)));
    }

    /// The server side of MSCHAPv2, from the RFC 2759 functions.
    #[test]
    fn mschapv2_against_a_server() {
        let password = ["correct", "horse"].join(" ");
        let mut c = EapClient::new(
            EapMethod::MsChapV2,
            "alice".into(),
            Zeroizing::new(password.clone()),
        );
        let authenticator = [0x5a; 16];
        let mut challenge = vec![opcode::CHALLENGE, 3, 0, 26, 16];
        challenge.extend_from_slice(&authenticator);
        challenge.extend_from_slice(b"gw");
        let Step::Respond(r) = c.handle(&request(1, kind::MSCHAPV2, &challenge)) else {
            panic!("no response");
        };
        // EAP header (5), OpCode, ID, MS-Length (2), Value-Size, then the value.
        let value = &r[10..59];
        assert_eq!(r[9], 49);
        let peer: [u8; 16] = value[..16].try_into().unwrap();
        let nt: [u8; 24] = value[24..48].try_into().unwrap();
        assert_eq!(&r[59..], b"alice");
        assert_eq!(
            nt,
            mschapv2::nt_response(&authenticator, &peer, b"alice", &password)
        );

        // A wrong server proof is refused.
        let mut fake = vec![opcode::SUCCESS, 3, 0, 46];
        fake.extend_from_slice(b"S=0000000000000000000000000000000000000000 M=ok");
        let mut doubtful = EapClient::new(
            EapMethod::MsChapV2,
            "alice".into(),
            Zeroizing::new(password.clone()),
        );
        let _ = doubtful.handle(&request(1, kind::MSCHAPV2, &challenge));
        assert!(matches!(
            doubtful.handle(&request(2, kind::MSCHAPV2, &fake)),
            Step::Failure(_)
        ));

        let proof =
            mschapv2::authenticator_response(&password, &nt, &peer, &authenticator, b"alice");
        let mut success = vec![opcode::SUCCESS, 3, 0, 46];
        success.extend_from_slice(format!("{proof} M=welcome").as_bytes());
        assert_eq!(
            c.handle(&request(2, kind::MSCHAPV2, &success)),
            Step::Respond(packet(
                code::RESPONSE,
                2,
                kind::MSCHAPV2,
                &[opcode::SUCCESS]
            ))
        );
        assert_eq!(c.handle(&[code::SUCCESS, 3, 0, 4]), Step::Success);
        assert_eq!(c.msk().map(<[u8]>::len), Some(32));
    }

    #[test]
    fn failures_are_explained() {
        assert_eq!(
            mschap_failure("E=691 R=0 C=00 V=3 M=bad"),
            "the username or password is wrong"
        );
        assert!(mschap_failure("E=648 R=0").contains("expired"));
        assert!(mschap_failure("garbage").contains("failed"));
    }
}
