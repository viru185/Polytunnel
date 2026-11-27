//! IKEv2 authentication ([RFC 7296] section 2.15, [RFC 7427] signatures): what each side
//! signs, shared-key AUTH (pre-shared key or EAP MSK), and checking the gateway's
//! certificate and signature.
//!
//! [RFC 7296]: https://www.rfc-editor.org/rfc/rfc7296
//! [RFC 7427]: https://www.rfc-editor.org/rfc/rfc7427

use std::fmt;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    AlgorithmIdentifier, CertificateDer, InvalidSignature, ServerName,
    SignatureVerificationAlgorithm, TrustAnchor, UnixTime, alg_id,
};
use subtle::ConstantTimeEq;
use webpki::{EndEntityCert, KeyUsage};

use super::wire::auth_method;
use crate::prf::HashAlg;

/// The constant mixed into every shared-key AUTH value.
pub const KEY_PAD: &[u8] = b"Key Pad for IKEv2";

/// `<SignedOctets>` = RealMessage | Nonce of the other side | prf(SK_p, ID payload body).
pub fn signed_octets(
    message: &[u8],
    nonce: &[u8],
    prf: HashAlg,
    sk_p: &[u8],
    id_body: &[u8],
) -> Vec<u8> {
    let maced_id = prf.prf(sk_p, &[id_body]);
    [message, nonce, &maced_id].concat()
}

/// AUTH = prf(prf(secret, "Key Pad for IKEv2"), <SignedOctets>), for a pre-shared key or an
/// EAP MSK.
pub fn shared_key_auth(prf: HashAlg, secret: &[u8], octets: &[u8]) -> Vec<u8> {
    let key = prf.prf(secret, &[KEY_PAD]);
    prf.prf(&key, &[octets])
}

/// Checks a shared-key AUTH in constant time.
pub fn shared_key_ok(prf: HashAlg, secret: &[u8], octets: &[u8], got: &[u8]) -> bool {
    bool::from(shared_key_auth(prf, secret, octets).ct_eq(got))
}

/// The EKU some IKE certificates carry instead of serverAuth (id-kp-ipsecIKE).
const EKU_IPSEC_IKE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x11];

/// Which certificates may authenticate the gateway, and for which name.
#[derive(Clone)]
pub struct Trust {
    anchors: Vec<TrustAnchor<'static>>,
    /// DNS name or IP address the gateway's certificate must be valid for.
    pub name: String,
}

impl fmt::Debug for Trust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Trust")
            .field("anchors", &self.anchors.len())
            .field("name", &self.name)
            .finish()
    }
}

impl Trust {
    /// Trusts the CA certificates in `pem` (from the profile) and, if `system`, the
    /// operating system's roots.
    pub fn new(pem: &[u8], system: bool, name: String) -> Result<Self, String> {
        let mut anchors = Vec::new();
        for cert in CertificateDer::pem_slice_iter(pem) {
            let cert = cert.map_err(|e| format!("cannot read the CA certificate: {e}"))?;
            let anchor = webpki::anchor_from_trusted_cert(&cert)
                .map_err(|e| format!("cannot use the CA certificate: {e}"))?;
            anchors.push(anchor.to_owned());
        }
        if system {
            let found = rustls_native_certs::load_native_certs();
            for cert in &found.certs {
                if let Ok(anchor) = webpki::anchor_from_trusted_cert(cert) {
                    anchors.push(anchor.to_owned());
                }
            }
        }
        if anchors.is_empty() {
            return Err("no trusted CA certificates".into());
        }
        Ok(Self { anchors, name })
    }

    /// Verifies the gateway's certificate chain (end-entity first, DER) and its AUTH
    /// signature over `octets`.
    pub fn verify(
        &self,
        certs: &[Vec<u8>],
        method: u8,
        auth: &[u8],
        octets: &[u8],
    ) -> Result<(), String> {
        let (leaf, rest) = certs
            .split_first()
            .ok_or("the gateway sent no certificate")?;
        let leaf_der = CertificateDer::from(leaf.as_slice());
        let ee = EndEntityCert::try_from(&leaf_der)
            .map_err(|e| format!("the gateway's certificate is malformed: {e}"))?;
        let intermediates: Vec<CertificateDer<'_>> = rest
            .iter()
            .map(|c| CertificateDer::from(c.as_slice()))
            .collect();
        let now = UnixTime::now();
        let chain = |usage: KeyUsage| {
            ee.verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &self.anchors,
                &intermediates,
                now,
                usage,
                None,
                None,
            )
            .map(|_| ())
        };
        chain(KeyUsage::server_auth())
            .or_else(|_| chain(KeyUsage::required_if_present(EKU_IPSEC_IKE)))
            .map_err(|e| format!("the gateway's certificate is not trusted: {e}"))?;
        let name = ServerName::try_from(self.name.as_str())
            .map_err(|_| format!("'{}' is not a host name or address", self.name))?;
        ee.verify_is_valid_for_subject_name(&name).map_err(|_| {
            format!(
                "the gateway's certificate is not issued for {} (set remote-id to the name it carries)",
                self.name
            )
        })?;
        let valid = signature_algorithms(method, auth)?
            .into_iter()
            .any(|(alg, sig)| ee.verify_signature(alg, octets, sig).is_ok());
        if valid {
            Ok(())
        } else {
            Err("the gateway's signature did not verify".into())
        }
    }
}

/// A signature check done with ring, for the formats webpki does not cover.
#[derive(Debug)]
struct RingAlg {
    public_key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
    verify: &'static dyn ring::signature::VerificationAlgorithm,
}

impl SignatureVerificationAlgorithm for RingAlg {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        ring::signature::UnparsedPublicKey::new(self.verify, public_key)
            .verify(message, signature)
            .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }
}

/// AUTH method 1: RSA PKCS#1 v1.5 with SHA-1.
static RSA_SHA1: RingAlg = RingAlg {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: AlgorithmIdentifier::from_slice(&[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00,
    ]),
    verify: &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
};
/// AUTH methods 9 and 10: ECDSA with the raw r | s signature format (RFC 4754).
static ECDSA_P256_RAW: RingAlg = RingAlg {
    public_key: alg_id::ECDSA_P256,
    signature: alg_id::ECDSA_SHA256,
    verify: &ring::signature::ECDSA_P256_SHA256_FIXED,
};
static ECDSA_P384_RAW: RingAlg = RingAlg {
    public_key: alg_id::ECDSA_P384,
    signature: alg_id::ECDSA_SHA384,
    verify: &ring::signature::ECDSA_P384_SHA384_FIXED,
};

const OID_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_SHA512_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

type Candidate<'a> = (&'static dyn SignatureVerificationAlgorithm, &'a [u8]);

/// The algorithms an AUTH payload may have been made with, and the bare signature.
fn signature_algorithms(method: u8, auth: &[u8]) -> Result<Vec<Candidate<'_>>, String> {
    Ok(match method {
        auth_method::RSA => vec![(&RSA_SHA1, auth)],
        auth_method::ECDSA_256 => vec![(&ECDSA_P256_RAW, auth)],
        auth_method::ECDSA_384 => vec![(&ECDSA_P384_RAW, auth)],
        auth_method::DIGITAL_SIGNATURE => {
            // Length of the AlgorithmIdentifier, the AlgorithmIdentifier, the signature.
            let len = usize::from(*auth.first().ok_or("an empty signature")?);
            let alg = auth.get(1..1 + len).ok_or("a truncated signature")?;
            let sig = &auth[1 + len..];
            let oid = algorithm_oid(alg).ok_or("an unreadable signature algorithm")?;
            let contains = |needle: &[u8]| alg.windows(needle.len()).any(|w| w == needle);
            let algs: Vec<&'static dyn SignatureVerificationAlgorithm> = match oid {
                OID_SHA256_RSA => vec![webpki::ring::RSA_PKCS1_2048_8192_SHA256],
                OID_SHA384_RSA => vec![webpki::ring::RSA_PKCS1_2048_8192_SHA384],
                OID_SHA512_RSA => vec![webpki::ring::RSA_PKCS1_2048_8192_SHA512],
                OID_ECDSA_SHA256 => vec![
                    webpki::ring::ECDSA_P256_SHA256,
                    webpki::ring::ECDSA_P384_SHA256,
                ],
                OID_ECDSA_SHA384 => vec![
                    webpki::ring::ECDSA_P384_SHA384,
                    webpki::ring::ECDSA_P256_SHA384,
                ],
                OID_RSA_PSS if contains(OID_SHA512) => {
                    vec![webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY]
                }
                OID_RSA_PSS if contains(OID_SHA384) => {
                    vec![webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY]
                }
                OID_RSA_PSS if contains(OID_SHA256) => {
                    vec![webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY]
                }
                _ => return Err("the gateway signed with an unsupported algorithm".into()),
            };
            algs.into_iter().map(|a| (a, sig)).collect()
        }
        auth_method::PSK => {
            return Err("the gateway used a pre-shared key, not a certificate".into());
        }
        other => {
            return Err(format!(
                "the gateway used an unsupported authentication method ({other})"
            ));
        }
    })
}

/// The OID inside a DER AlgorithmIdentifier (SEQUENCE { OID, params }), short form only.
fn algorithm_oid(der: &[u8]) -> Option<&[u8]> {
    if der.len() < 4 || der[0] != 0x30 || der[2] != 0x06 {
        return None;
    }
    let len = usize::from(der[3]);
    der.get(4..4 + len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_key_auth_follows_the_formula() {
        let octets = signed_octets(
            b"message1",
            &[7; 16],
            HashAlg::Sha256,
            &[9; 32],
            &[2, 0, 0, 0, b'x'],
        );
        let maced = HashAlg::Sha256.prf(&[9; 32], &[&[2, 0, 0, 0, b'x']]);
        assert_eq!(octets, [&b"message1"[..], &[7; 16], &maced].concat());
        let auth = shared_key_auth(HashAlg::Sha256, b"secret", &octets);
        let key = HashAlg::Sha256.prf(b"secret", &[b"Key Pad for IKEv2"]);
        assert_eq!(auth, HashAlg::Sha256.prf(&key, &[&octets]));
        assert!(shared_key_ok(HashAlg::Sha256, b"secret", &octets, &auth));
        assert!(!shared_key_ok(HashAlg::Sha256, b"other", &octets, &auth));
    }

    #[test]
    fn signature_formats() {
        // RFC 7427: length, AlgorithmIdentifier (sha256WithRSAEncryption, NULL params), signature.
        let mut auth = vec![15, 0x30, 0x0d, 0x06, 0x09];
        auth.extend_from_slice(OID_SHA256_RSA);
        auth.extend_from_slice(&[0x05, 0x00]);
        auth.extend_from_slice(&[0xaa; 256]);
        let algs = signature_algorithms(auth_method::DIGITAL_SIGNATURE, &auth).unwrap();
        assert_eq!(algs.len(), 1);
        assert_eq!(algs[0].1, &[0xaa; 256][..]);
        assert_eq!(
            signature_algorithms(auth_method::RSA, &[1, 2])
                .unwrap()
                .len(),
            1
        );
        assert!(signature_algorithms(auth_method::PSK, &[]).is_err());
        assert!(signature_algorithms(auth_method::DIGITAL_SIGNATURE, &[200, 1]).is_err());
        assert_eq!(algorithm_oid(&auth[1..16]), Some(OID_SHA256_RSA));
    }

    #[test]
    fn trust_needs_some_anchor() {
        assert!(Trust::new(b"", false, "vpn.example.net".into()).is_err());
        assert!(
            Trust::new(
                b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n",
                false,
                "x".into()
            )
            .is_err()
        );
    }
}
