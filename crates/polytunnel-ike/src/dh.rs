//! Diffie-Hellman groups for IKE: MODP ([RFC 2409] section 6, [RFC 3526]) and ECP
//! ([RFC 5903]).
//!
//! [RFC 2409]: https://www.rfc-editor.org/rfc/rfc2409
//! [RFC 3526]: https://www.rfc-editor.org/rfc/rfc3526
//! [RFC 5903]: https://www.rfc-editor.org/rfc/rfc5903

use std::cmp::Ordering;
use std::fmt;

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Odd};
use zeroize::Zeroizing;

/// The groups Polytunnel offers, by their IKE group number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Group {
    /// Group 2 (legacy; offered only when a profile asks for it).
    Modp1024,
    /// Group 5.
    Modp1536,
    /// Group 14.
    Modp2048,
    /// Group 15.
    Modp3072,
    /// Group 16.
    Modp4096,
    /// Group 19 (NIST P-256).
    Ecp256,
    /// Group 20 (NIST P-384).
    Ecp384,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhError {
    /// The peer's public value has the wrong size or is not a valid group element.
    BadPublicValue,
    /// The operating system's random number generator failed.
    NoRandomness,
}

impl fmt::Display for DhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DhError::BadPublicValue => "the peer's Diffie-Hellman value is invalid",
            DhError::NoRandomness => "the system random number generator failed",
        })
    }
}

impl std::error::Error for DhError {}

impl Group {
    pub const ALL: [Group; 7] = [
        Group::Modp1024,
        Group::Modp1536,
        Group::Modp2048,
        Group::Modp3072,
        Group::Modp4096,
        Group::Ecp256,
        Group::Ecp384,
    ];

    /// The IKE group number (IKEv1 "group description", IKEv2 transform ID).
    pub fn id(self) -> u16 {
        match self {
            Group::Modp1024 => 2,
            Group::Modp1536 => 5,
            Group::Modp2048 => 14,
            Group::Modp3072 => 15,
            Group::Modp4096 => 16,
            Group::Ecp256 => 19,
            Group::Ecp384 => 20,
        }
    }

    pub fn from_id(id: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|g| g.id() == id)
    }

    /// The name used in profiles (strongSwan style): `modp2048`, `ecp256`.
    pub fn name(self) -> &'static str {
        match self {
            Group::Modp1024 => "modp1024",
            Group::Modp1536 => "modp1536",
            Group::Modp2048 => "modp2048",
            Group::Modp3072 => "modp3072",
            Group::Modp4096 => "modp4096",
            Group::Ecp256 => "ecp256",
            Group::Ecp384 => "ecp384",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|g| g.name().eq_ignore_ascii_case(name))
    }

    /// Size of the public value (the KE payload) in bytes.
    pub fn public_len(self) -> usize {
        match self {
            Group::Modp1024 => 128,
            Group::Modp1536 => 192,
            Group::Modp2048 => 256,
            Group::Modp3072 => 384,
            Group::Modp4096 => 512,
            Group::Ecp256 => 64,
            Group::Ecp384 => 96,
        }
    }

    fn modp_prime(self) -> Option<&'static [&'static str]> {
        match self {
            Group::Modp1024 => Some(MODP_1024),
            Group::Modp1536 => Some(MODP_1536),
            Group::Modp2048 => Some(MODP_2048),
            Group::Modp3072 => Some(MODP_3072),
            Group::Modp4096 => Some(MODP_4096),
            Group::Ecp256 | Group::Ecp384 => None,
        }
    }
}

/// An ephemeral key pair for one exchange.
pub struct KeyPair {
    group: Group,
    secret: Secret,
    public: Vec<u8>,
}

enum Secret {
    Modp(Zeroizing<Vec<u8>>),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    pub fn generate(group: Group) -> Result<Self, DhError> {
        let len = match group {
            Group::Ecp256 => 32,
            Group::Ecp384 => 48,
            _ => group.public_len(),
        };
        loop {
            let mut secret = Zeroizing::new(vec![0u8; len]);
            getrandom::fill(&mut secret).map_err(|_| DhError::NoRandomness)?;
            if group.modp_prime().is_some() {
                // Keeps the exponent below the prime, whose top bits are all ones.
                secret[0] &= 0x7f;
            }
            if let Some(pair) = Self::from_secret(group, &secret) {
                return Ok(pair);
            }
        }
    }

    /// The key pair for a given private value: an exponent (MODP) or scalar (ECP), big-endian.
    /// `None` when the value is out of range.
    pub fn from_secret(group: Group, secret: &[u8]) -> Option<Self> {
        match group {
            Group::Ecp256 => {
                let key = p256::SecretKey::from_slice(secret).ok()?;
                let public = key.public_key().to_sec1_bytes()[1..].to_vec();
                Some(Self {
                    group,
                    secret: Secret::P256(key),
                    public,
                })
            }
            Group::Ecp384 => {
                let key = p384::SecretKey::from_slice(secret).ok()?;
                let public = key.public_key().to_sec1_bytes()[1..].to_vec();
                Some(Self {
                    group,
                    secret: Secret::P384(key),
                    public,
                })
            }
            _ => {
                if secret.len() > group.public_len() || secret.iter().all(|&b| b == 0) {
                    return None;
                }
                let prime = Prime::of(group);
                let public = prime.pow(&prime.integer(&[2]), secret);
                Some(Self {
                    group,
                    secret: Secret::Modp(Zeroizing::new(secret.to_vec())),
                    public,
                })
            }
        }
    }

    pub fn group(&self) -> Group {
        self.group
    }

    /// Our public value, as sent in the KE payload.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// The shared secret g^xy (MODP: padded to the prime's length; ECP: the x coordinate).
    pub fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, DhError> {
        if peer.len() != self.group.public_len() {
            return Err(DhError::BadPublicValue);
        }
        match &self.secret {
            Secret::P256(key) => {
                let point = p256::PublicKey::from_sec1_bytes(&sec1(peer))
                    .map_err(|_| DhError::BadPublicValue)?;
                Ok(Zeroizing::new(
                    key.diffie_hellman(&point).raw_secret_bytes().to_vec(),
                ))
            }
            Secret::P384(key) => {
                let point = p384::PublicKey::from_sec1_bytes(&sec1(peer))
                    .map_err(|_| DhError::BadPublicValue)?;
                Ok(Zeroizing::new(
                    key.diffie_hellman(&point).raw_secret_bytes().to_vec(),
                ))
            }
            Secret::Modp(exponent) => {
                let prime = Prime::of(self.group);
                let value = prime.integer(peer);
                // 1 < y < p - 1 rejects the small-subgroup values 0, 1 and p - 1.
                let one = prime.integer(&[1]);
                let p_minus_1 = prime.modulus.wrapping_sub(&one);
                if value.cmp_vartime(&one) != Ordering::Greater
                    || value.cmp_vartime(&p_minus_1) != Ordering::Less
                {
                    return Err(DhError::BadPublicValue);
                }
                Ok(Zeroizing::new(prime.pow(&value, exponent)))
            }
        }
    }
}

/// `04 || x || y`: SEC1's uncompressed form of IKE's `x || y` point encoding.
fn sec1(xy: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(xy.len() + 1);
    out.push(0x04);
    out.extend_from_slice(xy);
    out
}

struct Prime {
    bits: u32,
    modulus: BoxedUint,
}

impl Prime {
    fn of(group: Group) -> Self {
        let hex: String = group.modp_prime().expect("MODP group").concat();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("constant is hex"))
            .collect();
        let bits = u32::try_from(bytes.len() * 8).expect("small");
        Self {
            bits,
            modulus: BoxedUint::from_be_slice(&bytes, bits).expect("constant fits"),
        }
    }

    fn integer(&self, be: &[u8]) -> BoxedUint {
        BoxedUint::from_be_slice(be, self.bits).expect("length checked")
    }

    /// base^exponent mod p, as big-endian bytes of the prime's length.
    fn pow(&self, base: &BoxedUint, exponent: &[u8]) -> Vec<u8> {
        let params =
            BoxedMontyParams::new(Odd::new(self.modulus.clone()).expect("the prime is odd"));
        let exponent = self.integer(exponent);
        BoxedMontyForm::new(base.clone(), &params)
            .pow(&exponent)
            .retrieve()
            .to_be_bytes()
            .to_vec()
    }
}

// The primes were generated from their defining formula
// (2^n - 2^(n-64) - 1 + 2^64 * (floor(2^(n-130) * pi) + k)), checked to be safe primes and,
// for groups 5 to 16, compared with OpenSSL's built-in copies.

/// Group 2 prime (1024 bits).
const MODP_1024: &[&str] = &[
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
];

/// Group 5 prime (1536 bits).
const MODP_1536: &[&str] = &[
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
];

/// Group 14 prime (2048 bits).
const MODP_2048: &[&str] = &[
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
];

/// Group 15 prime (3072 bits).
const MODP_3072: &[&str] = &[
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
];

/// Group 16 prime (4096 bits).
const MODP_4096: &[&str] = &[
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8",
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2",
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn group_ids_and_names_round_trip() {
        for g in Group::ALL {
            assert_eq!(Group::from_id(g.id()), Some(g));
            assert_eq!(Group::from_name(g.name()), Some(g));
        }
        assert_eq!(Group::from_id(1), None);
        assert_eq!(Group::from_name("MODP2048"), Some(Group::Modp2048));
    }

    #[test]
    fn primes_have_the_documented_shape() {
        for g in Group::ALL.into_iter().filter(|g| g.modp_prime().is_some()) {
            let p = Prime::of(g).modulus.to_be_bytes();
            assert_eq!(p.len(), g.public_len());
            assert!(p[..8].iter().all(|&b| b == 0xff), "{g:?} top 64 bits");
            assert!(
                p[p.len() - 8..].iter().all(|&b| b == 0xff),
                "{g:?} low 64 bits"
            );
        }
    }

    #[test]
    fn modp_small_exponents_match_plain_arithmetic() {
        // 2^10 and 2^100 are far below every prime, so nothing is reduced.
        let pair = KeyPair::from_secret(Group::Modp2048, &[10]).unwrap();
        let mut want = [0u8; 256];
        want[254] = 0x04;
        assert_eq!(pair.public(), &want[..]);
        let pair = KeyPair::from_secret(Group::Modp1024, &[100]).unwrap();
        let mut want = [0u8; 128];
        want[128 - 13] = 0x10; // 2^100 = 0x10 followed by 12 zero bytes
        assert_eq!(pair.public(), &want[..]);
    }

    #[test]
    fn modp_shared_secrets_agree() {
        for g in [Group::Modp1536, Group::Modp2048] {
            let a = KeyPair::generate(g).unwrap();
            let b = KeyPair::generate(g).unwrap();
            let ab = a.agree(b.public()).unwrap();
            assert_eq!(ab.len(), g.public_len());
            assert_eq!(*ab, *b.agree(a.public()).unwrap());
        }
    }

    #[test]
    fn modp_rejects_degenerate_public_values() {
        let a = KeyPair::generate(Group::Modp1024).unwrap();
        let mut one = vec![0u8; 128];
        one[127] = 1;
        assert_eq!(a.agree(&one), Err(DhError::BadPublicValue));
        assert_eq!(a.agree(&[0u8; 128]), Err(DhError::BadPublicValue));
        let mut p_minus_1 = Prime::of(Group::Modp1024).modulus.to_be_bytes().to_vec();
        p_minus_1[127] -= 1;
        assert_eq!(a.agree(&p_minus_1), Err(DhError::BadPublicValue));
        assert_eq!(a.agree(&[0xff; 128]), Err(DhError::BadPublicValue));
        assert_eq!(a.agree(&[1; 64]), Err(DhError::BadPublicValue));
    }

    #[test]
    fn ecp_public_values_are_x_then_y() {
        // Private value 1: the public value is the curve's generator.
        let mut one = [0u8; 32];
        one[31] = 1;
        let pair = KeyPair::from_secret(Group::Ecp256, &one).unwrap();
        let want = hex(concat!(
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
        ));
        assert_eq!(pair.public(), &want[..]);
    }

    #[test]
    fn ecp_shared_secrets_agree_and_reject_junk() {
        for g in [Group::Ecp256, Group::Ecp384] {
            let a = KeyPair::generate(g).unwrap();
            let b = KeyPair::generate(g).unwrap();
            let ab = a.agree(b.public()).unwrap();
            assert_eq!(ab.len(), g.public_len() / 2);
            assert_eq!(*ab, *b.agree(a.public()).unwrap());
            // Not a point on the curve.
            assert_eq!(
                a.agree(&vec![7u8; g.public_len()]),
                Err(DhError::BadPublicValue)
            );
        }
    }
}
