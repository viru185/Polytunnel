//! IKEv2 keys ([RFC 7296] sections 2.13 to 2.18) and the encrypted payload (section 3.14;
//! [RFC 5282] for AES-GCM).
//!
//! [RFC 7296]: https://www.rfc-editor.org/rfc/rfc7296
//! [RFC 5282]: https://www.rfc-editor.org/rfc/rfc5282

use std::fmt;

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use aes_gcm::aead::{AeadInOut, KeyInit};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::wire::{
    Encrypted, Header, Payload, Proposal, Transform, WireError, encode_chain, payload, protocol,
    transform,
};
use crate::dh::Group;
use crate::prf::HashAlg;

/// IKE SA encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encr {
    AesCbc { key_len: usize },
    AesGcm16 { key_len: usize },
}

/// One IKE SA proposal: encryption, prf, integrity (none with GCM) and DH group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IkeSuite {
    pub encr: Encr,
    pub prf: HashAlg,
    pub integ: Option<HashAlg>,
    pub group: Group,
}

fn aes_len(name: &str) -> Option<usize> {
    match name {
        "aes" | "aes128" => Some(16),
        "aes192" => Some(24),
        "aes256" => Some(32),
        _ => None,
    }
}

impl IkeSuite {
    /// Parses `aes256-sha256-modp2048` (CBC: the hash is both prf and integrity) or
    /// `aes256gcm16-prfsha256-ecp256` (GCM: a prf, no integrity).
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        let parts: Vec<&str> = s.split('-').collect();
        let [cipher, hash, group] = parts.as_slice() else {
            return None;
        };
        let group = Group::from_name(group)?;
        if let Some(bits) = cipher
            .strip_suffix("gcm16")
            .or_else(|| cipher.strip_suffix("gcm"))
        {
            let key_len = aes_len(bits).filter(|k| *k != 24)?;
            let prf = HashAlg::from_name(hash.strip_prefix("prf")?)?;
            return (prf != HashAlg::Md5).then_some(Self {
                encr: Encr::AesGcm16 { key_len },
                prf,
                integ: None,
                group,
            });
        }
        let hash = HashAlg::from_name(hash).filter(|h| *h != HashAlg::Md5)?;
        Some(Self {
            encr: Encr::AesCbc {
                key_len: aes_len(cipher)?,
            },
            prf: hash,
            integ: Some(hash),
            group,
        })
    }

    /// FortiGate's IKEv2 dial-up defaults with `group`.
    pub fn defaults(group: Group) -> Vec<Self> {
        [
            "aes256-sha256",
            "aes128-sha256",
            "aes256-sha1",
            "aes128-sha1",
        ]
        .iter()
        .map(|s| Self::parse(&format!("{s}-{}", group.name())).expect("valid default"))
        .collect()
    }

    pub fn proposal(&self, number: u8) -> Proposal {
        let (encr_id, key_len) = match self.encr {
            Encr::AesCbc { key_len } => (transform::ENCR_AES_CBC, key_len),
            Encr::AesGcm16 { key_len } => (transform::ENCR_AES_GCM_16, key_len),
        };
        let mut transforms = vec![
            Transform::with_key_len(transform::ENCR, encr_id, bits(key_len)),
            Transform::new(transform::PRF, prf_id(self.prf)),
        ];
        if let Some(h) = self.integ {
            transforms.push(Transform::new(transform::INTEG, integ_id(h)));
        }
        transforms.push(Transform::new(transform::DH, self.group.id()));
        Proposal {
            number,
            protocol: protocol::IKE,
            spi: Vec::new(),
            transforms,
        }
    }

    /// Whether the responder's chosen proposal is this suite.
    pub fn matches(&self, p: &Proposal) -> bool {
        let want = self.proposal(p.number);
        p.protocol == protocol::IKE
            && p.transforms.len() == want.transforms.len()
            && want.transforms.iter().all(|t| p.one(t.kind) == Some(t))
    }

    fn encr_key_len(&self) -> usize {
        match self.encr {
            Encr::AesCbc { key_len } => key_len,
            Encr::AesGcm16 { key_len } => key_len + 4,
        }
    }
}

impl fmt::Display for IkeSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.encr {
            Encr::AesCbc { key_len } => write!(f, "aes{}-{}", key_len * 8, self.prf.name())?,
            Encr::AesGcm16 { key_len } => {
                write!(f, "aes{}gcm16-prf{}", key_len * 8, self.prf.name())?;
            }
        }
        write!(f, "-{}", self.group.name())
    }
}

pub fn bits(key_len: usize) -> u16 {
    u16::try_from(key_len * 8).expect("small key")
}

pub fn prf_id(h: HashAlg) -> u16 {
    match h {
        HashAlg::Md5 => 1,
        HashAlg::Sha1 => transform::PRF_HMAC_SHA1,
        HashAlg::Sha256 => transform::PRF_HMAC_SHA2_256,
        HashAlg::Sha384 => transform::PRF_HMAC_SHA2_384,
        HashAlg::Sha512 => transform::PRF_HMAC_SHA2_512,
    }
}

pub fn integ_id(h: HashAlg) -> u16 {
    match h {
        HashAlg::Md5 => 1,
        HashAlg::Sha1 => transform::AUTH_HMAC_SHA1_96,
        HashAlg::Sha256 => transform::AUTH_HMAC_SHA2_256_128,
        HashAlg::Sha384 => transform::AUTH_HMAC_SHA2_384_192,
        HashAlg::Sha512 => transform::AUTH_HMAC_SHA2_512_256,
    }
}

/// Truncated HMAC length (half the output; 12 bytes for SHA-1).
fn icv_len(h: HashAlg) -> usize {
    match h {
        HashAlg::Sha1 => 12,
        other => other.output_len() / 2,
    }
}

/// prf+ (K, S) = T1 | T2 | ..., T1 = prf(K, S | 0x01), Tn = prf(K, Tn-1 | S | n).
pub fn prf_plus(prf: HashAlg, key: &[u8], seed: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(len + prf.output_len()));
    let mut t: Vec<u8> = Vec::new();
    let mut n: u8 = 1;
    while out.len() < len {
        t = prf.prf(key, &[&t, seed, &[n]]);
        out.extend_from_slice(&t);
        n = n.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// The IKE SA's keys.
pub struct IkeKeys {
    pub suite: IkeSuite,
    sk_d: Zeroizing<Vec<u8>>,
    sk_ai: Zeroizing<Vec<u8>>,
    sk_ar: Zeroizing<Vec<u8>>,
    sk_ei: Zeroizing<Vec<u8>>,
    sk_er: Zeroizing<Vec<u8>>,
    sk_pi: Zeroizing<Vec<u8>>,
    sk_pr: Zeroizing<Vec<u8>>,
}

impl IkeKeys {
    /// SKEYSEED = prf(Ni | Nr, g^ir); {SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr} =
    /// prf+(SKEYSEED, Ni | Nr | SPIi | SPIr).
    pub fn derive(
        suite: IkeSuite,
        nonces: (&[u8], &[u8]),
        gir: &[u8],
        spis: ([u8; 8], [u8; 8]),
    ) -> Self {
        let (ni, nr) = nonces;
        let prf = suite.prf;
        let skeyseed = Zeroizing::new(prf.prf(&[ni, nr].concat(), &[gir]));
        let p = prf.output_len();
        let a = suite.integ.map_or(0, HashAlg::output_len);
        let e = suite.encr_key_len();
        let km = prf_plus(
            prf,
            &skeyseed,
            &[ni, nr, &spis.0, &spis.1].concat(),
            3 * p + 2 * a + 2 * e,
        );
        let mut at = 0;
        let mut take = |n: usize| {
            let v = Zeroizing::new(km[at..at + n].to_vec());
            at += n;
            v
        };
        Self {
            suite,
            sk_d: take(p),
            sk_ai: take(a),
            sk_ar: take(a),
            sk_ei: take(e),
            sk_er: take(e),
            sk_pi: take(p),
            sk_pr: take(p),
        }
    }

    pub fn prf(&self) -> HashAlg {
        self.suite.prf
    }

    pub fn sk_pi(&self) -> &[u8] {
        &self.sk_pi
    }

    pub fn sk_pr(&self) -> &[u8] {
        &self.sk_pr
    }

    /// Child SA keying material: prf+(SK_d, [g^ir (new)] | Ni | Nr).
    pub fn child_keymat(
        &self,
        gir: Option<&[u8]>,
        ni: &[u8],
        nr: &[u8],
        len: usize,
    ) -> Zeroizing<Vec<u8>> {
        let seed = [gir.unwrap_or(&[]), ni, nr].concat();
        prf_plus(self.suite.prf, &self.sk_d, &seed, len)
    }

    fn keys(&self, initiator: bool) -> (&[u8], &[u8]) {
        if initiator {
            (&self.sk_ei, &self.sk_ai)
        } else {
            (&self.sk_er, &self.sk_ar)
        }
    }

    /// A complete message whose payloads are all inside an SK payload. `initiator`: which
    /// side is sending (its keys are used).
    pub fn encrypt(&self, initiator: bool, header: Header, inner: &[Payload]) -> Vec<u8> {
        let inner_first = inner.first().map_or(payload::NONE, |p| p.kind);
        self.encrypt_bytes(initiator, header, inner_first, &encode_chain(inner), None)
    }

    /// Encrypts already-encoded payloads as an SK payload, or as fragment `(number, total)`
    /// in an SKF payload (RFC 7383).
    pub fn encrypt_bytes(
        &self,
        initiator: bool,
        header: Header,
        inner_first: u8,
        chain: &[u8],
        fragment: Option<(u16, u16)>,
    ) -> Vec<u8> {
        let (ek, ak) = self.keys(initiator);
        let mut plain = chain.to_vec();
        let (kind, extra) = match fragment {
            Some((number, total)) => {
                let mut f = number.to_be_bytes().to_vec();
                f.extend_from_slice(&total.to_be_bytes());
                (payload::SKF, f)
            }
            None => (payload::SK, Vec::new()),
        };
        let header = Header {
            next: kind,
            ..header
        };
        // The generic payload header (plus fragment fields) that precedes the IV.
        let lead = |len: usize| {
            let mut h = vec![inner_first, 0];
            h.extend_from_slice(&u16::try_from(len).expect("small").to_be_bytes());
            h.extend_from_slice(&extra);
            h
        };
        match self.suite.encr {
            Encr::AesCbc { .. } => {
                let integ = self.suite.integ.expect("CBC suites have integrity");
                let icv = icv_len(integ);
                let pad = (16 - (plain.len() + 1) % 16) % 16;
                plain.resize(plain.len() + pad, 0);
                plain.push(u8::try_from(pad).expect("below 16"));
                let mut iv = [0u8; 16];
                getrandom::fill(&mut iv).expect("the system random number generator failed");
                let len = plain.len();
                cbc_encrypt(ek, &iv, &mut plain, len);
                let sk_len = 4 + extra.len() + 16 + plain.len() + icv;
                let mut out = header.encode(sk_len).to_vec();
                out.extend_from_slice(&lead(sk_len));
                out.extend_from_slice(&iv);
                out.extend_from_slice(&plain);
                let mac = integ.prf(ak, &[&out]);
                out.extend_from_slice(&mac[..icv]);
                out
            }
            Encr::AesGcm16 { key_len } => {
                plain.push(0); // pad length
                let mut iv = [0u8; 8];
                getrandom::fill(&mut iv).expect("the system random number generator failed");
                let sk_len = 4 + extra.len() + 8 + plain.len() + 16;
                let mut out = header.encode(sk_len).to_vec();
                out.extend_from_slice(&lead(sk_len));
                let salt: [u8; 4] = ek[key_len..].try_into().expect("4-byte salt");
                let tag = gcm_seal(&ek[..key_len], &salt, &iv, &out, &mut plain);
                out.extend_from_slice(&iv);
                out.extend_from_slice(&plain);
                out.extend_from_slice(&tag);
                out
            }
        }
    }

    /// Checks and decrypts the SK or SKF payload of a whole message (as long as its header
    /// says). `initiator`: which side sent it. Returns the payloads' plaintext.
    pub fn decrypt(
        &self,
        initiator: bool,
        message: &[u8],
        enc: &Encrypted,
    ) -> Result<Vec<u8>, WireError> {
        let (ek, ak) = self.keys(initiator);
        // SKF carries fragment number and total after the generic header.
        let data_start = enc.offset + if enc.kind == payload::SKF { 8 } else { 4 };
        match self.suite.encr {
            Encr::AesCbc { .. } => {
                let integ = self.suite.integ.expect("CBC suites have integrity");
                let icv = icv_len(integ);
                if message.len() < data_start + 16 + icv {
                    return Err(WireError("encrypted payload too short"));
                }
                let (signed, mac) = message.split_at(message.len() - icv);
                let want = integ.prf(ak, &[signed]);
                if !bool::from(want[..icv].ct_eq(mac)) {
                    return Err(WireError("integrity check failed"));
                }
                let iv = &signed[data_start..data_start + 16];
                let mut plain = signed[data_start + 16..].to_vec();
                if plain.is_empty() || plain.len() % 16 != 0 {
                    return Err(WireError("ciphertext is not whole blocks"));
                }
                cbc_decrypt(ek, iv, &mut plain);
                strip_padding(plain)
            }
            Encr::AesGcm16 { key_len } => {
                if message.len() < data_start + 8 + 16 {
                    return Err(WireError("encrypted payload too short"));
                }
                let salt: [u8; 4] = ek[key_len..].try_into().expect("4-byte salt");
                let aad = &message[..data_start];
                let iv = &message[data_start..data_start + 8];
                let (ct, tag) =
                    message[data_start + 8..].split_at(message.len() - data_start - 8 - 16);
                let mut plain = ct.to_vec();
                gcm_open(&ek[..key_len], &salt, iv, aad, &mut plain, tag)?;
                strip_padding(plain)
            }
        }
    }
}

fn strip_padding(mut plain: Vec<u8>) -> Result<Vec<u8>, WireError> {
    let pad = usize::from(*plain.last().ok_or(WireError("empty plaintext"))?);
    if pad + 1 > plain.len() {
        return Err(WireError("padding longer than the plaintext"));
    }
    plain.truncate(plain.len() - pad - 1);
    Ok(plain)
}

fn cbc_encrypt(key: &[u8], iv: &[u8], buf: &mut [u8], len: usize) {
    macro_rules! run {
        ($aes:ty) => {
            cbc::Encryptor::<$aes>::new_from_slices(key, iv)
                .expect("key and IV lengths checked")
                .encrypt_padded::<NoPadding>(buf, len)
                .expect("whole blocks")
        };
    }
    match key.len() {
        16 => run!(aes::Aes128),
        24 => run!(aes::Aes192),
        _ => run!(aes::Aes256),
    };
}

fn cbc_decrypt(key: &[u8], iv: &[u8], buf: &mut [u8]) {
    macro_rules! run {
        ($aes:ty) => {
            cbc::Decryptor::<$aes>::new_from_slices(key, iv)
                .expect("key and IV lengths checked")
                .decrypt_padded::<NoPadding>(buf)
                .expect("whole blocks")
        };
    }
    match key.len() {
        16 => run!(aes::Aes128),
        24 => run!(aes::Aes192),
        _ => run!(aes::Aes256),
    };
}

fn gcm_nonce(salt: &[u8; 4], iv: &[u8]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(salt);
    nonce[4..].copy_from_slice(iv);
    nonce
}

fn gcm_seal(key: &[u8], salt: &[u8; 4], iv: &[u8], aad: &[u8], buf: &mut [u8]) -> Vec<u8> {
    let nonce = gcm_nonce(salt, iv);
    macro_rules! run {
        ($gcm:ty) => {{
            let cipher = <$gcm>::new_from_slice(key).expect("key length checked");
            let nonce = aes_gcm::Nonce::<<$gcm as aes_gcm::aead::AeadCore>::NonceSize>::try_from(
                &nonce[..],
            )
            .expect("12-byte nonce");
            cipher
                .encrypt_inout_detached(&nonce, aad, buf.into())
                .expect("GCM encryption cannot fail for IKE-sized messages")
                .to_vec()
        }};
    }
    match key.len() {
        16 => run!(aes_gcm::Aes128Gcm),
        _ => run!(aes_gcm::Aes256Gcm),
    }
}

fn gcm_open(
    key: &[u8],
    salt: &[u8; 4],
    iv: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), WireError> {
    let nonce = gcm_nonce(salt, iv);
    macro_rules! run {
        ($gcm:ty) => {{
            let cipher = <$gcm>::new_from_slice(key).expect("key length checked");
            let nonce = aes_gcm::Nonce::<<$gcm as aes_gcm::aead::AeadCore>::NonceSize>::try_from(
                &nonce[..],
            )
            .expect("12-byte nonce");
            let tag = aes_gcm::Tag::<<$gcm as aes_gcm::aead::AeadCore>::TagSize>::try_from(tag)
                .map_err(|_| WireError("tag"))?;
            cipher
                .decrypt_inout_detached(&nonce, aad, buf.into(), &tag)
                .map_err(|_| WireError("integrity check failed"))
        }};
    }
    match key.len() {
        16 => run!(aes_gcm::Aes128Gcm),
        _ => run!(aes_gcm::Aes256Gcm),
    }
}

#[cfg(test)]
mod tests {
    use super::super::wire::{Chain, exchange};
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn suites_parse_print_and_propose() {
        for s in [
            "aes256-sha256-modp2048",
            "aes128-sha1-modp1536",
            "aes256gcm16-prfsha384-ecp384",
        ] {
            assert_eq!(IkeSuite::parse(s).unwrap().to_string(), s);
        }
        assert_eq!(IkeSuite::parse("aes256-md5-modp2048"), None);
        assert_eq!(
            IkeSuite::parse("aes256gcm16-sha256-modp2048"),
            None,
            "GCM needs prfX"
        );
        let suite = IkeSuite::parse("aes256-sha256-modp2048").unwrap();
        let p = suite.proposal(1);
        assert!(suite.matches(&p));
        assert!(
            !IkeSuite::parse("aes128-sha256-modp2048")
                .unwrap()
                .matches(&p)
        );
    }

    // From an independent implementation of the RFC 7296 formulas (Python hmac/hashlib).
    #[test]
    fn prf_plus_and_key_derivation_known_answers() {
        assert_eq!(
            *prf_plus(HashAlg::Sha256, b"key", b"seed", 40),
            hex(KAT_PRF_PLUS)
        );
        let suite = IkeSuite::parse("aes128-sha256-modp2048").unwrap();
        let keys = IkeKeys::derive(
            suite,
            (&[0x11; 16], &[0x22; 16]),
            &[0x33; 256],
            ([1; 8], [2; 8]),
        );
        assert_eq!(*keys.sk_d, hex(KAT_SK_D));
        assert_eq!(*keys.sk_ei, hex(KAT_SK_EI));
        assert_eq!(*keys.sk_pr, hex(KAT_SK_PR));
        assert_eq!(
            *keys.child_keymat(None, &[0x44; 16], &[0x55; 16], 32),
            hex(KAT_CHILD)
        );
    }

    #[test]
    fn sk_payload_round_trips_and_detects_tampering() {
        for s in [
            "aes256-sha256-modp2048",
            "aes128-sha1-modp2048",
            "aes256gcm16-prfsha256-modp2048",
            "aes128gcm16-prfsha256-modp2048",
        ] {
            let suite = IkeSuite::parse(s).unwrap();
            let keys = IkeKeys::derive(suite, (&[1; 16], &[2; 16]), &[3; 256], ([4; 8], [5; 8]));
            let header = Header {
                spi_i: [4; 8],
                spi_r: [5; 8],
                next: 0,
                exchange: exchange::IKE_AUTH,
                flags: 0x08,
                mid: 1,
                len: 0,
            };
            let inner = [
                Payload::new(payload::IDI, vec![2, 0, 0, 0, b'x']),
                Payload::new(payload::NONCE, vec![9; 33]),
            ];
            let msg = keys.encrypt(true, header, &inner);
            let (h, body) = Header::parse(&msg).unwrap();
            assert_eq!(h.next, payload::SK);
            let chain = Chain::parse(h.next, body, 28).unwrap();
            let enc = chain.encrypted.unwrap();
            let plain = keys.decrypt(true, &msg, &enc).unwrap();
            assert_eq!(
                Chain::parse(enc.inner_next, &plain, 0).unwrap().payloads,
                inner
            );
            assert!(
                keys.decrypt(false, &msg, &enc).is_err(),
                "{s}: wrong direction"
            );
            let mut bad = msg.clone();
            let n = bad.len();
            bad[n - 20] ^= 1;
            assert!(keys.decrypt(true, &bad, &enc).is_err(), "{s}: tampered");
        }
    }

    const KAT_PRF_PLUS: &str =
        "a2392e429a99b173341b368bb5ce320bfd483d89567c14ec187c2d77e3c0a208ba45d21d42611712";
    const KAT_SK_D: &str = "6587305414b9fddab3adbd95bd0d184a5c6370c0f931d221196eb9c30867c805";
    const KAT_SK_EI: &str = "a3cd8a34b4c920a0998db218241b3b81";
    const KAT_SK_PR: &str = "f1ec14835fa3f19f653d2b472b6f25bbcdbbf28c743cdd715383dac9a108b781";
    const KAT_CHILD: &str = "8e3aa8de15c6aec1f4f7b9872e5d5f280592e87223d33ca17d735f9ea6af8e22";
}
