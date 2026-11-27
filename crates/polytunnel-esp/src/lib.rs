//! ESP (RFC 4303) for Polytunnel's tunnels: GlobalProtect's ESP mode and IPsec.
//!
//! * [`OutboundSa::seal`] wraps an IP packet; [`InboundSa::open`] checks and unwraps one.
//! * Ciphers: AES-CBC (RFC 3602) with HMAC-SHA1-96 / SHA-256-128 / SHA-384-192 /
//!   SHA-512-256 (RFC 2404, 4868), or AES-GCM with a 16-byte ICV (RFC 4106).
//! * [`replay::ReplayWindow`] rejects replayed and too-old packets (RFC 4303 §3.4.3).
//! * [`udp`] handles UDP encapsulation (RFC 3948): keepalives and the non-ESP marker.
//!
//! Keys are wiped from memory when an SA is dropped. 64-bit extended sequence numbers are
//! not supported: an outbound SA refuses to wrap and must be rekeyed first.

pub mod replay;
pub mod udp;

use std::fmt;

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use aes_gcm::aead::{AeadInOut, KeyInit};
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::replay::ReplayWindow;

/// Next-header value for an IPv4 packet in tunnel mode.
pub const NEXT_HEADER_IPV4: u8 = 4;
/// Next-header value for an IPv6 packet in tunnel mode.
pub const NEXT_HEADER_IPV6: u8 = 41;

const HEADER_LEN: usize = 8; // SPI + sequence number
const CBC_IV_LEN: usize = 16;
const GCM_IV_LEN: usize = 8;
const GCM_ICV_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EspError {
    /// Key or algorithm combination not allowed.
    BadKeys(&'static str),
    /// The packet is too short or malformed.
    Malformed,
    /// The SPI is not this SA's.
    WrongSpi(u32),
    /// Replayed or older than the replay window.
    Replay(u32),
    /// The integrity check failed (tampered packet or wrong key).
    IntegrityFailed,
    /// Padding bytes are not 1, 2, 3, ...
    BadPadding,
    /// The sequence number would wrap: rekey first.
    SequenceExhausted,
}

impl fmt::Display for EspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EspError::BadKeys(why) => write!(f, "bad ESP keys: {why}"),
            EspError::Malformed => f.write_str("malformed ESP packet"),
            EspError::WrongSpi(spi) => write!(f, "unexpected SPI {spi:#010x}"),
            EspError::Replay(seq) => write!(f, "replayed or stale packet (sequence {seq})"),
            EspError::IntegrityFailed => f.write_str("ESP integrity check failed"),
            EspError::BadPadding => f.write_str("bad ESP padding"),
            EspError::SequenceExhausted => f.write_str("ESP sequence numbers exhausted"),
        }
    }
}

impl std::error::Error for EspError {}

/// Encryption algorithm and key.
#[derive(Clone, PartialEq, Eq)]
pub enum Cipher {
    /// AES-CBC with a 16, 24 or 32-byte key.
    AesCbc(Vec<u8>),
    /// AES-GCM with a 16 or 32-byte key and the 4-byte salt from the keying material.
    AesGcm16 { key: Vec<u8>, salt: [u8; 4] },
}

/// Integrity algorithm (not used with AES-GCM, which authenticates by itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    /// No separate integrity check: only valid with AES-GCM (and in test vectors).
    None,
    HmacSha1_96,
    HmacSha256_128,
    HmacSha384_192,
    HmacSha512_256,
}

impl Integrity {
    /// Bytes of ICV appended to each packet.
    pub fn icv_len(self) -> usize {
        match self {
            Integrity::None => 0,
            Integrity::HmacSha1_96 => 12,
            Integrity::HmacSha256_128 => 16,
            Integrity::HmacSha384_192 => 24,
            Integrity::HmacSha512_256 => 32,
        }
    }

    /// The key length the algorithm expects.
    pub fn key_len(self) -> usize {
        match self {
            Integrity::None => 0,
            Integrity::HmacSha1_96 => 20,
            Integrity::HmacSha256_128 => 32,
            Integrity::HmacSha384_192 => 48,
            Integrity::HmacSha512_256 => 64,
        }
    }
}

/// The keys for one direction.
#[derive(Clone, PartialEq, Eq)]
pub struct Keys {
    cipher: Cipher,
    integrity: Integrity,
    auth_key: Vec<u8>,
}

impl Keys {
    pub fn new(cipher: Cipher, integrity: Integrity, auth_key: Vec<u8>) -> Result<Self, EspError> {
        match &cipher {
            Cipher::AesCbc(key) => {
                if ![16, 24, 32].contains(&key.len()) {
                    return Err(EspError::BadKeys("AES-CBC keys are 16, 24 or 32 bytes"));
                }
            }
            Cipher::AesGcm16 { key, .. } => {
                if ![16, 32].contains(&key.len()) {
                    return Err(EspError::BadKeys("AES-GCM keys are 16 or 32 bytes"));
                }
                if integrity != Integrity::None {
                    return Err(EspError::BadKeys("AES-GCM takes no separate integrity"));
                }
            }
        }
        if auth_key.len() != integrity.key_len() {
            return Err(EspError::BadKeys("wrong integrity key length"));
        }
        Ok(Keys {
            cipher,
            integrity,
            auth_key,
        })
    }

    fn iv_len(&self) -> usize {
        match self.cipher {
            Cipher::AesCbc(_) => CBC_IV_LEN,
            Cipher::AesGcm16 { .. } => GCM_IV_LEN,
        }
    }

    fn icv_len(&self) -> usize {
        match self.cipher {
            Cipher::AesCbc(_) => self.integrity.icv_len(),
            Cipher::AesGcm16 { .. } => GCM_ICV_LEN,
        }
    }

    fn block(&self) -> usize {
        match self.cipher {
            Cipher::AesCbc(_) => 16,
            Cipher::AesGcm16 { .. } => 4,
        }
    }

    /// HMAC over `data`, truncated to the ICV length.
    fn icv(&self, data: &[u8]) -> Vec<u8> {
        fn mac<M: Mac + KeyInit>(key: &[u8], data: &[u8], len: usize) -> Vec<u8> {
            let mut m = <M as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
            m.update(data);
            m.finalize().into_bytes()[..len].to_vec()
        }
        let len = self.integrity.icv_len();
        match self.integrity {
            Integrity::None => Vec::new(),
            Integrity::HmacSha1_96 => mac::<Hmac<sha1::Sha1>>(&self.auth_key, data, len),
            Integrity::HmacSha256_128 => mac::<Hmac<sha2::Sha256>>(&self.auth_key, data, len),
            Integrity::HmacSha384_192 => mac::<Hmac<sha2::Sha384>>(&self.auth_key, data, len),
            Integrity::HmacSha512_256 => mac::<Hmac<sha2::Sha512>>(&self.auth_key, data, len),
        }
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        match &mut self.cipher {
            Cipher::AesCbc(key) => key.zeroize(),
            Cipher::AesGcm16 { key, salt } => {
                key.zeroize();
                salt.zeroize();
            }
        }
        self.auth_key.zeroize();
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cipher = match &self.cipher {
            Cipher::AesCbc(k) => format!("AES-{}-CBC", k.len() * 8),
            Cipher::AesGcm16 { key, .. } => format!("AES-{}-GCM-16", key.len() * 8),
        };
        write!(f, "Keys({cipher}, {:?}, ***)", self.integrity)
    }
}

/// Sending side of an SA.
#[derive(Debug)]
pub struct OutboundSa {
    spi: u32,
    seq: u32,
    keys: Keys,
}

impl OutboundSa {
    pub fn new(spi: u32, keys: Keys) -> Self {
        OutboundSa { spi, seq: 0, keys }
    }

    pub fn spi(&self) -> u32 {
        self.spi
    }

    /// Packets sent so far.
    pub fn sequence(&self) -> u32 {
        self.seq
    }

    /// Wraps `inner` (a whole IP packet in tunnel mode) into an ESP packet.
    pub fn seal(&mut self, next_header: u8, inner: &[u8]) -> Result<Vec<u8>, EspError> {
        let seq = self.seq.checked_add(1).ok_or(EspError::SequenceExhausted)?;
        self.seq = seq;
        let mut iv = vec![0u8; self.keys.iv_len()];
        match self.keys.cipher {
            Cipher::AesCbc(_) => {
                getrandom::fill(&mut iv).map_err(|_| EspError::BadKeys("no OS randomness"))?;
            }
            // RFC 4106: the IV must be unique per key; the sequence number is.
            Cipher::AesGcm16 { .. } => iv.copy_from_slice(&u64::from(seq).to_be_bytes()),
        }
        Ok(seal_with_iv(
            &self.keys,
            self.spi,
            seq,
            &iv,
            next_header,
            inner,
        ))
    }
}

fn seal_with_iv(
    keys: &Keys,
    spi: u32,
    seq: u32,
    iv: &[u8],
    next_header: u8,
    inner: &[u8],
) -> Vec<u8> {
    let block = keys.block();
    let pad_len = (block - (inner.len() + 2) % block) % block;
    let mut payload = Vec::with_capacity(inner.len() + pad_len + 2 + block);
    payload.extend_from_slice(inner);
    payload.extend((1..=pad_len).map(|i| i as u8));
    payload.push(pad_len as u8);
    payload.push(next_header);

    let mut packet = Vec::with_capacity(HEADER_LEN + iv.len() + payload.len() + keys.icv_len());
    packet.extend_from_slice(&spi.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(iv);
    match &keys.cipher {
        Cipher::AesCbc(key) => {
            let len = payload.len();
            cbc_encrypt(key, iv, &mut payload, len);
            packet.extend_from_slice(&payload);
            let icv = keys.icv(&packet);
            packet.extend_from_slice(&icv);
        }
        Cipher::AesGcm16 { key, salt } => {
            let aad = packet[..HEADER_LEN].to_vec();
            let tag = gcm_seal(key, salt, iv, &aad, &mut payload);
            packet.extend_from_slice(&payload);
            packet.extend_from_slice(&tag);
        }
    }
    packet
}

/// Receiving side of an SA.
#[derive(Debug)]
pub struct InboundSa {
    spi: u32,
    keys: Keys,
    replay: ReplayWindow,
}

impl InboundSa {
    /// `window`: replay window size in packets (64 to 1024, rounded up to a multiple of 64).
    pub fn new(spi: u32, keys: Keys, window: usize) -> Self {
        InboundSa {
            spi,
            keys,
            replay: ReplayWindow::new(window),
        }
    }

    pub fn spi(&self) -> u32 {
        self.spi
    }

    /// Checks and unwraps an ESP packet. Returns the next-header value and the inner packet.
    pub fn open(&mut self, packet: &[u8]) -> Result<(u8, Vec<u8>), EspError> {
        let iv_len = self.keys.iv_len();
        let icv_len = self.keys.icv_len();
        let block = self.keys.block();
        if packet.len() < HEADER_LEN + iv_len + block + icv_len {
            return Err(EspError::Malformed);
        }
        let spi = u32::from_be_bytes(packet[0..4].try_into().expect("4 bytes"));
        if spi != self.spi {
            return Err(EspError::WrongSpi(spi));
        }
        let seq = u32::from_be_bytes(packet[4..8].try_into().expect("4 bytes"));
        if !self.replay.check(seq) {
            return Err(EspError::Replay(seq));
        }
        let body_end = packet.len() - icv_len;
        let iv = &packet[HEADER_LEN..HEADER_LEN + iv_len];
        let mut payload = packet[HEADER_LEN + iv_len..body_end].to_vec();
        if payload.is_empty() || !payload.len().is_multiple_of(block) {
            return Err(EspError::Malformed);
        }
        match &self.keys.cipher {
            Cipher::AesCbc(key) => {
                let expected = self.keys.icv(&packet[..body_end]);
                if !bool::from(expected.ct_eq(&packet[body_end..])) {
                    return Err(EspError::IntegrityFailed);
                }
                cbc_decrypt(key, iv, &mut payload);
            }
            Cipher::AesGcm16 { key, salt } => {
                gcm_open(
                    key,
                    salt,
                    iv,
                    &packet[..HEADER_LEN],
                    &mut payload,
                    &packet[body_end..],
                )?;
            }
        }
        // Only authenticated packets move the window.
        self.replay.update(seq);

        let next_header = payload[payload.len() - 1];
        let pad_len = usize::from(payload[payload.len() - 2]);
        if pad_len + 2 > payload.len() {
            return Err(EspError::BadPadding);
        }
        let inner_len = payload.len() - 2 - pad_len;
        let padding = &payload[inner_len..payload.len() - 2];
        if padding
            .iter()
            .enumerate()
            .any(|(i, &b)| usize::from(b) != i + 1)
        {
            return Err(EspError::BadPadding);
        }
        payload.truncate(inner_len);
        Ok((next_header, payload))
    }
}

// ------------------------------------------------------------------------------ primitives

fn cbc_encrypt(key: &[u8], iv: &[u8], buf: &mut [u8], len: usize) {
    macro_rules! run {
        ($aes:ty) => {
            cbc::Encryptor::<$aes>::new_from_slices(key, iv)
                .expect("key and IV lengths checked")
                .encrypt_padded::<NoPadding>(buf, len)
                .expect("payload is block-aligned")
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
                .expect("payload is block-aligned")
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

/// Encrypts `buf` in place and returns the 16-byte tag.
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
                .expect("GCM encryption cannot fail for ESP-sized packets")
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
) -> Result<(), EspError> {
    let nonce = gcm_nonce(salt, iv);
    macro_rules! run {
        ($gcm:ty) => {{
            let cipher = <$gcm>::new_from_slice(key).expect("key length checked");
            let nonce = aes_gcm::Nonce::<<$gcm as aes_gcm::aead::AeadCore>::NonceSize>::try_from(
                &nonce[..],
            )
            .expect("12-byte nonce");
            let tag = aes_gcm::Tag::<<$gcm as aes_gcm::aead::AeadCore>::TagSize>::try_from(tag)
                .map_err(|_| EspError::Malformed)?;
            cipher
                .decrypt_inout_detached(&nonce, aad, buf.into(), &tag)
                .map_err(|_| EspError::IntegrityFailed)
        }};
    }
    match key.len() {
        16 => run!(aes_gcm::Aes128Gcm),
        _ => run!(aes_gcm::Aes256Gcm),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn cbc_only(key: &str) -> Keys {
        Keys::new(Cipher::AesCbc(hex(key)), Integrity::None, Vec::new()).unwrap()
    }

    /// RFC 3602, case #5: transport-mode ICMP payload.
    #[test]
    fn rfc3602_case_5() {
        let keys = cbc_only("90d382b4 10eeba7a d938c46c ec1a82bf");
        let data = hex(
            "08000ebd a70a0000 8e9c083d b95b0700 08090a0b 0c0d0e0f 10111213 14151617
             18191a1b 1c1d1e1f 20212223 24252627 28292a2b 2c2d2e2f 30313233 34353637",
        );
        let iv = hex("e96e8c08 ab465763 fd098d45 dd3ff893");
        let packet = seal_with_iv(&keys, 0x4321, 1, &iv, 1, &data);
        assert_eq!(&packet[..8], &hex("00004321 00000001")[..]);
        assert_eq!(&packet[8..24], &iv[..]);
        assert_eq!(
            &packet[24..],
            &hex(
                "f663c25d 325c18c6 a9453e19 4e120849 a4870b66 cc6b9965 330013b4 898dc856
                 a4699e52 3a55db08 0b59ec3a 8e4b7e52 775b07d1 db34ed9c 538ab50c 551b874a
                 a269add0 47ad2d59 13ac19b7 cfbad4a6"
            )[..]
        );
        let mut inbound =
            InboundSa::new(0x4321, cbc_only("90d382b4 10eeba7a d938c46c ec1a82bf"), 64);
        assert_eq!(inbound.open(&packet), Ok((1, data)));
    }

    /// RFC 3602, case #7: tunnel-mode ESP packet.
    #[test]
    fn rfc3602_case_7_tunnel_mode() {
        let keys = cbc_only("01234567 89abcdef 01234567 89abcdef");
        let inner = hex(
            "45000054 09040000 4001f988 c0a87b03 c0a87bc8 08009f76 a90a0100 b49c083d
             02a20400 08090a0b 0c0d0e0f 10111213 14151617 18191a1b 1c1d1e1f 20212223
             24252627 28292a2b 2c2d2e2f 30313233 34353637",
        );
        let iv = hex("f4e76524 4f6407ad f13dc138 0f673f37");
        let packet = seal_with_iv(&keys, 0x8765, 2, &iv, NEXT_HEADER_IPV4, &inner);
        assert_eq!(&packet[..8], &hex("00008765 00000002")[..]);
        assert_eq!(
            &packet[24..],
            &hex(
                "773b5241 a4c44922 5e4f3ce5 ed611b0c 237ca96c f74a9301 3c1b0ea1 a0cf70f8
                 e4ecaec7 8ac53aad 7a0f022b 859243c6 47752e94 a859352b 8a4d4d2d ecd136e5
                 c177f132 ad3fbfb2 201ac990 4c74ee0a 109e0ca1 e4dfe9d5 a100b842 f1c22f0d"
            )[..]
        );
    }

    /// RFC 4231, test case 1: the HMAC-SHA-256 primitive the ICV is cut from.
    #[test]
    fn rfc4231_hmac_sha256() {
        let mut m = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&[0x0b; 20]).unwrap();
        m.update(b"Hi There");
        assert_eq!(
            m.finalize().into_bytes()[..].to_vec(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        assert_eq!(Integrity::HmacSha256_128.icv_len(), 16);
    }

    /// AES-128-GCM, McGrew & Viega test case 2 (zero key, zero nonce, one zero block).
    #[test]
    fn gcm_known_answer() {
        let mut buf = vec![0u8; 16];
        let tag = gcm_seal(&[0u8; 16], &[0; 4], &[0; 8], &[], &mut buf);
        assert_eq!(buf, hex("0388dace60b6a392f328c2b971b2fe78"));
        assert_eq!(tag, hex("ab6e47d42cec13bdf53a67b21257bddf"));
    }

    fn suites() -> Vec<(&'static str, Keys)> {
        let k = |n: usize| (0..n).map(|i| i as u8).collect::<Vec<u8>>();
        vec![
            (
                "cbc128-sha1",
                Keys::new(Cipher::AesCbc(k(16)), Integrity::HmacSha1_96, k(20)).unwrap(),
            ),
            (
                "cbc192-sha256",
                Keys::new(Cipher::AesCbc(k(24)), Integrity::HmacSha256_128, k(32)).unwrap(),
            ),
            (
                "cbc256-sha384",
                Keys::new(Cipher::AesCbc(k(32)), Integrity::HmacSha384_192, k(48)).unwrap(),
            ),
            (
                "cbc256-sha512",
                Keys::new(Cipher::AesCbc(k(32)), Integrity::HmacSha512_256, k(64)).unwrap(),
            ),
            (
                "gcm128",
                Keys::new(
                    Cipher::AesGcm16 {
                        key: k(16),
                        salt: [1, 2, 3, 4],
                    },
                    Integrity::None,
                    Vec::new(),
                )
                .unwrap(),
            ),
            (
                "gcm256",
                Keys::new(
                    Cipher::AesGcm16 {
                        key: k(32),
                        salt: [9, 9, 9, 9],
                    },
                    Integrity::None,
                    Vec::new(),
                )
                .unwrap(),
            ),
        ]
    }

    #[test]
    fn every_suite_round_trips_and_detects_tampering() {
        for (name, keys) in suites() {
            let mut out = OutboundSa::new(0x1000, keys.clone());
            let mut inb = InboundSa::new(0x1000, keys, 128);
            for len in [0usize, 1, 20, 63, 64, 1400] {
                let inner: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
                let packet = out.seal(NEXT_HEADER_IPV4, &inner).unwrap();
                assert_eq!(
                    inb.open(&packet),
                    Ok((NEXT_HEADER_IPV4, inner)),
                    "{name} len {len}"
                );

                let mut bad = out.seal(NEXT_HEADER_IPV6, &[1, 2, 3]).unwrap();
                let last = bad.len() - 1;
                bad[last] ^= 0x01;
                assert_eq!(inb.open(&bad), Err(EspError::IntegrityFailed), "{name}");
            }
        }
    }

    #[test]
    fn replays_and_wrong_spi_are_rejected() {
        let (_, keys) = suites().remove(1);
        let mut out = OutboundSa::new(7, keys.clone());
        let mut inb = InboundSa::new(7, keys.clone(), 64);
        let p1 = out.seal(NEXT_HEADER_IPV4, b"one").unwrap();
        assert!(inb.open(&p1).is_ok());
        assert_eq!(inb.open(&p1), Err(EspError::Replay(1)));
        let mut other = InboundSa::new(8, keys, 64);
        assert_eq!(other.open(&p1), Err(EspError::WrongSpi(7)));
        assert_eq!(inb.open(&p1[..10]), Err(EspError::Malformed));
    }

    #[test]
    fn bad_key_combinations() {
        assert!(
            Keys::new(
                Cipher::AesCbc(vec![0; 15]),
                Integrity::HmacSha1_96,
                vec![0; 20]
            )
            .is_err()
        );
        assert!(
            Keys::new(
                Cipher::AesCbc(vec![0; 16]),
                Integrity::HmacSha1_96,
                vec![0; 19]
            )
            .is_err()
        );
        let gcm = Cipher::AesGcm16 {
            key: vec![0; 16],
            salt: [0; 4],
        };
        assert!(Keys::new(gcm, Integrity::HmacSha1_96, vec![0; 20]).is_err());
        let keys = Keys::new(
            Cipher::AesCbc(vec![0; 16]),
            Integrity::HmacSha1_96,
            vec![0; 20],
        )
        .unwrap();
        assert_eq!(format!("{keys:?}"), "Keys(AES-128-CBC, HmacSha1_96, ***)");
    }

    #[test]
    fn outbound_sequence_never_wraps() {
        let (_, keys) = suites().remove(0);
        let mut out = OutboundSa::new(1, keys);
        out.seq = u32::MAX - 1;
        assert!(out.seal(4, b"x").is_ok());
        assert_eq!(out.seal(4, b"x"), Err(EspError::SequenceExhausted));
    }
}
