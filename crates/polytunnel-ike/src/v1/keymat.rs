//! IKEv1 keying material ([RFC 2409] section 5, appendix B) and message encryption.
//!
//! [RFC 2409]: https://www.rfc-editor.org/rfc/rfc2409

use std::collections::HashMap;

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use zeroize::Zeroizing;

use super::wire::{Header, WireError, flag};
use crate::prf::HashAlg;

/// AES block size: IKE messages are padded to it and IVs are cut to it.
pub const BLOCK: usize = 16;

/// What phase 1 contributes to the keys (all `_b` values are payload bodies).
pub struct Material<'a> {
    pub psk: &'a [u8],
    pub ni_b: &'a [u8],
    pub nr_b: &'a [u8],
    pub gxy: &'a [u8],
    pub gxi: &'a [u8],
    pub gxr: &'a [u8],
    pub cky_i: [u8; 8],
    pub cky_r: [u8; 8],
}

/// The ISAKMP SA's keys, plus the CBC state of each exchange running under it.
pub struct Phase1 {
    hash: HashAlg,
    skeyid: Zeroizing<Vec<u8>>,
    skeyid_d: Zeroizing<Vec<u8>>,
    skeyid_a: Zeroizing<Vec<u8>>,
    key: Zeroizing<Vec<u8>>,
    /// The last CBC block of phase 1 (its starting IV while phase 1 sent nothing encrypted).
    phase1_iv: Vec<u8>,
    /// The running IV of each exchange (by message ID).
    ivs: HashMap<u32, Vec<u8>>,
}

impl Phase1 {
    /// Pre-shared key authentication: SKEYID = prf(psk, Ni_b | Nr_b).
    pub fn derive(hash: HashAlg, key_len: usize, m: &Material<'_>) -> Self {
        let skeyid = Zeroizing::new(hash.prf(m.psk, &[m.ni_b, m.nr_b]));
        let d = Zeroizing::new(hash.prf(&skeyid, &[m.gxy, &m.cky_i, &m.cky_r, &[0]]));
        let a = Zeroizing::new(hash.prf(&skeyid, &[&d, m.gxy, &m.cky_i, &m.cky_r, &[1]]));
        let e = Zeroizing::new(hash.prf(&skeyid, &[&a, m.gxy, &m.cky_i, &m.cky_r, &[2]]));
        let key = if e.len() >= key_len {
            Zeroizing::new(e[..key_len].to_vec())
        } else {
            // Appendix B: Ka = K1 | K2 | ..., K1 = prf(SKEYID_e, 0), Kn = prf(SKEYID_e, Kn-1).
            let mut out = Zeroizing::new(Vec::with_capacity(key_len + hash.output_len()));
            let mut k = hash.prf(&e, &[&[0]]);
            while out.len() < key_len {
                out.extend_from_slice(&k);
                k = hash.prf(&e, &[&k]);
            }
            out.truncate(key_len);
            out
        };
        Self {
            hash,
            phase1_iv: hash.hash(&[m.gxi, m.gxr])[..BLOCK].to_vec(),
            skeyid,
            skeyid_d: d,
            skeyid_a: a,
            key,
            ivs: HashMap::new(),
        }
    }

    pub fn hash_alg(&self) -> HashAlg {
        self.hash
    }

    /// HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b).
    pub fn hash_i(&self, m: &Material<'_>, sai_b: &[u8], idii_b: &[u8]) -> Vec<u8> {
        self.hash.prf(
            &self.skeyid,
            &[m.gxi, m.gxr, &m.cky_i, &m.cky_r, sai_b, idii_b],
        )
    }

    /// HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b).
    pub fn hash_r(&self, m: &Material<'_>, sai_b: &[u8], idir_b: &[u8]) -> Vec<u8> {
        self.hash.prf(
            &self.skeyid,
            &[m.gxr, m.gxi, &m.cky_r, &m.cky_i, sai_b, idir_b],
        )
    }

    /// prf(SKEYID_a, ...): the HASH payloads of every exchange after phase 1.
    pub fn prf_a(&self, parts: &[&[u8]]) -> Vec<u8> {
        self.hash.prf(&self.skeyid_a, parts)
    }

    /// Quick-mode keying material for one SA (the SPI is the receiver's):
    /// K1 = prf(SKEYID_d, [g(qm)^xy |] protocol | SPI | Ni_b | Nr_b), Kn = prf(SKEYID_d, Kn-1 | ...).
    pub fn keymat(
        &self,
        gqm: Option<&[u8]>,
        protocol: u8,
        spi: &[u8],
        nonces: (&[u8], &[u8]),
        len: usize,
    ) -> Zeroizing<Vec<u8>> {
        let gqm = gqm.unwrap_or(&[]);
        let (ni_b, nr_b) = nonces;
        let mut out = Zeroizing::new(Vec::with_capacity(len + self.hash.output_len()));
        let mut k: Vec<u8> = Vec::new();
        while out.len() < len {
            k = self
                .hash
                .prf(&self.skeyid_d, &[&k, gqm, &[protocol], spi, ni_b, nr_b]);
            out.extend_from_slice(&k);
        }
        out.truncate(len);
        out
    }

    fn iv(&self, mid: u32) -> Vec<u8> {
        if mid == 0 {
            return self.phase1_iv.clone();
        }
        self.ivs.get(&mid).cloned().unwrap_or_else(|| {
            self.hash.hash(&[&self.phase1_iv, &mid.to_be_bytes()])[..BLOCK].to_vec()
        })
    }

    /// Encrypts a payload chain into a complete message (sets the encryption flag).
    pub fn encrypt(&mut self, header: Header, chain: &[u8]) -> Vec<u8> {
        // Appendix B padding: zeros, then a last byte counting the zeros; always present.
        let pad = (BLOCK - (chain.len() + 1) % BLOCK) % BLOCK;
        let mut body = chain.to_vec();
        body.resize(chain.len() + pad, 0);
        body.push(u8::try_from(pad).expect("below the block size"));
        let iv = self.iv(header.mid);
        let len = body.len();
        cbc_encrypt(&self.key, &iv, &mut body, len);
        self.set_iv(header.mid, body[len - BLOCK..].to_vec());
        let header = Header {
            flags: header.flags | flag::ENCRYPTED,
            ..header
        };
        let mut out = header.encode(body.len()).to_vec();
        out.extend_from_slice(&body);
        out
    }

    /// Decrypts a message body. Returns the plaintext and the IV that follows this message,
    /// to be committed with [`Phase1::set_iv`] only once the message has authenticated.
    pub fn decrypt(&self, header: &Header, body: &[u8]) -> Result<(Vec<u8>, Vec<u8>), WireError> {
        if body.is_empty() || !body.len().is_multiple_of(BLOCK) {
            return Err(WireError("encrypted body is not whole blocks"));
        }
        let next_iv = body[body.len() - BLOCK..].to_vec();
        let mut plain = body.to_vec();
        cbc_decrypt(&self.key, &self.iv(header.mid), &mut plain);
        Ok((plain, next_iv))
    }

    pub fn set_iv(&mut self, mid: u32, iv: Vec<u8>) {
        if mid == 0 {
            self.phase1_iv = iv;
        } else {
            self.ivs.insert(mid, iv);
        }
    }

    /// Forgets a finished exchange's CBC state.
    pub fn forget(&mut self, mid: u32) {
        self.ivs.remove(&mid);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::wire::{Chain, Payload, encode_chain, exchange, payload};

    pub(crate) fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn material<'a>(gxy: &'a [u8], gxi: &'a [u8], gxr: &'a [u8]) -> Material<'a> {
        Material {
            psk: b"test-psk",
            ni_b: &[0x11; 16],
            nr_b: &[0x22; 16],
            gxy,
            gxi,
            gxr,
            cky_i: [1, 2, 3, 4, 5, 6, 7, 8],
            cky_r: [9, 10, 11, 12, 13, 14, 15, 16],
        }
    }

    // The expected values come from an independent implementation of the RFC 2409 formulas
    // (Python's hmac/hashlib), over these fixed inputs.
    #[test]
    fn phase1_known_answers_sha1_aes256() {
        let (gxy, gxi, gxr) = ([0x33; 128], [0x44; 128], [0x55; 128]);
        let m = material(&gxy, &gxi, &gxr);
        let p1 = Phase1::derive(HashAlg::Sha1, 32, &m);
        assert_eq!(*p1.skeyid, hex(KAT_SHA1_SKEYID));
        assert_eq!(*p1.skeyid_d, hex(KAT_SHA1_D));
        assert_eq!(*p1.skeyid_a, hex(KAT_SHA1_A));
        // SHA-1 output (20 bytes) is shorter than an AES-256 key: appendix B expansion.
        assert_eq!(*p1.key, hex(KAT_SHA1_KEY));
        assert_eq!(p1.phase1_iv, hex(KAT_SHA1_IV));
        assert_eq!(p1.hash_i(&m, b"sa", b"idi"), hex(KAT_SHA1_HASH_I));
        assert_eq!(p1.hash_r(&m, b"sa", b"idr"), hex(KAT_SHA1_HASH_R));
        assert_eq!(p1.iv(0x0102_0304), hex(KAT_SHA1_IV2));
        assert_eq!(
            *p1.keymat(
                None,
                3,
                &[0xa0, 0xb0, 0xc0, 0xd0],
                (&[0x66; 16], &[0x77; 16]),
                52
            ),
            hex(KAT_SHA1_KEYMAT)
        );
        assert_eq!(
            *p1.keymat(
                Some(&[0x88; 128]),
                3,
                &[0xa0, 0xb0, 0xc0, 0xd0],
                (&[0x66; 16], &[0x77; 16]),
                36
            ),
            hex(KAT_SHA1_KEYMAT_PFS)
        );
    }

    #[test]
    fn phase1_known_answers_sha256_aes128() {
        let (gxy, gxi, gxr) = ([0x33; 256], [0x44; 256], [0x55; 256]);
        let m = material(&gxy, &gxi, &gxr);
        let p1 = Phase1::derive(HashAlg::Sha256, 16, &m);
        assert_eq!(*p1.skeyid, hex(KAT_SHA256_SKEYID));
        assert_eq!(*p1.key, hex(KAT_SHA256_KEY));
        assert_eq!(p1.phase1_iv, hex(KAT_SHA256_IV));
    }

    #[test]
    fn encryption_round_trips_and_chains_ivs() {
        let (gxy, gxi, gxr) = ([0x33; 128], [0x44; 128], [0x55; 128]);
        let m = material(&gxy, &gxi, &gxr);
        let mut alice = Phase1::derive(HashAlg::Sha256, 32, &m);
        let mut bob = Phase1::derive(HashAlg::Sha256, 32, &m);
        let header = Header {
            cky_i: m.cky_i,
            cky_r: m.cky_r,
            next: payload::HASH,
            exchange: exchange::QUICK,
            flags: 0,
            mid: 77,
            len: 0,
        };
        for round in 0..3u8 {
            let chain = encode_chain(&[
                Payload::new(payload::HASH, vec![round; 20]),
                Payload::new(payload::NONCE, vec![round; 1 + usize::from(round) * 7]),
            ]);
            let msg = alice.encrypt(header, &chain);
            let (h, body) = Header::parse(&msg).unwrap();
            assert!(h.encrypted());
            assert_eq!(body.len() % BLOCK, 0);
            assert!(body.len() > chain.len());
            let (plain, next) = bob.decrypt(&h, body).unwrap();
            let parsed = Chain::parse(payload::HASH, &plain).unwrap();
            assert_eq!(parsed.payloads.len(), 2);
            assert_eq!(
                usize::from(*plain.last().unwrap()) + 1,
                plain.len() - chain.len()
            );
            bob.set_iv(h.mid, next);
        }
        assert!(bob.decrypt(&header, &[0; 15]).is_err());
    }

    const KAT_SHA1_SKEYID: &str = "928a0ab70c3de993a1bc4471bff6ecfad243edcd";
    const KAT_SHA1_D: &str = "e4791e86c9e6f4b88c03e4d5f9b1d294406ee100";
    const KAT_SHA1_A: &str = "287aac527df304d0058360cbe1cc82857c499dc7";
    const KAT_SHA1_KEY: &str = "f9665dd8d54e13cb2fd9cfd39a0c65e7fa50474fefa13f4b4b69b59342287e00";
    const KAT_SHA1_IV: &str = "979693df00d8529bc43ac5c9c1e27f6b";
    const KAT_SHA1_HASH_I: &str = "9aa0e9d0764bdd13267abb28c65cc9f191d5827a";
    const KAT_SHA1_HASH_R: &str = "afd05b0f724d14e80afeb8897e17f3618219839a";
    const KAT_SHA1_IV2: &str = "dd53a1c3a5e5c434ea5c99ada7605b66";
    const KAT_SHA1_KEYMAT: &str = "87f7f0782a499f169a4d01666fe225e4002d660255e120e83006844cca3f2e598c2f2d5ccf89297466b32bf95e4d3e4b247c3291";
    const KAT_SHA1_KEYMAT_PFS: &str =
        "87b044f4272c620abf802481c1a9638f1cea19c542a3e67d75353b5c9dc086de6a91d5c1";
    const KAT_SHA256_SKEYID: &str =
        "b1d8cb48b375ef9fad053d26fa52e330a7924658a4faa2a08088c05f733c7fd5";
    const KAT_SHA256_KEY: &str = "1a896293fe54dc7195e2f967383532ab";
    const KAT_SHA256_IV: &str = "f7a78f39d63ac4f93e99723c55b494ca";
}
