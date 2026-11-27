//! The hash negotiated for IKE: plain hashes (IVs, NAT detection) and HMAC, the IKE prf.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Digest;

/// Hash algorithms IKE can negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlg {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub const ALL: [HashAlg; 5] = [
        HashAlg::Md5,
        HashAlg::Sha1,
        HashAlg::Sha256,
        HashAlg::Sha384,
        HashAlg::Sha512,
    ];

    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Md5 => 16,
            HashAlg::Sha1 => 20,
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    /// The name used in profiles: `md5`, `sha1`, `sha256`, `sha384`, `sha512`.
    pub fn name(self) -> &'static str {
        match self {
            HashAlg::Md5 => "md5",
            HashAlg::Sha1 => "sha1",
            HashAlg::Sha256 => "sha256",
            HashAlg::Sha384 => "sha384",
            HashAlg::Sha512 => "sha512",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|h| h.name().eq_ignore_ascii_case(name))
    }

    /// The plain hash of the concatenated `parts`.
    pub fn hash(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for part in parts {
                d.update(part);
            }
            d.finalize().to_vec()
        }
        match self {
            HashAlg::Md5 => run::<md5::Md5>(parts),
            HashAlg::Sha1 => run::<sha1::Sha1>(parts),
            HashAlg::Sha256 => run::<sha2::Sha256>(parts),
            HashAlg::Sha384 => run::<sha2::Sha384>(parts),
            HashAlg::Sha512 => run::<sha2::Sha512>(parts),
        }
    }

    /// HMAC of the concatenated `parts` under `key`: IKE's prf.
    pub fn prf(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        fn run<M: Mac + KeyInit>(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            let mut m = <M as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
            for part in parts {
                m.update(part);
            }
            m.finalize().into_bytes().to_vec()
        }
        match self {
            HashAlg::Md5 => run::<Hmac<md5::Md5>>(key, parts),
            HashAlg::Sha1 => run::<Hmac<sha1::Sha1>>(key, parts),
            HashAlg::Sha256 => run::<Hmac<sha2::Sha256>>(key, parts),
            HashAlg::Sha384 => run::<Hmac<sha2::Sha384>>(key, parts),
            HashAlg::Sha512 => run::<Hmac<sha2::Sha512>>(key, parts),
        }
    }
}

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
    fn rfc_hmac_test_vectors() {
        // RFC 2202 test case 2 (HMAC-MD5, HMAC-SHA1) and RFC 4231 test case 2 (HMAC-SHA-256).
        let key = b"Jefe";
        let data: &[&[u8]] = &[b"what do ya want ", b"for nothing?"];
        assert_eq!(
            HashAlg::Md5.prf(key, data),
            hex("750c783e6ab0b503eaa86e310a5db738")
        );
        assert_eq!(
            HashAlg::Sha1.prf(key, data),
            hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
        );
        assert_eq!(
            HashAlg::Sha256.prf(key, data),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        assert_eq!(HashAlg::Sha384.prf(key, data).len(), 48);
        assert_eq!(HashAlg::Sha512.prf(key, data).len(), 64);
    }

    #[test]
    fn plain_hashes() {
        assert_eq!(
            HashAlg::Sha1.hash(&[b"a", b"bc"]),
            hex("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        for h in HashAlg::ALL {
            assert_eq!(h.hash(&[b"x"]).len(), h.output_len());
            assert_eq!(HashAlg::from_name(h.name()), Some(h));
        }
    }
}
