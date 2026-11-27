//! A server certificate's SHA-256 fingerprint, for servers whose certificate the operating
//! system does not trust (a FortiGate's factory certificate, for one). A profile that names
//! one trusts exactly that certificate and nothing else for its server.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CertFingerprint([u8; 32]);

impl CertFingerprint {
    /// From a SHA-256 digest of the certificate's DER bytes.
    pub fn from_digest(digest: [u8; 32]) -> Self {
        CertFingerprint(digest)
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.0
    }

    /// `01:23:AB:...`, as certificate viewers show it.
    pub fn colon_hex(&self) -> String {
        self.0
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// `sha256:` and 64 lower-case hex digits (the form profiles store).
impl fmt::Display for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Accepts the stored form and what certificate viewers show: an optional `sha256:` prefix,
/// then 64 hex digits, in any case, optionally separated by `:` or spaces.
impl FromStr for CertFingerprint {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let s = s
            .get(..7)
            .filter(|p| p.eq_ignore_ascii_case("sha256:"))
            .map_or(s, |_| &s[7..]);
        let hex: Vec<u8> = s.bytes().filter(|b| !matches!(b, b':' | b' ')).collect();
        let invalid = || {
            "a certificate fingerprint is sha256: and 64 hex digits (colons allowed)".to_string()
        };
        if hex.len() != 64 || s.len() > 200 {
            return Err(invalid());
        }
        let mut digest = [0u8; 32];
        for (i, pair) in hex.chunks(2).enumerate() {
            let text = std::str::from_utf8(pair).map_err(|_| invalid())?;
            digest[i] = u8::from_str_radix(text, 16).map_err(|_| invalid())?;
        }
        Ok(CertFingerprint(digest))
    }
}

impl TryFrom<String> for CertFingerprint {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<CertFingerprint> for String {
    fn from(pin: CertFingerprint) -> String {
        pin.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn accepts_the_common_spellings() {
        let pin: CertFingerprint = format!("sha256:{HEX}").parse().unwrap();
        assert_eq!(pin.to_string(), format!("sha256:{HEX}"));
        let colons = "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:\
                      01:23:45:67:89:AB:CD:EF";
        assert_eq!(colons.parse::<CertFingerprint>().unwrap(), pin);
        assert_eq!(
            format!("SHA256:{colons}")
                .parse::<CertFingerprint>()
                .unwrap(),
            pin
        );
        assert_eq!(HEX.parse::<CertFingerprint>().unwrap(), pin);
        assert_eq!(pin.colon_hex(), colons);
    }

    #[test]
    fn rejects_anything_else() {
        for bad in [
            "",
            "sha256:",
            &HEX[..62],
            &format!("{HEX}00"),
            &HEX.replace('8', "g"),
            "sha1:0123456789abcdef0123456789abcdef01234567",
            &format!("sha256:{HEX}\n"),
        ] {
            let parsed = bad.parse::<CertFingerprint>();
            if bad.ends_with('\n') {
                // Surrounding whitespace is trimmed.
                assert!(parsed.is_ok());
            } else {
                assert!(parsed.is_err(), "{bad:?}");
            }
        }
    }

    #[test]
    fn serde_round_trip_validates() {
        let pin: CertFingerprint = HEX.parse().unwrap();
        let json = serde_json::to_string(&pin).unwrap();
        assert_eq!(json, format!("\"sha256:{HEX}\""));
        assert_eq!(serde_json::from_str::<CertFingerprint>(&json).unwrap(), pin);
        assert!(serde_json::from_str::<CertFingerprint>("\"sha256:00\"").is_err());
    }
}
