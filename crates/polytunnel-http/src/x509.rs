//! What people need to see to decide whether to trust a server's certificate: who it was
//! issued to and by, when it is valid, the names it covers and its fingerprint.
//!
//! A small DER reader for X.509 certificates (RFC 5280) that reads only those fields. It
//! never fails: whatever it cannot read is left empty, and the fingerprint (taken over the
//! whole certificate) is always there.

use polytunnel_core::pin::CertFingerprint;

use crate::fingerprint;

/// The parts of a subject or issuer name that are shown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertName {
    /// CN
    pub common_name: Option<String>,
    /// O
    pub organization: Option<String>,
    /// OU
    pub organizational_unit: Option<String>,
}

impl CertName {
    /// `CN, O, OU`, leaving out the parts that are not set; empty when none is.
    pub fn summary(&self) -> String {
        [
            &self.common_name,
            &self.organization,
            &self.organizational_unit,
        ]
        .into_iter()
        .flatten()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
    }
}

/// A server certificate, as shown to someone deciding whether to trust it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub fingerprint: CertFingerprint,
    pub subject: CertName,
    pub issuer: CertName,
    /// The first day it is valid, `YYYY-MM-DD` (UTC).
    pub not_before: Option<String>,
    /// The last day it is valid, `YYYY-MM-DD` (UTC).
    pub not_after: Option<String>,
    /// The DNS names in its subject alternative names.
    pub dns_names: Vec<String>,
    /// Issued by itself (the subject and issuer names are the same), like a FortiGate's
    /// factory certificate.
    pub self_signed: bool,
}

/// Whether a certificate is within its validity period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    Valid,
    Expired,
    NotYetValid,
    /// The dates could not be read.
    Unknown,
}

impl CertInfo {
    /// Reads a certificate (DER).
    pub fn from_der(der: &[u8]) -> CertInfo {
        let parsed = parse(der).unwrap_or_default();
        CertInfo {
            fingerprint: fingerprint(der),
            subject: parsed.subject,
            issuer: parsed.issuer,
            not_before: parsed.not_before,
            not_after: parsed.not_after,
            dns_names: parsed.dns_names,
            self_signed: parsed.self_signed,
        }
    }

    /// Whether the certificate is valid today (UTC).
    pub fn validity(&self) -> Validity {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.validity_on(&utc_date(now))
    }

    /// Whether the certificate is valid on `day` (`YYYY-MM-DD`).
    pub fn validity_on(&self, day: &str) -> Validity {
        match (&self.not_before, &self.not_after) {
            (Some(from), _) if day < from.as_str() => Validity::NotYetValid,
            (_, Some(until)) if day > until.as_str() => Validity::Expired,
            (Some(_), Some(_)) => Validity::Valid,
            _ => Validity::Unknown,
        }
    }
}

/// The UTC date of a Unix time, `YYYY-MM-DD`.
pub fn utc_date(unix_secs: u64) -> String {
    // Days to civil date (Howard Hinnant's algorithm).
    let z = (unix_secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Text from a certificate is capped at this many characters.
const MAX_TEXT: usize = 200;
/// At most this many DNS names are kept.
const MAX_NAMES: usize = 50;

const BOOLEAN: u8 = 0x01;
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
/// `[0] EXPLICIT Version`
const VERSION: u8 = 0xA0;
/// `[3] EXPLICIT Extensions`
const EXTENSIONS: u8 = 0xA3;
/// `dNSName [2] IMPLICIT IA5String` in a GeneralName.
const DNS_NAME: u8 = 0x82;

/// The encoded object identifiers id-at-commonName, id-at-organizationName,
/// id-at-organizationalUnitName and id-ce-subjectAltName.
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_O: &[u8] = &[0x55, 0x04, 0x0A];
const OID_OU: &[u8] = &[0x55, 0x04, 0x0B];
const OID_SAN: &[u8] = &[0x55, 0x1D, 0x11];

#[derive(Default)]
struct Parsed {
    subject: CertName,
    issuer: CertName,
    not_before: Option<String>,
    not_after: Option<String>,
    dns_names: Vec<String>,
    self_signed: bool,
}

/// One DER element: its tag and its contents.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

/// Reads DER elements one after another.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn next(&mut self) -> Option<Tlv<'a>> {
        let (&tag, rest) = self.0.split_first()?;
        // Multi-byte tags never occur in the fields read here.
        if tag & 0x1F == 0x1F {
            return None;
        }
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            // Long form; DER has no indefinite lengths.
            let n = usize::from(first & 0x7F);
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let len = rest[..n]
                .iter()
                .fold(0usize, |len, b| len << 8 | usize::from(*b));
            (len, &rest[n..])
        };
        if rest.len() < len {
            return None;
        }
        let (value, after) = rest.split_at(len);
        self.0 = after;
        Some(Tlv { tag, value })
    }

    fn expect(&mut self, tag: u8) -> Option<Tlv<'a>> {
        self.next().filter(|t| t.tag == tag)
    }
}

fn parse(der: &[u8]) -> Option<Parsed> {
    let certificate = Reader(der).expect(SEQUENCE)?;
    let tbs = Reader(certificate.value).expect(SEQUENCE)?;
    let mut tbs = Reader(tbs.value);
    let mut field = tbs.next()?;
    if field.tag == VERSION {
        field = tbs.next()?;
    }
    if field.tag != INTEGER {
        return None; // the serial number
    }
    tbs.expect(SEQUENCE)?; // the signature algorithm
    let issuer = tbs.expect(SEQUENCE)?;
    let validity = tbs.expect(SEQUENCE)?;
    let subject = tbs.expect(SEQUENCE)?;
    tbs.expect(SEQUENCE)?; // the public key
    let mut dns_names = Vec::new();
    // The unique identifiers ([1], [2]) are skipped; the extensions come last.
    while let Some(field) = tbs.next() {
        if field.tag == EXTENSIONS {
            dns_names = san_dns_names(field.value);
        }
    }
    let mut validity = Reader(validity.value);
    let not_before = validity.next().and_then(|t| date(&t));
    let not_after = validity.next().and_then(|t| date(&t));
    Some(Parsed {
        subject: name(subject.value),
        issuer: name(issuer.value),
        not_before,
        not_after,
        dns_names,
        self_signed: subject.value == issuer.value,
    })
}

/// The CN, O and OU of a `Name` (a sequence of sets of type-value pairs); the first of each.
fn name(value: &[u8]) -> CertName {
    let mut out = CertName::default();
    let mut rdns = Reader(value);
    while let Some(rdn) = rdns.next() {
        if rdn.tag != SET {
            continue;
        }
        let mut attributes = Reader(rdn.value);
        while let Some(attribute) = attributes.next() {
            if attribute.tag != SEQUENCE {
                continue;
            }
            let mut parts = Reader(attribute.value);
            let (Some(oid), Some(value)) = (parts.expect(OID), parts.next()) else {
                continue;
            };
            let slot = match oid.value {
                OID_CN => &mut out.common_name,
                OID_O => &mut out.organization,
                OID_OU => &mut out.organizational_unit,
                _ => continue,
            };
            if slot.is_none() {
                *slot = text(&value).filter(|s| !s.is_empty());
            }
        }
    }
    out
}

/// A directory string as text.
fn text(t: &Tlv) -> Option<String> {
    let raw: String = match t.tag {
        // UTF8String
        0x0C => String::from_utf8_lossy(t.value).into_owned(),
        // PrintableString, IA5String and VisibleString are ASCII; TeletexString is read as
        // Latin-1, as most software does.
        0x13 | 0x16 | 0x1A | 0x14 => t.value.iter().map(|&b| char::from(b)).collect(),
        // BMPString: UTF-16, big-endian.
        0x1E => {
            let (pairs, _) = t.value.as_chunks::<2>();
            let units: Vec<u16> = pairs.iter().map(|c| u16::from_be_bytes(*c)).collect();
            String::from_utf16_lossy(&units)
        }
        // UniversalString: UTF-32, big-endian.
        0x1C => {
            let (quads, _) = t.value.as_chunks::<4>();
            quads
                .iter()
                .map(|c| {
                    char::from_u32(u32::from_be_bytes(*c)).unwrap_or(char::REPLACEMENT_CHARACTER)
                })
                .collect()
        }
        _ => return None,
    };
    Some(clean(&raw))
}

/// Without control characters or ones that change the text's direction (either could make
/// the text read differently from what it is), trimmed and capped.
fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
        .take(MAX_TEXT)
        .collect::<String>()
        .trim()
        .to_string()
}

/// A UTCTime or GeneralizedTime as `YYYY-MM-DD`.
fn date(t: &Tlv) -> Option<String> {
    let number = |digits: &[u8]| -> Option<u32> {
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(digits).ok()?.parse().ok()
    };
    let (year, rest) = match t.tag {
        // YYMMDD...: 50-99 are 1950-1999 (RFC 5280).
        UTC_TIME if t.value.len() >= 6 => {
            let yy = number(&t.value[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &t.value[2..])
        }
        // YYYYMMDD...
        GENERALIZED_TIME if t.value.len() >= 8 => (number(&t.value[..4])?, &t.value[4..]),
        _ => return None,
    };
    let month = number(&rest[..2])?;
    let day = number(&rest[2..4])?;
    ((1..=12).contains(&month) && (1..=31).contains(&day))
        .then(|| format!("{year:04}-{month:02}-{day:02}"))
}

/// The DNS names in the subject alternative name extension.
fn san_dns_names(extensions: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let Some(list) = Reader(extensions).expect(SEQUENCE) else {
        return names;
    };
    let mut list = Reader(list.value);
    while let Some(extension) = list.next() {
        if extension.tag != SEQUENCE {
            continue;
        }
        let mut parts = Reader(extension.value);
        if parts.expect(OID).map(|oid| oid.value) != Some(OID_SAN) {
            continue;
        }
        let mut value = parts.next();
        if value.as_ref().is_some_and(|v| v.tag == BOOLEAN) {
            value = parts.next(); // critical
        }
        let Some(value) = value.filter(|v| v.tag == OCTET_STRING) else {
            continue;
        };
        let Some(general_names) = Reader(value.value).expect(SEQUENCE) else {
            continue;
        };
        let mut general_names = Reader(general_names.value);
        while let Some(general_name) = general_names.next() {
            if general_name.tag == DNS_NAME && names.len() < MAX_NAMES {
                let name = clean(&String::from_utf8_lossy(general_name.value));
                if !name.is_empty() {
                    names.push(name);
                }
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use rcgen::string::BmpString;
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, DnValue, IsCa, Issuer, KeyPair, date_time_ymd,
    };

    use super::*;

    fn named(cn: &str, o: Option<&str>, ou: Option<&str>) -> DistinguishedName {
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, cn);
        if let Some(o) = o {
            name.push(DnType::OrganizationName, o);
        }
        if let Some(ou) = ou {
            name.push(DnType::OrganizationalUnitName, ou);
        }
        name
    }

    #[test]
    fn reads_a_self_signed_certificate() {
        let mut params =
            CertificateParams::new(vec!["vpn.example.com".into(), "fw.example.net".into()])
                .unwrap();
        params.distinguished_name = named("FGT-TEST", Some("Example Org"), Some("Firewalls"));
        params.not_before = date_time_ymd(2024, 1, 2);
        params.not_after = date_time_ymd(2049, 12, 31);
        let key = KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap().der().to_vec();

        let info = CertInfo::from_der(&der);
        assert_eq!(info.fingerprint, fingerprint(&der));
        assert_eq!(info.subject.common_name.as_deref(), Some("FGT-TEST"));
        assert_eq!(info.subject.organization.as_deref(), Some("Example Org"));
        assert_eq!(
            info.subject.organizational_unit.as_deref(),
            Some("Firewalls")
        );
        assert_eq!(info.subject.summary(), "FGT-TEST, Example Org, Firewalls");
        assert_eq!(info.issuer, info.subject);
        assert!(info.self_signed);
        // UTCTime (before 2050).
        assert_eq!(info.not_before.as_deref(), Some("2024-01-02"));
        assert_eq!(info.not_after.as_deref(), Some("2049-12-31"));
        assert_eq!(info.dns_names, ["vpn.example.com", "fw.example.net"]);
        assert_eq!(info.validity_on("2024-01-01"), Validity::NotYetValid);
        assert_eq!(info.validity_on("2024-01-02"), Validity::Valid);
        assert_eq!(info.validity_on("2049-12-31"), Validity::Valid);
        assert_eq!(info.validity_on("2050-01-01"), Validity::Expired);
    }

    #[test]
    fn reads_a_certificate_issued_by_a_ca() {
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name = named("Example Test CA", Some("Example CA Org"), None);
        let ca_key = KeyPair::generate().unwrap();
        let issuer = Issuer::new(ca, ca_key);

        let mut params = CertificateParams::new(vec!["gw.example.org".into()]).unwrap();
        let mut subject = DistinguishedName::new();
        // Not UTF-8 on the wire: a BMPString common name.
        subject.push(
            DnType::CommonName,
            DnValue::BmpString(BmpString::try_from("gw.example.org").unwrap()),
        );
        params.distinguished_name = subject;
        // GeneralizedTime (2050 and later).
        params.not_before = date_time_ymd(2050, 6, 7);
        params.not_after = date_time_ymd(2060, 8, 9);
        let key = KeyPair::generate().unwrap();
        let der = params.signed_by(&key, &issuer).unwrap().der().to_vec();

        let info = CertInfo::from_der(&der);
        assert!(!info.self_signed);
        assert_eq!(info.subject.summary(), "gw.example.org");
        assert_eq!(info.issuer.summary(), "Example Test CA, Example CA Org");
        assert_eq!(info.not_before.as_deref(), Some("2050-06-07"));
        assert_eq!(info.not_after.as_deref(), Some("2060-08-09"));
        assert_eq!(info.dns_names, ["gw.example.org"]);
        assert_eq!(info.validity_on("2026-11-28"), Validity::NotYetValid);
    }

    #[test]
    fn unreadable_certificates_still_have_their_fingerprint() {
        for der in [
            &b""[..],
            b"\x30\x03\x02\x01",
            b"\x30\x80\x00\x00",
            b"not a certificate",
        ] {
            let info = CertInfo::from_der(der);
            assert_eq!(info.fingerprint, fingerprint(der));
            assert_eq!(info.subject, CertName::default());
            assert_eq!(info.not_after, None);
            assert!(info.dns_names.is_empty() && !info.self_signed);
            assert_eq!(info.validity_on("2026-01-01"), Validity::Unknown);
        }
        // A real certificate cut short is unreadable too, never a panic.
        let cert = rcgen::generate_simple_self_signed(vec!["a.example.com".into()]).unwrap();
        let der = cert.cert.der().to_vec();
        for len in 0..der.len() {
            let _ = CertInfo::from_der(&der[..len]);
        }
    }

    #[test]
    fn text_that_could_mislead_is_removed() {
        assert_eq!(
            clean(" vpn.example.com\n\u{202E}moc.elpmaxe\u{0}\t"),
            "vpn.example.commoc.elpmaxe"
        );
        assert_eq!(clean(&"x".repeat(500)).len(), MAX_TEXT);
    }

    #[test]
    fn utc_dates() {
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(utc_date(951_782_400), "2000-02-29");
        assert_eq!(utc_date(1_767_225_599), "2025-12-31");
        assert_eq!(utc_date(1_767_225_600), "2026-01-01");
        assert_eq!(utc_date(4_107_542_400), "2100-03-01");
    }
}
