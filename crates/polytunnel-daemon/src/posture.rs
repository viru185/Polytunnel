//! The device's security posture for HIP reports, read from Windows at connect time:
//!
//! * Microsoft Defender's own status (WMI `root\Microsoft\Windows\Defender`,
//!   `MSFT_MpComputerStatus`): versions, signature date, real-time protection, last full scan;
//! * other antimalware and firewall products Windows Security Center knows
//!   (`root\SecurityCenter2`), with what it says about them (on or off);
//! * the Windows Firewall profiles (`root\StandardCimv2`, `MSFT_NetFirewallProfile`).
//!
//! Only what Windows reports is used; anything it does not tell is left unknown, and a query
//! that fails leaves its part empty. Other systems report nothing yet.

use polytunnel_gp::hip::Posture;

/// What Windows Security Center's `productState` says: (switched on, signatures up to date).
/// The state is `0xTTSSDD`: `SS` bit `0x10` set means on, `DD` `0x00` means up to date.
pub fn security_center_state(state: u32) -> (bool, bool) {
    let on = (state >> 8) & 0x10 != 0;
    let up_to_date = state & 0xff == 0;
    (on, up_to_date)
}

/// A WMI date (`yyyymmddHHMMSS.ffffff+UUU`, local time): (year, month, day, hour, min, sec).
pub fn wmi_date(text: &str) -> Option<(u16, u8, u8, u8, u8, u8)> {
    let digits = text.get(..14)?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = |range: std::ops::Range<usize>| digits[range].parse::<u16>().ok();
    let (year, month, day) = (n(0..4)?, n(4..6)?, n(6..8)?);
    let (hour, min, sec) = (n(8..10)?, n(10..12)?, n(12..14)?);
    // Windows writes 1601 or all zeros for "never".
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((
        year,
        month as u8,
        day as u8,
        hour as u8,
        min as u8,
        sec as u8,
    ))
}

/// A one-line summary for the log.
pub fn describe(posture: &Posture) -> String {
    let antimalware: Vec<String> = posture
        .antimalware
        .iter()
        .map(|p| {
            let rtp = match p.real_time_protection {
                Some(true) => "real-time protection on",
                Some(false) => "real-time protection off",
                None => "real-time protection unknown",
            };
            let signatures = match (&p.signatures, p.signature_date) {
                (Some(v), Some((y, m, d))) => format!(", signatures {v} from {y}-{m:02}-{d:02}"),
                (Some(v), None) => format!(", signatures {v}"),
                (None, _) => String::new(),
            };
            format!("{} ({rtp}{signatures})", p.name)
        })
        .collect();
    let firewall: Vec<String> = posture
        .firewall
        .iter()
        .map(|f| {
            let state = match f.enabled {
                Some(true) => "on",
                Some(false) => "off",
                None => "unknown",
            };
            format!("{} {state}", f.name)
        })
        .collect();
    format!(
        "antimalware: {}; firewall: {}",
        if antimalware.is_empty() {
            "none reported".into()
        } else {
            antimalware.join(", ")
        },
        if firewall.is_empty() {
            "none reported".into()
        } else {
            firewall.join(", ")
        }
    )
}

#[cfg(windows)]
pub use windows::read;

/// Other systems: nothing is read yet.
#[cfg(not(windows))]
pub fn read() -> Posture {
    Posture::default()
}

#[cfg(windows)]
mod windows {
    use polytunnel_gp::hip::{Antimalware, Firewall, Posture};
    use serde::Deserialize;
    use wmi::WMIConnection;

    use super::{security_center_state, wmi_date};

    #[derive(Deserialize)]
    struct MpComputerStatus {
        #[serde(rename = "AMServiceEnabled")]
        service: Option<bool>,
        #[serde(rename = "AntivirusEnabled")]
        antivirus: Option<bool>,
        #[serde(rename = "RealTimeProtectionEnabled")]
        real_time: Option<bool>,
        #[serde(rename = "AMRunningMode")]
        mode: Option<String>,
        #[serde(rename = "AMProductVersion")]
        version: Option<String>,
        #[serde(rename = "AMEngineVersion")]
        engine: Option<String>,
        #[serde(rename = "AntivirusSignatureVersion")]
        signatures: Option<String>,
        #[serde(rename = "AntivirusSignatureLastUpdated")]
        signatures_updated: Option<String>,
        #[serde(rename = "FullScanEndTime")]
        full_scan: Option<String>,
    }

    #[derive(Deserialize)]
    struct SecurityCenterProduct {
        #[serde(rename = "displayName")]
        name: String,
        #[serde(rename = "productState")]
        state: u32,
    }

    #[derive(Deserialize)]
    struct FirewallProfile {
        #[serde(rename = "Enabled")]
        enabled: Option<u16>,
    }

    fn query<T: for<'de> Deserialize<'de>>(namespace: &str, query: &str) -> Vec<T> {
        WMIConnection::with_namespace_path(namespace)
            .and_then(|c| c.raw_query(query))
            .unwrap_or_default()
    }

    /// Reads the posture (call from a blocking thread: WMI connections stay on their thread).
    pub fn read() -> Posture {
        let defender: Option<MpComputerStatus> = query(
            r"ROOT\Microsoft\Windows\Defender",
            "SELECT AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, \
             AMRunningMode, AMProductVersion, AMEngineVersion, AntivirusSignatureVersion, \
             AntivirusSignatureLastUpdated, FullScanEndTime FROM MSFT_MpComputerStatus",
        )
        .into_iter()
        .next();
        let antivirus: Vec<SecurityCenterProduct> = query(
            r"ROOT\SecurityCenter2",
            "SELECT displayName, productState FROM AntiVirusProduct",
        );
        let firewalls: Vec<SecurityCenterProduct> = query(
            r"ROOT\SecurityCenter2",
            "SELECT displayName, productState FROM FirewallProduct",
        );
        let profiles: Vec<FirewallProfile> = query(
            r"ROOT\StandardCimv2",
            "SELECT Enabled FROM MSFT_NetFirewallProfile",
        );

        let is_defender = |name: &str| name.to_ascii_lowercase().contains("defender");
        let mut antimalware = Vec::new();
        if let Some(d) = defender.filter(|d| d.service == Some(true)) {
            let name = antivirus.iter().find(|p| is_defender(&p.name)).map_or_else(
                || "Microsoft Defender Antivirus".to_string(),
                |p| p.name.clone(),
            );
            // Real-time protection counts only while Defender is the active antivirus (not
            // in passive mode next to another product).
            let active = d
                .mode
                .as_deref()
                .is_some_and(|m| m.eq_ignore_ascii_case("Normal"));
            let real_time = match (d.antivirus, d.real_time) {
                (Some(av), Some(rt)) => Some(av && rt && active),
                _ => None,
            };
            antimalware.push(Antimalware {
                name,
                vendor: Some("Microsoft Corporation".into()),
                version: d.version,
                signatures: d.signatures,
                engine: d.engine,
                signature_date: d
                    .signatures_updated
                    .as_deref()
                    .and_then(wmi_date)
                    .map(|(y, m, d, ..)| (y, m, d)),
                real_time_protection: real_time,
                last_full_scan: d.full_scan.as_deref().and_then(wmi_date).map(
                    |(y, mo, d, h, mi, s)| format!("{mo:02}/{d:02}/{y:04} {h:02}:{mi:02}:{s:02}"),
                ),
            });
        }
        let defender_listed = !antimalware.is_empty();
        for product in &antivirus {
            if defender_listed && is_defender(&product.name) {
                continue;
            }
            let (on, _) = security_center_state(product.state);
            antimalware.push(Antimalware {
                name: product.name.clone(),
                real_time_protection: Some(on),
                ..Default::default()
            });
        }

        let mut firewall = Vec::new();
        if !profiles.is_empty() {
            firewall.push(Firewall {
                name: "Microsoft Windows Firewall".into(),
                vendor: Some("Microsoft Corporation".into()),
                version: None,
                // On only if every profile (domain, private, public) is on.
                enabled: Some(profiles.iter().all(|p| p.enabled == Some(1))),
            });
        }
        for product in &firewalls {
            let (on, _) = security_center_state(product.state);
            firewall.push(Firewall {
                name: product.name.clone(),
                enabled: Some(on),
                ..Default::default()
            });
        }
        Posture {
            antimalware,
            firewall,
        }
    }
}

#[cfg(test)]
mod tests {
    use polytunnel_gp::hip::{Antimalware, Firewall};

    use super::*;

    #[test]
    fn security_center_states() {
        assert_eq!(security_center_state(0x061100), (true, true));
        assert_eq!(security_center_state(0x060100), (false, true));
        assert_eq!(security_center_state(0x061110), (true, false));
        assert_eq!(security_center_state(0x041000), (true, true));
    }

    #[test]
    fn wmi_dates() {
        assert_eq!(
            wmi_date("20261127085029.000000+330"),
            Some((2026, 11, 27, 8, 50, 29))
        );
        assert_eq!(wmi_date("16010101000000.000000+000"), None, "never");
        assert_eq!(wmi_date("2026"), None);
        assert_eq!(wmi_date("2026x127085029.000000+000"), None);
    }

    #[test]
    fn the_summary_names_what_was_read() {
        let posture = Posture {
            antimalware: vec![Antimalware {
                name: "Windows Defender".into(),
                signatures: Some("1.2.3.0".into()),
                signature_date: Some((2026, 3, 7)),
                real_time_protection: Some(true),
                ..Default::default()
            }],
            firewall: vec![Firewall {
                name: "Microsoft Windows Firewall".into(),
                enabled: Some(true),
                ..Default::default()
            }],
        };
        assert_eq!(
            describe(&posture),
            "antimalware: Windows Defender (real-time protection on, signatures 1.2.3.0 from \
             2026-03-07); firewall: Microsoft Windows Firewall on"
        );
        assert_eq!(
            describe(&Posture::default()),
            "antimalware: none reported; firewall: none reported"
        );
    }
}
