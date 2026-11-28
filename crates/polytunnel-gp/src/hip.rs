//! Host Information Profile (HIP) reports.
//!
//! Gateways may ask for a report on the connecting device. Polytunnel only ever reports
//! **real** facts: host name, OS, the installation ID, the tunnel address, and the security
//! products ([`Posture`]) the operating system itself reports at connect time (antimalware
//! with its real-time protection and signature date, firewall state). Nothing is invented: an
//! unknown value is left out, and if the device does not meet a gateway's policy, the report
//! says so and access stays restricted, as it should.
//!
//! The categories follow the form GlobalProtect 5.x and later send (`anti-malware` with
//! `prodType="3"`, `firewall`), as documented by openconnect and GlobalProtect-openconnect.

use polytunnel_core::http::{Request, Response};
use polytunnel_core::xml::Element;

use crate::client::{self, ClientInfo};
use crate::error::GpError;
use crate::login::GatewaySession;

fn base_fields(session: &GatewaySession, client_ip: &str) -> Vec<(&'static str, String)> {
    vec![
        ("client-role", "global-protect-full".to_string()),
        ("computer", session.computer.clone()),
        ("client-ip", client_ip.to_string()),
        ("user", session.user.clone()),
        ("portal", session.portal.clone()),
        ("authcookie", session.authcookie.expose().to_string()),
        ("domain", session.domain.clone()),
    ]
}

/// Asks whether the gateway wants a report with this checksum.
pub fn check_request(session: &GatewaySession, client_ip: &str, md5: &str) -> Request {
    let mut fields = base_fields(session, client_ip);
    fields.push(("md5", md5.to_string()));
    client::post(
        format!("{}/ssl-vpn/hipreportcheck.esp", session.gateway),
        &fields,
    )
}

/// `true`: the gateway wants the report.
pub fn parse_check(response: &Response) -> Result<bool, GpError> {
    if !response.is_success() {
        return Err(GpError::Status {
            step: "HIP check",
            status: response.status,
        });
    }
    let root = Element::parse(&response.body).map_err(|e| GpError::BadResponse {
        step: "HIP check",
        detail: e.to_string(),
    })?;
    Ok(root
        .text_at("hip-report-needed")
        .is_some_and(|v| v.eq_ignore_ascii_case("yes")))
}

pub fn submit_request(session: &GatewaySession, client_ip: &str, report: &str) -> Request {
    let mut fields = base_fields(session, client_ip);
    fields.push(("report", report.to_string()));
    client::post(
        format!("{}/ssl-vpn/hipreport.esp", session.gateway),
        &fields,
    )
}

/// Reads the answer to a report: the gateway's notification messages (its HIP verdict, e.g.
/// "VPN Access Denied ..."), as plain text. None: nothing to tell the user.
pub fn parse_submit(response: &Response) -> Result<Vec<String>, GpError> {
    if !response.is_success() {
        return Err(GpError::Status {
            step: "HIP report",
            status: response.status,
        });
    }
    let Ok(root) = Element::parse(&response.body) else {
        return Ok(Vec::new());
    };
    let Some(notifications) = root.path("notification/hip-notification") else {
        return Ok(Vec::new());
    };
    Ok(notifications
        .children_named("entry")
        .filter_map(|entry| entry.text_at("message"))
        .map(plain_text)
        .filter(|m| !m.is_empty())
        .collect())
}

/// A notification's HTML message as one line of plain text.
fn plain_text(html: &str) -> String {
    let mut text = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => {
                in_tag = true;
                text.push(' ');
            }
            '>' if in_tag => in_tag = false,
            _ if !in_tag => text.push(c),
            _ => {}
        }
    }
    let text = text
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Security facts read from the operating system at connect time. Never invented: what is
/// not known is `None` (and left out of the report).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Posture {
    pub antimalware: Vec<Antimalware>,
    pub firewall: Vec<Firewall>,
}

/// One antimalware product, as the OS reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Antimalware {
    pub name: String,
    pub vendor: Option<String>,
    pub version: Option<String>,
    /// The signature (definition) version.
    pub signatures: Option<String>,
    pub engine: Option<String>,
    /// When the signatures were last updated: (year, month, day).
    pub signature_date: Option<(u16, u8, u8)>,
    pub real_time_protection: Option<bool>,
    /// `MM/DD/YYYY HH:MM:SS`.
    pub last_full_scan: Option<String>,
}

/// One firewall, as the OS reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Firewall {
    pub name: String,
    pub vendor: Option<String>,
    pub version: Option<String>,
    pub enabled: Option<bool>,
}

fn yes_no(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "n/a",
    }
}

/// ` name="value"`, or nothing when the value is unknown.
fn attribute(name: &str, value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| format!(" {name}=\"{}\"", escape(v)))
        .unwrap_or_default()
}

/// A category: its products, or an empty list.
fn category(name: &str, products: Vec<String>) -> String {
    if products.is_empty() {
        format!("<entry name=\"{name}\"><list/></entry>")
    } else {
        format!(
            "<entry name=\"{name}\"><list>{}</list></entry>",
            products.concat()
        )
    }
}

fn posture_categories(posture: &Posture, os_type: &str) -> String {
    let antimalware = posture
        .antimalware
        .iter()
        .map(|p| {
            let date = p.signature_date.map_or(String::new(), |(y, m, d)| {
                format!(" dateyear=\"{y}\" datemon=\"{m}\" dateday=\"{d}\"")
            });
            format!(
                "<entry><ProductInfo><Prod{}{}{}{}{} prodType=\"3\" osType=\"{os_type}\"{date}/>\
                 <real-time-protection>{}</real-time-protection>\
                 <last-full-scan-time>{}</last-full-scan-time></ProductInfo></entry>",
                attribute("name", Some(&p.name)),
                attribute("vendor", p.vendor.as_deref()),
                attribute("version", p.version.as_deref()),
                attribute("defver", p.signatures.as_deref()),
                attribute("engver", p.engine.as_deref()),
                yes_no(p.real_time_protection),
                p.last_full_scan
                    .as_deref()
                    .map_or_else(|| "n/a".to_string(), escape),
            )
        })
        .collect();
    let firewall = posture
        .firewall
        .iter()
        .map(|p| {
            format!(
                "<entry><ProductInfo><Prod{}{}{}/><is-enabled>{}</is-enabled></ProductInfo></entry>",
                attribute("name", Some(&p.name)),
                attribute("vendor", p.vendor.as_deref()),
                attribute("version", p.version.as_deref()),
                yes_no(p.enabled),
            )
        })
        .collect();
    format!(
        "{}{}",
        category("anti-malware", antimalware),
        category("firewall", firewall)
    )
}

/// The report and its MD5 checksum. `generate_time` is `MM/DD/YYYY HH:MM:SS`.
pub fn report(
    client: &ClientInfo,
    session: &GatewaySession,
    client_ip: &str,
    generate_time: &str,
    posture: &Posture,
) -> (String, String) {
    let (vendor, os_type) = match client.os {
        polytunnel_core::profile::ClientOs::Windows => ("Microsoft", "1"),
        polytunnel_core::profile::ClientOs::Mac => ("Apple", "4"),
        polytunnel_core::profile::ClientOs::Linux => ("Linux", "1"),
    };
    let security = posture_categories(posture, os_type);
    let body = |md5: &str| {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <hip-report name=\"hip-report\">\
             <md5-sum>{md5}</md5-sum>\
             <user-name>{user}</user-name>\
             <domain>{domain}</domain>\
             <host-name>{host}</host-name>\
             <host-id>{host_id}</host-id>\
             <ip-address>{ip}</ip-address>\
             <ipv6-address></ipv6-address>\
             <generate-time>{time}</generate-time>\
             <hip-report-version>4</hip-report-version>\
             <categories><entry name=\"host-info\">\
             <client-version>{version}</client-version>\
             <os>{os}</os>\
             <os-vendor>{vendor}</os-vendor>\
             <domain>{domain}</domain>\
             <host-name>{host}</host-name>\
             <host-id>{host_id}</host-id>\
             </entry>{security}</categories>\
             </hip-report>",
            user = escape(&session.user),
            domain = escape(&session.domain),
            host = escape(&session.computer),
            host_id = escape(&client.host_id),
            ip = escape(client_ip),
            time = escape(generate_time),
            // The GlobalProtect app version this client announces (see
            // `client::announced_version`): gateways read the report's format by it, and an
            // unknown version makes them skip the anti-malware category. Without one, this
            // program's own version.
            version = escape(
                client
                    .app_version
                    .as_deref()
                    .unwrap_or(polytunnel_core::VERSION)
            ),
            os = escape(&client.os_version),
        )
    };
    // The checksum covers everything except the time and itself.
    let digest = md5_hex(body("").replace(&escape(generate_time), "").as_bytes());
    (body(&digest), digest)
}

fn md5_hex(data: &[u8]) -> String {
    use md5::Digest;
    md5::Md5::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use polytunnel_core::Secret;

    use super::*;
    use crate::client::test_client;

    fn session() -> GatewaySession {
        GatewaySession {
            gateway: "https://gw.example.com".into(),
            authcookie: Secret::new("FAKEcookie"),
            portal: "portal".into(),
            user: "user@example.com".into(),
            domain: "example.com".into(),
            computer: "WORKSTATION-1".into(),
            preferred_ip: None,
            preferred_ipv6: None,
        }
    }

    #[test]
    fn report_is_honest_and_stable() {
        let (report, md5) = report(
            &test_client(),
            &session(),
            "10.20.30.40",
            "01/02/2026 03:04:05",
            &Posture::default(),
        );
        assert_eq!(md5.len(), 32);
        assert!(report.contains(&format!("<md5-sum>{md5}</md5-sum>")));
        assert!(report.contains("<os>Microsoft Windows 11 Pro , 64-bit</os>"));
        assert!(report.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?><hip-report"));
        // No announced app version: this program's own.
        assert!(report.contains(&format!(
            "<client-version>{}</client-version>",
            polytunnel_core::VERSION
        )));
        // With one, the version the client announces to the gateway.
        let mut announcing = test_client();
        announcing.app_version = Some("6.3.0-33".into());
        let (announced, _) = super::report(
            &announcing,
            &session(),
            "10.20.30.40",
            "01/02/2026 03:04:05",
            &Posture::default(),
        );
        assert!(announced.contains("<client-version>6.3.0-33</client-version>"));
        // Nothing read from the OS: empty categories, no invented products.
        assert!(report.contains(
            "<entry name=\"anti-malware\"><list/></entry><entry name=\"firewall\"><list/></entry>"
        ));
        for absent in ["<Prod", "antivirus", "disk-encryption", "patch-management"] {
            assert!(!report.contains(absent), "{absent}");
        }
        // The checksum does not depend on the time.
        let (_, later) = super::report(
            &test_client(),
            &session(),
            "10.20.30.40",
            "12/31/2026 23:59:59",
            &Posture::default(),
        );
        assert_eq!(md5, later);
        // ...but does on the facts.
        let (_, other_ip) = super::report(
            &test_client(),
            &session(),
            "10.20.30.41",
            "01/02/2026 03:04:05",
            &Posture::default(),
        );
        assert_ne!(md5, other_ip);
    }

    #[test]
    fn check_and_submit() {
        let req = check_request(&session(), "10.20.30.40", "abc");
        assert_eq!(req.url, "https://gw.example.com/ssl-vpn/hipreportcheck.esp");
        assert_eq!(req.form_value("md5").as_deref(), Some("abc"));
        assert_eq!(
            parse_check(&Response::new(
                200,
                "<response status=\"success\"><hip-report-needed>yes</hip-report-needed></response>"
            )),
            Ok(true)
        );
        assert_eq!(
            parse_check(&Response::new(
                200,
                "<response status=\"success\"><hip-report-needed>no</hip-report-needed></response>"
            )),
            Ok(false)
        );
        let submit = submit_request(&session(), "10.20.30.40", "<hip-report/>");
        assert_eq!(
            submit.form_value("report").as_deref(),
            Some("<hip-report/>")
        );
        assert_eq!(parse_submit(&Response::new(200, "")), Ok(Vec::new()));
    }

    fn defender() -> Posture {
        Posture {
            antimalware: vec![Antimalware {
                name: "Windows Defender".into(),
                vendor: Some("Microsoft Corporation".into()),
                version: Some("4.18.2600.4".into()),
                signatures: Some("1.400.2.0".into()),
                engine: Some("1.1.2600.4".into()),
                signature_date: Some((2026, 3, 7)),
                real_time_protection: Some(true),
                last_full_scan: None,
            }],
            firewall: vec![Firewall {
                name: "Windows Firewall".into(),
                vendor: Some("Microsoft Corporation".into()),
                version: None,
                enabled: Some(true),
            }],
        }
    }

    #[test]
    fn security_products_are_reported_as_the_os_reports_them() {
        let (report, md5) = report(&test_client(), &session(), "10.0.0.1", "t", &defender());
        assert!(
            report.contains(
                "<entry name=\"anti-malware\"><list><entry><ProductInfo>\
                 <Prod name=\"Windows Defender\" vendor=\"Microsoft Corporation\" \
                 version=\"4.18.2600.4\" defver=\"1.400.2.0\" engver=\"1.1.2600.4\" prodType=\"3\" \
                 osType=\"1\" dateyear=\"2026\" datemon=\"3\" dateday=\"7\"/>\
                 <real-time-protection>yes</real-time-protection>\
                 <last-full-scan-time>n/a</last-full-scan-time></ProductInfo></entry></list></entry>"
            ),
            "{report}"
        );
        assert!(report.contains(
            "<entry name=\"firewall\"><list><entry><ProductInfo>\
             <Prod name=\"Windows Firewall\" vendor=\"Microsoft Corporation\"/>\
             <is-enabled>yes</is-enabled></ProductInfo></entry></list></entry>"
        ));
        // Unknown values are left out, never guessed.
        let mut unknown = defender();
        unknown.antimalware[0].signature_date = None;
        unknown.antimalware[0].real_time_protection = None;
        unknown.antimalware[0].vendor = None;
        let (partial, other_md5) =
            super::report(&test_client(), &session(), "10.0.0.1", "t", &unknown);
        assert!(!partial.contains("dateyear"));
        assert!(!partial.contains("vendor=\"Microsoft Corporation\" version=\"4.18"));
        assert!(partial.contains("<real-time-protection>n/a</real-time-protection>"));
        // A different posture is a different report.
        assert_ne!(md5, other_md5);
    }

    #[test]
    fn the_gateway_verdict_is_read_as_plain_text() {
        let answer = "<response status=\"success\"><notification><hip-notification>\
             <entry name=\"HIP-Example-NoProtection\"><value>1</value><message>VPN Access Denied\
             &lt;div&gt;&lt;br&gt;&lt;/div&gt;&lt;div&gt;Devices need antimalware &amp;amp; \
             real time protection.&lt;/div&gt;</message></entry>\
             <entry name=\"silent\"><value>1</value></entry>\
             </hip-notification></notification></response>";
        assert_eq!(
            parse_submit(&Response::new(200, answer)),
            Ok(vec![
                "VPN Access Denied Devices need antimalware & real time protection.".to_string()
            ])
        );
        assert!(parse_submit(&Response::new(500, "")).is_err());
    }

    #[test]
    fn values_are_escaped() {
        let mut s = session();
        s.user = "a<b>&\"c\"".into();
        let (report, _) = report(&test_client(), &s, "10.0.0.1", "t", &defender());
        assert!(report.contains("<user-name>a&lt;b&gt;&amp;&quot;c&quot;</user-name>"));
    }
}
