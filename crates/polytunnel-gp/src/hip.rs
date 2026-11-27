//! Host Information Profile (HIP) reports.
//!
//! Gateways may ask for a report on the connecting device. Polytunnel only ever reports
//! **real** facts it knows (host name, OS, the installation ID, the tunnel address) and lists
//! no security products it cannot vouch for. It never fakes posture data; if a gateway's
//! policy requires more, access is restricted, as it should be.

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

pub fn parse_submit(response: &Response) -> Result<(), GpError> {
    if response.is_success() {
        Ok(())
    } else {
        Err(GpError::Status {
            step: "HIP report",
            status: response.status,
        })
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The report and its MD5 checksum. `generate_time` is `MM/DD/YYYY HH:MM:SS`.
pub fn report(
    client: &ClientInfo,
    session: &GatewaySession,
    client_ip: &str,
    generate_time: &str,
) -> (String, String) {
    let vendor = match client.os {
        polytunnel_core::profile::ClientOs::Windows => "Microsoft",
        polytunnel_core::profile::ClientOs::Mac => "Apple",
        polytunnel_core::profile::ClientOs::Linux => "Linux",
    };
    let body = |md5: &str| {
        format!(
            "<hip-report name=\"hip-report\">\
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
             </entry></categories>\
             </hip-report>",
            user = escape(&session.user),
            domain = escape(&session.domain),
            host = escape(&session.computer),
            host_id = escape(&client.host_id),
            ip = escape(client_ip),
            time = escape(generate_time),
            version = escape(polytunnel_core::VERSION),
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
        );
        assert_eq!(md5.len(), 32);
        assert!(report.contains(&format!("<md5-sum>{md5}</md5-sum>")));
        assert!(report.contains("<os>Microsoft Windows 11 Pro , 64-bit</os>"));
        assert!(report.contains(&format!(
            "<client-version>{}</client-version>",
            polytunnel_core::VERSION
        )));
        // Only host information: no claims about security products.
        for absent in [
            "anti-malware",
            "antivirus",
            "firewall",
            "disk-encryption",
            "patch-management",
        ] {
            assert!(!report.contains(absent), "{absent}");
        }
        // The checksum does not depend on the time.
        let (_, later) = super::report(
            &test_client(),
            &session(),
            "10.20.30.40",
            "12/31/2026 23:59:59",
        );
        assert_eq!(md5, later);
        // ...but does on the facts.
        let (_, other_ip) = super::report(
            &test_client(),
            &session(),
            "10.20.30.41",
            "01/02/2026 03:04:05",
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
        assert!(parse_submit(&Response::new(200, "")).is_ok());
    }

    #[test]
    fn values_are_escaped() {
        let mut s = session();
        s.user = "a<b>&\"c\"".into();
        let (report, _) = report(&test_client(), &s, "10.0.0.1", "t");
        assert!(report.contains("<user-name>a&lt;b&gt;&amp;&quot;c&quot;</user-name>"));
    }
}
