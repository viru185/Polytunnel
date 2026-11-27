//! Gateway login: turns proof of identity into a tunnel session (`authcookie`).

use polytunnel_core::Secret;
use polytunnel_core::http::{Request, Response};
use polytunnel_core::xml::Element;

use crate::client::{self, ClientInfo};
use crate::error::GpError;
use crate::portal::host_of;

/// What proves the user's identity to the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayAuth {
    Password(Secret),
    /// From a SAML login at the gateway.
    PreloginCookie(Secret),
    /// The portal's reusable cookies (no second login needed).
    PortalCookie {
        cookie: Secret,
        prelogon: Option<Secret>,
    },
}

/// A logged-in gateway session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewaySession {
    /// `https://host[:port]` of the gateway.
    pub gateway: String,
    pub authcookie: Secret,
    pub portal: String,
    pub user: String,
    pub domain: String,
    pub computer: String,
    pub preferred_ip: Option<String>,
    pub preferred_ipv6: Option<String>,
}

impl GatewaySession {
    /// The session cookie in the form other GlobalProtect clients (e.g. openconnect's
    /// `--cookie`) accept: URL-encoded `authcookie`, `portal`, `user`, `domain`, `computer`
    /// and the preferred addresses.
    pub fn cookie_string(&self) -> Secret {
        let mut form = form_urlencoded::Serializer::new(String::new());
        form.append_pair("authcookie", self.authcookie.expose());
        form.append_pair("portal", &self.portal);
        form.append_pair("user", &self.user);
        form.append_pair("domain", &self.domain);
        form.append_pair("computer", &self.computer);
        if let Some(ip) = &self.preferred_ip {
            form.append_pair("preferred-ip", ip);
        }
        if let Some(ip) = &self.preferred_ipv6 {
            form.append_pair("preferred-ipv6", ip);
        }
        Secret::new(form.finish())
    }
}

pub fn request(base: &str, client: &ClientInfo, username: &str, auth: &GatewayAuth) -> Request {
    let url = format!("{base}/ssl-vpn/login.esp");
    let mut fields = vec![
        ("prot", "https:".to_string()),
        ("server", host_of(base).to_string()),
        ("inputStr", String::new()),
        ("jnlpReady", "jnlpReady".to_string()),
        ("ok", "Login".to_string()),
        ("direct", "yes".to_string()),
        ("host-id", client.host_id.clone()),
        ("user", username.to_string()),
    ];
    fields.extend(client.base_fields());
    match auth {
        GatewayAuth::Password(password) => fields.push(("passwd", password.expose().to_string())),
        GatewayAuth::PreloginCookie(cookie) => {
            fields.push(("passwd", String::new()));
            fields.push(("prelogin-cookie", cookie.expose().to_string()));
        }
        GatewayAuth::PortalCookie { cookie, prelogon } => {
            fields.push(("passwd", String::new()));
            fields.push(("portal-userauthcookie", cookie.expose().to_string()));
            fields.push((
                "portal-prelogonuserauthcookie",
                prelogon
                    .as_ref()
                    .map(|c| c.expose().to_string())
                    .unwrap_or_else(|| "empty".to_string()),
            ));
        }
    }
    client::post(url, &fields)
}

// Positions of the values in the gateway's JNLP answer.
const ARG_AUTHCOOKIE: usize = 1;
const ARG_PORTAL: usize = 3;
const ARG_USER: usize = 4;
const ARG_DOMAIN: usize = 7;
const ARG_CONNECTION_TYPE: usize = 12;
const ARG_PREFERRED_IP: usize = 15;
const ARG_PREFERRED_IPV6: usize = 18;

/// `computer` must be the value sent in the login request.
pub fn parse(base: &str, computer: &str, response: &Response) -> Result<GatewaySession, GpError> {
    const STEP: &str = "gateway login";
    match response.status {
        200 => {}
        512 | 401 | 403 => {
            let reason = response
                .body
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .unwrap_or("rejected by the gateway");
            return Err(GpError::AuthFailed(reason.to_string()));
        }
        status => return Err(GpError::Status { step: STEP, status }),
    }
    let root =
        Element::parse(&response.body).map_err(|e| GpError::not_xml(STEP, &response.body, e))?;
    if root.name == "response" && root.attr("status") == Some("error") {
        let msg = root.text_at("error").unwrap_or("unknown error").to_string();
        return Err(GpError::Server(msg));
    }
    let args: Vec<String> = root
        .path("application-desc")
        .filter(|_| root.name == "jnlp")
        .ok_or_else(|| GpError::BadResponse {
            step: STEP,
            detail: format!("expected <jnlp><application-desc>, got <{}>", root.name),
        })?
        .children_named("argument")
        .map(|a| {
            let v = a.text.trim();
            // Gateways write "(null)" or "-1" for values they do not have.
            if v == "(null)" || v == "-1" {
                String::new()
            } else {
                v.to_string()
            }
        })
        .collect();
    let arg = |i: usize| args.get(i).cloned().unwrap_or_default();
    let optional = |i: usize| Some(arg(i)).filter(|v| !v.is_empty());

    let authcookie = arg(ARG_AUTHCOOKIE);
    if authcookie.is_empty() {
        return Err(GpError::BadResponse {
            step: STEP,
            detail: "no authcookie in the answer".into(),
        });
    }
    let connection_type = arg(ARG_CONNECTION_TYPE);
    if !connection_type.is_empty() && connection_type != "tunnel" {
        return Err(GpError::Unsupported(format!(
            "gateway connection type '{connection_type}'"
        )));
    }
    Ok(GatewaySession {
        gateway: base.to_string(),
        authcookie: Secret::new(authcookie),
        portal: arg(ARG_PORTAL),
        user: arg(ARG_USER),
        domain: arg(ARG_DOMAIN),
        computer: computer.to_string(),
        preferred_ip: optional(ARG_PREFERRED_IP),
        preferred_ipv6: optional(ARG_PREFERRED_IPV6),
    })
}

#[cfg(test)]
mod tests {
    /// Built at run time so secret scanners do not mistake test data for a real password.
    fn test_password() -> String {
        ["not", "a", "real", "password"].join("-")
    }

    use super::*;
    use crate::client::test_client;

    pub(crate) fn jnlp(authcookie: &str) -> String {
        let args = [
            "(null)",
            authcookie,
            "FAKE-persistent",
            "vpn-portal",
            "user@example.com",
            "Entra",
            "vsys1",
            "example.com",
            "(null)",
            "",
            "",
            "",
            "tunnel",
            "-1",
            "4100",
            "10.20.30.40",
            "",
            "",
            "",
        ];
        let body: String = args
            .iter()
            .map(|a| format!("<argument>{a}</argument>"))
            .collect();
        format!("<?xml version=\"1.0\"?><jnlp><application-desc>{body}</application-desc></jnlp>")
    }

    #[test]
    fn parses_the_session_and_builds_the_cookie() {
        let session = parse(
            "https://gw.example.com",
            "WORKSTATION-1",
            &Response::new(200, jnlp("FAKE0123authcookie")),
        )
        .unwrap();
        assert_eq!(session.authcookie, Secret::new("FAKE0123authcookie"));
        assert_eq!(session.portal, "vpn-portal");
        assert_eq!(session.user, "user@example.com");
        assert_eq!(session.domain, "example.com");
        assert_eq!(session.preferred_ip.as_deref(), Some("10.20.30.40"));
        assert_eq!(session.preferred_ipv6, None);
        assert_eq!(
            session.cookie_string().expose(),
            "authcookie=FAKE0123authcookie&portal=vpn-portal&user=user%40example.com\
             &domain=example.com&computer=WORKSTATION-1&preferred-ip=10.20.30.40"
        );

        let unset = jnlp("FAKE0123authcookie").replace("10.20.30.40", "-1");
        let unset = parse(
            "https://gw.example.com",
            "WORKSTATION-1",
            &Response::new(200, unset),
        )
        .unwrap();
        assert_eq!(unset.preferred_ip, None, "-1 means no preferred address");
    }

    #[test]
    fn builds_requests_for_each_kind_of_proof() {
        let base = "https://gw.example.com";
        let client = test_client();
        let req = request(
            base,
            &client,
            "u",
            &GatewayAuth::PortalCookie {
                cookie: Secret::new("FAKE-portal"),
                prelogon: None,
            },
        );
        assert_eq!(req.url, "https://gw.example.com/ssl-vpn/login.esp");
        assert_eq!(
            req.form_value("portal-userauthcookie").as_deref(),
            Some("FAKE-portal")
        );
        assert_eq!(
            req.form_value("portal-prelogonuserauthcookie").as_deref(),
            Some("empty")
        );
        let req = request(
            base,
            &client,
            "u",
            &GatewayAuth::Password(Secret::new(test_password())),
        );
        assert_eq!(
            req.form_value("passwd").as_deref(),
            Some(test_password().as_str())
        );
        let req = request(
            base,
            &client,
            "u",
            &GatewayAuth::PreloginCookie(Secret::new("FAKE-pre")),
        );
        assert_eq!(
            req.form_value("prelogin-cookie").as_deref(),
            Some("FAKE-pre")
        );
    }

    #[test]
    fn errors() {
        let base = "https://gw.example.com";
        assert!(matches!(
            parse(
                base,
                "c",
                &Response::new(512, "Invalid username or password")
            ),
            Err(GpError::AuthFailed(_))
        ));
        assert!(matches!(
            parse(base, "c", &Response::new(200, jnlp(""))),
            Err(GpError::BadResponse { .. })
        ));
        assert!(matches!(
            parse(base, "c", &Response::new(200, "<html>login page</html>")),
            Err(GpError::BadResponse { .. })
        ));
    }
}
