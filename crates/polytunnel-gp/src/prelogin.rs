//! Pre-login: asks a portal or gateway how the user must authenticate.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use polytunnel_core::http::{Request, Response};
use polytunnel_core::xml::Element;

use crate::client::{self, ClientInfo};
use crate::error::GpError;

/// Which side of GlobalProtect a request goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interface {
    Portal,
    Gateway,
}

impl Interface {
    pub fn prelogin_path(self) -> &'static str {
        match self {
            Interface::Portal => "/global-protect/prelogin.esp",
            Interface::Gateway => "/ssl-vpn/prelogin.esp",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Interface::Portal => "portal",
            Interface::Gateway => "gateway",
        }
    }
}

/// How the browser must start the SAML login.
#[derive(Clone, PartialEq, Eq)]
pub enum SamlRequest {
    /// Open this identity-provider URL.
    Redirect { url: String },
    /// Load this HTML page (it auto-submits a form to the identity provider).
    Post { html: String },
}

impl std::fmt::Debug for SamlRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The URL carries a SAML request (not a secret, but long and noisy).
            SamlRequest::Redirect { url } => {
                let host = url.split('/').nth(2).unwrap_or_default();
                write!(f, "Redirect(https://{host}/...)")
            }
            SamlRequest::Post { html } => write!(f, "Post({} bytes)", html.len()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Prelogin {
    /// `Some` when the server requires SAML.
    pub saml: Option<SamlRequest>,
    /// The client's source region as seen by the server (used for gateway priorities).
    pub region: Option<String>,
    pub auth_message: Option<String>,
    pub username_label: Option<String>,
    pub password_label: Option<String>,
    /// The server prefers the system browser for SAML.
    pub default_browser: bool,
}

/// `default_browser`: announce that the SAML result can come back through the
/// `globalprotectcallback:` link (as the official app does when it uses the system browser).
pub fn request(
    base: &str,
    iface: Interface,
    client: &ClientInfo,
    default_browser: bool,
) -> Request {
    let url = format!(
        "{base}{}?{}",
        iface.prelogin_path(),
        client.prelogin_query()
    );
    let mut fields = vec![("tmp", "tmp".to_string())];
    fields.extend(client.base_fields());
    if default_browser {
        fields.push(("default-browser", "1".to_string()));
    }
    client::post(url, &fields)
}

pub fn parse(iface: Interface, response: &Response) -> Result<Prelogin, GpError> {
    let step = match iface {
        Interface::Portal => "portal pre-login",
        Interface::Gateway => "gateway pre-login",
    };
    if !response.is_success() {
        return Err(GpError::Status {
            step,
            status: response.status,
        });
    }
    let root = Element::parse(&response.body).map_err(|e| GpError::BadResponse {
        step,
        detail: format!("not XML: {e}"),
    })?;
    if let Some(status) = root.text_at("status")
        && !status.eq_ignore_ascii_case("success")
    {
        let msg = root.text_at("msg").unwrap_or(status).to_string();
        return Err(GpError::Server(msg));
    }

    let saml = match (
        root.text_at("saml-auth-method"),
        root.text_at("saml-request"),
    ) {
        (Some(method), Some(encoded)) => Some(decode_saml(step, method, encoded)?),
        _ => None,
    };
    Ok(Prelogin {
        saml,
        region: root.text_at("region").map(str::to_string),
        auth_message: root.text_at("authentication-message").map(str::to_string),
        username_label: root.text_at("username-label").map(str::to_string),
        password_label: root.text_at("password-label").map(str::to_string),
        default_browser: root
            .text_at("saml-default-browser")
            .is_some_and(|v| v.eq_ignore_ascii_case("yes")),
    })
}

fn decode_saml(step: &'static str, method: &str, encoded: &str) -> Result<SamlRequest, GpError> {
    let compact: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = STANDARD.decode(compact).map_err(|e| GpError::BadResponse {
        step,
        detail: format!("SAML request is not base64: {e}"),
    })?;
    let text = String::from_utf8(bytes).map_err(|_| GpError::BadResponse {
        step,
        detail: "SAML request is not UTF-8".into(),
    })?;
    match method.to_ascii_uppercase().as_str() {
        "REDIRECT" => {
            if !text.starts_with("https://") {
                return Err(GpError::BadResponse {
                    step,
                    detail: "SAML redirect is not an https:// URL".into(),
                });
            }
            Ok(SamlRequest::Redirect { url: text })
        }
        "POST" => Ok(SamlRequest::Post { html: text }),
        other => Err(GpError::Unsupported(format!("SAML method {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_client;

    fn b64(s: &str) -> String {
        STANDARD.encode(s)
    }

    #[test]
    fn builds_the_request() {
        let req = request(
            "https://portal.example.com",
            Interface::Portal,
            &test_client(),
            true,
        );
        assert_eq!(
            req.url,
            "https://portal.example.com/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Windows"
        );
        assert_eq!(req.form_value("default-browser").as_deref(), Some("1"));
        assert_eq!(req.form_value("computer").as_deref(), Some("WORKSTATION-1"));
        assert_eq!(req.form_value("clientgpversion"), None);
        assert!(
            req.headers
                .contains(&("User-Agent".into(), "PAN GlobalProtect".into()))
        );
    }

    #[test]
    fn parses_saml_redirect() {
        let body = format!(
            "<prelogin-response><status>Success</status><saml-auth-method>REDIRECT</saml-auth-method>\
             <saml-request>{}</saml-request><region>XX</region>\
             <saml-default-browser>yes</saml-default-browser></prelogin-response>",
            b64("https://idp.example.com/saml2?SAMLRequest=abc")
        );
        let pre = parse(Interface::Portal, &Response::new(200, body)).unwrap();
        assert_eq!(
            pre.saml,
            Some(SamlRequest::Redirect {
                url: "https://idp.example.com/saml2?SAMLRequest=abc".into()
            })
        );
        assert_eq!(pre.region.as_deref(), Some("XX"));
        assert!(pre.default_browser);
    }

    #[test]
    fn parses_password_login() {
        let body = "<prelogin-response><status>Success</status>\
                    <authentication-message>Enter login credentials</authentication-message>\
                    <username-label>Username</username-label><password-label>Password</password-label>\
                    </prelogin-response>";
        let pre = parse(Interface::Gateway, &Response::new(200, body)).unwrap();
        assert_eq!(pre.saml, None);
        assert_eq!(pre.username_label.as_deref(), Some("Username"));
    }

    #[test]
    fn reports_errors() {
        let body = "<prelogin-response><status>Error</status><msg>Valid client certificate is required</msg></prelogin-response>";
        assert_eq!(
            parse(Interface::Portal, &Response::new(200, body)),
            Err(GpError::Server(
                "Valid client certificate is required".into()
            ))
        );
        assert!(matches!(
            parse(Interface::Portal, &Response::new(404, "")),
            Err(GpError::Status { status: 404, .. })
        ));
        assert!(matches!(
            parse(Interface::Portal, &Response::new(200, "<html>oops")),
            Err(GpError::BadResponse { .. })
        ));
        let plain = format!(
            "<prelogin-response><status>Success</status><saml-auth-method>REDIRECT</saml-auth-method><saml-request>{}</saml-request></prelogin-response>",
            b64("http://idp.example.com/")
        );
        assert!(matches!(
            parse(Interface::Portal, &Response::new(200, plain)),
            Err(GpError::BadResponse { .. })
        ));
    }
}
