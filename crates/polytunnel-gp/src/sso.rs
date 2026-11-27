//! The result of a SAML login, as handed back by the browser.
//!
//! When the portal uses the system browser, its final page opens a
//! `globalprotectcallback:<data>` link, which the operating system passes to the registered
//! app. `<data>` is base64 of a small document holding `<saml-username>`,
//! `<prelogin-cookie>` (or `<portal-userauthcookie>`) and `<saml-auth-status>`. Portals that
//! use the Cloud Authentication Service send `cas-as=1&un=<user>&token=<token>` instead.
//!
//! [`parse_callback`] accepts the link, the bare `<data>`, or the page source/headers pasted
//! by the user, so the paste fallback works with whatever the user can copy.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use polytunnel_core::Secret;

use crate::error::GpError;

/// The scheme the official app registers.
pub const CALLBACK_SCHEME: &str = "globalprotectcallback";

/// Larger inputs are rejected (a real callback is well under 16 KiB).
pub const MAX_CALLBACK_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsoResult {
    Saml {
        username: String,
        /// Short-lived, single-use proof of the SAML login.
        prelogin_cookie: Option<Secret>,
        /// Some portals hand out their reusable cookie directly.
        portal_userauthcookie: Option<Secret>,
    },
    /// Cloud Authentication Service result.
    Cas { username: String, token: Secret },
}

impl SsoResult {
    pub fn username(&self) -> &str {
        match self {
            SsoResult::Saml { username, .. } | SsoResult::Cas { username, .. } => username,
        }
    }
}

/// Parses a callback link, its payload, or pasted page source / response headers.
pub fn parse_callback(input: &str) -> Result<SsoResult, GpError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(GpError::SsoFailed("empty callback".into()));
    }
    if input.len() > MAX_CALLBACK_LEN {
        return Err(GpError::SsoFailed("callback is too large".into()));
    }

    let payload = strip_scheme(input);
    let payload = percent_decode(payload);
    let payload = payload.trim();

    if payload.starts_with("cas-as=") || payload.contains("&token=") {
        return parse_cas(payload);
    }
    if let Some(result) = parse_tagged(payload)? {
        return Ok(result);
    }
    if let Some(decoded) = decode_base64(payload)
        && let Some(result) = parse_tagged(&decoded)?
    {
        return Ok(result);
    }
    Err(GpError::SsoFailed(
        "this does not look like a GlobalProtect login result".into(),
    ))
}

fn strip_scheme(input: &str) -> &str {
    match input.split_once(':') {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case(CALLBACK_SCHEME) => {
            rest.trim_start_matches('/')
        }
        _ => input,
    }
}

fn percent_decode(input: &str) -> String {
    if !input.contains('%') {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_base64(payload: &str) -> Option<String> {
    let compact: String = payload.chars().filter(|c| !c.is_whitespace()).collect();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(&compact).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

fn parse_cas(payload: &str) -> Result<SsoResult, GpError> {
    let mut username = None;
    let mut token = None;
    for (key, value) in form_urlencoded::parse(payload.as_bytes()) {
        match key.as_ref() {
            "un" => username = Some(value.into_owned()),
            "token" => token = Some(Secret::new(value.into_owned())),
            _ => {}
        }
    }
    match (username, token) {
        (Some(username), Some(token)) if !username.is_empty() && !token.is_empty() => {
            Ok(SsoResult::Cas { username, token })
        }
        _ => Err(GpError::SsoFailed(
            "Cloud Authentication Service result without user or token".into(),
        )),
    }
}

/// Looks for the result fields as XML-ish tags (`<prelogin-cookie>…`) or as response
/// headers (`prelogin-cookie: …`). `Ok(None)`: no result fields at all.
fn parse_tagged(text: &str) -> Result<Option<SsoResult>, GpError> {
    let field = |name: &str| tag_value(text, name).or_else(|| header_value(text, name));
    let status = field("saml-auth-status");
    let username = field("saml-username");
    let prelogin = field("prelogin-cookie");
    let portal = field("portal-userauthcookie");

    if status.is_none() && username.is_none() && prelogin.is_none() && portal.is_none() {
        return Ok(None);
    }
    if let Some(status) = &status
        && status != "1"
    {
        let message = field("saml-auth-status-message")
            .or_else(|| field("message"))
            .unwrap_or_else(|| format!("status {status}"));
        return Err(GpError::SsoFailed(message));
    }
    let username = username
        .filter(|u| !u.is_empty())
        .ok_or_else(|| GpError::SsoFailed("the login result has no username".into()))?;
    let usable = |v: Option<String>| v.filter(|c| !c.is_empty() && c != "empty").map(Secret::new);
    let prelogin_cookie = usable(prelogin);
    let portal_userauthcookie = usable(portal);
    if prelogin_cookie.is_none() && portal_userauthcookie.is_none() {
        return Err(GpError::SsoFailed(
            "the login result has no prelogin-cookie or portal-userauthcookie".into(),
        ));
    }
    Ok(Some(SsoResult::Saml {
        username,
        prelogin_cookie,
        portal_userauthcookie,
    }))
}

/// Text between `<name>` and `</name>` (the callback document wraps them in a comment).
fn tag_value(text: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(polytunnel_core::xml::decode_entities(
        text[start..end].trim(),
    ))
}

/// Value of a `name: value` header line.
fn header_value(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "<html><!-- <saml-auth-status>1</saml-auth-status>\
        <prelogin-cookie>FAKE-prelogin-cookie-0001</prelogin-cookie>\
        <saml-username>user@example.com</saml-username><saml-slo>no</saml-slo>\
        <saml-SessionNotOnOrAfter></saml-SessionNotOnOrAfter> --></html>";

    fn expected() -> SsoResult {
        SsoResult::Saml {
            username: "user@example.com".into(),
            prelogin_cookie: Some(Secret::new("FAKE-prelogin-cookie-0001")),
            portal_userauthcookie: None,
        }
    }

    #[test]
    fn callback_link_with_base64_payload() {
        let link = format!("globalprotectcallback:{}", STANDARD.encode(DOC));
        assert_eq!(parse_callback(&link), Ok(expected()));
        let slashed = format!("globalprotectcallback://{}", URL_SAFE_NO_PAD.encode(DOC));
        assert_eq!(parse_callback(&slashed), Ok(expected()));
        let encoded = format!(
            "GlobalProtectCallback:{}",
            STANDARD.encode(DOC).replace('=', "%3D").replace('+', "%2B")
        );
        assert_eq!(parse_callback(&encoded), Ok(expected()));
    }

    #[test]
    fn pasted_page_source_or_headers() {
        assert_eq!(parse_callback(DOC), Ok(expected()));
        let headers = "HTTP/1.1 200 OK\nsaml-username: user@example.com\n\
                       prelogin-cookie: FAKE-prelogin-cookie-0001\nsaml-auth-status: 1\n";
        assert_eq!(parse_callback(headers), Ok(expected()));
    }

    #[test]
    fn portal_cookie_variant() {
        let doc = "<saml-auth-status>1</saml-auth-status><saml-username>u</saml-username>\
                   <portal-userauthcookie>FAKE-portal-cookie</portal-userauthcookie>\
                   <prelogin-cookie>empty</prelogin-cookie>";
        assert_eq!(
            parse_callback(doc),
            Ok(SsoResult::Saml {
                username: "u".into(),
                prelogin_cookie: None,
                portal_userauthcookie: Some(Secret::new("FAKE-portal-cookie")),
            })
        );
    }

    #[test]
    fn cas_variant() {
        let link = "globalprotectcallback:cas-as=1&un=user%40example.com&token=FAKE.jwt.token";
        assert_eq!(
            parse_callback(link),
            Ok(SsoResult::Cas {
                username: "user@example.com".into(),
                token: Secret::new("FAKE.jwt.token"),
            })
        );
    }

    #[test]
    fn failures() {
        let failed = "<saml-auth-status>-1</saml-auth-status><saml-username>u</saml-username>";
        assert!(matches!(parse_callback(failed), Err(GpError::SsoFailed(_))));
        let no_cookie = "<saml-auth-status>1</saml-auth-status><saml-username>u</saml-username>";
        assert!(matches!(
            parse_callback(no_cookie),
            Err(GpError::SsoFailed(_))
        ));
        for junk in [
            "",
            "hello",
            "globalprotectcallback:",
            "globalprotectcallback:!!!",
        ] {
            assert!(
                matches!(parse_callback(junk), Err(GpError::SsoFailed(_))),
                "{junk}"
            );
        }
        assert!(parse_callback(&"A".repeat(MAX_CALLBACK_LEN + 1)).is_err());
    }
}
