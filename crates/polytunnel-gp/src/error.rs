use std::fmt;

use polytunnel_core::http::HttpError;
use polytunnel_core::xml::XmlError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpError {
    /// Network or TLS failure.
    Http(String),
    /// Unexpected HTTP status for a step.
    Status { step: &'static str, status: u16 },
    /// The server answered something we cannot understand.
    BadResponse { step: &'static str, detail: String },
    /// The server reported an error message.
    Server(String),
    /// Wrong credentials or an expired/rejected cookie.
    AuthFailed(String),
    /// The browser login did not complete.
    SsoFailed(String),
    /// The server wants something Polytunnel does not support (yet).
    Unsupported(String),
    /// No usable gateway.
    NoGateway(String),
    /// The user cancelled.
    Cancelled,
}

impl fmt::Display for GpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GpError::Http(e) => write!(f, "network error: {e}"),
            GpError::Status { step, status } => {
                write!(f, "{step}: unexpected HTTP status {status}")
            }
            GpError::BadResponse { step, detail } => {
                write!(f, "{step}: unexpected response ({detail})")
            }
            GpError::Server(msg) => write!(f, "the server reported an error: {msg}"),
            GpError::AuthFailed(msg) => write!(f, "authentication failed: {msg}"),
            GpError::SsoFailed(msg) => write!(f, "single sign-on failed: {msg}"),
            GpError::Unsupported(msg) => write!(f, "not supported: {msg}"),
            GpError::NoGateway(msg) => write!(f, "no gateway: {msg}"),
            GpError::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for GpError {}

impl From<HttpError> for GpError {
    fn from(e: HttpError) -> Self {
        GpError::Http(e.0)
    }
}

impl GpError {
    /// A reply that is not XML. GlobalProtect servers answer some errors with one line of
    /// plain text, often after an XML declaration (e.g. `Invalid authentication cookie`):
    /// that text is reported. Anything else is an unexpected response.
    pub(crate) fn not_xml(step: &'static str, body: &str, error: XmlError) -> GpError {
        match plain_text_message(body) {
            Some(msg) if msg.eq_ignore_ascii_case("Invalid authentication cookie") => {
                GpError::AuthFailed(format!("the gateway session expired ({step})"))
            }
            Some(msg) => GpError::Server(format!("{msg} ({step})")),
            None => GpError::BadResponse {
                step,
                detail: format!("not XML: {error}"),
            },
        }
    }
}

/// The server's plain-text message: an optional XML declaration, then text without markup.
/// Only the first line, at most 200 characters, without control characters.
fn plain_text_message(body: &str) -> Option<String> {
    let mut rest = body.strip_prefix('\u{feff}').unwrap_or(body).trim_start();
    if rest.starts_with("<?xml") {
        rest = &rest[rest.find("?>")? + 2..];
    }
    let text = rest.trim();
    if text.contains('<') {
        return None;
    }
    let msg: String = text
        .lines()
        .next()?
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    (!msg.is_empty()).then_some(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn not_xml(body: &str) -> GpError {
        let error = polytunnel_core::xml::Element::parse(body).unwrap_err();
        GpError::not_xml("tunnel configuration", body, error)
    }

    #[test]
    fn plain_text_replies_are_reported() {
        assert_eq!(
            not_xml(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n\terrors getting SSL/VPN config\n"
            ),
            GpError::Server("errors getting SSL/VPN config (tunnel configuration)".into())
        );
        assert_eq!(
            not_xml("Matching client config not found"),
            GpError::Server("Matching client config not found (tunnel configuration)".into())
        );
        assert!(matches!(
            not_xml("<?xml version=\"1.0\"?>Invalid authentication cookie"),
            GpError::AuthFailed(_)
        ));
        let long = not_xml(&"x".repeat(500));
        assert_eq!(
            long,
            GpError::Server(format!("{} (tunnel configuration)", "x".repeat(200)))
        );
    }

    #[test]
    fn markup_and_empty_replies_stay_unexpected() {
        for body in [
            "<html><body>Not found</body>",
            "",
            "<?xml version=\"1.0\"?>  \n",
            "a < b",
        ] {
            assert!(
                matches!(not_xml(body), GpError::BadResponse { .. }),
                "{body:?}"
            );
        }
    }
}
