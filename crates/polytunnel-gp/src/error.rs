use std::fmt;

use polytunnel_core::http::HttpError;

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
