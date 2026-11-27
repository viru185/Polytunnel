//! Palo Alto GlobalProtect: login and session setup.
//!
//! Everything here is "sans I/O": functions build [`Request`]s and parse [`Response`]s, and
//! [`flow::login`] drives the exchange through a caller-supplied [`Transport`] and
//! [`flow::Prompter`] (which shows browser logins and password prompts). Protocol facts come
//! from public documentation and observed behaviour; no third-party code is copied.
//!
//! The exchange:
//!
//! 1. **Portal pre-login** (`/global-protect/prelogin.esp`): password or SAML, and the
//!    client's source region.
//! 2. **SAML** in the browser; the result comes back through a `globalprotectcallback:` link
//!    ([`sso::parse_callback`]).
//! 3. **Portal configuration** (`/global-protect/getconfig.esp`): the gateway list and a
//!    portal cookie that can stand in for a second login at the gateway.
//! 4. **Gateway pre-login and login** (`/ssl-vpn/prelogin.esp`, `/ssl-vpn/login.esp`): the
//!    session `authcookie` used by the tunnel.
//!
//! [`Request`]: polytunnel_core::http::Request
//! [`Response`]: polytunnel_core::http::Response
//! [`Transport`]: polytunnel_core::http::Transport

pub mod client;
pub mod error;
pub mod flow;
pub mod login;
pub mod portal;
pub mod prelogin;
pub mod sso;

pub use client::ClientInfo;
pub use error::GpError;
