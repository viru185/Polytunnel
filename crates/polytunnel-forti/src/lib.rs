//! Fortinet (FortiGate) for Polytunnel.
//!
//! * [`login`]: SSL VPN login (`/remote/logincheck`), including token / two-factor rounds,
//!   which yields the `SVPNCOOKIE` session cookie.
//! * [`tunnel`]: the tunnel configuration and the framing of PPP over TLS.
//! * [`ppp`]: the PPP client (LCP, IPCP) that runs inside the tunnel.
//!
//! Like the GlobalProtect crate, this is "sans I/O": requests go through a caller-supplied
//! [`Transport`](polytunnel_core::http::Transport).

pub mod login;
pub mod ppp;
pub mod tunnel;

pub use login::{FortiError, TokenChallenge, login};
