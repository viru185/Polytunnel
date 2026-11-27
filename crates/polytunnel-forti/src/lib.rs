//! Fortinet (FortiGate) for Polytunnel.
//!
//! * [`login`]: SSL VPN login (`/remote/logincheck`), including token / two-factor rounds,
//!   which yields the `SVPNCOOKIE` session cookie.
//!
//! Like the GlobalProtect crate, this is "sans I/O": requests go through a caller-supplied
//! [`Transport`](polytunnel_core::http::Transport).

pub mod login;

pub use login::{FortiError, TokenChallenge, login};
