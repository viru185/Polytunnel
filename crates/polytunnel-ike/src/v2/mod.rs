//! IKEv2 for FortiGate dial-up IPsec (EAP, certificates, IPsec over TCP).

pub mod auth;
pub mod config;
pub mod crypto;
pub mod initiator;
pub mod wire;

pub use auth::Trust;
pub use config::{ClientAuth, Config, ServerAuth};
pub use crypto::IkeSuite;
pub use initiator::Initiator;

#[cfg(test)]
mod tests;
