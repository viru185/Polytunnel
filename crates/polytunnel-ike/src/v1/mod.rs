//! IKEv1 for FortiGate dial-up IPsec.

pub mod cfg;
pub mod config;
pub mod initiator;
pub mod keymat;
pub mod wire;

#[cfg(test)]
mod tests;

pub use cfg::{ModeConfig, XauthField, XauthPrompt};
pub use config::{Config, Credentials, EspProposal, Identity, IkeProposal, ModeConfigMode};
pub use initiator::{ChildSa, Initiator, Output};
