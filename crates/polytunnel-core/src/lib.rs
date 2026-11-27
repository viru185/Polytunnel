//! Shared types for Polytunnel.
//!
//! This crate holds only plain data and validation: no I/O, no keyring, no OS calls. Both the
//! user-side app and the privileged daemon depend on it, so everything here must be safe to
//! use on either side of the IPC boundary.

pub mod http;
pub mod profile;
pub mod secret;
pub mod xml;

pub use secret::Secret;

/// The product name shown to users.
pub const PRODUCT_NAME: &str = "Polytunnel";

/// The version every Polytunnel crate shares (they are released in lockstep).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_semver_like() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "{VERSION}");
        assert!(parts.iter().all(|p| p.parse::<u64>().is_ok()), "{VERSION}");
    }
}
