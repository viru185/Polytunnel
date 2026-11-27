//! Shared types for Polytunnel.
//!
//! This crate holds only plain data and validation: no I/O, no keyring, no OS calls. Both the
//! user-side app and the privileged daemon depend on it, so everything here must be safe to
//! use on either side of the IPC boundary.

pub mod http;
pub mod ipc;
pub mod pin;
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

/// `x.y.z` (an optional leading `v` allowed) as numbers.
fn version_parts(v: &str) -> Option<[u64; 3]> {
    let mut parts = v.trim().trim_start_matches('v').split('.');
    let mut out = [0u64; 3];
    for slot in &mut out {
        *slot = parts.next()?.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// Whether `latest` is a newer release than `current` (plain x.y.z versions).
pub fn is_newer_version(latest: &str, current: &str) -> bool {
    matches!((version_parts(latest), version_parts(current)), (Some(l), Some(c)) if l > c)
}

/// Whether `v` is a plain x.y.z version.
pub fn is_version(v: &str) -> bool {
    version_parts(v).is_some()
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn version_order() {
        assert!(is_newer_version("0.2.0", "0.1.9"));
        assert!(is_newer_version("v1.0.0", "0.9.9"));
        assert!(is_newer_version("0.10.0", "0.9.0"));
        assert!(!is_newer_version("0.1.0", "0.1.0"));
        assert!(!is_newer_version("0.0.9", "0.1.0"), "no downgrades");
        assert!(!is_newer_version("garbage", "0.1.0"));
        assert!(!is_newer_version("1.0", "0.1.0"));
        assert!(is_version("1.2.3") && !is_version("latest"));
    }
}
