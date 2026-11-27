//! Network setup for Polytunnel's tunnels.
//!
//! * [`prefix::Prefix`]: an IP network (`192.0.2.0/24`).
//! * [`plan::plan`]: turns a tunnel's settings into the list of [`plan::Change`]s to make
//!   (routes into the tunnel, host routes that keep the VPN server outside it, DNS routing,
//!   IPv6 leak protection). Pure and fully tested.
//! * [`system`]: applies and reverts changes on Windows (IP Helper API and NRPT rules),
//!   Linux (`ip`, `resolvectl`) and macOS (`route`, `scutil`).
//! * [`journal::Journal`]: records every change before it is made, so a crash or reboot can
//!   be cleaned up on the next start.
//! * [`tun`]: opens the TUN device (Wintun on Windows).

pub mod journal;
pub mod plan;
pub mod prefix;
pub mod system;
pub mod tun;

pub use plan::{Change, TunnelConfig};
pub use prefix::Prefix;
