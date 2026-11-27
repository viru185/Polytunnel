//! The TUN device (Wintun on Windows, `/dev/net/tun` on Linux, utun on macOS).

use std::io;
use std::net::IpAddr;
use std::path::PathBuf;

use crate::prefix::Prefix;

pub use tun_rs::SyncDevice;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunOptions {
    /// Interface name (Windows adapter name; on macOS the system picks `utunN`).
    pub name: String,
    /// Windows: a stable adapter GUID per profile, so Windows recognises the same network
    /// each time instead of creating "Network 2", "Network 3", ...
    pub guid: Option<u128>,
    pub addresses: Vec<Prefix>,
    pub mtu: u16,
    /// Windows: full path of `wintun.dll` (loaded by full path only).
    pub wintun_dll: Option<PathBuf>,
}

/// Creates the device with its addresses and MTU, ready for packets.
pub fn open(options: &TunOptions) -> io::Result<SyncDevice> {
    let mut builder = tun_rs::DeviceBuilder::new().mtu(options.mtu);
    if !cfg!(target_os = "macos") {
        builder = builder.name(options.name.clone());
    }
    let v4: Vec<&Prefix> = options.addresses.iter().filter(|p| p.is_ipv4()).collect();
    let v6: Vec<&Prefix> = options.addresses.iter().filter(|p| !p.is_ipv4()).collect();
    if let Some(first) = v4.first()
        && let IpAddr::V4(addr) = first.addr()
    {
        builder = builder.ipv4(addr, first.prefix_len(), None);
    }
    if let Some(first) = v6.first()
        && let IpAddr::V6(addr) = first.addr()
    {
        builder = builder.ipv6(addr, first.prefix_len());
    }
    #[cfg(windows)]
    {
        if let Some(dll) = &options.wintun_dll {
            builder = builder.wintun_file(dll.display().to_string());
        }
        if let Some(guid) = options.guid {
            builder = builder.device_guid(guid);
        }
    }
    builder.build_sync()
}

/// A stable 128-bit identifier derived from a profile name (FNV-1a, so it never changes
/// between builds or Rust versions).
pub fn stable_guid(seed: &str) -> u128 {
    let mut hash: u128 = 0x6c62272e07bb014262b821756295c58d;
    for byte in seed.as_bytes() {
        hash ^= u128::from(*byte);
        hash = hash.wrapping_mul(0x0000000001000000000000000000013B);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_are_stable_and_distinct() {
        assert_eq!(stable_guid("work"), stable_guid("work"));
        assert_ne!(stable_guid("work"), stable_guid("office"));
        // Pinned so a change in the algorithm is noticed (it would rename adapters).
        assert_eq!(stable_guid(""), 0x6c62272e07bb014262b821756295c58d);
    }
}
