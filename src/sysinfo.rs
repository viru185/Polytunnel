//! Real facts about this machine for the VPN server: host name, OS version and a stable,
//! random installation ID. Nothing here is a hardware identifier.

use std::fs;

use polytunnel_core::profile::ClientOs;
use polytunnel_gp::ClientInfo;

use crate::paths;

/// Client facts, with the profile's explicit overrides applied.
pub fn client_info(os: Option<ClientOs>, app_version: Option<String>) -> ClientInfo {
    let os = os.unwrap_or_else(ClientOs::current);
    ClientInfo {
        os,
        os_version: os_version(),
        computer: computer_name(),
        host_id: host_id(),
        // An empty `client-version` turns the announcement off.
        app_version: app_version.filter(|v| !v.trim().is_empty()),
    }
}

pub fn computer_name() -> String {
    #[cfg(windows)]
    let name = crate::win::computer_name();
    #[cfg(unix)]
    let name = unix_hostname();
    #[cfg(not(any(windows, unix)))]
    let name: Option<String> = None;
    name.filter(|n| !n.is_empty())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "localhost".into())
}

#[cfg(unix)]
fn unix_hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is valid for `buf.len()` bytes; gethostname NUL-terminates on success.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// e.g. `Microsoft Windows 11 Pro , 64-bit`, `Linux Ubuntu 24.04 LTS`, `Apple Mac OS X 14.5`.
pub fn os_version() -> String {
    #[cfg(windows)]
    {
        use crate::win::{Hive, reg_get_string};
        const KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        let mut product =
            reg_get_string(Hive::LocalMachine, KEY, "ProductName").unwrap_or("Windows".into());
        // Windows 11 still reports "Windows 10" in ProductName; the build number tells.
        let build: u32 = reg_get_string(Hive::LocalMachine, KEY, "CurrentBuildNumber")
            .and_then(|b| b.parse().ok())
            .unwrap_or(0);
        if build >= 22000 {
            product = product.replace("Windows 10", "Windows 11");
        }
        let bits = if cfg!(target_pointer_width = "64") {
            "64-bit"
        } else {
            "32-bit"
        };
        format!("Microsoft {product} , {bits}")
    }
    #[cfg(target_os = "macos")]
    {
        let version = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        format!("Apple Mac OS X {version}")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let pretty = fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|text| {
                text.lines().find_map(|line| {
                    line.strip_prefix("PRETTY_NAME=")
                        .map(|v| v.trim_matches('"').to_string())
                })
            })
            .unwrap_or_else(|| "Linux".into());
        if pretty.starts_with("Linux") {
            pretty
        } else {
            format!("Linux {pretty}")
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        "Unknown".into()
    }
}

/// A random ID created once per user and kept in the config directory.
pub fn host_id() -> String {
    let file = paths::config_dir().map(|d| d.join("host-id"));
    if let Some(existing) = file
        .as_ref()
        .and_then(|f| fs::read_to_string(f).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| is_uuid(s))
    {
        return existing;
    }
    let id = new_uuid();
    if let Some(file) = file {
        if let Some(dir) = file.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let _ = fs::write(file, &id);
    }
    id
}

fn new_uuid() -> String {
    let mut b = [0u8; 16];
    if getrandom::fill(&mut b).is_err() {
        // No OS randomness: fall back to the clock (only used as an installation label).
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        b = nanos.to_le_bytes();
    }
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_are_v4_shaped() {
        let id = new_uuid();
        assert!(is_uuid(&id), "{id}");
        assert_eq!(&id[14..15], "4");
        assert!(!is_uuid("not-a-uuid"));
    }

    #[test]
    fn os_version_is_not_empty() {
        assert!(!os_version().is_empty());
        assert!(!computer_name().is_empty());
    }
}
