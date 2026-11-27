//! The kill switch: while a tunnel is up (or always, in lockdown), traffic may only leave
//! through the tunnel. Exceptions: the VPN servers themselves, loopback, DHCP, IPv6
//! link-local and multicast (neighbour discovery), and optionally the local network.
//!
//! - Windows: Windows Filtering Platform filters in Polytunnel's own sublayer. In a dynamic
//!   session they vanish when the service stops or crashes; lockdown uses persistent filters.
//! - Linux: an nftables table (`inet polytunnel`).
//! - macOS: a pf anchor (`com.apple/polytunnel`, which the default pf.conf evaluates).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// What may pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    /// The tunnel interface; `None` in lockdown while disconnected.
    pub tunnel_if: Option<u32>,
    /// VPN servers that stay reachable outside the tunnel.
    pub servers: Vec<IpAddr>,
    /// Also allow the local network (private ranges, link-local, multicast).
    pub allow_lan: bool,
    /// Programs allowed outside the tunnel (Windows only: the Polytunnel programs).
    pub programs: Vec<PathBuf>,
}

pub trait KillSwitch: Send {
    /// Replaces whatever rules are in force with `rules`.
    fn apply(&mut self, rules: &Rules) -> io::Result<()>;
    /// Removes the kill switch.
    fn clear(&mut self) -> io::Result<()>;
}

/// The local network: private IPv4 ranges, link-local, multicast and broadcast.
pub const LAN_V4: [(Ipv4Addr, u8); 6] = [
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(255, 255, 255, 255), 32),
];
/// IPv6 unique-local addresses (allowed with the LAN).
pub const LAN_V6: [(Ipv6Addr, u8); 1] = [(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7)];
/// IPv6 link-local and multicast: always allowed (neighbour discovery).
pub const LINK_V6: [(Ipv6Addr, u8); 2] = [
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
];

/// The kill switch for this platform. `persistent`: keep the rules if the service stops
/// (lockdown); otherwise they go with it.
pub fn native(persistent: bool) -> Box<dyn KillSwitch> {
    #[cfg(windows)]
    {
        Box::new(wfp::Wfp::new(persistent))
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(Nft { persistent })
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(Pf {
            persistent,
            token: None,
        })
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = persistent;
        Box::new(Unsupported)
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
struct Unsupported;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
impl KillSwitch for Unsupported {
    fn apply(&mut self, _: &Rules) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no kill switch on this platform",
        ))
    }

    fn clear(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn v4(list: &[IpAddr]) -> Vec<String> {
    list.iter()
        .filter(|a| a.is_ipv4())
        .map(IpAddr::to_string)
        .collect()
}

fn v6(list: &[IpAddr]) -> Vec<String> {
    list.iter()
        .filter(|a| a.is_ipv6())
        .map(IpAddr::to_string)
        .collect()
}

/// The nftables ruleset (replaces any earlier Polytunnel table atomically).
pub fn nft_script(rules: &Rules, tunnel: Option<&str>) -> String {
    let set = |items: Vec<String>| format!("{{ {} }}", items.join(", "));
    let mut accept = Vec::new();
    if let Some(name) = tunnel {
        accept.push(format!("ifname \"{name}\" accept"));
    }
    if !v4(&rules.servers).is_empty() {
        accept.push(format!("ip addr {} accept", set(v4(&rules.servers))));
    }
    if !v6(&rules.servers).is_empty() {
        accept.push(format!("ip6 addr {} accept", set(v6(&rules.servers))));
    }
    let link: Vec<String> = LINK_V6.iter().map(|(a, l)| format!("{a}/{l}")).collect();
    accept.push(format!("ip6 addr {} accept", set(link)));
    if rules.allow_lan {
        let lan: Vec<String> = LAN_V4.iter().map(|(a, l)| format!("{a}/{l}")).collect();
        accept.push(format!("ip addr {} accept", set(lan)));
        let lan6: Vec<String> = LAN_V6.iter().map(|(a, l)| format!("{a}/{l}")).collect();
        accept.push(format!("ip6 addr {} accept", set(lan6)));
    }
    // Each rule is written for both directions: "addr" becomes daddr/saddr, "ifname" oif/iif.
    let chain = |hook: &str, dir_addr: &str, dir_if: &str| {
        let mut out = format!(
            "  chain {hook} {{\n    type filter hook {hook} priority 0; policy drop;\n    {dir_if}name \"lo\" accept\n"
        );
        // Like WFP's connection-level filters: only new connections are judged.
        out.push_str("    ct state established,related accept\n");
        out.push_str("    udp dport { 67, 68, 546, 547 } accept\n");
        for rule in &accept {
            let rule = rule
                .replace("ifname", &format!("{dir_if}name"))
                .replace(" addr ", &format!(" {dir_addr} "));
            out.push_str(&format!("    {rule}\n"));
        }
        out.push_str("  }\n");
        out
    };
    format!(
        "table inet polytunnel\ndelete table inet polytunnel\ntable inet polytunnel {{\n{}{}}}\n",
        chain("output", "daddr", "oif"),
        chain("input", "saddr", "iif"),
    )
}

/// The pf rules for the `com.apple/polytunnel` anchor.
pub fn pf_rules(rules: &Rules, tunnel: Option<&str>) -> String {
    let mut out = String::from("pass quick on lo0 all\n");
    if let Some(name) = tunnel {
        out.push_str(&format!("pass quick on {name} all\n"));
    }
    out.push_str("pass quick proto udp from any to any port { 67, 68, 546, 547 }\n");
    for addr in rules.servers.iter().map(IpAddr::to_string) {
        out.push_str(&format!(
            "pass out quick to {addr}\npass in quick from {addr}\n"
        ));
    }
    for (a, l) in LINK_V6 {
        out.push_str(&format!("pass quick inet6 from any to {a}/{l}\n"));
    }
    if rules.allow_lan {
        for (a, l) in LAN_V4 {
            out.push_str(&format!("pass quick inet from any to {a}/{l}\n"));
        }
        for (a, l) in LAN_V6 {
            out.push_str(&format!("pass quick inet6 from any to {a}/{l}\n"));
        }
    }
    out.push_str("block drop quick all\n");
    out
}

/// Runs `program` with `input` on its standard input; a failure carries its error output.
#[cfg(unix)]
fn run_with_input(program: &str, args: &[&str], input: &str) -> io::Result<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(io::Error::other(format!(
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(target_os = "linux")]
struct Nft {
    persistent: bool,
}

#[cfg(target_os = "linux")]
impl KillSwitch for Nft {
    fn apply(&mut self, rules: &Rules) -> io::Result<()> {
        let tunnel = rules.tunnel_if.map(crate::system::if_name).transpose()?;
        run_with_input("nft", &["-f", "-"], &nft_script(rules, tunnel.as_deref())).map(|_| ())
    }

    fn clear(&mut self) -> io::Result<()> {
        run_with_input(
            "nft",
            &["-f", "-"],
            "table inet polytunnel\ndelete table inet polytunnel\n",
        )
        .map(|_| ())
    }
}

#[cfg(target_os = "linux")]
impl Drop for Nft {
    fn drop(&mut self) {
        if !self.persistent {
            let _ = self.clear();
        }
    }
}

#[cfg(target_os = "macos")]
struct Pf {
    persistent: bool,
    /// The reference from `pfctl -E`, released when the rules go.
    token: Option<String>,
}

#[cfg(target_os = "macos")]
const ANCHOR: &str = "com.apple/polytunnel";

#[cfg(target_os = "macos")]
impl KillSwitch for Pf {
    fn apply(&mut self, rules: &Rules) -> io::Result<()> {
        let tunnel = rules.tunnel_if.map(crate::system::if_name).transpose()?;
        run_with_input(
            "pfctl",
            &["-a", ANCHOR, "-f", "-"],
            &pf_rules(rules, tunnel.as_deref()),
        )?;
        if self.token.is_none() {
            // pfctl prints "Token : <n>" (on standard error) when it enables pf.
            let out = std::process::Command::new("/sbin/pfctl")
                .arg("-E")
                .output()?;
            let text = String::from_utf8_lossy(&out.stderr).into_owned()
                + &String::from_utf8_lossy(&out.stdout);
            self.token = text
                .lines()
                .find_map(|l| l.split_once("Token : ").map(|(_, t)| t.trim().to_string()));
        }
        Ok(())
    }

    fn clear(&mut self) -> io::Result<()> {
        run_with_input("pfctl", &["-a", ANCHOR, "-F", "all"], "")?;
        if let Some(token) = self.token.take() {
            let _ = run_with_input("pfctl", &["-X", &token], "");
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Drop for Pf {
    fn drop(&mut self) {
        if !self.persistent {
            let _ = self.clear();
        }
    }
}

#[cfg(windows)]
mod wfp {
    use std::ffi::c_void;
    use std::io;
    use std::net::IpAddr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
        FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT8,
        FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
        FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS,
        FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL,
        FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER_CONDITION0,
        FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0,
        FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0,
        FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
        FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
        FwpmTransactionCommit0,
    };
    use windows_sys::core::GUID;

    use super::{KillSwitch, LAN_V4, LAN_V6, LINK_V6, Rules};

    /// Polytunnel's sublayer, and the base of its filter keys (persistent filters are deleted
    /// by key).
    const SUBLAYER: GUID = GUID::from_u128(0x7d3c_2b1a_9e4f_4c6d_8a5b_1f0e_2d3c_4b5a);
    const FILTER_BASE: u128 = 0x7d3c_2b1a_9e4f_4c6d_8a5b_1f0e_2d3c_0000;
    const MAX_FILTERS: u128 = 512;
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const IPPROTO_UDP: u8 = 17;
    const V4_LAYERS: [GUID; 2] = [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    ];
    const V6_LAYERS: [GUID; 2] = [
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    ];

    fn check(code: u32, what: &str) -> io::Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!("{what} failed (0x{code:08x})")))
        }
    }

    fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
        s.as_ref().encode_wide().chain(Some(0)).collect()
    }

    pub struct Wfp {
        engine: HANDLE,
        persistent: bool,
        next_key: u128,
    }

    // SAFETY: the engine handle is only used through &mut self.
    unsafe impl Send for Wfp {}

    impl Wfp {
        pub fn new(persistent: bool) -> Self {
            Self {
                engine: null_mut(),
                persistent,
                next_key: 0,
            }
        }

        fn open(&mut self) -> io::Result<()> {
            if !self.engine.is_null() {
                return Ok(());
            }
            let session = FWPM_SESSION0 {
                flags: if self.persistent {
                    0
                } else {
                    FWPM_SESSION_FLAG_DYNAMIC
                },
                ..Default::default()
            };
            let mut engine = null_mut();
            // SAFETY: valid pointers; `engine` receives the handle.
            let code = unsafe {
                FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut engine)
            };
            check(code, "opening the Windows Filtering Platform")?;
            self.engine = engine;
            Ok(())
        }

        fn close(&mut self) {
            if !self.engine.is_null() {
                // SAFETY: the handle came from FwpmEngineOpen0. Dynamic objects go with it.
                unsafe { FwpmEngineClose0(self.engine) };
                self.engine = null_mut();
            }
        }

        fn remove_all(&mut self) -> io::Result<()> {
            if self.persistent {
                self.open()?;
                for i in 0..MAX_FILTERS {
                    let key = GUID::from_u128(FILTER_BASE + i);
                    // SAFETY: valid engine and key; a missing filter is not an error here.
                    unsafe { FwpmFilterDeleteByKey0(self.engine, &key) };
                }
                // SAFETY: as above.
                unsafe { FwpmSubLayerDeleteByKey0(self.engine, &SUBLAYER) };
            } else {
                self.close();
            }
            Ok(())
        }

        fn add_filter(
            &mut self,
            layer: GUID,
            conditions: &mut [FWPM_FILTER_CONDITION0],
            permit: bool,
        ) -> io::Result<()> {
            if self.next_key >= MAX_FILTERS {
                return Err(io::Error::other("too many kill switch filters"));
            }
            let mut name = wide("Polytunnel kill switch");
            let mut filter = FWPM_FILTER0 {
                filterKey: GUID::from_u128(FILTER_BASE + self.next_key),
                flags: if self.persistent {
                    FWPM_FILTER_FLAG_PERSISTENT
                } else {
                    0
                },
                layerKey: layer,
                subLayerKey: SUBLAYER,
                numFilterConditions: u32::try_from(conditions.len()).expect("few conditions"),
                filterCondition: if conditions.is_empty() {
                    null_mut()
                } else {
                    conditions.as_mut_ptr()
                },
                ..Default::default()
            };
            self.next_key += 1;
            filter.displayData.name = name.as_mut_ptr();
            filter.weight.r#type = FWP_UINT8;
            filter.weight.Anonymous.uint8 = if permit { 15 } else { 0 };
            filter.action.r#type = if permit {
                FWP_ACTION_PERMIT
            } else {
                FWP_ACTION_BLOCK
            };
            let mut id = 0u64;
            // SAFETY: every pointer in `filter` (name, conditions and the values they point
            // to) outlives the call.
            let code = unsafe { FwpmFilterAdd0(self.engine, &filter, null_mut(), &mut id) };
            check(code, "adding a kill switch filter")
        }

        fn add_rules(&mut self, rules: &Rules) -> io::Result<()> {
            let mut name = wide("Polytunnel kill switch");
            let mut sublayer = FWPM_SUBLAYER0 {
                subLayerKey: SUBLAYER,
                flags: if self.persistent {
                    FWPM_SUBLAYER_FLAG_PERSISTENT
                } else {
                    0
                },
                weight: 0xffff,
                ..Default::default()
            };
            sublayer.displayData.name = name.as_mut_ptr();
            // SAFETY: valid pointers for the call.
            check(
                unsafe { FwpmSubLayerAdd0(self.engine, &sublayer, null_mut()) },
                "adding the kill switch sublayer",
            )?;
            self.next_key = 0;
            let all_layers: Vec<GUID> = V4_LAYERS.iter().chain(&V6_LAYERS).copied().collect();

            // The tunnel interface.
            if let Some(index) = rules.tunnel_if {
                let mut luid = NET_LUID_LH::default();
                // SAFETY: `luid` receives the result.
                let code = unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) };
                check(code, "finding the tunnel interface")?;
                // SAFETY: Value is the whole 64-bit LUID.
                let mut value: u64 = unsafe { luid.Value };
                for layer in &all_layers {
                    let mut c = [FWPM_FILTER_CONDITION0::default()];
                    c[0].fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
                    c[0].matchType = FWP_MATCH_EQUAL;
                    c[0].conditionValue.r#type = FWP_UINT64;
                    c[0].conditionValue.Anonymous.uint64 = &mut value;
                    self.add_filter(*layer, &mut c, true)?;
                }
            }
            // Loopback.
            for layer in &all_layers {
                let mut c = [FWPM_FILTER_CONDITION0::default()];
                c[0].fieldKey = FWPM_CONDITION_FLAGS;
                c[0].matchType = FWP_MATCH_FLAGS_ALL_SET;
                c[0].conditionValue.r#type = FWP_UINT32;
                c[0].conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                self.add_filter(*layer, &mut c, true)?;
            }
            // The Polytunnel programs.
            for path in &rules.programs {
                let mut blob: *mut FWP_BYTE_BLOB = null_mut();
                // SAFETY: NUL-terminated path; `blob` receives memory freed below.
                let code = unsafe { FwpmGetAppIdFromFileName0(wide(path).as_ptr(), &mut blob) };
                if code != 0 {
                    continue; // not installed there
                }
                let result = (|| {
                    for layer in &all_layers {
                        let mut c = [FWPM_FILTER_CONDITION0::default()];
                        c[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
                        c[0].matchType = FWP_MATCH_EQUAL;
                        c[0].conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                        c[0].conditionValue.Anonymous.byteBlob = blob;
                        self.add_filter(*layer, &mut c, true)?;
                    }
                    Ok::<(), io::Error>(())
                })();
                // SAFETY: allocated by FwpmGetAppIdFromFileName0.
                unsafe { FwpmFreeMemory0((&raw mut blob).cast::<*mut c_void>()) };
                result?;
            }
            // VPN servers, LAN, link-local.
            let mut v4_nets: Vec<(u32, u32)> = Vec::new();
            let mut v6_nets: Vec<([u8; 16], u8)> = Vec::new();
            for addr in &rules.servers {
                match addr {
                    IpAddr::V4(a) => v4_nets.push((u32::from(*a), u32::MAX)),
                    IpAddr::V6(a) => v6_nets.push((a.octets(), 128)),
                }
            }
            for (a, l) in LINK_V6 {
                v6_nets.push((a.octets(), l));
            }
            if rules.allow_lan {
                for (a, l) in LAN_V4 {
                    v4_nets.push((
                        u32::from(a),
                        u32::MAX.checked_shl(32 - u32::from(l)).unwrap_or(0),
                    ));
                }
                for (a, l) in LAN_V6 {
                    v6_nets.push((a.octets(), l));
                }
            }
            for (addr, mask) in v4_nets {
                let mut value = FWP_V4_ADDR_AND_MASK { addr, mask };
                for layer in &V4_LAYERS {
                    let mut c = [FWPM_FILTER_CONDITION0::default()];
                    c[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    c[0].matchType = FWP_MATCH_EQUAL;
                    c[0].conditionValue.r#type = FWP_V4_ADDR_MASK;
                    c[0].conditionValue.Anonymous.v4AddrMask = &mut value;
                    self.add_filter(*layer, &mut c, true)?;
                }
            }
            for (addr, prefix) in v6_nets {
                let mut value = FWP_V6_ADDR_AND_MASK {
                    addr,
                    prefixLength: prefix,
                };
                for layer in &V6_LAYERS {
                    let mut c = [FWPM_FILTER_CONDITION0::default()];
                    c[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    c[0].matchType = FWP_MATCH_EQUAL;
                    c[0].conditionValue.r#type = FWP_V6_ADDR_MASK;
                    c[0].conditionValue.Anonymous.v6AddrMask = &mut value;
                    self.add_filter(*layer, &mut c, true)?;
                }
            }
            // DHCP (v4: server port 67; v6: 547).
            for (layers, port) in [(&V4_LAYERS, 67u16), (&V6_LAYERS, 547u16)] {
                for layer in layers.iter() {
                    let mut c = [
                        FWPM_FILTER_CONDITION0::default(),
                        FWPM_FILTER_CONDITION0::default(),
                    ];
                    c[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                    c[0].matchType = FWP_MATCH_EQUAL;
                    c[0].conditionValue.r#type = FWP_UINT8;
                    c[0].conditionValue.Anonymous.uint8 = IPPROTO_UDP;
                    c[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                    c[1].matchType = FWP_MATCH_EQUAL;
                    c[1].conditionValue.r#type = FWP_UINT16;
                    c[1].conditionValue.Anonymous.uint16 = port;
                    self.add_filter(*layer, &mut c, true)?;
                }
            }
            // Everything else.
            for layer in &all_layers {
                self.add_filter(*layer, &mut [], false)?;
            }
            Ok(())
        }
    }

    impl KillSwitch for Wfp {
        fn apply(&mut self, rules: &Rules) -> io::Result<()> {
            self.remove_all()?;
            self.open()?;
            // SAFETY: valid engine handle.
            check(
                unsafe { FwpmTransactionBegin0(self.engine, 0) },
                "starting a WFP transaction",
            )?;
            match self.add_rules(rules) {
                // SAFETY: as above.
                Ok(()) => check(
                    unsafe { FwpmTransactionCommit0(self.engine) },
                    "committing the kill switch",
                ),
                Err(e) => {
                    // SAFETY: as above.
                    unsafe { FwpmTransactionAbort0(self.engine) };
                    Err(e)
                }
            }
        }

        fn clear(&mut self) -> io::Result<()> {
            self.remove_all()
        }
    }

    impl Drop for Wfp {
        fn drop(&mut self) {
            // Dynamic filters vanish with the session; persistent ones stay (lockdown).
            self.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Rules {
        Rules {
            tunnel_if: Some(7),
            servers: vec![
                "203.0.113.9".parse().unwrap(),
                "2001:db8::9".parse().unwrap(),
            ],
            allow_lan: false,
            programs: Vec::new(),
        }
    }

    #[test]
    fn nftables_ruleset() {
        let script = nft_script(&rules(), Some("tun0"));
        assert!(script.starts_with("table inet polytunnel\ndelete table inet polytunnel\n"));
        assert!(script.contains("type filter hook output priority 0; policy drop;"));
        assert!(script.contains("oifname \"tun0\" accept"));
        assert!(script.contains("iifname \"tun0\" accept"));
        assert!(script.contains("ip daddr { 203.0.113.9 } accept"));
        assert!(script.contains("ip6 saddr { 2001:db8::9 } accept"));
        assert!(script.contains("fe80::/10"));
        assert!(!script.contains("192.168.0.0/16"));
        let lan = nft_script(
            &Rules {
                allow_lan: true,
                ..rules()
            },
            None,
        );
        assert!(lan.contains("ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"));
        assert!(!lan.contains("tun0"));
    }

    #[test]
    fn pf_ruleset() {
        let r = pf_rules(&rules(), Some("utun4"));
        assert!(r.contains("pass quick on utun4 all"));
        assert!(r.contains("pass out quick to 203.0.113.9"));
        assert!(r.trim_end().ends_with("block drop quick all"));
        assert!(
            pf_rules(
                &Rules {
                    allow_lan: true,
                    ..rules()
                },
                None
            )
            .contains("10.0.0.0/8")
        );
    }
}
