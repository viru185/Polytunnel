//! Windows: routes through the IP Helper API, DNS routing through NRPT rules.
//!
//! NRPT (Name Resolution Policy Table) rules send queries for chosen domains (or, with
//! `"."`, every query) to the tunnel's DNS servers no matter which adapter would otherwise
//! answer, so split DNS works and a full tunnel cannot leak DNS. If Group Policy already
//! defines NRPT rules, Windows ignores locally defined ones, so the rule goes next to the
//! policy rules instead.

use std::io;
use std::mem::zeroed;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use std::process::Command;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, ERROR_SUCCESS,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, GetBestRoute2, InitializeIpForwardEntry,
    MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, MIB_IPPROTO_NETMGMT, SOCKADDR_INET,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_MULTI_SZ, REG_SZ, RegCloseKey,
    RegDeleteKeyW, RegDeleteTreeW, RegOpenKeyExW, RegQueryInfoKeyW, RegSetKeyValueW,
};

use super::System;
use crate::plan::{Change, Via};
use crate::prefix::Prefix;

pub struct Windows;

const NRPT_LOCAL: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
const NRPT_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn os_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    // SAFETY: SOCKADDR_INET is plain data; all-zero is a valid (unspecified) value.
    let mut sa: SOCKADDR_INET = unsafe { zeroed() };
    match ip {
        IpAddr::V4(v4) => {
            sa.Ipv4.sin_family = AF_INET;
            sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            sa.Ipv6.sin6_family = AF_INET6;
            sa.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    sa
}

fn ip_of(sa: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: si_family tells which union member is valid.
    unsafe {
        match sa.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                sa.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

fn route_row(prefix: &Prefix, via: &Via) -> MIB_IPFORWARD_ROW2 {
    // SAFETY: plain data; InitializeIpForwardEntry fills in the defaults.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    let (gateway, index) = match *via {
        Via::Tunnel { if_index } => (None, if_index),
        Via::Gateway { gateway, if_index } => (gateway, if_index),
    };
    let unspecified = if prefix.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    row.InterfaceIndex = index;
    row.DestinationPrefix.Prefix = sockaddr(prefix.addr());
    row.DestinationPrefix.PrefixLength = prefix.prefix_len();
    row.NextHop = sockaddr(gateway.unwrap_or(unspecified));
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

fn set_value(key: &str, name: &str, kind: u32, data: &[u8]) -> io::Result<()> {
    let (key, name) = (wide(key), wide(name));
    // SAFETY: NUL-terminated strings; `data` is `data.len()` bytes.
    let rc = unsafe {
        RegSetKeyValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            kind,
            data.as_ptr().cast(),
            data.len() as u32,
        )
    };
    if rc == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(os_error(rc))
    }
}

fn utf16_bytes(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|u| u.to_le_bytes()).collect()
}

fn set_sz(key: &str, name: &str, value: &str) -> io::Result<()> {
    set_value(key, name, REG_SZ, &utf16_bytes(&wide(value)))
}

fn set_dword(key: &str, name: &str, value: u32) -> io::Result<()> {
    set_value(key, name, REG_DWORD, &value.to_le_bytes())
}

fn set_multi_sz(key: &str, name: &str, values: &[String]) -> io::Result<()> {
    let mut units: Vec<u16> = Vec::new();
    for v in values {
        units.extend(std::ffi::OsStr::new(v).encode_wide());
        units.push(0);
    }
    units.push(0);
    set_value(key, name, REG_MULTI_SZ, &utf16_bytes(&units))
}

fn has_subkeys(key: &str) -> bool {
    let key = wide(key);
    let mut handle: HKEY = null_mut();
    // SAFETY: valid out-pointers; the handle is closed below.
    unsafe {
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.as_ptr(), 0, KEY_READ, &mut handle)
            != ERROR_SUCCESS
        {
            return false;
        }
        let mut subkeys = 0u32;
        let rc = RegQueryInfoKeyW(
            handle,
            null_mut(),
            null_mut(),
            null(),
            &mut subkeys,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
        );
        RegCloseKey(handle);
        rc == ERROR_SUCCESS && subkeys > 0
    }
}

fn nrpt_key(if_index: u32) -> String {
    let base = if has_subkeys(NRPT_POLICY) {
        NRPT_POLICY
    } else {
        NRPT_LOCAL
    };
    format!(r"{base}\{{8b3d2a1e-5c7f-4e2a-9d61-{if_index:012x}}}")
}

fn delete_tree(key: &str) {
    let key = wide(key);
    // SAFETY: NUL-terminated string; missing keys just fail.
    unsafe {
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, key.as_ptr());
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, key.as_ptr());
    }
}

fn flush_dns() {
    let _ = Command::new("ipconfig").arg("/flushdns").output();
}

impl System for Windows {
    fn apply(&mut self, change: &Change) -> io::Result<bool> {
        match change {
            Change::Route { prefix, via } => {
                let row = route_row(prefix, via);
                // SAFETY: `row` is a fully initialised MIB_IPFORWARD_ROW2.
                match unsafe { CreateIpForwardEntry2(&row) } {
                    ERROR_SUCCESS => Ok(true),
                    ERROR_OBJECT_ALREADY_EXISTS => Ok(false),
                    rc => Err(os_error(rc)),
                }
            }
            Change::Dns {
                if_index,
                servers,
                domains,
            } => {
                let key = nrpt_key(*if_index);
                let names: Vec<String> = domains
                    .iter()
                    .map(|d| {
                        if d == "." {
                            ".".into()
                        } else {
                            format!(".{d}")
                        }
                    })
                    .collect();
                let servers: Vec<String> = servers.iter().map(IpAddr::to_string).collect();
                set_dword(&key, "Version", 2)?;
                set_multi_sz(&key, "Name", &names)?;
                set_sz(&key, "GenericDNSServers", &servers.join(";"))?;
                set_dword(&key, "ConfigOptions", 8)?;
                set_sz(&key, "IPSECCARestriction", "")?;
                set_sz(&key, "Comment", "Polytunnel")?;
                flush_dns();
                Ok(true)
            }
        }
    }

    fn revert(&mut self, change: &Change) -> io::Result<()> {
        match change {
            Change::Route { prefix, via } => {
                let row = route_row(prefix, via);
                // SAFETY: `row` is a fully initialised MIB_IPFORWARD_ROW2.
                match unsafe { DeleteIpForwardEntry2(&row) } {
                    ERROR_SUCCESS | ERROR_NOT_FOUND | ERROR_FILE_NOT_FOUND => Ok(()),
                    rc => Err(os_error(rc)),
                }
            }
            Change::Dns { if_index, .. } => {
                for base in [NRPT_LOCAL, NRPT_POLICY] {
                    delete_tree(&format!(
                        r"{base}\{{8b3d2a1e-5c7f-4e2a-9d61-{if_index:012x}}}"
                    ));
                }
                flush_dns();
                Ok(())
            }
        }
    }

    fn route_to(&self, dest: IpAddr) -> io::Result<(Option<IpAddr>, u32)> {
        let target = sockaddr(dest);
        // SAFETY: plain data out-parameters, written by GetBestRoute2.
        let mut best: MIB_IPFORWARD_ROW2 = unsafe { zeroed() };
        let mut source: SOCKADDR_INET = unsafe { zeroed() };
        let rc = unsafe { GetBestRoute2(null(), 0, null(), &target, 0, &mut best, &mut source) };
        if rc != ERROR_SUCCESS {
            return Err(os_error(rc));
        }
        let gateway = ip_of(&best.NextHop).filter(|ip| !ip.is_unspecified());
        Ok((gateway, best.InterfaceIndex))
    }
}
