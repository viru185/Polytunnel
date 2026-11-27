//! IP networks (`address/length`).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A network: the address with host bits cleared, and the prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    /// `len` is checked against the address family; host bits are cleared.
    pub fn new(addr: IpAddr, len: u8) -> Option<Self> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (len <= max).then(|| Prefix {
            addr: mask(addr, len),
            len,
        })
    }

    /// A single host (`/32` or `/128`).
    pub fn host(addr: IpAddr) -> Self {
        Prefix {
            addr,
            len: if addr.is_ipv4() { 32 } else { 128 },
        }
    }

    /// From an address and a dotted netmask (`255.255.255.0`); contiguous masks only.
    pub fn from_netmask(addr: Ipv4Addr, netmask: Ipv4Addr) -> Option<Self> {
        let bits = u32::from(netmask);
        if bits.leading_ones() + bits.trailing_zeros() != 32 {
            return None;
        }
        Prefix::new(IpAddr::V4(addr), bits.leading_ones() as u8)
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// `0.0.0.0/0` or `::/0`.
    pub fn is_default(&self) -> bool {
        self.len == 0
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        ip.is_ipv4() == self.addr.is_ipv4() && mask(ip, self.len) == self.addr
    }

    /// The dotted netmask of an IPv4 prefix.
    pub fn netmask_v4(&self) -> Option<Ipv4Addr> {
        self.is_ipv4().then(|| {
            Ipv4Addr::from(if self.len == 0 {
                0
            } else {
                u32::MAX << (32 - self.len)
            })
        })
    }
}

fn mask(addr: IpAddr, len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let m = if len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(len))
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & m))
        }
        IpAddr::V6(v6) => {
            let m = if len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(len))
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & m))
        }
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixError(pub String);

impl fmt::Display for PrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid network '{}'", self.0)
    }
}

impl std::error::Error for PrefixError {}

impl FromStr for Prefix {
    type Err = PrefixError;

    /// `192.0.2.0/24`, `192.0.2.0/255.255.255.0`, `2001:db8::/32`, or a bare address (host).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || PrefixError(s.to_string());
        let s = s.trim();
        match s.split_once('/') {
            None => s.parse::<IpAddr>().map(Prefix::host).map_err(|_| err()),
            Some((addr, len)) => {
                let addr: IpAddr = addr.parse().map_err(|_| err())?;
                if let (IpAddr::V4(v4), Ok(netmask)) = (addr, len.parse::<Ipv4Addr>()) {
                    return Prefix::from_netmask(v4, netmask).ok_or_else(err);
                }
                let len: u8 = len.parse().map_err(|_| err())?;
                Prefix::new(addr, len).ok_or_else(err)
            }
        }
    }
}

impl TryFrom<String> for Prefix {
    type Error = PrefixError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Prefix> for String {
    fn from(p: Prefix) -> String {
        p.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes() {
        let p: Prefix = "192.0.2.77/24".parse().unwrap();
        assert_eq!(p.to_string(), "192.0.2.0/24");
        assert_eq!(
            "198.51.100.0/255.255.255.128"
                .parse::<Prefix>()
                .unwrap()
                .prefix_len(),
            25
        );
        assert_eq!(
            "2001:db8::1/32".parse::<Prefix>().unwrap().to_string(),
            "2001:db8::/32"
        );
        assert_eq!("203.0.113.9".parse::<Prefix>().unwrap().prefix_len(), 32);
        assert!("0.0.0.0/0".parse::<Prefix>().unwrap().is_default());
        for bad in [
            "",
            "x/24",
            "192.0.2.0/33",
            "2001:db8::/129",
            "192.0.2.0/255.0.255.0",
        ] {
            assert!(bad.parse::<Prefix>().is_err(), "{bad}");
        }
    }

    #[test]
    fn contains_and_netmask() {
        let p: Prefix = "192.0.2.0/24".parse().unwrap();
        assert!(p.contains("192.0.2.200".parse().unwrap()));
        assert!(!p.contains("198.51.100.1".parse().unwrap()));
        assert!(!p.contains("2001:db8::1".parse().unwrap()));
        assert_eq!(p.netmask_v4(), Some(Ipv4Addr::new(255, 255, 255, 0)));
    }

    #[test]
    fn serde_uses_the_text_form() {
        let p: Prefix = "192.0.2.0/24".parse().unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, "\"192.0.2.0/24\"");
        assert_eq!(serde_json::from_str::<Prefix>(&json).unwrap(), p);
        assert!(serde_json::from_str::<Prefix>("\"nope\"").is_err());
    }
}
