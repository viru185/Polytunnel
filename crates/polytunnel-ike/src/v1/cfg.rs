//! Mode-config and XAuth attributes (draft-dukes-ike-mode-cfg, draft-beaulieu-ike-xauth,
//! and the Cisco Unity extensions FortiGate also sends).

use std::net::Ipv4Addr;

use super::wire::{Attribute, find_attr};

/// Attribute payload types.
pub mod cfg_type {
    pub const REQUEST: u8 = 1;
    pub const REPLY: u8 = 2;
    pub const SET: u8 = 3;
    pub const ACK: u8 = 4;
}

/// Attribute types.
pub mod attr {
    pub const INTERNAL_IP4_ADDRESS: u16 = 1;
    pub const INTERNAL_IP4_NETMASK: u16 = 2;
    pub const INTERNAL_IP4_DNS: u16 = 3;
    pub const INTERNAL_IP4_NBNS: u16 = 4;
    pub const APPLICATION_VERSION: u16 = 7;
    pub const INTERNAL_IP4_SUBNET: u16 = 13;

    pub const XAUTH_TYPE: u16 = 16520;
    pub const XAUTH_USER_NAME: u16 = 16521;
    pub const XAUTH_USER_PASSWORD: u16 = 16522;
    pub const XAUTH_PASSCODE: u16 = 16523;
    pub const XAUTH_MESSAGE: u16 = 16524;
    pub const XAUTH_CHALLENGE: u16 = 16525;
    pub const XAUTH_DOMAIN: u16 = 16526;
    pub const XAUTH_STATUS: u16 = 16527;
    pub const XAUTH_NEXT_PIN: u16 = 16528;
    pub const XAUTH_ANSWER: u16 = 16529;

    pub const UNITY_BANNER: u16 = 28672;
    pub const UNITY_DEF_DOMAIN: u16 = 28674;
    pub const UNITY_SPLIT_DNS_NAME: u16 = 28675;
    pub const UNITY_SPLIT_INCLUDE: u16 = 28676;
}

/// What mode-config assigned to us.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModeConfig {
    pub address: Option<Ipv4Addr>,
    pub netmask: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    /// Networks to send through the tunnel (empty: everything).
    pub split_include: Vec<(Ipv4Addr, u8)>,
    pub default_domain: Option<String>,
    /// Domains to resolve through the tunnel's DNS servers (split DNS).
    pub split_dns: Vec<String>,
    pub banner: Option<String>,
}

impl ModeConfig {
    /// Whether `attrs` carry any mode-config setting (as opposed to XAuth).
    pub fn present(attrs: &[Attribute]) -> bool {
        attrs.iter().any(|a| {
            matches!(
                a.kind,
                attr::INTERNAL_IP4_ADDRESS
                    | attr::INTERNAL_IP4_NETMASK
                    | attr::INTERNAL_IP4_DNS
                    | attr::INTERNAL_IP4_SUBNET
                    | attr::UNITY_SPLIT_INCLUDE
                    | attr::UNITY_DEF_DOMAIN
                    | attr::UNITY_SPLIT_DNS_NAME
            )
        })
    }

    pub fn parse(attrs: &[Attribute]) -> Self {
        let mut out = ModeConfig::default();
        for a in attrs {
            match a.kind {
                attr::INTERNAL_IP4_ADDRESS if out.address.is_none() => out.address = ipv4(&a.value),
                attr::INTERNAL_IP4_NETMASK => out.netmask = ipv4(&a.value),
                attr::INTERNAL_IP4_DNS => out.dns.extend(ipv4(&a.value)),
                attr::INTERNAL_IP4_SUBNET => {
                    if let (Some(net), Some(mask)) = (
                        a.value.get(0..4).and_then(ipv4),
                        a.value.get(4..8).and_then(ipv4),
                    ) {
                        push_network(&mut out.split_include, net, mask);
                    }
                }
                attr::UNITY_SPLIT_INCLUDE => {
                    // 14-byte entries: address, mask, then protocol and ports (unused).
                    for entry in a.value.as_chunks::<14>().0 {
                        if let (Some(net), Some(mask)) = (ipv4(&entry[0..4]), ipv4(&entry[4..8])) {
                            push_network(&mut out.split_include, net, mask);
                        }
                    }
                }
                attr::UNITY_DEF_DOMAIN => out.default_domain = text(&a.value),
                attr::UNITY_SPLIT_DNS_NAME => {
                    if let Some(list) = text(&a.value) {
                        out.split_dns.extend(
                            list.split([',', ' '])
                                .map(str::trim)
                                .filter(|d| !d.is_empty())
                                .map(str::to_string),
                        );
                    }
                }
                attr::UNITY_BANNER => out.banner = text(&a.value),
                _ => {}
            }
        }
        out
    }

    /// The attributes of our pull REQUEST.
    pub fn request(client_version: &str) -> Vec<Attribute> {
        let mut attrs: Vec<Attribute> = [
            attr::INTERNAL_IP4_ADDRESS,
            attr::INTERNAL_IP4_NETMASK,
            attr::INTERNAL_IP4_DNS,
            attr::INTERNAL_IP4_SUBNET,
            attr::UNITY_DEF_DOMAIN,
            attr::UNITY_SPLIT_DNS_NAME,
            attr::UNITY_SPLIT_INCLUDE,
            attr::UNITY_BANNER,
        ]
        .into_iter()
        .map(|kind| Attribute::variable(kind, Vec::new()))
        .collect();
        attrs.push(Attribute::variable(
            attr::APPLICATION_VERSION,
            client_version.as_bytes().to_vec(),
        ));
        attrs
    }
}

fn ipv4(b: &[u8]) -> Option<Ipv4Addr> {
    <[u8; 4]>::try_from(b).ok().map(Ipv4Addr::from)
}

fn text(b: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(b);
    let s = s.trim_matches(char::from(0)).trim();
    (!s.is_empty()).then(|| {
        s.chars()
            .filter(|c| !c.is_control() || *c == '\n')
            .collect()
    })
}

fn push_network(out: &mut Vec<(Ipv4Addr, u8)>, net: Ipv4Addr, mask: Ipv4Addr) {
    let bits = u32::from(mask);
    // Only contiguous masks describe a network.
    if bits.leading_ones() + bits.trailing_zeros() == 32 || bits == 0 {
        let len = u8::try_from(bits.leading_ones()).expect("at most 32");
        let net = Ipv4Addr::from(u32::from(net) & bits);
        if !out.contains(&(net, len)) {
            out.push((net, len));
        }
    }
}

/// A field the gateway asks for during XAuth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XauthField {
    Name,
    Password,
    Passcode,
    NextPin,
    Answer,
    Domain,
}

impl XauthField {
    pub fn from_attr(kind: u16) -> Option<Self> {
        Some(match kind {
            attr::XAUTH_USER_NAME => XauthField::Name,
            attr::XAUTH_USER_PASSWORD => XauthField::Password,
            attr::XAUTH_PASSCODE => XauthField::Passcode,
            attr::XAUTH_NEXT_PIN => XauthField::NextPin,
            attr::XAUTH_ANSWER => XauthField::Answer,
            attr::XAUTH_DOMAIN => XauthField::Domain,
            _ => return None,
        })
    }

    pub fn attr(self) -> u16 {
        match self {
            XauthField::Name => attr::XAUTH_USER_NAME,
            XauthField::Password => attr::XAUTH_USER_PASSWORD,
            XauthField::Passcode => attr::XAUTH_PASSCODE,
            XauthField::NextPin => attr::XAUTH_NEXT_PIN,
            XauthField::Answer => attr::XAUTH_ANSWER,
            XauthField::Domain => attr::XAUTH_DOMAIN,
        }
    }

    /// Whether the answer should be typed without echo.
    pub fn secret(self) -> bool {
        !matches!(self, XauthField::Name | XauthField::Domain)
    }

    pub fn label(self) -> &'static str {
        match self {
            XauthField::Name => "Username",
            XauthField::Password => "Password",
            XauthField::Passcode => "Passcode",
            XauthField::NextPin => "New PIN",
            XauthField::Answer => "Answer",
            XauthField::Domain => "Domain",
        }
    }
}

/// An XAuth round that needs the user (a one-time code, a new PIN, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XauthPrompt {
    /// The gateway's message (XAUTH_MESSAGE or XAUTH_CHALLENGE), if any.
    pub message: Option<String>,
    pub fields: Vec<XauthField>,
}

impl XauthPrompt {
    pub fn from_request(attrs: &[Attribute]) -> Self {
        let message = find_attr(attrs, attr::XAUTH_MESSAGE)
            .or_else(|| find_attr(attrs, attr::XAUTH_CHALLENGE))
            .and_then(|a| text(&a.value));
        let mut fields: Vec<XauthField> = Vec::new();
        for f in attrs.iter().filter_map(|a| XauthField::from_attr(a.kind)) {
            if !fields.contains(&f) {
                fields.push(f);
            }
        }
        Self { message, fields }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_config_reply_with_unity_split_include() {
        let mut split = Vec::new();
        for (net, mask) in [
            ([10, 1, 0, 0], [255, 255, 0, 0]),
            ([192, 0, 2, 0], [255, 255, 255, 0]),
        ] {
            split.extend_from_slice(&net);
            split.extend_from_slice(&mask);
            split.extend_from_slice(&[0; 6]);
        }
        let attrs = vec![
            Attribute::variable(attr::INTERNAL_IP4_ADDRESS, vec![10, 212, 134, 200]),
            Attribute::variable(attr::INTERNAL_IP4_NETMASK, vec![255, 255, 255, 255]),
            Attribute::variable(attr::INTERNAL_IP4_DNS, vec![10, 1, 0, 53]),
            Attribute::variable(attr::INTERNAL_IP4_DNS, vec![10, 1, 0, 54]),
            Attribute::variable(attr::UNITY_SPLIT_INCLUDE, split),
            Attribute::variable(attr::UNITY_DEF_DOMAIN, b"corp.example.com\0".to_vec()),
            Attribute::variable(
                attr::UNITY_SPLIT_DNS_NAME,
                b"corp.example.com,example.net".to_vec(),
            ),
            Attribute::variable(attr::INTERNAL_IP4_SUBNET, vec![10, 1, 0, 0, 255, 255, 0, 0]),
            Attribute::variable(attr::INTERNAL_IP4_SUBNET, vec![10, 9, 0, 0, 255, 0, 255, 0]),
        ];
        assert!(ModeConfig::present(&attrs));
        let mc = ModeConfig::parse(&attrs);
        assert_eq!(mc.address, Some(Ipv4Addr::new(10, 212, 134, 200)));
        assert_eq!(
            mc.dns,
            vec![Ipv4Addr::new(10, 1, 0, 53), Ipv4Addr::new(10, 1, 0, 54)]
        );
        assert_eq!(
            mc.split_include,
            vec![
                (Ipv4Addr::new(10, 1, 0, 0), 16),
                (Ipv4Addr::new(192, 0, 2, 0), 24)
            ]
        );
        assert_eq!(mc.default_domain.as_deref(), Some("corp.example.com"));
        assert_eq!(mc.split_dns, vec!["corp.example.com", "example.net"]);
    }

    #[test]
    fn request_asks_for_everything_and_names_the_client() {
        let req = ModeConfig::request("Polytunnel 0.1.0");
        assert!(
            req.iter()
                .any(|a| a.kind == attr::INTERNAL_IP4_ADDRESS && a.value.is_empty())
        );
        let version = find_attr(&req, attr::APPLICATION_VERSION).unwrap();
        assert_eq!(version.value, b"Polytunnel 0.1.0");
        assert!(!ModeConfig::present(&[Attribute::basic(
            attr::XAUTH_STATUS,
            1
        )]));
    }

    #[test]
    fn xauth_prompts_list_fields_once_with_the_message() {
        let attrs = vec![
            Attribute::basic(attr::XAUTH_TYPE, 0),
            Attribute::variable(attr::XAUTH_MESSAGE, b"Enter your token code".to_vec()),
            Attribute::variable(attr::XAUTH_USER_NAME, Vec::new()),
            Attribute::variable(attr::XAUTH_PASSCODE, Vec::new()),
            Attribute::variable(attr::XAUTH_PASSCODE, Vec::new()),
        ];
        let p = XauthPrompt::from_request(&attrs);
        assert_eq!(p.message.as_deref(), Some("Enter your token code"));
        assert_eq!(p.fields, vec![XauthField::Name, XauthField::Passcode]);
        assert!(XauthField::Passcode.secret());
        assert!(!XauthField::Name.secret());
        for f in [
            XauthField::Name,
            XauthField::Password,
            XauthField::Passcode,
            XauthField::NextPin,
            XauthField::Answer,
            XauthField::Domain,
        ] {
            assert_eq!(XauthField::from_attr(f.attr()), Some(f));
        }
    }
}
