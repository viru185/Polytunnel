//! What a connection negotiates: proposals, identity, lifetimes and credentials.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use polytunnel_esp::Integrity;
use zeroize::Zeroizing;

use super::wire::{Id, id_type};
use crate::dh::Group;
use crate::prf::HashAlg;

/// A phase-1 (ISAKMP SA) proposal: AES-CBC key size, hash and Diffie-Hellman group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IkeProposal {
    /// AES key length in bytes (16, 24 or 32).
    pub key_len: usize,
    pub hash: HashAlg,
    pub group: Group,
}

impl IkeProposal {
    /// Parses `aes256-sha256-modp2048` (cipher, hash, group).
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.trim().split('-');
        let key_len = aes_key_len(parts.next()?)?;
        let hash = HashAlg::from_name(parts.next()?)?;
        let group = Group::from_name(parts.next()?)?;
        parts.next().is_none().then_some(Self {
            key_len,
            hash,
            group,
        })
    }

    /// FortiGate's dial-up defaults, strongest first, all with one DH group (aggressive mode
    /// sends its key share in the first message, so every proposal must use the same group).
    pub fn defaults(group: Group) -> Vec<Self> {
        [
            (32, HashAlg::Sha256),
            (16, HashAlg::Sha256),
            (32, HashAlg::Sha1),
            (16, HashAlg::Sha1),
        ]
        .into_iter()
        .map(|(key_len, hash)| Self {
            key_len,
            hash,
            group,
        })
        .collect()
    }
}

impl fmt::Display for IkeProposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "aes{}-{}-{}",
            self.key_len * 8,
            self.hash.name(),
            self.group.name()
        )
    }
}

/// ESP encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspCipher {
    AesCbc { key_len: usize },
    AesGcm16 { key_len: usize },
}

/// A phase-2 (ESP) proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EspProposal {
    pub cipher: EspCipher,
    pub integrity: Integrity,
}

impl EspProposal {
    /// Parses `aes256-sha256`, `aes128-sha1` or `aes256gcm16`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        if let Some(bits) = s.strip_suffix("gcm16").or_else(|| s.strip_suffix("gcm")) {
            let key_len = aes_key_len(bits)?;
            return (key_len != 24).then_some(Self {
                cipher: EspCipher::AesGcm16 { key_len },
                integrity: Integrity::None,
            });
        }
        let (cipher, integrity) = s.split_once('-')?;
        let integrity = match integrity {
            "sha1" => Integrity::HmacSha1_96,
            "sha256" => Integrity::HmacSha256_128,
            "sha384" => Integrity::HmacSha384_192,
            "sha512" => Integrity::HmacSha512_256,
            _ => return None,
        };
        Some(Self {
            cipher: EspCipher::AesCbc {
                key_len: aes_key_len(cipher)?,
            },
            integrity,
        })
    }

    /// FortiGate's dial-up defaults, strongest first.
    pub fn defaults() -> Vec<Self> {
        [
            "aes256-sha256",
            "aes128-sha256",
            "aes256-sha1",
            "aes128-sha1",
            "aes256gcm16",
            "aes128gcm16",
        ]
        .into_iter()
        .map(|s| Self::parse(s).expect("valid default"))
        .collect()
    }

    pub fn key_len(&self) -> usize {
        match self.cipher {
            EspCipher::AesCbc { key_len } | EspCipher::AesGcm16 { key_len } => key_len,
        }
    }

    /// Bytes of keying material per direction: cipher key (plus GCM salt) then integrity key.
    pub fn keymat_len(&self) -> usize {
        match self.cipher {
            EspCipher::AesCbc { key_len } => key_len + self.integrity.key_len(),
            EspCipher::AesGcm16 { key_len } => key_len + 4,
        }
    }
}

impl fmt::Display for EspProposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.cipher {
            EspCipher::AesGcm16 { key_len } => write!(f, "aes{}gcm16", key_len * 8),
            EspCipher::AesCbc { key_len } => {
                let integrity = match self.integrity {
                    Integrity::HmacSha1_96 => "sha1",
                    Integrity::HmacSha256_128 => "sha256",
                    Integrity::HmacSha384_192 => "sha384",
                    Integrity::HmacSha512_256 => "sha512",
                    Integrity::None => "none",
                };
                write!(f, "aes{}-{integrity}", key_len * 8)
            }
        }
    }
}

fn aes_key_len(name: &str) -> Option<usize> {
    match name.to_ascii_lowercase().as_str() {
        "aes" | "aes128" => Some(16),
        "aes192" => Some(24),
        "aes256" => Some(32),
        _ => None,
    }
}

/// Our identity in phase 1 (FortiClient's "local ID", FortiGate's "peer ID").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    Ipv4(Ipv4Addr),
    Fqdn(String),
    UserFqdn(String),
    KeyId(Vec<u8>),
}

impl Identity {
    /// The ID payload body (protocol and port zero, as phase 1 allows).
    pub fn to_id(&self) -> Id {
        let (kind, data) = match self {
            Identity::Ipv4(a) => (id_type::IPV4_ADDR, a.octets().to_vec()),
            Identity::Fqdn(s) => (id_type::FQDN, s.as_bytes().to_vec()),
            Identity::UserFqdn(s) => (id_type::USER_FQDN, s.as_bytes().to_vec()),
            Identity::KeyId(k) => (id_type::KEY_ID, k.clone()),
        };
        Id {
            kind,
            protocol: 0,
            port: 0,
            data,
        }
    }
}

/// How the address and DNS settings are obtained after XAuth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModeConfigMode {
    /// We ask (REQUEST/REPLY). A gateway that pushes anyway is handled too.
    #[default]
    Pull,
    /// We wait for the gateway's SET, and ask after a few seconds without one.
    Push,
}

/// XAuth username and password (the first round's answers).
#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: Zeroizing<String>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"***")
            .finish()
    }
}

/// One connection's settings.
#[derive(Clone)]
pub struct Config {
    pub psk: Zeroizing<Vec<u8>>,
    /// `None`: our IPv4 address.
    pub local_id: Option<Identity>,
    pub ike: Vec<IkeProposal>,
    pub ike_lifetime: Duration,
    pub esp: Vec<EspProposal>,
    /// PFS group for quick mode; `None` disables PFS.
    pub pfs: Option<Group>,
    pub esp_lifetime: Duration,
    /// Also limit each ESP SA by traffic (kilobytes), if the profile asks.
    pub esp_lifetime_kb: Option<u32>,
    /// `None`: plain pre-shared key authentication, no XAuth.
    pub xauth: Option<Credentials>,
    pub mode_config: ModeConfigMode,
    /// The remote side of the quick-mode selectors (`0.0.0.0/0`: everything).
    pub remote_network: (Ipv4Addr, u8),
    /// Dead-peer detection interval; `None` turns it off.
    pub dpd: Option<Duration>,
    /// Our UDP address (as bound) and the gateway's IKE address (port 500).
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// Sent as APPLICATION_VERSION in mode-config requests.
    pub client_version: String,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("local_id", &self.local_id)
            .field("ike", &self.ike)
            .field("esp", &self.esp)
            .field("pfs", &self.pfs)
            .field("xauth", &self.xauth)
            .field("remote", &self.remote)
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        let Some(first) = self.ike.first() else {
            return Err("no IKE proposals".into());
        };
        if self.ike.iter().any(|p| p.group != first.group) {
            return Err(
                "aggressive mode needs one Diffie-Hellman group for every IKE proposal".into(),
            );
        }
        if self.ike.len() > 32 || self.esp.len() > 32 {
            return Err("too many proposals".into());
        }
        if self.esp.is_empty() {
            return Err("no ESP proposals".into());
        }
        if self.psk.is_empty() {
            return Err("the pre-shared key is empty".into());
        }
        if self.ike_lifetime < Duration::from_secs(120)
            || self.esp_lifetime < Duration::from_secs(60)
        {
            return Err("lifetimes are too short".into());
        }
        if self.remote_network.1 > 32 {
            return Err("the remote network's prefix length is over 32".into());
        }
        if !self.remote.is_ipv4() {
            return Err("IKEv1 gateways are reached over IPv4".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ike_proposals_parse_and_print() {
        let p = IkeProposal::parse("aes256-sha256-modp2048").unwrap();
        assert_eq!(p.key_len, 32);
        assert_eq!(p.hash, HashAlg::Sha256);
        assert_eq!(p.group, Group::Modp2048);
        assert_eq!(p.to_string(), "aes256-sha256-modp2048");
        assert_eq!(
            IkeProposal::parse("AES128-SHA1-MODP1536")
                .unwrap()
                .to_string(),
            "aes128-sha1-modp1536"
        );
        for bad in [
            "3des-sha1-modp1024",
            "aes256-sha256",
            "aes256-sha256-modp2048-x",
            "",
        ] {
            assert_eq!(IkeProposal::parse(bad), None, "{bad}");
        }
        assert!(
            IkeProposal::defaults(Group::Modp1536)
                .iter()
                .all(|p| p.group == Group::Modp1536)
        );
    }

    #[test]
    fn esp_proposals_parse_and_print() {
        for s in [
            "aes256-sha256",
            "aes128-sha1",
            "aes192-sha512",
            "aes256gcm16",
        ] {
            assert_eq!(EspProposal::parse(s).unwrap().to_string(), s);
        }
        assert_eq!(
            EspProposal::parse("aes128gcm").unwrap().to_string(),
            "aes128gcm16"
        );
        assert_eq!(EspProposal::parse("aes256-md5"), None);
        assert_eq!(EspProposal::parse("aes192gcm16"), None);
        let p = EspProposal::parse("aes256-sha256").unwrap();
        assert_eq!(p.keymat_len(), 64);
        assert_eq!(EspProposal::parse("aes128gcm16").unwrap().keymat_len(), 20);
        assert_eq!(EspProposal::defaults().len(), 6);
    }

    #[test]
    fn identities_encode() {
        let id = Identity::Fqdn("laptop".into()).to_id();
        assert_eq!(id.encode(), [&[2u8, 0, 0, 0][..], b"laptop"].concat());
        let id = Identity::Ipv4(Ipv4Addr::new(192, 0, 2, 7)).to_id();
        assert_eq!(id.encode(), vec![1, 0, 0, 0, 192, 0, 2, 7]);
    }
}
