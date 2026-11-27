//! What an IKEv2 connection negotiates.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use zeroize::Zeroizing;

use super::auth::Trust;
use super::crypto::IkeSuite;
use crate::dh::Group;
use crate::eap::EapMethod;
use crate::v1::config::{EspProposal, Identity};

/// How we prove who we are.
#[derive(Clone)]
pub enum ClientAuth {
    Psk(Zeroizing<Vec<u8>>),
    Eap {
        method: EapMethod,
        username: String,
        password: Zeroizing<String>,
    },
}

/// How the gateway must prove who it is.
#[derive(Clone, Debug)]
pub enum ServerAuth {
    Psk(Zeroizing<Vec<u8>>),
    Certificate(Trust),
}

#[derive(Clone)]
pub struct Config {
    /// IKE SA proposals; the first one's group goes in the first key exchange.
    pub ike: Vec<IkeSuite>,
    pub esp: Vec<EspProposal>,
    /// DH group for child SA rekeys; `None` disables PFS.
    pub pfs: Option<Group>,
    pub ike_lifetime: Duration,
    pub esp_lifetime: Duration,
    /// `None`: our IPv4 address.
    pub local_id: Option<Identity>,
    pub client_auth: ClientAuth,
    pub server_auth: ServerAuth,
    /// The remote side of the traffic selectors.
    pub remote_network: (Ipv4Addr, u8),
    pub dpd: Option<Duration>,
    pub local: SocketAddr,
    /// The gateway's IKE address (UDP 500; for TCP, the TCP port).
    pub remote: SocketAddr,
    /// IKE runs over TCP (RFC 9329): nothing is retransmitted.
    pub reliable: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("ike", &self.ike)
            .field("esp", &self.esp)
            .field("pfs", &self.pfs)
            .field("local_id", &self.local_id)
            .field("server_auth", &self.server_auth)
            .field("remote", &self.remote)
            .field("reliable", &self.reliable)
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.ike.is_empty() || self.esp.is_empty() {
            return Err("no IKE or ESP proposals".into());
        }
        if self.ike.len() > 16 || self.esp.len() > 16 {
            return Err("too many proposals".into());
        }
        if let ClientAuth::Psk(k) = &self.client_auth
            && k.is_empty()
        {
            return Err("the pre-shared key is empty".into());
        }
        if self.ike_lifetime < Duration::from_secs(120)
            || self.esp_lifetime < Duration::from_secs(60)
        {
            return Err("lifetimes are too short".into());
        }
        if self.remote_network.1 > 32 || !self.remote.is_ipv4() {
            return Err("IKEv2 connections are made over IPv4".into());
        }
        Ok(())
    }
}
