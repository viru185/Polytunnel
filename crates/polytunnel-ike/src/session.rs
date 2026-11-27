//! What every IKE version hands the daemon, and the interface it drives them through.

use std::time::{Duration, Instant};

use polytunnel_esp::Keys;
use zeroize::Zeroizing;

use crate::v1::cfg::{ModeConfig, XauthPrompt};
use crate::v1::config::EspProposal;

/// What the caller must do.
#[derive(Debug)]
pub enum Output {
    /// Send an IKE message to the gateway: over UDP, to its NAT-T port (4500, after the
    /// four-byte non-ESP marker) when `natt`, else to the IKE port (500). Over TCP
    /// (RFC 9329) every IKE message goes on the stream.
    Send { natt: bool, message: Vec<u8> },
    /// The gateway wants more sign-in input; reply with [`Session::answer`].
    Prompt(XauthPrompt),
    /// Our address, DNS servers and split networks.
    Configured(ModeConfig),
    /// A pair of ESP SAs is ready (the first, or a rekeyed one): send with it from now on.
    ChildSa(ChildSa),
    /// Stop accepting packets for this inbound SPI.
    Retire { inbound_spi: u32 },
    /// The session is over. `retry`: a fresh connection may well succeed (the gateway went
    /// away or the session expired); otherwise it was refused (wrong key, password, ...).
    Closed { reason: String, retry: bool },
}

/// One ESP SA in each direction.
#[derive(Debug)]
pub struct ChildSa {
    pub inbound_spi: u32,
    pub inbound: Keys,
    pub outbound_spi: u32,
    pub outbound: Keys,
    pub proposal: EspProposal,
    pub lifetime: Duration,
}

/// An IKE session as the daemon drives it (IKEv1 or IKEv2).
pub trait Session: Send {
    /// Sends the first message.
    fn start(&mut self, now: Instant) -> Vec<Output>;
    /// Handles an IKE message from the gateway (non-ESP marker and TCP framing removed).
    fn receive(&mut self, now: Instant, message: &[u8]) -> Vec<Output>;
    /// Answers the pending prompt, one value per requested field.
    fn answer(&mut self, values: Vec<Zeroizing<String>>) -> Vec<Output>;
    /// ESP traffic arrived: the gateway is alive.
    fn note_alive(&mut self, now: Instant);
    /// Timers. Call about once a second.
    fn poll(&mut self, now: Instant) -> Vec<Output>;
    /// Ends the session at the gateway.
    fn close(&mut self) -> Vec<Output>;
    fn is_closed(&self) -> bool;
}
