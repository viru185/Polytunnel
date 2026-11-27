//! UDP encapsulation of IKE and ESP (RFC 3948).
//!
//! On the NAT-traversal port (4500) one UDP stream carries three kinds of datagrams:
//! a single `0xFF` byte (NAT keepalive), IKE messages prefixed with four zero bytes (the
//! non-ESP marker), and ESP packets (which never start with a zero SPI).

/// Four zero bytes in front of IKE messages on the NAT-traversal port.
pub const NON_ESP_MARKER: [u8; 4] = [0; 4];

/// A NAT keepalive datagram.
pub const NAT_KEEPALIVE: [u8; 1] = [0xFF];

/// The standard NAT-traversal port.
pub const NAT_T_PORT: u16 = 4500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datagram<'a> {
    Keepalive,
    /// An IKE message (marker removed).
    Ike(&'a [u8]),
    /// An ESP packet.
    Esp(&'a [u8]),
    Invalid,
}

pub fn classify(payload: &[u8]) -> Datagram<'_> {
    match payload {
        [0xFF] => Datagram::Keepalive,
        [0, 0, 0, 0, ike @ ..] if !ike.is_empty() => Datagram::Ike(ike),
        esp if esp.len() >= 8 && esp[..4] != NON_ESP_MARKER => Datagram::Esp(esp),
        _ => Datagram::Invalid,
    }
}

/// `ike` with the non-ESP marker in front, ready to send on port 4500.
pub fn ike_datagram(ike: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ike.len() + 4);
    out.extend_from_slice(&NON_ESP_MARKER);
    out.extend_from_slice(ike);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_datagrams() {
        assert_eq!(classify(&[0xFF]), Datagram::Keepalive);
        let ike = ike_datagram(&[1, 2, 3]);
        assert_eq!(classify(&ike), Datagram::Ike(&[1, 2, 3]));
        let esp = [0, 0, 0x10, 0, 0, 0, 0, 1, 9, 9];
        assert_eq!(classify(&esp), Datagram::Esp(&esp));
        assert_eq!(classify(&[0, 0, 0, 0]), Datagram::Invalid);
        assert_eq!(classify(&[1, 2]), Datagram::Invalid);
        assert_eq!(classify(&[]), Datagram::Invalid);
    }
}
