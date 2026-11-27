//! IKE and ESP over TCP ([RFC 9329]): after the `IKETCP` prefix, every message is a 2-byte
//! length (counting itself) followed by an IKE message behind a four-byte zero marker, or by
//! an ESP packet.
//!
//! [RFC 9329]: https://www.rfc-editor.org/rfc/rfc9329

use crate::v1::wire::WireError;

/// Sent once, first, on every connection.
pub const PREFIX: &[u8; 6] = b"IKETCP";

/// The non-ESP marker in front of IKE messages.
const MARKER: [u8; 4] = [0; 4];

/// One unit on the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Ike(Vec<u8>),
    Esp(Vec<u8>),
}

fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let len: usize = 2 + parts.iter().map(|p| p.len()).sum::<usize>();
    let mut out = u16::try_from(len)
        .expect("IKE and ESP messages are below 64 KiB")
        .to_be_bytes()
        .to_vec();
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

pub fn frame_ike(message: &[u8]) -> Vec<u8> {
    framed(&[&MARKER, message])
}

pub fn frame_esp(packet: &[u8]) -> Vec<u8> {
    framed(&[packet])
}

/// Cuts the incoming byte stream into frames.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// The next whole frame, if one has arrived. Frames too short to hold anything are
    /// skipped (keepalives); a length below 2 is an error (the stream is out of step).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Frame>, WireError> {
        loop {
            if self.buf.len() < 2 {
                return Ok(None);
            }
            let len = usize::from(u16::from_be_bytes([self.buf[0], self.buf[1]]));
            if len < 2 {
                return Err(WireError("TCP frame length below 2"));
            }
            if self.buf.len() < len {
                return Ok(None);
            }
            let body: Vec<u8> = self.buf.drain(..len).skip(2).collect();
            if body.len() < 4 {
                continue; // keepalive or padding
            }
            return Ok(Some(if body[..4] == MARKER {
                Frame::Ike(body[4..].to_vec())
            } else {
                Frame::Esp(body)
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_across_arbitrary_chunks() {
        let mut stream = Vec::new();
        stream.extend(frame_ike(b"an IKE message"));
        stream.extend(frame_esp(&[0xde, 0xad, 0xbe, 0xef, 1, 2, 3]));
        stream.extend_from_slice(&[0, 3, 0xff]); // keepalive
        stream.extend(frame_ike(&[7; 300]));
        let mut d = Decoder::default();
        let mut got = Vec::new();
        for chunk in stream.chunks(5) {
            d.push(chunk);
            while let Some(f) = d.next().unwrap() {
                got.push(f);
            }
        }
        assert_eq!(
            got,
            vec![
                Frame::Ike(b"an IKE message".to_vec()),
                Frame::Esp(vec![0xde, 0xad, 0xbe, 0xef, 1, 2, 3]),
                Frame::Ike(vec![7; 300]),
            ]
        );
        assert_eq!(&frame_esp(&[9; 4])[..2], &[0, 6]);
    }

    #[test]
    fn a_broken_length_is_an_error() {
        let mut d = Decoder::default();
        d.push(&[0, 1, 9]);
        assert!(d.next().is_err());
    }
}
