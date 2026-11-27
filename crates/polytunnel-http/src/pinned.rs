//! TLS for servers whose certificate the operating system does not trust (a FortiGate's
//! factory certificate, for one): the profile names the certificate's SHA-256, and exactly
//! that certificate is accepted. The check runs on the same connection right after the
//! handshake, before anything is sent.
//!
//! The ureq connector below uses ureq's `unversioned` transport API (pinned in Cargo.lock);
//! it mirrors ureq's own native-tls connector with the pin check added.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use native_tls::{HandshakeError, TlsConnector, TlsStream};
use polytunnel_core::pin::CertFingerprint;
use sha2::{Digest, Sha256};
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout, Transport,
    TransportAdapter,
};

/// The SHA-256 fingerprint of a certificate (DER).
pub fn fingerprint(der: &[u8]) -> CertFingerprint {
    CertFingerprint::from_digest(Sha256::digest(der).into())
}

/// A TLS connector: the system's checks, or, with a pin, only the pin (which
/// [`check_pin`] must then verify right after the handshake).
pub fn tls_connector(pin: Option<&CertFingerprint>) -> Result<TlsConnector, String> {
    let mut builder = TlsConnector::builder();
    if pin.is_some() {
        builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }
    builder.build().map_err(|e| e.to_string())
}

/// Accepts the connection only if the server's certificate is the pinned one.
pub fn check_pin<S: Read + Write>(
    stream: &TlsStream<S>,
    pin: &CertFingerprint,
) -> Result<(), String> {
    let cert = stream
        .peer_certificate()
        .map_err(|e| format!("cannot read the server's certificate: {e}"))?
        .ok_or("the server sent no certificate")?;
    let der = cert
        .to_der()
        .map_err(|e| format!("cannot read the server's certificate: {e}"))?;
    let actual = fingerprint(&der);
    if actual == *pin {
        Ok(())
    } else {
        Err(format!(
            "the server's certificate ({}) is not the trusted one ({}); \
             if the server's certificate was replaced, update the profile's server certificate",
            actual.colon_hex(),
            pin.colon_hex()
        ))
    }
}

/// When the system rejects `host:port`'s certificate but a TLS connection is otherwise
/// possible, the certificate's fingerprint (for the user to compare and trust). `None` when
/// the system trusts it, or no TLS connection can be made at all.
pub fn untrusted_certificate(host: &str, port: u16) -> Option<CertFingerprint> {
    let handshake = |connector: TlsConnector| -> Option<TlsStream<TcpStream>> {
        let addr = (host, port).to_socket_addrs().ok()?.next()?;
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).ok()?;
        tcp.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
        tcp.set_write_timeout(Some(Duration::from_secs(10))).ok()?;
        connector.connect(host, tcp).ok()
    };
    if handshake(tls_connector(None).ok()?).is_some() {
        return None;
    }
    let mut accept_any = TlsConnector::builder();
    accept_any
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true);
    let stream = handshake(accept_any.build().ok()?)?;
    let der = stream.peer_certificate().ok()??.to_der().ok()?;
    Some(fingerprint(&der))
}

fn io_error(message: impl Into<String>) -> ureq::Error {
    ureq::Error::Io(io::Error::other(message.into()))
}

/// The pinned TLS step of a ureq connector chain (after TCP).
#[derive(Debug)]
pub(crate) struct PinnedTls {
    pub pin: CertFingerprint,
}

impl<In: Transport> Connector<In> for PinnedTls {
    type Out = Either<In, PinnedTlsTransport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(transport) = chained else {
            return Ok(None);
        };
        if !details.needs_tls() || transport.is_tls() {
            return Ok(Some(Either::A(transport)));
        }
        let host = details
            .uri
            .host()
            .unwrap_or_default()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let connector = tls_connector(Some(&self.pin)).map_err(io_error)?;
        let mut adapter = TransportAdapter::new(transport.boxed(), details.current_time.clone());
        adapter.set_timeout(details.timeout);
        let stream = connector.connect(&host, adapter).map_err(|e| match e {
            HandshakeError::Failure(e) => io_error(format!("TLS: {e}")),
            HandshakeError::WouldBlock(_) => io_error("the TLS handshake was interrupted"),
        })?;
        check_pin(&stream, &self.pin).map_err(io_error)?;
        let buffers = LazyBuffers::new(
            details.config.input_buffer_size(),
            details.config.output_buffer_size(),
        );
        Ok(Some(Either::B(PinnedTlsTransport { buffers, stream })))
    }
}

pub(crate) struct PinnedTlsTransport {
    buffers: LazyBuffers,
    stream: TlsStream<TransportAdapter>,
}

impl fmt::Debug for PinnedTlsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinnedTlsTransport")
    }
}

impl Transport for PinnedTlsTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input)?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.get_mut().get_mut().is_open()
    }

    fn is_tls(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    use polytunnel_core::http::{Request, Transport as _};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;
    use crate::UreqTransport;

    /// A local HTTPS server with a self-signed certificate (like a FortiGate's factory one)
    /// that answers every request with "hello". Returns its port and certificate fingerprint.
    /// The server side is rustls; the client under test is the system's TLS stack.
    fn self_signed_server() -> (u16, CertFingerprint) {
        let cert = rcgen::generate_simple_self_signed(vec!["fortigate.test".into()]).unwrap();
        let der = cert.cert.der().to_vec();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![CertificateDer::from(der.clone())], key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let config = config.clone();
                thread::spawn(move || {
                    let conn = rustls::ServerConnection::new(config).unwrap();
                    let mut tls = rustls::StreamOwned::new(conn, tcp);
                    let mut request = Vec::new();
                    let mut byte = [0u8; 1];
                    while !request.ends_with(b"\r\n\r\n") {
                        match tls.read(&mut byte) {
                            Ok(1) => request.push(byte[0]),
                            _ => return,
                        }
                    }
                    let _ = tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                    );
                    let _ = tls.flush();
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
        (port, fingerprint(&der))
    }

    fn get(transport: &UreqTransport, port: u16) -> Result<String, String> {
        transport
            .send(&Request::get(format!(
                "https://127.0.0.1:{port}/remote/login"
            )))
            .map(|r| r.body)
            .map_err(|e| e.0)
    }

    #[test]
    fn the_pinned_certificate_and_only_it_is_accepted() {
        let (port, pin) = self_signed_server();
        let pinned = UreqTransport::with_server_cert(Some(pin));
        assert_eq!(get(&pinned, port).unwrap(), "hello");
        // A second request on the same transport works too.
        assert_eq!(get(&pinned, port).unwrap(), "hello");

        let other = fingerprint(b"some other certificate");
        let err = get(&UreqTransport::with_server_cert(Some(other)), port).unwrap_err();
        assert!(err.contains("is not the trusted one"), "{err}");

        let system = get(&UreqTransport::new(), port).unwrap_err();
        assert!(
            !system.is_empty(),
            "the system must not trust a self-signed certificate"
        );
    }

    #[test]
    fn untrusted_certificates_are_identified_for_the_user() {
        let (port, pin) = self_signed_server();
        assert_eq!(untrusted_certificate("127.0.0.1", port), Some(pin));
        // Nothing listening: no TLS at all, so nothing to trust.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        assert_eq!(untrusted_certificate("127.0.0.1", closed_port), None);
    }
}
