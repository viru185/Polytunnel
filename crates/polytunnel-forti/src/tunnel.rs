//! The FortiGate SSL VPN tunnel: its configuration and the framing of PPP over TLS.
//!
//! 1. `GET /remote/fortisslvpn_xml` (with the `SVPNCOOKIE`) returns the assigned address,
//!    DNS servers, DNS suffixes and split-tunnel networks.
//! 2. `GET /remote/sslvpn-tunnel` on a fresh TLS connection turns it into a PPP link. Every
//!    PPP packet is framed with a 6-byte header: total length, `0x5050`, PPP length.
//! 3. `GET /remote/logout` ends the session.
//!
//! Field names and framing follow observed protocol behaviour (see
//! `docs/protocols/fortinet-ssl.md`).

use std::net::{IpAddr, Ipv4Addr};

use polytunnel_core::Secret;
use polytunnel_core::http::{Request, Response};
use polytunnel_core::xml::Element;

use crate::login::{COOKIE_NAME, FortiError};

fn cookie_header(cookie: &Secret) -> String {
    format!("{COOKIE_NAME}={}", cookie.expose())
}

pub fn config_request(base: &str, cookie: &Secret) -> Request {
    Request::get(format!("{base}/remote/fortisslvpn_xml")).header("Cookie", &cookie_header(cookie))
}

pub fn logout_request(base: &str, cookie: &Secret) -> Request {
    Request::get(format!("{base}/remote/logout")).header("Cookie", &cookie_header(cookie))
}

/// The bytes that turn a fresh TLS connection into the PPP tunnel.
pub fn tunnel_request(host: &str, cookie: &Secret) -> Vec<u8> {
    format!(
        "GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: {host}\r\nCookie: {}\r\n\r\n",
        cookie_header(cookie)
    )
    .into_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TunnelSettings {
    pub address: Option<Ipv4Addr>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_suffixes: Vec<String>,
    /// `(network, netmask)` pairs to route into the tunnel; empty = everything.
    pub routes: Vec<(Ipv4Addr, Ipv4Addr)>,
    pub exclude_routes: Vec<(Ipv4Addr, Ipv4Addr)>,
    pub idle_timeout_secs: Option<u32>,
}

pub fn parse_config(response: &Response) -> Result<TunnelSettings, FortiError> {
    if matches!(response.status, 401 | 403) || response.status == 302 {
        return Err(FortiError::AuthFailed(
            "the session cookie was not accepted".into(),
        ));
    }
    if !response.is_success() {
        return Err(FortiError::Status(response.status));
    }
    let root = Element::parse(&response.body)
        .map_err(|e| FortiError::BadResponse(format!("tunnel configuration is not XML: {e}")))?;
    if root.name != "sslvpn-tunnel" {
        return Err(FortiError::BadResponse(format!(
            "expected <sslvpn-tunnel>, got <{}>",
            root.name
        )));
    }
    let mut settings = TunnelSettings::default();
    let Some(ipv4) = root.child("ipv4") else {
        return Ok(settings);
    };
    settings.address = ipv4
        .child("assigned-addr")
        .and_then(|a| a.attr("ipv4"))
        .and_then(|a| a.parse().ok());
    for dns in ipv4.children_named("dns") {
        if let Some(ip) = dns.attr("ip").and_then(|ip| ip.parse().ok()) {
            settings.dns_servers.push(ip);
        }
    }
    for suffix in ipv4.children_named("dns-suffix") {
        let text = suffix.text.trim();
        settings.dns_suffixes.extend(
            text.split([';', ',', ' '])
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        );
    }
    for split in ipv4.children_named("split-dns") {
        if let Some(domains) = split.attr("domains") {
            settings.dns_suffixes.extend(
                domains
                    .split([';', ',', ' '])
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            );
        }
    }
    for info in ipv4.children_named("split-tunnel-info") {
        let exclude = info.attr("negate") == Some("1");
        for addr in info.children_named("addr") {
            let parsed = addr
                .attr("ip")
                .and_then(|ip| ip.parse().ok())
                .zip(addr.attr("mask").and_then(|m| m.parse().ok()));
            if let Some(pair) = parsed {
                if exclude {
                    settings.exclude_routes.push(pair);
                } else {
                    settings.routes.push(pair);
                }
            }
        }
    }
    settings.idle_timeout_secs = root
        .child("idle-timeout")
        .and_then(|t| t.attr("val"))
        .and_then(|v| v.parse().ok());
    Ok(settings)
}

pub mod frame {
    //! The 6-byte header in front of every PPP packet.

    use crate::login::FortiError;

    pub const HEADER_LEN: usize = 6;
    pub const MAGIC: [u8; 2] = [0x50, 0x50];
    /// Largest PPP packet accepted.
    pub const MAX_PPP: usize = 16 * 1024;

    pub fn encode(ppp: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + ppp.len());
        out.extend_from_slice(&((HEADER_LEN + ppp.len()) as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&(ppp.len() as u16).to_be_bytes());
        out.extend_from_slice(ppp);
        out
    }

    /// Reassembles PPP packets from the TLS byte stream.
    #[derive(Debug, Default)]
    pub struct Decoder {
        buf: Vec<u8>,
    }

    impl Decoder {
        pub fn feed(&mut self, bytes: &[u8]) {
            self.buf.extend_from_slice(bytes);
        }

        pub fn next_packet(&mut self) -> Result<Option<Vec<u8>>, FortiError> {
            if self.buf.len() < HEADER_LEN {
                return Ok(None);
            }
            let total = usize::from(u16::from_be_bytes([self.buf[0], self.buf[1]]));
            let len = usize::from(u16::from_be_bytes([self.buf[4], self.buf[5]]));
            if self.buf[2..4] != MAGIC || total != len + HEADER_LEN {
                return Err(FortiError::BadResponse("bad tunnel frame header".into()));
            }
            if len > MAX_PPP {
                return Err(FortiError::BadResponse("tunnel frame too large".into()));
            }
            if self.buf.len() < total {
                return Ok(None);
            }
            let packet = self.buf[HEADER_LEN..total].to_vec();
            self.buf.drain(..total);
            Ok(Some(packet))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::frame::{Decoder, encode};
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<sslvpn-tunnel ver="2" dtls="1" patch="1">
  <tunnel-method value="ppp"/>
  <ipv4>
    <dns ip="10.0.0.53"/>
    <dns ip="10.0.0.54"/>
    <dns-suffix>corp.example.com;lab.example.com</dns-suffix>
    <assigned-addr ipv4="10.212.134.200"/>
    <split-tunnel-info>
      <addr ip="10.0.0.0" mask="255.0.0.0"/>
      <addr ip="192.0.2.0" mask="255.255.255.0"/>
    </split-tunnel-info>
    <split-tunnel-info negate="1">
      <addr ip="10.99.0.0" mask="255.255.0.0"/>
    </split-tunnel-info>
  </ipv4>
  <idle-timeout val="3600"/>
</sslvpn-tunnel>"#;

    #[test]
    fn parses_the_tunnel_configuration() {
        let s = parse_config(&Response::new(200, XML)).unwrap();
        assert_eq!(s.address, Some(Ipv4Addr::new(10, 212, 134, 200)));
        assert_eq!(s.dns_servers.len(), 2);
        assert_eq!(s.dns_suffixes, ["corp.example.com", "lab.example.com"]);
        assert_eq!(
            s.routes,
            [
                (Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 0, 0, 0)),
                (Ipv4Addr::new(192, 0, 2, 0), Ipv4Addr::new(255, 255, 255, 0))
            ]
        );
        assert_eq!(
            s.exclude_routes,
            [(Ipv4Addr::new(10, 99, 0, 0), Ipv4Addr::new(255, 255, 0, 0))]
        );
        assert_eq!(s.idle_timeout_secs, Some(3600));
    }

    #[test]
    fn rejected_cookies_and_junk() {
        assert!(matches!(
            parse_config(&Response::new(302, "")),
            Err(FortiError::AuthFailed(_))
        ));
        assert!(matches!(
            parse_config(&Response::new(200, "<html/>")),
            Err(FortiError::BadResponse(_))
        ));
    }

    #[test]
    fn requests_carry_the_cookie() {
        let cookie = Secret::new("FAKE+cookie==");
        let req = config_request("https://vpn.example.net:10443", &cookie);
        assert_eq!(
            req.url,
            "https://vpn.example.net:10443/remote/fortisslvpn_xml"
        );
        assert!(
            req.headers
                .contains(&("Cookie".into(), "SVPNCOOKIE=FAKE+cookie==".into()))
        );
        let tunnel = String::from_utf8(tunnel_request("vpn.example.net:10443", &cookie)).unwrap();
        assert_eq!(
            tunnel,
            "GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: vpn.example.net:10443\r\n\
             Cookie: SVPNCOOKIE=FAKE+cookie==\r\n\r\n"
        );
    }

    #[test]
    fn frames_round_trip_across_splits() {
        let a = vec![0xc0, 0x21, 1, 1, 0, 4];
        let b = vec![0x00, 0x21, 0x45, 0, 0, 20];
        let mut stream = encode(&a);
        stream.extend(encode(&b));
        assert_eq!(&stream[..6], &[0, 12, 0x50, 0x50, 0, 6]);
        for split in 1..stream.len() {
            let mut d = Decoder::default();
            let mut got = Vec::new();
            for chunk in stream.chunks(split) {
                d.feed(chunk);
                while let Some(p) = d.next_packet().unwrap() {
                    got.push(p);
                }
            }
            assert_eq!(got, [a.clone(), b.clone()]);
        }
        let mut bad = Decoder::default();
        bad.feed(&[0, 12, 0x51, 0x50, 0, 6]);
        assert!(bad.next_packet().is_err());
    }
}
