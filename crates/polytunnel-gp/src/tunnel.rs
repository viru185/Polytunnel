//! The GlobalProtect tunnel: configuration, the TLS tunnel's framing, and logout.
//!
//! 1. `POST /ssl-vpn/getconfig.esp` returns the tunnel's addresses, routes, DNS and, for the
//!    faster ESP-over-UDP mode, the IPsec keys.
//! 2. ESP mode: IP packets in ESP (RFC 4303) over UDP to the gateway (usually port 4501).
//! 3. TLS mode (fallback): `GET <ssl-tunnel-url>?user=..&authcookie=..` on a TLS connection;
//!    the gateway answers `START_TUNNEL`, then both sides exchange framed IP packets:
//!    a 16-byte header (magic `1a2b3c4d`, ethertype, payload length, then `01` and seven
//!    zero bytes) followed by the packet. An all-zero header after the magic is a keepalive.
//!
//! Frame layout and field names follow observed protocol behaviour (see
//! `docs/protocols/globalprotect.md`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use polytunnel_core::Secret;
use polytunnel_core::http::{Request, Response};
use polytunnel_core::xml::Element;

use crate::client::{self, ClientInfo};
use crate::error::GpError;
use crate::login::GatewaySession;
use crate::portal::host_of;

/// The session's fields, once each, in the order the gateway login returned them (as
/// openconnect documents): authcookie, portal, user, domain, preferred addresses, computer.
fn session_fields(session: &GatewaySession) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        ("authcookie", session.authcookie.expose().to_string()),
        ("portal", session.portal.clone()),
        ("user", session.user.clone()),
        ("domain", session.domain.clone()),
    ];
    if let Some(ip) = &session.preferred_ip {
        fields.push(("preferred-ip", ip.clone()));
    }
    if let Some(ip) = &session.preferred_ipv6 {
        fields.push(("preferred-ipv6", ip.clone()));
    }
    fields.push(("computer", session.computer.clone()));
    fields
}

/// The tunnel configuration request: the fields official clients send, in their order, then
/// the session. The ESP algorithms are the ones Polytunnel implements (no MD5).
pub fn getconfig_request(client: &ClientInfo, session: &GatewaySession) -> Request {
    let mut fields = vec![
        ("client-type", "1".to_string()),
        ("protocol-version", "p1".to_string()),
        ("internal", "no".to_string()),
    ];
    if let Some(version) = &client.app_version {
        fields.push(("app-version", version.clone()));
    }
    fields.extend([
        ("ipv6-support", "yes".to_string()),
        ("clientos", client.os.gp_name().to_string()),
        ("os-version", client.os_version.clone()),
        ("hmac-algo", "sha256,sha1".to_string()),
        ("enc-algo", "aes-256-cbc,aes-128-cbc".to_string()),
    ]);
    fields.extend(session_fields(session));
    client::post(
        format!("{}/ssl-vpn/getconfig.esp", session.gateway),
        &fields,
    )
}

pub fn logout_request(client: &ClientInfo, session: &GatewaySession) -> Request {
    // `computer` comes with the session.
    let mut fields: Vec<_> = client
        .base_fields()
        .into_iter()
        .filter(|(name, _)| *name != "computer")
        .collect();
    fields.extend(session_fields(session));
    client::post(format!("{}/ssl-vpn/logout.esp", session.gateway), &fields)
}

/// ESP algorithms as named by the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspCipher {
    Aes128Cbc,
    Aes256Cbc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspHmac {
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspSettings {
    pub udp_port: u16,
    pub cipher: EspCipher,
    pub hmac: EspHmac,
    /// Client to server.
    pub c2s_spi: u32,
    pub s2c_spi: u32,
    pub c2s_enc_key: Secret,
    pub c2s_auth_key: Secret,
    pub s2c_enc_key: Secret,
    pub s2c_auth_key: Secret,
}

impl EspSettings {
    /// Raw key bytes (the gateway sends hex).
    pub fn key_bytes(key: &Secret) -> Vec<u8> {
        hex_decode(key.expose()).unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TunnelSettings {
    pub address_v4: Option<(Ipv4Addr, Ipv4Addr)>,
    pub address_v6: Option<(Ipv6Addr, u8)>,
    pub mtu: Option<u16>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_suffixes: Vec<String>,
    /// Networks to route into the tunnel (`a.b.c.d/len`); empty = everything.
    pub routes: Vec<String>,
    pub exclude_routes: Vec<String>,
    /// The gateway's address for ESP.
    pub gateway_address: Option<IpAddr>,
    /// Path for the TLS tunnel request.
    pub tunnel_path: String,
    /// Seconds of inactivity after which the gateway drops the session.
    pub timeout_secs: Option<u32>,
    /// `None` when the gateway offers no (usable) ESP.
    pub esp: Option<EspSettings>,
}

fn members(root: &Element, path: &str) -> Vec<String> {
    root.path(path)
        .map(|list| {
            list.children_named("member")
                .map(|m| m.text.trim().to_string())
                .filter(|m| !m.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim().trim_start_matches("0x");
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn parse_u32(text: &str) -> Option<u32> {
    let text = text.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// A key element: `<bits>` and hex `<val>`, checked against each other.
fn key(ipsec: &Element, name: &str) -> Option<Secret> {
    let el = ipsec.child(name)?;
    let bits: usize = el.text_at("bits")?.parse().ok()?;
    let val = el.text_at("val")?;
    let bytes = hex_decode(val)?;
    (bytes.len() * 8 == bits).then(|| Secret::new(val.trim().trim_start_matches("0x").to_string()))
}

fn parse_esp(root: &Element) -> Option<EspSettings> {
    let ipsec = root.child("ipsec")?;
    if ipsec
        .text_at("ipsec-mode")
        .is_some_and(|m| m != "esp-tunnel")
    {
        return None;
    }
    let cipher = match ipsec.text_at("enc-algo")? {
        "aes-128-cbc" | "aes128" => EspCipher::Aes128Cbc,
        "aes-256-cbc" | "aes256" => EspCipher::Aes256Cbc,
        _ => return None,
    };
    let hmac = match ipsec.text_at("hmac-algo")? {
        "sha1" => EspHmac::Sha1,
        "sha256" => EspHmac::Sha256,
        _ => return None,
    };
    Some(EspSettings {
        udp_port: ipsec
            .text_at("udp-port")
            .and_then(|p| p.parse().ok())
            .unwrap_or(4501),
        cipher,
        hmac,
        c2s_spi: parse_u32(ipsec.text_at("c2s-spi")?)?,
        s2c_spi: parse_u32(ipsec.text_at("s2c-spi")?)?,
        c2s_enc_key: key(ipsec, "ekey-c2s")?,
        c2s_auth_key: key(ipsec, "akey-c2s")?,
        s2c_enc_key: key(ipsec, "ekey-s2c")?,
        s2c_auth_key: key(ipsec, "akey-s2c")?,
    })
}

pub fn parse_getconfig(response: &Response) -> Result<TunnelSettings, GpError> {
    const STEP: &str = "tunnel configuration";
    match response.status {
        200 => {}
        512 | 401 | 403 => return Err(GpError::AuthFailed("the gateway session expired".into())),
        status => return Err(GpError::Status { step: STEP, status }),
    }
    let root =
        Element::parse(&response.body).map_err(|e| GpError::not_xml(STEP, &response.body, e))?;
    if root.attr("status").is_some_and(|s| s != "success") {
        let msg = root
            .text_at("error")
            .unwrap_or("the gateway refused the tunnel");
        return Err(GpError::Server(msg.to_string()));
    }
    let address_v4 = match (root.text_at("ip-address"), root.text_at("netmask")) {
        (Some(ip), mask) => Some((
            ip.parse().map_err(|_| GpError::BadResponse {
                step: STEP,
                detail: "bad ip-address".into(),
            })?,
            mask.and_then(|m| m.parse().ok())
                .unwrap_or(Ipv4Addr::BROADCAST),
        )),
        (None, _) => None,
    };
    let address_v6 = root.text_at("ip-address-v6").and_then(|ip| {
        let (addr, len) = ip.split_once('/').unwrap_or((ip, "128"));
        Some((addr.parse().ok()?, len.parse().ok()?))
    });
    if address_v4.is_none() && address_v6.is_none() {
        return Err(GpError::BadResponse {
            step: STEP,
            detail: "no tunnel address".into(),
        });
    }
    let mut routes = members(&root, "access-routes");
    routes.extend(members(&root, "access-routes-v6"));
    let mut exclude_routes = members(&root, "exclude-access-routes");
    exclude_routes.extend(members(&root, "exclude-access-routes-v6"));
    let mut dns_servers: Vec<IpAddr> = members(&root, "dns")
        .iter()
        .filter_map(|d| d.parse().ok())
        .collect();
    dns_servers.extend(
        members(&root, "dns-v6")
            .iter()
            .filter_map(|d| d.parse::<IpAddr>().ok()),
    );
    Ok(TunnelSettings {
        address_v4,
        address_v6,
        mtu: root
            .text_at("mtu")
            .and_then(|m| m.parse().ok())
            .filter(|m| *m >= 576),
        dns_servers,
        dns_suffixes: members(&root, "dns-suffix"),
        routes,
        exclude_routes,
        gateway_address: root.text_at("gw-address").and_then(|a| a.parse().ok()),
        tunnel_path: root
            .text_at("ssl-tunnel-url")
            .filter(|p| p.starts_with('/') && !p.contains(['\r', '\n', ' ']))
            .unwrap_or("/ssl-tunnel-connect.sslvpn")
            .to_string(),
        timeout_secs: root.text_at("timeout").and_then(|t| t.parse().ok()),
        esp: parse_esp(&root),
    })
}

/// The bytes that start the TLS tunnel on a fresh TLS connection to the gateway.
pub fn tunnel_request(session: &GatewaySession, path: &str) -> Vec<u8> {
    let mut query = form_urlencoded::Serializer::new(String::new());
    query.append_pair("user", &session.user);
    query.append_pair("authcookie", session.authcookie.expose());
    format!(
        "GET {path}?{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n\r\n",
        query.finish(),
        host_of(&session.gateway),
        client::USER_AGENT
    )
    .into_bytes()
}

/// What the gateway sends when the TLS tunnel is up.
pub const START_TUNNEL: &[u8] = b"START_TUNNEL";

pub mod frame {
    //! TLS-tunnel framing.

    use crate::error::GpError;

    pub const MAGIC: [u8; 4] = [0x1a, 0x2b, 0x3c, 0x4d];
    pub const HEADER_LEN: usize = 16;
    /// Largest packet accepted from the gateway.
    pub const MAX_PACKET: usize = 16 * 1024;

    const DATA_TAIL: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Frame {
        Packet(Vec<u8>),
        Keepalive,
    }

    /// Frames an IP packet (the ethertype comes from its version nibble).
    pub fn encode_packet(packet: &[u8]) -> Vec<u8> {
        let ethertype: u16 = if packet.first().map(|b| b >> 4) == Some(6) {
            0x86dd
        } else {
            0x0800
        };
        let mut out = Vec::with_capacity(HEADER_LEN + packet.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        out.extend_from_slice(&DATA_TAIL);
        out.extend_from_slice(packet);
        out
    }

    pub fn encode_keepalive() -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..4].copy_from_slice(&MAGIC);
        out
    }

    /// Reassembles frames from a byte stream.
    #[derive(Debug, Default)]
    pub struct Decoder {
        buf: Vec<u8>,
    }

    impl Decoder {
        pub fn feed(&mut self, bytes: &[u8]) {
            self.buf.extend_from_slice(bytes);
        }

        /// The next complete frame, if any.
        pub fn next_frame(&mut self) -> Result<Option<Frame>, GpError> {
            if self.buf.len() < HEADER_LEN {
                return Ok(None);
            }
            if self.buf[..4] != MAGIC {
                return Err(bad("bad frame magic"));
            }
            let ethertype = u16::from_be_bytes([self.buf[4], self.buf[5]]);
            let len = usize::from(u16::from_be_bytes([self.buf[6], self.buf[7]]));
            if ethertype == 0 && len == 0 {
                self.buf.drain(..HEADER_LEN);
                return Ok(Some(Frame::Keepalive));
            }
            if ethertype != 0x0800 && ethertype != 0x86dd {
                return Err(bad("unknown frame type"));
            }
            if len > MAX_PACKET {
                return Err(bad("frame too large"));
            }
            if self.buf.len() < HEADER_LEN + len {
                return Ok(None);
            }
            let packet = self.buf[HEADER_LEN..HEADER_LEN + len].to_vec();
            self.buf.drain(..HEADER_LEN + len);
            Ok(Some(Frame::Packet(packet)))
        }
    }

    fn bad(detail: &str) -> GpError {
        GpError::BadResponse {
            step: "tunnel",
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::frame::{Decoder, Frame, encode_keepalive, encode_packet};
    use super::*;
    use crate::client::test_client;

    fn session() -> GatewaySession {
        GatewaySession {
            gateway: "https://gw.example.com".into(),
            authcookie: Secret::new("FAKEcookie"),
            portal: "portal".into(),
            user: "user@example.com".into(),
            domain: "example.com".into(),
            computer: "WORKSTATION-1".into(),
            preferred_ip: Some("10.20.30.40".into()),
            preferred_ipv6: None,
        }
    }

    const CONFIG: &str = r#"<response status="success">
  <ip-address>10.20.30.40</ip-address>
  <netmask>255.255.255.255</netmask>
  <mtu>1400</mtu>
  <dns><member>10.0.0.53</member><member>10.0.0.54</member></dns>
  <dns-suffix><member>corp.example.com</member></dns-suffix>
  <access-routes><member>10.0.0.0/8</member><member>192.0.2.0/24</member></access-routes>
  <exclude-access-routes><member>10.99.0.0/16</member></exclude-access-routes>
  <gw-address>203.0.113.10</gw-address>
  <timeout>3600</timeout>
  <ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>
  <ipsec>
    <udp-port>4501</udp-port>
    <ipsec-mode>esp-tunnel</ipsec-mode>
    <enc-algo>aes-128-cbc</enc-algo>
    <hmac-algo>sha1</hmac-algo>
    <c2s-spi>0x1A2B3C4D</c2s-spi>
    <s2c-spi>0x5E6F7A8B</s2c-spi>
    <ekey-c2s><bits>128</bits><val>000102030405060708090a0b0c0d0e0f</val></ekey-c2s>
    <akey-c2s><bits>160</bits><val>101112131415161718191a1b1c1d1e1f20212223</val></akey-c2s>
    <ekey-s2c><bits>128</bits><val>202122232425262728292a2b2c2d2e2f</val></ekey-s2c>
    <akey-s2c><bits>160</bits><val>303132333435363738393a3b3c3d3e3f40414243</val></akey-s2c>
  </ipsec>
</response>"#;

    #[test]
    fn parses_the_tunnel_configuration() {
        let s = parse_getconfig(&Response::new(200, CONFIG)).unwrap();
        assert_eq!(
            s.address_v4,
            Some((Ipv4Addr::new(10, 20, 30, 40), Ipv4Addr::BROADCAST))
        );
        assert_eq!(s.mtu, Some(1400));
        assert_eq!(s.dns_servers.len(), 2);
        assert_eq!(s.dns_suffixes, ["corp.example.com"]);
        assert_eq!(s.routes, ["10.0.0.0/8", "192.0.2.0/24"]);
        assert_eq!(s.exclude_routes, ["10.99.0.0/16"]);
        assert_eq!(s.gateway_address, Some("203.0.113.10".parse().unwrap()));
        let esp = s.esp.unwrap();
        assert_eq!(esp.c2s_spi, 0x1A2B3C4D);
        assert_eq!(esp.cipher, EspCipher::Aes128Cbc);
        assert_eq!(esp.hmac, EspHmac::Sha1);
        assert_eq!(EspSettings::key_bytes(&esp.c2s_enc_key).len(), 16);
        assert_eq!(EspSettings::key_bytes(&esp.s2c_auth_key).len(), 20);
    }

    #[test]
    fn unusable_esp_falls_back_to_tls_only() {
        let md5 = CONFIG.replace("<hmac-algo>sha1</hmac-algo>", "<hmac-algo>md5</hmac-algo>");
        assert!(
            parse_getconfig(&Response::new(200, md5))
                .unwrap()
                .esp
                .is_none()
        );
        let short_key = CONFIG.replace("<bits>128</bits><val>0001", "<bits>256</bits><val>0001");
        assert!(
            parse_getconfig(&Response::new(200, short_key))
                .unwrap()
                .esp
                .is_none()
        );
    }

    #[test]
    fn configuration_errors() {
        assert!(matches!(
            parse_getconfig(&Response::new(512, "")),
            Err(GpError::AuthFailed(_))
        ));
        assert_eq!(
            parse_getconfig(&Response::new(
                200,
                "<response status=\"error\"><error>Assign private IP address failed</error></response>"
            )),
            Err(GpError::Server("Assign private IP address failed".into()))
        );
        assert!(parse_getconfig(&Response::new(200, "<response status=\"success\"/>")).is_err());
    }

    #[test]
    fn requests_carry_the_session() {
        let req = getconfig_request(&test_client(), &session());
        assert_eq!(req.url, "https://gw.example.com/ssl-vpn/getconfig.esp");
        assert_eq!(req.form_value("authcookie").as_deref(), Some("FAKEcookie"));
        assert_eq!(
            req.form_value("preferred-ip").as_deref(),
            Some("10.20.30.40")
        );
        assert_eq!(req.form_value("app-version"), None);
        assert_eq!(req.form_value("internal").as_deref(), Some("no"));
        let body = req.body.clone().unwrap();
        let names: Vec<&str> = body
            .split('&')
            .map(|pair| pair.split('=').next().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "client-type",
                "protocol-version",
                "internal",
                "ipv6-support",
                "clientos",
                "os-version",
                "hmac-algo",
                "enc-algo",
                "authcookie",
                "portal",
                "user",
                "domain",
                "preferred-ip",
                "computer"
            ],
            "every field once, in the official order"
        );
        let logout = logout_request(&test_client(), &session());
        assert_eq!(logout.url, "https://gw.example.com/ssl-vpn/logout.esp");
        let body = logout.body.clone().unwrap();
        assert_eq!(body.matches("computer=").count(), 1, "{body}");
        let tunnel =
            String::from_utf8(tunnel_request(&session(), "/ssl-tunnel-connect.sslvpn")).unwrap();
        assert_eq!(
            tunnel,
            "GET /ssl-tunnel-connect.sslvpn?user=user%40example.com&authcookie=FAKEcookie HTTP/1.1\r\n\
             Host: gw.example.com\r\nUser-Agent: PAN GlobalProtect\r\n\r\n"
        );
    }

    #[test]
    fn frames_round_trip_across_arbitrary_splits() {
        let v4 = vec![0x45, 0, 0, 20, 1, 2, 3, 4];
        let v6 = vec![0x60, 0, 0, 0];
        let mut stream = encode_packet(&v4);
        stream.extend_from_slice(&encode_keepalive());
        stream.extend_from_slice(&encode_packet(&v6));
        assert_eq!(&stream[4..6], &[0x08, 0x00]);

        for split in 1..stream.len() {
            let mut d = Decoder::default();
            let mut frames = Vec::new();
            for chunk in stream.chunks(split) {
                d.feed(chunk);
                while let Some(f) = d.next_frame().unwrap() {
                    frames.push(f);
                }
            }
            assert_eq!(
                frames,
                [
                    Frame::Packet(v4.clone()),
                    Frame::Keepalive,
                    Frame::Packet(v6.clone())
                ]
            );
        }
    }

    #[test]
    fn bad_frames_are_errors() {
        let mut d = Decoder::default();
        d.feed(&[0u8; 16]);
        assert!(d.next_frame().is_err());
        let mut d = Decoder::default();
        let mut header = encode_packet(&[0x45]);
        header[6] = 0xff; // length 65281 > MAX_PACKET
        d.feed(&header);
        assert!(d.next_frame().is_err());
    }
}
