//! End to end over real TLS: Polytunnel's Fortinet login and configuration request against a
//! local fake FortiGate with a self-signed certificate (pinned), answering the way the real
//! one does (chunked bodies, `Set-Cookie: SVPNCOOKIE=...; path=/; secure; httponly;
//! SameSite=Strict`). Proves the session cookie survives the HTTP and TLS layers.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use polytunnel_core::Secret;
use polytunnel_core::http::Transport;
use polytunnel_core::pin::CertFingerprint;
use polytunnel_http::{UreqTransport, fingerprint};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// One request as the fake server saw it.
#[derive(Debug, Clone)]
struct Seen {
    line: String,
    headers: Vec<(String, String)>,
    body: String,
}

fn read_request<S: Read>(stream: &mut S) -> Option<Seen> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let line = lines.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).ok()?;
    Some(Seen {
        line,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn chunked(status: &str, extra_headers: &str, content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\n{extra_headers}Transfer-Encoding: chunked\r\nContent-Type: \
         {content_type}\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
        body.len()
    )
    .into_bytes()
}

const CONFIG: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<sslvpn-tunnel ver="2" dtls="1" patch="1">
  <dtls-config heartbeat-interval="10" heartbeat-fail-count="10" heartbeat-idle-timeout="10" client-hello-timeout="10"/>
  <tunnel-method value="ppp"/>
  <tunnel-method value="tun"/>
  <fos platform="FGT100F" major="7" minor="02" patch="9" build="1688" branch="1688"/>
  <auth-ses tun-connect-without-reauth="0" check-src-ip="1" tun-user-ses-timeout="30"/>
  <client-config save-password="off" keep-alive="on" auto-connect="off"/>
  <ipv4>
    <dns ip="192.0.2.53"/>
    <assigned-addr ipv4="198.51.100.201"/>
  </ipv4>
  <idle-timeout val="300"/>
  <auth-timeout val="28800"/>
</sslvpn-tunnel>"#;

/// The fake FortiGate: returns its port, its certificate's fingerprint, and the requests seen.
fn fake_fortigate() -> (u16, CertFingerprint, Arc<Mutex<Vec<Seen>>>) {
    let cert = rcgen::generate_simple_self_signed(vec!["FGT-FAKE".into()]).unwrap();
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
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let (config, log) = (config.clone(), log.clone());
            thread::spawn(move || {
                let conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let Some(request) = read_request(&mut tls) else {
                    return;
                };
                log.lock().unwrap().push(request.clone());
                let cookie = request
                    .headers
                    .iter()
                    .find(|(k, _)| k == "cookie")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                let reply = match request.line.split(' ').nth(1).unwrap_or("") {
                    "/" => b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nContent-Type: text/html\r\n\
                             Connection: close\r\n\r\n<html>login</html>\r\n"
                        .to_vec(),
                    "/remote/logincheck" if request.body.contains("credential=") => chunked(
                        "200 OK",
                        "Set-Cookie: SVPNCOOKIE=FAKEsession%2Fvalue%3D%3D; path=/; secure; \
                         httponly; SameSite=Strict\r\n",
                        "text/html",
                        "ret=1,redir=/remote/fortisslvpn_xml",
                    ),
                    "/remote/fortisslvpn_xml?dual_stack=1"
                        if cookie.contains("SVPNCOOKIE=FAKEsession") =>
                    {
                        chunked("200 OK", "", "text/xml", CONFIG)
                    }
                    _ => {
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    }
                };
                let _ = tls.write_all(&reply);
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    (port, fingerprint(&der), seen)
}

#[test]
fn logs_in_and_reads_the_configuration_over_pinned_tls() {
    let (port, pin, seen) = fake_fortigate();
    let base = format!("https://127.0.0.1:{port}");
    let transport = UreqTransport::with_server_cert(Some(pin));
    let cookies = polytunnel_forti::login::login(
        &transport,
        &base,
        "user",
        &Secret::new(["not", "real"].join("-")),
        "",
        &mut |_| panic!("no token expected"),
    )
    .expect("login");
    assert_eq!(cookies.expose(), "SVPNCOOKIE=FAKEsession%2Fvalue%3D%3D");

    let response = transport
        .send(&polytunnel_forti::tunnel::config_request(&base, &cookies))
        .expect("configuration");
    let settings = polytunnel_forti::tunnel::parse_config(&response).expect("parse");
    assert_eq!(settings.address, Some("198.51.100.201".parse().unwrap()));
    assert_eq!(settings.idle_timeout_secs, Some(300));

    let seen = seen.lock().unwrap();
    let lines: Vec<&str> = seen.iter().map(|s| s.line.as_str()).collect();
    assert_eq!(
        lines,
        [
            "GET / HTTP/1.1",
            "POST /remote/logincheck HTTP/1.1",
            "GET /remote/fortisslvpn_xml?dual_stack=1 HTTP/1.1",
        ]
    );
    for request in seen.iter() {
        assert!(
            request
                .headers
                .contains(&("user-agent".into(), "Mozilla/5.0 SV1".into())),
            "{request:?}"
        );
    }
}

/// A gateway that cannot be reached (nothing listens on its port) is a network error, which
/// is what lets a Fortinet profile move on to its next gateway; it is never mistaken for a
/// refused login.
#[test]
fn an_unreachable_gateway_is_a_network_error() {
    // A port that was free a moment ago: nothing listens on it now.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let transport = UreqTransport::with_server_cert(None);
    let result = polytunnel_forti::login::login(
        &transport,
        &format!("https://127.0.0.1:{port}"),
        "user",
        &Secret::new(["not", "real"].join("-")),
        "",
        &mut |_| panic!("no token expected"),
    );
    assert!(
        matches!(result, Err(polytunnel_forti::FortiError::Http(_))),
        "{result:?}"
    );
}
