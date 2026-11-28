//! The real HTTP transport for Polytunnel: ureq with the operating system's TLS stack and
//! trust store. Shared by the app (logins) and the daemon (tunnel setup, HIP, logout).

mod pinned;
pub mod trace;

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use polytunnel_core::http::{HttpError, Method, Request, Response, Transport};
use polytunnel_core::pin::CertFingerprint;
use ureq::Agent;
use ureq::config::Config;
use ureq::http::Uri;
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{Connector, DefaultConnector, NextTimeout, TcpConnector};

pub use pinned::{check_pin, fingerprint, tls_connector, untrusted_certificate};

/// Response bodies larger than this are refused (VPN login answers are a few KB).
const MAX_BODY: u64 = 4 * 1024 * 1024;

pub struct UreqTransport {
    agent: Agent,
}

impl UreqTransport {
    /// HTTPS checked by the system's TLS stack and trust store.
    pub fn new() -> Self {
        Self::configured(None, None)
    }

    /// With a pin, HTTPS that accepts exactly that certificate (see [`pinned`]); without
    /// one, the same as [`UreqTransport::new`].
    pub fn with_server_cert(pin: Option<CertFingerprint>) -> Self {
        Self::configured(pin, None)
    }

    /// `server`: a host name and the addresses to use for it instead of asking DNS. The
    /// service resolves the VPN server once, before a tunnel points DNS at servers that may
    /// only be reachable through it, and keeps talking to that same server.
    pub fn configured(pin: Option<CertFingerprint>, server: Option<(String, Vec<IpAddr>)>) -> Self {
        let resolver = FixedResolver {
            fixed: server.filter(|(_, addrs)| !addrs.is_empty()),
            system: DefaultResolver::default(),
        };
        let agent = match pin {
            Some(pin) => Agent::with_parts(
                config(),
                TcpConnector::default().chain(pinned::PinnedTls { pin }),
                resolver,
            ),
            None => Agent::with_parts(config(), DefaultConnector::new(), resolver),
        };
        UreqTransport { agent }
    }
}

/// Answers one host name with fixed addresses and asks the system for any other.
struct FixedResolver {
    fixed: Option<(String, Vec<IpAddr>)>,
    system: DefaultResolver,
}

impl fmt::Debug for FixedResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedResolver")
            .field("fixed", &self.fixed)
            .finish()
    }
}

impl Resolver for FixedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        if let Some((host, addrs)) = &self.fixed {
            let asked = uri
                .host()
                .unwrap_or_default()
                .trim_start_matches('[')
                .trim_end_matches(']');
            if asked.eq_ignore_ascii_case(host) {
                let port = uri.port_u16().unwrap_or(443);
                let mut out = self.empty();
                for ip in addrs.iter().take(16) {
                    out.push(SocketAddr::new(*ip, port));
                }
                return Ok(out);
            }
        }
        self.system.resolve(uri, config, timeout)
    }
}

fn config() -> Config {
    let tls = TlsConfig::builder()
        .provider(TlsProvider::NativeTls)
        .root_certs(RootCerts::PlatformVerifier)
        .build();
    Agent::config_builder()
        .tls_config(tls)
        // Protocol code interprets every status itself.
        .http_status_as_error(false)
        // ...and must see redirects instead of following them.
        .max_redirects(0)
        .max_redirects_will_error(false)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_global(Some(Duration::from_secs(60)))
        // The app and the service run with different environments, and the tunnel itself
        // never uses a proxy: no proxy from environment variables either.
        .proxy(None)
        .build()
}

impl Default for UreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for UreqTransport {
    fn send(&self, request: &Request) -> Result<Response, HttpError> {
        if !request.url.starts_with("https://") {
            return Err(HttpError(format!(
                "refusing a non-HTTPS request: {request:?}"
            )));
        }
        let error = |e: ureq::Error| HttpError(e.to_string());
        let result = match request.method {
            Method::Get => {
                let mut builder = self.agent.get(&request.url);
                for (name, value) in &request.headers {
                    builder = builder.header(name.as_str(), value.as_str());
                }
                builder.call()
            }
            Method::Post => {
                let mut builder = self.agent.post(&request.url);
                for (name, value) in &request.headers {
                    builder = builder.header(name.as_str(), value.as_str());
                }
                builder.send(request.body.as_deref().unwrap_or_default())
            }
        };
        let mut response = result.map_err(error)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            // Kept even if a value has bytes outside visible ASCII (a cookie must never be
            // dropped because of one odd character).
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_string()
            .map_err(error)?;
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

/// The host of an `https://host[:port]/...` URL, lower-cased.
fn https_host(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') {
        return None;
    }
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => authority,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Downloads a file over HTTPS (at most `max` bytes), following redirects only to hosts in
/// `allowed_hosts` (and only over HTTPS).
pub fn download(url: &str, allowed_hosts: &[&str], max: u64) -> Result<Vec<u8>, HttpError> {
    let agent = UreqTransport::new().agent;
    let mut url = url.to_string();
    for _ in 0..6 {
        let host =
            https_host(&url).ok_or_else(|| HttpError(format!("not an HTTPS address: {url}")))?;
        if !allowed_hosts.contains(&host.as_str()) {
            return Err(HttpError(format!("refusing to download from {host}")));
        }
        let mut response = agent
            .get(&url)
            .header("User-Agent", "Polytunnel")
            .call()
            .map_err(|e| HttpError(e.to_string()))?;
        match response.status().as_u16() {
            301 | 302 | 303 | 307 | 308 => {
                url = response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| HttpError("a redirect without a location".into()))?
                    .to_string();
            }
            200 => {
                return response
                    .body_mut()
                    .with_config()
                    .limit(max)
                    .read_to_vec()
                    .map_err(|e| HttpError(e.to_string()));
            }
            status => return Err(HttpError(format!("the server answered {status}"))),
        }
    }
    Err(HttpError("too many redirects".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_of_https_addresses() {
        assert_eq!(
            https_host("https://GitHub.com/a/b").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            https_host("https://example.com:8443/x").as_deref(),
            Some("example.com")
        );
        assert_eq!(https_host("http://github.com/"), None);
        assert_eq!(https_host("https://user@github.com/"), None);
        assert!(download("http://github.com/x", &["github.com"], 10).is_err());
        assert!(download("https://example.com/x", &["github.com"], 10).is_err());
    }
}
