//! The real HTTP transport for Polytunnel: ureq with the operating system's TLS stack and
//! trust store. Shared by the app (logins) and the daemon (tunnel setup, HIP, logout).

use std::time::Duration;

use polytunnel_core::http::{HttpError, Method, Request, Response, Transport};
use ureq::Agent;
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

/// Response bodies larger than this are refused (VPN login answers are a few KB).
const MAX_BODY: u64 = 4 * 1024 * 1024;

pub struct UreqTransport {
    agent: Agent,
}

impl UreqTransport {
    pub fn new() -> Self {
        let tls = TlsConfig::builder()
            .provider(TlsProvider::NativeTls)
            .root_certs(RootCerts::PlatformVerifier)
            .build();
        let agent: Agent = Agent::config_builder()
            .tls_config(tls)
            // Protocol code interprets every status itself.
            .http_status_as_error(false)
            // ...and must see redirects instead of following them.
            .max_redirects(0)
            .max_redirects_will_error(false)
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_global(Some(Duration::from_secs(60)))
            .build()
            .into();
        UreqTransport { agent }
    }
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
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_string(), v.to_string()))
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
