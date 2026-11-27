//! The service's troubleshooting trace (see `polytunnel_http::trace`): `trace.log` in the
//! state directory, written for connections the app starts while its trace is on.

use std::sync::atomic::{AtomicBool, Ordering};

use polytunnel_core::pin::CertFingerprint;
use polytunnel_http::UreqTransport;
use polytunnel_http::trace::Traced;

use crate::paths;

static ON: AtomicBool = AtomicBool::new(false);

/// Set by each connect request.
pub fn set(on: bool) {
    ON.store(on, Ordering::Relaxed);
}

/// The HTTPS transport for tunnel setup: traced while tracing is on.
pub fn transport(pin: Option<CertFingerprint>) -> Traced<UreqTransport> {
    let path = ON
        .load(Ordering::Relaxed)
        .then(|| paths::ensure_state_dir().ok())
        .flatten()
        .map(|dir| dir.join("trace.log"));
    Traced::new(UreqTransport::with_server_cert(pin), path)
}
