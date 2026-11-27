//! The app's troubleshooting trace (see `polytunnel_http::trace`): on while
//! `POLYTUNNEL_TRACE=1` is set or the window's Diagnostics switch is on, written to
//! `trace.log` next to the switch file in [`paths::log_dir`]. The service writes its own
//! trace for connections the app starts while tracing.

use std::io;
use std::path::PathBuf;

use polytunnel_core::pin::CertFingerprint;
use polytunnel_http::UreqTransport;
use polytunnel_http::trace::Traced;

use crate::paths;

fn switch_file() -> PathBuf {
    paths::log_dir().join("trace-on")
}

/// The trace file.
pub fn file() -> PathBuf {
    paths::log_dir().join("trace.log")
}

/// Whether exchanges are being recorded.
pub fn enabled() -> bool {
    std::env::var_os("POLYTUNNEL_TRACE").is_some_and(|v| v == "1") || switch_file().exists()
}

/// Turns the window's switch on or off.
pub fn set(on: bool) -> io::Result<()> {
    if on {
        std::fs::create_dir_all(paths::log_dir())?;
        std::fs::write(switch_file(), b"")
    } else {
        match std::fs::remove_file(switch_file()) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// The HTTPS transport for logins: traced while tracing is on.
pub fn transport(pin: Option<CertFingerprint>) -> Traced<UreqTransport> {
    Traced::new(UreqTransport::with_server_cert(pin), enabled().then(file))
}
