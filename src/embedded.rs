//! The optional embedded login window: the `polytunnel-sso` helper installed next to this
//! program (Windows and macOS). Used when a profile asks for it or with `--embedded`.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use polytunnel_gp::prelogin::SamlRequest;
use polytunnel_gp::sso::{self, SsoResult};

/// The helper's path, if it is installed.
pub fn helper() -> Option<PathBuf> {
    let name = if cfg!(windows) {
        "polytunnel-sso.exe"
    } else {
        "polytunnel-sso"
    };
    let path = std::env::current_exe().ok()?.parent()?.join(name);
    path.is_file().then_some(path)
}

/// Shows the login in the embedded window and returns its result.
pub fn login(request: &SamlRequest, title: &str) -> Result<SsoResult, String> {
    let exe = helper().ok_or(
        "the embedded login window (polytunnel-sso) is not installed; sign in with the browser",
    )?;
    let mut command = Command::new(exe);
    command
        .arg("--title")
        .arg(title)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    match request {
        SamlRequest::Redirect { url } => {
            command.arg("--url").arg(url).stdin(Stdio::null());
        }
        SamlRequest::Post { .. } => {
            command.arg("--html").stdin(Stdio::piped());
        }
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot open the login window: {e}"))?;
    if let (SamlRequest::Post { html }, Some(mut stdin)) = (request, child.stdin.take()) {
        stdin
            .write_all(html.as_bytes())
            .map_err(|e| format!("cannot hand the login page over: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("the login window failed: {e}"))?;
    parse_output(&String::from_utf8_lossy(&output.stdout))
}

/// The helper's one JSON line, turned into a login result.
fn parse_output(stdout: &str) -> Result<SsoResult, String> {
    let line = stdout
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or_default();
    let v: serde_json::Value =
        serde_json::from_str(line).map_err(|_| "the login window gave no result".to_string())?;
    match v.get("result").and_then(|r| r.as_str()) {
        Some("callback" | "page") => {
            let value = v.get("value").and_then(|r| r.as_str()).unwrap_or_default();
            sso::parse_callback(value).map_err(|e| format!("the login did not complete: {e}"))
        }
        Some("closed") => Err("the login window was closed".into()),
        Some("unavailable") => Err(
            "the embedded login window is not available on this system; sign in with the browser"
                .into(),
        ),
        _ => Err("the login window gave no result".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_output() {
        assert_eq!(
            parse_output(r#"{"result":"closed"}"#).unwrap_err(),
            "the login window was closed"
        );
        assert!(
            parse_output(r#"{"result":"unavailable"}"#)
                .unwrap_err()
                .contains("browser")
        );
        assert!(parse_output("").is_err());
        assert!(parse_output("garbage").is_err());
        // A link that is not a valid login result is reported, not accepted.
        assert!(parse_output(r#"{"result":"callback","value":"globalprotectcallback:"}"#).is_err());
    }
}
