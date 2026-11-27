//! Printing a login result.
//!
//! * `openconnect` (default): `KEY='value'` lines like `openconnect --authenticate`, so a shell
//!   can `eval` them.
//! * `cookie`: only the cookie, for `| openconnect --cookie-on-stdin ...`.
//! * `json`: one JSON object.

use polytunnel_core::Secret;

use crate::cli::Emit;

pub struct LoginOutput {
    /// openconnect protocol name: `gp` or `fortinet`.
    pub protocol: &'static str,
    /// `https://host[:port]` to connect to.
    pub host: String,
    /// openconnect `--os` value (GlobalProtect only).
    pub os: Option<&'static str>,
    pub cookie: Secret,
    pub username: Option<String>,
    /// Gateway label (GlobalProtect only).
    pub gateway: Option<String>,
    /// The portal's verdict on the client's region (GlobalProtect only).
    pub region: Option<String>,
}

/// The text for stdout.
pub fn render(format: Emit, out: &LoginOutput) -> String {
    match format {
        Emit::Cookie => format!("{}\n", out.cookie.expose()),
        Emit::Openconnect => {
            let mut lines = vec![
                format!("COOKIE={}", shell_quote(out.cookie.expose())),
                format!("HOST={}", shell_quote(&out.host)),
                format!("CONNECT_URL={}", shell_quote(&out.host)),
                format!("PROTOCOL={}", shell_quote(out.protocol)),
            ];
            if let Some(os) = out.os {
                lines.push(format!("OS={}", shell_quote(os)));
            }
            lines.join("\n") + "\n"
        }
        Emit::Json => {
            let mut fields = vec![
                ("protocol", Some(out.protocol.to_string())),
                ("host", Some(out.host.clone())),
                ("os", out.os.map(str::to_string)),
                ("username", out.username.clone()),
                ("gateway", out.gateway.clone()),
                ("region", out.region.clone()),
            ];
            fields.push(("cookie", Some(out.cookie.expose().to_string())));
            let body: Vec<String> = fields
                .into_iter()
                .filter_map(|(k, v)| v.map(|v| format!("\"{k}\":{}", json_string(&v))))
                .collect();
            format!("{{{}}}\n", body.join(","))
        }
    }
}

/// A hint for stderr on how to use the result.
pub fn hint(out: &LoginOutput) -> String {
    let host = out.host.strip_prefix("https://").unwrap_or(&out.host);
    let os = out.os.map(|os| format!(" --os={os}")).unwrap_or_default();
    format!(
        "Logged in. To connect with openconnect (as administrator/root), pipe `--emit cookie` \
         into:\n  openconnect --protocol={}{os} --cookie-on-stdin {host}\n\
         The cookie grants access to the VPN until it expires: do not share it.",
        out.protocol
    )
}

/// `'value'` with embedded quotes escaped for POSIX shells.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> LoginOutput {
        LoginOutput {
            protocol: "gp",
            host: "https://gw.example.com".into(),
            os: Some("win"),
            cookie: Secret::new("authcookie=FAKE&user=a'b"),
            username: Some("user@example.com".into()),
            gateway: Some("US \"East\"".into()),
            region: None,
        }
    }

    #[test]
    fn formats() {
        let out = sample();
        assert_eq!(render(Emit::Cookie, &out), "authcookie=FAKE&user=a'b\n");
        assert_eq!(
            render(Emit::Openconnect, &out),
            "COOKIE='authcookie=FAKE&user=a'\\''b'\nHOST='https://gw.example.com'\n\
             CONNECT_URL='https://gw.example.com'\nPROTOCOL='gp'\nOS='win'\n"
        );
        assert_eq!(
            render(Emit::Json, &out),
            "{\"protocol\":\"gp\",\"host\":\"https://gw.example.com\",\"os\":\"win\",\
             \"username\":\"user@example.com\",\"gateway\":\"US \\\"East\\\"\",\
             \"cookie\":\"authcookie=FAKE&user=a'b\"}\n"
        );
        assert!(
            hint(&out)
                .contains("openconnect --protocol=gp --os=win --cookie-on-stdin gw.example.com")
        );
    }
}
