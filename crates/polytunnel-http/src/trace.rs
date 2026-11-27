//! An opt-in record of HTTP exchanges for troubleshooting a connection. Every secret is
//! redacted before anything is written: passwords, codes, session cookies, the gateway's
//! authcookie, portal cookies and tunnel keys become `<redacted:N>` (N = their length), so a
//! trace can be shared.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use polytunnel_core::http::{HttpError, Method, Request, Response, Transport};

/// Bodies are cut after this many characters (after redaction).
const MAX_BODY: usize = 2000;
/// The trace file is started afresh (the old one kept as `.old`) beyond this size.
const MAX_FILE: u64 = 4 * 1024 * 1024;

/// A transport that writes each exchange to `path` (when set) and otherwise does nothing.
pub struct Traced<T> {
    inner: T,
    path: Option<PathBuf>,
}

impl<T> Traced<T> {
    pub fn new(inner: T, path: Option<PathBuf>) -> Self {
        Traced { inner, path }
    }
}

impl<T: Transport> Transport for Traced<T> {
    fn send(&self, request: &Request) -> Result<Response, HttpError> {
        let started = Instant::now();
        let result = self.inner.send(request);
        if let Some(path) = &self.path {
            let _ = append(path, &describe(request, &result, started.elapsed()));
        }
        result
    }
}

fn append(path: &Path, text: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    if fs::metadata(path).is_ok_and(|m| m.len() > MAX_FILE) {
        let _ = fs::rename(path, path.with_extension("log.old"));
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(text.as_bytes())
}

/// Whether a field, cookie, query parameter or XML element called `name` holds a secret.
fn is_secret(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    if n == "tokeninfo" {
        return false;
    }
    matches!(n.as_str(), "code" | "code2" | "passwd")
        || ["cookie", "passw", "credential", "secret", "token", "key"]
            .iter()
            .any(|s| n.contains(s))
}

fn redacted(value: &str) -> String {
    format!("<redacted:{}>", value.len())
}

/// The trace entry for one exchange.
pub fn describe(request: &Request, result: &Result<Response, HttpError>, took: Duration) -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let method = match request.method {
        Method::Get => "GET",
        Method::Post => "POST",
    };
    let mut out = format!(
        "== {secs} {method} {} ({} ms)\n",
        redact_url(&request.url),
        took.as_millis()
    );
    for (name, value) in &request.headers {
        out.push_str(&format!("> {name}: {}\n", redact_header(name, value)));
    }
    if let Some(body) = &request.body {
        let fields: Vec<String> = form_urlencoded::parse(body.as_bytes())
            .map(|(k, v)| {
                if is_secret(&k) {
                    format!("{k}={}", redacted(&v))
                } else {
                    format!("{k}={v}")
                }
            })
            .collect();
        out.push_str(&format!("> form: {}\n", fields.join(" ")));
    }
    match result {
        Err(e) => out.push_str(&format!("< error: {}\n", e.0)),
        Ok(response) => {
            out.push_str(&format!("< {}\n", response.status));
            for (name, value) in &response.headers {
                out.push_str(&format!("< {name}: {}\n", redact_header(name, value)));
            }
            let body = redact_body(&response.body);
            let shown: String = body.chars().take(MAX_BODY).collect();
            let cut = if body.chars().count() > MAX_BODY {
                " ..."
            } else {
                ""
            };
            out.push_str(&format!(
                "< body ({} bytes): {shown}{cut}\n",
                response.body.len()
            ));
        }
    }
    out.push('\n');
    out
}

fn redact_url(url: &str) -> String {
    match url.split_once('?') {
        None => url.to_string(),
        Some((base, query)) => format!("{base}?{}", redact_pairs(query, '&')),
    }
}

fn redact_header(name: &str, value: &str) -> String {
    let n = name.to_ascii_lowercase();
    if n == "cookie" {
        redact_pairs(value, ';')
    } else if n == "set-cookie" {
        // Only the cookie's own value; its attributes (path, secure, ...) stay.
        let (pair, attributes) = value.split_once(';').unwrap_or((value, ""));
        let pair = match pair.split_once('=') {
            Some((k, v)) => format!("{}={}", k.trim(), redacted(v.trim())),
            None => pair.to_string(),
        };
        if attributes.is_empty() {
            pair
        } else {
            format!("{pair};{attributes}")
        }
    } else if n == "authorization" || is_secret(&n) {
        redacted(value)
    } else {
        value.to_string()
    }
}

/// `k=v` pairs separated by `separator`, with secret values redacted.
fn redact_pairs(text: &str, separator: char) -> String {
    text.split(separator)
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) if is_secret(k) => format!("{k}={}", redacted(v)),
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join(&separator.to_string())
}

/// A response body with secrets removed: GlobalProtect login answers (authcookie and portal
/// cookies by position), secret XML elements, and `k=v` text such as Fortinet's `ret=...`.
pub fn redact_body(body: &str) -> String {
    let body = if body.contains("<application-desc") {
        redact_jnlp(body)
    } else {
        body.to_string()
    };
    let body = redact_xml_elements(&body);
    if body.trim_start().starts_with('<') {
        body
    } else {
        // Plain text such as `ret=1,redir=...`: secret `k=v` values.
        body.split(',')
            .map(|part| match part.split_once('=') {
                Some((k, v)) if is_secret(k) => format!("{k}={}", redacted(v)),
                _ => part.to_string(),
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// JNLP arguments 1 (authcookie), 2 (persistent cookie), 16 and 17 (portal cookies).
fn redact_jnlp(body: &str) -> String {
    const SECRET: [usize; 4] = [1, 2, 16, 17];
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    let mut index = 0;
    while let Some(start) = rest.find("<argument>") {
        let open_end = start + "<argument>".len();
        out.push_str(&rest[..open_end]);
        rest = &rest[open_end..];
        let Some(close) = rest.find("</argument>") else {
            break;
        };
        let value = &rest[..close];
        if SECRET.contains(&index) && !value.trim().is_empty() {
            out.push_str(&redacted(value.trim()));
        } else {
            out.push_str(value);
        }
        rest = &rest[close..];
        index += 1;
    }
    out.push_str(rest);
    out
}

/// `<name>value</name>` with a secret `name` (e.g. `portal-userauthcookie`, `ekey-c2s`).
fn redact_xml_elements(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(lt) = rest.find('<') {
        let after = &rest[lt + 1..];
        let name_len = after
            .find(|c: char| c == '>' || c == '/' || c.is_whitespace())
            .unwrap_or(after.len());
        let name = &after[..name_len];
        let opening = !name.is_empty()
            && !name.starts_with(['/', '?', '!'])
            && after[name_len..].starts_with('>');
        if opening && is_secret(name) {
            let close_tag = format!("</{name}>");
            let content_start = lt + 1 + name_len + 1;
            if let Some(close) = rest[content_start..].find(&close_tag) {
                out.push_str(&rest[..content_start]);
                out.push_str(&redacted(&rest[content_start..content_start + close]));
                rest = &rest[content_start + close..];
                continue;
            }
        }
        out.push_str(&rest[..lt + 1]);
        rest = &rest[lt + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(tag: &str) -> String {
        format!("SECRET{tag}VALUE0123456789")
    }

    #[test]
    fn secrets_never_reach_the_trace() {
        let request = Request::post_form(
            "https://vpn.example.net:10443/remote/logincheck?authcookie=QQ".to_string(),
            [
                ("username", "user@example.com"),
                ("credential", secret("pw").as_str()),
                ("ajax", "1"),
            ],
        )
        .header(
            "Cookie",
            &format!("SVPNCOOKIE={}; lang=en", secret("cookie")),
        )
        .header("User-Agent", "Mozilla/5.0 SV1");
        let jnlp = format!(
            "<jnlp><application-desc><argument>(null)</argument><argument>{}</argument>\
             <argument>{}</argument><argument>vpn</argument><argument>user%40example.com</argument>\
             </application-desc></jnlp>",
            secret("auth"),
            secret("persist")
        );
        let response = Response {
            status: 200,
            headers: vec![(
                "Set-Cookie".into(),
                format!("SVPNCOOKIE={}; path=/; secure", secret("set")),
            )],
            body: jnlp,
        };
        let text = describe(&request, &Ok(response), Duration::from_millis(5));
        assert!(!text.contains("SECRET"), "{text}");
        for visible in [
            "POST https://vpn.example.net:10443/remote/logincheck?authcookie=<redacted:2>",
            "username=user@example.com",
            "credential=<redacted:",
            "> User-Agent: Mozilla/5.0 SV1",
            "SVPNCOOKIE=<redacted:",
            "; path=/; secure",
            "<argument>user%40example.com</argument>",
            "<argument>vpn</argument>",
        ] {
            assert!(text.contains(visible), "missing {visible:?} in\n{text}");
        }
    }

    #[test]
    fn secret_xml_and_text_values_are_removed() {
        let config = format!(
            "<policy><portal-userauthcookie>{}</portal-userauthcookie><version>6.2.8</version>\
             <ipsec><ekey-c2s>{}</ekey-c2s><akey-s2c>{}</akey-s2c><enc-algo>aes-128-cbc</enc-algo></ipsec></policy>",
            secret("portal"),
            secret("ekey"),
            secret("akey")
        );
        let redacted_config = redact_body(&config);
        assert!(!redacted_config.contains("SECRET"), "{redacted_config}");
        assert!(redacted_config.contains("<version>6.2.8</version>"));
        assert!(redacted_config.contains("<enc-algo>aes-128-cbc</enc-algo>"));
        let text = redact_body("ret=1,redir=/remote/fortisslvpn_xml,tokeninfo=ftm_push");
        assert_eq!(
            text,
            "ret=1,redir=/remote/fortisslvpn_xml,tokeninfo=ftm_push"
        );
        assert!(!redact_body("ret=2,reqid=7,code=123456").contains("123456"));
    }

    #[test]
    fn the_trace_is_written_only_when_asked() {
        struct Fixed;
        impl Transport for Fixed {
            fn send(&self, _: &Request) -> Result<Response, HttpError> {
                Ok(Response::new(200, "ret=1"))
            }
        }
        let dir = std::env::temp_dir().join(format!("polytunnel-trace-{}", std::process::id()));
        let path = dir.join("trace.log");
        let _ = fs::remove_file(&path);
        Traced::new(Fixed, None)
            .send(&Request::get("https://a.example.com/"))
            .unwrap();
        assert!(!path.exists());
        Traced::new(Fixed, Some(path.clone()))
            .send(&Request::get("https://a.example.com/"))
            .unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("GET https://a.example.com/"), "{text}");
        assert!(text.contains("< body (5 bytes): ret=1"), "{text}");
        let _ = fs::remove_dir_all(&dir);
    }
}
