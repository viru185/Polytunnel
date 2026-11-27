//! Opening the system browser, and serving a one-off page for SAML POST logins.

use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

/// Opens `url` (an `https://` identity-provider URL or our own `http://127.0.0.1` page).
pub fn open(url: &str) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://127.0.0.1:")) {
        return Err("refusing to open a non-HTTPS URL".into());
    }
    #[cfg(windows)]
    {
        crate::win::open_url(url)
    }
    #[cfg(not(windows))]
    {
        let program = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        std::process::Command::new(program)
            .arg(url)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("cannot run {program}: {e}"))
    }
}

/// Serves `html` on `127.0.0.1` under a random path (for SAML logins that start with a form
/// POST) and returns the URL to open. The server stops after serving the page once, or after
/// twenty unrelated requests.
pub fn serve_page(html: String) -> io::Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let token = random_token();
    let url = format!("http://{}/{token}", listener.local_addr()?);
    let path = format!("/{token}");
    thread::Builder::new()
        .name("saml-post-page".into())
        .spawn(move || {
            for mut stream in listener.incoming().filter_map(Result::ok).take(20) {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let mut first = String::new();
                if BufReader::new(&stream).read_line(&mut first).is_err() {
                    continue;
                }
                let target = first.split_whitespace().nth(1).unwrap_or_default();
                if target == path {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                         Cache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}",
                        html.len()
                    );
                    break;
                }
                let _ = stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        })?;
    Ok(url)
}

fn random_token() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom::fill(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
