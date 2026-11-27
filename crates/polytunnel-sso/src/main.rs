//! `polytunnel-sso`: Polytunnel's optional embedded login window, for single sign-on when the
//! default-browser hand-off is not possible.
//!
//! ```text
//! polytunnel-sso --url <login URL> [--title <text>]
//! polytunnel-sso --html [--title <text>]     (the page to show comes on standard input)
//! ```
//!
//! It shows the login in an embedded web view (WebView2 on Windows, WKWebView on macOS),
//! catches the `globalprotectcallback:` link the portal ends with, or a final page that carries
//! the SAML result in its source, and prints one JSON line to standard output:
//! `{"result":"callback","value":...}`, `{"result":"page","value":...}` or
//! `{"result":"closed"}`. Linux builds print `{"result":"unavailable"}`: use the default
//! browser there.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::io::Read;

/// What the window ended with.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Callback(String),
    Page(String),
    Closed,
}

impl Outcome {
    fn json(&self) -> String {
        let (result, value) = match self {
            Outcome::Callback(v) => ("callback", Some(v)),
            Outcome::Page(v) => ("page", Some(v)),
            Outcome::Closed => ("closed", None),
        };
        let mut map = serde_json::Map::new();
        map.insert("result".into(), result.into());
        if let Some(v) = value {
            map.insert("value".into(), v.clone().into());
        }
        serde_json::Value::Object(map).to_string()
    }
}

/// What to show.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    Url(String),
    Html(String),
}

struct Args {
    source: Source,
    title: String,
}

fn parse_args(
    args: &[String],
    stdin: impl FnOnce() -> std::io::Result<String>,
) -> Result<Args, String> {
    let mut url = None;
    let mut html = false;
    let mut title = "Sign in".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--url" => url = Some(it.next().ok_or("--url needs a value")?.clone()),
            "--html" => html = true,
            "--title" => title = it.next().ok_or("--title needs a value")?.clone(),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let source = match (url, html) {
        (Some(u), false) if u.starts_with("https://") || u.starts_with("http://127.0.0.1") => {
            Source::Url(u)
        }
        (Some(_), false) => return Err("--url must be an https:// address".into()),
        (None, true) => Source::Html(stdin().map_err(|e| e.to_string())?),
        _ => return Err("give either --url <address> or --html".into()),
    };
    Ok(Args { source, title })
}

/// Whether a page's source carries a SAML result (GlobalProtect puts it in a comment).
fn carries_result(source: &str) -> bool {
    source.contains("<saml-auth-status>") || source.contains("<prelogin-cookie>")
}

/// Runs in every page: hands the whole source to us once it is loaded, if it has a result.
const PAGE_SCRIPT: &str = r#"
window.addEventListener('DOMContentLoaded', function () {
  try {
    var source = new XMLSerializer().serializeToString(document);
    if (source.indexOf('<saml-auth-status>') >= 0 || source.indexOf('<prelogin-cookie>') >= 0) {
      window.ipc.postMessage(source);
    }
  } catch (e) {}
});
"#;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&args, || {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).map(|_| s)
    }) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("polytunnel-sso: {e}");
            std::process::exit(2);
        }
    };
    window::run(args);
}

#[cfg(any(windows, target_os = "macos"))]
mod window {
    use tao::dpi::LogicalSize;
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tao::window::WindowBuilder;
    use wry::WebViewBuilder;

    use super::{Args, Outcome, PAGE_SCRIPT, Source, carries_result};

    pub fn run(args: Args) -> ! {
        let event_loop = EventLoopBuilder::<Outcome>::with_user_event().build();
        let window = match WindowBuilder::new()
            .with_title(&args.title)
            .with_inner_size(LogicalSize::new(520.0, 720.0))
            .build(&event_loop)
        {
            Ok(w) => w,
            Err(e) => {
                eprintln!("polytunnel-sso: cannot open a window: {e}");
                std::process::exit(1);
            }
        };
        let on_navigate = event_loop.create_proxy();
        let on_ipc = event_loop.create_proxy();
        let builder = WebViewBuilder::new()
            .with_initialization_script(PAGE_SCRIPT)
            .with_navigation_handler(move |url| {
                if url
                    .to_ascii_lowercase()
                    .starts_with("globalprotectcallback:")
                {
                    let _ = on_navigate.send_event(Outcome::Callback(url));
                    return false;
                }
                true
            })
            .with_ipc_handler(move |request| {
                let body = request.into_body();
                if carries_result(&body) {
                    let _ = on_ipc.send_event(Outcome::Page(body));
                }
            });
        let builder = match args.source {
            Source::Url(url) => builder.with_url(url),
            Source::Html(html) => builder.with_html(html),
        };
        let webview = match builder.build(&window) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("polytunnel-sso: cannot start the web view: {e}");
                std::process::exit(1);
            }
        };
        event_loop.run(move |event, _, control_flow| {
            *control_flow = ControlFlow::Wait;
            let _ = &webview;
            let outcome = match event {
                Event::UserEvent(outcome) => Some(outcome),
                Event::WindowEvent {
                    event: WindowEvent::CloseRequested,
                    ..
                } => Some(Outcome::Closed),
                _ => None,
            };
            if let Some(outcome) = outcome {
                println!("{}", outcome.json());
                std::process::exit(0);
            }
        })
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod window {
    use super::Args;

    pub fn run(_args: Args) -> ! {
        println!(r#"{{"result":"unavailable"}}"#);
        std::process::exit(3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn arguments() {
        let a = parse_args(
            &args(&["--url", "https://login.example.com/x"]),
            || unreachable!(),
        )
        .unwrap();
        assert_eq!(a.source, Source::Url("https://login.example.com/x".into()));
        assert_eq!(a.title, "Sign in");
        let a = parse_args(&args(&["--html", "--title", "Portal"]), || {
            Ok("<html/>".into())
        })
        .unwrap();
        assert_eq!(a.source, Source::Html("<html/>".into()));
        assert_eq!(a.title, "Portal");
        for bad in [
            &["--url", "file:///etc/passwd"][..],
            &["--url"],
            &[],
            &["--url", "https://a.example.com", "--html"],
            &["-x"],
        ] {
            assert!(
                parse_args(&args(bad), || Ok(String::new())).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn outcomes_are_one_json_line() {
        assert_eq!(Outcome::Closed.json(), r#"{"result":"closed"}"#);
        let line = Outcome::Callback("globalprotectcallback:abc".into()).json();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["result"], "callback");
        assert_eq!(v["value"], "globalprotectcallback:abc");
        assert!(!Outcome::Page("a\nb".into()).json().contains('\n'));
    }

    #[test]
    fn result_pages_are_recognised() {
        assert!(carries_result(
            "<!-- <saml-auth-status>1</saml-auth-status> -->"
        ));
        assert!(!carries_result("<html><body>Welcome</body></html>"));
    }
}
