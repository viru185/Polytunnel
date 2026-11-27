//! FortiGate SSL VPN login, step for step as openconnect does it:
//!
//! 1. `GET /`, following same-host redirects (including FortiOS 7.4's JavaScript
//!    `top.location="..."`); the final address may name the realm (`?realm=`).
//! 2. `POST /remote/logincheck` with `username`, `credential`, `realm`, `ajax=1` and
//!    `just_logged_in=1`. The answer is a short comma-separated status line:
//!    * `ret=1,redir=...` plus `Set-Cookie: SVPNCOOKIE=...`: logged in;
//!    * `...,tokeninfo=...,reqid=...`: a token / one-time code is required, answered with
//!      `code` and the server's `reqid, polid, grp, portal, peer, magic`;
//!    * anything else: rejected (`err=` in `redir` says why).
//!
//! Every request carries the user agent FortiGates expect and the cookies the server has set so
//! far. The result is that cookie jar (as a `Cookie` header value), which the tunnel requests
//! send back.

use std::fmt;

use polytunnel_core::Secret;
use polytunnel_core::http::{CookieJar, HttpError, Request, Response, Transport};

/// The session cookie's name.
pub const COOKIE_NAME: &str = "SVPNCOOKIE";

/// Token rounds allowed before giving up (FortiGate may ask again after a wrong code).
pub const MAX_TOKEN_ROUNDS: usize = 3;

/// The user agent openconnect sends to FortiGates.
pub const USER_AGENT: &str = "Mozilla/5.0 SV1";

/// Redirects followed on the first page.
const MAX_REDIRECTS: usize = 5;

/// Fields of a token challenge that go back with the code (as openconnect sends them).
const ECHOED: [&str; 6] = ["reqid", "polid", "grp", "portal", "peer", "magic"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FortiError {
    Http(String),
    Status(u16),
    AuthFailed(String),
    BadResponse(String),
    Cancelled,
}

impl fmt::Display for FortiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FortiError::Http(e) => write!(f, "network error: {e}"),
            FortiError::Status(s) => write!(f, "login: unexpected HTTP status {s}"),
            FortiError::AuthFailed(m) => write!(f, "authentication failed: {m}"),
            FortiError::BadResponse(m) => write!(f, "login: unexpected response ({m})"),
            FortiError::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for FortiError {}

impl From<HttpError> for FortiError {
    fn from(e: HttpError) -> Self {
        FortiError::Http(e.0)
    }
}

/// A request for a token / one-time code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenChallenge {
    /// Text to show the user (`chal_msg`), if the server sent one.
    pub message: Option<String>,
    /// e.g. `ftm_push`, `email`, `sms`: what kind of token is expected.
    pub token_info: Option<String>,
    /// Where to post the answer.
    path: String,
    /// Fields that must be echoed back with the code.
    echo: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginStep {
    /// The session cookie is in the jar.
    Done,
    NeedToken(TokenChallenge),
    /// Logged in, but the cookie comes with the page the server sends the client to.
    Redirect(String),
}

/// Adds the user agent and the session's cookies to a request.
pub fn with_session(request: Request, jar: &CookieJar) -> Request {
    let request = request.header("User-Agent", USER_AGENT);
    if jar.is_empty() {
        request
    } else {
        request.header("Cookie", &jar.header())
    }
}

pub fn logincheck_request(
    base: &str,
    username: &str,
    password: &Secret,
    realm: &str,
    jar: &CookieJar,
) -> Request {
    with_session(
        Request::post_form(
            format!("{base}/remote/logincheck"),
            [
                ("username", username),
                ("credential", password.expose()),
                ("realm", realm),
                ("ajax", "1"),
                ("just_logged_in", "1"),
            ],
        ),
        jar,
    )
}

/// The answer to a token challenge. An empty code for a FortiToken push asks the server to
/// wait for the push approval (`ftmpush=1`).
pub fn token_request(
    base: &str,
    username: &str,
    realm: &str,
    challenge: &TokenChallenge,
    code: &Secret,
    jar: &CookieJar,
) -> Request {
    let push = challenge.token_info.as_deref() == Some("ftm_push") && code.is_empty();
    let mut fields: Vec<(&str, &str)> = vec![
        ("username", username),
        ("code", code.expose()),
        ("realm", realm),
    ];
    fields.extend(
        challenge
            .echo
            .iter()
            .filter(|(k, _)| !(push && k == "magic"))
            .map(|(k, v)| (k.as_str(), v.as_str())),
    );
    if push {
        fields.push(("ftmpush", "1"));
    }
    with_session(
        Request::post_form(format!("{base}{}", challenge.path), fields),
        jar,
    )
}

/// Reads a logincheck answer; `jar` must already hold the answer's cookies.
pub fn parse_logincheck(response: &Response, jar: &CookieJar) -> Result<LoginStep, FortiError> {
    if jar.get(COOKIE_NAME).is_some() {
        return Ok(LoginStep::Done);
    }
    if matches!(response.status, 401 | 403 | 405) {
        return Err(FortiError::AuthFailed("rejected by the server".into()));
    }
    if !response.is_success() {
        return Err(FortiError::Status(response.status));
    }
    let fields = parse_status_line(&response.body);
    let get = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let ret = get("ret");
    if get("tokeninfo").is_some() || (ret.as_deref() == Some("2") && get("reqid").is_some()) {
        let path = get("actionurl")
            .filter(|p| local_path(p))
            .unwrap_or_else(|| "/remote/logincheck".to_string());
        return Ok(LoginStep::NeedToken(TokenChallenge {
            message: get("chal_msg").filter(|m| !m.is_empty()),
            token_info: get("tokeninfo").filter(|m| !m.is_empty()),
            path,
            echo: fields
                .iter()
                .filter(|(k, _)| ECHOED.contains(&k.as_str()))
                .cloned()
                .collect(),
        }));
    }
    if ret.as_deref() == Some("1") {
        return match get("redir").filter(|p| local_path(p)) {
            Some(path) => Ok(LoginStep::Redirect(path)),
            None => Err(FortiError::BadResponse(
                "logged in (ret=1), but the server set no session cookie".into(),
            )),
        };
    }
    let reason = get("redir")
        .and_then(|r| {
            r.split("err=")
                .nth(1)
                .map(|e| e.split('&').next().unwrap_or(e).to_string())
        })
        .unwrap_or_else(|| "wrong username, password or realm".into());
    Err(FortiError::AuthFailed(reason))
}

/// A path on the same server (`/...`, not `//host/...`).
fn local_path(path: &str) -> bool {
    path.starts_with('/') && !path.starts_with("//")
}

/// Splits `key=value,key=value,...`. Values may themselves contain commas (`chal_msg`), so a
/// segment that does not start with `word=` belongs to the previous value.
fn parse_status_line(body: &str) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = Vec::new();
    for segment in body.trim().split(',') {
        let key_value = segment.split_once('=').filter(|(k, _)| {
            !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
        match (key_value, fields.last_mut()) {
            (Some((k, v)), _) => fields.push((k.to_string(), v.to_string())),
            (None, Some((_, previous))) => {
                previous.push(',');
                previous.push_str(segment);
            }
            (None, None) => {}
        }
    }
    fields
}

/// Where a redirect on `base` leads, if it stays on the same server.
fn same_server_path(base: &str, location: &str) -> Option<String> {
    let location = location.trim();
    if local_path(location) {
        return Some(location.to_string());
    }
    let rest = location
        .get(..base.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(base))
        .map(|_| &location[base.len()..])?;
    match rest {
        "" => Some("/".into()),
        r if local_path(r) => Some(r.to_string()),
        _ => None,
    }
}

/// FortiOS 7.4 sends the login page's address in JavaScript: `top.location="/remote/..."`.
fn script_redirect(base: &str, body: &str) -> Option<String> {
    let after = &body[body.find("top.location")? + "top.location".len()..];
    let after = after.trim_start().strip_prefix('=')?.trim_start();
    let quote = after.chars().next().filter(|c| matches!(c, '"' | '\''))?;
    let url = &after[1..];
    same_server_path(base, &url[..url.find(quote)?])
}

/// The value of query parameter `name` in a path.
fn query_value(path: &str, name: &str) -> Option<String> {
    let (_, query) = path.split_once('?')?;
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name && !v.is_empty()).then(|| v.to_string())
    })
}

/// Step 1: the first page, as openconnect fetches it. Returns the realm its address names.
fn first_page(
    transport: &dyn Transport,
    base: &str,
    jar: &mut CookieJar,
) -> Result<Option<String>, FortiError> {
    let mut path = "/".to_string();
    for _ in 0..MAX_REDIRECTS {
        let response = transport.send(&with_session(Request::get(format!("{base}{path}")), jar))?;
        jar.update(&response);
        let next = if (300..400).contains(&response.status) {
            response
                .header("location")
                .and_then(|l| same_server_path(base, l))
        } else {
            script_redirect(base, &response.body)
        };
        match next {
            Some(next) if next != path => path = next,
            _ => break,
        }
    }
    Ok(query_value(&path, "realm"))
}

/// Logs in and returns the session's cookies (a `Cookie` header value with `SVPNCOOKIE`).
/// `realm` empty: the one the server's first page names, if any. `ask_token` is called for
/// each token round.
pub fn login(
    transport: &dyn Transport,
    base: &str,
    username: &str,
    password: &Secret,
    realm: &str,
    ask_token: &mut dyn FnMut(&TokenChallenge) -> Result<Secret, FortiError>,
) -> Result<Secret, FortiError> {
    let mut jar = CookieJar::default();
    let named = first_page(transport, base, &mut jar)?;
    let realm = if realm.is_empty() {
        named.unwrap_or_default()
    } else {
        realm.to_string()
    };
    let mut response =
        transport.send(&logincheck_request(base, username, password, &realm, &jar))?;
    let mut rounds = 0;
    loop {
        jar.update(&response);
        match parse_logincheck(&response, &jar)? {
            LoginStep::Done => return Ok(Secret::new(jar.header())),
            LoginStep::Redirect(path) => {
                let page =
                    transport.send(&with_session(Request::get(format!("{base}{path}")), &jar))?;
                jar.update(&page);
                return if jar.get(COOKIE_NAME).is_some() {
                    Ok(Secret::new(jar.header()))
                } else {
                    Err(FortiError::BadResponse(format!(
                        "logged in (ret=1), but the server set no session cookie, \
                         also not on {path} (HTTP {})",
                        page.status
                    )))
                };
            }
            LoginStep::NeedToken(challenge) => {
                rounds += 1;
                if rounds > MAX_TOKEN_ROUNDS {
                    return Err(FortiError::AuthFailed("too many token attempts".into()));
                }
                let code = ask_token(&challenge)?;
                response = transport.send(&token_request(
                    base, username, &realm, &challenge, &code, &jar,
                ))?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// Built at run time so secret scanners do not mistake test data for a real password.
    fn test_password() -> String {
        ["not", "a", "real", "password"].join("-")
    }

    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;

    struct Script {
        answers: RefCell<VecDeque<Response>>,
        seen: RefCell<Vec<Request>>,
    }

    impl Transport for Script {
        fn send(&self, request: &Request) -> Result<Response, HttpError> {
            self.seen.borrow_mut().push(request.clone());
            Ok(self
                .answers
                .borrow_mut()
                .pop_front()
                .expect("unexpected request"))
        }
    }

    /// The server's answers, after the login page (`GET /`).
    fn script(answers: Vec<Response>) -> Script {
        let mut all = vec![Response::new(200, "<html>login</html>")];
        all.extend(answers);
        Script {
            answers: RefCell::new(all.into()),
            seen: RefCell::new(Vec::new()),
        }
    }

    const BASE: &str = "https://vpn.example.com:10443";

    fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn password_only() {
        let t = script(vec![
            Response::new(200, "ret=1,redir=/remote/fortisslvpn_xml").with_header(
                "Set-Cookie",
                "SVPNCOOKIE=FAKE+cookie/value==; path=/; secure; httponly",
            ),
        ]);
        let cookie = login(
            &t,
            BASE,
            "user",
            &Secret::new(test_password()),
            "",
            &mut |_| panic!("no token expected"),
        )
        .unwrap();
        assert_eq!(cookie.expose(), "SVPNCOOKIE=FAKE+cookie/value==");
        let seen = t.seen.borrow();
        assert_eq!(seen[0].url, "https://vpn.example.com:10443/");
        let check = &seen[1];
        assert_eq!(check.url, "https://vpn.example.com:10443/remote/logincheck");
        assert_eq!(
            check.form(),
            vec![
                ("username".to_string(), "user".to_string()),
                ("credential".to_string(), test_password()),
                ("realm".to_string(), String::new()),
                ("ajax".to_string(), "1".to_string()),
                ("just_logged_in".to_string(), "1".to_string()),
            ]
        );
        for request in seen.iter() {
            assert_eq!(header(request, "User-Agent"), Some(USER_AGENT));
        }
    }

    #[test]
    fn the_first_page_is_followed_and_may_name_the_realm() {
        let t = Script {
            answers: RefCell::new(
                vec![
                    Response::new(302, "")
                        .with_header(
                            "Location",
                            "https://vpn.example.com:10443/remote/login?lang=en",
                        )
                        .with_header("Set-Cookie", "lang=en; path=/"),
                    Response::new(
                        200,
                        "<html><script>top.location=\"/remote/login?realm=staff\";</script></html>",
                    ),
                    Response::new(200, "<html>form</html>"),
                    Response::new(200, "ret=1,redir=/remote/fortisslvpn_xml")
                        .with_header("Set-Cookie", "SVPNCOOKIE=FAKE-cookie; path=/"),
                ]
                .into(),
            ),
            seen: RefCell::new(Vec::new()),
        };
        let cookie = login(&t, BASE, "user", &Secret::new("p"), "", &mut |_| {
            panic!("no token expected")
        })
        .unwrap();
        assert_eq!(cookie.expose(), "lang=en; SVPNCOOKIE=FAKE-cookie");
        let seen = t.seen.borrow();
        assert_eq!(seen[1].url, format!("{BASE}/remote/login?lang=en"));
        assert_eq!(seen[2].url, format!("{BASE}/remote/login?realm=staff"));
        assert_eq!(header(&seen[2], "Cookie"), Some("lang=en"));
        assert_eq!(seen[3].form_value("realm").as_deref(), Some("staff"));
        // Off-server redirects are never followed.
        assert_eq!(same_server_path(BASE, "https://evil.example.net/x"), None);
        assert_eq!(same_server_path(BASE, "//evil.example.net/x"), None);
        assert_eq!(
            script_redirect(BASE, "top.location = 'https://evil.example.net/'"),
            None
        );
    }

    #[test]
    fn a_cookie_on_the_redirect_target_is_taken() {
        let t = script(vec![
            Response::new(200, "ret=1,redir=/remote/hostcheck_validate?x=1"),
            Response::new(200, "<html/>").with_header("Set-Cookie", "SVPNCOOKIE=FAKE-late; path=/"),
        ]);
        let cookie = login(&t, BASE, "user", &Secret::new("p"), "", &mut |_| {
            panic!("no token expected")
        })
        .unwrap();
        assert_eq!(cookie.expose(), "SVPNCOOKIE=FAKE-late");
        assert_eq!(
            t.seen.borrow()[2].url,
            format!("{BASE}/remote/hostcheck_validate?x=1")
        );

        let t = script(vec![
            Response::new(200, "ret=1,redir=/remote/somewhere"),
            Response::new(200, "<html/>"),
        ]);
        let err = login(&t, BASE, "user", &Secret::new("p"), "", &mut |_| {
            panic!("no token expected")
        })
        .unwrap_err();
        assert!(err.to_string().contains("/remote/somewhere"), "{err}");
    }

    #[test]
    fn token_round() {
        let t = script(vec![
            Response::new(
                200,
                "ret=2,actionurl=/remote/logincheck,reqid=42,polid=1-2-3,grp=staff,portal=full,\
                 magic=1-2,tokeninfo=email,chal_msg=Enter the code sent to u***@example.com, then press Login",
            ),
            Response::new(200, "ret=1,redir=/remote/fortisslvpn_xml")
                .with_header("Set-Cookie", "SVPNCOOKIE=FAKE-cookie; path=/"),
        ]);
        let mut asked = Vec::new();
        let cookie = login(
            &t,
            BASE,
            "user",
            &Secret::new(test_password()),
            "staff",
            &mut |c| {
                asked.push((c.message.clone(), c.token_info.clone()));
                Ok(Secret::new("123456"))
            },
        )
        .unwrap();
        assert_eq!(cookie.expose(), "SVPNCOOKIE=FAKE-cookie");
        assert_eq!(
            asked,
            vec![(
                Some("Enter the code sent to u***@example.com, then press Login".into()),
                Some("email".into())
            )]
        );
        let seen = t.seen.borrow();
        let answer = &seen[2];
        assert_eq!(answer.form_value("code").as_deref(), Some("123456"));
        assert_eq!(answer.form_value("reqid").as_deref(), Some("42"));
        assert_eq!(answer.form_value("magic").as_deref(), Some("1-2"));
        assert_eq!(answer.form_value("realm").as_deref(), Some("staff"));
        assert_eq!(answer.form_value("tokeninfo"), None);
        assert_eq!(
            answer.form_value("ajax"),
            None,
            "openconnect sends no ajax here"
        );
        assert_eq!(answer.form_value("ret"), None);
    }

    #[test]
    fn fortitoken_push_is_requested_with_an_empty_code() {
        let t = script(vec![
            Response::new(200, "ret=2,reqid=7,polid=1,magic=9-9,tokeninfo=ftm_push"),
            Response::new(200, "ret=1").with_header("Set-Cookie", "SVPNCOOKIE=FAKE-push; path=/"),
        ]);
        login(&t, BASE, "user", &Secret::new("p"), "", &mut |_| {
            Ok(Secret::new(""))
        })
        .unwrap();
        let seen = t.seen.borrow();
        assert_eq!(seen[2].form_value("ftmpush").as_deref(), Some("1"));
        assert_eq!(seen[2].form_value("magic"), None);
        assert_eq!(seen[2].form_value("reqid").as_deref(), Some("7"));
    }

    #[test]
    fn rejections() {
        let jar = CookieJar::default();
        let wrong = Response::new(
            200,
            "ret=0,redir=/remote/login?&err=sslvpn_login_permission_denied&lang=en",
        );
        assert_eq!(
            parse_logincheck(&wrong, &jar),
            Err(FortiError::AuthFailed(
                "sslvpn_login_permission_denied".into()
            ))
        );
        let empty_cookie = Response::new(200, "ret=0")
            .with_header("Set-Cookie", "SVPNCOOKIE=; expires=Thu, 01 Jan 1970");
        let mut cleared = CookieJar::default();
        cleared.update(&empty_cookie);
        assert!(matches!(
            parse_logincheck(&empty_cookie, &cleared),
            Err(FortiError::AuthFailed(_))
        ));
        assert_eq!(
            parse_logincheck(&Response::new(405, ""), &jar),
            Err(FortiError::AuthFailed("rejected by the server".into()))
        );
        assert_eq!(
            parse_logincheck(&Response::new(500, ""), &jar),
            Err(FortiError::Status(500))
        );
        let offsite = Response::new(200, "ret=2,reqid=1,actionurl=//evil.example.com/x");
        match parse_logincheck(&offsite, &jar).unwrap() {
            LoginStep::NeedToken(c) => assert_eq!(c.path, "/remote/logincheck"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn gives_up_after_repeated_token_requests() {
        let challenge = || Response::new(200, "ret=2,reqid=1,tokeninfo=ftm");
        let t = script(vec![challenge(), challenge(), challenge(), challenge()]);
        let err = login(&t, BASE, "u", &Secret::new("p"), "", &mut |_| {
            Ok(Secret::new("0"))
        })
        .unwrap_err();
        assert_eq!(
            err,
            FortiError::AuthFailed("too many token attempts".into())
        );
    }
}
