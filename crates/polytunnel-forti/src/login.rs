//! FortiGate SSL VPN login.
//!
//! `POST /remote/logincheck` with the username, password and realm answers with a short
//! comma-separated status line:
//!
//! * `ret=1,redir=...` plus a `Set-Cookie: SVPNCOOKIE=...`: logged in;
//! * `ret=2,...,reqid=...,polid=...,tokeninfo=...,chal_msg=...`: a token / one-time code is
//!   required; the same fields go back with the code;
//! * anything else (or an empty cookie): rejected.

use std::fmt;

use polytunnel_core::Secret;
use polytunnel_core::http::{HttpError, Request, Response, Transport};

/// The session cookie's name.
pub const COOKIE_NAME: &str = "SVPNCOOKIE";

/// Token rounds allowed before giving up (FortiGate may ask again after a wrong code).
pub const MAX_TOKEN_ROUNDS: usize = 3;

const USER_AGENT: &str = concat!("Mozilla/5.0 Polytunnel/", env!("CARGO_PKG_VERSION"));

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
    Done { cookie: Secret },
    NeedToken(TokenChallenge),
}

pub fn logincheck_request(base: &str, username: &str, password: &Secret, realm: &str) -> Request {
    Request::post_form(
        format!("{base}/remote/logincheck"),
        [
            ("ajax", "1"),
            ("username", username),
            ("realm", realm),
            ("credential", password.expose()),
        ],
    )
    .header("User-Agent", USER_AGENT)
}

pub fn token_request(
    base: &str,
    username: &str,
    realm: &str,
    challenge: &TokenChallenge,
    code: &Secret,
) -> Request {
    let mut fields: Vec<(&str, &str)> =
        vec![("ajax", "1"), ("username", username), ("realm", realm)];
    fields.extend(challenge.echo.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    fields.push(("code", code.expose()));
    fields.push(("code2", ""));
    Request::post_form(format!("{base}{}", challenge.path), fields).header("User-Agent", USER_AGENT)
}

pub fn parse_logincheck(response: &Response) -> Result<LoginStep, FortiError> {
    if let Some(cookie) = response.set_cookie(COOKIE_NAME).filter(|c| !c.is_empty()) {
        return Ok(LoginStep::Done {
            cookie: Secret::new(cookie),
        });
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
    match get("ret").as_deref() {
        Some("2") | None if get("reqid").is_some() || get("tokeninfo").is_some() => {
            let path = get("actionurl")
                .filter(|p| p.starts_with('/') && !p.starts_with("//"))
                .unwrap_or_else(|| "/remote/logincheck".to_string());
            const NOT_ECHOED: &[&str] = &["ret", "actionurl", "tokeninfo", "chal_msg", "redir"];
            Ok(LoginStep::NeedToken(TokenChallenge {
                message: get("chal_msg").filter(|m| !m.is_empty()),
                token_info: get("tokeninfo").filter(|m| !m.is_empty()),
                path,
                echo: fields
                    .iter()
                    .filter(|(k, _)| !NOT_ECHOED.contains(&k.as_str()))
                    .cloned()
                    .collect(),
            }))
        }
        Some("1") => Err(FortiError::BadResponse(
            "logged in but no session cookie was set".into(),
        )),
        _ => {
            let reason = get("redir")
                .and_then(|r| {
                    r.split("err=")
                        .nth(1)
                        .map(|e| e.split('&').next().unwrap_or(e).to_string())
                })
                .unwrap_or_else(|| "wrong username, password or realm".into());
            Err(FortiError::AuthFailed(reason))
        }
    }
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

/// Logs in and returns the `SVPNCOOKIE` value. `ask_token` is called for each token round.
pub fn login(
    transport: &dyn Transport,
    base: &str,
    username: &str,
    password: &Secret,
    realm: &str,
    ask_token: &mut dyn FnMut(&TokenChallenge) -> Result<Secret, FortiError>,
) -> Result<Secret, FortiError> {
    let mut step =
        parse_logincheck(&transport.send(&logincheck_request(base, username, password, realm))?)?;
    for _ in 0..MAX_TOKEN_ROUNDS {
        match step {
            LoginStep::Done { cookie } => return Ok(cookie),
            LoginStep::NeedToken(challenge) => {
                let code = ask_token(&challenge)?;
                let request = token_request(base, username, realm, &challenge, &code);
                step = parse_logincheck(&transport.send(&request)?)?;
            }
        }
    }
    match step {
        LoginStep::Done { cookie } => Ok(cookie),
        LoginStep::NeedToken(_) => Err(FortiError::AuthFailed("too many token attempts".into())),
    }
}

#[cfg(test)]
mod tests {
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

    fn script(answers: Vec<Response>) -> Script {
        Script {
            answers: RefCell::new(answers.into()),
            seen: RefCell::new(Vec::new()),
        }
    }

    const BASE: &str = "https://vpn.example.com:10443";

    #[test]
    fn password_only() {
        let t = script(vec![
            Response::new(200, "ret=1,redir=/remote/fortisslvpn_xml").with_header(
                "Set-Cookie",
                "SVPNCOOKIE=FAKE+cookie/value==; path=/; secure; httponly",
            ),
        ]);
        let cookie = login(&t, BASE, "user", &Secret::new("FAKE-pw"), "", &mut |_| {
            panic!("no token expected")
        })
        .unwrap();
        assert_eq!(cookie.expose(), "FAKE+cookie/value==");
        let seen = t.seen.borrow();
        assert_eq!(
            seen[0].url,
            "https://vpn.example.com:10443/remote/logincheck"
        );
        assert_eq!(seen[0].form_value("credential").as_deref(), Some("FAKE-pw"));
        assert_eq!(seen[0].form_value("ajax").as_deref(), Some("1"));
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
            &Secret::new("FAKE-pw"),
            "staff",
            &mut |c| {
                asked.push((c.message.clone(), c.token_info.clone()));
                Ok(Secret::new("123456"))
            },
        )
        .unwrap();
        assert_eq!(cookie.expose(), "FAKE-cookie");
        assert_eq!(
            asked,
            vec![(
                Some("Enter the code sent to u***@example.com, then press Login".into()),
                Some("email".into())
            )]
        );
        let seen = t.seen.borrow();
        let answer = &seen[1];
        assert_eq!(answer.form_value("code").as_deref(), Some("123456"));
        assert_eq!(answer.form_value("reqid").as_deref(), Some("42"));
        assert_eq!(answer.form_value("magic").as_deref(), Some("1-2"));
        assert_eq!(answer.form_value("realm").as_deref(), Some("staff"));
        assert_eq!(answer.form_value("tokeninfo"), None);
    }

    #[test]
    fn rejections() {
        let wrong = Response::new(
            200,
            "ret=0,redir=/remote/login?&err=sslvpn_login_permission_denied&lang=en",
        );
        assert_eq!(
            parse_logincheck(&wrong),
            Err(FortiError::AuthFailed(
                "sslvpn_login_permission_denied".into()
            ))
        );
        let empty_cookie = Response::new(200, "ret=0")
            .with_header("Set-Cookie", "SVPNCOOKIE=; expires=Thu, 01 Jan 1970");
        assert!(matches!(
            parse_logincheck(&empty_cookie),
            Err(FortiError::AuthFailed(_))
        ));
        assert_eq!(
            parse_logincheck(&Response::new(405, "")),
            Err(FortiError::AuthFailed("rejected by the server".into()))
        );
        assert_eq!(
            parse_logincheck(&Response::new(500, "")),
            Err(FortiError::Status(500))
        );
        let offsite = Response::new(200, "ret=2,reqid=1,actionurl=//evil.example.com/x");
        match parse_logincheck(&offsite).unwrap() {
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
