//! A minimal HTTP abstraction for the protocol crates.
//!
//! The protocol crates build [`Request`]s and parse [`Response`]s; the program that uses them
//! supplies a [`Transport`] that actually talks to the network. Tests supply a fake one, so
//! every login flow can be exercised without a server.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    /// Absolute `https://` URL.
    pub url: String,
    pub headers: Vec<(String, String)>,
    /// `application/x-www-form-urlencoded` body for POST requests.
    pub body: Option<String>,
}

impl Request {
    pub fn get(url: impl Into<String>) -> Self {
        Request {
            method: Method::Get,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// A POST with a form-encoded body built from `fields` (in order).
    pub fn post_form<'a>(
        url: impl Into<String>,
        fields: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        let mut form = form_urlencoded::Serializer::new(String::new());
        for (name, value) in fields {
            form.append_pair(name, value);
        }
        Request {
            method: Method::Post,
            url: url.into(),
            headers: vec![(
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            body: Some(form.finish()),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// The decoded form fields of the body (for tests and fake transports).
    pub fn form(&self) -> Vec<(String, String)> {
        self.body
            .as_deref()
            .map(|body| {
                form_urlencoded::parse(body.as_bytes())
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// One decoded form field.
    pub fn form_value(&self, name: &str) -> Option<String> {
        self.form()
            .into_iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    }
}

/// Bodies carry passwords and cookies: `Debug` shows only the method and URL path.
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = self.url.split('?').next().unwrap_or_default();
        write!(f, "{:?} {path}", self.method)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Response {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// The first header called `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every header called `name` (case-insensitive), e.g. several `Set-Cookie`.
    pub fn headers_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The value of cookie `name` from the `Set-Cookie` headers: the last one wins, as in a
    /// browser (servers may clear a cookie before setting it again).
    pub fn set_cookie(&self, name: &str) -> Option<String> {
        self.set_cookies()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v)
            .last()
    }

    /// Every `(name, value)` from the `Set-Cookie` headers, in order.
    pub fn set_cookies(&self) -> impl Iterator<Item = (String, String)> + '_ {
        self.headers_all("set-cookie").filter_map(|header| {
            let pair = header.split(';').next()?.trim();
            let (k, v) = pair.split_once('=')?;
            let k = k.trim();
            (!k.is_empty()).then(|| (k.to_string(), v.trim().to_string()))
        })
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP {} ({} bytes)", self.status, self.body.len())
    }
}

/// A transport failure (DNS, TCP, TLS, timeout). HTTP error statuses are not errors here:
/// they come back as a [`Response`] for the protocol code to interpret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError(pub String);

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HttpError {}

/// Sends requests. Implementations must verify TLS certificates against the operating
/// system's trust store and must not follow redirects (the protocols need to see them).
pub trait Transport {
    fn send(&self, request: &Request) -> Result<Response, HttpError>;
}

/// The cookies a server has set during one session, as a browser keeps them: the last
/// `Set-Cookie` for a name wins, and an empty value deletes the cookie.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct CookieJar(Vec<(String, String)>);

impl CookieJar {
    /// From a `Cookie` header value (`a=1; b=2`).
    pub fn from_header(header: &str) -> Self {
        let mut jar = CookieJar::default();
        for pair in header.split(';') {
            if let Some((k, v)) = pair.split_once('=') {
                jar.set(k.trim(), v.trim());
            }
        }
        jar
    }

    fn set(&mut self, name: &str, value: &str) {
        self.0.retain(|(k, _)| k != name);
        if !value.is_empty() {
            self.0.push((name.to_string(), value.to_string()));
        }
    }

    /// Takes in the cookies a response sets.
    pub fn update(&mut self, response: &Response) {
        for (name, value) in response.set_cookies() {
            self.set(&name, &value);
        }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The `Cookie` header value.
    pub fn header(&self) -> String {
        self.0
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Cookie values are secrets: only the names are shown.
impl fmt::Debug for CookieJar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(k, _)| k))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_jar_keeps_cookies_like_a_browser() {
        let mut jar = CookieJar::from_header("lang=en; SVPNCOOKIE=old");
        let res = Response::new(200, "")
            .with_header(
                "Set-Cookie",
                "SVPNCOOKIE=; path=/; expires=Thu, 01 Jan 1970",
            )
            .with_header("Set-Cookie", "SVPNCOOKIE=new; path=/; secure")
            .with_header("Set-Cookie", "lang=; path=/");
        jar.update(&res);
        assert_eq!(jar.get("SVPNCOOKIE"), Some("new"));
        assert_eq!(jar.get("lang"), None, "an empty value deletes");
        assert_eq!(jar.header(), "SVPNCOOKIE=new");
        assert_eq!(format!("{jar:?}"), "[\"SVPNCOOKIE\"]");
        assert_eq!(
            res.set_cookie("SVPNCOOKIE").as_deref(),
            Some("new"),
            "last wins"
        );
    }

    #[test]
    fn form_bodies_round_trip() {
        let req = Request::post_form(
            "https://vpn.example.com/x?y=1",
            [("user", "a b&c"), ("passwd", "")],
        );
        assert_eq!(req.body.as_deref(), Some("user=a+b%26c&passwd="));
        assert_eq!(req.form_value("user").as_deref(), Some("a b&c"));
        assert_eq!(format!("{req:?}"), "Post https://vpn.example.com/x");
    }

    #[test]
    fn cookies_are_read_from_set_cookie() {
        let res = Response::new(200, "ret=1")
            .with_header("Set-Cookie", "other=1; path=/")
            .with_header("set-cookie", "SVPNCOOKIE=FAKE+value==; path=/; secure");
        assert_eq!(
            res.set_cookie("SVPNCOOKIE").as_deref(),
            Some("FAKE+value==")
        );
        assert_eq!(res.set_cookie("missing"), None);
    }
}
