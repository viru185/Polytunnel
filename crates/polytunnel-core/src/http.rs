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

    /// The value of cookie `name` from the `Set-Cookie` headers.
    pub fn set_cookie(&self, name: &str) -> Option<String> {
        self.headers_all("set-cookie").find_map(|header| {
            let pair = header.split(';').next()?.trim();
            let (k, v) = pair.split_once('=')?;
            (k.trim() == name).then(|| v.trim().to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

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
