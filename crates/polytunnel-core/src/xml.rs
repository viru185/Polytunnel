//! A small, strict-enough XML reader for VPN server responses.
//!
//! VPN portals answer with short, simple XML documents. This reader builds a tiny element tree
//! and deliberately supports only what those documents use:
//!
//! * elements, attributes, text and CDATA;
//! * the five predefined entities and numeric character references;
//! * comments, processing instructions and a DOCTYPE are skipped. Entities declared in a
//!   DOCTYPE are **never** expanded, so entity-expansion attacks cannot happen;
//! * nesting is limited to [`MAX_DEPTH`] levels.
//!
//! It never panics on bad input; malformed documents return an [`XmlError`].

use std::fmt;

/// Deepest element nesting accepted.
pub const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Element {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Element>,
    /// The element's own text (CDATA included), concatenated, not trimmed.
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlError {
    pub message: String,
    pub offset: usize,
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at byte {})", self.message, self.offset)
    }
}

impl std::error::Error for XmlError {}

impl Element {
    /// Parses a document and returns its root element. Anything after the root is ignored.
    pub fn parse(document: &str) -> Result<Element, XmlError> {
        let mut parser = Parser {
            src: document.strip_prefix('\u{feff}').unwrap_or(document),
            pos: 0,
        };
        parser.skip_misc()?;
        if !parser.rest().starts_with('<') {
            return Err(parser.error("expected an XML element"));
        }
        parser.element(0)
    }

    /// The first child called `name`.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    /// All children called `name`.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// The descendant at a `/`-separated path of child names, e.g. `gateways/external/list`.
    pub fn path(&self, path: &str) -> Option<&Element> {
        path.split('/')
            .filter(|p| !p.is_empty())
            .try_fold(self, |el, name| el.child(name))
    }

    /// Trimmed text at `path`, or `None` if missing or empty.
    pub fn text_at(&self, path: &str) -> Option<&str> {
        self.path(path)
            .map(|el| el.text.trim())
            .filter(|t| !t.is_empty())
    }

    /// The value of attribute `name`.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

struct Parser<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    fn error(&self, message: &str) -> XmlError {
        XmlError {
            message: message.to_string(),
            offset: self.pos,
        }
    }

    fn skip_ws(&mut self) {
        let rest = self.rest();
        self.pos += rest.len() - rest.trim_start().len();
    }

    /// Skips the text up to and including `end`.
    fn skip_past(&mut self, end: &str, what: &str) -> Result<(), XmlError> {
        match self.rest().find(end) {
            Some(i) => {
                self.pos += i + end.len();
                Ok(())
            }
            None => Err(self.error(&format!("unterminated {what}"))),
        }
    }

    /// Whitespace, comments, processing instructions and DOCTYPE between markup.
    fn skip_misc(&mut self) -> Result<(), XmlError> {
        loop {
            self.skip_ws();
            let rest = self.rest();
            if rest.starts_with("<?") {
                self.skip_past("?>", "processing instruction")?;
            } else if rest.starts_with("<!--") {
                self.skip_past("-->", "comment")?;
            } else if rest.starts_with("<!DOCTYPE") || rest.starts_with("<!doctype") {
                self.skip_doctype()?;
            } else {
                return Ok(());
            }
        }
    }

    fn skip_doctype(&mut self) -> Result<(), XmlError> {
        let mut depth = 0usize;
        for (i, c) in self.rest().char_indices() {
            match c {
                '[' => depth += 1,
                ']' => depth = depth.saturating_sub(1),
                '>' if depth == 0 => {
                    self.pos += i + 1;
                    return Ok(());
                }
                _ => {}
            }
        }
        Err(self.error("unterminated DOCTYPE"))
    }

    fn name(&mut self) -> Result<String, XmlError> {
        let rest = self.rest();
        let len = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '>' | '=' | '<'))
            .unwrap_or(rest.len());
        if len == 0 {
            return Err(self.error("expected a name"));
        }
        self.pos += len;
        Ok(rest[..len].to_string())
    }

    fn element(&mut self, depth: usize) -> Result<Element, XmlError> {
        if depth >= MAX_DEPTH {
            return Err(self.error("elements nested too deeply"));
        }
        self.pos += 1; // '<'
        let mut el = Element {
            name: self.name()?,
            ..Element::default()
        };
        // attributes
        loop {
            self.skip_ws();
            let rest = self.rest();
            if let Some(after) = rest.strip_prefix("/>") {
                let _ = after;
                self.pos += 2;
                return Ok(el);
            }
            if rest.starts_with('>') {
                self.pos += 1;
                break;
            }
            if rest.is_empty() {
                return Err(self.error("unterminated start tag"));
            }
            let key = self.name()?;
            self.skip_ws();
            if !self.rest().starts_with('=') {
                return Err(self.error("expected '=' after attribute name"));
            }
            self.pos += 1;
            self.skip_ws();
            let quote = self
                .rest()
                .chars()
                .next()
                .filter(|q| *q == '"' || *q == '\'')
                .ok_or_else(|| self.error("expected a quoted attribute value"))?;
            self.pos += 1;
            let end = self
                .rest()
                .find(quote)
                .ok_or_else(|| self.error("unterminated attribute value"))?;
            let raw = &self.rest()[..end];
            self.pos += end + 1;
            el.attrs.push((key, decode_entities(raw)));
        }
        // content
        loop {
            let rest = self.rest();
            let next = rest.find('<').unwrap_or(rest.len());
            if next > 0 {
                el.text.push_str(&decode_entities(&rest[..next]));
                self.pos += next;
            }
            let rest = self.rest();
            if rest.is_empty() {
                return Err(self.error(&format!("missing </{}>", el.name)));
            } else if rest.starts_with("</") {
                self.pos += 2;
                let name = self.name()?;
                if name != el.name {
                    return Err(self.error(&format!("expected </{}>, found </{name}>", el.name)));
                }
                self.skip_ws();
                if !self.rest().starts_with('>') {
                    return Err(self.error("bad end tag"));
                }
                self.pos += 1;
                return Ok(el);
            } else if let Some(cdata) = rest.strip_prefix("<![CDATA[") {
                let end = cdata
                    .find("]]>")
                    .ok_or_else(|| self.error("unterminated CDATA"))?;
                el.text.push_str(&cdata[..end]);
                self.pos += "<![CDATA[".len() + end + "]]>".len();
            } else if rest.starts_with("<!--") {
                self.skip_past("-->", "comment")?;
            } else if rest.starts_with("<?") {
                self.skip_past("?>", "processing instruction")?;
            } else {
                let child = self.element(depth + 1)?;
                el.children.push(child);
            }
        }
    }
}

/// Decodes the predefined entities and numeric references; unknown entities stay as written.
pub fn decode_entities(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let decoded = rest.find(';').filter(|&semi| semi <= 12).and_then(|semi| {
            let entity = &rest[1..semi];
            let ch = match entity {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                    .map(|hex| u32::from_str_radix(hex, 16))
                    .or_else(|| entity.strip_prefix('#').map(str::parse::<u32>))
                    .and_then(Result::ok)
                    .and_then(char::from_u32),
            };
            ch.map(|c| (c, semi))
        });
        match decoded {
            Some((c, semi)) => {
                out.push(c);
                rest = &rest[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_typical_response() {
        let doc = r#"<?xml version="1.0" encoding="UTF-8" ?>
<!-- comment -->
<prelogin-response>
  <status>Success</status>
  <saml-request><![CDATA[aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20v]]></saml-request>
  <msg>a &amp; b &lt;c&gt; &#65;&#x42;</msg>
  <empty/>
  <entry name="gw1.example.com" note='x &quot;y&quot;'><priority>1</priority></entry>
</prelogin-response>
trailing junk ignored"#;
        let root = Element::parse(doc).unwrap();
        assert_eq!(root.name, "prelogin-response");
        assert_eq!(root.text_at("status"), Some("Success"));
        assert_eq!(
            root.text_at("saml-request"),
            Some("aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20v")
        );
        assert_eq!(root.text_at("msg"), Some("a & b <c> AB"));
        assert_eq!(root.text_at("empty"), None);
        let entry = root.child("entry").unwrap();
        assert_eq!(entry.attr("name"), Some("gw1.example.com"));
        assert_eq!(entry.attr("note"), Some("x \"y\""));
        assert_eq!(root.text_at("entry/priority"), Some("1"));
    }

    #[test]
    fn doctype_entities_are_not_expanded() {
        let doc = r#"<!DOCTYPE x [<!ENTITY a "aaaaaaaa"><!ENTITY b "&a;&a;&a;">]><x>&b;</x>"#;
        assert_eq!(Element::parse(doc).unwrap().text, "&b;");
    }

    #[test]
    fn malformed_documents_are_errors_not_panics() {
        for doc in [
            "",
            "not xml",
            "<a>",
            "<a></b>",
            "<a x=1></a>",
            "<a x=\"1></a>",
            "<a><![CDATA[x</a>",
            "<a><!-- x</a>",
            "<",
            "<a/",
            "<a b",
            "<\u{e9}t\u{e9}>caf\u{e9}</\u{e9}t\u{e9}", // multi-byte names, missing '>'
        ] {
            assert!(Element::parse(doc).is_err(), "{doc:?}");
        }
        let deep = "<a>".repeat(MAX_DEPTH + 1);
        assert!(Element::parse(&deep).is_err());
    }

    #[test]
    fn multibyte_text_is_kept() {
        let root = Element::parse("<r><m>caf\u{e9} \u{2014} ok</m></r>").unwrap();
        assert_eq!(root.text_at("m"), Some("caf\u{e9} \u{2014} ok"));
    }

    #[test]
    fn unknown_entities_stay_literal() {
        assert_eq!(
            decode_entities("&nbsp; &#xZZ; & &amp;"),
            "&nbsp; &#xZZ; & &"
        );
    }
}
