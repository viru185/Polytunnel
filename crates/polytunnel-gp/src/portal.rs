//! Portal configuration: the gateway list and the portal's reusable cookies.

use polytunnel_core::Secret;
use polytunnel_core::http::{Request, Response};
use polytunnel_core::profile::normalize_server;
use polytunnel_core::xml::Element;

use crate::client::{self, ClientInfo};
use crate::error::GpError;

/// What proves the user's identity to the portal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortalAuth {
    Password(Secret),
    /// From a SAML login.
    PreloginCookie(Secret),
    /// A reusable portal cookie (from an earlier login or straight from SAML).
    PortalCookie(Secret),
}

/// A gateway as listed by the portal.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Gateway {
    /// `https://host[:port]`.
    pub address: String,
    /// What the portal calls it (often a site name), if anything.
    pub description: Option<String>,
    /// Default priority (lower number = preferred). `None` when not given.
    pub priority: Option<u32>,
    /// Per-source-region priorities: `("US", 1)`, `("Any", 3)`.
    pub priority_rules: Vec<(String, u32)>,
    /// Only used when the user picks it explicitly.
    pub manual: bool,
    /// Listed under the internal gateways (used inside the corporate network).
    pub internal: bool,
}

impl Gateway {
    /// Host part of [`Gateway::address`].
    pub fn host(&self) -> &str {
        host_of(&self.address)
    }

    /// The description, or the host when there is none.
    pub fn label(&self) -> &str {
        self.description.as_deref().unwrap_or_else(|| self.host())
    }
}

/// `https://host[:port]` -> `host[:port]`.
pub fn host_of(base: &str) -> &str {
    base.strip_prefix("https://").unwrap_or(base)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PortalConfig {
    pub gateways: Vec<Gateway>,
    pub portal_userauthcookie: Option<Secret>,
    pub portal_prelogonuserauthcookie: Option<Secret>,
    /// Seconds the client waits for gateway responses when picking the best one.
    pub cutoff_time: Option<u32>,
}

pub fn request(base: &str, client: &ClientInfo, username: &str, auth: &PortalAuth) -> Request {
    let url = format!("{base}/global-protect/getconfig.esp");
    let mut fields = vec![
        ("prot", "https:".to_string()),
        ("server", host_of(base).to_string()),
        ("inputStr", String::new()),
        ("jnlpReady", "jnlpReady".to_string()),
        ("ok", "Login".to_string()),
        ("direct", "yes".to_string()),
        ("internal", "no".to_string()),
        ("host-id", client.host_id.clone()),
        ("user", username.to_string()),
    ];
    fields.extend(client.base_fields());
    match auth {
        PortalAuth::Password(password) => fields.push(("passwd", password.expose().to_string())),
        PortalAuth::PreloginCookie(cookie) => {
            fields.push(("passwd", String::new()));
            fields.push(("prelogin-cookie", cookie.expose().to_string()));
        }
        PortalAuth::PortalCookie(cookie) => {
            fields.push(("passwd", String::new()));
            fields.push(("portal-userauthcookie", cookie.expose().to_string()));
        }
    }
    client::post(url, &fields)
}

pub fn parse(response: &Response) -> Result<PortalConfig, GpError> {
    const STEP: &str = "portal configuration";
    match response.status {
        200 => {}
        512 | 401 | 403 => {
            return Err(GpError::AuthFailed(
                first_line(&response.body)
                    .unwrap_or("rejected by the portal")
                    .to_string(),
            ));
        }
        status => return Err(GpError::Status { step: STEP, status }),
    }
    let root =
        Element::parse(&response.body).map_err(|e| GpError::not_xml(STEP, &response.body, e))?;
    if root.name == "response" && root.attr("status") == Some("error") {
        let msg = root.text_at("error").unwrap_or("unknown error").to_string();
        return Err(GpError::Server(msg));
    }
    if root.name != "policy" {
        return Err(GpError::BadResponse {
            step: STEP,
            detail: format!("expected <policy>, got <{}>", root.name),
        });
    }

    let mut gateways = Vec::new();
    for (section, internal) in [("external", false), ("internal", true)] {
        let Some(list) = root.path(&format!("gateways/{section}/list")) else {
            continue;
        };
        for entry in list.children_named("entry") {
            if let Some(gw) = parse_gateway(entry, internal) {
                gateways.push(gw);
            }
        }
    }

    Ok(PortalConfig {
        gateways,
        portal_userauthcookie: cookie(&root, "portal-userauthcookie"),
        portal_prelogonuserauthcookie: cookie(&root, "portal-prelogonuserauthcookie"),
        cutoff_time: root
            .text_at("gateways/cutoff-time")
            .and_then(|t| t.parse().ok()),
    })
}

fn parse_gateway(entry: &Element, internal: bool) -> Option<Gateway> {
    let name = entry.attr("name")?.trim();
    let address = normalize_server(name).ok()?;
    let priority_rules = entry
        .path("priority-rule")
        .map(|rules| {
            rules
                .children_named("entry")
                .filter_map(|rule| {
                    let region = rule.attr("name")?.trim().to_string();
                    let priority = rule.text_at("priority")?.parse().ok()?;
                    Some((region, priority))
                })
                .collect()
        })
        .unwrap_or_default();
    Some(Gateway {
        address,
        description: entry.text_at("description").map(str::to_string),
        priority: entry.text_at("priority").and_then(|p| p.parse().ok()),
        priority_rules,
        manual: entry
            .text_at("manual")
            .is_some_and(|m| m.eq_ignore_ascii_case("yes")),
        internal,
    })
}

fn cookie(root: &Element, name: &str) -> Option<Secret> {
    root.text_at(name)
        .filter(|v| !v.eq_ignore_ascii_case("empty"))
        .map(Secret::new)
}

fn first_line(body: &str) -> Option<&str> {
    body.lines().map(str::trim).find(|l| !l.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_client;

    const CONFIG: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<policy>
  <portal-name>vpn</portal-name>
  <portal-userauthcookie>FAKE-portal-cookie</portal-userauthcookie>
  <portal-prelogonuserauthcookie>empty</portal-prelogonuserauthcookie>
  <gateways>
    <cutoff-time>5</cutoff-time>
    <external>
      <list>
        <entry name="gw-east.example.com">
          <priority-rule>
            <entry name="US"><priority>1</priority></entry>
            <entry name="Any"><priority>3</priority></entry>
          </priority-rule>
          <priority>3</priority>
          <description>US East</description>
        </entry>
        <entry name="gw-manual.example.com:8443">
          <manual>yes</manual>
          <description>Lab</description>
        </entry>
        <entry name="bad host"><description>ignored</description></entry>
      </list>
    </external>
    <internal>
      <list><entry name="192.0.2.10"/></list>
    </internal>
  </gateways>
</policy>"#;

    #[test]
    fn parses_gateways_and_cookies() {
        let config = parse(&Response::new(200, CONFIG)).unwrap();
        assert_eq!(config.cutoff_time, Some(5));
        assert_eq!(
            config.portal_userauthcookie,
            Some(Secret::new("FAKE-portal-cookie"))
        );
        assert_eq!(config.portal_prelogonuserauthcookie, None);
        assert_eq!(config.gateways.len(), 3);
        let east = &config.gateways[0];
        assert_eq!(east.address, "https://gw-east.example.com");
        assert_eq!(east.label(), "US East");
        assert_eq!(east.priority, Some(3));
        assert_eq!(
            east.priority_rules,
            vec![("US".to_string(), 1), ("Any".to_string(), 3)]
        );
        let manual = &config.gateways[1];
        assert!(manual.manual);
        assert_eq!(manual.host(), "gw-manual.example.com:8443");
        let internal = &config.gateways[2];
        assert!(internal.internal);
        assert_eq!(internal.label(), "192.0.2.10");
    }

    #[test]
    fn builds_the_request() {
        let req = request(
            "https://portal.example.com",
            &test_client(),
            "user@example.com",
            &PortalAuth::PreloginCookie(Secret::new("FAKE-prelogin")),
        );
        assert_eq!(
            req.url,
            "https://portal.example.com/global-protect/getconfig.esp"
        );
        assert_eq!(
            req.form_value("prelogin-cookie").as_deref(),
            Some("FAKE-prelogin")
        );
        assert_eq!(req.form_value("passwd").as_deref(), Some(""));
        assert_eq!(
            req.form_value("server").as_deref(),
            Some("portal.example.com")
        );
        assert_eq!(req.form_value("user").as_deref(), Some("user@example.com"));
    }

    #[test]
    fn errors() {
        assert!(matches!(
            parse(&Response::new(512, "Invalid username or password\n")),
            Err(GpError::AuthFailed(m)) if m == "Invalid username or password"
        ));
        assert_eq!(
            parse(&Response::new(
                200,
                "<response status=\"error\"><error>Portal is disabled</error></response>"
            )),
            Err(GpError::Server("Portal is disabled".into()))
        );
        assert!(matches!(
            parse(&Response::new(200, "<html/>")),
            Err(GpError::BadResponse { .. })
        ));
    }
}
