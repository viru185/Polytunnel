//! What the client tells the server about itself.

use polytunnel_core::http::Request;
use polytunnel_core::profile::ClientOs;

/// The protocol version GlobalProtect clients announce.
pub const CLIENT_VER: &str = "4100";

/// GlobalProtect servers expect this user agent on protocol requests.
pub const USER_AGENT: &str = "PAN GlobalProtect";

/// Facts about this machine, sent with every request. All values are real by default; only
/// a profile can override the OS or announce an app version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfo {
    pub os: ClientOs,
    /// e.g. `Microsoft Windows 11 Pro , 64-bit`.
    pub os_version: String,
    /// The computer's host name.
    pub computer: String,
    /// A stable random identifier for this installation (not a hardware ID).
    pub host_id: String,
    /// `clientgpversion`, sent only when a profile sets it explicitly.
    pub app_version: Option<String>,
}

impl ClientInfo {
    /// Query string for pre-login requests.
    pub(crate) fn prelogin_query(&self) -> String {
        format!(
            "tmp=tmp&clientVer={CLIENT_VER}&clientos={}",
            self.os.gp_name()
        )
    }

    /// Fields common to every form the client posts.
    pub(crate) fn base_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("clientVer", CLIENT_VER.to_string()),
            ("clientos", self.os.gp_name().to_string()),
            ("os-version", self.os_version.clone()),
            ("computer", self.computer.clone()),
            ("ipv6-support", "yes".to_string()),
        ];
        if let Some(version) = &self.app_version {
            fields.push(("clientgpversion", version.clone()));
        }
        fields
    }
}

/// A form POST with the GlobalProtect user agent.
pub(crate) fn post(url: String, fields: &[(&str, String)]) -> Request {
    Request::post_form(url, fields.iter().map(|(k, v)| (*k, v.as_str())))
        .header("User-Agent", USER_AGENT)
}

#[cfg(test)]
pub(crate) fn test_client() -> ClientInfo {
    ClientInfo {
        os: ClientOs::Windows,
        os_version: "Microsoft Windows 11 Pro , 64-bit".into(),
        computer: "WORKSTATION-1".into(),
        host_id: "00000000-0000-4000-8000-000000000001".into(),
        app_version: None,
    }
}
