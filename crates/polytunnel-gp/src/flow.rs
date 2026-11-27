//! The whole login: portal, gateway choice, gateway session.

use polytunnel_core::Secret;
use polytunnel_core::http::Transport;
use polytunnel_core::profile::normalize_server;

use crate::client::ClientInfo;
use crate::error::GpError;
use crate::login::{self, GatewayAuth, GatewaySession};
use crate::portal::{self, Gateway, PortalAuth, PortalConfig};
use crate::prelogin::{self, Interface, Prelogin, SamlRequest};
use crate::sso::SsoResult;

/// Labels for a password prompt, as sent by the server.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PasswordPrompt {
    pub message: Option<String>,
    pub username_label: String,
    pub password_label: String,
    /// Pre-filled username (from the profile or an earlier step).
    pub username: Option<String>,
}

/// The user-facing side of a login: browser SSO, password prompts and progress messages.
pub trait Prompter {
    /// Shows the SAML login (`server` is `https://host`) and returns its result.
    fn saml(
        &mut self,
        iface: Interface,
        server: &str,
        request: &SamlRequest,
    ) -> Result<SsoResult, GpError>;

    /// Asks for a username and password.
    fn password(
        &mut self,
        iface: Interface,
        server: &str,
        prompt: &PasswordPrompt,
    ) -> Result<(String, Secret), GpError>;

    /// A short progress message ("Contacting the portal...").
    fn progress(&mut self, _message: &str) {}

    /// Picks the gateway when the user did not name one. `Ok(None)`: use the default
    /// [`choose_gateway`]. Implementations usually probe the gateways and call
    /// [`crate::rank::rank`].
    fn select_gateway(&mut self, _portal: &PortalSession) -> Result<Option<Gateway>, GpError> {
        Ok(None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoginOptions {
    /// Portal address in any form [`normalize_server`] accepts.
    pub portal: String,
    pub username: Option<String>,
    /// Gateway to use: address, host or description. `None`: [`Prompter::select_gateway`]
    /// (or [`choose_gateway`]) picks one.
    pub gateway: Option<String>,
    /// Ask the portal for the system-browser SAML flow.
    pub default_browser: bool,
}

/// A logged-in portal: who the user is and which gateways they may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalSession {
    /// `https://host[:port]` of the portal.
    pub portal: String,
    /// The portal's source-region verdict for this client.
    pub region: Option<String>,
    pub username: String,
    pub config: PortalConfig,
    /// The typed password, if any (gateways often accept the same one).
    password: Option<Secret>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginResult {
    pub portal: String,
    /// The portal's source-region verdict for this client.
    pub region: Option<String>,
    pub config: PortalConfig,
    pub gateway: Gateway,
    pub session: GatewaySession,
}

/// The whole login: portal, gateway choice, gateway session.
pub fn login(
    transport: &dyn Transport,
    client: &ClientInfo,
    options: &LoginOptions,
    prompter: &mut dyn Prompter,
) -> Result<LoginResult, GpError> {
    let portal = portal_login(transport, client, options, prompter)?;
    let gateway = match options.gateway.as_deref() {
        Some(wanted) => choose_gateway(&portal.portal, &portal.config, Some(wanted))?,
        None => match prompter.select_gateway(&portal)? {
            Some(gateway) => gateway,
            None => choose_gateway(&portal.portal, &portal.config, None)?,
        },
    };
    let session = connect_gateway(transport, client, options, prompter, &portal, &gateway)?;
    Ok(LoginResult {
        portal: portal.portal,
        region: portal.region,
        config: portal.config,
        gateway,
        session,
    })
}

/// Logs in to the portal and fetches its configuration (the gateway list).
pub fn portal_login(
    transport: &dyn Transport,
    client: &ClientInfo,
    options: &LoginOptions,
    prompter: &mut dyn Prompter,
) -> Result<PortalSession, GpError> {
    let portal = normalize_server(&options.portal).map_err(|e| GpError::NoGateway(e.0))?;

    prompter.progress(&format!(
        "Contacting the portal {}",
        portal::host_of(&portal)
    ));
    let pre = prelogin_at(transport, client, &portal, Interface::Portal, options)?;

    let (username, auth, password) =
        portal_proof(prompter, &portal, &pre, options.username.as_deref())?;

    prompter.progress("Fetching the portal configuration");
    let config =
        portal::parse(&transport.send(&portal::request(&portal, client, &username, &auth))?)?;

    Ok(PortalSession {
        portal,
        region: pre.region,
        username,
        config,
        password,
    })
}

/// Logs in to `gateway` with what the portal login provided.
pub fn connect_gateway(
    transport: &dyn Transport,
    client: &ClientInfo,
    options: &LoginOptions,
    prompter: &mut dyn Prompter,
    portal: &PortalSession,
    gateway: &Gateway,
) -> Result<GatewaySession, GpError> {
    prompter.progress(&format!("Logging in to the gateway {}", gateway.label()));
    gateway_login(
        transport,
        client,
        options,
        prompter,
        gateway,
        &portal.username,
        &portal.config,
        portal.password.clone(),
    )
}

fn prelogin_at(
    transport: &dyn Transport,
    client: &ClientInfo,
    base: &str,
    iface: Interface,
    options: &LoginOptions,
) -> Result<Prelogin, GpError> {
    let request = prelogin::request(base, iface, client, options.default_browser);
    prelogin::parse(iface, &transport.send(&request)?)
}

/// How the user proves their identity to the portal. Returns the username, the proof, and
/// the password if one was typed (gateways often accept the same password).
fn portal_proof(
    prompter: &mut dyn Prompter,
    portal: &str,
    pre: &Prelogin,
    username: Option<&str>,
) -> Result<(String, PortalAuth, Option<Secret>), GpError> {
    if let Some(saml) = &pre.saml {
        return match prompter.saml(Interface::Portal, portal, saml)? {
            SsoResult::Saml {
                username,
                portal_userauthcookie: Some(cookie),
                ..
            } => Ok((username, PortalAuth::PortalCookie(cookie), None)),
            SsoResult::Saml {
                username,
                prelogin_cookie: Some(cookie),
                ..
            } => Ok((username, PortalAuth::PreloginCookie(cookie), None)),
            SsoResult::Saml { .. } => Err(GpError::SsoFailed("no cookie in the result".into())),
            SsoResult::Cas { .. } => Err(cas_unsupported()),
        };
    }
    let (username, password) =
        prompter.password(Interface::Portal, portal, &password_prompt(pre, username))?;
    Ok((
        username,
        PortalAuth::Password(password.clone()),
        Some(password),
    ))
}

#[allow(clippy::too_many_arguments)]
fn gateway_login(
    transport: &dyn Transport,
    client: &ClientInfo,
    options: &LoginOptions,
    prompter: &mut dyn Prompter,
    gateway: &Gateway,
    username: &str,
    config: &PortalConfig,
    portal_password: Option<Secret>,
) -> Result<GatewaySession, GpError> {
    let base = gateway.address.as_str();
    let pre = prelogin_at(transport, client, base, Interface::Gateway, options)?;

    let send = |auth: &GatewayAuth, user: &str| -> Result<GatewaySession, GpError> {
        let response = transport.send(&login::request(base, client, user, auth))?;
        login::parse(base, &client.computer, &response)
    };

    // 1. The portal's cookie usually works at its gateways: no second login.
    if let Some(cookie) = &config.portal_userauthcookie {
        let auth = GatewayAuth::PortalCookie {
            cookie: cookie.clone(),
            prelogon: config.portal_prelogonuserauthcookie.clone(),
        };
        match send(&auth, username) {
            Ok(session) => return Ok(session),
            Err(GpError::AuthFailed(_)) => {
                prompter.progress("The gateway did not accept the portal cookie; logging in again");
            }
            Err(e) => return Err(e),
        }
    }

    // 2. SAML at the gateway.
    if let Some(saml) = &pre.saml {
        return match prompter.saml(Interface::Gateway, base, saml)? {
            SsoResult::Saml {
                username,
                prelogin_cookie: Some(cookie),
                ..
            } => send(&GatewayAuth::PreloginCookie(cookie), &username),
            SsoResult::Saml {
                username,
                portal_userauthcookie: Some(cookie),
                ..
            } => send(
                &GatewayAuth::PortalCookie {
                    cookie,
                    prelogon: None,
                },
                &username,
            ),
            SsoResult::Saml { .. } => Err(GpError::SsoFailed("no cookie in the result".into())),
            SsoResult::Cas { .. } => Err(cas_unsupported()),
        };
    }

    // 3. Password: reuse the portal's, then ask.
    if let Some(password) = portal_password {
        match send(&GatewayAuth::Password(password), username) {
            Ok(session) => return Ok(session),
            Err(GpError::AuthFailed(_)) => {}
            Err(e) => return Err(e),
        }
    }
    let (user, password) = prompter.password(
        Interface::Gateway,
        base,
        &password_prompt(&pre, Some(username)),
    )?;
    send(&GatewayAuth::Password(password), &user)
}

fn password_prompt(pre: &Prelogin, username: Option<&str>) -> PasswordPrompt {
    PasswordPrompt {
        message: pre.auth_message.clone(),
        username_label: pre
            .username_label
            .clone()
            .unwrap_or_else(|| "Username".into()),
        password_label: pre
            .password_label
            .clone()
            .unwrap_or_else(|| "Password".into()),
        username: username.map(str::to_string),
    }
}

fn cas_unsupported() -> GpError {
    GpError::Unsupported(
        "this portal uses the Cloud Authentication Service, which Polytunnel does not support yet"
            .into(),
    )
}

/// Picks the gateway: the one asked for (by address, host or description), else the
/// preferred external one by priority. Without a gateway list the portal is the gateway.
pub fn choose_gateway(
    portal: &str,
    config: &PortalConfig,
    wanted: Option<&str>,
) -> Result<Gateway, GpError> {
    if config.gateways.is_empty() {
        return Ok(Gateway {
            address: portal.to_string(),
            ..Gateway::default()
        });
    }
    if let Some(wanted) = wanted.map(str::trim).filter(|w| !w.is_empty()) {
        let as_address = normalize_server(wanted).ok();
        return config
            .gateways
            .iter()
            .find(|gw| {
                Some(&gw.address) == as_address.as_ref()
                    || gw
                        .description
                        .as_deref()
                        .is_some_and(|d| d.eq_ignore_ascii_case(wanted))
            })
            .cloned()
            .ok_or_else(|| {
                let names: Vec<String> = config
                    .gateways
                    .iter()
                    .map(|gw| format!("{} ({})", gw.label(), gw.host()))
                    .collect();
                GpError::NoGateway(format!(
                    "'{wanted}' is not one of the portal's gateways: {}",
                    names.join(", ")
                ))
            });
    }
    config
        .gateways
        .iter()
        .filter(|gw| !gw.manual && !gw.internal)
        .min_by_key(|gw| gw.priority.unwrap_or(u32::MAX))
        .or_else(|| config.gateways.iter().find(|gw| !gw.manual))
        .or_else(|| config.gateways.first())
        .cloned()
        .ok_or_else(|| GpError::NoGateway("the portal lists no gateways".into()))
}

#[cfg(test)]
mod tests {
    /// Built at run time so secret scanners do not mistake test data for a real password.
    fn test_password() -> String {
        ["not", "a", "real", "password"].join("-")
    }

    use std::cell::RefCell;
    use std::collections::VecDeque;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use polytunnel_core::http::{HttpError, Request, Response};

    use super::*;
    use crate::client::test_client;

    /// Answers requests in order and records them.
    struct Script {
        answers: RefCell<VecDeque<(&'static str, Response)>>,
        seen: RefCell<Vec<Request>>,
    }

    impl Script {
        fn new(answers: Vec<(&'static str, Response)>) -> Self {
            Script {
                answers: RefCell::new(answers.into()),
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl Transport for Script {
        fn send(&self, request: &Request) -> Result<Response, HttpError> {
            self.seen.borrow_mut().push(request.clone());
            let (expected, response) = self
                .answers
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected request {request:?}"));
            assert!(
                request.url.starts_with(expected),
                "expected {expected}, got {request:?}"
            );
            Ok(response)
        }
    }

    #[derive(Default)]
    struct User {
        callbacks: VecDeque<String>,
        saml_seen: Vec<(Interface, String)>,
        passwords: VecDeque<(String, String)>,
        /// Host to pick in `select_gateway` (None: default choice).
        pick: Option<&'static str>,
    }

    impl Prompter for User {
        fn select_gateway(&mut self, portal: &PortalSession) -> Result<Option<Gateway>, GpError> {
            Ok(self.pick.and_then(|host| {
                portal
                    .config
                    .gateways
                    .iter()
                    .find(|g| g.host() == host)
                    .cloned()
            }))
        }

        fn saml(
            &mut self,
            iface: Interface,
            server: &str,
            request: &SamlRequest,
        ) -> Result<SsoResult, GpError> {
            assert!(matches!(request, SamlRequest::Redirect { .. }));
            self.saml_seen.push((iface, server.to_string()));
            let callback = self.callbacks.pop_front().expect("no more callbacks");
            crate::sso::parse_callback(&callback)
        }

        fn password(
            &mut self,
            _iface: Interface,
            _server: &str,
            _prompt: &PasswordPrompt,
        ) -> Result<(String, Secret), GpError> {
            let (u, p) = self.passwords.pop_front().expect("no more passwords");
            Ok((u, Secret::new(p)))
        }
    }

    fn saml_prelogin() -> Response {
        let req = STANDARD.encode("https://idp.example.com/saml2?SAMLRequest=FAKE");
        Response::new(
            200,
            format!(
                "<prelogin-response><status>Success</status><saml-auth-method>REDIRECT</saml-auth-method>\
                 <saml-request>{req}</saml-request><region>US</region></prelogin-response>"
            ),
        )
    }

    fn password_prelogin() -> Response {
        Response::new(
            200,
            "<prelogin-response><status>Success</status><username-label>Username</username-label></prelogin-response>",
        )
    }

    fn callback(cookie: &str) -> String {
        let doc = format!(
            "<html><!-- <saml-auth-status>1</saml-auth-status><prelogin-cookie>{cookie}</prelogin-cookie>\
             <saml-username>user@example.com</saml-username> --></html>"
        );
        format!("globalprotectcallback:{}", STANDARD.encode(doc))
    }

    fn config(with_portal_cookie: bool) -> Response {
        let cookie = if with_portal_cookie {
            "<portal-userauthcookie>FAKE-portal-cookie</portal-userauthcookie>"
        } else {
            "<portal-userauthcookie>empty</portal-userauthcookie>"
        };
        Response::new(
            200,
            format!(
                "<policy>{cookie}<gateways><external><list>\
                 <entry name=\"gw2.example.com\"><priority>2</priority><description>Two</description></entry>\
                 <entry name=\"gw1.example.com\"><priority>1</priority><description>One</description></entry>\
                 </list></external></gateways></policy>"
            ),
        )
    }

    fn jnlp() -> Response {
        let mut args = vec!["(null)"; 19];
        args[1] = "FAKEauthcookie0001";
        args[3] = "portal";
        args[4] = "user@example.com";
        args[12] = "tunnel";
        let body: String = args
            .iter()
            .map(|a| format!("<argument>{a}</argument>"))
            .collect();
        Response::new(
            200,
            format!("<jnlp><application-desc>{body}</application-desc></jnlp>"),
        )
    }

    fn options() -> LoginOptions {
        LoginOptions {
            portal: "portal.example.com".into(),
            default_browser: true,
            ..Default::default()
        }
    }

    #[test]
    fn saml_portal_with_portal_cookie_needs_one_browser_login() {
        let transport = Script::new(vec![
            (
                "https://portal.example.com/global-protect/prelogin.esp",
                saml_prelogin(),
            ),
            (
                "https://portal.example.com/global-protect/getconfig.esp",
                config(true),
            ),
            (
                "https://gw1.example.com/ssl-vpn/prelogin.esp",
                saml_prelogin(),
            ),
            ("https://gw1.example.com/ssl-vpn/login.esp", jnlp()),
        ]);
        let mut user = User {
            callbacks: [callback("FAKE-pre-1")].into(),
            ..Default::default()
        };
        let result = login(&transport, &test_client(), &options(), &mut user).unwrap();
        assert_eq!(result.gateway.address, "https://gw1.example.com");
        assert_eq!(result.region.as_deref(), Some("US"));
        assert_eq!(result.session.authcookie, Secret::new("FAKEauthcookie0001"));
        assert_eq!(user.saml_seen.len(), 1);

        let seen = transport.seen.borrow();
        assert_eq!(
            seen[1].form_value("prelogin-cookie").as_deref(),
            Some("FAKE-pre-1")
        );
        assert_eq!(
            seen[1].form_value("user").as_deref(),
            Some("user@example.com")
        );
        assert_eq!(
            seen[3].form_value("portal-userauthcookie").as_deref(),
            Some("FAKE-portal-cookie")
        );
    }

    #[test]
    fn saml_at_portal_and_gateway_without_portal_cookie() {
        let transport = Script::new(vec![
            (
                "https://portal.example.com/global-protect/prelogin.esp",
                saml_prelogin(),
            ),
            (
                "https://portal.example.com/global-protect/getconfig.esp",
                config(false),
            ),
            (
                "https://gw2.example.com/ssl-vpn/prelogin.esp",
                saml_prelogin(),
            ),
            ("https://gw2.example.com/ssl-vpn/login.esp", jnlp()),
        ]);
        let mut user = User {
            callbacks: [callback("FAKE-pre-1"), callback("FAKE-pre-2")].into(),
            ..Default::default()
        };
        let options = LoginOptions {
            gateway: Some("two".into()),
            ..options()
        };
        let result = login(&transport, &test_client(), &options, &mut user).unwrap();
        assert_eq!(result.gateway.address, "https://gw2.example.com");
        assert_eq!(
            user.saml_seen,
            vec![
                (Interface::Portal, "https://portal.example.com".into()),
                (Interface::Gateway, "https://gw2.example.com".into())
            ]
        );
        let seen = transport.seen.borrow();
        assert_eq!(
            seen[3].form_value("prelogin-cookie").as_deref(),
            Some("FAKE-pre-2")
        );
    }

    #[test]
    fn password_portal_reuses_the_password_at_the_gateway() {
        let transport = Script::new(vec![
            (
                "https://portal.example.com/global-protect/prelogin.esp",
                password_prelogin(),
            ),
            (
                "https://portal.example.com/global-protect/getconfig.esp",
                config(false),
            ),
            (
                "https://gw1.example.com/ssl-vpn/prelogin.esp",
                password_prelogin(),
            ),
            ("https://gw1.example.com/ssl-vpn/login.esp", jnlp()),
        ]);
        let mut user = User {
            passwords: [("user".to_string(), test_password())].into(),
            ..Default::default()
        };
        login(&transport, &test_client(), &options(), &mut user).unwrap();
        let seen = transport.seen.borrow();
        assert_eq!(
            seen[1].form_value("passwd").as_deref(),
            Some(test_password().as_str())
        );
        assert_eq!(
            seen[3].form_value("passwd").as_deref(),
            Some(test_password().as_str())
        );
        assert!(user.passwords.is_empty());
    }

    #[test]
    fn rejected_portal_cookie_falls_back_to_gateway_saml() {
        let transport = Script::new(vec![
            (
                "https://portal.example.com/global-protect/prelogin.esp",
                saml_prelogin(),
            ),
            (
                "https://portal.example.com/global-protect/getconfig.esp",
                config(true),
            ),
            (
                "https://gw1.example.com/ssl-vpn/prelogin.esp",
                saml_prelogin(),
            ),
            (
                "https://gw1.example.com/ssl-vpn/login.esp",
                Response::new(512, "Invalid username or password"),
            ),
            ("https://gw1.example.com/ssl-vpn/login.esp", jnlp()),
        ]);
        let mut user = User {
            callbacks: [callback("FAKE-pre-1"), callback("FAKE-pre-2")].into(),
            ..Default::default()
        };
        login(&transport, &test_client(), &options(), &mut user).unwrap();
        assert_eq!(user.saml_seen.len(), 2);
    }

    #[test]
    fn the_prompter_can_pick_the_gateway() {
        let transport = Script::new(vec![
            (
                "https://portal.example.com/global-protect/prelogin.esp",
                saml_prelogin(),
            ),
            (
                "https://portal.example.com/global-protect/getconfig.esp",
                config(true),
            ),
            (
                "https://gw2.example.com/ssl-vpn/prelogin.esp",
                saml_prelogin(),
            ),
            ("https://gw2.example.com/ssl-vpn/login.esp", jnlp()),
        ]);
        let mut user = User {
            callbacks: [callback("FAKE-pre-1")].into(),
            pick: Some("gw2.example.com"),
            ..Default::default()
        };
        let result = login(&transport, &test_client(), &options(), &mut user).unwrap();
        assert_eq!(result.gateway.address, "https://gw2.example.com");
    }

    #[test]
    fn unknown_gateway_names_list_the_choices() {
        let config = portal::parse(&config(false)).unwrap();
        let err = choose_gateway("https://portal.example.com", &config, Some("nope")).unwrap_err();
        assert!(matches!(&err, GpError::NoGateway(m) if m.contains("One (gw1.example.com)")));
        let by_host = choose_gateway(
            "https://portal.example.com",
            &config,
            Some("gw2.example.com"),
        );
        assert_eq!(by_host.unwrap().address, "https://gw2.example.com");
        let empty = PortalConfig::default();
        assert_eq!(
            choose_gateway("https://portal.example.com", &empty, None)
                .unwrap()
                .address,
            "https://portal.example.com"
        );
    }
}
