//! Connecting from the window: the login and the service hand-off run on a background thread;
//! every question (password, code, browser login) comes to the window as a [`Prompt`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use polytunnel_core::Secret;
use polytunnel_core::ipc;
use polytunnel_core::profile::{
    FortinetIpsecProfile, FortinetSslProfile, GlobalProtectProfile, Profile, normalize_server,
};
use polytunnel_forti::FortiError;
use polytunnel_gp::GpError;
use polytunnel_gp::flow::{self, LoginOptions, PasswordPrompt, PortalSession, Prompter};
use polytunnel_gp::portal::Gateway;
use polytunnel_gp::prelogin::{Interface, SamlRequest};
use polytunnel_gp::sso::{self, SsoResult};
use polytunnel_http::UreqTransport;

use crate::gateways::{self, GatewayPrefs};
use crate::{browser, callback, connect, ipsec, sysinfo, uri};

const SSO_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// A question for the user.
pub enum Prompt {
    Credentials {
        title: String,
        message: Option<String>,
        username_label: String,
        password_label: String,
        username: Option<String>,
        reply: Sender<Option<(String, Secret)>>,
    },
    /// One hidden value: a verification code, a pre-shared key, ...
    Code {
        title: String,
        message: String,
        reply: Sender<Option<Secret>>,
    },
    /// A browser login is in progress; the window may paste a result into `paste`.
    Browser {
        server: String,
        url: String,
        paste: Sender<String>,
    },
}

pub enum Event {
    Progress(String),
    Prompt(Prompt),
    /// The browser prompt is no longer needed.
    BrowserDone,
    Finished(Result<String, String>),
}

pub struct Worker {
    pub events: Receiver<Event>,
    cancel: Arc<AtomicBool>,
}

impl Worker {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }
}

/// Logs in with `profile` and has the service bring the tunnel up.
pub fn start(name: String, profile: Profile, repaint: impl Fn() + Send + 'static) -> Worker {
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    thread::spawn(move || {
        let events = Notifier {
            tx,
            repaint: Box::new(repaint),
        };
        let result = run(&name, &profile, &events, &worker_cancel);
        events.send(Event::Finished(result));
    });
    Worker { events: rx, cancel }
}

struct Notifier {
    tx: Sender<Event>,
    repaint: Box<dyn Fn() + Send>,
}

impl Notifier {
    fn send(&self, event: Event) {
        let _ = self.tx.send(event);
        (self.repaint)();
    }

    fn progress(&self, message: impl Into<String>) {
        self.send(Event::Progress(message.into()));
    }
}

fn run(
    name: &str,
    profile: &Profile,
    events: &Notifier,
    cancel: &AtomicBool,
) -> Result<String, String> {
    // Fail early if the service is missing, before any login.
    connect::status()?;
    let request = match profile {
        Profile::GlobalProtect(p) => login_gp(name, p, events, cancel)?,
        Profile::FortinetSsl(p) => login_fortinet(name, p, events)?,
        Profile::FortinetIpsec(p) => ipsec_request(name, p, events)?,
    };
    if cancel.load(Ordering::SeqCst) {
        return Err("cancelled".into());
    }
    connect::send_connect(request)?;
    events.progress("Bringing the tunnel up...");
    let status = connect::wait_connected(&mut |_| {}, &mut |prompt| {
        if cancel.load(Ordering::SeqCst) {
            return Err("cancelled".into());
        }
        answer_prompt(prompt, events)
    })?;
    Ok(connect::describe(&status))
}

/// Asks one hidden value in the window; `None` when the user cancels.
fn ask_hidden(events: &Notifier, title: String, message: String) -> Option<Secret> {
    let (reply, answer) = mpsc::channel();
    events.send(Event::Prompt(Prompt::Code {
        title,
        message,
        reply,
    }));
    answer.recv().ok().flatten()
}

/// The service needs more sign-in input (a one-time code, ...): ask for each field.
fn answer_prompt(prompt: &ipc::Prompt, events: &Notifier) -> Result<Vec<Secret>, String> {
    prompt
        .fields
        .iter()
        .map(|field| {
            let message = prompt.message.clone().unwrap_or_else(|| {
                format!("The gateway asks for your {}.", field.label.to_lowercase())
            });
            ask_hidden(events, field.label.clone(), message).ok_or_else(|| "cancelled".to_string())
        })
        .collect()
}

fn ipsec_request(
    name: &str,
    p: &FortinetIpsecProfile,
    events: &Notifier,
) -> Result<ipc::Connect, String> {
    let server = ipsec::server_host(p)?;
    let psk = if ipsec::needs_psk(p) {
        ask_hidden(
            events,
            "Pre-shared key".into(),
            format!("The pre-shared key of the IPsec tunnel to {server}."),
        )
        .ok_or("cancelled")?
    } else {
        Secret::new("")
    };
    let xauth = if ipsec::needs_login(p) {
        let (reply, answer) = mpsc::channel();
        events.send(Event::Prompt(Prompt::Credentials {
            title: format!("Sign in to {server}"),
            message: None,
            username_label: "Username".into(),
            password_label: "Password".into(),
            username: p.username.clone(),
            reply,
        }));
        Some(answer.recv().ok().flatten().ok_or("cancelled")?)
    } else {
        None
    };
    events.progress(format!("Negotiating IPsec with {server}..."));
    ipsec::connect_request(name.to_string(), p, ipsec::Secrets { psk, xauth })
}

fn login_gp(
    name: &str,
    p: &GlobalProtectProfile,
    events: &Notifier,
    cancel: &AtomicBool,
) -> Result<ipc::Connect, String> {
    let client = sysinfo::client_info(p.client_os, p.client_version.clone());
    let options = LoginOptions {
        portal: p.portal.clone(),
        username: p.username.clone(),
        gateway: p.gateway.clone(),
        default_browser: true,
    };
    let mut prompter = GuiPrompter {
        events,
        cancel,
        embedded: p.embedded_login == Some(true),
        listener: None,
        prefs: GatewayPrefs {
            preferred: p.preferred_gateway.clone(),
            policy: p.gateway_selection.unwrap_or_default(),
            method: p.probe.unwrap_or_default(),
        },
    };
    let result = flow::login(&UreqTransport::new(), &client, &options, &mut prompter)
        .map_err(|e| e.to_string())?;
    Ok(connect::gp_connect(
        name.to_string(),
        client,
        result.session,
    ))
}

fn login_fortinet(
    name: &str,
    p: &FortinetSslProfile,
    events: &Notifier,
) -> Result<ipc::Connect, String> {
    let base = normalize_server(&p.server).map_err(|e| e.to_string())?;
    let (reply, answer) = mpsc::channel();
    events.send(Event::Prompt(Prompt::Credentials {
        title: format!("Sign in to {}", base.trim_start_matches("https://")),
        message: None,
        username_label: "Username".into(),
        password_label: "Password".into(),
        username: p.username.clone(),
        reply,
    }));
    let (username, password) = answer.recv().ok().flatten().ok_or("cancelled")?;
    events.progress(format!(
        "Logging in to {}...",
        base.trim_start_matches("https://")
    ));
    let realm = p.realm.clone().unwrap_or_default();
    let cookie = polytunnel_forti::login(
        &UreqTransport::new(),
        &base,
        &username,
        &password,
        &realm,
        &mut |challenge| {
            let (reply, answer) = mpsc::channel();
            let mut message = challenge
                .message
                .clone()
                .unwrap_or_else(|| "Enter the code from your token.".into());
            if challenge
                .token_info
                .as_deref()
                .is_some_and(|t| t.contains("push"))
            {
                message.push_str("\n(Approve the push notification, then press OK.)");
            }
            events.send(Event::Prompt(Prompt::Code {
                title: "Verification code".into(),
                message,
                reply,
            }));
            answer.recv().ok().flatten().ok_or(FortiError::Cancelled)
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(connect::forti_connect(name.to_string(), base, cookie))
}

struct GuiPrompter<'a> {
    events: &'a Notifier,
    cancel: &'a AtomicBool,
    /// Sign in in the embedded login window instead of the browser.
    embedded: bool,
    listener: Option<callback::Listener>,
    prefs: GatewayPrefs,
}

impl Prompter for GuiPrompter<'_> {
    fn saml(
        &mut self,
        iface: Interface,
        server: &str,
        request: &SamlRequest,
    ) -> Result<SsoResult, GpError> {
        if self.embedded {
            let host = server.trim_start_matches("https://");
            self.events.progress(format!(
                "Single sign-on for the {} {host}: complete it in the login window.",
                iface.label()
            ));
            return crate::embedded::login(request, &format!("Sign in to {host}"))
                .map_err(GpError::SsoFailed);
        }
        if self.listener.is_none() {
            self.listener = callback::Listener::start().ok();
        }
        if let Some(listener) = &self.listener {
            while listener.receiver().try_recv().is_ok() {}
        }
        if let Some(notice) = uri::ensure_registered() {
            self.events.progress(notice);
        }
        let url = match request {
            SamlRequest::Redirect { url } => url.clone(),
            SamlRequest::Post { html } => browser::serve_page(html.clone())
                .map_err(|e| GpError::SsoFailed(format!("cannot serve the login page: {e}")))?,
        };
        let host = server.trim_start_matches("https://").to_string();
        self.events.progress(format!(
            "Single sign-on for the {} {host}: complete it in your browser.",
            iface.label()
        ));
        if let Err(e) = browser::open(&url) {
            self.events.progress(e);
        }
        let (paste, pasted) = mpsc::channel();
        self.events.send(Event::Prompt(Prompt::Browser {
            server: host,
            url,
            paste,
        }));
        let result = self.wait_for_result(&pasted);
        self.events.send(Event::BrowserDone);
        result
    }

    fn password(
        &mut self,
        iface: Interface,
        server: &str,
        prompt: &PasswordPrompt,
    ) -> Result<(String, Secret), GpError> {
        let (reply, answer) = mpsc::channel();
        self.events.send(Event::Prompt(Prompt::Credentials {
            title: format!(
                "Sign in to the {} {}",
                iface.label(),
                server.trim_start_matches("https://")
            ),
            message: prompt.message.clone(),
            username_label: prompt.username_label.clone(),
            password_label: prompt.password_label.clone(),
            username: prompt.username.clone(),
            reply,
        }));
        answer.recv().ok().flatten().ok_or(GpError::Cancelled)
    }

    fn progress(&mut self, message: &str) {
        self.events.progress(format!("{message}..."));
    }

    fn select_gateway(&mut self, portal: &PortalSession) -> Result<Option<Gateway>, GpError> {
        if let Err(e) = gateways::save_cache(portal) {
            self.events
                .progress(format!("Could not save the gateway list: {e}"));
        }
        if portal.config.gateways.len() <= 1 {
            return Ok(None);
        }
        self.events.progress(format!(
            "Measuring {} gateways...",
            portal.config.gateways.len()
        ));
        let ranking = gateways::rank_gateways(
            &portal.config.gateways,
            portal.region.as_deref(),
            portal.config.cutoff_time,
            &self.prefs,
        );
        for line in &ranking.explanation {
            self.events.progress(line.clone());
        }
        ranking
            .chosen()
            .map(|r| Some(r.gateway.clone()))
            .ok_or_else(|| GpError::NoGateway("no gateway answered".into()))
    }
}

impl GuiPrompter<'_> {
    fn wait_for_result(&self, pasted: &Receiver<String>) -> Result<SsoResult, GpError> {
        let deadline = Instant::now() + SSO_TIMEOUT;
        loop {
            if self.cancel.load(Ordering::SeqCst) {
                return Err(GpError::Cancelled);
            }
            if Instant::now() > deadline {
                return Err(GpError::SsoFailed(
                    "timed out waiting for the browser".into(),
                ));
            }
            if let Ok(text) = pasted.try_recv() {
                match sso::parse_callback(&text) {
                    Ok(result) => return Ok(result),
                    Err(e) => self
                        .events
                        .progress(format!("That is not a usable login result: {e}")),
                }
            }
            let link = match &self.listener {
                Some(listener) => {
                    match listener.receiver().recv_timeout(Duration::from_millis(200)) {
                        Ok(link) => Some(link),
                        Err(RecvTimeoutError::Timeout) => None,
                        Err(RecvTimeoutError::Disconnected) => None,
                    }
                }
                None => {
                    thread::sleep(Duration::from_millis(200));
                    None
                }
            };
            if let Some(link) = link {
                match sso::parse_callback(&link) {
                    Ok(result) => return Ok(result),
                    Err(e) => self
                        .events
                        .progress(format!("Ignoring a login link that could not be used: {e}")),
                }
            }
        }
    }
}
