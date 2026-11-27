//! The terminal side of a login: browser SSO, password and code prompts.

use std::io::{self, BufRead, Write};
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use polytunnel_core::Secret;
use polytunnel_gp::GpError;
use polytunnel_gp::flow::{PasswordPrompt, PortalSession, Prompter};
use polytunnel_gp::portal::Gateway;
use polytunnel_gp::prelogin::{Interface, SamlRequest};
use polytunnel_gp::sso::{self, MAX_CALLBACK_LEN, SsoResult};

use crate::gateways::{self, GatewayPrefs};
use crate::{browser, callback, uri};

/// How long to wait for the browser to finish a SAML login.
const SSO_TIMEOUT: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsoMode {
    /// Wait for the `globalprotectcallback:` link (from the browser or `polytunnel --callback`).
    Callback,
    /// Read the login result pasted into the terminal.
    Paste,
}

pub struct CliPrompter {
    mode: SsoMode,
    open_browser: bool,
    listener: Option<callback::Listener>,
    prefs: GatewayPrefs,
}

impl CliPrompter {
    pub fn new(mode: SsoMode, open_browser: bool, prefs: GatewayPrefs) -> Self {
        CliPrompter {
            mode,
            open_browser,
            listener: None,
            prefs,
        }
    }

    fn show_login_page(&self, request: &SamlRequest) -> Result<(), GpError> {
        let url = match request {
            SamlRequest::Redirect { url } => url.clone(),
            SamlRequest::Post { html } => browser::serve_page(html.clone())
                .map_err(|e| GpError::SsoFailed(format!("cannot serve the login page: {e}")))?,
        };
        if self.open_browser {
            match browser::open(&url) {
                Ok(()) => return Ok(()),
                Err(e) => eprintln!("{e}"),
            }
        }
        eprintln!("Open this address in your browser to sign in:\n\n  {url}\n");
        Ok(())
    }

    fn wait_for_callback(&self) -> Result<SsoResult, GpError> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| GpError::SsoFailed("no callback listener".into()))?;
        let deadline = Instant::now() + SSO_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match listener.receiver().recv_timeout(left) {
                Ok(link) => match sso::parse_callback(&link) {
                    Ok(result) => return Ok(result),
                    Err(e) => eprintln!("Ignoring a login link that could not be used: {e}"),
                },
                Err(RecvTimeoutError::Timeout) => {
                    return Err(GpError::SsoFailed(
                        "timed out waiting for the browser (try again with --paste)".into(),
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(GpError::SsoFailed("the callback listener stopped".into()));
                }
            }
        }
    }

    fn read_pasted(&self) -> Result<SsoResult, GpError> {
        eprintln!(
            "When the browser shows the end of the login, paste the globalprotectcallback: link \
             (or the final page's source or response headers) here and press Enter."
        );
        let mut collected = String::new();
        for line in io::stdin().lock().lines() {
            let line = line.map_err(|e| GpError::SsoFailed(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            collected.push_str(&line);
            collected.push('\n');
            if collected.len() > MAX_CALLBACK_LEN {
                return Err(GpError::SsoFailed("pasted text is too large".into()));
            }
            // One line may already be complete (the link); page source or headers may take
            // several.
            if let Ok(result) =
                sso::parse_callback(&line).or_else(|_| sso::parse_callback(&collected))
            {
                return Ok(result);
            }
            eprintln!("Not a login result yet; paste more or press Ctrl+C to cancel.");
        }
        Err(GpError::Cancelled)
    }
}

impl Prompter for CliPrompter {
    fn saml(
        &mut self,
        iface: Interface,
        server: &str,
        request: &SamlRequest,
    ) -> Result<SsoResult, GpError> {
        let host = server.strip_prefix("https://").unwrap_or(server);
        eprintln!("Single sign-on required by the {} {host}.", iface.label());

        if self.mode == SsoMode::Paste {
            self.show_login_page(request)?;
            return self.read_pasted();
        }

        if self.listener.is_none() {
            let listener = callback::Listener::start().map_err(|e| {
                GpError::SsoFailed(format!(
                    "cannot listen for the login link ({e}); is another `polytunnel auth` \
                     running? Try again with --paste"
                ))
            })?;
            self.listener = Some(listener);
        }
        if let Some(listener) = &self.listener {
            while listener.receiver().try_recv().is_ok() {} // drop stale links
        }
        if let Some(notice) = uri::ensure_registered() {
            eprintln!("{notice}");
        }
        self.show_login_page(request)?;
        eprintln!(
            "Waiting for the browser to hand the login back (up to 10 minutes).\n\
             If it does not, copy the globalprotectcallback: link and run in another terminal:\n\
             \n  polytunnel --callback \"<link>\"\n"
        );
        self.wait_for_callback()
    }

    fn password(
        &mut self,
        iface: Interface,
        server: &str,
        prompt: &PasswordPrompt,
    ) -> Result<(String, Secret), GpError> {
        let host = server.strip_prefix("https://").unwrap_or(server);
        if let Some(message) = &prompt.message {
            eprintln!("{message} ({} {host})", iface.label());
        }
        let username = match &prompt.username {
            Some(u) => u.clone(),
            None => ask(&format!("{}: ", prompt.username_label))
                .map_err(|e| GpError::SsoFailed(e.to_string()))?,
        };
        let password = ask_secret(&format!("{}: ", prompt.password_label))
            .map_err(|e| GpError::SsoFailed(e.to_string()))?;
        Ok((username, password))
    }

    fn progress(&mut self, message: &str) {
        eprintln!("{message}...");
    }

    fn select_gateway(&mut self, portal: &PortalSession) -> Result<Option<Gateway>, GpError> {
        if let Err(e) = gateways::save_cache(portal) {
            eprintln!("Could not save the gateway list: {e}");
        }
        let list = &portal.config.gateways;
        if list.len() <= 1 {
            return Ok(None); // nothing to choose from
        }
        eprintln!("Measuring {} gateways...", list.len());
        let ranking = gateways::rank_gateways(
            list,
            portal.region.as_deref(),
            portal.config.cutoff_time,
            &self.prefs,
        );
        eprint!("{}", gateways::render_table(&ranking, self.prefs.method));
        for line in &ranking.explanation {
            eprintln!("{line}");
        }
        ranking
            .chosen()
            .map(|r| Some(r.gateway.clone()))
            .ok_or_else(|| GpError::NoGateway("no gateway answered".into()))
    }
}

/// Reads one visible line from the terminal.
pub fn ask(prompt: &str) -> io::Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no input"));
    }
    Ok(line.trim().to_string())
}

/// Reads one line without echoing it.
pub fn ask_secret(prompt: &str) -> io::Result<Secret> {
    rpassword::prompt_password(prompt).map(Secret::new)
}
