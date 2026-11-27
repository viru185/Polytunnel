//! Keeps the kill switch in line with its setting and the tunnel: the engines report when a
//! tunnel comes up and goes down, and the setting is kept in the service's state folder (so
//! lockdown comes back at boot).

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use polytunnel_core::ipc::{KillSwitchMode, KillSwitchSettings};
use polytunnel_net::killswitch::{self, KillSwitch, Rules};

use crate::{info, paths, warn};

struct Controller {
    settings: KillSwitchSettings,
    /// The active rules' backend, and whether it is the persistent (lockdown) kind.
    backend: Option<(Box<dyn KillSwitch>, bool)>,
    /// The tunnel interface and VPN servers while a tunnel is up.
    tunnel: Option<(u32, Vec<IpAddr>)>,
    /// The last VPN servers, for lockdown while disconnected.
    last_servers: Vec<IpAddr>,
    problem: Option<String>,
}

static CONTROLLER: Mutex<Controller> = Mutex::new(Controller {
    settings: KillSwitchSettings {
        mode: KillSwitchMode::Off,
        allow_lan: false,
    },
    backend: None,
    tunnel: None,
    last_servers: Vec::new(),
    problem: None,
});

fn controller() -> MutexGuard<'static, Controller> {
    CONTROLLER.lock().unwrap_or_else(|e| e.into_inner())
}

fn settings_file() -> PathBuf {
    paths::state_dir().join("killswitch.conf")
}

/// `mode=…`, `allow_lan=…`, `servers=a,b` lines.
fn encode(settings: &KillSwitchSettings, servers: &[IpAddr]) -> String {
    let mode = match settings.mode {
        KillSwitchMode::Off => "off",
        KillSwitchMode::Connected => "connected",
        KillSwitchMode::Always => "always",
    };
    let servers: Vec<String> = servers.iter().map(IpAddr::to_string).collect();
    format!(
        "mode={mode}\nallow_lan={}\nservers={}\n",
        settings.allow_lan,
        servers.join(",")
    )
}

fn decode(text: &str) -> (KillSwitchSettings, Vec<IpAddr>) {
    let mut settings = KillSwitchSettings::default();
    let mut servers = Vec::new();
    for line in text.lines() {
        match line.split_once('=') {
            Some(("mode", "connected")) => settings.mode = KillSwitchMode::Connected,
            Some(("mode", "always")) => settings.mode = KillSwitchMode::Always,
            Some(("allow_lan", v)) => settings.allow_lan = v.trim() == "true",
            Some(("servers", list)) => {
                servers = list
                    .split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect();
            }
            _ => {}
        }
    }
    (settings, servers)
}

/// The Polytunnel programs, allowed out during lockdown (logins while disconnected).
fn programs() -> Vec<PathBuf> {
    let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
    else {
        return Vec::new();
    };
    let ext = std::env::consts::EXE_SUFFIX;
    ["polytunnel-daemon", "polytunnel", "polytunnel-sso"]
        .iter()
        .map(|name| dir.join(format!("{name}{ext}")))
        .collect()
}

impl Controller {
    fn save(&self) {
        let _ = paths::ensure_state_dir();
        if let Err(e) = fs::write(settings_file(), encode(&self.settings, &self.last_servers)) {
            warn!("cannot save the kill switch setting: {e}");
        }
    }

    /// Brings the rules in line with the setting and the tunnel.
    fn apply(&mut self) {
        let rules = match (self.settings.mode, &self.tunnel) {
            (KillSwitchMode::Off, _) | (KillSwitchMode::Connected, None) => None,
            (KillSwitchMode::Connected, Some((index, servers))) => Some(Rules {
                tunnel_if: Some(*index),
                servers: servers.clone(),
                allow_lan: self.settings.allow_lan,
                programs: Vec::new(),
            }),
            (KillSwitchMode::Always, tunnel) => Some(Rules {
                tunnel_if: tunnel.as_ref().map(|(index, _)| *index),
                servers: match tunnel {
                    Some((_, servers)) => servers.clone(),
                    None => self.last_servers.clone(),
                },
                allow_lan: self.settings.allow_lan,
                programs: programs(),
            }),
        };
        let persistent = self.settings.mode == KillSwitchMode::Always;
        // Switching between the kinds: take the old rules away first.
        if let Some((mut old, kind)) = self.backend.take() {
            if rules.is_none() || kind != persistent {
                if let Err(e) = old.clear() {
                    warn!("cannot remove the kill switch: {e}");
                }
            } else {
                self.backend = Some((old, kind));
            }
        }
        self.problem = None;
        if let Some(rules) = rules {
            let (backend, _) = self
                .backend
                .get_or_insert_with(|| (killswitch::native(persistent), persistent));
            match backend.apply(&rules) {
                Ok(()) => info!(
                    "kill switch on ({}{})",
                    if rules.tunnel_if.is_some() {
                        "tunnel up"
                    } else {
                        "lockdown"
                    },
                    if rules.allow_lan { ", LAN allowed" } else { "" }
                ),
                Err(e) => {
                    warn!("cannot apply the kill switch: {e}");
                    self.problem = Some(e.to_string());
                }
            }
        }
    }
}

/// At service start: the saved setting (lockdown comes back here).
pub fn load() {
    let mut c = controller();
    let (settings, servers) = fs::read_to_string(settings_file())
        .map(|t| decode(&t))
        .unwrap_or_default();
    c.settings = settings;
    c.last_servers = servers;
    // Persistent rules from an earlier lockdown are replaced (or removed when it is off).
    if c.settings.mode != KillSwitchMode::Always {
        let _ = killswitch::native(true).clear();
    }
    c.apply();
}

pub fn set(settings: KillSwitchSettings) {
    let mut c = controller();
    c.settings = settings;
    c.save();
    c.apply();
}

/// The setting, whether rules are in force, and any problem applying them.
pub fn status() -> (KillSwitchSettings, bool, Option<String>) {
    let c = controller();
    (
        c.settings,
        c.backend.is_some() && c.problem.is_none(),
        c.problem.clone(),
    )
}

/// A tunnel is up on interface `index`; `servers` must stay reachable.
pub fn tunnel_up(index: u32, servers: Vec<IpAddr>) {
    let mut c = controller();
    c.last_servers.clone_from(&servers);
    c.tunnel = Some((index, servers));
    if c.settings.mode == KillSwitchMode::Always {
        c.save();
    }
    c.apply();
}

/// The tunnel is down.
pub fn tunnel_down() {
    let mut c = controller();
    if c.tunnel.take().is_some() {
        c.apply();
    }
}

/// Service shutdown: dynamic rules go; lockdown stays.
pub fn shutdown() {
    let mut c = controller();
    c.tunnel = None;
    if c.settings.mode != KillSwitchMode::Always
        && let Some((mut backend, _)) = c.backend.take()
    {
        let _ = backend.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip() {
        let s = KillSwitchSettings {
            mode: KillSwitchMode::Always,
            allow_lan: true,
        };
        let servers: Vec<IpAddr> = vec![
            "203.0.113.9".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ];
        assert_eq!(decode(&encode(&s, &servers)), (s, servers));
        assert_eq!(
            decode("garbage"),
            (KillSwitchSettings::default(), Vec::new())
        );
        assert_eq!(decode("mode=connected\n").0.mode, KillSwitchMode::Connected);
    }
}
