//! Gateway discovery and selection on the user side: the cached gateway list, probing,
//! ranking, and `polytunnel gateways`.
//!
//! The gateway list (not secret: addresses, priorities, region) is cached per portal after
//! every portal login, so "find the best gateway" can run again without logging in.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use polytunnel_core::profile::{GatewayPolicy, ProbeMethod, Profile, normalize_server};
use polytunnel_gp::flow::{self, LoginOptions, PortalSession};
use polytunnel_gp::portal::{Gateway, host_of};
use polytunnel_gp::rank::{self, Probe, RankInput, Ranking, Status};
use serde::{Deserialize, Serialize};

use crate::cli::{AuthTarget, GatewaysArgs};
use crate::prompter::{CliPrompter, SsoMode};
use crate::{auth, paths, probe, sysinfo};

/// How the user wants gateways picked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayPrefs {
    pub preferred: Option<String>,
    pub policy: GatewayPolicy,
    pub method: ProbeMethod,
}

/// Probe timeout when the portal sets no cutoff.
const DEFAULT_CUTOFF_SECS: u32 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedGateways {
    pub portal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cutoff_time: Option<u32>,
    /// Seconds since the Unix epoch.
    pub saved_at: u64,
    #[serde(default)]
    pub gateways: Vec<Gateway>,
}

fn cache_file(portal: &str) -> Option<PathBuf> {
    let name: String = host_of(portal)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    paths::config_dir().map(|d| d.join("cache").join(format!("gateways-{name}.toml")))
}

pub fn save_cache(portal: &PortalSession) -> Result<(), String> {
    let file = cache_file(&portal.portal).ok_or("no configuration directory")?;
    let cached = CachedGateways {
        portal: portal.portal.clone(),
        region: portal.region.clone(),
        cutoff_time: portal.config.cutoff_time,
        saved_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        gateways: portal.config.gateways.clone(),
    };
    let text = toml::to_string(&cached).map_err(|e| e.to_string())?;
    if let Some(dir) = file.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    fs::write(&file, text).map_err(|e| format!("{}: {e}", file.display()))
}

pub fn load_cache(portal: &str) -> Option<CachedGateways> {
    let text = fs::read_to_string(cache_file(portal)?).ok()?;
    toml::from_str(&text).ok()
}

/// Probes and ranks `gateways`.
pub fn rank_gateways(
    gateways: &[Gateway],
    region: Option<&str>,
    cutoff_secs: Option<u32>,
    prefs: &GatewayPrefs,
) -> Ranking {
    let cutoff = Duration::from_secs(u64::from(
        cutoff_secs.unwrap_or(DEFAULT_CUTOFF_SECS).clamp(1, 30),
    ));
    let probes = probe::probe_all(gateways, prefs.method, cutoff, None);
    rank::rank(&RankInput {
        gateways,
        region,
        probes: &probes,
        policy: prefs.policy,
        cutoff: Some(cutoff),
        preferred: prefs.preferred.as_deref(),
    })
}

fn method_name(method: ProbeMethod) -> &'static str {
    match method {
        ProbeMethod::Tls => "TLS handshake",
        ProbeMethod::Tcp => "TCP handshake",
    }
}

fn probe_text(probe: Probe) -> String {
    match probe {
        Probe::Answered(t) => format!("{} ms", t.as_millis()),
        Probe::Failed => "no answer".into(),
        Probe::Unknown => "-".into(),
    }
}

/// A table of the ranking, best first.
pub fn render_table(ranking: &Ranking, method: ProbeMethod) -> String {
    let mut rows = vec![[
        "#".to_string(),
        "Gateway".into(),
        "Host".into(),
        "Priority".into(),
        method_name(method).into(),
        "Status".into(),
    ]];
    for (i, r) in ranking.gateways.iter().enumerate() {
        let status = if ranking.chosen == Some(i) {
            "selected".to_string()
        } else {
            rank::describe(&r.status).to_string()
        };
        let priority = if r.priority == u32::MAX {
            "-".to_string()
        } else {
            rank::priority_name(r.priority).to_string()
        };
        rows.push([
            (i + 1).to_string(),
            r.gateway.label().to_string(),
            r.gateway.host().to_string(),
            priority,
            probe_text(r.probe),
            status,
        ]);
    }
    let widths: Vec<usize> = (0..6)
        .map(|c| {
            rows.iter()
                .map(|row| row[c].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    for row in rows {
        let cells: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(cell, w)| format!("{cell:<w$}"))
            .collect();
        out.push_str("  ");
        out.push_str(cells.join("  ").trim_end());
        out.push('\n');
    }
    out
}

pub fn render_json(ranking: &Ranking, portal: &str, region: Option<&str>) -> String {
    let quote = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    let gateways: Vec<String> = ranking
        .gateways
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let ms = match r.probe {
                Probe::Answered(t) => t.as_millis().to_string(),
                _ => "null".into(),
            };
            let priority = if r.priority == u32::MAX {
                "null".into()
            } else {
                r.priority.to_string()
            };
            format!(
                "{{\"label\":{},\"address\":{},\"priority\":{priority},\"response_ms\":{ms},\
                 \"status\":{},\"selected\":{}}}",
                quote(r.gateway.label()),
                quote(&r.gateway.address),
                quote(rank::describe(&r.status)),
                ranking.chosen == Some(i)
            )
        })
        .collect();
    format!(
        "{{\"portal\":{},\"region\":{},\"gateways\":[{}]}}\n",
        quote(portal),
        region.map_or("null".to_string(), quote),
        gateways.join(",")
    )
}

/// `polytunnel gateways`.
pub fn run(args: &GatewaysArgs) -> i32 {
    match run_inner(args) {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("polytunnel: {message}");
            1
        }
    }
}

fn run_inner(args: &GatewaysArgs) -> Result<(), String> {
    let profile = match &args.target {
        AuthTarget::Profile(name) => match auth::load_profile(name)? {
            Profile::GlobalProtect(p) => p,
            other => return Err(format!("profile '{name}' is a {} profile", other.kind())),
        },
        AuthTarget::GlobalProtect(portal) => polytunnel_core::profile::GlobalProtectProfile {
            portal: portal.clone(),
            ..Default::default()
        },
        AuthTarget::Fortinet(_) => return Err("gateways are a GlobalProtect feature".into()),
    };
    let portal = normalize_server(&profile.portal).map_err(|e| e.to_string())?;
    let prefs = GatewayPrefs {
        preferred: args.prefer.clone().or(profile.preferred_gateway.clone()),
        policy: profile.gateway_selection.unwrap_or_default(),
        method: profile.probe.unwrap_or_default(),
    };

    let cached = if args.refresh {
        None
    } else {
        load_cache(&portal)
    };
    let cached = match cached {
        Some(cached) => {
            eprintln!("Using the gateway list saved at the last login (refresh with --refresh).");
            cached
        }
        None => {
            let client = sysinfo::client_info(profile.client_os, profile.client_version.clone());
            let options = LoginOptions {
                portal: portal.clone(),
                username: profile.username.clone(),
                gateway: None,
                default_browser: true,
            };
            let mut prompter = CliPrompter::new(SsoMode::Callback, true, prefs.clone());
            let session = flow::portal_login(
                &crate::trace::transport(None),
                &client,
                &options,
                &mut prompter,
            )
            .map_err(|e| e.to_string())?;
            save_cache(&session)?;
            load_cache(&portal).ok_or("cannot read the saved gateway list")?
        }
    };
    if cached.gateways.is_empty() {
        println!("The portal lists no separate gateways: it is its own gateway.");
        return Ok(());
    }

    eprintln!(
        "Measuring {} gateways ({})...",
        cached.gateways.len(),
        method_name(prefs.method)
    );
    let ranking = rank_gateways(
        &cached.gateways,
        cached.region.as_deref(),
        cached.cutoff_time,
        &prefs,
    );
    if args.json {
        print!(
            "{}",
            render_json(&ranking, &portal, cached.region.as_deref())
        );
    } else {
        print!("{}", render_table(&ranking, prefs.method));
        for line in &ranking.explanation {
            println!("{line}");
        }
    }
    if ranking.chosen.is_none()
        && ranking
            .gateways
            .iter()
            .all(|r| r.status != Status::Candidate)
    {
        return Err("no gateway is available".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranking() -> Ranking {
        let gateways = vec![
            Gateway {
                address: "https://gw1.example.com".into(),
                description: Some("East".into()),
                priority: Some(1),
                ..Gateway::default()
            },
            Gateway {
                address: "https://gw2.example.com".into(),
                priority: Some(4),
                ..Gateway::default()
            },
        ];
        rank::rank(&RankInput {
            gateways: &gateways,
            region: Some("XX"),
            probes: &[Probe::Answered(Duration::from_millis(12)), Probe::Failed],
            policy: GatewayPolicy::Pools,
            cutoff: Some(Duration::from_secs(5)),
            preferred: None,
        })
    }

    #[test]
    fn table_and_json() {
        let r = ranking();
        let table = render_table(&r, ProbeMethod::Tls);
        let lines: Vec<&str> = table.lines().collect();
        assert!(lines[0].contains("Gateway") && lines[0].contains("TLS handshake"));
        assert!(
            lines[1].contains("East")
                && lines[1].contains("12 ms")
                && lines[1].contains("selected")
        );
        assert!(lines[2].contains("gw2.example.com") && lines[2].contains("no answer"));
        let json = render_json(&r, "https://portal.example.com", Some("XX"));
        assert!(json.starts_with("{\"portal\":\"https://portal.example.com\",\"region\":\"XX\""));
        assert!(json.contains("\"response_ms\":12,\"status\":\"available\",\"selected\":true"));
        assert!(json.contains("\"response_ms\":null,\"status\":\"no answer\",\"selected\":false"));
    }

    #[test]
    fn cache_round_trips_through_toml() {
        let cached = CachedGateways {
            portal: "https://portal.example.com".into(),
            region: Some("XX".into()),
            cutoff_time: Some(5),
            saved_at: 1,
            gateways: vec![Gateway {
                address: "https://gw1.example.com".into(),
                priority_rules: vec![("US".into(), 1), ("Any".into(), 3)],
                ..Gateway::default()
            }],
        };
        let text = toml::to_string(&cached).unwrap();
        assert_eq!(toml::from_str::<CachedGateways>(&text).unwrap(), cached);
    }
}
