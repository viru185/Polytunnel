//! Best-gateway selection, following Palo Alto's documented rules:
//!
//! 1. **Source region first.** A gateway's priority comes from the rule for the client's
//!    region (as reported by the portal), else from its "Any" rule. A gateway whose rules
//!    name neither the region nor "Any" is not offered in that region. Without rules, the
//!    gateway's default priority applies.
//! 2. **Priority pools.** Highest, High and Medium gateways form one pool and the fastest of
//!    them wins; Low and Lowest gateways are only used when none of the first pool answers.
//!    [`Policy::StrictTiers`] instead ranks strictly by priority, then speed.
//! 3. **Response time.** Gateways that do not answer within the portal's cutoff time are
//!    skipped. Manual-only and internal gateways are never picked automatically.
//! 4. **Preferred gateway.** If one is set and it answered, it wins; otherwise the best one.
//!
//! [`rank`] is a pure function: it gets the measured response times and explains its choice.

use std::time::Duration;

use crate::portal::Gateway;

pub use polytunnel_core::profile::GatewayPolicy as Policy;

/// GlobalProtect priority levels as numbered in the portal configuration.
pub fn priority_name(priority: u32) -> &'static str {
    match priority {
        0 => "Manual only",
        1 => "Highest",
        2 => "High",
        3 => "Medium",
        4 => "Low",
        5 => "Lowest",
        _ => "Other",
    }
}

/// Priority used when the portal gives none.
pub const DEFAULT_PRIORITY: u32 = 3;

/// The outcome of probing one gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// Answered in this time.
    Answered(Duration),
    /// No answer (timeout, refused, TLS failure).
    Failed,
    /// Not probed.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Taking part in the automatic choice.
    Candidate,
    ManualOnly,
    Internal,
    /// Its priority rules do not cover the client's region.
    NotForRegion,
    /// Did not answer, or slower than the cutoff.
    Unreachable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranked {
    pub gateway: Gateway,
    /// Effective priority for the client's region.
    pub priority: u32,
    pub probe: Probe,
    pub status: Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranking {
    /// Every gateway, best first; non-candidates at the end.
    pub gateways: Vec<Ranked>,
    /// Index into `gateways` of the chosen one.
    pub chosen: Option<usize>,
    /// Human-readable reasons, in order.
    pub explanation: Vec<String>,
}

impl Ranking {
    pub fn chosen(&self) -> Option<&Ranked> {
        self.chosen.map(|i| &self.gateways[i])
    }
}

pub struct RankInput<'a> {
    pub gateways: &'a [Gateway],
    /// The portal's verdict on the client's region (from pre-login).
    pub region: Option<&'a str>,
    /// One entry per gateway, same order as `gateways`.
    pub probes: &'a [Probe],
    pub policy: Policy,
    /// Answers slower than this count as unreachable.
    pub cutoff: Option<Duration>,
    /// Address, host or description of the preferred gateway.
    pub preferred: Option<&'a str>,
}

/// Effective priority for `region`, or `None` if the gateway is not offered there.
pub fn effective_priority(gateway: &Gateway, region: Option<&str>) -> Option<u32> {
    if gateway.priority_rules.is_empty() {
        return Some(gateway.priority.unwrap_or(DEFAULT_PRIORITY));
    }
    let rule = |name: &str| {
        gateway
            .priority_rules
            .iter()
            .find(|(r, _)| r.eq_ignore_ascii_case(name))
            .map(|(_, p)| *p)
    };
    region.and_then(rule).or_else(|| rule("Any"))
}

/// Does `wanted` name this gateway (address, host or description, case-insensitive)?
pub fn matches(gateway: &Gateway, wanted: &str) -> bool {
    let wanted = wanted.trim();
    let address = polytunnel_core::profile::normalize_server(wanted).ok();
    Some(&gateway.address) == address.as_ref()
        || gateway.host().eq_ignore_ascii_case(wanted)
        || gateway
            .description
            .as_deref()
            .is_some_and(|d| d.eq_ignore_ascii_case(wanted))
}

pub fn rank(input: &RankInput<'_>) -> Ranking {
    let mut explanation = Vec::new();
    match input.region {
        Some(region) => {
            explanation.push(format!("The portal places this client in region {region}."))
        }
        None => explanation.push("The portal did not report a region; using \"Any\" rules.".into()),
    }

    let mut ranked: Vec<Ranked> = input
        .gateways
        .iter()
        .enumerate()
        .map(|(i, gw)| {
            let probe = input.probes.get(i).copied().unwrap_or(Probe::Unknown);
            let priority = effective_priority(gw, input.region);
            let too_slow = matches!(
                (probe, input.cutoff),
                (Probe::Answered(t), Some(cutoff)) if t > cutoff
            );
            let status = if gw.manual || priority == Some(0) {
                Status::ManualOnly
            } else if gw.internal {
                Status::Internal
            } else if priority.is_none() {
                Status::NotForRegion
            } else if probe == Probe::Failed || too_slow {
                Status::Unreachable
            } else {
                Status::Candidate
            };
            Ranked {
                gateway: gw.clone(),
                priority: priority.unwrap_or(u32::MAX),
                probe,
                status,
            }
        })
        .collect();

    let pool = |p: u32| match input.policy {
        Policy::Pools => u32::from(p > 3),
        Policy::StrictTiers => p,
    };
    let latency = |probe: Probe| match probe {
        Probe::Answered(t) => t,
        _ => Duration::MAX, // unprobed candidates after measured ones
    };
    ranked.sort_by(|a, b| {
        let a_key = (
            a.status != Status::Candidate,
            pool(a.priority),
            latency(a.probe),
            a.priority,
        );
        let b_key = (
            b.status != Status::Candidate,
            pool(b.priority),
            latency(b.probe),
            b.priority,
        );
        a_key.cmp(&b_key)
    });

    let best = ranked.iter().position(|r| r.status == Status::Candidate);
    let preferred = input
        .preferred
        .filter(|p| !p.trim().is_empty())
        .and_then(|wanted| {
            let found = ranked.iter().position(|r| matches(&r.gateway, wanted));
            match found {
                None => {
                    explanation.push(format!(
                        "The preferred gateway '{wanted}' is not in the portal's list."
                    ));
                    None
                }
                Some(i) if ranked[i].status == Status::Candidate => {
                    explanation.push(format!(
                        "Using the preferred gateway {}.",
                        ranked[i].gateway.label()
                    ));
                    Some(i)
                }
                Some(i) => {
                    explanation.push(format!(
                    "The preferred gateway {} is not available ({}); falling back to the best one.",
                    ranked[i].gateway.label(),
                    describe(&ranked[i].status)
                ));
                    None
                }
            }
        });

    let chosen = preferred.or(best);
    match chosen.map(|i| &ranked[i]) {
        Some(r) if preferred.is_none() => explanation.push(format!(
            "Best gateway: {} (priority {}, {}).",
            r.gateway.label(),
            priority_name(r.priority),
            match r.probe {
                Probe::Answered(t) => format!("{} ms", t.as_millis()),
                _ => "not measured".into(),
            }
        )),
        Some(_) => {}
        None => explanation.push("No gateway is available for automatic selection.".into()),
    }

    Ranking {
        gateways: ranked,
        chosen,
        explanation,
    }
}

pub fn describe(status: &Status) -> &'static str {
    match status {
        Status::Candidate => "available",
        Status::ManualOnly => "manual only",
        Status::Internal => "internal",
        Status::NotForRegion => "not offered in this region",
        Status::Unreachable => "no answer",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gw(host: &str, priority: Option<u32>, rules: &[(&str, u32)]) -> Gateway {
        Gateway {
            address: format!("https://{host}"),
            description: Some(host.split('.').next().unwrap_or(host).to_string()),
            priority,
            priority_rules: rules.iter().map(|(r, p)| (r.to_string(), *p)).collect(),
            ..Gateway::default()
        }
    }

    fn ms(n: u64) -> Probe {
        Probe::Answered(Duration::from_millis(n))
    }

    fn rank_with(
        gateways: &[Gateway],
        region: Option<&str>,
        probes: &[Probe],
        policy: Policy,
        preferred: Option<&str>,
    ) -> Ranking {
        rank(&RankInput {
            gateways,
            region,
            probes,
            policy,
            cutoff: Some(Duration::from_secs(5)),
            preferred,
        })
    }

    fn chosen_host(r: &Ranking) -> Option<&str> {
        r.chosen().map(|c| c.gateway.host())
    }

    #[test]
    fn region_rules_then_any() {
        let g = gw("a.example.com", Some(5), &[("US", 1), ("Any", 4)]);
        assert_eq!(effective_priority(&g, Some("US")), Some(1));
        assert_eq!(effective_priority(&g, Some("us")), Some(1));
        assert_eq!(effective_priority(&g, Some("DE")), Some(4));
        assert_eq!(effective_priority(&g, None), Some(4));
        let only_us = gw("b.example.com", None, &[("US", 2)]);
        assert_eq!(effective_priority(&only_us, Some("DE")), None);
        let no_rules = gw("c.example.com", None, &[]);
        assert_eq!(
            effective_priority(&no_rules, Some("DE")),
            Some(DEFAULT_PRIORITY)
        );
    }

    #[test]
    fn high_and_medium_compete_on_speed() {
        let gws = [
            gw("highest.example.com", Some(1), &[]),
            gw("medium.example.com", Some(3), &[]),
            gw("low.example.com", Some(4), &[]),
        ];
        let probes = [ms(80), ms(20), ms(5)];
        let pools = rank_with(&gws, None, &probes, Policy::Pools, None);
        assert_eq!(chosen_host(&pools), Some("medium.example.com"));
        let order: Vec<&str> = pools.gateways.iter().map(|r| r.gateway.host()).collect();
        assert_eq!(
            order,
            [
                "medium.example.com",
                "highest.example.com",
                "low.example.com"
            ]
        );

        let strict = rank_with(&gws, None, &probes, Policy::StrictTiers, None);
        assert_eq!(chosen_host(&strict), Some("highest.example.com"));
    }

    #[test]
    fn low_is_used_only_when_the_first_pool_is_down() {
        let gws = [
            gw("high.example.com", Some(2), &[]),
            gw("low.example.com", Some(5), &[]),
        ];
        let r = rank_with(&gws, None, &[Probe::Failed, ms(10)], Policy::Pools, None);
        assert_eq!(chosen_host(&r), Some("low.example.com"));
        assert_eq!(r.gateways[1].status, Status::Unreachable);
    }

    #[test]
    fn cutoff_manual_internal_and_region_exclusions() {
        let mut manual = gw("manual.example.com", Some(1), &[]);
        manual.manual = true;
        let mut internal = gw("internal.example.com", Some(1), &[]);
        internal.internal = true;
        let gws = [
            manual,
            internal,
            gw("us-only.example.com", None, &[("US", 1)]),
            gw("slow.example.com", Some(1), &[]),
            gw("ok.example.com", Some(3), &[]),
        ];
        let probes = [
            ms(1),
            ms(1),
            ms(1),
            Probe::Answered(Duration::from_secs(9)),
            ms(50),
        ];
        let r = rank_with(&gws, Some("DE"), &probes, Policy::Pools, None);
        assert_eq!(chosen_host(&r), Some("ok.example.com"));
        let status = |host: &str| {
            r.gateways
                .iter()
                .find(|g| g.gateway.host() == host)
                .map(|g| g.status.clone())
        };
        assert_eq!(status("manual.example.com"), Some(Status::ManualOnly));
        assert_eq!(status("internal.example.com"), Some(Status::Internal));
        assert_eq!(status("us-only.example.com"), Some(Status::NotForRegion));
        assert_eq!(status("slow.example.com"), Some(Status::Unreachable));
    }

    #[test]
    fn ties_go_to_the_higher_priority() {
        let gws = [
            gw("medium.example.com", Some(3), &[]),
            gw("highest.example.com", Some(1), &[]),
        ];
        let r = rank_with(&gws, None, &[ms(10), ms(10)], Policy::Pools, None);
        assert_eq!(chosen_host(&r), Some("highest.example.com"));
    }

    #[test]
    fn preferred_gateway_wins_or_falls_back() {
        let gws = [
            gw("fast.example.com", Some(1), &[]),
            gw("pref.example.com", Some(4), &[]),
        ];
        let r = rank_with(&gws, None, &[ms(5), ms(90)], Policy::Pools, Some("pref"));
        assert_eq!(chosen_host(&r), Some("pref.example.com"));

        let down = rank_with(
            &gws,
            None,
            &[ms(5), Probe::Failed],
            Policy::Pools,
            Some("pref.example.com"),
        );
        assert_eq!(chosen_host(&down), Some("fast.example.com"));
        assert!(down.explanation.iter().any(|e| e.contains("falling back")));

        let unknown = rank_with(&gws, None, &[ms(5), ms(9)], Policy::Pools, Some("nope"));
        assert_eq!(chosen_host(&unknown), Some("fast.example.com"));
    }

    #[test]
    fn nothing_available() {
        let gws = [gw("a.example.com", Some(1), &[])];
        let r = rank_with(&gws, None, &[Probe::Failed], Policy::Pools, None);
        assert_eq!(r.chosen, None);
        assert!(r.explanation.last().unwrap().contains("No gateway"));
    }

    #[test]
    fn unprobed_candidates_rank_by_priority() {
        let gws = [
            gw("b.example.com", Some(3), &[]),
            gw("a.example.com", Some(1), &[]),
        ];
        let r = rank_with(
            &gws,
            None,
            &[Probe::Unknown, Probe::Unknown],
            Policy::Pools,
            None,
        );
        assert_eq!(chosen_host(&r), Some("a.example.com"));
    }
}
