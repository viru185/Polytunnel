//! The window's view of the VPN integrations: each one describes itself (name, badge,
//! connection types, what it can do, and the fields of its profile form) and the screens loop
//! over [`ALL`] instead of naming integrations. Adding an integration's window side is one
//! file here plus one line in [`ALL`]; its connection side is listed in
//! `docs/adding-an-integration.md`.

mod fortinet;
mod globalprotect;

use polytunnel_core::profile::Profile;

use super::Kind;

/// Every integration the window offers, in the order "Add a profile" lists them.
pub const ALL: &[&Integration] = &[&globalprotect::INTEGRATION, &fortinet::INTEGRATION];

/// One VPN integration (a vendor's family of connection types).
#[derive(Debug)]
pub struct Integration {
    pub id: &'static str,
    pub name: &'static str,
    /// Two letters for its badge.
    pub badge: &'static str,
    /// One line under its name in "Add a profile".
    pub summary: &'static str,
    pub types: &'static [ConnType],
    /// Another program's profiles it can import, if any.
    pub import: Option<ImportSource>,
}

/// A way to connect within an integration (Fortinet: SSL VPN, IPsec IKEv1, IPsec IKEv2).
#[derive(Debug)]
pub struct ConnType {
    pub id: &'static str,
    pub kind: Kind,
    /// Its name in the type picker ("SSL VPN").
    pub name: &'static str,
    /// Its full name on profile rows and the form's title ("Fortinet SSL VPN").
    pub full_name: &'static str,
    pub tag: Option<&'static str>,
    pub summary: &'static str,
    /// For IPsec: IKEv2 (`true`) or IKEv1.
    pub ike2: bool,
    pub gateways: Gateways,
    pub sections: &'static [Section],
}

/// How an integration's gateways are chosen; Home's gateway row follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gateways {
    /// Measured and ranked by latency (a picker: Fastest / Prefer one / Only one).
    Ranked,
    /// Tried in the order of the list (failover).
    Ordered,
}

/// Where another program's profiles come from.
#[derive(Debug)]
pub struct ImportSource {
    pub name: &'static str,
}

/// The form's standard sections, always in this order; a type fills the ones it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Basics,
    Gateways,
    SignIn,
    Security,
    Advanced,
}

impl SectionKind {
    pub fn title(self) -> &'static str {
        match self {
            SectionKind::Basics => "Basics",
            SectionKind::Gateways => "Gateways",
            SectionKind::SignIn => "Sign-in",
            SectionKind::Security => "Security",
            SectionKind::Advanced => "Advanced",
        }
    }
}

#[derive(Debug)]
pub struct Section {
    pub kind: SectionKind,
    pub fields: &'static [Field],
    /// For Advanced: the summary shown while it is folded.
    pub summary: &'static str,
}

/// One field of a profile form: which value it edits and how it is shown.
#[derive(Debug)]
pub struct Field {
    pub id: FieldId,
    pub label: &'static str,
    pub hint: &'static str,
    pub help: Option<&'static str>,
}

/// The values a form can edit (the editor maps each to its model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldId {
    Name,
    /// A single server or portal.
    Server,
    /// The ordered gateway list (the first is the server).
    GatewayList,
    Username,
    /// Browser or Polytunnel window sign-in (GlobalProtect).
    SignInMode,
    /// A secret asked when connecting, never saved (the pre-shared key).
    AskedWhenConnecting,
    /// The trusted gateway certificates (added from the trust prompt).
    TrustedCertificates,
    Realm,
    Pfs,
    DhGroup,
    LocalId,
    Tcp,
}

pub const fn field(id: FieldId, label: &'static str) -> Field {
    Field {
        id,
        label,
        hint: "",
        help: None,
    }
}

pub const fn field_help(
    id: FieldId,
    label: &'static str,
    hint: &'static str,
    help: &'static str,
) -> Field {
    Field {
        id,
        label,
        hint,
        help: Some(help),
    }
}

/// The integration and connection type of a form's kind (and IKE version).
pub fn find(kind: Kind, ike2: bool) -> (&'static Integration, &'static ConnType) {
    for integration in ALL {
        for t in integration.types {
            if t.kind == kind && (kind != Kind::FortinetIpsec || t.ike2 == ike2) {
                return (integration, t);
            }
        }
    }
    unreachable!("every kind has a connection type")
}

/// The integration and connection type of a saved profile.
pub fn of(profile: &Profile) -> (&'static Integration, &'static ConnType) {
    match profile {
        Profile::GlobalProtect(_) => find(Kind::GlobalProtect, false),
        Profile::FortinetSsl(_) => find(Kind::FortinetSsl, false),
        Profile::FortinetIpsec(p) => find(Kind::FortinetIpsec, crate::ipsec::ike_version(p) == 2),
    }
}

/// The profile's servers: the portal, or the gateways in order.
pub fn servers(profile: &Profile) -> Vec<String> {
    match profile {
        Profile::GlobalProtect(p) => vec![p.portal.clone()],
        Profile::FortinetSsl(p) => p.servers(),
        Profile::FortinetIpsec(p) => p.servers(),
    }
}

/// `gw.example.net`, `gw.example.net + 1 backup`, `gw.example.net + 2 backups`.
pub fn hosts_line(servers: &[String]) -> String {
    let first = servers
        .first()
        .map(|s| s.trim_start_matches("https://"))
        .unwrap_or("");
    match servers.len() {
        0 | 1 => first.to_string(),
        2 => format!("{first} + 1 backup"),
        n => format!("{first} + {} backups", n - 1),
    }
}

/// The line under a profile's name: `Fortinet SSL VPN · gw.example.net + 1 backup`.
pub fn profile_line(profile: &Profile) -> String {
    let (_, t) = of(profile);
    format!("{} · {}", t.full_name, hosts_line(&servers(profile)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui::Editor;

    #[test]
    fn names_and_badges_are_unique() {
        let mut names = Vec::new();
        let mut badges = Vec::new();
        let mut ids = Vec::new();
        for i in ALL {
            names.push(i.name);
            badges.push(i.badge);
            for t in i.types {
                ids.push((i.id, t.id));
            }
        }
        for list in [&mut names, &mut badges] {
            let n = list.len();
            list.sort_unstable();
            list.dedup();
            assert_eq!(list.len(), n);
        }
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn every_type_has_name_and_gateways_sections_in_order() {
        for i in ALL {
            for t in i.types {
                let kinds: Vec<SectionKind> = t.sections.iter().map(|s| s.kind).collect();
                let mut sorted = kinds.clone();
                sorted.sort_by_key(|k| *k as u8);
                assert_eq!(kinds, sorted, "{} sections out of order", t.full_name);
                let fields: Vec<FieldId> = t
                    .sections
                    .iter()
                    .flat_map(|s| s.fields.iter().map(|f| f.id))
                    .collect();
                assert!(fields.contains(&FieldId::Name), "{}", t.full_name);
                assert!(
                    fields.contains(&FieldId::Server) || fields.contains(&FieldId::GatewayList),
                    "{}",
                    t.full_name
                );
            }
        }
    }

    #[test]
    fn every_type_makes_a_profile_and_finds_itself_again() {
        for i in ALL {
            for t in i.types {
                let mut editor = Editor::new(t.kind);
                editor.ike2 = t.ike2;
                editor.eap = t.ike2;
                editor.name = "test".into();
                editor.server = if t.kind == Kind::FortinetIpsec {
                    "198.51.100.7".into()
                } else {
                    "vpn.example.com".into()
                };
                let (_, profile) = editor
                    .to_profile()
                    .unwrap_or_else(|e| panic!("{}: {e}", t.full_name));
                let (found_i, found_t) = of(&profile);
                assert_eq!((found_i.id, found_t.id), (i.id, t.id));
                let back = Editor::from_profile("test", &profile);
                assert_eq!((back.kind, back.ike2), (t.kind, t.ike2));
            }
        }
    }

    #[test]
    fn host_lines() {
        assert_eq!(hosts_line(&["gw.example.net".into()]), "gw.example.net");
        assert_eq!(
            hosts_line(&["gw.example.net:10443".into(), "b.example.net".into()]),
            "gw.example.net:10443 + 1 backup"
        );
        assert_eq!(
            hosts_line(&["a".into(), "b".into(), "c".into()]),
            "a + 2 backups"
        );
    }
}
