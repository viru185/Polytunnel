//! GlobalProtect: portal sign-in (browser single sign-on, or Polytunnel's window), gateways
//! measured and ranked.

use super::{ConnType, FieldId, Gateways, Integration, Section, SectionKind, field, field_help};
use crate::gui::Kind;

pub const INTEGRATION: Integration = Integration {
    id: "globalprotect",
    name: "GlobalProtect",
    badge: "GP",
    summary: "Palo Alto Networks portals · browser sign-in",
    types: &[ConnType {
        id: "portal",
        kind: Kind::GlobalProtect,
        name: "GlobalProtect",
        full_name: "GlobalProtect",
        tag: None,
        summary: "Portal sign-in in your browser.",
        ike2: false,
        gateways: Gateways::Ranked,
        sections: &[
            Section {
                kind: SectionKind::Basics,
                fields: &[field(FieldId::Name, "Name")],
                summary: "",
            },
            Section {
                kind: SectionKind::Gateways,
                fields: &[field_help(
                    FieldId::Server,
                    "Portal",
                    "vpn.example.com",
                    "The address IT gave you. Gateways are picked automatically after you sign in.",
                )],
                summary: "",
            },
            Section {
                kind: SectionKind::SignIn,
                fields: &[
                    field(FieldId::SignInMode, "Sign in"),
                    field_help(
                        FieldId::Username,
                        "Username",
                        "",
                        "Leave empty to be asked each time.",
                    ),
                ],
                summary: "",
            },
        ],
    }],
    import: None,
};
