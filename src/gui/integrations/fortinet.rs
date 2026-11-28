//! Fortinet: SSL VPN, and IPsec with IKEv1 (XAuth) or IKEv2 (EAP); gateways tried in order.

use super::{
    ConnType, FieldId, Gateways, ImportSource, Integration, Section, SectionKind, field, field_help,
};
use crate::gui::Kind;

const BASICS: Section = Section {
    kind: SectionKind::Basics,
    fields: &[field(FieldId::Name, "Name")],
    summary: "",
};

const GATEWAYS: Section = Section {
    kind: SectionKind::Gateways,
    fields: &[field_help(
        FieldId::GatewayList,
        "Gateways",
        "",
        "Tried in order when one can't be reached. A wrong password stops there.",
    )],
    summary: "",
};

const USERNAME: super::Field = field_help(
    FieldId::Username,
    "Username",
    "",
    "Leave empty to be asked each time.",
);

const IPSEC_SIGN_IN: Section = Section {
    kind: SectionKind::SignIn,
    fields: &[
        USERNAME,
        field(FieldId::AskedWhenConnecting, "Pre-shared key"),
    ],
    summary: "",
};

const IPSEC_ADVANCED: &[super::Field] = &[
    field(FieldId::Pfs, "Perfect forward secrecy"),
    field(FieldId::DhGroup, "Key exchange group"),
    field_help(
        FieldId::LocalId,
        "Local ID",
        "This PC",
        "Only if IT gave you one.",
    ),
    field(FieldId::Tcp, "Use TCP on port 443"),
];

pub const INTEGRATION: Integration = Integration {
    id: "fortinet",
    name: "Fortinet",
    badge: "FT",
    summary: "FortiGate SSL VPN or IPsec",
    types: &[
        ConnType {
            id: "ssl",
            kind: Kind::FortinetSsl,
            name: "SSL VPN",
            full_name: "Fortinet SSL VPN",
            tag: Some("Most common"),
            summary: "Username and password, sometimes a code. Works on most networks.",
            ike2: false,
            gateways: Gateways::Ordered,
            sections: &[
                BASICS,
                GATEWAYS,
                Section {
                    kind: SectionKind::SignIn,
                    fields: &[USERNAME],
                    summary: "",
                },
                Section {
                    kind: SectionKind::Security,
                    fields: &[field(FieldId::TrustedCertificates, "Trusted certificates")],
                    summary: "",
                },
                Section {
                    kind: SectionKind::Advanced,
                    fields: &[field_help(
                        FieldId::Realm,
                        "Realm",
                        "None",
                        "Only if IT gave you one.",
                    )],
                    summary: "Realm",
                },
            ],
        },
        ConnType {
            id: "ipsec-ikev1",
            kind: Kind::FortinetIpsec,
            name: "IPsec · IKEv1",
            full_name: "Fortinet IPsec · IKEv1",
            tag: None,
            summary: "Pre-shared key, then username and password (XAuth).",
            ike2: false,
            gateways: Gateways::Ordered,
            sections: &[
                BASICS,
                GATEWAYS,
                IPSEC_SIGN_IN,
                Section {
                    kind: SectionKind::Advanced,
                    fields: IPSEC_ADVANCED,
                    summary: "Forward secrecy, key exchange",
                },
            ],
        },
        ConnType {
            id: "ipsec-ikev2",
            kind: Kind::FortinetIpsec,
            name: "IPsec · IKEv2",
            full_name: "Fortinet IPsec · IKEv2",
            tag: None,
            summary: "Pre-shared key, then username and password (EAP).",
            ike2: true,
            gateways: Gateways::Ordered,
            sections: &[
                BASICS,
                GATEWAYS,
                IPSEC_SIGN_IN,
                Section {
                    kind: SectionKind::Advanced,
                    fields: IPSEC_ADVANCED,
                    summary: "Forward secrecy, key exchange, TCP",
                },
            ],
        },
    ],
    import: Some(ImportSource {
        name: "FortiClient",
    }),
};
