//! IKE for Polytunnel.
//!
//! IKEv1 ([RFC 2408], [RFC 2409]) the way FortiGate dial-up IPsec uses it: aggressive mode
//! with a pre-shared key, XAuth, mode-config, NAT traversal ([RFC 3947]), dead-peer detection
//! ([RFC 3706]) and quick mode with PFS. Nothing here does I/O: the daemon passes in datagrams,
//! the time and the user's answers, and carries out what comes back.
//!
//! [RFC 2408]: https://www.rfc-editor.org/rfc/rfc2408
//! [RFC 2409]: https://www.rfc-editor.org/rfc/rfc2409
//! [RFC 3947]: https://www.rfc-editor.org/rfc/rfc3947
//! [RFC 3706]: https://www.rfc-editor.org/rfc/rfc3706

pub mod dh;
pub mod prf;
pub mod v1;
