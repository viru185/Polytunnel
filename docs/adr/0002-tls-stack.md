# ADR 0002: TLS stack

Status: accepted

## Context

Corporate VPN portals often use certificates issued by an internal CA that is installed in the
operating system's trust store, and some older appliances still negotiate CBC cipher suites.
The user-side process should stay small.

## Decision

- Use **`native-tls`** (SChannel on Windows, Security.framework on macOS, OpenSSL on Linux) for
  HTTPS logins and for the TLS-based tunnels. It trusts exactly what the OS trusts and supports
  the cipher suites the OS supports.
- Use **`ureq`** (no async runtime) for HTTP on the user side; **tokio** only in the daemon.
- Use **`rustls`** only where a TLS engine must run inside another protocol (EAP-TTLS inside
  IKEv2), because it can be driven over in-memory buffers.
- The user side validates the gateway certificate during login and hands its SHA-256 pin to the
  daemon; the daemon's tunnel connection must pass OS validation **and** match the pin.

## Consequences

- No bundled root store and no OpenSSL vendoring.
- TLS behaviour differs slightly between platforms; tests run on all three.
