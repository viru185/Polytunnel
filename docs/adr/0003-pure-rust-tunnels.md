# ADR 0003: Pure-Rust tunnels

Status: accepted

## Context

openconnect implements GlobalProtect and Fortinet SSL VPN tunnels, but using it from a
Windows service means: building it ourselves (no MSYS2 package exists), running its network
script through `cscript.exe`, injecting Ctrl-C into a hidden console to log out cleanly,
shipping GnuTLS DLLs, and publishing LGPL source bundles. It has no IKE support, so an IPsec
engine in Rust is needed anyway.

## Decision

Implement all tunnels in Rust:

- **GlobalProtect**: ESP over UDP with keys from the gateway configuration (shared with the
  IPsec code), falling back to the TLS tunnel.
- **Fortinet SSL VPN**: PPP (LCP, IPCP, IP6CP) over TLS.
- **Fortinet IPsec**: IKEv1, later IKEv2 with EAP and TCP encapsulation.

`polytunnel auth --emit openconnect` prints a cookie that a separately installed openconnect
can use, as an escape hatch while the tunnels mature.

## Consequences

- Smaller install, no third-party binaries except the signed Wintun driver DLL, easy ARM64
  builds.
- Polytunnel must match real servers' framing and state machines. Mitigations: protocol notes
  from public documentation, mock servers and strongSwan/libreswan interop tests in CI, and
  manual tests against real deployments with redacted logs.
