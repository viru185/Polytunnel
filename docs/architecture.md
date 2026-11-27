# Architecture

Polytunnel is split into small processes so that only the part that must change the
system's network configuration runs with elevated rights, and the part with a window only
exists while you look at it.

```
 user session                                   privileged
┌──────────────────────────────┐             ┌──────────────────────────────┐
│ polytunnel (tray agent)      │  local IPC  │ polytunnel-daemon            │
│  login orchestration, SSO    │◄───────────►│  tunnels: GP TLS/ESP,        │
│  callback, keyring, gateway  │  typed JSON │  Fortinet PPP, IKEv1/IKEv2   │
│  probes, update checks       │   frames    │  TUN, routes, DNS, journal   │
├──────────────────────────────┤             │  kill switch, HIP, updates   │
│ polytunnel --window (egui)   │             └──────────────────────────────┘
│  only while open             │
├──────────────────────────────┤
│ polytunnel-sso (optional)    │
│  embedded login window       │
└──────────────────────────────┘
```

## Processes

| Process | Runs as | Lifetime | Job |
|---|---|---|---|
| `polytunnel` (agent) | the user | from login, in the tray | Logins (browser SSO, portal/gateway exchanges, Fortinet logincheck), keyring access, gateway probing, update checks, talking to the daemon |
| `polytunnel --window` | the user | while the window is open | Profiles, connect/disconnect, gateway table, prompts, logs, settings |
| `polytunnel <subcommand>` | the user | one command | The same features from a terminal |
| `polytunnel-daemon` | LocalSystem / root | always (service) | Tunnel engines, network configuration and rollback journal, kill switch, honest HIP reports, verified updates |
| `polytunnel-sso` | the user | one login | Embedded browser for portals that cannot use the default browser |

## Crates

| Crate | Contents |
|---|---|
| `polytunnel-core` | Validated values, secrets, profile schema, IPC schema, redaction. No I/O. |
| `polytunnel-app` | The `polytunnel` binary. |
| `polytunnel-daemon` | The `polytunnel-daemon` binary. |
| `polytunnel-gp` *(M1)* | GlobalProtect: prelogin, SSO callback, portal and gateway exchanges, gateway ranking and probing, HIP report, tunnel framing. |
| `polytunnel-forti` *(M1)* | Fortinet: SSL VPN login, PPP over TLS, FortiClient profile import. |
| `polytunnel-net` *(M3)* | TUN, routes, DNS/NRPT, rollback journal, kill switch. |
| `polytunnel-esp` *(M3)* | ESP security associations, replay window, UDP encapsulation. |
| `polytunnel-ike` *(M8)* | IKEv1 and IKEv2 (with EAP), TCP encapsulation. |
| `polytunnel-update` *(M13)* | Signed update manifests. |
| `polytunnel-sso` *(M10)* | Embedded login window. |

Protocol code is written "sans I/O": it turns bytes into events and decisions, and a thin
transport layer does the actual networking. That keeps every protocol testable with fixtures.

## Decision records

- [ADR 0001: process split](adr/0001-process-split.md)
- [ADR 0002: TLS stack](adr/0002-tls-stack.md)
- [ADR 0003: pure-Rust tunnels](adr/0003-pure-rust-tunnels.md)
- [ADR 0004: Windows installer](adr/0004-windows-installer.md)
