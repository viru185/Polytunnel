# Polytunnel

A lightweight, cross-platform VPN client written in Rust for **Palo Alto GlobalProtect** and
**Fortinet** (SSL VPN and IPsec), with native single sign-on and automatic best-gateway
selection.

> **Status: early development.** Nothing here is ready for daily use yet. Follow the
> [milestones](#roadmap) below.

## Why

Official clients are heavy and vendor-specific; the open-source ones each cover part of the
picture. Polytunnel aims to be one small app that handles:

- **GlobalProtect with SAML SSO**: sign in through your default browser (the
  `globalprotectcallback:` flow the official app uses), with a paste-the-callback fallback and
  an optional embedded login window.
- **Best gateway selection**: discovers the portal's gateways and ranks them the way the
  official app does (source region, then priority, then measured response time), with a
  *Find best gateway* button and a preferred gateway that falls back automatically.
- **Fortinet SSL VPN** with username and password (and two-factor prompts).
- **Fortinet dial-up IPsec**: IKEv1 (aggressive mode, pre-shared key + XAuth, mode-config,
  NAT traversal, dead-peer detection), then IKEv2 with EAP and IPsec over TCP.
- **Pure Rust tunnels**: no openconnect, no extra runtimes. A tiny tray process, a window that
  only runs while it is open, and a background service so connecting never needs an admin
  prompt.
- **Kill switch, auto-update and signed releases** (planned).

Platforms: Windows (x64, ARM64) first, Linux (x64, ARM64), macOS (beta).

## Roadmap

| Milestone | Scope |
|---|---|
| M0 | Workspace, CI/CD, release automation, repository hygiene |
| M1 | GlobalProtect and Fortinet login on the command line |
| M2 | GlobalProtect gateway discovery and best-gateway ranking |
| M3 | Network setup (TUN, routes, DNS) and ESP |
| M4 | Background service, IPC and the GlobalProtect tunnel |
| M5 | Fortinet SSL VPN tunnel |
| M6 | Tray agent and window |
| M7 | Installers (MSI, deb, rpm, pkg) and the first release |
| M8 | Fortinet IPsec (IKEv1) |
| M9 | IKEv2 with EAP, IPsec over TCP |
| M10–M11 | Embedded login window, kill switch |
| M12–M13 | Code signing, auto-update |

## Building from source

Requires the stable Rust toolchain (see `rust-toolchain.toml`).

```sh
cargo build --release
cargo test --workspace
```

The binaries are `target/release/polytunnel` (app and CLI) and
`target/release/polytunnel-daemon` (background service).

## Project layout

```
crates/polytunnel-core     shared types, validation, IPC schema
crates/polytunnel-app      `polytunnel`: tray agent, window, command line
crates/polytunnel-daemon   `polytunnel-daemon`: privileged background service
xtask                      repository tasks (`cargo xtask lint-fixtures`)
docs/                      architecture notes and decision records
```

More crates (GlobalProtect, Fortinet, IKE, ESP, networking, updates) arrive with their
milestones. See [docs/architecture.md](docs/architecture.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Never paste real hostnames, IP addresses, usernames,
cookies or logs from a VPN you use into issues or test data.

## Disclaimer

Polytunnel is an independent project, not affiliated with or endorsed by Palo Alto Networks or
Fortinet. Check that your organization allows third-party VPN clients before using it.

## License

[MIT](LICENSE)
