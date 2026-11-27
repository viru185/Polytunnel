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

## Usage (early preview)

Log in from the command line. Until Polytunnel's own tunnels land (M4), you can hand the
session to a separately installed [openconnect](https://www.infradead.org/openconnect/):

```sh
# GlobalProtect: your default browser opens for single sign-on
polytunnel auth gp vpn.example.com
polytunnel auth gp vpn.example.com --emit cookie | openconnect --protocol=gp --os=win --cookie-on-stdin gw.example.com

# Fortinet SSL VPN (username/password, plus a code if two-factor is on)
polytunnel auth fortinet vpn.example.net:10443 --user me --emit cookie \
  | openconnect --protocol=fortinet --cookie-on-stdin vpn.example.net:10443
```

- The first browser login registers Polytunnel for `globalprotectcallback:` links for your
  user account (`polytunnel uri status|register|unregister`). If the browser cannot hand the
  login back, add `--paste` and paste the link (or the final page's source) into the terminal.
- Without `--gateway`, Polytunnel measures every gateway's TLS handshake time in parallel and
  picks the best one the way the official app does (source region, then the Highest/High/Medium
  pool before Low/Lowest, then speed). `--prefer <name>` uses a gateway when it answers and
  falls back to the best one; `--gateway <name>` always uses that gateway.
- `polytunnel gateways <profile>` shows the ranking (the gateway list is saved at each login,
  so this does not log in again; `--refresh` does). `--emit json` / `--json` print JSON.
- Profiles in `profiles.toml` (`polytunnel profiles` shows where) save typing:

```toml
[profile.work]
type = "global-protect"
portal = "vpn.example.com"

[profile.office]
type = "fortinet-ssl"
server = "vpn.example.net:10443"
username = "me"
```

GlobalProtect profiles also accept `preferred-gateway = "<name>"`,
`gateway-selection = "pools"` (default) or `"strict-tiers"`, and `probe = "tls"` (default) or
`"tcp"`. Then `polytunnel auth work`.

### Connecting

Polytunnel's own tunnels run in a small background service, so connecting never needs an
administrator prompt. Install the service once (administrator / root), then connect as a
normal user:

```sh
polytunnel-daemon install        # once; Windows: put wintun.dll next to polytunnel-daemon.exe
polytunnel connect work          # GlobalProtect: browser SSO, best gateway, tunnel up
polytunnel connect office        # Fortinet SSL VPN: password (+ code), PPP tunnel up
polytunnel status
polytunnel disconnect
```

The GlobalProtect tunnel uses ESP over UDP when the gateway offers it and falls back to the
TLS tunnel. Routes, DNS (split DNS via NRPT on Windows, systemd-resolved on Linux) and IPv6
leak protection are applied by the service and rolled back on disconnect, even after a crash.
If the gateway asks for a host information (HIP) report, Polytunnel sends only real facts about
the machine. Fortinet tunnels follow in the next milestone.

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
src/                       `polytunnel` (root crate): tray agent, window, command line
crates/polytunnel-core     shared types: HTTP abstraction, secrets, profiles, XML reader
crates/polytunnel-gp       GlobalProtect login (pre-login, SAML callback, portal, gateway)
crates/polytunnel-forti    Fortinet SSL VPN login
crates/polytunnel-daemon   `polytunnel-daemon`: privileged background service
xtask                      repository tasks (`cargo xtask lint-fixtures`)
docs/                      architecture notes, decision records, protocol notes
```

More crates (IKE, ESP, networking, updates) arrive with their milestones. See [docs/architecture.md](docs/architecture.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Never paste real hostnames, IP addresses, usernames,
cookies or logs from a VPN you use into issues or test data.

## Disclaimer

Polytunnel is an independent project, not affiliated with or endorsed by Palo Alto Networks or
Fortinet. Check that your organization allows third-party VPN clients before using it.

## License

[MIT](LICENSE)
