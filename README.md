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

## Install

Download the package for your system from the
[latest release](https://github.com/viru185/Polytunnel/releases/latest). Each file has a
`.sha256` checksum next to it.

| System | File | What it installs |
|---|---|---|
| Windows x64 / ARM64 | `polytunnel-<version>-windows-x64.msi` / `-arm64.msi` | The app in Program Files, a Start menu entry and the Polytunnel service. Uninstall from **Settings > Apps**. |
| Debian, Ubuntu | `polytunnel_<version>_amd64.deb` / `_arm64.deb` | `sudo apt install ./polytunnel_<version>_amd64.deb` (the service starts at once) |
| Fedora, RHEL, openSUSE | `polytunnel-<version>-1.x86_64.rpm` / `.aarch64.rpm` | `sudo dnf install ./polytunnel-<version>-1.x86_64.rpm` |
| macOS (beta) | `polytunnel-<version>-macos-universal.pkg` | Polytunnel.app in Applications and its launch daemon |

Portable builds (`.zip` for Windows, `.tar.gz` for Linux) are there too; register their
service with `polytunnel-daemon install` as administrator or root. Releases are not code-signed
yet, so Windows SmartScreen may warn the first time; choose **More info > Run anyway**.

## The app

Run `polytunnel` (or open it from the Start menu) for the window: profiles for GlobalProtect and
Fortinet, **Connect**, the connection status, and for GlobalProtect a gateway table with
measured response times, **Find best gateway** and a preferred gateway. Sign-in prompts
(password, verification code, browser login with a paste box) appear in the window. A tiny tray
icon (`polytunnel tray`, about 2 MB of memory) shows whether you are connected; the window only
runs while it is open. FortiClient SSL VPN and IPsec profiles can be imported on Windows
(passwords and pre-shared keys are never read from FortiClient).

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
- On Windows and macOS, `--embedded` (or `embedded-login = true` in the profile, or the
  checkbox in the window) signs in in Polytunnel's own small login window instead of the
  browser; it catches the result by itself.
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

[profile.office-ipsec]
type = "fortinet-ipsec"
server = "vpn.example.net"
username = "me"
```

GlobalProtect profiles also accept `preferred-gateway = "<name>"`,
`gateway-selection = "pools"` (default) or `"strict-tiers"`, and `probe = "tls"` (default) or
`"tcp"`. Then `polytunnel auth work`.

### Connecting

Polytunnel's own tunnels run in a small background service, so connecting never needs an
administrator prompt. The installers set the service up; for a portable or source build,
install it once as administrator / root. Then connect as a normal user:

```sh
polytunnel-daemon install        # portable builds only; Windows: wintun.dll next to the exe
polytunnel connect work          # GlobalProtect: browser SSO, best gateway, tunnel up
polytunnel connect office        # Fortinet SSL VPN: password (+ code), PPP tunnel up
polytunnel connect office-ipsec  # Fortinet IPsec: pre-shared key, password (+ code)
polytunnel status
polytunnel disconnect
```

The GlobalProtect tunnel uses ESP over UDP when the gateway offers it and falls back to the
TLS tunnel. Routes, DNS (split DNS via NRPT on Windows, systemd-resolved on Linux) and IPv6
leak protection are applied by the service and rolled back on disconnect, even after a crash.
If the gateway asks for a host information (HIP) report, Polytunnel sends only real facts about
the machine. Fortinet SSL VPN runs PPP over TLS
([protocol notes](docs/protocols/fortinet-ssl.md)).

Fortinet IPsec profiles follow FortiClient's dial-up tunnels: IKEv1 aggressive mode with a
pre-shared key and XAuth, mode-config, PFS, dead-peer detection and NAT traversal (always on, so
ESP travels in UDP port 4500 and nothing clashes with FortiClient or the system's IKE service).
They also accept `dh-group` (14 by default), `local-id` and `local-id-type`
(`fqdn`, `user-fqdn`, `key-id`, `ipv4`), `ike-proposals` (`["aes256-sha256", ...]`),
`esp-proposals` (`["aes256-sha256", "aes256gcm16", ...]`), `pfs-group` (`0` turns PFS off),
`ike-lifetime`, `esp-lifetime`, `esp-lifetime-kb`, `xauth = false`, `mode-config = "push"`,
`remote-network = "a.b.c.d/len"`, `dpd` and `nat-keepalive` (seconds). One-time codes the
gateway asks for during sign-in are prompted for in the terminal or the window
([protocol notes](docs/protocols/fortigate-ikev1.md)).

With `ike-version = 2` the same profiles use IKEv2: a pre-shared key, or EAP sign-in
(`eap = "mschapv2"` or `"ttls-pap"`) to a gateway that proves itself with a pre-shared key or a
certificate (`server-auth = "certificate"`, checked against the system's roots plus an optional
`ca-file`, and issued for `remote-id`). `transport = "tcp"` (with `tcp-port`, default 443) runs
IKE and ESP over TCP as FortiOS's "transport tcp" does (RFC 9329)
([IKEv2 notes](docs/protocols/ikev2.md)):

```toml
[profile.office-ikev2]
type = "fortinet-ipsec"
server = "vpn.example.net"
ike-version = 2
eap = "mschapv2"
server-auth = "certificate"
transport = "tcp"
```

### Kill switch

`polytunnel killswitch connected` blocks traffic outside the tunnel while a tunnel is up;
`always` also blocks while disconnected (lockdown: then only the Polytunnel programs on Windows,
the last VPN servers and, with `--allow-lan`, the local network get through); `off` lifts it.
The VPN servers, loopback, DHCP and IPv6 neighbour discovery always pass. It uses the Windows
Filtering Platform (the rules vanish if the service stops, except in lockdown), nftables on
Linux and a pf anchor on macOS. The window has the same switches under Settings.

### Updates

`polytunnel update` asks the service whether a newer release exists; `polytunnel update
--install` installs it (Windows and macOS; Linux updates come from the package manager). The
service only trusts an update manifest signed with the project's update key, downloads the
installer into its own administrators-only folder and checks its SHA-256 before running it.
The tray checks once a day and offers the update in its menu (nothing is downloaded without a
click); set `POLYTUNNEL_NO_UPDATE_CHECK=1` to turn the daily check off.

## Building from source

Requires the stable Rust toolchain (see `rust-toolchain.toml`).

```sh
cargo build --release
cargo test --workspace
```

The binaries are `target/release/polytunnel` (app and CLI) and
`target/release/polytunnel-daemon` (background service).

`packaging/build.sh <target> <version>` turns a `cargo build --release --target <target>` into
the installers (MSI and zip, deb/rpm and tarball, or macOS pkg); the script's header lists the
tools each platform needs. The Windows MSI uses WiX 5 as a local .NET tool (`dotnet tool
restore`).

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
