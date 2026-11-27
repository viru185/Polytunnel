# ADR 0001: Process split

Status: accepted

## Context

A VPN client must create network adapters and change routes and DNS, which needs
administrator/root rights. Logging in, on the other hand, needs the user's browser, the user's
keyring and a user interface. Running everything elevated (as many open-source clients do)
means a UAC prompt on every connect and a large privileged attack surface. The app must also be
as light as possible.

## Decision

- **`polytunnel-daemon`** runs as a service (LocalSystem / root / launchd). It owns tunnels and
  all network changes, and accepts only typed, validated requests over a local IPC channel
  (Windows named pipe with an explicit security descriptor; Unix socket with peer-credential
  checks). It never runs commands, scripts or paths supplied by a client.
- **`polytunnel`** runs as the user. By default it is a tray agent with no graphics context
  (a few MB). It does all authentication and keeps secrets in the OS keyring.
- **`polytunnel --window`** is a separate process started on demand that fully exits when the
  window closes, so the GPU driver's memory is returned.
- Prompts that arise inside the daemon (XAuth, one-time codes, EAP) are relayed to the user
  side over the same IPC channel.

## Consequences

- No elevation prompt per connection; the installer registers the service once.
- The daemon must defend its IPC boundary: caller identity checks, input validation, size
  limits, protocol versioning.
- The window costs memory only while it is open.
