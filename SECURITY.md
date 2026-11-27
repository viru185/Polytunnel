# Security policy

Polytunnel handles VPN credentials, session cookies and network configuration, so security
reports are very welcome.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through
[GitHub security advisories](https://github.com/viru185/Polytunnel/security/advisories/new).
You will get an answer within a few days.

**Do not include real hostnames, IP addresses, usernames, cookies or unredacted logs** in any
report. Once available, `polytunnel diag --redact` exports logs with those values replaced.

## Supported versions

Only the latest release gets fixes.

## Design principles

- **Least privilege.** Only the background service runs with administrator/root rights. It
  accepts typed requests over a local, access-controlled channel and never runs commands or
  paths supplied by the user-side app.
- **Secrets stay on the user side.** Passwords, pre-shared keys and reusable cookies live in the
  operating system's keyring (Windows Credential Manager, macOS Keychain, Secret Service). They
  are wiped from memory after use and never logged.
- **Honest device reports.** Host-information (HIP) reports always describe the real machine.
  Polytunnel never fakes posture data, client OS or version.
- **Verified updates.** Updates are signed; the service checks the signature before installing.
