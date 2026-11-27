# Contributing

## Setup

```sh
git config core.hooksPath .githooks
```

This enables two hooks:

- **commit-msg** checks that every commit message is a
  [Conventional Commit](https://www.conventionalcommits.org) (`feat(gp): ...`, `fix(net): ...`).
- **pre-commit** blocks commits that contain strings from your **local denylist** and runs
  [gitleaks](https://github.com/gitleaks/gitleaks) on the staged changes if it is installed.

### The local denylist

This repository is public. If you work with real VPN servers, list the identifiers that must
never be published (company domains, gateway hostnames, office IP addresses, your usernames)
in a file **inside `.git`**, so the list itself can never be committed:

```sh
# one fixed string per line, case-insensitive; # starts a comment
$EDITOR "$(git rev-parse --git-path info/polytunnel-denylist)"
```

`POLYTUNNEL_DENYLIST=/path/to/file` points the hooks at another file.

## Test data rules

- Hostnames: `example.com`, `example.net`, `example.org`, or names ending in `.example`,
  `.test`, `.invalid` or `.localhost`.
- IP addresses: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and `2001:db8::/32`
  (private ranges are fine too).
- Cookies, keys and passwords: obviously fake values such as `FAKE-authcookie-0001`.
- Never commit captures (`.pcap`, `.har`), raw logs or real server responses. Rewrite them by
  hand into synthetic fixtures.

`cargo xtask lint-fixtures` enforces the first two rules and runs in CI, together with a
gitleaks scan of the full history.

## Checks

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo xtask lint-fixtures
```

## Pull requests

PRs are squash-merged with the PR title as the commit message, so the title must be a
Conventional Commit too. Releases are cut by release-please from those messages.

## Protocol code

Protocol implementations are written from public documentation and observed protocol behaviour
only. Do not copy code from GPL- or LGPL-licensed projects into this repository.
