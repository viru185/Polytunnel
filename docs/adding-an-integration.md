# Adding a VPN integration

Polytunnel's integrations are compiled in ([ADR 0005](adr/0005-integrations.md)). An
integration has a **connection side** (signing in, the tunnel) and a **window side** (how the
window shows and edits its profiles). This page lists every place you touch, in order.

## 1. The profile (`crates/polytunnel-core/src/profile.rs`)

- Add a `Profile` variant with its own struct, using `#[serde(rename_all = "kebab-case",
  deny_unknown_fields)]` like the others.
- Keep secrets out of it: passwords and pre-shared keys are asked when connecting and never
  saved.
- Add TOML round-trip tests.

## 2. The connect request (`crates/polytunnel-core/src/ipc.rs`)

- Add a `Connect` variant carrying what the service needs to bring the tunnel up after the
  app has signed in (cookies, addresses, the trusted certificate pin…), and validate it in
  `validate()`.
- This changes the service protocol: bump `PROTOCOL_VERSION` when an older service can't
  understand it.

## 3. Signing in (app side)

- Put the protocol in its own crate under `crates/` when it is more than a page of code. The
  existing `polytunnel-gp` and `polytunnel-forti` crates are the pattern.
- The window's worker (`src/gui/worker.rs`) logs in on a background thread and asks the user
  through `worker::Prompt`:
  - `Credentials`, `Code`, `Fields`, `Browser`, `Certificate`.
  - Reuse them; a new kind of question needs a new variant, plus its dialog in
    `src/gui/dialogs.rs`.
- The command line does the same in `src/auth.rs` and `src/connect.rs`.

## 4. The tunnel (service side)

- Add a module under `crates/polytunnel-daemon/src/` that turns the connect request into a
  running tunnel.
- Report the state through the same `Status` values, so the window, the tray and
  notifications work unchanged.
- Add an interop or fake-server test where possible (see `crates/polytunnel-http/tests/`).

## 5. The window (`src/gui/integrations/`)

- Add `<name>.rs` with an `Integration` constant and list it in `integrations::ALL`:
  - `name`, `badge` (two letters), `summary`: shown in "Add a profile". Use the vendor's
    product name as plain text; never their logo.
  - `types`: one `ConnType` per way to connect, each with:
    - `kind`, its names and summary;
    - `gateways` (`Ranked` or `Ordered`);
    - `sections`: the form, in the standard order **Basics · Gateways · Sign-in · Security ·
      Advanced**, using the existing `FieldId`s.
  - `import`: another program's profiles you can read, if any.
- Map the new `Profile` variant in `integrations::of` and `integrations::servers`.
- Map it in the editor model (`Editor::from_profile` / `to_profile` in `src/gui/mod.rs`).
- The registry tests check that names are unique, the sections are in order, and every type
  round-trips through the form.

## 6. Docs and checks

- Add the protocol notes under `docs/protocols/`.
- Run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` and `cargo xtask lint-fixtures`.
- Test data uses documentation addresses only: `example.com`, 192.0.2.0/24, 198.51.100.0/24
  and 203.0.113.0/24.
