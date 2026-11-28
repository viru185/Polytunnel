# ADR 0005: VPN integrations are compiled in and described to the window

Status: accepted

## Context

Polytunnel connects to GlobalProtect and Fortinet (SSL VPN, IPsec IKEv1 and IKEv2). More VPN
families will follow (for example the openconnect family: AnyConnect, Pulse/Ivanti, F5,
Array), and other developers may add theirs. Before this, the window named each integration in
many places: the "+" menu, profile rows, the form, Home's gateway area. Adding one meant
touching every screen.

Two directions were considered:

- **Runtime plugins** (separate binaries or libraries loaded at run time). This is rejected.
  The tunnel side runs in the Polytunnel service as SYSTEM, so a plugin would run with
  SYSTEM's rights. That would need signing, sandboxing and a stable plugin ABI that a small
  project can't maintain safely.
- **Compiled-in integrations that describe themselves.** This is accepted.

## Decision

- Each integration is compiled into Polytunnel.
- The window learns about it from a descriptor in `src/gui/integrations/<name>.rs`, listed
  once in `integrations::ALL`. A descriptor gives:
  - name, a two-letter badge and a one-line summary ("Add a profile");
  - its **connection types** (Fortinet: SSL VPN, IPsec IKEv1, IPsec IKEv2);
  - what it can do: gateways **ranked** by latency (Home opens a picker) or tried **in order**
    (Home opens the gateway order), and an import source;
  - per connection type, the form's fields in the standard sections **Basics · Gateways ·
    Sign-in · Security · Advanced**, using a fixed set of field kinds.
- The screens loop over `ALL`, so a new integration's window side is one file plus one line.
- The connection side stays ordinary code with four touch points, listed in
  `docs/adding-an-integration.md`.

## Consequences

- A new integration gets every window surface for free: Add a profile, the type picker,
  profile rows, Home's gateway row, the form and Activity.
- Field kinds an integration needs but the window lacks (for example a client-certificate file
  picker) are added once to `FieldId` and the editor, then reused.
- The service's protocol grows one connect request per integration; that is reviewed like any
  protocol change.
