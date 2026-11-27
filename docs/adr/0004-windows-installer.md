# ADR 0004: Windows installer

Status: accepted

## Context

Polytunnel must install like a normal Windows application (Start menu entry, clean
uninstall, upgrades) and register a Windows service. Options considered: WiX (MSI), NSIS,
Inno Setup, cargo-wix/cargo-packager.

## Decision

Build an **MSI with WiX Toolset 5.0.2**, for x64 and ARM64:

- `ServiceInstall` / `ServiceControl` register, stop, restart and remove `polytunnel-daemon`;
  `MajorUpgrade` replaces older versions without leaving a duplicate service.
- Per-machine install, Start menu shortcut, licences included.
- Built in GitHub Actions with the .NET SDK (`dotnet tool install --global wix --version 5.0.2`).

WiX 6 and later require accepting the Open Source Maintenance Fee EULA; 5.0.2 is the last
release under the plain MS-RL licence. cargo-wix and cargo-packager generate WiX v3 projects,
which is end-of-life.

## Consequences

- MSI works with Intune/GPO and `msiexec /qn` out of the box.
- Moving to a newer WiX later means accepting its EULA terms.
