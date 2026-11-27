# Releasing

Releases come from release-please. Its "chore(main): release x.y.z" pull request collects
the Conventional Commits merged to `main`. Merging that pull request tags the release, and
`.github/workflows/release.yml` then:

1. generates `THIRD-PARTY-NOTICES.txt` (cargo-about);
2. builds and packages every target with `packaging/build.sh`:
   - MSI and zip for Windows x64 and ARM64;
   - deb, rpm and tarball for Linux amd64 and arm64;
   - the universal macOS pkg;
3. publishes `SHA256SUMS` and the update manifest `latest.json`.

## Signing (optional, by secrets)

Each signing step runs only when its secrets exist, so releases stay unsigned (but complete)
until you set up the accounts. Add the secrets under **Settings > Secrets and variables >
Actions**.

### Windows (Azure Trusted Signing)

Azure Trusted Signing signs the programs before they go into the MSI, then the MSI itself.
The workflow then runs `signtool verify /pa` on all of them.

| Secret | Value |
|---|---|
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | An app registration with the "Trusted Signing Certificate Profile Signer" role |
| `AZURE_SIGNING_ENDPOINT` | The account's region endpoint, e.g. `https://weu.codesigning.azure.net/` |
| `AZURE_SIGNING_ACCOUNT`, `AZURE_SIGNING_PROFILE` | The signing account and certificate profile names |

SignPath Foundation (free for open source) is an alternative. It needs its own action and an
approval flow, so it is not wired in.

### macOS (Developer ID and notarization)

| Secret | Value |
|---|---|
| `MACOS_APP_P12`, `MACOS_INSTALLER_P12` | Base64 of the "Developer ID Application" and "Developer ID Installer" certificates (`.p12`) |
| `MACOS_P12_PASSWORD` | Their export password |
| `APPLE_API_KEY`, `APPLE_API_KEY_ID`, `APPLE_API_ISSUER` | An App Store Connect API key (`.p8` contents, key ID, issuer ID) for notarization |

- The programs and the app bundle are signed with the hardened runtime.
- The pkg is signed with the installer certificate, then notarized and stapled.

### Checksums (GPG)

| Secret | Value |
|---|---|
| `GPG_PRIVATE_KEY` | An ASCII-armoured private key (`gpg --armor --export-secret-keys <id>`) |
| `GPG_PASSPHRASE` | Its passphrase |

With these set, `SHA256SUMS.asc` is published next to `SHA256SUMS`.

## Updates

The service checks `latest.json` from the latest release, and accepts it only if its
Ed25519 signature (`latest.json.sig`) verifies against the public key built into the
service.

Create the key pair once, on your own machine:

```sh
openssl genpkey -algorithm ed25519 -out polytunnel-update-key.pem
openssl pkey -in polytunnel-update-key.pem -pubout -outform DER | tail -c 32 | base64
```

- Put the whole `polytunnel-update-key.pem` in the secret `UPDATE_SIGNING_KEY`, and keep a
  safe offline copy.
- Put the base64 line in the repository variable `UPDATE_PUBLIC_KEY`. The release build
  compiles it into the service; a build without it cannot install updates.

If the key is ever lost or leaked, put out a new key in a normal release. Users install that
release by hand, and later updates follow the new key.
