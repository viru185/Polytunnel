//! Updates. The service reads `latest.json` from the latest GitHub release and trusts it only
//! if its Ed25519 signature (`latest.json.sig`) verifies against the key built into this
//! program (docs/releasing.md). To install, it downloads the installer into its own
//! administrators-only folder, checks the SHA-256 the manifest names, and runs it (Windows:
//! msiexec; macOS: installer). It never installs a file a user process handed it. Linux
//! systems update through their package manager.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use base64::Engine;
use polytunnel_core::ipc::Response;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{info, paths, warn};

const REPOSITORY: &str = "https://github.com/viru185/Polytunnel";
const ALLOWED_HOSTS: [&str; 3] = [
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];
const MAX_MANIFEST: u64 = 16 * 1024;
const MAX_SIGNATURE: u64 = 512;
const MAX_INSTALLER: u64 = 256 * 1024 * 1024;
/// The update key (base64 of the raw 32-byte Ed25519 public key), from the release build.
const PUBLIC_KEY: Option<&str> = option_env!("POLYTUNNEL_UPDATE_KEY");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: String,
    pub assets: BTreeMap<String, Asset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub name: String,
    pub sha256: String,
}

/// Whether `latest` is a newer release than `current`.
pub fn newer(latest: &str, current: &str) -> bool {
    polytunnel_core::is_newer_version(latest, current)
}

/// Checks the signature, then the manifest's shape.
pub fn verify(manifest: &[u8], signature_b64: &str, key_b64: &str) -> Result<Manifest, String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let key = b64
        .decode(key_b64.trim())
        .ok()
        .filter(|k| k.len() == 32)
        .ok_or("the built-in update key is invalid")?;
    let signature = b64
        .decode(signature_b64.trim())
        .ok()
        .filter(|s| s.len() == 64)
        .ok_or("the update signature is malformed")?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key)
        .verify(manifest, &signature)
        .map_err(|_| "the update manifest's signature did not verify".to_string())?;
    let parsed: Manifest = serde_json::from_slice(manifest)
        .map_err(|e| format!("the update manifest is malformed: {e}"))?;
    if !polytunnel_core::is_version(&parsed.version) {
        return Err("the update manifest has an invalid version".into());
    }
    for asset in parsed.assets.values() {
        let safe_name = !asset.name.is_empty()
            && asset.name.len() <= 128
            && !asset.name.starts_with('.')
            && asset
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        let hash = asset.sha256.len() == 64 && asset.sha256.bytes().all(|b| b.is_ascii_hexdigit());
        if !safe_name || !hash {
            return Err("the update manifest names an invalid file".into());
        }
    }
    Ok(parsed)
}

/// The manifest entry for this system's installer.
pub fn platform_asset() -> Option<&'static str> {
    if cfg!(all(windows, target_arch = "x86_64")) {
        Some("windows-x64")
    } else if cfg!(all(windows, target_arch = "aarch64")) {
        Some("windows-arm64")
    } else if cfg!(target_os = "macos") {
        Some("macos")
    } else {
        None
    }
}

fn fetch_latest() -> Result<Manifest, String> {
    let key = PUBLIC_KEY
        .filter(|k| !k.is_empty())
        .ok_or("this build cannot verify updates (it was made without the update key)")?;
    let base = format!("{REPOSITORY}/releases/latest/download");
    let get = |name: &str, max| {
        polytunnel_http::download(&format!("{base}/{name}"), &ALLOWED_HOSTS, max)
            .map_err(|e| format!("cannot fetch {name}: {e}"))
    };
    let manifest = get("latest.json", MAX_MANIFEST)?;
    let signature = get("latest.json.sig", MAX_SIGNATURE)?;
    verify(&manifest, &String::from_utf8_lossy(&signature), key)
}

/// Downloads, checks and starts the installer (in the background).
fn install(manifest: &Manifest, asset: &Asset) -> Result<(), String> {
    let url = format!(
        "{REPOSITORY}/releases/download/v{}/{}",
        manifest.version, asset.name
    );
    let data = polytunnel_http::download(&url, &ALLOWED_HOSTS, MAX_INSTALLER)
        .map_err(|e| format!("cannot download the installer: {e}"))?;
    let digest: String = Sha256::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if !digest.eq_ignore_ascii_case(&asset.sha256) {
        return Err("the downloaded installer does not match the manifest".into());
    }
    let dir = paths::ensure_state_dir()
        .map_err(|e| e.to_string())?
        .join("updates");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(&asset.name);
    fs::write(&path, &data).map_err(|e| format!("cannot save the installer: {e}"))?;
    info!(
        "installing Polytunnel {} from {}",
        manifest.version,
        path.display()
    );
    run_installer(&path, &dir)
}

#[cfg(windows)]
fn run_installer(path: &Path, dir: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let msiexec = std::path::PathBuf::from(root)
        .join("System32")
        .join("msiexec.exe");
    std::process::Command::new(msiexec)
        .arg("/i")
        .arg(path)
        .args(["/qn", "/norestart", "/l*v"])
        .arg(dir.join("install.log"))
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("cannot start the installer: {e}"))
}

#[cfg(target_os = "macos")]
fn run_installer(path: &Path, _dir: &Path) -> Result<(), String> {
    std::process::Command::new("/usr/sbin/installer")
        .arg("-pkg")
        .arg(path)
        .args(["-target", "/"])
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("cannot start the installer: {e}"))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn run_installer(_path: &Path, _dir: &Path) -> Result<(), String> {
    Err("install updates with the package manager".into())
}

/// Answers an update request.
pub fn handle(install_it: bool) -> Response {
    let current = polytunnel_core::VERSION.to_string();
    let reply = |latest: Option<String>, installing, message: String| Response::Update {
        current: current.clone(),
        latest,
        installing,
        message,
    };
    let manifest = match fetch_latest() {
        Ok(m) => m,
        Err(e) => return reply(None, false, e),
    };
    let latest = Some(manifest.version.clone());
    if !newer(&manifest.version, &current) {
        return reply(
            latest,
            false,
            format!("Polytunnel {current} is up to date."),
        );
    }
    let asset = platform_asset().and_then(|kind| manifest.assets.get(kind).cloned());
    if !install_it {
        let how = if asset.is_some() {
            "install it with `polytunnel update --install` or from the window"
        } else {
            "install it with your package manager"
        };
        return reply(
            latest,
            false,
            format!(
                "Polytunnel {} is available (this is {current}); {how}.",
                manifest.version
            ),
        );
    }
    let Some(asset) = asset else {
        return reply(
            latest,
            false,
            format!(
                "Polytunnel {} is available; install it with your package manager ({REPOSITORY}/releases).",
                manifest.version
            ),
        );
    };
    let version = manifest.version.clone();
    std::thread::spawn(move || {
        if let Err(e) = install(&manifest, &asset) {
            warn!("the update failed: {e}");
        }
    });
    reply(
        latest,
        true,
        format!(
            "Downloading and installing Polytunnel {version}; the service restarts when it is done."
        ),
    )
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    fn keys() -> (Ed25519KeyPair, String) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public = base64::engine::general_purpose::STANDARD.encode(pair.public_key().as_ref());
        (pair, public)
    }

    fn sign(pair: &Ed25519KeyPair, data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(pair.sign(data).as_ref())
    }

    const MANIFEST: &str = r#"{
  "assets": {
    "windows-x64": { "name": "polytunnel-0.2.0-windows-x64.msi", "sha256": "0000000000000000000000000000000000000000000000000000000000000000" }
  },
  "version": "0.2.0"
}"#;

    #[test]
    fn signed_manifests_verify_and_others_do_not() {
        let (pair, public) = keys();
        let m = verify(
            MANIFEST.as_bytes(),
            &sign(&pair, MANIFEST.as_bytes()),
            &public,
        )
        .unwrap();
        assert_eq!(m.version, "0.2.0");
        assert_eq!(
            m.assets["windows-x64"].name,
            "polytunnel-0.2.0-windows-x64.msi"
        );

        let tampered = MANIFEST.replace("0.2.0", "9.9.9");
        let err = verify(
            tampered.as_bytes(),
            &sign(&pair, MANIFEST.as_bytes()),
            &public,
        )
        .unwrap_err();
        assert!(err.contains("signature"), "{err}");
        let (other, _) = keys();
        assert!(
            verify(
                MANIFEST.as_bytes(),
                &sign(&other, MANIFEST.as_bytes()),
                &public
            )
            .is_err()
        );
        assert!(verify(MANIFEST.as_bytes(), "not base64!", &public).is_err());
        assert!(
            verify(
                MANIFEST.as_bytes(),
                &sign(&pair, MANIFEST.as_bytes()),
                "c2hvcnQ="
            )
            .is_err()
        );
    }

    #[test]
    fn signed_but_unsafe_manifests_are_refused() {
        let (pair, public) = keys();
        for bad in [
            MANIFEST.replace("polytunnel-0.2.0-windows-x64.msi", "../../evil.msi"),
            MANIFEST.replace("\"0.2.0\"", "\"latest\""),
            MANIFEST.replace(
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abc",
            ),
            MANIFEST.replace("\"version\"", "\"extra\": 1, \"version\""),
        ] {
            assert!(
                verify(bad.as_bytes(), &sign(&pair, bad.as_bytes()), &public).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn version_order() {
        assert!(newer("0.2.0", "0.1.9"));
        assert!(newer("v1.0.0", "0.9.9"));
        assert!(newer("0.10.0", "0.9.0"));
        assert!(!newer("0.1.0", "0.1.0"));
        assert!(!newer("0.0.9", "0.1.0"), "no downgrades");
        assert!(!newer("garbage", "0.1.0"));
        assert!(!newer("1.0", "0.1.0"));
    }

    #[test]
    fn this_platform_has_an_asset_kind_where_installers_exist() {
        if cfg!(any(windows, target_os = "macos")) {
            assert!(platform_asset().is_some());
        }
    }
}
