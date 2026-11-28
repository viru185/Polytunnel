//! Writing `profiles.toml` (and the window's settings file), for the window and the command
//! line alike.

use std::fs;
use std::path::Path;

use polytunnel_core::pin::CertFingerprint;
use polytunnel_core::profile::{Profile, Profiles};

use crate::paths;

/// Writes `text` to `path` through a temporary file, so a failed write never leaves half a
/// file, and keeps the previous version next to it as `<name>.bak`.
pub fn write_with_backup(path: &Path, text: &str) -> Result<(), String> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!("{name}.tmp"));
    fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
    if path.exists() {
        let _ = fs::copy(path, path.with_file_name(format!("{name}.bak")));
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })
}

/// Saves every profile to the profiles file.
pub fn save_profiles(profiles: &Profiles) -> Result<(), String> {
    let path = paths::profiles_file().ok_or("no configuration directory")?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    write_with_backup(&path, &profiles.to_toml())
}

/// Makes Fortinet SSL VPN profile `name` always trust `fingerprint` on `gateway` (a
/// `trusted-certs` key, `host:port`).
pub fn trust_certificate(
    profiles: &mut Profiles,
    name: &str,
    gateway: &str,
    fingerprint: CertFingerprint,
) -> Result<(), String> {
    match profiles.profiles.get_mut(name) {
        Some(Profile::FortinetSsl(p)) => {
            p.trusted_certs.insert(gateway.to_string(), fingerprint);
            Ok(())
        }
        Some(_) => Err(format!("'{name}' is not a Fortinet SSL VPN profile")),
        None => Err(format!("there is no profile '{name}'")),
    }
}

/// [`trust_certificate`] in the profiles file: read again first, so nothing else in it
/// changes.
pub fn save_trusted_certificate(
    name: &str,
    gateway: &str,
    fingerprint: CertFingerprint,
) -> Result<(), String> {
    let path = paths::profiles_file().ok_or("no configuration directory")?;
    save_trusted_certificate_in(&path, name, gateway, fingerprint)
}

fn save_trusted_certificate_in(
    path: &Path,
    name: &str,
    gateway: &str,
    fingerprint: CertFingerprint,
) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut profiles = Profiles::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    trust_certificate(&mut profiles, name, gateway, fingerprint)?;
    write_with_backup(path, &profiles.to_toml())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use polytunnel_core::profile::FortinetSslProfile;

    use super::*;

    fn temp_dir(what: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("polytunnel-{what}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn saving_keeps_the_previous_file() {
        let dir = temp_dir("save");
        let path = dir.join("profiles.toml");
        write_with_backup(&path, "first").unwrap();
        write_with_backup(&path, "second").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
        assert_eq!(
            fs::read_to_string(dir.join("profiles.toml.bak")).unwrap(),
            "first"
        );
        assert!(!dir.join("profiles.toml.tmp").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn always_trust_is_saved_in_the_profile() {
        let dir = temp_dir("trust");
        let path = dir.join("profiles.toml");
        let text = "[profile.office]\ntype = \"fortinet-ssl\"\nserver = \"fw.example.net\"\n\
                    username = \"me\"\n\n[profile.work]\ntype = \"global-protect\"\n\
                    portal = \"vpn.example.com\"\n";
        fs::write(&path, text).unwrap();
        let pin: CertFingerprint = "ab".repeat(32).parse().unwrap();
        save_trusted_certificate_in(&path, "office", "fw.example.net:443", pin).unwrap();

        let saved = Profiles::parse(&fs::read_to_string(&path).unwrap()).unwrap();
        let Some(Profile::FortinetSsl(office)) = saved.get("office") else {
            panic!("office");
        };
        assert_eq!(office.trusted_cert("fw.example.net:443"), Some(pin));
        assert_eq!(office.username.as_deref(), Some("me"));
        assert!(saved.get("work").is_some(), "other profiles are kept");
        assert!(dir.join("profiles.toml.bak").exists());

        // Only Fortinet SSL VPN profiles take it; the file is then left alone.
        let before = fs::read_to_string(&path).unwrap();
        assert!(save_trusted_certificate_in(&path, "work", "a.example.com:443", pin).is_err());
        assert!(save_trusted_certificate_in(&path, "gone", "a.example.com:443", pin).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), before);
        let _ = fs::remove_dir_all(&dir);

        let mut profiles = Profiles::default();
        profiles.profiles.insert(
            "lab".into(),
            Profile::FortinetSsl(FortinetSslProfile::default()),
        );
        trust_certificate(&mut profiles, "lab", "fw.example.net:10443", pin).unwrap();
        assert!(matches!(
            profiles.get("lab"),
            Some(Profile::FortinetSsl(p)) if p.trusted_certs.len() == 1
        ));
    }
}
