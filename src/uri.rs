//! Registers Polytunnel as the handler for `globalprotectcallback:` links, for the current
//! user only, so the browser hands GlobalProtect logins to Polytunnel.
//!
//! * Windows: `HKEY_CURRENT_USER\Software\Classes\globalprotectcallback` (takes precedence
//!   over the official app's machine-wide registration for this user).
//! * Linux: a hidden `.desktop` file plus `xdg-mime default`.
//! * macOS: needs an app bundle (comes with the installer); use `--paste` until then.

use crate::cli::UriAction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Links go to this Polytunnel executable.
    Polytunnel(String),
    /// Links go to another program (e.g. the official GlobalProtect app).
    Other(String),
    NotRegistered,
    Unsupported,
}

pub fn run(action: UriAction) -> i32 {
    let result = match action {
        UriAction::Register => register().map(|()| {
            "Polytunnel now handles globalprotectcallback: links for your account.".to_string()
        }),
        UriAction::Unregister => unregister().map(|()| {
            "Removed Polytunnel as the handler for globalprotectcallback: links.".to_string()
        }),
        UriAction::Status => Ok(match status() {
            Status::Polytunnel(cmd) => format!("Handled by Polytunnel: {cmd}"),
            Status::Other(cmd) => format!("Handled by another program: {cmd}"),
            Status::NotRegistered => "No program handles globalprotectcallback: links.".into(),
            Status::Unsupported => {
                "Link registration is not available on this platform yet; use --paste.".into()
            }
        }),
    };
    match result {
        Ok(msg) => {
            println!("{msg}");
            0
        }
        Err(e) => {
            eprintln!("polytunnel: {e}");
            1
        }
    }
}

/// Registers if needed. Returns a message to show the user, if anything changed or failed.
pub fn ensure_registered() -> Option<String> {
    match status() {
        Status::Polytunnel(_) | Status::Unsupported => None,
        Status::Other(_) | Status::NotRegistered => Some(match register() {
            Ok(()) => "Polytunnel now handles globalprotectcallback: links for your account \
                       (the official GlobalProtect app will not receive them; undo with \
                       `polytunnel uri unregister`)."
                .to_string(),
            Err(e) => format!("Could not register the login link handler: {e}"),
        }),
    }
}

#[cfg(any(windows, all(unix, not(target_os = "macos"))))]
fn exe() -> Result<String, String> {
    std::env::current_exe()
        .map(|p| p.display().to_string())
        .map_err(|e| format!("cannot find this program's path: {e}"))
}

#[cfg(windows)]
mod imp {
    use super::{Status, exe};
    use crate::win::{Hive, reg_delete_tree, reg_get_string, reg_set_string};

    const KEY: &str = r"Software\Classes\globalprotectcallback";
    const COMMAND: &str = r"Software\Classes\globalprotectcallback\shell\open\command";

    pub fn register() -> Result<(), String> {
        let command = format!("\"{}\" --callback \"%1\"", exe()?);
        reg_set_string(KEY, "", "URL:GlobalProtect login callback (Polytunnel)")?;
        reg_set_string(KEY, "URL Protocol", "")?;
        reg_set_string(COMMAND, "", &command)
    }

    pub fn unregister() -> Result<(), String> {
        reg_delete_tree(KEY);
        Ok(())
    }

    pub fn status() -> Status {
        let mine = exe().unwrap_or_default().to_ascii_lowercase();
        if let Some(cmd) = reg_get_string(Hive::CurrentUser, COMMAND, "") {
            return if !mine.is_empty() && cmd.to_ascii_lowercase().contains(&mine) {
                Status::Polytunnel(cmd)
            } else {
                Status::Other(cmd)
            };
        }
        match reg_get_string(Hive::LocalMachine, COMMAND, "") {
            Some(cmd) => Status::Other(cmd),
            None => Status::NotRegistered,
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod imp {
    use std::fs;
    use std::process::Command;

    use super::{Status, exe};

    const DESKTOP: &str = "polytunnel-callback.desktop";
    const MIME: &str = "x-scheme-handler/globalprotectcallback";

    fn desktop_file() -> Result<std::path::PathBuf, String> {
        dirs::data_dir()
            .map(|d| d.join("applications").join(DESKTOP))
            .ok_or_else(|| "cannot find ~/.local/share".to_string())
    }

    pub fn register() -> Result<(), String> {
        let path = desktop_file()?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let entry = format!(
            "[Desktop Entry]\nType=Application\nName=Polytunnel login callback\n\
             Exec=\"{}\" --callback %u\nNoDisplay=true\nTerminal=false\nMimeType={MIME};\n",
            exe()?
        );
        fs::write(&path, entry).map_err(|e| e.to_string())?;
        let ok = Command::new("xdg-mime")
            .args(["default", DESKTOP, MIME])
            .status()
            .map_err(|e| format!("cannot run xdg-mime: {e}"))?
            .success();
        if ok {
            Ok(())
        } else {
            Err("xdg-mime failed".into())
        }
    }

    pub fn unregister() -> Result<(), String> {
        let _ = fs::remove_file(desktop_file()?);
        Ok(())
    }

    pub fn status() -> Status {
        let current = Command::new("xdg-mime")
            .args(["query", "default", MIME])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        match current.as_str() {
            "" => Status::NotRegistered,
            DESKTOP => Status::Polytunnel(DESKTOP.to_string()),
            other => Status::Other(other.to_string()),
        }
    }
}

#[cfg(not(any(windows, all(unix, not(target_os = "macos")))))]
mod imp {
    use super::Status;

    pub fn register() -> Result<(), String> {
        Err("link registration needs the Polytunnel app bundle; use --paste for now".into())
    }

    pub fn unregister() -> Result<(), String> {
        Ok(())
    }

    pub fn status() -> Status {
        Status::Unsupported
    }
}

pub use imp::{register, status, unregister};
