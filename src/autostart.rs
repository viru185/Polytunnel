//! Starting the tray agent when the user signs in.
//!
//! * Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Polytunnel`.
//! * Linux: `~/.config/autostart/polytunnel.desktop`.
//! * macOS: handled by the installer package (a login item); not available here yet.

/// The command that starts the tray agent.
fn command() -> Option<String> {
    std::env::current_exe()
        .ok()
        .map(|exe| format!("\"{}\" tray", exe.display()))
}

#[cfg(windows)]
mod imp {
    use crate::win::{Hive, reg_get_string, reg_set_string};

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const NAME: &str = "Polytunnel";

    pub fn enabled() -> bool {
        reg_get_string(Hive::CurrentUser, KEY, NAME).is_some()
    }

    pub fn set(on: bool) -> Result<(), String> {
        if on {
            let command = super::command().ok_or("cannot find this program's path")?;
            reg_set_string(KEY, NAME, &command)
        } else {
            crate::win::reg_delete_value(KEY, NAME);
            Ok(())
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod imp {
    use std::fs;
    use std::path::PathBuf;

    fn file() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("autostart").join("polytunnel.desktop"))
    }

    pub fn enabled() -> bool {
        file().is_some_and(|f| f.exists())
    }

    pub fn set(on: bool) -> Result<(), String> {
        let file = file().ok_or("cannot find ~/.config")?;
        if on {
            let command = super::command().ok_or("cannot find this program's path")?;
            if let Some(dir) = file.parent() {
                fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            }
            fs::write(
                &file,
                format!(
                    "[Desktop Entry]\nType=Application\nName=Polytunnel\nExec={command}\n\
                     X-GNOME-Autostart-enabled=true\nNoDisplay=true\n"
                ),
            )
            .map_err(|e| e.to_string())
        } else {
            let _ = fs::remove_file(file);
            Ok(())
        }
    }
}

#[cfg(not(any(windows, all(unix, not(target_os = "macos")))))]
mod imp {
    pub fn enabled() -> bool {
        false
    }

    pub fn set(_on: bool) -> Result<(), String> {
        let _ = super::command;
        Err("use the installer's login item on this platform".into())
    }
}

pub use imp::{enabled, set};
