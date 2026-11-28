//! Starting the tray agent when the user signs in.
//!
//! * Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Polytunnel`.
//! * Linux: `~/.config/autostart/polytunnel.desktop`.
//! * macOS: handled by the installer package (a login item); not available here yet.

/// The command that starts the tray agent (without a console window on Windows).
fn command() -> Option<String> {
    crate::paths::gui_program().map(|exe| format!("\"{}\" tray", exe.display()))
}

#[cfg(windows)]
mod imp {
    use crate::win::{Hive, reg_get_binary, reg_get_string, reg_set_string};

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    /// Where Task Manager and Settings record that the user turned a startup entry off.
    const APPROVED: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    const NAME: &str = "Polytunnel";

    /// Turned off in Task Manager or Settings: the first byte of the entry is odd.
    fn disabled_by_user() -> bool {
        reg_get_binary(Hive::CurrentUser, APPROVED, NAME)
            .and_then(|flags| flags.first().copied())
            .is_some_and(|first| first & 1 == 1)
    }

    /// On only when the entry starts this installation's tray and the user has not turned it
    /// off elsewhere.
    pub fn enabled() -> bool {
        let current = reg_get_string(Hive::CurrentUser, KEY, NAME);
        current.is_some() && current == super::command() && !disabled_by_user()
    }

    pub fn set(on: bool) -> Result<(), String> {
        if on {
            let command = super::command().ok_or("cannot find this program's path")?;
            reg_set_string(KEY, NAME, &command)?;
            // Clears an "off" from Task Manager, which would otherwise win.
            crate::win::reg_delete_value(APPROVED, NAME);
            Ok(())
        } else {
            crate::win::reg_delete_value(KEY, NAME);
            Ok(())
        }
    }

    /// An entry left by another copy or an older version (for example without the console-free
    /// launcher) is pointed at this installation; one the user turned off stays off.
    pub fn refresh() {
        if let (Some(current), Some(command)) = (
            reg_get_string(Hive::CurrentUser, KEY, NAME),
            super::command(),
        ) && current != command
            && !disabled_by_user()
        {
            let _ = reg_set_string(KEY, NAME, &command);
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

    pub fn refresh() {}
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

    pub fn refresh() {}
}

/// Whether this platform can start the tray at sign-in from here.
pub const SUPPORTED: bool = cfg!(any(windows, all(unix, not(target_os = "macos"))));

pub use imp::{enabled, refresh, set};
