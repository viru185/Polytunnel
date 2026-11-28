//! Where Polytunnel keeps its files.

use std::path::PathBuf;

const APP_DIR: &str = "Polytunnel";

/// `%APPDATA%\Polytunnel`, `~/.config/Polytunnel`, `~/Library/Application Support/Polytunnel`.
pub fn config_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join(APP_DIR))
}

/// `profiles.toml` in [`config_dir`].
pub fn profiles_file() -> Option<PathBuf> {
    config_dir().map(|d| d.join("profiles.toml"))
}

/// A per-user directory for sockets and locks.
pub fn runtime_dir() -> PathBuf {
    dirs::runtime_dir()
        .or_else(dirs::data_local_dir)
        .or_else(dirs::cache_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join(APP_DIR)
}

/// A per-user directory for logs and traces: `%LOCALAPPDATA%\Polytunnel`,
/// `~/.local/share/Polytunnel`, `~/Library/Application Support/Polytunnel`.
pub fn log_dir() -> PathBuf {
    dirs::data_local_dir()
        .or_else(dirs::cache_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join(APP_DIR)
}

/// The login name, reduced to characters that are safe in pipe and file names.
/// The program that opens the window and the tray without a console window: `polytunnelw`
/// next to this program (Windows), else this program itself.
pub fn gui_program() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    if cfg!(windows)
        && let Some(gui) = exe.parent().map(|d| d.join("polytunnelw.exe"))
        && gui.is_file()
    {
        return Some(gui);
    }
    Some(exe)
}

pub fn user_name() -> String {
    let raw = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();
    let safe: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(64)
        .collect();
    if safe.is_empty() { "user".into() } else { safe }
}
