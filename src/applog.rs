//! A small log for the window and the tray (they have no console): `app.log` in the user's
//! local data folder, kept under 256 KiB by starting over when it grows past that.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SIZE: u64 = 256 * 1024;

/// Appends `message` (one line) to the log; problems writing it are ignored.
pub fn write(level: &str, message: &str) {
    let dir = crate::paths::log_dir();
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("app.log");
    if fs::metadata(&path).is_ok_and(|m| m.len() > MAX_SIZE) {
        let _ = fs::remove_file(&path);
    }
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let line: String = message.chars().filter(|c| !c.is_control()).collect();
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{secs} {level} [{}] {line}", std::process::id());
    }
}
