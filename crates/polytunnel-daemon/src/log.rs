//! A tiny append-only log (`daemon.log` in the state directory, rotated at 1 MiB).
//! Secrets never reach it: they are [`polytunnel_core::Secret`]s, which print as `***`.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SIZE: u64 = 1024 * 1024;

struct Sink {
    path: Option<PathBuf>,
    file: Option<File>,
    echo: bool,
}

static SINK: Mutex<Sink> = Mutex::new(Sink {
    path: None,
    file: None,
    echo: true,
});

/// Logs to `path` (if given) and, with `echo`, to stderr.
pub fn init(path: Option<&Path>, echo: bool) {
    let mut sink = SINK.lock().unwrap_or_else(|e| e.into_inner());
    sink.echo = echo;
    sink.path = path.map(Path::to_path_buf);
    sink.file = path.and_then(|p| OpenOptions::new().create(true).append(true).open(p).ok());
}

pub fn write(level: &str, message: &str) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let line = format!("{secs} {level} {message}\n");
    let mut sink = SINK.lock().unwrap_or_else(|e| e.into_inner());
    if sink.echo {
        eprint!("{line}");
    }
    let too_big = sink
        .file
        .as_ref()
        .and_then(|f| f.metadata().ok())
        .is_some_and(|m| m.len() > MAX_SIZE);
    if too_big && let Some(path) = sink.path.clone() {
        sink.file = None;
        let _ = fs::rename(&path, path.with_extension("log.1"));
        sink.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok();
    }
    if let Some(file) = sink.file.as_mut() {
        let _ = file.write_all(line.as_bytes());
    }
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::log::write("INFO", &format!($($arg)*)) };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { $crate::log::write("WARN", &format!($($arg)*)) };
}
