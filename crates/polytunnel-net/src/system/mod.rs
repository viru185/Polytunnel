//! Applying [`Change`]s to the operating system.
//!
//! Commands are always run with explicit argument lists (never through a shell), and every
//! value in them comes from parsed addresses, prefixes and validated domain names.

use std::io;
use std::net::IpAddr;

use crate::plan::Change;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

pub mod args;

/// The operating system's network configuration.
pub trait System {
    /// Makes `change`. `Ok(false)`: it was already there (so it is not ours to undo).
    fn apply(&mut self, change: &Change) -> io::Result<bool>;

    /// Undoes `change`. Undoing something that is already gone is not an error.
    fn revert(&mut self, change: &Change) -> io::Result<()>;

    /// How `dest` is reached right now: `(gateway, interface index)`; `None` = on-link.
    fn route_to(&self, dest: IpAddr) -> io::Result<(Option<IpAddr>, u32)>;
}

/// The real system for this platform.
pub fn native() -> Box<dyn System> {
    #[cfg(windows)]
    {
        Box::new(windows::Windows)
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::Linux)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOs)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Box::new(Unsupported)
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
struct Unsupported;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
impl System for Unsupported {
    fn apply(&mut self, _change: &Change) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported platform",
        ))
    }

    fn revert(&mut self, _change: &Change) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported platform",
        ))
    }

    fn route_to(&self, _dest: IpAddr) -> io::Result<(Option<IpAddr>, u32)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported platform",
        ))
    }
}

/// Runs a command and returns its output; a non-zero exit becomes an error with stderr.
#[cfg(unix)]
pub(crate) fn run(program: &str, args: &[String]) -> io::Result<std::process::Output> {
    let output = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(io::Error::other(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// The interface name for an index.
#[cfg(unix)]
pub(crate) fn if_name(index: u32) -> io::Result<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `buf` has IF_NAMESIZE bytes, as if_indextoname requires.
    let ptr = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if ptr.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success the buffer holds a NUL-terminated name.
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    Ok(name.to_string_lossy().into_owned())
}

/// The interface index for a name.
#[cfg(unix)]
pub(crate) fn if_index(name: &str) -> io::Result<u32> {
    let name = std::ffi::CString::new(name).map_err(io::Error::other)?;
    // SAFETY: `name` is NUL-terminated.
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        index => Ok(index),
    }
}
