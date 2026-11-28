//! One window and one tray agent per user, and a tiny line-based protocol between them
//! (adapted from AutoTyper).
//!
//! * A lock file (`gui.lock` / `agent.lock`) decides who is the running instance. The OS
//!   releases the lock when the process exits, even after a crash.
//! * The running instance listens on a per-user local socket (a named pipe on Windows,
//!   restricted to this user). A second launch sends it one line and exits.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::thread;

use interprocess::local_socket::{
    GenericFilePath, GenericNamespaced, ListenerOptions, Name, Stream, prelude::*,
};

use crate::paths;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Gui,
    Agent,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Role::Gui => "gui",
            Role::Agent => "agent",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Bring the window to the front.
    Show,
    /// Exit.
    Quit,
    /// Bring the window to the front and connect with this profile.
    Connect(String),
}

/// A profile name as the window accepts it: letters, digits, `-` and `_`, at most 64.
pub fn valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl Message {
    fn line(&self) -> String {
        match self {
            Message::Show => "show".into(),
            Message::Quit => "quit".into(),
            Message::Connect(name) => format!("connect {name}"),
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "show" => Some(Message::Show),
            "quit" => Some(Message::Quit),
            other => other
                .strip_prefix("connect ")
                .filter(|name| valid_profile_name(name))
                .map(|name| Message::Connect(name.to_string())),
        }
    }
}

/// Held by the running instance; dropping it releases the role.
pub struct Instance {
    _lock: File,
}

/// Tries to become the running instance for `role`. `Ok(None)`: another one is running.
pub fn claim(role: Role) -> io::Result<Option<Instance>> {
    let dir = paths::runtime_dir();
    fs::create_dir_all(&dir)?;
    // Opened, not created afresh: truncating a file another process holds locked fails.
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(format!("{}.lock", role.name())))?;
    match lock.try_lock() {
        Ok(()) => Ok(Some(Instance { _lock: lock })),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(e)) => Err(e),
    }
}

impl Instance {
    /// Starts a background thread that passes every received message to `on_message`.
    pub fn listen(
        &self,
        role: Role,
        on_message: impl Fn(Message) + Send + 'static,
    ) -> io::Result<()> {
        if let Some(path) = socket_file(role) {
            // We hold the lock, so an existing socket file is a leftover from a crash.
            let _ = fs::remove_file(path);
        }
        let listener = listener_options(role)?.create_sync()?;
        thread::Builder::new()
            .name(format!("ipc-{}", role.name()))
            .spawn(move || {
                for conn in listener.incoming().filter_map(Result::ok) {
                    let mut conn = BufReader::new(conn);
                    let mut line = String::new();
                    if conn.read_line(&mut line).is_ok() {
                        let _ = conn.get_mut().write_all(b"ok\n");
                        if let Some(message) = Message::parse(&line) {
                            on_message(message);
                        }
                    }
                }
            })?;
        Ok(())
    }
}

/// Sends a message to the running instance. Fails if none is running.
pub fn send(role: Role, message: Message) -> io::Result<()> {
    #[cfg(windows)]
    // Let the running instance bring its window to the front: we were just started by the
    // user, so we may hand that right on.
    // SAFETY: no preconditions.
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow(
            windows_sys::Win32::UI::WindowsAndMessaging::ASFW_ANY,
        );
    }
    let mut conn = BufReader::new(Stream::connect(socket_name(role)?)?);
    conn.get_mut()
        .write_all(format!("{}\n", message.line()).as_bytes())?;
    let mut reply = String::new();
    conn.read_line(&mut reply)?;
    Ok(())
}

pub fn is_running(role: Role) -> bool {
    matches!(claim(role), Ok(None))
}

fn socket_name(role: Role) -> io::Result<Name<'static>> {
    if cfg!(windows) {
        format!("polytunnel-{}-{}", paths::user_name(), role.name())
            .to_ns_name::<GenericNamespaced>()
    } else {
        socket_file(role)
            .expect("unix has a socket file")
            .to_fs_name::<GenericFilePath>()
    }
}

fn socket_file(role: Role) -> Option<PathBuf> {
    if cfg!(windows) {
        None
    } else {
        Some(paths::runtime_dir().join(format!("{}.sock", role.name())))
    }
}

#[cfg(windows)]
fn listener_options(role: Role) -> io::Result<ListenerOptions<'static>> {
    use interprocess::os::windows::local_socket::ListenerOptionsExt;
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;

    let sid = crate::win::current_user_sid()?;
    let sddl = widestring::U16CString::from_str(format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})"))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(ListenerOptions::new()
        .name(socket_name(role)?)
        .security_descriptor(SecurityDescriptor::deserialize(&sddl)?))
}

#[cfg(not(windows))]
fn listener_options(role: Role) -> io::Result<ListenerOptions<'static>> {
    Ok(ListenerOptions::new().name(socket_name(role)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip() {
        for m in [
            Message::Show,
            Message::Quit,
            Message::Connect("office-2".into()),
        ] {
            assert_eq!(Message::parse(&format!("{}\n", m.line())), Some(m));
        }
        assert_eq!(Message::parse("rm -rf"), None);
        // Only names a profile could have.
        assert_eq!(Message::parse("connect ../x"), None);
        assert_eq!(Message::parse("connect "), None);
        assert_eq!(Message::parse("connect a b"), None);
    }
}
