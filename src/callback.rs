//! Login callbacks between processes.
//!
//! The browser starts `polytunnel --callback <globalprotectcallback:...>`; that process hands
//! the link to the `polytunnel auth` process waiting for it over a per-user local socket (a
//! named pipe on Windows, a socket file in the user's runtime directory elsewhere) and exits.
//! The same command can be run by hand to deliver a link copied from the browser.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use interprocess::local_socket::{
    GenericFilePath, GenericNamespaced, ListenerOptions, Name, Stream, prelude::*,
};
use polytunnel_gp::sso::{CALLBACK_SCHEME, MAX_CALLBACK_LEN};

use crate::paths;

fn socket_file() -> PathBuf {
    paths::runtime_dir().join("callback.sock")
}

fn socket_name() -> io::Result<Name<'static>> {
    if cfg!(windows) {
        format!("polytunnel-callback-{}", paths::user_name()).to_ns_name::<GenericNamespaced>()
    } else {
        // Not the abstract namespace: any user could connect to that.
        socket_file().to_fs_name::<GenericFilePath>()
    }
}

/// Windows: the pipe admits only this user (elevated or not), SYSTEM and administrators.
/// Without an explicit DACL, a pipe created from an elevated terminal is owned by the
/// Administrators group, and the browser-started (non-elevated) `--callback` process could
/// not write to it; other users could read it.
#[cfg(windows)]
fn listener_options() -> io::Result<ListenerOptions<'static>> {
    use interprocess::os::windows::local_socket::ListenerOptionsExt;
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;

    let sid = crate::win::current_user_sid()?;
    let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})");
    let sddl = widestring::U16CString::from_str(&sddl)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(ListenerOptions::new()
        .name(socket_name()?)
        .security_descriptor(SecurityDescriptor::deserialize(&sddl)?))
}

/// Unix: the socket lives in a directory only this user can enter.
#[cfg(not(windows))]
fn listener_options() -> io::Result<ListenerOptions<'static>> {
    Ok(ListenerOptions::new().name(socket_name()?))
}

/// Receives callback links while it lives.
pub struct Listener {
    rx: Receiver<String>,
}

impl Listener {
    pub fn start() -> io::Result<Self> {
        if !cfg!(windows) {
            let dir = paths::runtime_dir();
            fs::create_dir_all(&dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            }
            // A leftover socket from a crashed run would make binding fail.
            let _ = fs::remove_file(socket_file());
        }
        let listener = listener_options()?.create_sync()?;
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("callback-listener".into())
            .spawn(move || {
                for conn in listener.incoming().filter_map(Result::ok) {
                    let mut reader = BufReader::new(conn);
                    let mut line = String::new();
                    let read = reader
                        .by_ref()
                        .take(MAX_CALLBACK_LEN as u64 + 2)
                        .read_line(&mut line);
                    if read.is_ok() {
                        let _ = reader.get_mut().write_all(b"ok\n");
                        if tx.send(line.trim().to_string()).is_err() {
                            break;
                        }
                    }
                }
            })?;
        Ok(Listener { rx })
    }

    pub fn receiver(&self) -> &Receiver<String> {
        &self.rx
    }
}

/// Hands `link` to the waiting login.
pub fn send(link: &str) -> io::Result<()> {
    let mut conn = BufReader::new(Stream::connect(socket_name()?)?);
    conn.get_mut().write_all(format!("{link}\n").as_bytes())?;
    let mut reply = String::new();
    conn.read_line(&mut reply)?;
    Ok(())
}

pub fn is_callback_link(text: &str) -> bool {
    text.len() <= MAX_CALLBACK_LEN
        && text
            .split_once(':')
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case(CALLBACK_SCHEME))
}

/// `polytunnel --callback <link>`.
pub fn run(link: &str) -> i32 {
    #[cfg(windows)]
    crate::win::hide_own_console();
    if !is_callback_link(link) {
        report("This is not a GlobalProtect login link (globalprotectcallback:...).");
        return 2;
    }
    match send(link) {
        Ok(()) => {
            println!("Login handed to Polytunnel.");
            0
        }
        Err(_) => {
            report(
                "No Polytunnel login is waiting for this link.\n\
                 Start the login again with `polytunnel auth`.",
            );
            1
        }
    }
}

fn report(message: &str) {
    eprintln!("polytunnel: {message}");
    #[cfg(windows)]
    crate::win::message_box("Polytunnel", message, true);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sent_link_reaches_the_listener() {
        let listener = Listener::start().expect("start the callback listener");
        send("globalprotectcallback:FAKE-test-payload").expect("send a link");
        let got = listener
            .receiver()
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("receive the link");
        assert_eq!(got, "globalprotectcallback:FAKE-test-payload");
    }

    #[test]
    fn recognizes_links() {
        assert!(is_callback_link("globalprotectcallback:abc"));
        assert!(is_callback_link("GlobalProtectCallback://abc"));
        assert!(!is_callback_link("https://example.com"));
        assert!(!is_callback_link("nothing"));
    }
}
