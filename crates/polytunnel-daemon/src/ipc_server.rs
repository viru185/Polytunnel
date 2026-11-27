//! The local, access-controlled IPC endpoint.
//!
//! * Windows: `\\.\pipe\polytunnel` with an explicit DACL: SYSTEM and administrators get full
//!   access, interactive users may read and write. Nobody else may connect, and only the
//!   service can create pipe instances (so no other process can pose as it).
//! * Unix: a socket in a root-owned directory.

use std::io::{self, BufReader, BufWriter};
use std::sync::Arc;
use std::thread;

use interprocess::local_socket::{ListenerOptions, Stream, prelude::*};
use polytunnel_core::ipc::{self, Request, Response};

use crate::manager::Manager;
use crate::{info, warn};

/// Where to listen. [`Endpoint::service`] is the real one; tests use private endpoints.
pub struct Endpoint {
    /// Pipe name (Windows) or socket path (Unix).
    pub name: String,
    /// Windows: the pipe's security descriptor in SDDL.
    pub sddl: String,
}

impl Endpoint {
    pub fn service() -> Self {
        #[cfg(windows)]
        let name = ipc::PIPE_NAME.to_string();
        #[cfg(unix)]
        let name = ipc::SOCKET_PATH.to_string();
        Endpoint {
            name,
            // SYSTEM and administrators: full; interactive users: read/write (not create).
            sddl: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)".into(),
        }
    }
}

#[cfg(windows)]
fn listener_options(endpoint: &Endpoint) -> io::Result<ListenerOptions<'static>> {
    use interprocess::local_socket::GenericNamespaced;
    use interprocess::os::windows::local_socket::ListenerOptionsExt;
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;

    let sddl = widestring::U16CString::from_str(&endpoint.sddl)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(ListenerOptions::new()
        .name(endpoint.name.clone().to_ns_name::<GenericNamespaced>()?)
        .security_descriptor(SecurityDescriptor::deserialize(&sddl)?))
}

#[cfg(unix)]
fn listener_options(endpoint: &Endpoint) -> io::Result<ListenerOptions<'static>> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use interprocess::local_socket::GenericFilePath;

    let path = Path::new(&endpoint.name);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
    }
    let _ = fs::remove_file(path); // stale socket from a crash
    Ok(ListenerOptions::new().name(endpoint.name.clone().to_fs_name::<GenericFilePath>()?))
}

/// Starts accepting connections on the service endpoint, on a background thread.
pub fn spawn(manager: Arc<Manager>) -> io::Result<()> {
    spawn_at(&Endpoint::service(), manager)
}

pub fn spawn_at(endpoint: &Endpoint, manager: Arc<Manager>) -> io::Result<()> {
    let listener = listener_options(endpoint)?.create_sync()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Local users may ask for status and connect with their own credentials.
        std::fs::set_permissions(&endpoint.name, std::fs::Permissions::from_mode(0o666))?;
    }
    info!("listening for the app");
    thread::Builder::new()
        .name("ipc-accept".into())
        .spawn(move || {
            for conn in listener.incoming() {
                match conn {
                    Ok(conn) => {
                        let manager = manager.clone();
                        let _ = thread::Builder::new()
                            .name("ipc-client".into())
                            .spawn(move || serve_client(conn, &manager));
                    }
                    Err(e) => warn!("IPC accept failed: {e}"),
                }
            }
        })?;
    Ok(())
}

fn serve_client(conn: Stream, manager: &Manager) {
    let mut reader = BufReader::new(&conn);
    let mut writer = BufWriter::new(&conn);
    loop {
        let request: Request = match ipc::read_frame(&mut reader) {
            Ok(request) => request,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return,
            Err(e) => {
                let _ = ipc::write_frame(
                    &mut writer,
                    &Response::Error {
                        message: format!("bad request: {e}"),
                    },
                );
                return;
            }
        };
        let response = manager.handle(request);
        if ipc::write_frame(&mut writer, &response).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, BufWriter};

    use polytunnel_core::Secret;
    use polytunnel_core::ipc::{
        Connect, FortiConnect, PROTOCOL_VERSION, Request, Response, Status,
    };

    use super::*;

    fn exchange(endpoint: &Endpoint, request: &Request) -> Response {
        #[cfg(windows)]
        let name = {
            use interprocess::local_socket::GenericNamespaced;
            endpoint
                .name
                .clone()
                .to_ns_name::<GenericNamespaced>()
                .unwrap()
        };
        #[cfg(unix)]
        let name = {
            use interprocess::local_socket::GenericFilePath;
            endpoint
                .name
                .clone()
                .to_fs_name::<GenericFilePath>()
                .unwrap()
        };
        let stream = Stream::connect(name).expect("connect to the test endpoint");
        let mut writer = BufWriter::new(&stream);
        let mut reader = BufReader::new(&stream);
        ipc::write_frame(&mut writer, request).unwrap();
        ipc::read_frame(&mut reader).unwrap()
    }

    #[test]
    fn handshake_status_validation_and_disconnect_over_a_real_endpoint() {
        #[cfg(windows)]
        let name = format!("polytunnel-test-{}", std::process::id());
        #[cfg(unix)]
        let name = std::env::temp_dir()
            .join(format!(
                "polytunnel-test-{}/daemon.sock",
                std::process::id()
            ))
            .display()
            .to_string();
        // Test-only descriptor: whoever runs the tests may connect.
        let endpoint = Endpoint {
            name,
            sddl: "D:P(A;;GA;;;WD)".into(),
        };
        let manager = Manager::new().unwrap();
        spawn_at(&endpoint, manager).unwrap();

        assert!(matches!(
            exchange(
                &endpoint,
                &Request::Hello {
                    version: PROTOCOL_VERSION
                }
            ),
            Response::Hello {
                version: PROTOCOL_VERSION,
                ..
            }
        ));
        assert!(matches!(
            exchange(&endpoint, &Request::Hello { version: 999 }),
            Response::Error { .. }
        ));
        assert_eq!(
            exchange(&endpoint, &Request::Status {}),
            Response::Status {
                status: Status::Idle {}
            }
        );
        // An injected header in the cookie is refused before anything happens.
        let bad = Request::Connect {
            connect: Connect::FortinetSsl(FortiConnect {
                profile: "office".into(),
                server: "https://vpn.example.net:10443".into(),
                cookie: Secret::new("a\r\nX-Injected: 1"),
            }),
        };
        assert!(matches!(exchange(&endpoint, &bad), Response::Error { .. }));
        assert_eq!(
            exchange(&endpoint, &Request::Status {}),
            Response::Status {
                status: Status::Idle {}
            }
        );
        assert_eq!(
            exchange(&endpoint, &Request::Disconnect {}),
            Response::Accepted {}
        );
    }
}
