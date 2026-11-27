//! Owns the (single) active connection and answers IPC requests.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use polytunnel_core::Secret;
use polytunnel_core::ipc::{Connect, PROTOCOL_VERSION, Request, Response, Status, validate_answer};
use polytunnel_net::journal::Journal;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::common::StatusCell;
use crate::{gp, ipsec, killswitch};
use crate::{info, paths, warn};

struct Running {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
    /// Where answers to the connection's prompts go (IPsec only).
    answers: Option<mpsc::Sender<ipsec::Answer>>,
}

pub struct Manager {
    runtime: Runtime,
    status: StatusCell,
    current: Mutex<Option<Running>>,
}

impl Manager {
    /// Starts the runtime and undoes network changes a previous run left behind.
    pub fn new() -> io::Result<Arc<Self>> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("polytunnel-worker")
            .build()?;
        match Journal::open(paths::journal_file()) {
            Ok(mut journal) if !journal.entries().is_empty() => {
                warn!(
                    "undoing {} network change(s) left by an earlier run",
                    journal.entries().len()
                );
                if let Err(e) = journal.rollback(polytunnel_net::system::native().as_mut()) {
                    warn!("could not undo every earlier change: {e}");
                }
            }
            Ok(_) => {}
            Err(e) => warn!("cannot read the network journal: {e}"),
        }
        killswitch::load();
        Ok(Arc::new(Manager {
            runtime,
            status: Arc::new(Mutex::new(Status::Idle {})),
            current: Mutex::new(None),
        }))
    }

    pub fn status(&self) -> Status {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn handle(&self, request: Request) -> Response {
        match request {
            Request::Hello { version } if version == PROTOCOL_VERSION => Response::Hello {
                version: PROTOCOL_VERSION,
                daemon_version: polytunnel_core::VERSION.to_string(),
            },
            Request::Hello { version } => Response::Error {
                message: format!(
                    "protocol version {version} is not supported (the service speaks {PROTOCOL_VERSION})"
                ),
            },
            Request::Status {} => Response::Status {
                status: self.status(),
            },
            Request::Connect { connect } => self.connect(connect),
            Request::Disconnect {} => {
                self.stop_current();
                Response::Accepted {}
            }
            Request::Answer { id, values } => self.answer(id, values),
            Request::KillSwitch { set } => {
                if let Some(settings) = set {
                    info!(
                        "kill switch set to {:?} (LAN allowed: {})",
                        settings.mode, settings.allow_lan
                    );
                    killswitch::set(settings);
                }
                let (settings, active, problem) = killswitch::status();
                Response::KillSwitch {
                    settings,
                    active,
                    problem,
                }
            }
        }
    }

    fn answer(&self, id: u32, values: Vec<Secret>) -> Response {
        if let Err(message) = validate_answer(&values) {
            return Response::Error { message };
        }
        let current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        match current.as_ref().and_then(|r| r.answers.as_ref()) {
            Some(tx) if tx.try_send((id, values)).is_ok() => Response::Accepted {},
            _ => Response::Error {
                message: "the connection is not waiting for an answer".into(),
            },
        }
    }

    fn connect(&self, connect: Connect) -> Response {
        if let Err(message) = connect.validate() {
            return Response::Error { message };
        }
        self.stop_current();
        let profile = connect.profile().to_string();
        *self.status.lock().unwrap_or_else(|e| e.into_inner()) = Status::Connecting {
            profile: profile.clone(),
        };
        let (stop, stop_rx) = watch::channel(false);
        let status = self.status.clone();
        let mut answers = None;
        let task = match connect {
            Connect::GlobalProtect(gp) => {
                info!("connect request for profile '{profile}' (GlobalProtect)");
                self.runtime.spawn(gp::run(*gp, status, stop_rx))
            }
            Connect::FortinetSsl(forti) => {
                info!("connect request for profile '{profile}' (Fortinet SSL VPN)");
                self.runtime
                    .spawn(crate::forti::run(forti, status, stop_rx))
            }
            Connect::FortinetIpsec(c) => {
                info!("connect request for profile '{profile}' (Fortinet IPsec)");
                let (tx, rx) = mpsc::channel(4);
                answers = Some(tx);
                self.runtime.spawn(ipsec::run(*c, status, stop_rx, rx))
            }
        };
        *self.current.lock().unwrap_or_else(|e| e.into_inner()) = Some(Running {
            stop,
            task,
            answers,
        });
        Response::Accepted {}
    }

    /// Stops the active connection and waits (bounded) for its cleanup.
    pub fn stop_current(&self) {
        let running = self
            .current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(Running { stop, task, .. }) = running {
            if let Status::Connected { profile, .. }
            | Status::Connecting { profile }
            | Status::NeedsInput { profile, .. } = self.status()
            {
                *self.status.lock().unwrap_or_else(|e| e.into_inner()) =
                    Status::Disconnecting { profile };
            }
            let _ = stop.send(true);
            let _ = self
                .runtime
                .block_on(async { tokio::time::timeout(Duration::from_secs(20), task).await });
        }
    }

    pub fn shutdown(&self) {
        self.stop_current();
        killswitch::shutdown();
    }
}
