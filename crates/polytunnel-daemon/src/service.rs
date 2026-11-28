//! Running as a system service, and installing/removing it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::manager::Manager;
use crate::{info, ipc_server, log, paths};

pub const SERVICE_NAME: &str = "Polytunnel";
pub const DISPLAY_NAME: &str = "Polytunnel VPN service";
#[cfg(windows)]
const DESCRIPTION: &str =
    "Creates Polytunnel's VPN tunnels and network settings for the Polytunnel app.";

/// Runs the daemon until `stop` receives a message. Logs to the state directory.
pub fn serve(stop: mpsc::Receiver<()>, echo: bool) -> Result<(), String> {
    let log_file = paths::ensure_state_dir()
        .map(|_| paths::log_file())
        .map_err(|e| format!("cannot prepare {}: {e}", paths::state_dir().display()))?;
    log::init(Some(&log_file), echo);
    info!("Polytunnel daemon {} starting", polytunnel_core::VERSION);
    let manager = Manager::new().map_err(|e| e.to_string())?;
    ipc_server::spawn(manager.clone()).map_err(|e| format!("cannot open the IPC endpoint: {e}"))?;
    let _ = stop.recv();
    info!("stopping");
    manager.shutdown();
    Ok(())
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Foreground mode (terminal, systemd, launchd): stops on Ctrl+C / SIGTERM.
pub fn run_foreground() -> Result<(), String> {
    catch_interrupt();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        while !INTERRUPTED.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(200));
        }
        let _ = tx.send(());
    });
    serve(rx, true)
}

#[cfg(unix)]
fn catch_interrupt() {
    extern "C" fn on_signal(_: libc::c_int) {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }
    let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

#[cfg(windows)]
fn catch_interrupt() {
    use windows_sys::Win32::Foundation::TRUE;
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    extern "system" fn on_ctrl(_kind: u32) -> windows_sys::core::BOOL {
        INTERRUPTED.store(true, Ordering::SeqCst);
        TRUE
    }
    // SAFETY: a plain function valid for the whole program.
    unsafe { SetConsoleCtrlHandler(Some(on_ctrl), TRUE) };
}

#[cfg(windows)]
pub mod windows {
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;

    use windows_service::service::{
        Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl,
        ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    use super::{DESCRIPTION, DISPLAY_NAME, SERVICE_NAME, serve};

    define_windows_service!(ffi_service_main, service_main);

    /// If the service stops unexpectedly (a crash, or an exit with an error), Windows starts it
    /// again: after 2 s, 10 s, then every minute; the count resets after a day. On start it
    /// undoes whatever network changes the stopped run left behind.
    fn restart_on_failure(service: &Service) -> windows_service::Result<()> {
        let restart = |secs| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(secs),
        };
        service.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(2), restart(10), restart(60)]),
        })?;
        service.set_failure_actions_on_non_crash_failures(true)
    }

    /// The installer creates the service without recovery actions: the service sets them on
    /// itself (as LocalSystem it may). Windows wants the start right as well as the
    /// change-configuration right for a "restart" action.
    fn ensure_restart_on_failure() {
        let result = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .and_then(|manager| {
                manager.open_service(
                    SERVICE_NAME,
                    ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
                )
            })
            .and_then(|service| restart_on_failure(&service));
        if let Err(e) = result {
            crate::warn!("cannot set the service's restart-on-failure actions: {e}");
        }
    }

    /// Called by the service control manager (`polytunnel-daemon run --service`).
    pub fn run_service() -> Result<(), String> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| e.to_string())
    }

    fn status(state: ServiceState, accept: ServiceControlAccept, code: u32) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(20),
            process_id: None,
        }
    }

    fn service_main(_arguments: Vec<OsString>) {
        let (tx, rx) = mpsc::channel();
        let handler = move |event| match event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let Ok(handle) = service_control_handler::register(SERVICE_NAME, handler) else {
            return;
        };
        let accept = ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN;
        let _ = handle.set_service_status(status(ServiceState::Running, accept, 0));
        // The log first, so a problem setting the recovery actions is recorded.
        if crate::paths::ensure_state_dir().is_ok() {
            crate::log::init(Some(&crate::paths::log_file()), false);
        }
        ensure_restart_on_failure();
        let code = match serve(rx, false) {
            Ok(()) => 0,
            Err(e) => {
                crate::warn!("service failed: {e}");
                1
            }
        };
        let _ = handle.set_service_status(status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            code,
        ));
    }

    pub fn install() -> Result<String, String> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(|e| format!("cannot open the service manager (run as administrator): {e}"))?;
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let info = ServiceInfo {
            name: SERVICE_NAME.into(),
            display_name: DISPLAY_NAME.into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments: vec!["run".into(), "--service".into()],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let service = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
            .map_err(|e| format!("cannot create the service: {e}"))?;
        let _ = service.set_description(DESCRIPTION);
        let _ = restart_on_failure(&service);
        service
            .start::<&str>(&[])
            .map_err(|e| format!("created, but cannot start the service: {e}"))?;
        Ok(format!(
            "Installed and started the \"{DISPLAY_NAME}\" service."
        ))
    }

    pub fn uninstall() -> Result<String, String> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| {
            format!("cannot open the service manager (run as administrator): {e}")
        })?;
        let service = manager
            .open_service(
                SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .map_err(|e| format!("cannot open the service: {e}"))?;
        let _ = service.stop();
        for _ in 0..40 {
            match service.query_status() {
                Ok(s) if s.current_state == ServiceState::Stopped => break,
                _ => std::thread::sleep(Duration::from_millis(250)),
            }
        }
        service
            .delete()
            .map_err(|e| format!("cannot delete the service: {e}"))?;
        Ok(format!("Removed the \"{DISPLAY_NAME}\" service."))
    }
}

#[cfg(target_os = "linux")]
pub mod linux {
    use std::fs;
    use std::process::Command;

    use super::DISPLAY_NAME;

    const UNIT: &str = "/etc/systemd/system/polytunnel-daemon.service";

    pub fn unit(exe: &str) -> String {
        format!(
            "[Unit]\nDescription={DISPLAY_NAME}\nWants=network-online.target\n\
             After=network-online.target\n\n[Service]\nExecStart={exe} run\nRestart=on-failure\n\n\
             [Install]\nWantedBy=multi-user.target\n"
        )
    }

    fn systemctl(args: &[&str]) -> Result<(), String> {
        let ok = Command::new("systemctl")
            .args(args)
            .status()
            .map_err(|e| format!("cannot run systemctl: {e}"))?
            .success();
        if ok {
            Ok(())
        } else {
            Err(format!("systemctl {} failed", args.join(" ")))
        }
    }

    pub fn install() -> Result<String, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        fs::write(UNIT, unit(&exe.display().to_string()))
            .map_err(|e| format!("cannot write {UNIT} (run as root): {e}"))?;
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "--now", "polytunnel-daemon.service"])?;
        Ok("Installed and started polytunnel-daemon.service.".into())
    }

    pub fn uninstall() -> Result<String, String> {
        let _ = systemctl(&["disable", "--now", "polytunnel-daemon.service"]);
        let _ = fs::remove_file(UNIT);
        systemctl(&["daemon-reload"])?;
        Ok("Removed polytunnel-daemon.service.".into())
    }
}

pub fn install() -> Result<String, String> {
    #[cfg(windows)]
    return windows::install();
    #[cfg(target_os = "linux")]
    return linux::install();
    #[cfg(not(any(windows, target_os = "linux")))]
    Err("use the Polytunnel installer package on this platform".into())
}

pub fn uninstall() -> Result<String, String> {
    #[cfg(windows)]
    return windows::uninstall();
    #[cfg(target_os = "linux")]
    return linux::uninstall();
    #[cfg(not(any(windows, target_os = "linux")))]
    Err("use the Polytunnel installer package on this platform".into())
}
