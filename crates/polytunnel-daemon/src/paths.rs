//! Where the daemon keeps its state: an administrators-only directory.

use std::fs;
use std::io;
use std::path::PathBuf;

/// `%ProgramData%\Polytunnel`, `/var/lib/polytunnel`, `/Library/Application Support/Polytunnel`.
pub fn state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("Polytunnel")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/Polytunnel")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/var/lib/polytunnel")
    }
}

pub fn journal_file() -> PathBuf {
    state_dir().join("network-journal.json")
}

pub fn log_file() -> PathBuf {
    state_dir().join("daemon.log")
}

/// `wintun.dll` next to the daemon (Windows); loaded by full path only.
pub fn wintun_dll() -> Option<PathBuf> {
    let dll = std::env::current_exe().ok()?.parent()?.join("wintun.dll");
    dll.is_file().then_some(dll)
}

/// Creates the state directory and restricts it to SYSTEM and administrators (Windows) or
/// root (Unix). The default `ProgramData` permissions would let any user create files there.
pub fn ensure_state_dir() -> io::Result<PathBuf> {
    let dir = state_dir();
    fs::create_dir_all(&dir)?;
    #[cfg(windows)]
    restrict_windows(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

#[cfg(windows)]
fn restrict_windows(dir: &std::path::Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SetFileSecurityW;
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    // Full control for SYSTEM and Administrators, inherited by everything inside.
    let sddl: Vec<u16> = std::ffi::OsStr::new("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let path: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut sd = null_mut();
    // SAFETY: NUL-terminated strings; the descriptor is freed with LocalFree.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let ok = SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        );
        LocalFree(sd);
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
