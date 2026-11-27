//! Small Win32 helpers: console, message boxes, registry, shell (adapted from AutoTyper).

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList, GetConsoleWindow};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, REG_SZ, RRF_RT_REG_SZ, RegDeleteKeyW,
    RegDeleteTreeW, RegGetValueW, RegSetKeyValueW,
};
use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MB_SETFOREGROUND, MessageBoxW, SW_HIDE, SW_SHOWNORMAL,
    ShowWindow,
};

/// NUL-terminated UTF-16 for Win32 `W` functions.
pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

pub fn message_box(title: &str, text: &str, error: bool) {
    let icon = if error {
        MB_ICONERROR
    } else {
        MB_ICONINFORMATION
    };
    // SAFETY: both strings are NUL-terminated and outlive the call.
    unsafe {
        MessageBoxW(
            null_mut(),
            wide(text).as_ptr(),
            wide(title).as_ptr(),
            MB_OK | icon | MB_SETFOREGROUND,
        );
    }
}

/// Hides and releases a console window that was created just for this process (for example
/// when the browser starts us to deliver a login callback). A terminal we were started from
/// is left alone.
pub fn hide_own_console() {
    // SAFETY: plain Win32 calls; the list buffer is large enough for the count we pass.
    unsafe {
        let window = GetConsoleWindow();
        if window.is_null() {
            return;
        }
        let mut list = [0u32; 2];
        if GetConsoleProcessList(list.as_mut_ptr(), list.len() as u32) == 1 {
            ShowWindow(window, SW_HIDE);
            FreeConsole();
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Hive {
    CurrentUser,
    LocalMachine,
}

impl Hive {
    fn handle(self) -> HKEY {
        match self {
            Hive::CurrentUser => HKEY_CURRENT_USER,
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
        }
    }
}

fn check(code: u32, what: &str) -> Result<(), String> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!("{what} failed (error {code})"))
    }
}

/// Writes a string value under `HKEY_CURRENT_USER\key` (`name` "" = the default value).
pub fn reg_set_string(key: &str, name: &str, value: &str) -> Result<(), String> {
    let data = wide(value);
    let name = (!name.is_empty()).then(|| wide(name));
    // SAFETY: all strings are NUL-terminated and outlive the call; `data` is `cb` bytes long.
    let code = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            wide(key).as_ptr(),
            name.as_ref().map_or(null(), |n| n.as_ptr()),
            REG_SZ,
            data.as_ptr().cast(),
            (data.len() * 2) as u32,
        )
    };
    check(code, "writing to the registry")
}

/// Reads a string value (`name` "" = the default value).
pub fn reg_get_string(hive: Hive, key: &str, name: &str) -> Option<String> {
    let key = wide(key);
    let name = (!name.is_empty()).then(|| wide(name));
    let mut buf = vec![0u16; 2048];
    let mut bytes = (buf.len() * 2) as u32;
    // SAFETY: `buf` holds `bytes` bytes; strings are NUL-terminated.
    let code = unsafe {
        RegGetValueW(
            hive.handle(),
            key.as_ptr(),
            name.as_ref().map_or(null(), |n| n.as_ptr()),
            RRF_RT_REG_SZ,
            null_mut(),
            buf.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if code != ERROR_SUCCESS {
        return None;
    }
    let units = (bytes as usize / 2).saturating_sub(1);
    Some(String::from_utf16_lossy(&buf[..units.min(buf.len())]))
}

/// Deletes `HKEY_CURRENT_USER\key` and everything below it; a missing key is not an error.
pub fn reg_delete_tree(key: &str) {
    let key = wide(key);
    // SAFETY: NUL-terminated strings.
    unsafe {
        RegDeleteTreeW(HKEY_CURRENT_USER, key.as_ptr());
        RegDeleteKeyW(HKEY_CURRENT_USER, key.as_ptr());
    }
}

/// Opens a URL in the default browser.
pub fn open_url(url: &str) -> Result<(), String> {
    // SAFETY: NUL-terminated strings that outlive the call.
    let result = unsafe {
        ShellExecuteW(
            null_mut(),
            wide("open").as_ptr(),
            wide(url).as_ptr(),
            null(),
            null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecute reports success with a value above 32.
    if result as usize > 32 {
        Ok(())
    } else {
        Err(format!(
            "cannot open the browser (error {})",
            result as usize
        ))
    }
}

/// The DNS host name of this computer.
pub fn computer_name() -> Option<String> {
    let mut buf = vec![0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` UTF-16 units.
    let ok = unsafe { GetComputerNameExW(ComputerNameDnsHostname, buf.as_mut_ptr(), &mut len) };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}
