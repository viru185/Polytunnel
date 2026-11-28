//! Notifications about the connection: which changes deserve one, and showing them (Windows:
//! through the tray icon, so they appear as Windows notifications).

use polytunnel_core::ipc::Status;

/// How a notification looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub kind: Kind,
    pub title: String,
    pub text: String,
}

fn notice(kind: Kind, title: &str, text: impl Into<String>) -> Option<Notice> {
    Some(Notice {
        kind,
        title: title.into(),
        text: text.into(),
    })
}

/// The notification for the change from `before` to `now`, if it deserves one: connected,
/// dropped, back, failed, or waiting for the user. Repeated polls of the same state give
/// none.
pub fn notice_for(before: Option<&Status>, now: &Status) -> Option<Notice> {
    use Status::*;
    match (before, now) {
        (Some(Reconnecting { .. }), Connected { server, .. }) => notice(
            Kind::Info,
            "Reconnected",
            format!("The connection to {server} is back."),
        ),
        (Some(Connected { .. }), Connected { .. }) => None,
        (
            Some(_),
            Connected {
                profile, server, ..
            },
        ) => notice(
            Kind::Info,
            "Connected",
            format!("{profile} is connected through {server}."),
        ),
        (Some(Connected { .. }), Reconnecting { server, .. }) => notice(
            Kind::Warning,
            "Connection dropped",
            format!("Reconnecting to {server}…"),
        ),
        (Some(NeedsInput { .. }), NeedsInput { .. }) | (None, NeedsInput { .. }) => None,
        (Some(_), NeedsInput { profile, .. }) => notice(
            Kind::Warning,
            "Sign-in needed",
            format!("Open Polytunnel to finish signing in to {profile}."),
        ),
        (Some(Connected { .. } | Reconnecting { .. }), Failed { message, .. }) => {
            notice(Kind::Error, "VPN disconnected", message.clone())
        }
        (Some(Connecting { .. } | NeedsInput { .. }), Failed { message, .. }) => {
            notice(Kind::Error, "Couldn't connect", message.clone())
        }
        _ => None,
    }
}

/// A tray icon GUID for this program's path: Windows ties a GUID to the program it first saw
/// it with, so another copy of Polytunnel elsewhere needs its own (FNV-1a, stable across
/// versions so the icon keeps its taskbar settings after updates).
pub fn tray_guid(exe: &str) -> u128 {
    let fnv = |seed: u64| {
        let mut hash = 0xcbf2_9ce4_8422_2325u64 ^ seed;
        for byte in exe.to_lowercase().bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    };
    let raw = (u128::from(fnv(0x5054_554e)) << 64) | u128::from(fnv(0x4e45_4c00));
    // A version-4-style GUID (variant and version bits set).
    (raw & !(0xf000u128 << 64) | (0x4000u128 << 64)) & !(0xc000u128 << 48) | (0x8000u128 << 48)
}

/// Shows `notice` as a Windows notification from the tray icon with `guid` (`hwnd`: the tray
/// icon's window).
#[cfg(windows)]
pub fn show(hwnd: *mut core::ffi::c_void, guid: u128, notice: &Notice) -> bool {
    use windows_sys::Win32::UI::Shell::{
        NIF_GUID, NIF_INFO, NIIF_ERROR, NIIF_INFO, NIIF_WARNING, NIM_MODIFY, NOTIFYICONDATAW,
        Shell_NotifyIconW,
    };
    fn copy(dst: &mut [u16], text: &str) {
        let wide: Vec<u16> = text.encode_utf16().take(dst.len() - 1).collect();
        dst[..wide.len()].copy_from_slice(&wide);
        dst[wide.len()] = 0;
    }
    // SAFETY: plain data; zero is valid for every field.
    let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    data.hWnd = hwnd;
    data.uFlags = NIF_INFO | NIF_GUID;
    data.guidItem = windows_sys::core::GUID::from_u128(guid);
    copy(&mut data.szInfoTitle, &notice.title);
    copy(&mut data.szInfo, &notice.text);
    data.dwInfoFlags = match notice.kind {
        Kind::Info => NIIF_INFO,
        Kind::Warning => NIIF_WARNING,
        Kind::Error => NIIF_ERROR,
    };
    // SAFETY: `data` is a fully initialised NOTIFYICONDATAW of the size it states.
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connected(server: &str) -> Status {
        Status::Connected {
            profile: "work".into(),
            server: server.into(),
            addresses: vec![],
            transport: "esp".into(),
            since_unix: 0,
            notice: None,
            gateway: None,
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    #[test]
    fn each_change_is_announced_once() {
        let connecting = Status::Connecting {
            profile: "work".into(),
        };
        let reconnecting = Status::Reconnecting {
            profile: "work".into(),
            server: "gw.example.com".into(),
            attempt: 1,
            since_unix: 0,
        };
        let failed = Status::Failed {
            profile: "work".into(),
            message: "no answer".into(),
            since_unix: 0,
        };
        let up = connected("gw.example.com");
        let title = |b: Option<&Status>, n: &Status| notice_for(b, n).map(|n| n.title);
        assert_eq!(title(Some(&connecting), &up).as_deref(), Some("Connected"));
        assert_eq!(title(Some(&up), &up), None, "polling the same state");
        assert_eq!(
            title(Some(&up), &reconnecting).as_deref(),
            Some("Connection dropped")
        );
        assert_eq!(title(Some(&reconnecting), &reconnecting), None);
        assert_eq!(
            title(Some(&reconnecting), &up).as_deref(),
            Some("Reconnected")
        );
        assert_eq!(
            title(Some(&reconnecting), &failed).as_deref(),
            Some("VPN disconnected")
        );
        assert_eq!(
            title(Some(&connecting), &failed).as_deref(),
            Some("Couldn't connect")
        );
        // A disconnect the user asked for, and the first status after start, say nothing.
        assert_eq!(title(Some(&up), &Status::Idle {}), None);
        assert_eq!(title(None, &up), None);
        let asking = Status::NeedsInput {
            profile: "work".into(),
            prompt: polytunnel_core::ipc::Prompt {
                id: 1,
                message: None,
                fields: vec![],
            },
        };
        assert_eq!(
            title(Some(&connecting), &asking).as_deref(),
            Some("Sign-in needed")
        );
        assert_eq!(title(Some(&asking), &asking), None);
    }

    #[test]
    fn tray_guids_are_stable_and_differ_per_path() {
        let a = tray_guid(r"C:\Program Files\Polytunnel\polytunnelw.exe");
        assert_eq!(a, tray_guid(r"c:\program files\polytunnel\POLYTUNNELW.exe"));
        assert_ne!(a, tray_guid(r"D:\Tools\Polytunnel\polytunnelw.exe"));
        // Version 4, RFC 4122 variant.
        assert_eq!((a >> 76) & 0xf, 4);
        assert_eq!((a >> 62) & 0x3, 2);
    }
}
