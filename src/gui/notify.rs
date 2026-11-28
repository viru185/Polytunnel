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

impl Notice {
    /// Problems (and requests for the user) are shown even when notifications are turned off;
    /// news (connected) follows the setting.
    pub fn is_problem(&self) -> bool {
        self.kind != Kind::Info
    }
}

fn notice(kind: Kind, title: impl Into<String>, text: impl Into<String>) -> Option<Notice> {
    Some(Notice {
        kind,
        title: title.into(),
        text: text.into(),
    })
}

/// How long the service keeps trying to bring a dropped connection back (the service's
/// `RECONNECT_FOR`).
const RECONNECT_MINUTES: u32 = 5;

/// What the tray knows besides the status, for the wording.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Context<'a> {
    /// The kill switch is set to block (while connected, or always).
    pub killswitch_on: bool,
    /// The kill switch holds internet traffic after a connection dropped and could not be
    /// brought back ("while connected" mode).
    pub held: bool,
    /// What to call the server the connection runs to (the gateway's name), when known.
    pub place: Option<&'a str>,
}

/// The first sentence of a failure, as a sentence: "the gateway did not answer. The kill
/// switch ..." → "The gateway did not answer.", at most 150 characters. A host name or an
/// address at the start keeps its case.
pub fn short_reason(message: &str) -> String {
    const MAX: usize = 150;
    let message = message.trim();
    let first = message
        .find(". ")
        .map_or(message, |end| &message[..end])
        .trim_end_matches('.');
    let word = first.split_whitespace().next().unwrap_or_default();
    let mut chars = first.chars();
    let mut text: String = match chars.next() {
        None => return String::new(),
        Some(_) if word.contains(['.', ':', '/']) => first.to_string(),
        Some(c) => c.to_uppercase().chain(chars).collect(),
    };
    if text.chars().count() > MAX {
        text = text
            .chars()
            .take(MAX - 1)
            .collect::<String>()
            .trim_end()
            .to_string();
        text.push('…');
    } else {
        text.push('.');
    }
    text
}

/// The reason for a failure and where to find more.
fn failure_text(message: &str) -> String {
    let reason = short_reason(message);
    if reason.is_empty() {
        "Click to see what happened.".into()
    } else {
        format!("{reason} Click to see what happened.")
    }
}

/// "US East · your VPN address is 10.20.30.40".
fn connected_text(place: &str, addresses: &[String]) -> String {
    match addresses.first() {
        Some(address) => format!("{place} · your VPN address is {address}"),
        None => place.to_string(),
    }
}

/// The notification for the change from `before` to `now`, if it deserves one: connected,
/// dropped, back, waiting for the user, failed, or given up with the internet blocked.
/// Repeated polls of the same state give none, and so does the first status after start.
pub fn notice_for(before: Option<&Status>, now: &Status, ctx: &Context) -> Option<Notice> {
    use Status::*;
    let before = before?;
    match (before, now) {
        (Connected { profile: was, .. }, Connected { profile: is, .. }) if was == is => None,
        (
            _,
            Connected {
                profile,
                server,
                addresses,
                ..
            },
        ) => {
            let title = if matches!(before, Reconnecting { profile: was, .. } if was == profile) {
                format!("Reconnected to {profile}")
            } else {
                format!("Connected to {profile}")
            };
            let place = ctx.place.unwrap_or(server);
            notice(Kind::Info, title, connected_text(place, addresses))
        }
        (Reconnecting { .. }, Reconnecting { .. }) => None,
        (_, Reconnecting { profile, .. }) => {
            let mut text = format!("Polytunnel keeps trying for {RECONNECT_MINUTES} minutes.");
            if ctx.killswitch_on {
                text.push_str(" The kill switch holds traffic.");
            }
            notice(
                Kind::Warning,
                format!("{profile} dropped, reconnecting"),
                text,
            )
        }
        (NeedsInput { .. }, NeedsInput { .. }) => None,
        (_, NeedsInput { profile, .. }) => notice(
            Kind::Warning,
            format!("{profile} needs your sign-in"),
            "Click to open Polytunnel and finish connecting.",
        ),
        (
            Failed {
                profile: p0,
                message: m0,
                since_unix: s0,
            },
            Failed {
                profile,
                message,
                since_unix,
            },
        ) if p0 == profile && m0 == message && s0 == since_unix => None,
        (Connected { .. } | Reconnecting { .. }, Failed { profile, .. }) if ctx.held => {
            blocked(profile)
        }
        (
            Reconnecting { .. },
            Failed {
                profile, message, ..
            },
        ) => notice(
            Kind::Error,
            format!("Couldn't reconnect to {profile}"),
            failure_text(message),
        ),
        (
            Connected { .. },
            Failed {
                profile, message, ..
            },
        ) => notice(
            Kind::Error,
            format!("{profile} disconnected"),
            failure_text(message),
        ),
        // Stopping went wrong after the user asked to disconnect: the window says so.
        (Disconnecting { .. }, Failed { .. }) => None,
        (
            _,
            Failed {
                profile, message, ..
            },
        ) => notice(
            Kind::Error,
            format!("Couldn't connect to {profile}"),
            failure_text(message),
        ),
        (Reconnecting { profile, .. }, Idle {}) if ctx.held => blocked(profile),
        _ => None,
    }
}

fn blocked(profile: &str) -> Option<Notice> {
    notice(
        Kind::Error,
        format!("Internet blocked: {profile} couldn't reconnect"),
        "The kill switch holds traffic until you connect or unblock. Click to open.",
    )
}

/// Said once, the first time the window is closed while the tray runs.
pub fn still_running() -> Notice {
    Notice {
        kind: Kind::Info,
        title: "Polytunnel is still running".into(),
        text: "It stays in the tray next to the clock. Quit it from the tray menu.".into(),
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

/// The message tray-icon 0.27 registers its icons with (its private `WM_USER_TRAYICON`); the
/// shell sends notification clicks with it too, which tray-icon does not pass on.
#[cfg(windows)]
const TRAY_CALLBACK: u32 = 6002;

#[cfg(windows)]
static ON_CLICK: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>> = std::sync::OnceLock::new();

/// Calls `on_click` when the user clicks a notification shown by the tray icon whose window
/// is `hwnd` (`NIN_BALLOONUSERCLICK`). Call it once, on the thread that owns that window.
#[cfg(windows)]
pub fn on_click(hwnd: *mut core::ffi::c_void, on_click: impl Fn() + Send + Sync + 'static) {
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::UI::Shell::{DefSubclassProc, NIN_BALLOONUSERCLICK, SetWindowSubclass};

    unsafe extern "system" fn subclass(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
        _id: usize,
        _data: usize,
    ) -> LRESULT {
        // Without NOTIFYICON_VERSION_4 the event is the whole of lParam.
        if msg == TRAY_CALLBACK
            && (lparam as u32 & 0xFFFF) == NIN_BALLOONUSERCLICK
            && let Some(on_click) = ON_CLICK.get()
        {
            on_click();
        }
        // SAFETY: passes the message on unchanged to the next handler of this window.
        unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
    }

    if ON_CLICK.set(Box::new(on_click)).is_err() {
        return;
    }
    // SAFETY: `hwnd` is the tray icon's window, owned by this thread; the subclass procedure
    // only reads a static and passes every message on.
    unsafe {
        SetWindowSubclass(hwnd, Some(subclass), 0x5054_434b, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connected(profile: &str) -> Status {
        Status::Connected {
            profile: profile.into(),
            server: "gw.example.com".into(),
            addresses: vec!["10.20.30.40".into()],
            transport: "esp".into(),
            since_unix: 0,
            notice: None,
            gateway: None,
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    fn reconnecting() -> Status {
        Status::Reconnecting {
            profile: "Work".into(),
            server: "gw.example.com".into(),
            attempt: 1,
            since_unix: 0,
        }
    }

    fn failed(profile: &str, message: &str, since_unix: u64) -> Status {
        Status::Failed {
            profile: profile.into(),
            message: message.into(),
            since_unix,
        }
    }

    fn asking(profile: &str) -> Status {
        Status::NeedsInput {
            profile: profile.into(),
            prompt: polytunnel_core::ipc::Prompt {
                id: 1,
                message: None,
                fields: vec![],
            },
        }
    }

    const PLAIN: Context = Context {
        killswitch_on: false,
        held: false,
        place: None,
    };

    fn say(before: Option<&Status>, now: &Status, ctx: &Context) -> Option<(String, String)> {
        notice_for(before, now, ctx).map(|n| (n.title, n.text))
    }

    #[test]
    fn connected_names_the_profile_the_place_and_the_address() {
        let connecting = Status::Connecting {
            profile: "Work".into(),
        };
        let up = connected("Work");
        let east = Context {
            place: Some("US East"),
            ..PLAIN
        };
        let n = notice_for(Some(&connecting), &up, &east).unwrap();
        assert_eq!(n.title, "Connected to Work");
        assert_eq!(n.text, "US East · your VPN address is 10.20.30.40");
        assert!(!n.is_problem(), "follows the notifications setting");
        // Without a gateway name: the server.
        assert_eq!(
            say(Some(&Status::Idle {}), &up, &PLAIN).unwrap().1,
            "gw.example.com · your VPN address is 10.20.30.40"
        );
        // Polling the same state, and the first status after start, say nothing.
        assert_eq!(say(Some(&up), &up, &PLAIN), None);
        assert_eq!(say(None, &up, &PLAIN), None);
        // Switching profiles is news.
        assert_eq!(
            say(Some(&connected("Office")), &up, &PLAIN).unwrap().0,
            "Connected to Work"
        );
        assert_eq!(
            say(Some(&reconnecting()), &up, &PLAIN).unwrap().0,
            "Reconnected to Work"
        );
        // A disconnect the user asked for says nothing.
        assert_eq!(say(Some(&up), &Status::Idle {}, &PLAIN), None);
    }

    #[test]
    fn a_drop_says_how_long_polytunnel_keeps_trying() {
        let up = connected("Work");
        let n = notice_for(Some(&up), &reconnecting(), &PLAIN).unwrap();
        assert_eq!(n.title, "Work dropped, reconnecting");
        assert_eq!(n.text, "Polytunnel keeps trying for 5 minutes.");
        assert!(n.is_problem());
        let guarded = Context {
            killswitch_on: true,
            ..PLAIN
        };
        assert_eq!(
            say(Some(&up), &reconnecting(), &guarded).unwrap().1,
            "Polytunnel keeps trying for 5 minutes. The kill switch holds traffic."
        );
        assert_eq!(say(Some(&reconnecting()), &reconnecting(), &guarded), None);
    }

    #[test]
    fn sign_in_requests_are_announced_once() {
        let connecting = Status::Connecting {
            profile: "Office".into(),
        };
        let n = notice_for(Some(&connecting), &asking("Office"), &PLAIN).unwrap();
        assert_eq!(n.title, "Office needs your sign-in");
        assert_eq!(n.text, "Click to open Polytunnel and finish connecting.");
        assert!(n.is_problem(), "shown even with notifications off");
        assert_eq!(
            say(Some(&asking("Office")), &asking("Office"), &PLAIN),
            None
        );
        assert_eq!(say(None, &asking("Office"), &PLAIN), None);
    }

    #[test]
    fn failures_give_a_short_reason() {
        let connecting = Status::Connecting {
            profile: "Office".into(),
        };
        let down = failed("Office", "gw.example.com and its backup didn't answer", 9);
        let n = notice_for(Some(&connecting), &down, &PLAIN).unwrap();
        assert_eq!(n.kind, Kind::Error);
        assert_eq!(n.title, "Couldn't connect to Office");
        assert_eq!(
            n.text,
            "gw.example.com and its backup didn't answer. Click to see what happened."
        );
        // Seen only after it failed (the poll missed "connecting"): still news.
        assert!(say(Some(&Status::Idle {}), &down, &PLAIN).is_some());
        // The same failure polled again: nothing; a new one: again.
        assert_eq!(say(Some(&down), &down, &PLAIN), None);
        let again = failed("Office", "gw.example.com and its backup didn't answer", 30);
        assert!(say(Some(&down), &again, &PLAIN).is_some());
        // A connection that dropped and could not come back.
        let lost = failed(
            "Work",
            "the tunnel was lost (no answer) and could not be brought back",
            9,
        );
        assert_eq!(
            say(Some(&reconnecting()), &lost, &PLAIN).unwrap().0,
            "Couldn't reconnect to Work"
        );
        let ended = failed("Work", "the gateway ended the session", 9);
        assert_eq!(
            say(Some(&connected("Work")), &ended, &PLAIN).unwrap(),
            (
                "Work disconnected".into(),
                "The gateway ended the session. Click to see what happened.".into()
            )
        );
        let stopping = Status::Disconnecting {
            profile: "Work".into(),
        };
        assert_eq!(say(Some(&stopping), &ended, &PLAIN), None);
    }

    #[test]
    fn giving_up_with_the_kill_switch_holding_says_the_internet_is_blocked() {
        let held = Context {
            killswitch_on: true,
            held: true,
            place: None,
        };
        let lost = failed(
            "Work",
            "the tunnel was lost (no answer) and could not be brought back. The kill switch \
             keeps blocking internet traffic until you disconnect.",
            9,
        );
        for now in [&lost, &Status::Idle {}] {
            let n = notice_for(Some(&reconnecting()), now, &held).unwrap();
            assert_eq!(n.title, "Internet blocked: Work couldn't reconnect");
            assert_eq!(
                n.text,
                "The kill switch holds traffic until you connect or unblock. Click to open."
            );
            assert!(n.is_problem());
        }
        // Reconnecting, then disconnected on purpose: nothing.
        assert_eq!(say(Some(&reconnecting()), &Status::Idle {}, &PLAIN), None);
    }

    #[test]
    fn reasons_are_one_short_sentence() {
        assert_eq!(short_reason("no answer"), "No answer.");
        assert_eq!(
            short_reason("the tunnel was lost. The kill switch keeps blocking."),
            "The tunnel was lost."
        );
        assert_eq!(short_reason("  "), "");
        assert_eq!(failure_text(""), "Click to see what happened.");
        let long = short_reason(&"x".repeat(400));
        assert_eq!(long.chars().count(), 150);
        assert!(long.ends_with('…'));
        // Host names and addresses keep their dots.
        assert_eq!(
            short_reason("10.0.0.1 refused the connection"),
            "10.0.0.1 refused the connection."
        );
    }

    #[test]
    fn the_still_running_hint() {
        let n = still_running();
        assert_eq!(n.title, "Polytunnel is still running");
        assert_eq!(
            n.text,
            "It stays in the tray next to the clock. Quit it from the tray menu."
        );
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
