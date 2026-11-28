//! The window's and the tray's own preferences: appearance, notifications, and where the
//! window was. Kept in `ui.toml` next to the profiles; anything missing or unreadable falls
//! back to the defaults.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::paths;

/// Light, dark, or whatever the system uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Appearance {
    #[default]
    System,
    Light,
    Dark,
}

/// The window's outer top-left corner and inner size, in points, and the scale they were
/// recorded at (to compare them with the screens in pixels).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WindowPlace {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub scale: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct Prefs {
    pub appearance: Appearance,
    /// Windows notifications when the connection changes.
    pub notifications: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<WindowPlace>,
    /// The tray has said once that Polytunnel keeps running after the window closes.
    #[serde(default)]
    pub close_hint_shown: bool,
    /// The profile connected with last (Home opens on it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_profile: Option<String>,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            appearance: Appearance::System,
            notifications: true,
            window: None,
            close_hint_shown: false,
            last_profile: None,
        }
    }
}

pub fn file() -> Option<PathBuf> {
    paths::config_dir().map(|d| d.join("ui.toml"))
}

/// The preferences, or the defaults when there are none (or they cannot be read).
pub fn load() -> Prefs {
    file()
        .and_then(|f| std::fs::read_to_string(f).ok())
        .and_then(|text| toml::from_str(&text).ok())
        .unwrap_or_default()
}

pub fn save(prefs: &Prefs) -> Result<(), String> {
    let path = file().ok_or("no configuration directory")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let text = toml::to_string(prefs).map_err(|e| e.to_string())?;
    crate::profiles_file::write_with_backup(&path, &text)
}

/// When the preferences file last changed (to notice changes made by the other process).
pub fn changed_at() -> Option<std::time::SystemTime> {
    file()
        .and_then(|f| std::fs::metadata(f).ok())
        .and_then(|m| m.modified().ok())
}

/// A rectangle in physical pixels: left, top, width, height.
pub type ScreenRect = (f32, f32, f32, f32);

/// Where to put the window: the remembered place when its title bar is on one of the screens
/// (`screens`: the desktop spanning every monitor, in pixels), else `None` (the system
/// decides). A remembered size below `min` is raised to it.
pub fn placement(place: WindowPlace, screens: ScreenRect, min: (f32, f32)) -> Option<WindowPlace> {
    let valid = |v: f32| v.is_finite();
    if ![place.x, place.y, place.width, place.height, place.scale]
        .into_iter()
        .all(valid)
        || place.scale <= 0.0
    {
        return None;
    }
    let (left, top, width, height) = screens;
    // The title bar's left part (where people grab it) must be on screen.
    let (px, py) = (place.x * place.scale, place.y * place.scale);
    let grab = 60.0 * place.scale;
    let on_screen = px + grab >= left
        && px + grab <= left + width
        && py >= top
        && py + 20.0 * place.scale <= top + height;
    on_screen.then(|| WindowPlace {
        width: place.width.max(min.0),
        height: place.height.max(min.1),
        ..place
    })
}

/// The desktop spanning every monitor, in pixels.
#[cfg(windows)]
pub fn screens() -> Option<ScreenRect> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN,
    };
    // SAFETY: no preconditions.
    let (x, y, w, h) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    };
    (w > 0 && h > 0).then_some((x as f32, y as f32, w as f32, h as f32))
}

#[cfg(not(windows))]
pub fn screens() -> Option<ScreenRect> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferences_round_trip_and_default_when_missing() {
        let prefs = Prefs {
            appearance: Appearance::Dark,
            notifications: false,
            window: Some(WindowPlace {
                x: 100.0,
                y: 80.0,
                width: 380.0,
                height: 680.0,
                scale: 1.5,
            }),
            close_hint_shown: true,
            last_profile: Some("Work".into()),
        };
        let text = toml::to_string(&prefs).unwrap();
        assert!(text.contains("appearance = \"dark\""));
        assert_eq!(toml::from_str::<Prefs>(&text).unwrap(), prefs);
        // An empty or partial file gives the defaults for what is missing.
        let partial: Prefs = toml::from_str("notifications = false").unwrap();
        assert_eq!(partial.appearance, Appearance::System);
        assert!(!partial.notifications);
        assert!(!partial.close_hint_shown);
        assert_eq!(toml::from_str::<Prefs>("").unwrap(), Prefs::default());
    }

    #[test]
    fn a_remembered_place_is_used_only_when_it_is_on_a_screen() {
        let place = WindowPlace {
            x: 100.0,
            y: 100.0,
            width: 300.0,
            height: 400.0,
            scale: 1.0,
        };
        let screens = (0.0, 0.0, 1920.0, 1080.0);
        let fitted = placement(place, screens, (340.0, 520.0)).unwrap();
        assert_eq!((fitted.x, fitted.y), (100.0, 100.0));
        // Too small: raised to the minimum.
        assert_eq!((fitted.width, fitted.height), (340.0, 520.0));
        // On a monitor that is gone, or above the top edge: the system decides.
        let gone = WindowPlace { x: 2500.0, ..place };
        assert_eq!(placement(gone, screens, (340.0, 520.0)), None);
        let above = WindowPlace { y: -50.0, ..place };
        assert_eq!(placement(above, screens, (340.0, 520.0)), None);
        // A second monitor to the left (negative coordinates) counts.
        let left = WindowPlace {
            x: -1500.0,
            ..place
        };
        assert!(placement(left, (-1920.0, 0.0, 3840.0, 1080.0), (340.0, 520.0)).is_some());
        // Scaled: points times the scale are pixels.
        let hidpi = WindowPlace {
            x: 1200.0,
            scale: 2.0,
            ..place
        };
        assert_eq!(placement(hidpi, screens, (340.0, 520.0)), None);
        let nan = WindowPlace {
            x: f32::NAN,
            ..place
        };
        assert_eq!(placement(nan, screens, (340.0, 520.0)), None);
    }
}
