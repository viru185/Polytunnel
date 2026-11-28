//! The look: two palettes (true-black dark, and light), the egui style made from them, and the
//! system fonts.

use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Shadow,
    Stroke, TextStyle, Theme, ThemePreference, Visuals, vec2,
};
use polytunnel_core::ipc::Status;

use super::prefs::Appearance;

/// Every colour the window uses.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    pub bg: Color32,
    pub surface: Color32,
    pub sunken: Color32,
    pub border: Color32,
    pub border_strong: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub accent_ink: Color32,
    pub accent_soft: Color32,
    pub green: Color32,
    pub green_soft: Color32,
    pub amber: Color32,
    pub amber_soft: Color32,
    pub red: Color32,
    pub red_soft: Color32,
    /// Status dots (bright on both backgrounds).
    pub dot_idle: Color32,
    pub dot_green: Color32,
    pub dot_amber: Color32,
    pub dot_red: Color32,
}

const fn hex(rgb: u32) -> Color32 {
    Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8)
}

/// True black, for OLED screens.
pub const DARK: Palette = Palette {
    bg: hex(0x000000),
    surface: hex(0x0B0C0E),
    sunken: hex(0x15171B),
    border: hex(0x23262C),
    border_strong: hex(0x2E323A),
    text: hex(0xF2F4F7),
    muted: hex(0xA1A9B5),
    accent: hex(0x8BA2FF),
    accent_ink: hex(0x000000),
    accent_soft: hex(0x141B33),
    green: hex(0x62D995),
    green_soft: hex(0x0C2416),
    amber: hex(0xF5BC55),
    amber_soft: hex(0x2A1E08),
    red: hex(0xFF8A80),
    red_soft: hex(0x2E100E),
    dot_idle: hex(0x4B5563),
    dot_green: hex(0x22C55E),
    dot_amber: hex(0xF59E0B),
    dot_red: hex(0xEF4444),
};

pub const LIGHT: Palette = Palette {
    bg: hex(0xF4F5F7),
    surface: hex(0xFFFFFF),
    sunken: hex(0xEEF0F3),
    border: hex(0xDFE3E8),
    border_strong: hex(0xC9CFD7),
    text: hex(0x14171C),
    muted: hex(0x5B6472),
    accent: hex(0x2F55D4),
    accent_ink: hex(0xFFFFFF),
    accent_soft: hex(0xE8EDFC),
    green: hex(0x167A3E),
    green_soft: hex(0xE3F4EA),
    amber: hex(0x9A5B00),
    amber_soft: hex(0xFDF1DC),
    red: hex(0xB42318),
    red_soft: hex(0xFDE8E6),
    dot_idle: hex(0xC2C8D0),
    dot_green: hex(0x22C55E),
    dot_amber: hex(0xF59E0B),
    dot_red: hex(0xEF4444),
};

/// The palette for the theme egui is showing now.
pub fn palette(ctx: &egui::Context) -> &'static Palette {
    palette_of(ctx.theme())
}

pub fn palette_of(theme: Theme) -> &'static Palette {
    match theme {
        Theme::Dark => &DARK,
        Theme::Light => &LIGHT,
    }
}

/// The theme preference for the user's appearance setting.
pub fn preference(appearance: Appearance) -> ThemePreference {
    match appearance {
        Appearance::System => ThemePreference::System,
        Appearance::Light => ThemePreference::Light,
        Appearance::Dark => ThemePreference::Dark,
    }
}

/// The name of the semibold font family (titles, the status line).
pub const SEMIBOLD: &str = "semibold";

/// A text style for the large status title.
pub fn title_style() -> TextStyle {
    TextStyle::Name("title".into())
}

fn visuals(p: &Palette, theme: Theme) -> Visuals {
    let mut v = match theme {
        Theme::Dark => Visuals::dark(),
        Theme::Light => Visuals::light(),
    };
    let radius = CornerRadius::same(9);
    v.panel_fill = p.bg;
    v.window_fill = p.surface;
    v.extreme_bg_color = p.surface;
    v.text_edit_bg_color = Some(p.surface);
    v.faint_bg_color = p.sunken;
    v.code_bg_color = p.sunken;
    v.window_stroke = Stroke::new(1.0, p.border_strong);
    v.window_corner_radius = CornerRadius::same(14);
    v.menu_corner_radius = CornerRadius::same(10);
    v.window_shadow = Shadow {
        offset: [0, 8],
        blur: 24,
        spread: 0,
        color: Color32::from_black_alpha(if theme == Theme::Dark { 200 } else { 60 }),
    };
    v.popup_shadow = Shadow {
        offset: [0, 6],
        blur: 16,
        spread: 0,
        color: Color32::from_black_alpha(if theme == Theme::Dark { 200 } else { 50 }),
    };
    v.hyperlink_color = p.accent;
    v.weak_text_color = Some(p.muted);
    v.warn_fg_color = p.amber;
    v.error_fg_color = p.red;
    v.selection.bg_fill = p.accent_soft;
    v.selection.stroke = Stroke::new(1.0, p.accent);
    v.striped = false;
    v.indent_has_left_vline = false;

    let w = &mut v.widgets;
    w.noninteractive.bg_fill = p.surface;
    w.noninteractive.weak_bg_fill = p.surface;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    w.noninteractive.corner_radius = radius;
    for (state, fill, stroke) in [
        (&mut w.inactive, p.sunken, p.border),
        (&mut w.hovered, p.border, p.border_strong),
        (&mut w.active, p.border_strong, p.accent),
        (&mut w.open, p.border, p.border_strong),
    ] {
        state.bg_fill = fill;
        state.weak_bg_fill = fill;
        state.bg_stroke = Stroke::new(1.0, stroke);
        state.fg_stroke = Stroke::new(1.5, p.text);
        state.corner_radius = radius;
        state.expansion = 0.0;
    }
    v
}

/// Applies the look for `appearance`: both palettes' styles, the theme preference, spacing
/// and text sizes.
pub fn apply(ctx: &egui::Context, appearance: Appearance) {
    ctx.set_visuals_of(Theme::Dark, visuals(&DARK, Theme::Dark));
    ctx.set_visuals_of(Theme::Light, visuals(&LIGHT, Theme::Light));
    ctx.set_theme(preference(appearance));
    ctx.all_styles_mut(|style| {
        let s = &mut style.spacing;
        s.item_spacing = vec2(8.0, 8.0);
        s.button_padding = vec2(12.0, 6.0);
        s.interact_size = vec2(36.0, 30.0);
        s.window_margin = Margin::same(16);
        s.menu_margin = Margin::same(6);
        s.icon_width = 16.0;
        s.icon_spacing = 6.0;
        let semibold = FontFamily::Name(SEMIBOLD.into());
        style.text_styles = [
            (TextStyle::Small, FontId::proportional(11.0)),
            (TextStyle::Body, FontId::proportional(13.0)),
            (TextStyle::Button, FontId::proportional(13.0)),
            (TextStyle::Monospace, FontId::monospace(12.0)),
            (TextStyle::Heading, FontId::new(17.0, semibold.clone())),
            (title_style(), FontId::new(20.0, semibold)),
        ]
        .into();
    });
}

/// System fonts to use, regular and semibold, in order of preference.
fn font_files() -> (Vec<&'static str>, Vec<&'static str>) {
    if cfg!(windows) {
        (
            vec![r"C:\Windows\Fonts\segoeui.ttf"],
            vec![
                r"C:\Windows\Fonts\seguisb.ttf",
                r"C:\Windows\Fonts\segoeuib.ttf",
            ],
        )
    } else if cfg!(target_os = "macos") {
        (
            vec!["/System/Library/Fonts/Supplemental/Arial.ttf"],
            vec!["/System/Library/Fonts/Supplemental/Arial Bold.ttf"],
        )
    } else {
        (
            vec![
                "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
                "/usr/share/fonts/noto/NotoSans-Regular.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                "/usr/share/fonts/TTF/DejaVuSans.ttf",
            ],
            vec![
                "/usr/share/fonts/truetype/noto/NotoSans-SemiBold.ttf",
                "/usr/share/fonts/noto/NotoSans-SemiBold.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
            ],
        )
    }
}

fn first_readable(paths: &[&str]) -> Option<Vec<u8>> {
    paths.iter().find_map(|p| std::fs::read(p).ok())
}

/// Uses the system's UI font (read at start, so it adds nothing to the program), with egui's
/// own fonts behind it for anything it lacks. Without one, egui's fonts are used.
pub fn fonts(ctx: &egui::Context) {
    let mut defs = FontDefinitions::default();
    let (regular, semibold) = font_files();
    let regular = first_readable(&regular);
    let semibold = first_readable(&semibold);
    let mut proportional = defs
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    if let Some(bytes) = regular {
        defs.font_data
            .insert("system".into(), Arc::new(FontData::from_owned(bytes)));
        proportional.insert(0, "system".into());
    }
    let mut bold = proportional.clone();
    if let Some(bytes) = semibold {
        defs.font_data.insert(
            "system-semibold".into(),
            Arc::new(FontData::from_owned(bytes)),
        );
        bold.insert(0, "system-semibold".into());
    }
    defs.families.insert(FontFamily::Proportional, proportional);
    defs.families
        .insert(FontFamily::Name(SEMIBOLD.into()), bold);
    ctx.set_fonts(defs);
}

/// The status's colours: (dot, text, soft background).
pub fn status_colors(
    p: &Palette,
    status: Option<&Result<Status, String>>,
) -> (Color32, Color32, Color32) {
    match status {
        Some(Ok(Status::Connected { notice: None, .. })) => (p.dot_green, p.green, p.green_soft),
        Some(Ok(
            Status::Connected { .. }
            | Status::Connecting { .. }
            | Status::NeedsInput { .. }
            | Status::Reconnecting { .. }
            | Status::Disconnecting { .. },
        )) => (p.dot_amber, p.amber, p.amber_soft),
        Some(Ok(Status::Failed { .. }) | Err(_)) => (p.dot_red, p.red, p.red_soft),
        Some(Ok(Status::Idle {})) | None => (p.dot_idle, p.text, p.sunken),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_appearance_picks_the_palette() {
        assert_eq!(palette_of(Theme::Dark).bg, Color32::BLACK);
        assert_eq!(preference(Appearance::System), ThemePreference::System);
    }

    /// WCAG contrast of `a` on `b`.
    fn contrast(a: Color32, b: Color32) -> f32 {
        let lum = |c: Color32| {
            let f = |v: u8| {
                let v = f32::from(v) / 255.0;
                if v <= 0.04045 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * f(c.r()) + 0.7152 * f(c.g()) + 0.0722 * f(c.b())
        };
        let (x, y) = (lum(a), lum(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    #[test]
    fn text_is_readable_in_both_themes() {
        for p in [&DARK, &LIGHT] {
            for bg in [p.bg, p.surface, p.sunken] {
                assert!(contrast(p.text, bg) >= 7.0);
                assert!(contrast(p.muted, bg) >= 4.5, "muted on {bg:?}");
            }
            assert!(contrast(p.accent_ink, p.accent) >= 4.5);
            for (ink, soft) in [
                (p.green, p.green_soft),
                (p.amber, p.amber_soft),
                (p.red, p.red_soft),
            ] {
                assert!(contrast(ink, soft) >= 4.5, "{ink:?} on {soft:?}");
            }
        }
    }
}
