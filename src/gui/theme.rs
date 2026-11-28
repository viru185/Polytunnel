//! The look: two palettes (true-black dark, and light) mirroring `design/tokens.css`, the egui
//! style made from them, and the system fonts.

use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Shadow,
    Stroke, TextStyle, Theme, ThemePreference, Visuals, vec2,
};

use super::prefs::Appearance;

/// Every colour the window uses (the names follow the design tokens).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    pub bg: Color32,
    pub surface: Color32,
    pub surface2: Color32,
    pub surface3: Color32,
    /// Dividers and card borders.
    pub line: Color32,
    /// Input sides, secondary button borders.
    pub line_strong: Color32,
    /// Radio and checkbox rings, the toggle-off outline, the input bottom edge (≥ 3:1).
    pub control_line: Color32,
    pub text: Color32,
    pub text2: Color32,
    pub text3: Color32,
    pub text_disabled: Color32,
    pub accent: Color32,
    /// The top of the hero's gradient, and the primary button's hover.
    pub accent_hi: Color32,
    pub accent_ink: Color32,
    pub accent_soft: Color32,
    pub accent_line: Color32,
    pub accent_shadow: Color32,
    /// Status colours for rings and glyphs …
    pub green: Color32,
    pub amber: Color32,
    pub red: Color32,
    /// … for text of 14 px or less …
    pub green_text: Color32,
    pub amber_text: Color32,
    pub red_text: Color32,
    /// … and their tinted fills and borders.
    pub green_soft: Color32,
    pub amber_soft: Color32,
    pub red_soft: Color32,
    pub green_line: Color32,
    pub amber_line: Color32,
    pub red_line: Color32,
    /// The glow behind the connected hero (dark only; light uses a tinted shadow).
    pub glow_green: Color32,
    pub scrim: Color32,
    pub dialog: Color32,
    pub menu: Color32,
    /// The selected segment.
    pub thumb: Color32,
    pub badge: Color32,
    pub badge_ink: Color32,
    pub title_bar: Color32,
    pub title_ink: Color32,
    /// The hero disc in every state but the call to action.
    pub disc: Color32,
    pub disc_shadow: Option<Shadow>,
    pub hover: Color32,
    pub pressed: Color32,
    pub shadow: Color32,
    pub dark: bool,
}

const fn hex(rgb: u32) -> Color32 {
    Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8)
}

/// `rgb` at `alpha` (0–255), unmultiplied.
const fn rgba(rgb: u32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied_const((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8, alpha)
}

/// AMOLED dark: true black.
pub const DARK: Palette = Palette {
    bg: hex(0x000000),
    surface: hex(0x0E0F12),
    surface2: hex(0x16181D),
    surface3: hex(0x22252C),
    line: hex(0x24272E),
    line_strong: hex(0x353943),
    control_line: hex(0x686E7A),
    text: hex(0xF3F4F6),
    text2: hex(0xB0B5BF),
    text3: hex(0x8A909B),
    text_disabled: hex(0x70767F),
    accent: hex(0x8C9BFF),
    accent_hi: hex(0xA6B1FF),
    accent_ink: hex(0x090B18),
    accent_soft: rgba(0x8C9BFF, 36),
    accent_line: rgba(0x8C9BFF, 107),
    accent_shadow: rgba(0x8C9BFF, 89),
    green: hex(0x5CD69B),
    amber: hex(0xF4BE4F),
    red: hex(0xFF7E7E),
    green_text: hex(0x5CD69B),
    amber_text: hex(0xF4BE4F),
    red_text: hex(0xFF7E7E),
    green_soft: rgba(0x5CD69B, 31),
    amber_soft: rgba(0xF4BE4F, 31),
    red_soft: rgba(0xFF7E7E, 31),
    green_line: rgba(0x5CD69B, 107),
    amber_line: rgba(0xF4BE4F, 107),
    red_line: rgba(0xFF7E7E, 112),
    glow_green: rgba(0x5CD69B, 56),
    scrim: rgba(0x000000, 168),
    dialog: hex(0x121318),
    menu: hex(0x16181D),
    thumb: hex(0x2A2E37),
    badge: hex(0x22252C),
    badge_ink: hex(0xB0B5BF),
    title_bar: hex(0x000000),
    title_ink: hex(0xC9CDD4),
    disc: hex(0x16181D),
    disc_shadow: None,
    hover: rgba(0xFFFFFF, 15),
    pressed: rgba(0xFFFFFF, 26),
    shadow: rgba(0x000000, 140),
    dark: true,
};

pub const LIGHT: Palette = Palette {
    bg: hex(0xF4F5F7),
    surface: hex(0xFFFFFF),
    surface2: hex(0xF0F1F4),
    surface3: hex(0xE6E8ED),
    line: hex(0xE1E4E9),
    line_strong: hex(0xCDD1D8),
    control_line: hex(0x80868F),
    text: hex(0x0F1115),
    text2: hex(0x4B5260),
    text3: hex(0x5E6572),
    text_disabled: hex(0x80868F),
    accent: hex(0x4352D6),
    accent_hi: hex(0x5260E4),
    accent_ink: hex(0xFFFFFF),
    accent_soft: rgba(0x4352D6, 26),
    accent_line: rgba(0x4352D6, 102),
    accent_shadow: rgba(0x4352D6, 71),
    green: hex(0x15803D),
    amber: hex(0xA16207),
    red: hex(0xC62828),
    green_text: hex(0x116B33),
    amber_text: hex(0x854D0E),
    red_text: hex(0xB42318),
    green_soft: rgba(0x15803D, 26),
    amber_soft: rgba(0xCA8A04, 31),
    red_soft: rgba(0xDC2626, 23),
    green_line: rgba(0x15803D, 102),
    amber_line: rgba(0xA16207, 102),
    red_line: rgba(0xC62828, 102),
    glow_green: rgba(0x15803D, 51),
    scrim: rgba(0x0F1115, 97),
    dialog: hex(0xFFFFFF),
    menu: hex(0xFFFFFF),
    thumb: hex(0xFFFFFF),
    badge: hex(0xE6E8ED),
    badge_ink: hex(0x4B5260),
    title_bar: hex(0xF4F5F7),
    title_ink: hex(0x3A3F48),
    disc: hex(0xFFFFFF),
    disc_shadow: Some(Shadow {
        offset: [0, 4],
        blur: 16,
        spread: 0,
        color: rgba(0x0F1115, 26),
    }),
    hover: rgba(0x0F1115, 13),
    pressed: rgba(0x0F1115, 20),
    shadow: rgba(0x0F1115, 41),
    dark: false,
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

/// The semibold font family (titles, labels, buttons).
pub const SEMIBOLD: &str = "semibold";

pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SEMIBOLD.into()))
}

pub fn regular(size: f32) -> FontId {
    FontId::proportional(size)
}

/// Cascadia Mono (fingerprints only).
pub fn mono(size: f32) -> FontId {
    FontId::monospace(size)
}

/// The hero's state word: 26 px semibold.
pub fn title_style() -> TextStyle {
    TextStyle::Name("title".into())
}

fn visuals(p: &Palette, theme: Theme) -> Visuals {
    let mut v = match theme {
        Theme::Dark => Visuals::dark(),
        Theme::Light => Visuals::light(),
    };
    let radius = CornerRadius::same(8);
    v.panel_fill = p.bg;
    v.window_fill = p.dialog;
    v.extreme_bg_color = p.surface2;
    v.text_edit_bg_color = Some(p.surface2);
    v.faint_bg_color = p.surface2;
    v.code_bg_color = p.surface2;
    v.window_stroke = Stroke::new(1.0, p.line_strong);
    v.window_corner_radius = CornerRadius::same(16);
    v.menu_corner_radius = CornerRadius::same(8);
    v.window_shadow = Shadow {
        offset: [0, 8],
        blur: 28,
        spread: 0,
        color: p.shadow,
    };
    v.popup_shadow = Shadow {
        offset: [0, 8],
        blur: 24,
        spread: 0,
        color: p.shadow,
    };
    v.hyperlink_color = p.accent;
    v.weak_text_color = Some(p.text3);
    v.warn_fg_color = p.amber_text;
    v.error_fg_color = p.red_text;
    v.selection.bg_fill = p.accent_soft;
    v.selection.stroke = Stroke::new(1.0, p.accent);
    v.text_cursor.stroke = Stroke::new(1.5, p.accent);
    v.striped = false;
    v.indent_has_left_vline = false;
    v.override_text_color = Some(p.text);

    let w = &mut v.widgets;
    w.noninteractive.bg_fill = p.surface;
    w.noninteractive.weak_bg_fill = p.surface;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.line);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    w.noninteractive.corner_radius = radius;
    for (state, fill, stroke) in [
        (&mut w.inactive, p.surface2, p.line_strong),
        (&mut w.hovered, p.surface3, p.line_strong),
        (&mut w.active, p.surface3, p.accent),
        (&mut w.open, p.surface3, p.line_strong),
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
        s.interact_size = vec2(32.0, 32.0);
        s.window_margin = Margin::same(16);
        s.menu_margin = Margin::same(4);
        s.icon_width = 16.0;
        s.icon_spacing = 8.0;
        s.scroll.bar_width = 6.0;
        s.scroll.floating = true;
        style.text_styles = [
            (TextStyle::Small, regular(12.0)),
            (TextStyle::Body, regular(14.0)),
            (TextStyle::Button, semibold(14.0)),
            (TextStyle::Monospace, mono(12.0)),
            (TextStyle::Heading, semibold(18.0)),
            (title_style(), semibold(26.0)),
        ]
        .into();
    });
}

/// System fonts to use, regular and semibold, in order of preference.
fn font_files() -> (Vec<&'static str>, Vec<&'static str>, Vec<&'static str>) {
    if cfg!(windows) {
        (
            vec![r"C:\Windows\Fonts\segoeui.ttf"],
            vec![
                r"C:\Windows\Fonts\seguisb.ttf",
                r"C:\Windows\Fonts\segoeuib.ttf",
            ],
            vec![
                r"C:\Windows\Fonts\CascadiaMono.ttf",
                r"C:\Windows\Fonts\consola.ttf",
            ],
        )
    } else if cfg!(target_os = "macos") {
        (
            vec!["/System/Library/Fonts/Supplemental/Arial.ttf"],
            vec!["/System/Library/Fonts/Supplemental/Arial Bold.ttf"],
            vec!["/System/Library/Fonts/Menlo.ttc"],
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
            vec![
                "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
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
    let (regular, semibold, mono) = font_files();
    let regular = first_readable(&regular);
    let semibold = first_readable(&semibold);
    let mono = first_readable(&mono);
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
    if let Some(bytes) = mono {
        defs.font_data
            .insert("system-mono".into(), Arc::new(FontData::from_owned(bytes)));
        if let Some(family) = defs.families.get_mut(&FontFamily::Monospace) {
            family.insert(0, "system-mono".into());
        }
    }
    defs.families.insert(FontFamily::Proportional, proportional);
    defs.families
        .insert(FontFamily::Name(SEMIBOLD.into()), bold);
    ctx.set_fonts(defs);
}

/// Linear blend of `a` towards `b` by `t` (0–1), on unmultiplied channels.
pub fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let [ar, ag, ab, aa] = a.to_srgba_unmultiplied();
    let [br, bg, bb, ba] = b.to_srgba_unmultiplied();
    let f = |x: u8, y: u8| (f32::from(x) + (f32::from(y) - f32::from(x)) * t).round() as u8;
    Color32::from_rgba_unmultiplied(f(ar, br), f(ag, bg), f(ab, bb), f(aa, ba))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `top` drawn over the opaque `under`.
    fn over(top: Color32, under: Color32) -> Color32 {
        let [r, g, b, a] = top.to_srgba_unmultiplied();
        mix(under, Color32::from_rgb(r, g, b), f32::from(a) / 255.0)
    }

    #[test]
    fn the_appearance_picks_the_palette() {
        assert_eq!(palette_of(Theme::Dark).bg, Color32::BLACK);
        assert!(!palette_of(Theme::Light).dark);
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
            for bg in [p.bg, p.surface, p.surface2] {
                assert!(contrast(p.text, bg) >= 7.0);
                assert!(contrast(p.text2, bg) >= 4.5, "text2 on {bg:?}");
                assert!(contrast(p.text3, bg) >= 4.5, "text3 on {bg:?}");
                assert!(
                    contrast(p.control_line, bg) >= 3.0,
                    "control line on {bg:?}"
                );
                assert!(contrast(p.accent, bg) >= 4.5, "accent on {bg:?}");
            }
            assert!(contrast(p.accent_ink, p.accent) >= 4.5);
            assert!(contrast(p.accent_ink, p.accent_hi) >= 4.5);
            for (ink, soft) in [
                (p.green_text, p.green_soft),
                (p.amber_text, p.amber_soft),
                (p.red_text, p.red_soft),
            ] {
                for bg in [p.bg, p.surface] {
                    let fill = over(soft, bg);
                    assert!(contrast(ink, fill) >= 4.5, "{ink:?} on {fill:?}");
                }
            }
        }
    }
}
