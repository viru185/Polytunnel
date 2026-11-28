//! The window's building blocks, drawn to `design/mockups.html` and `design/tokens.css`:
//! buttons, rows, cards, chips and pills, the segmented control, switches, radios, banners,
//! text fields, the stats row and the big connect button. All take their colours from the
//! current palette, show a hover state, and draw a focus ring when reached with the keyboard.

use std::f32::consts::{PI, TAU};

use eframe::egui::{
    self, Align2, Color32, ColorImage, CornerRadius, CursorIcon, FontId, Frame, Id, Margin, Mesh,
    Pos2, Rect, Response, Sense, Shadow, Shape, Stroke, StrokeKind, TextEdit, TextureHandle,
    TextureOptions, Ui, Vec2, pos2, vec2,
};

use super::icons::{self, Icon};
use super::theme::{self, Palette};

/// The palette for `ui`'s theme.
pub fn pal(ui: &Ui) -> &'static Palette {
    theme::palette(ui.ctx())
}

// ---------------------------------------------------------------------------------------------
// Basics

/// The keyboard focus ring: 2 px accent with a 2 px gap outside `rect` (or inset inside it).
pub fn focus_ring(ui: &Ui, rect: Rect, radius: f32, inset: bool, response: &Response) {
    if !response.has_focus() {
        return;
    }
    let p = pal(ui);
    let (r, rad) = if inset {
        (rect.shrink(1.0), (radius - 1.0).max(0.0))
    } else {
        (rect.expand(3.0), radius + 3.0)
    };
    ui.painter().rect_stroke(
        r,
        CornerRadius::same(rad.round() as u8),
        Stroke::new(2.0, p.accent),
        StrokeKind::Middle,
    );
}

fn text_width(ui: &Ui, text: &str, font: FontId) -> f32 {
    ui.painter()
        .layout_no_wrap(text.to_string(), font, Color32::WHITE)
        .size()
        .x
}

/// Draws `text` at `pos` (anchored by `align`), cut with "…" to `max_width`.
pub fn text_cut(
    ui: &Ui,
    pos: Pos2,
    align: Align2,
    text: &str,
    font: FontId,
    color: Color32,
    max_width: f32,
) -> Rect {
    let mut job = egui::text::LayoutJob::simple_singleline(text.to_string(), font, color);
    job.wrap.max_width = max_width.max(8.0);
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    let galley = ui.painter().layout_job(job);
    let rect = align.anchor_size(pos, galley.size());
    ui.painter().galley(rect.min, galley, color);
    rect
}

// ---------------------------------------------------------------------------------------------
// Buttons

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Primary,
    Secondary,
    Quiet,
    Danger,
}

/// A button: 36 points tall (32 when `small`), with an optional 16 point icon.
pub fn button(ui: &mut Ui, kind: Kind, text: &str, icon: Option<Icon>, small: bool) -> Response {
    button_sized(ui, kind, text, icon, small, None)
}

/// A button as wide as the space.
pub fn button_block(ui: &mut Ui, kind: Kind, text: &str, icon: Option<Icon>) -> Response {
    let width = ui.available_width();
    button_sized(ui, kind, text, icon, false, Some(width))
}

fn button_sized(
    ui: &mut Ui,
    kind: Kind,
    text: &str,
    icon: Option<Icon>,
    small: bool,
    width: Option<f32>,
) -> Response {
    let p = pal(ui);
    let enabled = ui.is_enabled();
    let height = if small { 32.0 } else { 36.0 };
    let pad = if small { 12.0 } else { 16.0 };
    let font = theme::semibold(14.0);
    let label_width = text_width(ui, text, font.clone());
    let icon_space = if icon.is_some() { 24.0 } else { 0.0 };
    let w = width.unwrap_or(pad * 2.0 + label_width + icon_space);
    let (rect, response) = ui.allocate_exact_size(vec2(w, height), Sense::click());
    let response = if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    };
    if ui.is_rect_visible(rect) {
        let hovered = enabled && response.hovered();
        let pressed = enabled && response.is_pointer_button_down_on();
        let (fill, stroke, ink) = match kind {
            Kind::Primary => (
                if pressed {
                    theme::mix(p.accent, Color32::BLACK, 0.08)
                } else if hovered {
                    p.accent_hi
                } else {
                    p.accent
                },
                Stroke::NONE,
                p.accent_ink,
            ),
            Kind::Secondary => (p.surface2, Stroke::new(1.0, p.line_strong), p.text),
            Kind::Quiet => (Color32::TRANSPARENT, Stroke::NONE, p.text),
            Kind::Danger => (p.red_soft, Stroke::new(1.0, p.red_line), p.red_text),
        };
        let (fill, ink) = if enabled {
            (fill, ink)
        } else {
            (fill.gamma_multiply(0.5), p.text_disabled)
        };
        let painter = ui.painter();
        painter.rect(
            rect,
            CornerRadius::same(8),
            fill,
            stroke,
            StrokeKind::Inside,
        );
        if kind != Kind::Primary && (hovered || pressed) {
            painter.rect_filled(
                rect,
                CornerRadius::same(8),
                if pressed { p.pressed } else { p.hover },
            );
        }
        let content = icon_space + label_width;
        let mut x = rect.center().x - content / 2.0;
        if let Some(icon) = icon {
            icons::paint(
                painter,
                Rect::from_min_size(pos2(x, rect.center().y - 8.0), vec2(16.0, 16.0)),
                icon,
                ink,
            );
            x += icon_space;
        }
        painter.text(
            pos2(x, rect.center().y),
            Align2::LEFT_CENTER,
            text,
            font,
            ink,
        );
        focus_ring(ui, rect, 8.0, false, &response);
    }
    response
}

/// A text link: 32 points tall, semibold, in the muted ink (or the accent).
pub fn link(ui: &mut Ui, text: &str, accent: bool, icon: Option<Icon>) -> Response {
    let p = pal(ui);
    let font = theme::semibold(14.0);
    let icon_space = if icon.is_some() { 22.0 } else { 0.0 };
    let w = 24.0 + text_width(ui, text, font.clone()) + icon_space;
    let (rect, response) = ui.allocate_exact_size(vec2(w, 32.0), Sense::click());
    let response = response.on_hover_cursor(CursorIcon::PointingHand);
    if ui.is_rect_visible(rect) {
        let ink = if accent { p.accent } else { p.text2 };
        if response.hovered() {
            ui.painter()
                .rect_filled(rect, CornerRadius::same(8), p.hover);
        }
        let mut x = rect.left() + 12.0;
        if let Some(icon) = icon {
            icons::paint(
                ui.painter(),
                Rect::from_min_size(pos2(x, rect.center().y - 8.0), vec2(16.0, 16.0)),
                icon,
                ink,
            );
            x += icon_space;
        }
        ui.painter().text(
            pos2(x, rect.center().y),
            Align2::LEFT_CENTER,
            text,
            font,
            ink,
        );
        focus_ring(ui, rect, 8.0, false, &response);
    }
    response
}

/// A square button with a line icon and a tooltip; `dot`: a small badge at the top right.
pub fn icon_button(
    ui: &mut Ui,
    icon: Icon,
    tip: &str,
    size: f32,
    dot: Option<Color32>,
) -> Response {
    icon_button_ink(ui, icon, tip, size, dot, None)
}

/// Like [`icon_button`], with the icon in `ink` (default: the muted ink).
pub fn icon_button_ink(
    ui: &mut Ui,
    icon: Icon,
    tip: &str,
    size: f32,
    dot: Option<Color32>,
    ink: Option<Color32>,
) -> Response {
    let p = pal(ui);
    let enabled = ui.is_enabled();
    let (rect, response) = ui.allocate_exact_size(vec2(size, size), Sense::click());
    if ui.is_rect_visible(rect) {
        if enabled && response.hovered() {
            ui.painter()
                .rect_filled(rect, CornerRadius::same(8), p.hover);
        }
        let ink = if enabled {
            ink.unwrap_or(p.text2)
        } else {
            p.text_disabled
        };
        let side = if size >= 36.0 { 20.0 } else { 16.0 };
        icons::paint(
            ui.painter(),
            Rect::from_center_size(rect.center(), vec2(side, side)),
            icon,
            ink,
        );
        if let Some(color) = dot {
            let c = rect.right_top() + vec2(-11.0, 11.0);
            ui.painter().circle_filled(c, 6.0, p.bg);
            ui.painter().circle_filled(c, 4.0, color);
        }
        focus_ring(ui, rect, 8.0, false, &response);
    }
    let response = response.on_hover_text(tip);
    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    }
}

/// Lays out `add` inside a builder's rect without moving the parent's cursor (overlays: the
/// trailing controls of a row, a header's right side).
pub fn place<R>(
    ui: &mut Ui,
    builder: egui::UiBuilder,
    add: impl FnOnce(&mut Ui) -> R,
) -> egui::InnerResponse<R> {
    let mut child = ui.new_child(builder);
    let inner = add(&mut child);
    egui::InnerResponse::new(inner, child.response())
}

// ---------------------------------------------------------------------------------------------
// Containers

/// A rounded card on the surface colour, as wide as the space; `pad`: 16 points inside.
pub fn card<R>(ui: &mut Ui, pad: bool, add: impl FnOnce(&mut Ui) -> R) -> R {
    let p = pal(ui);
    Frame::NONE
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(12)
        .inner_margin(if pad { Margin::same(16) } else { Margin::ZERO })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;
            add(ui)
        })
        .inner
}

/// A section label above a group: 24 points above, 8 below; `right` adds controls on its line.
pub fn section(ui: &mut Ui, text: &str, right: Option<&mut dyn FnMut(&mut Ui)>) {
    let p = pal(ui);
    ui.add_space(24.0);
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 16.0), Sense::hover());
    ui.painter().text(
        rect.left_center(),
        Align2::LEFT_CENTER,
        text,
        theme::semibold(12.0),
        p.text3,
    );
    if let Some(right) = right {
        let area = Rect::from_min_max(
            pos2(rect.center().x, rect.center().y - 16.0),
            pos2(rect.right(), rect.center().y + 16.0),
        );
        place(
            ui,
            egui::UiBuilder::new()
                .max_rect(area)
                .layout(egui::Layout::right_to_left(egui::Align::Center)),
            |ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                right(ui);
            },
        );
    }
    ui.add_space(8.0);
}

/// Help text under a control: 12 points, muted, wrapped.
pub fn help(ui: &mut Ui, text: &str) {
    let p = pal(ui);
    ui.add(
        egui::Label::new(egui::RichText::new(text).size(12.0).color(p.text3))
            .wrap()
            .selectable(false),
    );
}

/// The corners of a row inside a card: the first and last rows follow the card's radius.
pub fn row_corners(first: bool, last: bool) -> CornerRadius {
    CornerRadius {
        nw: if first { 11 } else { 0 },
        ne: if first { 11 } else { 0 },
        sw: if last { 11 } else { 0 },
        se: if last { 11 } else { 0 },
    }
}

/// Allocates a full-width row of `height` inside a card, with the hover fill and a divider
/// above it unless it is the first. Returns its rect and response.
pub fn row_frame(
    ui: &mut Ui,
    height: f32,
    first: bool,
    last: bool,
    sense: Sense,
) -> (Rect, Response) {
    let p = pal(ui);
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), height), sense);
    let clickable = sense.senses_click() && ui.is_enabled();
    if ui.is_rect_visible(rect) {
        if clickable && response.hovered() {
            ui.painter()
                .rect_filled(rect, row_corners(first, last), p.hover);
        }
        if !first {
            ui.painter()
                .hline(rect.x_range(), rect.top() + 0.5, Stroke::new(1.0, p.line));
        }
        if clickable && response.has_focus() {
            ui.painter().rect_stroke(
                rect.shrink(1.0),
                row_corners(first, last),
                Stroke::new(2.0, p.accent),
                StrokeKind::Middle,
            );
        }
    }
    let response = if clickable {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    };
    (rect, response)
}

/// A 48 point row: a label on the left, a value on the right (cut to fit), and a chevron when
/// it opens something.
pub fn nav_row(
    ui: &mut Ui,
    label: &str,
    value: &str,
    chevron: Option<Icon>,
    first: bool,
    last: bool,
) -> Response {
    let p = pal(ui);
    let sense = if chevron.is_some() {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, response) = row_frame(ui, 48.0, first, last, sense);
    if ui.is_rect_visible(rect) {
        let label_rect = text_cut(
            ui,
            pos2(rect.left() + 16.0, rect.center().y),
            Align2::LEFT_CENTER,
            label,
            theme::regular(14.0),
            p.text2,
            rect.width() * 0.5,
        );
        let mut right = rect.right() - 16.0;
        if let Some(icon) = chevron {
            icons::paint(
                ui.painter(),
                Rect::from_min_size(pos2(right - 16.0, rect.center().y - 8.0), vec2(16.0, 16.0)),
                icon,
                p.text3,
            );
            right -= 28.0;
        }
        text_cut(
            ui,
            pos2(right, rect.center().y),
            Align2::RIGHT_CENTER,
            value,
            theme::regular(14.0),
            p.text,
            right - label_rect.right() - 16.0,
        );
    }
    response
}

/// A 48 point row with a title on the left and a value on the right (details, diagnostics).
pub fn value_row(ui: &mut Ui, label: &str, value: &str, value_ink: Option<Color32>) {
    let p = pal(ui);
    let (rect, _) = row_frame(ui, 48.0, false, false, Sense::hover());
    if ui.is_rect_visible(rect) {
        let label_rect = text_cut(
            ui,
            pos2(rect.left() + 16.0, rect.center().y),
            Align2::LEFT_CENTER,
            label,
            theme::regular(14.0),
            p.text2,
            rect.width() * 0.5,
        );
        text_cut(
            ui,
            pos2(rect.right() - 16.0, rect.center().y),
            Align2::RIGHT_CENTER,
            value,
            theme::regular(14.0),
            value_ink.unwrap_or(p.text),
            rect.right() - 16.0 - label_rect.right() - 16.0,
        );
    }
}

/// A fold: a 48 point "Advanced" row with a summary, opening the content below. Returns
/// whether it is open (remembered per `id`).
pub fn fold_row(ui: &mut Ui, id: &str, title: &str, summary: &str, first: bool) -> bool {
    let p = pal(ui);
    let key = Id::unique(("fold", id));
    let mut open = ui.data_mut(|d| *d.get_temp_mut_or(key, false));
    let (rect, response) = row_frame(ui, 48.0, first, !open, Sense::click());
    if response.clicked() {
        open = !open;
        ui.data_mut(|d| d.insert_temp(key, open));
    }
    if ui.is_rect_visible(rect) {
        let t = ui.painter().text(
            pos2(rect.left() + 16.0, rect.center().y),
            Align2::LEFT_CENTER,
            title,
            theme::regular(14.0),
            p.text,
        );
        icons::paint(
            ui.painter(),
            Rect::from_min_size(
                pos2(rect.right() - 32.0, rect.center().y - 8.0),
                vec2(16.0, 16.0),
            ),
            if open {
                Icon::ChevronUp
            } else {
                Icon::ChevronDown
            },
            p.text3,
        );
        if !open && !summary.is_empty() {
            text_cut(
                ui,
                pos2(rect.right() - 44.0, rect.center().y),
                Align2::RIGHT_CENTER,
                summary,
                theme::regular(14.0),
                p.text2,
                rect.right() - 44.0 - t.right() - 16.0,
            );
        }
    }
    open
}

// ---------------------------------------------------------------------------------------------
// Chips, pills, badges

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Accent,
    Mute,
}

fn tone_colors(p: &Palette, tone: Tone) -> (Color32, Color32, Color32) {
    // (ink, fill, line)
    match tone {
        Tone::Good => (p.green_text, p.green_soft, p.green_line),
        Tone::Warn => (p.amber_text, p.amber_soft, p.amber_line),
        Tone::Bad => (p.red_text, p.red_soft, p.red_line),
        Tone::Accent => (p.accent, p.accent_soft, p.accent_line),
        Tone::Mute => (p.text2, p.surface3, p.line_strong),
    }
}

/// A 20 point status pill.
pub fn pill(ui: &mut Ui, text: &str, tone: Tone) -> Response {
    let p = pal(ui);
    let (ink, fill, _) = tone_colors(p, tone);
    let font = theme::semibold(12.0);
    let w = text_width(ui, text, font.clone()) + 16.0;
    let (rect, response) = ui.allocate_exact_size(vec2(w, 20.0), Sense::hover());
    if ui.is_rect_visible(rect) {
        ui.painter().rect_filled(rect, CornerRadius::same(10), fill);
        ui.painter()
            .text(rect.center(), Align2::CENTER_CENTER, text, font, ink);
    }
    response
}

/// The 32 point chip in Home's header (the kill switch), with a chevron: it opens Settings.
pub fn chip(ui: &mut Ui, icon: Icon, text: &str, warn: bool) -> Response {
    let p = pal(ui);
    let font = theme::semibold(12.0);
    let w = 12.0 + 16.0 + 8.0 + text_width(ui, text, font.clone()) + 8.0 + 16.0 + 8.0;
    let (rect, response) = ui.allocate_exact_size(vec2(w, 32.0), Sense::click());
    let response = response.on_hover_cursor(CursorIcon::PointingHand);
    if ui.is_rect_visible(rect) {
        let (ink, fill, line, chev) = if warn {
            (p.amber_text, p.amber_soft, p.amber_line, p.amber_text)
        } else {
            (p.text2, p.surface, p.line_strong, p.text3)
        };
        let painter = ui.painter();
        painter.rect(
            rect,
            CornerRadius::same(16),
            fill,
            Stroke::new(1.0, line),
            StrokeKind::Inside,
        );
        if response.hovered() {
            painter.rect_filled(rect, CornerRadius::same(16), p.hover);
        }
        let y = rect.center().y;
        icons::paint(
            painter,
            Rect::from_min_size(pos2(rect.left() + 12.0, y - 8.0), vec2(16.0, 16.0)),
            icon,
            ink,
        );
        painter.text(
            pos2(rect.left() + 36.0, y),
            Align2::LEFT_CENTER,
            text,
            font,
            ink,
        );
        icons::paint(
            painter,
            Rect::from_min_size(pos2(rect.right() - 24.0, y - 8.0), vec2(16.0, 16.0)),
            Icon::ChevronRight,
            chev,
        );
        focus_ring(ui, rect, 16.0, false, &response);
    }
    response
}

pub fn paint_badge(ui: &Ui, rect: Rect, text: &str, large: bool) {
    let p = pal(ui);
    ui.painter()
        .rect_filled(rect, CornerRadius::same(8), p.badge);
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        text,
        theme::semibold(if large { 14.0 } else { 12.0 }),
        p.badge_ink,
    );
}

/// A badge holding an icon instead of letters.
pub fn paint_icon_badge(ui: &Ui, rect: Rect, icon: Icon) {
    let p = pal(ui);
    ui.painter()
        .rect_filled(rect, CornerRadius::same(8), p.badge);
    icons::paint(
        ui.painter(),
        Rect::from_center_size(rect.center(), vec2(20.0, 20.0)),
        icon,
        p.text2,
    );
}

// ---------------------------------------------------------------------------------------------
// List rows

/// What a list row shows on its left.
pub enum Lead<'a> {
    Badge(&'a str),
    BigBadge(&'a str),
    IconBadge(Icon),
    BigIconBadge(Icon),
    Icon(Icon),
}

/// A 56 point list row: lead, a title and a line under it, and trailing controls on the
/// right. `current`: highlighted with the accent bar (the hero's profile). The row itself is
/// clickable; controls added by `trailing` take their own clicks.
#[allow(clippy::too_many_arguments)]
pub fn list_row(
    ui: &mut Ui,
    lead: Lead,
    title: &str,
    sub: &str,
    current: bool,
    first: bool,
    last: bool,
    trailing: impl FnOnce(&mut Ui),
) -> Response {
    let p = pal(ui);
    let (rect, response) = row_frame(ui, 56.0, first, last, Sense::click());
    if ui.is_rect_visible(rect) {
        if current {
            ui.painter().rect_filled(
                rect.shrink2(vec2(0.0, 0.5)),
                row_corners(first, last),
                p.surface2,
            );
            let bar = Rect::from_min_size(
                pos2(rect.left(), rect.top() + 12.0),
                vec2(3.0, rect.height() - 24.0),
            );
            ui.painter().rect_filled(
                bar,
                CornerRadius {
                    nw: 0,
                    sw: 0,
                    ne: 2,
                    se: 2,
                },
                p.accent,
            );
            if !first {
                ui.painter()
                    .hline(rect.x_range(), rect.top() + 0.5, Stroke::new(1.0, p.line));
            }
        }
        let mut x = rect.left() + 16.0;
        let cy = rect.center().y;
        match lead {
            Lead::Badge(t) | Lead::BigBadge(t) => {
                let side = if matches!(lead, Lead::BigBadge(_)) {
                    40.0
                } else {
                    32.0
                };
                paint_badge(
                    ui,
                    Rect::from_min_size(pos2(x, cy - side / 2.0), vec2(side, side)),
                    t,
                    side > 32.0,
                );
                x += side + 12.0;
            }
            Lead::IconBadge(icon) | Lead::BigIconBadge(icon) => {
                let side = if matches!(lead, Lead::BigIconBadge(_)) {
                    40.0
                } else {
                    32.0
                };
                paint_icon_badge(
                    ui,
                    Rect::from_min_size(pos2(x, cy - side / 2.0), vec2(side, side)),
                    icon,
                );
                x += side + 12.0;
            }
            Lead::Icon(icon) => {
                icons::paint(
                    ui.painter(),
                    Rect::from_min_size(pos2(x, cy - 10.0), vec2(20.0, 20.0)),
                    icon,
                    p.text2,
                );
                x += 32.0;
            }
        }
        // Trailing controls, right-aligned, in their own space.
        let trail_area = Rect::from_min_max(
            pos2(x, rect.top()),
            pos2(rect.right() - 12.0, rect.bottom()),
        );
        let trail = place(
            ui,
            egui::UiBuilder::new()
                .max_rect(trail_area)
                .layout(egui::Layout::right_to_left(egui::Align::Center)),
            |ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                trailing(ui);
                ui.min_rect()
            },
        )
        .inner;
        let text_right = if trail.width() > 1.0 {
            trail.left() - 8.0
        } else {
            rect.right() - 16.0
        };
        let width = (text_right - x).max(20.0);
        let title_ink = if ui.is_enabled() { p.text } else { p.text2 };
        if sub.is_empty() {
            text_cut(
                ui,
                pos2(x, cy),
                Align2::LEFT_CENTER,
                title,
                theme::semibold(14.0),
                title_ink,
                width,
            );
        } else {
            text_cut(
                ui,
                pos2(x, cy - 9.0),
                Align2::LEFT_CENTER,
                title,
                theme::semibold(14.0),
                title_ink,
                width,
            );
            text_cut(
                ui,
                pos2(x, cy + 10.0),
                Align2::LEFT_CENTER,
                sub,
                theme::regular(12.0),
                p.text3,
                width,
            );
        }
    }
    response
}

// ---------------------------------------------------------------------------------------------
// Choices

/// A row of options of which one is chosen (40 point track, 32 point segments). True when the
/// choice changed.
pub fn segmented<T: PartialEq + Copy>(ui: &mut Ui, value: &mut T, options: &[(T, &str)]) -> bool {
    let p = pal(ui);
    let mut changed = false;
    let (track, _) = ui.allocate_exact_size(vec2(ui.available_width(), 40.0), Sense::hover());
    let painter = ui.painter().clone();
    painter.rect(
        track,
        CornerRadius::same(8),
        p.surface2,
        Stroke::new(1.0, p.line_strong),
        StrokeKind::Inside,
    );
    let inner = track.shrink(4.0);
    let count = options.len().max(1) as f32;
    let gap = 2.0;
    let w = (inner.width() - gap * (count - 1.0)) / count;
    for (i, (option, label)) in options.iter().enumerate() {
        let rect = Rect::from_min_size(
            pos2(inner.left() + i as f32 * (w + gap), inner.top()),
            vec2(w, 32.0),
        );
        let id = ui.scope_id().with(("segment", i, *label));
        let response = ui
            .interact(rect, id, Sense::click())
            .on_hover_cursor(CursorIcon::PointingHand);
        let selected = *value == *option;
        if selected {
            painter.add(
                Shadow {
                    offset: [0, 1],
                    blur: 3,
                    spread: 0,
                    color: Color32::from_black_alpha(50),
                }
                .as_shape(rect, CornerRadius::same(4)),
            );
            painter.rect(
                rect,
                CornerRadius::same(4),
                p.thumb,
                Stroke::new(1.0, p.accent),
                StrokeKind::Inside,
            );
        } else if response.hovered() {
            painter.rect_filled(rect, CornerRadius::same(4), p.hover);
        }
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            *label,
            if selected {
                theme::semibold(14.0)
            } else {
                theme::regular(14.0)
            },
            if selected { p.text } else { p.text2 },
        );
        if response.has_focus() {
            painter.rect_stroke(
                rect.shrink(1.0),
                CornerRadius::same(3),
                Stroke::new(2.0, p.accent),
                StrokeKind::Middle,
            );
        }
        if response.clicked() && !selected {
            *value = *option;
            changed = true;
        }
    }
    changed
}

/// Paints a Fluent switch (40 × 20) in `rect`; `t`: 0 off … 1 on.
fn paint_switch(ui: &Ui, rect: Rect, t: f32, enabled: bool) {
    let p = pal(ui);
    let painter = ui.painter();
    let alpha = if enabled { 1.0 } else { 0.45 };
    if t > 0.5 {
        painter.rect_filled(rect, CornerRadius::same(10), p.accent.gamma_multiply(alpha));
        let x = egui::lerp((rect.left() + 10.0)..=(rect.right() - 10.0), t);
        painter.circle_filled(
            pos2(x, rect.center().y),
            7.0,
            p.accent_ink.gamma_multiply(alpha),
        );
    } else {
        painter.rect_stroke(
            rect,
            CornerRadius::same(10),
            Stroke::new(1.5, p.control_line.gamma_multiply(alpha)),
            StrokeKind::Inside,
        );
        let x = egui::lerp((rect.left() + 9.0)..=(rect.right() - 10.0), t);
        painter.circle_filled(pos2(x, rect.center().y), 6.0, p.text2.gamma_multiply(alpha));
    }
}

/// Lays out a two-line text block (title and optional line) from `x` to `right`, centred on
/// `cy`; returns its height.
#[allow(clippy::too_many_arguments)]
fn two_lines(
    ui: &Ui,
    x: f32,
    top: f32,
    right: f32,
    title: &str,
    desc: Option<&str>,
    title_ink: Color32,
    strong: bool,
) -> f32 {
    let p = pal(ui);
    let width = (right - x).max(40.0);
    let font = if strong {
        theme::semibold(14.0)
    } else {
        theme::regular(14.0)
    };
    let t = ui
        .painter()
        .layout(title.to_string(), font, title_ink, width);
    let th = t.size().y;
    ui.painter().galley(pos2(x, top), t, title_ink);
    let mut h = th;
    if let Some(desc) = desc {
        let d = ui
            .painter()
            .layout(desc.to_string(), theme::regular(12.0), p.text3, width);
        let dh = d.size().y;
        ui.painter().galley(pos2(x, top + th + 2.0), d, p.text3);
        h += 2.0 + dh;
    }
    h
}

fn measure_two_lines(ui: &Ui, width: f32, title: &str, desc: Option<&str>, strong: bool) -> f32 {
    let font = if strong {
        theme::semibold(14.0)
    } else {
        theme::regular(14.0)
    };
    let mut h = ui
        .painter()
        .layout(title.to_string(), font, Color32::WHITE, width.max(40.0))
        .size()
        .y;
    if let Some(desc) = desc {
        h += 2.0
            + ui.painter()
                .layout(
                    desc.to_string(),
                    theme::regular(12.0),
                    Color32::WHITE,
                    width.max(40.0),
                )
                .size()
                .y;
    }
    h
}

/// A settings row whose whole area flips a switch on the right. True when it was flipped.
pub fn toggle_row(
    ui: &mut Ui,
    title: &str,
    desc: Option<&str>,
    enabled: bool,
    on: &mut bool,
    first: bool,
    last: bool,
) -> bool {
    let p = pal(ui);
    let width = ui.available_width();
    let text_w = width - 16.0 - 16.0 - 40.0 - 12.0;
    let h = (measure_two_lines(ui, text_w, title, desc, false) + 16.0).max(if desc.is_some() {
        56.0
    } else {
        48.0
    });
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, response) = row_frame(ui, h, first, last, sense);
    let mut changed = false;
    if enabled && response.clicked() {
        *on = !*on;
        changed = true;
    }
    let t = ui.ctx().animate_bool_with_time(response.id, *on, 0.16);
    if ui.is_rect_visible(rect) {
        let th = measure_two_lines(ui, text_w, title, desc, false);
        two_lines(
            ui,
            rect.left() + 16.0,
            rect.center().y - th / 2.0,
            rect.left() + 16.0 + text_w,
            title,
            desc,
            if enabled { p.text } else { p.text_disabled },
            false,
        );
        paint_switch(
            ui,
            Rect::from_min_size(
                pos2(rect.right() - 56.0, rect.center().y - 10.0),
                vec2(40.0, 20.0),
            ),
            t,
            enabled,
        );
    }
    changed
}

/// A settings row with a title (and a line under it) and controls on the right.
pub fn setting_row(
    ui: &mut Ui,
    title: &str,
    desc: Option<&str>,
    first: bool,
    trailing: impl FnOnce(&mut Ui),
) {
    let p = pal(ui);
    let width = ui.available_width();
    // Leave room for up to a small button on the right.
    let text_w = width - 16.0 - 16.0 - 96.0;
    let h = (measure_two_lines(ui, text_w, title, desc, false) + 16.0).max(if desc.is_some() {
        56.0
    } else {
        48.0
    });
    let (rect, _) = row_frame(ui, h, first, false, Sense::hover());
    if ui.is_rect_visible(rect) {
        let th = measure_two_lines(ui, text_w, title, desc, false);
        two_lines(
            ui,
            rect.left() + 16.0,
            rect.center().y - th / 2.0,
            rect.left() + 16.0 + text_w,
            title,
            desc,
            p.text,
            false,
        );
    }
    place(
        ui,
        egui::UiBuilder::new()
            .max_rect(Rect::from_min_max(
                pos2(rect.right() - 16.0 - 160.0, rect.top()),
                pos2(rect.right() - 16.0, rect.bottom()),
            ))
            .layout(egui::Layout::right_to_left(egui::Align::Center)),
        trailing,
    );
}

/// A row that opens something: title (and line), and a chevron or an external-link icon.
pub fn link_row(
    ui: &mut Ui,
    title: &str,
    desc: Option<&str>,
    icon: Icon,
    first: bool,
    last: bool,
) -> Response {
    let p = pal(ui);
    let width = ui.available_width();
    let text_w = width - 16.0 - 16.0 - 28.0;
    let h = (measure_two_lines(ui, text_w, title, desc, false) + 16.0).max(if desc.is_some() {
        56.0
    } else {
        48.0
    });
    let (rect, response) = row_frame(ui, h, first, last, Sense::click());
    if ui.is_rect_visible(rect) {
        let th = measure_two_lines(ui, text_w, title, desc, false);
        two_lines(
            ui,
            rect.left() + 16.0,
            rect.center().y - th / 2.0,
            rect.left() + 16.0 + text_w,
            title,
            desc,
            p.text,
            false,
        );
        icons::paint(
            ui.painter(),
            Rect::from_min_size(
                pos2(rect.right() - 32.0, rect.center().y - 8.0),
                vec2(16.0, 16.0),
            ),
            icon,
            p.text3,
        );
    }
    response
}

/// A radio option row (the whole row is the target). `desc`: the line under the title.
#[allow(clippy::too_many_arguments)]
pub fn radio_row(
    ui: &mut Ui,
    selected: bool,
    title: &str,
    tag: Option<&str>,
    desc: Option<&str>,
    enabled: bool,
    divider: bool,
    strong: bool,
) -> Response {
    let p = pal(ui);
    let width = ui.available_width();
    let text_w = width - 16.0 - 20.0 - 12.0 - 16.0;
    let h = measure_two_lines(ui, text_w, title, desc, strong) + 24.0;
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(vec2(width, h), sense);
    if ui.is_rect_visible(rect) {
        if enabled && response.hovered() {
            ui.painter().rect_filled(rect, CornerRadius::ZERO, p.hover);
        }
        if divider {
            ui.painter()
                .hline(rect.x_range(), rect.top() + 0.5, Stroke::new(1.0, p.line));
        }
        let c = pos2(rect.left() + 26.0, rect.top() + 12.0 + 10.0);
        let alpha = if enabled { 1.0 } else { 0.4 };
        if selected {
            ui.painter()
                .circle_stroke(c, 9.25, Stroke::new(1.5, p.accent.gamma_multiply(alpha)));
            ui.painter()
                .circle_filled(c, 4.5, p.accent.gamma_multiply(alpha));
        } else {
            ui.painter().circle_stroke(
                c,
                9.25,
                Stroke::new(1.5, p.control_line.gamma_multiply(alpha)),
            );
        }
        let x = rect.left() + 48.0;
        let ink = if enabled { p.text } else { p.text_disabled };
        two_lines(
            ui,
            x,
            rect.top() + 12.0,
            x + text_w,
            title,
            desc,
            ink,
            strong,
        );
        if let Some(tag) = tag {
            let font = if strong {
                theme::semibold(14.0)
            } else {
                theme::regular(14.0)
            };
            let tw = text_width(ui, title, font);
            let font12 = theme::semibold(12.0);
            let pw = text_width(ui, tag, font12.clone()) + 16.0;
            let r = Rect::from_min_size(pos2(x + tw + 8.0, rect.top() + 12.0), vec2(pw, 20.0));
            ui.painter()
                .rect_filled(r, CornerRadius::same(10), p.surface3);
            ui.painter()
                .text(r.center(), Align2::CENTER_CENTER, tag, font12, p.text2);
        }
        if enabled && response.has_focus() {
            ui.painter().rect_stroke(
                rect.shrink(1.0),
                CornerRadius::ZERO,
                Stroke::new(2.0, p.accent),
                StrokeKind::Middle,
            );
        }
    }
    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    }
}

/// A checkbox option row.
pub fn check_row(
    ui: &mut Ui,
    checked: bool,
    title: &str,
    desc: Option<&str>,
    divider: bool,
) -> Response {
    let p = pal(ui);
    let width = ui.available_width();
    let text_w = width - 16.0 - 20.0 - 12.0 - 16.0;
    let h = measure_two_lines(ui, text_w, title, desc, true) + 24.0;
    let (rect, response) = ui.allocate_exact_size(vec2(width, h), Sense::click());
    if ui.is_rect_visible(rect) {
        if response.hovered() {
            ui.painter().rect_filled(rect, CornerRadius::ZERO, p.hover);
        }
        if divider {
            ui.painter()
                .hline(rect.x_range(), rect.top() + 0.5, Stroke::new(1.0, p.line));
        }
        let b = Rect::from_min_size(
            pos2(rect.left() + 16.0, rect.top() + 12.0),
            vec2(20.0, 20.0),
        );
        if checked {
            ui.painter().rect_filled(b, CornerRadius::same(4), p.accent);
            icons::paint(ui.painter(), b.shrink(2.0), Icon::Check, p.accent_ink);
        } else {
            ui.painter().rect_stroke(
                b,
                CornerRadius::same(4),
                Stroke::new(1.5, p.control_line),
                StrokeKind::Inside,
            );
        }
        let x = rect.left() + 48.0;
        two_lines(
            ui,
            x,
            rect.top() + 12.0,
            x + text_w,
            title,
            desc,
            p.text,
            true,
        );
        if response.has_focus() {
            ui.painter().rect_stroke(
                rect.shrink(1.0),
                CornerRadius::ZERO,
                Stroke::new(2.0, p.accent),
                StrokeKind::Middle,
            );
        }
    }
    response.on_hover_cursor(CursorIcon::PointingHand)
}

// ---------------------------------------------------------------------------------------------
// Messages

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Banner {
    Info,
    Warn,
    Bad,
}

/// A banner: an icon, a title, a line, and actions added by `actions` (may add nothing).
pub fn banner(
    ui: &mut Ui,
    kind: Banner,
    icon: Icon,
    title: &str,
    body: &str,
    actions: impl FnOnce(&mut Ui),
) {
    let p = pal(ui);
    let (ink, fill, line) = match kind {
        Banner::Info => (p.accent, p.accent_soft, p.accent_line),
        Banner::Warn => (p.amber_text, p.amber_soft, p.amber_line),
        Banner::Bad => (p.red_text, p.red_soft, p.red_line),
    };
    Frame::NONE
        .fill(fill)
        .stroke(Stroke::new(1.0, line))
        .corner_radius(12)
        .inner_margin(Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 12.0;
                let (r, _) = ui.allocate_exact_size(vec2(20.0, 20.0), Sense::hover());
                icons::paint(ui.painter(), r, icon, ink);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(title)
                                .font(theme::semibold(14.0))
                                .color(p.text),
                        )
                        .wrap()
                        .selectable(false),
                    );
                    if !body.is_empty() {
                        ui.add(
                            egui::Label::new(egui::RichText::new(body).size(12.0).color(p.text2))
                                .wrap(),
                        );
                    }
                    // The actions, laid out apart first: an empty band takes no space.
                    let top = ui.cursor().top() + 10.0;
                    let area = Rect::from_min_max(
                        pos2(ui.cursor().left(), top),
                        pos2(ui.max_rect().right(), top + 400.0),
                    );
                    let used = place(
                        ui,
                        egui::UiBuilder::new().max_rect(area).layout(
                            egui::Layout::left_to_right(egui::Align::Center).with_main_wrap(true),
                        ),
                        |ui| {
                            ui.spacing_mut().item_spacing = vec2(8.0, 8.0);
                            actions(ui);
                            ui.min_rect()
                        },
                    )
                    .inner;
                    if used.height() > 1.0 {
                        ui.allocate_space(vec2(
                            ui.available_width(),
                            used.bottom() - ui.cursor().top(),
                        ));
                    }
                });
            });
        });
}

// ---------------------------------------------------------------------------------------------
// Headers

/// A page's header: back button, title and an optional line under it, controls on the right.
/// True when back was pressed.
pub fn page_header(ui: &mut Ui, title: &str, sub: &str, right: impl FnOnce(&mut Ui)) -> bool {
    let p = pal(ui);
    let mut back = false;
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 52.0), Sense::hover());
    place(
        ui,
        egui::UiBuilder::new()
            .max_rect(Rect::from_min_max(
                pos2(rect.left() + 8.0, rect.top()),
                pos2(rect.right() - 12.0, rect.bottom()),
            ))
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
        |ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            back = icon_button(ui, Icon::Back, "Back (Esc)", 36.0, None).clicked();
            let left = ui.cursor().left();
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                right(ui);
                let space = ui.available_rect_before_wrap();
                let width = (space.right() - left - 8.0).max(40.0);
                if sub.is_empty() {
                    text_cut(
                        ui,
                        pos2(left, rect.center().y),
                        Align2::LEFT_CENTER,
                        title,
                        theme::semibold(18.0),
                        p.text,
                        width,
                    );
                } else {
                    text_cut(
                        ui,
                        pos2(left, rect.center().y - 9.0),
                        Align2::LEFT_CENTER,
                        title,
                        theme::semibold(18.0),
                        p.text,
                        width,
                    );
                    text_cut(
                        ui,
                        pos2(left, rect.center().y + 12.0),
                        Align2::LEFT_CENTER,
                        sub,
                        theme::regular(12.0),
                        p.text3,
                        width,
                    );
                }
            });
        },
    );
    back
}

// ---------------------------------------------------------------------------------------------
// Fields

/// A labelled one-line text field (36 points) as wide as the space, with optional help text
/// or an error under it. `secret`: dots, with an eye button to show it.
pub struct Field<'a> {
    pub label: &'a str,
    pub hint: &'a str,
    pub help: Option<&'a str>,
    pub error: Option<&'a str>,
    pub secret: bool,
    pub mono: bool,
}

impl<'a> Field<'a> {
    pub fn new(label: &'a str) -> Self {
        Self {
            label,
            hint: "",
            help: None,
            error: None,
            secret: false,
            mono: false,
        }
    }

    pub fn hint(mut self, hint: &'a str) -> Self {
        self.hint = hint;
        self
    }

    pub fn help(mut self, help: &'a str) -> Self {
        self.help = Some(help);
        self
    }

    pub fn error(mut self, error: Option<&'a str>) -> Self {
        self.error = error;
        self
    }

    pub fn secret(mut self) -> Self {
        self.secret = true;
        self
    }

    pub fn show(self, ui: &mut Ui, value: &mut String) -> Response {
        let p = pal(ui);
        let width = ui.available_width();
        if !self.label.is_empty() {
            let (r, _) = ui.allocate_exact_size(vec2(width, 16.0), Sense::hover());
            ui.painter().text(
                r.left_center(),
                Align2::LEFT_CENTER,
                self.label,
                theme::semibold(12.0),
                p.text2,
            );
            ui.add_space(4.0);
        }
        let (rect, _) = ui.allocate_exact_size(vec2(width, 36.0), Sense::hover());
        let bg = ui.painter().add(Shape::Noop);
        let shown_key = Id::unique(("field-shown", self.label, ui.scope_id()));
        let mut shown = ui.data_mut(|d| *d.get_temp_mut_or(shown_key, false));
        let eye_w = if self.secret { 32.0 } else { 0.0 };
        let edit_rect = Rect::from_min_max(
            pos2(rect.left() + 12.0, rect.top() + 1.0),
            pos2(rect.right() - 8.0 - eye_w, rect.bottom() - 1.0),
        );
        let font = if self.mono {
            theme::mono(14.0)
        } else {
            theme::regular(14.0)
        };
        let response = place(ui, egui::UiBuilder::new().max_rect(edit_rect), |ui| {
            ui.add_sized(
                edit_rect.size(),
                TextEdit::singleline(value)
                    .frame(Frame::NONE)
                    .hint_text(egui::RichText::new(self.hint).color(p.text3))
                    .password(self.secret && !shown)
                    .font(font)
                    .text_color(p.text)
                    .align(Align2::LEFT_CENTER)
                    .margin(Margin::ZERO)
                    .desired_width(edit_rect.width()),
            )
        })
        .inner;
        if self.secret {
            let eye = Rect::from_min_size(
                pos2(rect.right() - 36.0, rect.top() + 2.0),
                vec2(32.0, 32.0),
            );
            let eye_response = ui.interact(eye, shown_key.with("eye"), Sense::click());
            if eye_response.hovered() {
                ui.painter()
                    .rect_filled(eye, CornerRadius::same(6), p.hover);
            }
            icons::paint(
                ui.painter(),
                Rect::from_center_size(eye.center(), vec2(16.0, 16.0)),
                Icon::Eye,
                if shown { p.accent } else { p.text2 },
            );
            if eye_response
                .on_hover_text(if shown { "Hide" } else { "Show" })
                .clicked()
            {
                shown = !shown;
                ui.data_mut(|d| d.insert_temp(shown_key, shown));
            }
        }
        let focused = response.has_focus();
        let bottom = if self.error.is_some() {
            Stroke::new(2.0, p.red)
        } else if focused {
            Stroke::new(2.0, p.accent)
        } else {
            Stroke::new(1.0, p.control_line)
        };
        let mut shapes = vec![Shape::rect_filled(rect, CornerRadius::same(8), p.surface2)];
        shapes.push(Shape::Rect(egui::epaint::RectShape::stroke(
            rect,
            CornerRadius::same(8),
            Stroke::new(1.0, p.line_strong),
            StrokeKind::Inside,
        )));
        ui.painter().set(bg, Shape::Vec(shapes));
        // The stronger bottom edge (Fluent): the border's lower part, round corners included.
        ui.painter()
            .with_clip_rect(Rect::from_min_max(
                pos2(rect.left(), rect.bottom() - 4.0),
                pos2(rect.right(), rect.bottom() + 1.0),
            ))
            .rect_stroke(rect, CornerRadius::same(8), bottom, StrokeKind::Inside);
        if let Some(error) = self.error {
            ui.add_space(4.0);
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                let (r, _) = ui.allocate_exact_size(vec2(16.0, 16.0), Sense::hover());
                icons::paint(ui.painter(), r, Icon::Error, p.red_text);
                ui.add(
                    egui::Label::new(egui::RichText::new(error).size(12.0).color(p.red_text))
                        .wrap(),
                );
            });
        } else if let Some(help) = self.help {
            ui.add_space(4.0);
            ui.add(egui::Label::new(egui::RichText::new(help).size(12.0).color(p.text3)).wrap());
        }
        response
    }
}

// ---------------------------------------------------------------------------------------------
// Home pieces

/// The live strip: received, sent and time, and a chevron that opens the details. The whole
/// row is the target.
pub fn stats_row(ui: &mut Ui, received: &str, sent: &str, time: &str, open: bool) -> Response {
    let p = pal(ui);
    let (rect, response) = row_frame(ui, 64.0, true, false, Sense::click());
    if ui.is_rect_visible(rect) {
        let inner = Rect::from_min_max(
            pos2(rect.left() + 32.0, rect.top()),
            pos2(rect.right() - 32.0, rect.bottom()),
        );
        let w = inner.width() / 3.0;
        for (i, (icon, value, label)) in [
            (Some(Icon::ArrowDown), received, "Received"),
            (Some(Icon::ArrowUp), sent, "Sent"),
            (None, time, "Time"),
        ]
        .into_iter()
        .enumerate()
        {
            let cx = inner.left() + w * (i as f32 + 0.5);
            let font = theme::semibold(18.0);
            let vw = text_width(ui, value, font.clone()) + if icon.is_some() { 20.0 } else { 0.0 };
            let mut x = cx - vw / 2.0;
            let vy = rect.top() + 12.0 + 12.0;
            if let Some(icon) = icon {
                icons::paint(
                    ui.painter(),
                    Rect::from_min_size(pos2(x, vy - 8.0), vec2(16.0, 16.0)),
                    icon,
                    p.text3,
                );
                x += 20.0;
            }
            ui.painter()
                .text(pos2(x, vy), Align2::LEFT_CENTER, value, font, p.text);
            ui.painter().text(
                pos2(cx, rect.top() + 12.0 + 24.0 + 8.0),
                Align2::CENTER_CENTER,
                label,
                theme::regular(12.0),
                p.text3,
            );
        }
        icons::paint(
            ui.painter(),
            Rect::from_min_size(
                pos2(rect.right() - 28.0, rect.center().y - 8.0),
                vec2(16.0, 16.0),
            ),
            if open {
                Icon::ChevronUp
            } else {
                Icon::ChevronDown
            },
            p.text3,
        );
    }
    response.on_hover_text(if open {
        "Hide the details"
    } else {
        "Show the details"
    })
}

// ---------------------------------------------------------------------------------------------
// The connect button

/// The hero button's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mood {
    /// Not connected: the filled call to action.
    Cta,
    /// Connecting or waiting: accent arc spinning.
    Busy,
    /// Connected: green ring, the light on, a glow.
    Good,
    /// Connected with limits: amber ring, amber light.
    Warn,
    /// Reconnecting: amber arc spinning.
    WarnSpin,
    /// Failed: red ring, light off.
    Bad,
    /// Internet blocked: amber ring, light off.
    Blocked,
    /// The service is not running: nothing to press.
    Off,
}

/// A dithered white radial falloff, tinted when drawn (no banding on true black).
fn glow_texture(ctx: &egui::Context) -> TextureHandle {
    let id = Id::unique("polytunnel-glow-texture");
    if let Some(t) = ctx.data(|d| d.get_temp::<TextureHandle>(id)) {
        return t;
    }
    let n = 128usize;
    let mut pixels = Vec::with_capacity(n * n);
    let mut seed: u32 = 0x9E37_79B9;
    for y in 0..n {
        for x in 0..n {
            let dx = (x as f32 + 0.5) / n as f32 * 2.0 - 1.0;
            let dy = (y as f32 + 0.5) / n as f32 * 2.0 - 1.0;
            let d = (dx * dx + dy * dy).sqrt().min(1.0);
            let a = (1.0 - d).powf(1.4) * 255.0;
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let noise = (seed % 1000) as f32 / 1000.0 - 0.5;
            let a = (a + noise).clamp(0.0, 255.0) as u8;
            pixels.push(Color32::from_rgba_premultiplied(a, a, a, a));
        }
    }
    let image = ColorImage::new([n, n], pixels);
    let texture = ctx.load_texture("polytunnel-glow", image, TextureOptions::LINEAR);
    ctx.data_mut(|d| d.insert_temp(id, texture.clone()));
    texture
}

/// A disc filled with a vertical gradient from `top` to `bottom`.
fn gradient_disc(center: Pos2, radius: f32, top: Color32, bottom: Color32) -> Shape {
    let mut mesh = Mesh::default();
    let steps = 72;
    mesh.colored_vertex(center, theme::mix(top, bottom, 0.5));
    for i in 0..=steps {
        let a = i as f32 / steps as f32 * TAU;
        let q = center + Vec2::angled(a) * radius;
        let t = (q.y - (center.y - radius)) / (2.0 * radius);
        mesh.colored_vertex(q, theme::mix(top, bottom, t));
    }
    for i in 0..steps {
        mesh.add_triangle(0, i as u32 + 1, i as u32 + 2);
    }
    Shape::mesh(mesh)
}

/// The arch with its light: the hero's glyph (the logo's mark), 28 points.
fn paint_arch(
    painter: &egui::Painter,
    rect: Rect,
    stroke: Color32,
    light: Option<Color32>,
    light_on: f32,
) {
    let s = rect.width() / 28.0;
    let at = |x: f32, y: f32| rect.min + vec2(x * s, y * s);
    let w = 3.5 * s;
    let mut points = vec![at(6.75, 26.0), at(6.75, 12.5)];
    points.extend(icons::arc(at(14.0, 12.5), 7.25 * s, PI, PI, 24));
    points.push(at(21.25, 26.0));
    painter.add(Shape::line(points, Stroke::new(w, stroke)));
    if let Some(light) = light {
        let c = at(14.0, 19.5);
        painter.circle_filled(c, 5.5 * s * light_on, light.gamma_multiply(0.25 * light_on));
        painter.circle_filled(c, 2.9 * s * light_on.max(0.001), light);
    }
}

/// The big connect button (120 points): ring, disc, the arch glyph and the action label.
/// `light_on`: 0 … 1, animates the light turning on.
pub fn hero_button(ui: &mut Ui, mood: Mood, label: &str, light_on: f32) -> Response {
    let p = pal(ui);
    let size = 120.0;
    let sense = if mood == Mood::Off {
        Sense::hover()
    } else {
        Sense::click()
    };
    let (rect, response) = ui.allocate_exact_size(vec2(size, size), sense);
    let response = if mood == Mood::Off {
        response
    } else {
        response.on_hover_cursor(CursorIcon::PointingHand)
    };
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let painter = ui.painter();
    let c = rect.center();
    let hovered = response.hovered() && mood != Mood::Off;
    let pressed = response.is_pointer_button_down_on() && mood != Mood::Off;
    let disc_r = 50.0 * if pressed { 0.97 } else { 1.0 };
    let ring_r = 56.5;

    // Glow (dark) or a tinted shadow (light) behind a connected button.
    if mood == Mood::Good {
        if p.dark {
            let glow = glow_texture(ui.ctx());
            painter.image(
                glow.id(),
                Rect::from_center_size(c, vec2(232.0, 232.0)),
                Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
                p.glow_green,
            );
        } else {
            painter.add(
                Shadow {
                    offset: [0, 8],
                    blur: 24,
                    spread: 0,
                    color: p.glow_green,
                }
                .as_shape(
                    Rect::from_center_size(c, vec2(100.0, 100.0)),
                    CornerRadius::same(50),
                ),
            );
        }
    }

    let spinning = matches!(mood, Mood::Busy | Mood::WarnSpin);
    let (ring, arc) = match mood {
        Mood::Cta => (None, None),
        Mood::Busy => (Some(p.accent_soft), Some(p.accent)),
        Mood::Good => (Some(p.green), None),
        Mood::Warn | Mood::Blocked => (Some(p.amber), None),
        Mood::WarnSpin => (Some(p.amber_soft), Some(p.amber)),
        Mood::Bad => (Some(p.red), None),
        Mood::Off => (Some(p.line_strong), None),
    };
    if let Some(ring) = ring {
        painter.circle_stroke(c, ring_r, Stroke::new(3.0, ring));
    }
    if let Some(arc_color) = arc {
        let t = ui.input(|i| i.time) as f32;
        let start = (t / 1.1).fract() * TAU - 70f32.to_radians();
        let points = icons::arc(c, ring_r, start, TAU * 0.26, 40);
        for end in [points.first(), points.last()].into_iter().flatten() {
            painter.circle_filled(*end, 1.5, arc_color);
        }
        painter.add(Shape::line(points, Stroke::new(3.0, arc_color)));
    }
    if spinning {
        ui.ctx().request_repaint();
    }

    let disc_rect = Rect::from_center_size(c, vec2(disc_r * 2.0, disc_r * 2.0));
    let (glyph, light, label_ink) = if mood == Mood::Cta {
        painter.add(
            Shadow {
                offset: [0, 8],
                blur: 24,
                spread: 0,
                color: p.accent_shadow,
            }
            .as_shape(disc_rect, CornerRadius::same(50)),
        );
        let (top, bottom) = if pressed {
            (p.accent, theme::mix(p.accent, Color32::BLACK, 0.08))
        } else if hovered {
            (theme::mix(p.accent_hi, Color32::WHITE, 0.08), p.accent_hi)
        } else {
            (p.accent_hi, p.accent)
        };
        painter.add(gradient_disc(c, disc_r, top, bottom));
        // The inner highlight: a thin arc along the top that fades out to the sides.
        for i in 0..24 {
            let f = i as f32 / 24.0;
            let a0 = -PI / 2.0 - PI / 3.0 + f * (2.0 * PI / 3.0);
            let a1 = a0 + (2.0 * PI / 3.0) / 24.0;
            let alpha = (1.0 - (f * 2.0 - 1.0).abs()) * 0.16;
            painter.line_segment(
                [
                    c + Vec2::angled(a0) * (disc_r - 0.75),
                    c + Vec2::angled(a1) * (disc_r - 0.75),
                ],
                Stroke::new(1.0, Color32::WHITE.gamma_multiply(alpha)),
            );
        }
        (p.accent_ink, Some(p.accent_ink), p.accent_ink)
    } else {
        if let Some(shadow) = p.disc_shadow.filter(|_| mood != Mood::Good) {
            painter.add(shadow.as_shape(disc_rect, CornerRadius::same(50)));
        }
        painter.circle_filled(c, disc_r, p.disc);
        if hovered || pressed {
            painter.circle_filled(c, disc_r, if pressed { p.pressed } else { p.hover });
        }
        match mood {
            Mood::Busy => (p.text2, Some(p.accent), p.text),
            Mood::Good => (p.text, Some(p.green), p.text),
            Mood::Warn => (p.text, Some(p.amber), p.text),
            Mood::WarnSpin => (p.text2, Some(p.amber), p.text),
            Mood::Bad | Mood::Blocked => (p.text2, None, p.text),
            Mood::Off => (p.text_disabled, None, p.text_disabled),
            Mood::Cta => unreachable!(),
        }
    };
    paint_arch(
        painter,
        Rect::from_center_size(c - vec2(0.0, 12.0), vec2(28.0, 28.0)),
        glyph,
        light,
        light_on,
    );
    painter.text(
        c + vec2(0.0, 18.0),
        Align2::CENTER_CENTER,
        label,
        theme::semibold(14.0),
        label_ink,
    );
    if response.has_focus() {
        // Always outside the status ring: a 2 point gap, then 2 points (radius 60–62).
        painter.circle_stroke(c, 61.0, Stroke::new(2.0, p.accent));
    }
    response
}

/// The app icon (256 px) as a texture, for the welcome page.
pub fn logo_texture(ctx: &egui::Context) -> TextureHandle {
    let id = Id::unique("polytunnel-logo-texture");
    if let Some(t) = ctx.data(|d| d.get_temp::<TextureHandle>(id)) {
        return t;
    }
    let rgba = include_bytes!(concat!(env!("OUT_DIR"), "/icon256.rgba"));
    let image = ColorImage::from_rgba_unmultiplied([256, 256], rgba);
    let texture = ctx.load_texture("polytunnel-logo", image, TextureOptions::LINEAR);
    ctx.data_mut(|d| d.insert_temp(id, texture.clone()));
    texture
}
