//! The window's building blocks: cards, the connect button, segmented controls, switches,
//! pills, icon buttons, the bottom navigation bar, folds and banners. All take their colours
//! from the current palette.

use std::f32::consts::TAU;

use eframe::egui::{
    self, Align, Color32, CornerRadius, CursorIcon, Frame, Layout, Margin, Rect, Response,
    RichText, Sense, Shape, Stroke, StrokeKind, Ui, pos2, vec2,
};

use super::icons::{self, Icon};
use super::theme::{self, Palette};

/// The palette for `ui`'s theme.
pub fn pal(ui: &Ui) -> &'static Palette {
    theme::palette(ui.ctx())
}

/// A rounded card on the surface colour, as wide as the space it is in.
pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    let p = pal(ui);
    Frame::NONE
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(12)
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A small upper-case heading above a group of cards.
pub fn section(ui: &mut Ui, text: &str) {
    let p = pal(ui);
    ui.add_space(2.0);
    ui.label(
        RichText::new(text.to_uppercase())
            .small()
            .strong()
            .color(p.muted),
    );
}

/// A thin line between rows inside a card.
pub fn divider(ui: &mut Ui) {
    let p = pal(ui);
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, 0, p.border);
}

/// How the connect button looks in one state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RingLook {
    pub ring: Color32,
    /// The moving part of the ring while something is under way.
    pub arc: Color32,
    pub core: Color32,
    pub ink: Color32,
}

/// The large round connect button. `spinning`: an arc runs round the ring.
pub fn connect_button(ui: &mut Ui, look: RingLook, spinning: bool, label: &str) -> Response {
    let size = 128.0;
    let (rect, response) = ui.allocate_exact_size(vec2(size, size), Sense::click());
    let response = response
        .on_hover_cursor(CursorIcon::PointingHand)
        .on_hover_text(label);
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let center = rect.center();
        let hover = ui.ctx().animate_bool(response.id, response.hovered());
        let pressed = response.is_pointer_button_down_on();
        let ring_radius = size / 2.0 - 3.0;
        painter.circle_stroke(center, ring_radius, Stroke::new(5.0, look.ring));
        if spinning {
            let t = ui.input(|i| i.time) as f32;
            let points = icons::arc(center, ring_radius, t * TAU * 0.8, TAU * 0.28, 32);
            for end in [points.first(), points.last()].into_iter().flatten() {
                painter.circle_filled(*end, 2.5, look.arc);
            }
            painter.add(Shape::line(points, Stroke::new(5.0, look.arc)));
            ui.ctx().request_repaint();
        }
        let core_radius = ring_radius - 13.0 + hover * 2.0 - if pressed { 3.0 } else { 0.0 };
        painter.circle_filled(center, core_radius, look.core);
        icons::paint(
            painter,
            Rect::from_center_size(center, vec2(40.0, 40.0)),
            Icon::Power,
            look.ink,
            2.2,
        );
    }
    response
}

/// A row of options of which one is chosen. True when the choice changed.
pub fn segmented<T: PartialEq + Copy>(ui: &mut Ui, value: &mut T, options: &[(T, &str)]) -> bool {
    let p = pal(ui);
    let mut changed = false;
    Frame::NONE
        .fill(p.sunken)
        .corner_radius(10)
        .inner_margin(Margin::same(3))
        .show(ui, |ui| {
            let gap = 3.0;
            let count = options.len().max(1) as f32;
            let width = ((ui.available_width() - gap * (count - 1.0)) / count).max(40.0);
            ui.spacing_mut().item_spacing.x = gap;
            ui.horizontal(|ui| {
                for (option, label) in options {
                    let selected = *value == *option;
                    let text = RichText::new(*label).size(12.0).color(if selected {
                        p.text
                    } else {
                        p.muted
                    });
                    let button = egui::Button::new(text)
                        .fill(if selected {
                            p.border
                        } else {
                            Color32::TRANSPARENT
                        })
                        .stroke(Stroke::NONE)
                        .corner_radius(7)
                        .min_size(vec2(width, 28.0));
                    if ui.add(button).clicked() && !selected {
                        *value = *option;
                        changed = true;
                    }
                }
            });
        });
    changed
}

/// An on/off switch. The response is marked changed when it was flipped.
pub fn toggle(ui: &mut Ui, enabled: bool, on: &mut bool) -> Response {
    let p = pal(ui);
    let size = vec2(38.0, 22.0);
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, mut response) = ui.allocate_exact_size(size, sense);
    if enabled && response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    let how_on = ui.ctx().animate_bool_responsive(response.id, *on);
    if ui.is_rect_visible(rect) {
        let fill = if how_on > 0.5 {
            p.accent
        } else {
            p.border_strong
        };
        let fill = if enabled {
            fill
        } else {
            fill.gamma_multiply(0.45)
        };
        ui.painter().rect_filled(rect, CornerRadius::same(11), fill);
        let x = egui::lerp((rect.left() + 11.0)..=(rect.right() - 11.0), how_on);
        ui.painter()
            .circle_filled(pos2(x, rect.center().y), 8.0, Color32::WHITE);
    }
    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    }
}

/// A small rounded label.
pub fn pill(ui: &mut Ui, text: &str, fg: Color32, bg: Color32) {
    Frame::NONE
        .fill(bg)
        .corner_radius(255)
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.0).strong().color(fg));
        });
}

/// A filled status dot.
pub fn dot(ui: &mut Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.5, color);
}

/// A square button with a line icon (and a tooltip).
pub fn icon_button(ui: &mut Ui, icon: Icon, tip: &str) -> Response {
    icon_button_sized(ui, icon, tip, 34.0, true)
}

pub fn icon_button_sized(ui: &mut Ui, icon: Icon, tip: &str, size: f32, enabled: bool) -> Response {
    let p = pal(ui);
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(vec2(size, size), sense);
    if ui.is_rect_visible(rect) {
        let fill = if enabled && response.hovered() {
            p.border
        } else {
            p.surface
        };
        ui.painter().rect(
            rect,
            CornerRadius::same(9),
            fill,
            Stroke::new(1.0, p.border),
            StrokeKind::Inside,
        );
        let ink = if enabled {
            p.text
        } else {
            p.muted.gamma_multiply(0.6)
        };
        icons::paint(
            ui.painter(),
            Rect::from_center_size(rect.center(), vec2(size * 0.5, size * 0.5)),
            icon,
            ink,
            2.0,
        );
    }
    let response = response.on_hover_text(tip);
    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    }
}

/// The main button style (accent fill).
pub fn primary(ui: &Ui, text: &str) -> egui::Button<'static> {
    let p = pal(ui);
    egui::Button::new(RichText::new(text).strong().color(p.accent_ink))
        .fill(p.accent)
        .stroke(Stroke::NONE)
        .corner_radius(9)
        .min_size(vec2(0.0, 34.0))
}

/// The ordinary button style.
pub fn secondary(ui: &Ui, text: &str) -> egui::Button<'static> {
    let p = pal(ui);
    egui::Button::new(RichText::new(text).color(p.text))
        .fill(p.sunken)
        .stroke(Stroke::new(1.0, p.border_strong))
        .corner_radius(9)
        .min_size(vec2(0.0, 34.0))
}

/// A frameless red button (Delete).
pub fn danger(ui: &Ui, text: &str) -> egui::Button<'static> {
    let p = pal(ui);
    egui::Button::new(RichText::new(text).color(p.red))
        .frame(false)
        .min_size(vec2(0.0, 34.0))
}

/// A small, compact button for actions inside rows.
pub fn mini(ui: &Ui, text: &str) -> egui::Button<'static> {
    let p = pal(ui);
    egui::Button::new(RichText::new(text).size(12.0).color(p.text))
        .fill(p.sunken)
        .stroke(Stroke::new(1.0, p.border_strong))
        .corner_radius(8)
        .min_size(vec2(0.0, 26.0))
}

/// A value tile: a small label over a value.
pub fn stat_tile(ui: &mut Ui, label: &str, value: &str) {
    let p = pal(ui);
    Frame::NONE
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(12)
        .inner_margin(Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.label(RichText::new(label).size(10.0).strong().color(p.muted));
            ui.label(RichText::new(value).strong().color(p.text));
        });
}

/// A header that opens and closes the content below it (remembered per `id`). Returns
/// whether it is open.
pub fn fold(ui: &mut Ui, id: &str, title: &str, trailing: Option<(&str, Color32)>) -> bool {
    let p = pal(ui);
    let key = ui.scope_id().with(("fold", id));
    let mut open = ui.data_mut(|d| *d.get_temp_mut_or(key, false));
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 30.0), Sense::click());
    if response.clicked() {
        open = !open;
        ui.data_mut(|d| d.insert_temp(key, open));
    }
    if ui.is_rect_visible(rect) {
        let turn = ui.ctx().animate_bool(key, open);
        let chevron = Rect::from_min_size(rect.left_center() - vec2(0.0, 8.0), vec2(16.0, 16.0));
        // A right-pointing chevron that turns down when open.
        let painter = ui.painter();
        let c = chevron.center();
        let angle = turn * std::f32::consts::FRAC_PI_2;
        let rot = |x: f32, y: f32| {
            let (s, co) = angle.sin_cos();
            c + vec2(x * co - y * s, x * s + y * co)
        };
        let points = vec![rot(-2.0, -5.0), rot(3.0, 0.0), rot(-2.0, 5.0)];
        painter.add(Shape::line(points, Stroke::new(1.8, p.text)));
        painter.text(
            pos2(rect.left() + 22.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            title,
            egui::FontId::new(13.0, egui::FontFamily::Name(theme::SEMIBOLD.into())),
            p.text,
        );
        if let Some((text, color)) = trailing {
            painter.text(
                pos2(rect.right(), rect.center().y),
                egui::Align2::RIGHT_CENTER,
                text,
                egui::FontId::proportional(12.0),
                color,
            );
        }
    }
    response.on_hover_cursor(CursorIcon::PointingHand);
    open
}

/// How serious a banner is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Info,
    Warning,
    Error,
}

/// A coloured message box with a title and text.
pub fn banner(ui: &mut Ui, tone: Tone, title: &str, text: &str) {
    let p = pal(ui);
    let (ink, soft) = match tone {
        Tone::Info => (p.accent, p.accent_soft),
        Tone::Warning => (p.amber, p.amber_soft),
        Tone::Error => (p.red, p.red_soft),
    };
    Frame::NONE
        .fill(soft)
        .corner_radius(10)
        .inner_margin(Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                let (rect, _) = ui.allocate_exact_size(vec2(18.0, 18.0), Sense::hover());
                icons::paint(ui.painter(), rect, Icon::Warning, ink, 2.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    if !title.is_empty() {
                        ui.label(RichText::new(title).strong().color(ink));
                    }
                    if !text.is_empty() {
                        ui.add(
                            egui::Label::new(RichText::new(text).size(12.0).color(p.text)).wrap(),
                        );
                    }
                });
            });
        });
}

/// A settings row: a title (and an optional line below it) on the left, controls on the right.
pub fn row(ui: &mut Ui, title: &str, detail: Option<&str>, trailing: impl FnOnce(&mut Ui)) {
    let p = pal(ui);
    ui.horizontal(|ui| {
        ui.set_min_height(36.0);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            trailing(ui);
            ui.with_layout(Layout::top_down(Align::Min), |ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.add(egui::Label::new(RichText::new(title).color(p.text)).truncate());
                if let Some(detail) = detail {
                    ui.add(
                        egui::Label::new(RichText::new(detail).size(11.0).color(p.muted)).wrap(),
                    );
                }
            });
        });
    });
}

/// The bottom navigation bar: one tab per item, the current one in the accent colour.
pub fn nav_bar<T: PartialEq + Copy>(ui: &mut Ui, current: &mut T, items: &[(T, Icon, &str)]) {
    let p = pal(ui);
    let width = ui.available_width() / items.len().max(1) as f32;
    let height = ui.available_height().max(48.0);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for (item, icon, label) in items {
            let (rect, response) = ui.allocate_exact_size(vec2(width, height), Sense::click());
            let selected = *current == *item;
            let ink = if selected {
                p.accent
            } else if response.hovered() {
                p.text
            } else {
                p.muted
            };
            let icon_rect =
                Rect::from_center_size(rect.center() - vec2(0.0, 8.0), vec2(20.0, 20.0));
            icons::paint(ui.painter(), icon_rect, *icon, ink, 2.0);
            ui.painter().text(
                rect.center() + vec2(0.0, 12.0),
                egui::Align2::CENTER_CENTER,
                *label,
                egui::FontId::proportional(11.0),
                ink,
            );
            if response.on_hover_cursor(CursorIcon::PointingHand).clicked() {
                *current = *item;
            }
        }
    });
}
