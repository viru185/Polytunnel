//! The window's pages (`design/mockups.html`). Each is a method on the window's state
//! ([`super::App`]): Home, and the pages opened from it with a back arrow.

mod activity;
mod editor;
mod gateways;
mod home;
mod profiles;
mod settings;

use eframe::egui::{self, Margin, Ui};

/// A page's scrolling body: 16 points at the sides and the bottom.
pub(super) fn body<R>(ui: &mut Ui, id: &str, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::ScrollArea::vertical()
        .id_salt(id)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Frame::NONE
                .inner_margin(Margin {
                    left: 16,
                    right: 16,
                    top: 0,
                    bottom: 16,
                })
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 0.0;
                    add(ui)
                })
                .inner
        })
        .inner
}
