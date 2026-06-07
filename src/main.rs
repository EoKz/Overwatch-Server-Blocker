#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod core;
mod firewall;
mod settings;

use app::OwSvBlockerApp;

fn main() -> eframe::Result {
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([780.0, 720.0])
            .with_min_inner_size([560.0, 520.0]),
        ..Default::default()
    };

    eframe::run_native(
        "OW Server Blocker",
        native_options,
        Box::new(|cc| Ok(Box::new(OwSvBlockerApp::new(cc)))),
    )
}
