use std::collections::BTreeSet;
use std::path::PathBuf;

use eframe::egui::{self, Color32, RichText, Stroke};

use crate::core::{FirewallPlan, Server, ServerRegion, default_servers, detect_overwatch_path};
use crate::firewall::{FirewallBackend, FirewallReport, FirewallStatus, WindowsFirewall};

pub struct OwSvBlockerApp {
    servers: Vec<Server>,
    selected_regions: BTreeSet<ServerRegion>,
    firewall: WindowsFirewall,
    status: FirewallStatus,
    last_report: FirewallReport,
    overwatch_path: String,
    detected_overwatch_path: Option<PathBuf>,
}

const BG: Color32 = Color32::from_rgb(14, 17, 21);
const PANEL: Color32 = Color32::from_rgb(22, 27, 33);
const PANEL_ALT: Color32 = Color32::from_rgb(28, 34, 41);
const PANEL_SELECTED: Color32 = Color32::from_rgb(43, 34, 35);
const BORDER: Color32 = Color32::from_rgb(55, 66, 77);
const BORDER_SELECTED: Color32 = Color32::from_rgb(184, 89, 77);
const TEXT: Color32 = Color32::from_rgb(232, 237, 242);
const MUTED: Color32 = Color32::from_rgb(154, 166, 179);
const ACCENT: Color32 = Color32::from_rgb(63, 128, 112);
const ACCENT_DARK: Color32 = Color32::from_rgb(35, 86, 75);
const WARNING: Color32 = Color32::from_rgb(224, 168, 76);
const DANGER: Color32 = Color32::from_rgb(204, 84, 73);

impl OwSvBlockerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_style(&cc.egui_ctx);

        let mut firewall = WindowsFirewall::new();
        let status = firewall.status();
        let detected_overwatch_path = detect_overwatch_path();
        let overwatch_path = status
            .application_path
            .clone()
            .or_else(|| detected_overwatch_path.clone())
            .unwrap_or_else(|| {
                PathBuf::from(r"C:\Program Files (x86)\Overwatch\_retail_\Overwatch.exe")
            });

        Self {
            servers: default_servers(),
            selected_regions: BTreeSet::new(),
            firewall,
            status,
            last_report: FirewallReport::idle(),
            overwatch_path: overwatch_path.display().to_string(),
            detected_overwatch_path,
        }
        .with_active_regions_selected()
    }

    fn with_active_regions_selected(mut self) -> Self {
        for active_region in &self.status.active_regions {
            if let Some(server) = self
                .servers
                .iter()
                .find(|server| server.name == active_region)
            {
                self.selected_regions.insert(server.region);
            }
        }

        self
    }

    fn selected_servers(&self) -> Vec<Server> {
        self.servers
            .iter()
            .filter(|server| self.selected_regions.contains(&server.region))
            .cloned()
            .collect()
    }

    fn apply_blocks(&mut self) {
        let overwatch_path = (!self.overwatch_path.trim().is_empty())
            .then(|| PathBuf::from(self.overwatch_path.trim()));

        let plan = FirewallPlan::from_servers(self.selected_servers(), overwatch_path);
        self.last_report = self.firewall.sync(plan);
        self.status = self.firewall.status();
    }

    fn unblock_all(&mut self) {
        self.selected_regions.clear();
        self.last_report = self.firewall.unblock_all();
        self.status = self.firewall.status();
    }

    fn select_overwatch_executable(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Select Overwatch.exe")
            .add_filter("Windows executable", &["exe"])
            .pick_file()
        {
            let is_overwatch_exe = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("Overwatch.exe"));

            if is_overwatch_exe {
                self.overwatch_path = path.display().to_string();
                self.last_report = FirewallReport {
                    ok: true,
                    summary: String::from("Overwatch executable selected."),
                };
            } else {
                self.last_report = FirewallReport {
                    ok: false,
                    summary: String::from("Select the file named Overwatch.exe."),
                };
            }
        }
    }

    fn draw_header(&self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("OW Server Blocker").size(28.0).color(TEXT));
        ui.label(
            RichText::new("Selected servers will be blocked. Unselected servers stay allowed.")
                .strong()
                .color(WARNING),
        );
        ui.label(
            RichText::new(
                "Use this to prevent Overwatch.exe from connecting to the servers you select.",
            )
            .color(MUTED),
        );
    }

    fn draw_status(&self, ui: &mut egui::Ui) {
        panel_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Status").strong().color(TEXT));
                status_chip(ui, "Backend", self.status.backend_name, ACCENT);
                status_chip(
                    ui,
                    "Rule",
                    if self.status.rule_active {
                        "active"
                    } else {
                        "inactive"
                    },
                    if self.status.rule_active {
                        ACCENT
                    } else {
                        MUTED
                    },
                );
                status_chip(
                    ui,
                    "Admin",
                    if self.status.is_admin { "yes" } else { "no" },
                    if self.status.is_admin {
                        ACCENT
                    } else {
                        WARNING
                    },
                );
                status_chip(
                    ui,
                    "Blocked IPs",
                    &self.status.active_address_count.to_string(),
                    MUTED,
                );
            });

            if !self.status.active_regions.is_empty() {
                ui.label(
                    RichText::new(format!(
                        "Currently blocked servers: {}",
                        self.status.active_regions.join(", ")
                    ))
                    .color(TEXT),
                );
            }

            ui.label(RichText::new(&self.status.note).color(MUTED));

            if let Some(error) = &self.status.last_error {
                ui.colored_label(Color32::from_rgb(220, 80, 70), error);
            }
        });
    }

    fn draw_overwatch_scope(&mut self, ui: &mut egui::Ui) {
        panel_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Scope").strong().color(TEXT));
            ui.label(
                RichText::new("Rules are outbound and limited to this executable.").color(MUTED),
            );

            ui.add_sized(
                [ui.available_width(), 28.0],
                egui::TextEdit::singleline(&mut self.overwatch_path),
            );

            ui.horizontal_wrapped(|ui| {
                if ui
                    .button(RichText::new("Select Overwatch.exe").color(TEXT))
                    .clicked()
                {
                    self.select_overwatch_executable();
                }

                if let Some(path) = &self.detected_overwatch_path {
                    if ui
                        .button(RichText::new("Use detected path").color(TEXT))
                        .clicked()
                    {
                        self.overwatch_path = path.display().to_string();
                    }

                    ui.label(RichText::new(path.display().to_string()).color(MUTED));
                } else {
                    ui.label(
                        RichText::new("No Overwatch.exe was detected automatically.").color(MUTED),
                    );
                }
            });
        });
    }

    fn draw_server_list(&mut self, ui: &mut egui::Ui) {
        panel_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Servers to block").strong().color(TEXT));
                ui.label(
                    RichText::new(format!("{} selected", self.selected_regions.len()))
                        .color(WARNING),
                );
            });
            ui.label(
                RichText::new("Select only the servers you want to prevent the game from using.")
                    .color(MUTED),
            );
            ui.add_space(4.0);

            for server in &self.servers {
                let mut checked = self.selected_regions.contains(&server.region);
                let before = checked;

                server_row_frame(checked).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal_wrapped(|ui| {
                        let label_color = if checked {
                            TEXT
                        } else {
                            Color32::from_rgb(211, 218, 225)
                        };
                        ui.checkbox(
                            &mut checked,
                            RichText::new(format!("Block {}", server.name))
                                .strong()
                                .color(label_color),
                        );

                        ui.label(
                            RichText::new(format!("{} IPs/CIDRs", server.addresses.len()))
                                .color(MUTED),
                        );
                        ui.label(RichText::new(server.hint).color(MUTED));
                    });
                });

                if checked != before {
                    if checked {
                        self.selected_regions.insert(server.region);
                    } else {
                        self.selected_regions.remove(&server.region);
                    }
                }
            }
        });
    }

    fn draw_actions(&mut self, ui: &mut egui::Ui) {
        let selected_count = self.selected_regions.len();
        let has_path = !self.overwatch_path.trim().is_empty();

        ui.horizontal_wrapped(|ui| {
            ui.add_enabled_ui(has_path || selected_count == 0, |ui| {
                let apply_label = format!("Apply {} selected block(s)", selected_count);
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new(apply_label).strong().color(Color32::WHITE),
                        )
                        .fill(ACCENT_DARK),
                    )
                    .clicked()
                {
                    self.apply_blocks();
                }
            });

            if ui
                .add(
                    egui::Button::new(RichText::new("Unblock all").strong().color(Color32::WHITE))
                        .fill(DANGER),
                )
                .clicked()
            {
                self.unblock_all();
            }
        });

        if !self.status.is_admin {
            ui.colored_label(
                WARNING,
                "Run this app as administrator to apply or remove firewall rules.",
            );
        }
    }

    fn draw_logs(&self, ui: &mut egui::Ui) {
        panel_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Logs").strong().color(TEXT));

            let level = if self.last_report.ok { "info" } else { "error" };
            let text = format!("[{level}] {}", self.last_report.summary);

            if self.last_report.ok {
                ui.label(RichText::new(text).color(MUTED));
            } else {
                ui.colored_label(DANGER, text);
            }
        });
    }
}

impl eframe::App for OwSvBlockerApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Frame::central_panel(ui.style())
            .inner_margin(egui::Margin::same(18))
            .fill(BG)
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 12.0;

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());

                        self.draw_header(ui);
                        ui.add_space(2.0);
                        self.draw_status(ui);
                        self.draw_overwatch_scope(ui);
                        self.draw_server_list(ui);
                        self.draw_actions(ui);
                        self.draw_logs(ui);
                    });
            });
    }
}

fn configure_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = PANEL;
    visuals.extreme_bg_color = Color32::from_rgb(10, 12, 15);
    visuals.override_text_color = Some(TEXT);

    visuals.widgets.noninteractive.bg_fill = PANEL;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.inactive.bg_fill = PANEL_ALT;
    visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(35, 43, 51);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(46, 56, 65);
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(50, 61, 70);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.active.bg_fill = ACCENT_DARK;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);

    let mut style = (*ctx.global_style()).clone();
    style.visuals = visuals;
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 8.0);
    style.spacing.window_margin = egui::Margin::same(12);

    ctx.set_global_style(style);
}

fn panel_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(8)
        .inner_margin(egui::Margin::symmetric(14, 12))
}

fn server_row_frame(blocked: bool) -> egui::Frame {
    egui::Frame::new()
        .fill(if blocked { PANEL_SELECTED } else { PANEL_ALT })
        .stroke(Stroke::new(
            1.0,
            if blocked { BORDER_SELECTED } else { BORDER },
        ))
        .corner_radius(7)
        .inner_margin(egui::Margin::symmetric(10, 8))
        .outer_margin(egui::Margin::symmetric(0, 3))
}

fn status_chip(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    egui::Frame::new()
        .fill(Color32::from_rgb(31, 38, 45))
        .stroke(Stroke::new(1.0, Color32::from_rgb(52, 63, 73)))
        .corner_radius(7)
        .inner_margin(egui::Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(label).color(MUTED));
                ui.label(RichText::new(value).strong().color(color));
            });
        });
}
