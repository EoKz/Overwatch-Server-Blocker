use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use eframe::egui::{self, Color32, RichText, Stroke};

use crate::core::{
    FirewallPlan, LatencyMonitor, LatencyProbe, LatencyResult, ServerGroup, ServerRegion,
    ServerTarget, default_overwatch_path, default_servers, detect_overwatch_path, first_ipv4_probe,
};
use crate::firewall::{FirewallBackend, FirewallReport, FirewallStatus, WindowsFirewall};
use crate::settings::{AppSettings, settings_path};

pub struct OwSvBlockerApp {
    servers: Vec<ServerGroup>,
    selected_targets: BTreeSet<String>,
    firewall: WindowsFirewall,
    status: FirewallStatus,
    last_report: FirewallReport,
    overwatch_path: String,
    detected_overwatch_path: Option<PathBuf>,
    latency_monitor: LatencyMonitor,
    latency_results: BTreeMap<String, LatencyResult>,
    expanded_groups: BTreeSet<ServerRegion>,
}

const BG: Color32 = Color32::from_rgb(17, 17, 27);
const PANEL: Color32 = Color32::from_rgb(30, 30, 46);
const PANEL_ALT: Color32 = Color32::from_rgb(49, 50, 68);
const PANEL_SELECTED: Color32 = Color32::from_rgb(54, 48, 62);
const BORDER: Color32 = Color32::from_rgb(69, 71, 90);
const BORDER_SELECTED: Color32 = Color32::from_rgb(250, 179, 135);
const TEXT: Color32 = Color32::from_rgb(205, 214, 244);
const MUTED: Color32 = Color32::from_rgb(166, 173, 200);
const ACCENT: Color32 = Color32::from_rgb(148, 226, 213);
const ACCENT_DARK: Color32 = Color32::from_rgb(49, 116, 143);
const WARNING: Color32 = Color32::from_rgb(249, 226, 175);
const DANGER: Color32 = Color32::from_rgb(243, 139, 168);

impl OwSvBlockerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_style(&cc.egui_ctx);

        let mut firewall = WindowsFirewall::new();
        let status = firewall.status();
        let (settings, settings_report) = load_settings_report();
        let detected_overwatch_path = detect_overwatch_path();
        let overwatch_path = status
            .application_path
            .clone()
            .or_else(|| settings.overwatch_path.clone())
            .or_else(|| detected_overwatch_path.clone())
            .unwrap_or_else(default_overwatch_path);
        let servers = default_servers();
        let selected_targets = initial_selected_targets(&servers, &status, &settings);
        let latency_monitor = LatencyMonitor::start(latency_probes(&servers));

        Self {
            servers,
            selected_targets,
            firewall,
            status,
            last_report: settings_report.unwrap_or_else(FirewallReport::idle),
            overwatch_path: overwatch_path.display().to_string(),
            detected_overwatch_path,
            latency_monitor,
            latency_results: BTreeMap::new(),
            expanded_groups: BTreeSet::new(),
        }
    }

    fn selected_target_refs(&self) -> Vec<(&ServerGroup, &ServerTarget)> {
        self.servers
            .iter()
            .flat_map(|group| {
                group
                    .targets
                    .iter()
                    .filter(|target| self.selected_targets.contains(target.id))
                    .map(move |target| (group, target))
            })
            .collect()
    }

    fn apply_blocks(&mut self) {
        let overwatch_path = (!self.overwatch_path.trim().is_empty())
            .then(|| PathBuf::from(self.overwatch_path.trim()));

        let plan = FirewallPlan::from_targets(self.selected_target_refs(), overwatch_path);
        self.last_report = self.firewall.sync(plan);
        self.status = self.firewall.status();
        self.persist_settings();
    }

    fn unblock_all(&mut self) {
        self.selected_targets.clear();
        self.last_report = self.firewall.unblock_all();
        self.status = self.firewall.status();
        self.persist_settings();
    }

    fn current_settings(&self) -> AppSettings {
        AppSettings {
            overwatch_path: (!self.overwatch_path.trim().is_empty())
                .then(|| PathBuf::from(self.overwatch_path.trim())),
            selected_regions: self
                .servers
                .iter()
                .filter(|group| self.group_selected_count(group) > 0)
                .map(|group| group.region.id().to_string())
                .collect(),
            selected_targets: self.selected_targets.iter().cloned().collect(),
        }
    }

    fn persist_settings(&mut self) {
        if let Err(error) = self.current_settings().save() {
            self.last_report = FirewallReport {
                ok: false,
                summary: format!("Could not save settings: {error}"),
            };
        }
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
                self.persist_settings();
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
                ui.colored_label(DANGER, error);
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

            let path_response = ui.add_sized(
                [ui.available_width(), 28.0],
                egui::TextEdit::singleline(&mut self.overwatch_path),
            );
            if path_response.changed() {
                self.persist_settings();
            }

            ui.horizontal_wrapped(|ui| {
                if ui
                    .button(RichText::new("Select Overwatch.exe").color(TEXT))
                    .clicked()
                {
                    self.select_overwatch_executable();
                }

                if let Some(path) = self.detected_overwatch_path.clone() {
                    if ui
                        .button(RichText::new("Use detected path").color(TEXT))
                        .clicked()
                    {
                        self.overwatch_path = path.display().to_string();
                        self.persist_settings();
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
                    RichText::new(format!("{} selected", self.selected_targets.len()))
                        .color(WARNING),
                );
            });
            ui.label(
                RichText::new("Select only the servers you want to prevent the game from using.")
                    .color(MUTED),
            );
            ui.add_space(4.0);

            let mut selection_changed = false;
            for index in 0..self.servers.len() {
                let group = self.servers[index].clone();
                selection_changed |= self.draw_server_group(ui, &group);
            }

            if selection_changed {
                self.persist_settings();
            }
        });
    }

    fn draw_server_group(&mut self, ui: &mut egui::Ui, group: &ServerGroup) -> bool {
        let total_targets = group.target_count();
        let selected_targets = self.group_selected_count(group);
        let all_selected = total_targets > 0 && selected_targets == total_targets;
        let partial_selected = selected_targets > 0 && !all_selected;
        let blocked = selected_targets > 0;
        let expanded = self.expanded_groups.contains(&group.region);
        let mut selection_changed = false;

        server_row_frame(blocked).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                let toggle_label = if expanded { "v" } else { ">" };
                let toggle_hint = if expanded {
                    "Hide specific targets"
                } else {
                    "Show specific targets"
                };

                if ui
                    .add_sized([24.0, 24.0], egui::Button::new(toggle_label))
                    .on_hover_text(toggle_hint)
                    .clicked()
                {
                    self.toggle_group_expanded(group.region);
                }

                let mut checked = all_selected;
                let label_color = if blocked {
                    TEXT
                } else {
                    Color32::from_rgb(186, 194, 222)
                };
                let checkbox = ui.checkbox(
                    &mut checked,
                    RichText::new(format!("Block {}", group.name))
                        .strong()
                        .color(label_color),
                );

                if checkbox.clicked() {
                    if all_selected {
                        self.set_group_selected(group, false);
                    } else {
                        self.set_group_selected(group, true);
                    }
                    selection_changed = true;
                }

                ui.label(
                    RichText::new(format!("{} IPs/CIDRs", group.addresses().len())).color(MUTED),
                );
                ui.label(RichText::new(group.hint).color(MUTED));
                ui.label(RichText::new(format!("{} targets", total_targets)).color(MUTED));

                if partial_selected {
                    mini_chip(ui, "partial", WARNING);
                }
            });

            if expanded {
                ui.add_space(4.0);
                for target in &group.targets {
                    selection_changed |= self.draw_target_row(ui, target);
                }
            }
        });

        selection_changed
    }

    fn draw_target_row(&mut self, ui: &mut egui::Ui, target: &ServerTarget) -> bool {
        let mut checked = self.selected_targets.contains(target.id);
        let before = checked;

        target_row_frame(checked).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                let label_color = if checked {
                    TEXT
                } else {
                    Color32::from_rgb(186, 194, 222)
                };
                ui.checkbox(&mut checked, RichText::new(target.label).color(label_color));
                mini_chip(ui, target.provider.label(), ACCENT);
                mini_chip(ui, target.confidence.label(), confidence_color(target));
                ui.label(RichText::new(target.identifier).color(MUTED));
                ui.label(
                    RichText::new(format!("{} IPs/CIDRs", target.address_count())).color(MUTED),
                );
                ui.label(RichText::new(self.latency_label(target)).color(MUTED));
            });
        });

        if checked != before {
            if checked {
                self.selected_targets.insert(target.id.to_string());
            } else {
                self.selected_targets.remove(target.id);
            }
            return true;
        }

        false
    }

    fn group_selected_count(&self, group: &ServerGroup) -> usize {
        group
            .targets
            .iter()
            .filter(|target| self.selected_targets.contains(target.id))
            .count()
    }

    fn set_group_selected(&mut self, group: &ServerGroup, selected: bool) {
        for target in &group.targets {
            if selected {
                self.selected_targets.insert(target.id.to_string());
            } else {
                self.selected_targets.remove(target.id);
            }
        }
    }

    fn toggle_group_expanded(&mut self, region: ServerRegion) {
        if !self.expanded_groups.remove(&region) {
            self.expanded_groups.insert(region);
        }
    }

    fn latency_label(&self, target: &ServerTarget) -> String {
        match self.latency_results.get(target.id) {
            Some(LatencyResult::Ready { milliseconds }) => format!("{milliseconds} ms"),
            Some(LatencyResult::Timeout) => String::from("timeout"),
            Some(LatencyResult::Unavailable) => String::from("n/a"),
            None if target.probe_ips.is_empty() => String::from("n/a"),
            None => String::from("checking..."),
        }
    }

    fn draw_actions(&mut self, ui: &mut egui::Ui) {
        let selected_count = self.selected_targets.len();
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
        for update in self.latency_monitor.drain_updates() {
            self.latency_results.insert(update.target_id, update.result);
        }
        ui.ctx().request_repaint_after(Duration::from_secs(1));

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
    visuals.extreme_bg_color = Color32::from_rgb(17, 17, 27);
    visuals.override_text_color = Some(TEXT);

    visuals.widgets.noninteractive.bg_fill = PANEL;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.inactive.bg_fill = PANEL_ALT;
    visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(49, 50, 68);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(69, 71, 90);
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(88, 91, 112);
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

fn target_row_frame(blocked: bool) -> egui::Frame {
    egui::Frame::new()
        .fill(if blocked {
            Color32::from_rgb(59, 50, 68)
        } else {
            Color32::from_rgb(24, 24, 37)
        })
        .stroke(Stroke::new(
            1.0,
            if blocked {
                Color32::from_rgb(235, 160, 172)
            } else {
                Color32::from_rgb(69, 71, 90)
            },
        ))
        .corner_radius(6)
        .inner_margin(egui::Margin::symmetric(9, 6))
        .outer_margin(egui::Margin::symmetric(0, 3))
}

fn status_chip(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    egui::Frame::new()
        .fill(PANEL_ALT)
        .stroke(Stroke::new(1.0, Color32::from_rgb(88, 91, 112)))
        .corner_radius(7)
        .inner_margin(egui::Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(label).color(MUTED));
                ui.label(RichText::new(value).strong().color(color));
            });
        });
}

fn mini_chip(ui: &mut egui::Ui, value: &str, color: Color32) {
    egui::Frame::new()
        .fill(PANEL_ALT)
        .stroke(Stroke::new(1.0, Color32::from_rgb(88, 91, 112)))
        .corner_radius(6)
        .inner_margin(egui::Margin::symmetric(7, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(value).strong().color(color));
        });
}

fn confidence_color(target: &ServerTarget) -> Color32 {
    match target.confidence {
        crate::core::TargetConfidence::KnownOw => ACCENT,
        crate::core::TargetConfidence::ProviderRegion => WARNING,
        crate::core::TargetConfidence::Community => MUTED,
    }
}

fn load_settings_report() -> (AppSettings, Option<FirewallReport>) {
    match AppSettings::load() {
        Ok(settings) => (settings, None),
        Err(error) => (
            AppSettings::default(),
            Some(FirewallReport {
                ok: false,
                summary: format!(
                    "Could not load settings from {}: {error}",
                    settings_path().display()
                ),
            }),
        ),
    }
}

fn initial_selected_targets(
    servers: &[ServerGroup],
    status: &FirewallStatus,
    settings: &AppSettings,
) -> BTreeSet<String> {
    let known_target_ids = all_target_ids(servers);

    if !status.active_targets.is_empty() {
        let active_targets: BTreeSet<String> = status
            .active_targets
            .iter()
            .filter(|target| known_target_ids.contains(target.as_str()))
            .cloned()
            .collect();

        if !active_targets.is_empty() {
            return active_targets;
        }
    }

    if !status.active_regions.is_empty() {
        return target_ids_for_regions(servers, &status.active_regions);
    }

    if !settings.selected_targets.is_empty() {
        let selected_targets: BTreeSet<String> = settings
            .selected_targets
            .iter()
            .filter(|target| known_target_ids.contains(target.as_str()))
            .cloned()
            .collect();

        if !selected_targets.is_empty() {
            return selected_targets;
        }
    }

    target_ids_for_regions(servers, &settings.selected_regions)
}

fn all_target_ids(servers: &[ServerGroup]) -> BTreeSet<&'static str> {
    servers
        .iter()
        .flat_map(|group| group.targets.iter().map(|target| target.id))
        .collect()
}

fn target_ids_for_regions(servers: &[ServerGroup], regions: &[String]) -> BTreeSet<String> {
    servers
        .iter()
        .filter(|group| {
            regions.iter().any(|region| {
                group.name.eq_ignore_ascii_case(region)
                    || ServerRegion::from_id(region) == Some(group.region)
            })
        })
        .flat_map(|group| group.targets.iter().map(|target| target.id.to_string()))
        .collect()
}

fn latency_probes(servers: &[ServerGroup]) -> Vec<LatencyProbe> {
    servers
        .iter()
        .flat_map(|group| {
            group.targets.iter().filter_map(|target| {
                first_ipv4_probe(&target.probe_ips).map(|ip| LatencyProbe {
                    target_id: target.id.to_string(),
                    ip,
                })
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{initial_selected_targets, target_ids_for_regions};
    use crate::core::default_servers;
    use crate::firewall::FirewallStatus;
    use crate::settings::AppSettings;

    #[test]
    fn legacy_regions_select_every_target_in_that_region() {
        let servers = default_servers();
        let selected = target_ids_for_regions(&servers, &["Australia".to_string()]);

        assert!(selected.contains("google:australia-southeast1"));
        assert!(selected.contains("blizzard:syd2"));
        assert!(selected.contains("community:aus"));
    }

    #[test]
    fn active_target_ids_restore_exact_selection() {
        let servers = default_servers();
        let status = status_with(vec!["Australia"], vec!["blizzard:syd2"]);

        let selected = initial_selected_targets(&servers, &status, &AppSettings::default());

        assert_eq!(selected.len(), 1);
        assert!(selected.contains("blizzard:syd2"));
    }

    #[test]
    fn invalid_target_ids_fall_back_to_legacy_regions() {
        let servers = default_servers();
        let status = status_with(vec!["Australia"], vec!["old:unknown"]);

        let selected = initial_selected_targets(&servers, &status, &AppSettings::default());

        assert!(selected.contains("google:australia-southeast1"));
        assert!(selected.contains("blizzard:syd2"));
        assert!(selected.contains("community:aus"));
    }

    fn status_with(regions: Vec<&str>, targets: Vec<&str>) -> FirewallStatus {
        FirewallStatus {
            backend_name: "test",
            is_admin: true,
            rule_active: true,
            active_regions: regions.into_iter().map(ToString::to_string).collect(),
            active_targets: targets.into_iter().map(ToString::to_string).collect(),
            active_address_count: 1,
            application_path: None,
            note: String::new(),
            last_error: None,
        }
    }
}
