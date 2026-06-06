use std::path::PathBuf;

use crate::core::FirewallPlan;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::WindowsFirewall;

pub trait FirewallBackend {
    fn status(&mut self) -> FirewallStatus;
    fn sync(&mut self, plan: FirewallPlan) -> FirewallReport;
    fn unblock_all(&mut self) -> FirewallReport;
}

#[derive(Clone, Debug)]
pub struct FirewallStatus {
    pub backend_name: &'static str,
    pub is_admin: bool,
    pub rule_active: bool,
    pub active_regions: Vec<String>,
    pub active_address_count: usize,
    pub application_path: Option<PathBuf>,
    pub note: String,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FirewallReport {
    pub ok: bool,
    pub summary: String,
}

impl FirewallReport {
    pub fn idle() -> Self {
        Self {
            ok: true,
            summary: String::from("No action applied yet."),
        }
    }

    pub fn error(summary: impl Into<String>) -> Self {
        Self {
            ok: false,
            summary: summary.into(),
        }
    }
}

#[cfg(not(windows))]
pub struct WindowsFirewall;

#[cfg(not(windows))]
impl WindowsFirewall {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(windows))]
impl FirewallBackend for WindowsFirewall {
    fn status(&mut self) -> FirewallStatus {
        FirewallStatus {
            backend_name: "unavailable",
            is_admin: false,
            rule_active: false,
            active_regions: Vec::new(),
            active_address_count: 0,
            application_path: None,
            note: String::from("Windows Firewall is only available on Windows."),
            last_error: None,
        }
    }

    fn sync(&mut self, _plan: FirewallPlan) -> FirewallReport {
        FirewallReport::error("Windows Firewall is only available on Windows.")
    }

    fn unblock_all(&mut self) -> FirewallReport {
        FirewallReport {
            ok: false,
            summary: String::from("Windows Firewall is only available on Windows."),
        }
    }
}
