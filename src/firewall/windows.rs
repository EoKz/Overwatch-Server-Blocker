use std::path::PathBuf;

use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_ANY, NET_FW_PROFILE2_ALL,
    NET_FW_RULE_DIR_OUT, NetFwPolicy2, NetFwRule,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
    CoInitializeEx, CoUninitialize,
};
use windows::Win32::UI::Shell::IsUserAnAdmin;
use windows::core::BSTR;

use crate::core::FirewallPlan;

use super::{FirewallBackend, FirewallReport, FirewallStatus};

const BACKEND_NAME: &str = "Windows Firewall";
const RULE_NAME: &str = "OWServerBlocker - Overwatch.exe";
const GROUP_NAME: &str = "OWServerBlocker";
const DESCRIPTION_PREFIX: &str = "OWServerBlocker";

pub struct WindowsFirewall {
    last_error: Option<String>,
}

impl WindowsFirewall {
    pub fn new() -> Self {
        Self { last_error: None }
    }

    fn read_status(&mut self) -> Result<FirewallStatus, String> {
        let _com = ComApartment::init()?;
        let rules = firewall_rules()?;
        let is_admin = is_admin();

        let Ok(rule) = item_rule(&rules, RULE_NAME) else {
            return Ok(FirewallStatus {
                backend_name: BACKEND_NAME,
                is_admin,
                rule_active: false,
                active_regions: Vec::new(),
                active_address_count: 0,
                application_path: None,
                note: String::from("No active OWServerBlocker rule found."),
                last_error: self.last_error.clone(),
            });
        };

        let enabled = unsafe { rule.Enabled() }
            .map(|value| value == VARIANT_TRUE)
            .map_err(error_message)?;
        let remote_addresses = unsafe { rule.RemoteAddresses() }
            .map(|value| value.to_string())
            .unwrap_or_default();
        let description = unsafe { rule.Description() }
            .map(|value| value.to_string())
            .unwrap_or_default();
        let application_path = unsafe { rule.ApplicationName() }
            .map(|value| {
                let value = value.to_string();
                (!value.trim().is_empty()).then(|| PathBuf::from(value))
            })
            .unwrap_or_default();

        let active_regions = decode_regions(&description);
        let active_address_count = count_remote_addresses(&remote_addresses);

        Ok(FirewallStatus {
            backend_name: BACKEND_NAME,
            is_admin,
            rule_active: enabled && active_address_count > 0,
            active_regions,
            active_address_count,
            application_path,
            note: if enabled {
                String::from("Single OWServerBlocker rule found.")
            } else {
                String::from("Rule exists, but it is disabled.")
            },
            last_error: self.last_error.clone(),
        })
    }

    fn apply_plan(&mut self, plan: FirewallPlan) -> Result<FirewallReport, String> {
        plan.validate_for_apply()?;

        let _com = ComApartment::init()?;
        let rules = firewall_rules()?;

        if plan.selected_regions.is_empty() {
            remove_rule_if_exists(&rules, RULE_NAME)?;
            return Ok(FirewallReport {
                ok: true,
                summary: String::from("No servers selected. Rule removed."),
            });
        }

        let remote_addresses = plan.remote_addresses.join(",");
        if remote_addresses.trim().is_empty() {
            return Err(String::from(
                "Empty IP list. The rule will not be enabled for safety.",
            ));
        }

        remove_rule_if_exists(&rules, RULE_NAME)?;

        let rule: INetFwRule = unsafe {
            CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER).map_err(error_message)?
        };

        let name = BSTR::from(RULE_NAME);
        let group = BSTR::from(GROUP_NAME);
        let description = BSTR::from(encode_description(
            &plan.selected_regions,
            plan.remote_addresses.len(),
        ));
        let application_path = BSTR::from(
            plan.application_path
                .as_ref()
                .expect("validated application path")
                .display()
                .to_string(),
        );
        let addresses = BSTR::from(remote_addresses);

        unsafe {
            rule.SetName(&name).map_err(error_message)?;
            rule.SetGrouping(&group).map_err(error_message)?;
            rule.SetDescription(&description).map_err(error_message)?;
            rule.SetApplicationName(&application_path)
                .map_err(error_message)?;
            rule.SetProtocol(NET_FW_IP_PROTOCOL_ANY.0)
                .map_err(error_message)?;
            rule.SetDirection(NET_FW_RULE_DIR_OUT)
                .map_err(error_message)?;
            rule.SetProfiles(NET_FW_PROFILE2_ALL.0)
                .map_err(error_message)?;
            rule.SetAction(NET_FW_ACTION_BLOCK).map_err(error_message)?;
            rule.SetRemoteAddresses(&addresses).map_err(error_message)?;
            rule.SetEnabled(VARIANT_TRUE).map_err(error_message)?;
            rules.Add(&rule).map_err(error_message)?;
        }

        Ok(FirewallReport {
            ok: true,
            summary: String::from("Windows Firewall rule synchronized."),
        })
    }

    fn remove_all(&mut self) -> Result<FirewallReport, String> {
        let _com = ComApartment::init()?;
        let rules = firewall_rules()?;
        remove_rule_if_exists(&rules, RULE_NAME)?;

        Ok(FirewallReport {
            ok: true,
            summary: String::from("OWServerBlocker rule removed."),
        })
    }
}

impl FirewallBackend for WindowsFirewall {
    fn status(&mut self) -> FirewallStatus {
        match self.read_status() {
            Ok(status) => status,
            Err(error) => {
                self.last_error = Some(error.clone());
                FirewallStatus {
                    backend_name: BACKEND_NAME,
                    is_admin: is_admin(),
                    rule_active: false,
                    active_regions: Vec::new(),
                    active_address_count: 0,
                    application_path: None,
                    note: String::from("Could not read Windows Firewall status."),
                    last_error: Some(error),
                }
            }
        }
    }

    fn sync(&mut self, plan: FirewallPlan) -> FirewallReport {
        match self.apply_plan(plan) {
            Ok(report) => {
                self.last_error = None;
                report
            }
            Err(error) => {
                self.last_error = Some(error.clone());
                FirewallReport::error(error)
            }
        }
    }

    fn unblock_all(&mut self) -> FirewallReport {
        match self.remove_all() {
            Ok(report) => {
                self.last_error = None;
                report
            }
            Err(error) => {
                self.last_error = Some(error.clone());
                FirewallReport {
                    ok: false,
                    summary: error,
                }
            }
        }
    }
}

struct ComApartment {
    initialized: bool,
}

impl ComApartment {
    fn init() -> Result<Self, String> {
        let flags = COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE;
        let hr = unsafe { CoInitializeEx(None, flags) };

        if hr.is_ok() {
            Ok(Self { initialized: true })
        } else {
            Err(error_message(hr.into()))
        }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

fn firewall_rules()
-> Result<windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules, String> {
    let policy: INetFwPolicy2 = unsafe {
        CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER).map_err(error_message)?
    };

    unsafe { policy.Rules().map_err(error_message) }
}

fn item_rule(
    rules: &windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules,
    name: &str,
) -> Result<INetFwRule, String> {
    let name = BSTR::from(name);
    unsafe { rules.Item(&name).map_err(error_message) }
}

fn remove_rule_if_exists(
    rules: &windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules,
    name: &str,
) -> Result<(), String> {
    let name = BSTR::from(name);
    unsafe { rules.Remove(&name).map_err(error_message) }
}

fn encode_description(regions: &[String], address_count: usize) -> String {
    format!(
        "{DESCRIPTION_PREFIX}\nregions={}\naddresses={address_count}",
        regions.join(";")
    )
}

fn decode_regions(description: &str) -> Vec<String> {
    description
        .lines()
        .find_map(|line| line.strip_prefix("regions="))
        .map(|regions| {
            regions
                .split(';')
                .map(str::trim)
                .filter(|region| !region.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn count_remote_addresses(remote_addresses: &str) -> usize {
    remote_addresses
        .split(',')
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .count()
}

fn is_admin() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

fn error_message(error: windows::core::Error) -> String {
    error.message()
}

#[cfg(test)]
mod tests {
    use super::{count_remote_addresses, decode_regions, encode_description};

    #[test]
    fn description_roundtrip_keeps_regions() {
        let regions = vec!["Brazil".to_string(), "Australia".to_string()];
        let description = encode_description(&regions, 12);
        assert_eq!(decode_regions(&description), regions);
    }

    #[test]
    fn counts_remote_addresses() {
        assert_eq!(count_remote_addresses("1.1.1.1, 8.8.8.8/32,"), 2);
    }
}
