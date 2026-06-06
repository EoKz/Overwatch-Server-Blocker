use std::path::PathBuf;

pub use server::{Server, ServerRegion, default_servers};

mod address;
mod server;

#[derive(Clone, Debug)]
pub struct FirewallPlan {
    pub selected_regions: Vec<String>,
    pub remote_addresses: Vec<String>,
    pub application_path: Option<PathBuf>,
}

impl FirewallPlan {
    pub fn from_servers(servers: Vec<Server>, application_path: Option<PathBuf>) -> Self {
        let selected_regions = servers
            .iter()
            .map(|server| server.name.to_string())
            .collect();

        let mut seen = std::collections::BTreeSet::new();
        let mut remote_addresses = Vec::new();

        for address in servers
            .iter()
            .flat_map(|server| server.addresses.iter())
            .cloned()
        {
            if seen.insert(address.clone()) {
                remote_addresses.push(address);
            }
        }

        Self {
            selected_regions,
            remote_addresses,
            application_path,
        }
    }

    pub fn validate_for_apply(&self) -> Result<(), String> {
        if self.selected_regions.is_empty() {
            return Ok(());
        }

        if self.remote_addresses.is_empty() {
            return Err(String::from(
                "No valid IPs were found for the selected servers.",
            ));
        }

        let Some(path) = &self.application_path else {
            return Err(String::from("Select the Overwatch.exe path."));
        };

        if !path.exists() {
            return Err(format!("The executable does not exist: {}", path.display()));
        }

        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();

        if !file_name.eq_ignore_ascii_case("Overwatch.exe") {
            return Err(String::from(
                "The path must point to a file named Overwatch.exe.",
            ));
        }

        Ok(())
    }
}

pub fn detect_overwatch_path() -> Option<PathBuf> {
    common_overwatch_paths()
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
}

fn common_overwatch_paths() -> [&'static str; 4] {
    [
        r"C:\Program Files (x86)\Overwatch\_retail_\Overwatch.exe",
        r"C:\Program Files (x86)\Overwatch\Overwatch.exe",
        r"C:\Program Files (x86)\Steam\steamapps\common\Overwatch\Overwatch.exe",
        r"C:\Program Files\Steam\steamapps\common\Overwatch\Overwatch.exe",
    ]
}

#[cfg(test)]
mod tests {
    use super::{FirewallPlan, Server, ServerRegion};

    #[test]
    fn plan_deduplicates_addresses() {
        let servers = vec![
            Server {
                region: ServerRegion::Brazil,
                name: "Brazil",
                hint: "",
                addresses: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            },
            Server {
                region: ServerRegion::Australia,
                name: "Australia",
                hint: "",
                addresses: vec!["8.8.8.8".into()],
            },
        ];

        let plan = FirewallPlan::from_servers(servers, None);
        assert_eq!(plan.remote_addresses, vec!["1.1.1.1", "8.8.8.8"]);
    }
}
