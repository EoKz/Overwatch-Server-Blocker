use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub use latency::{LatencyMonitor, LatencyProbe, LatencyResult, first_ipv4_probe};
pub use server::{ServerGroup, ServerRegion, ServerTarget, TargetConfidence, default_servers};

mod address;
mod latency;
mod server;

#[derive(Clone, Debug)]
pub struct FirewallPlan {
    pub selected_regions: Vec<String>,
    pub selected_targets: Vec<String>,
    pub remote_addresses: Vec<String>,
    pub application_path: Option<PathBuf>,
}

impl FirewallPlan {
    pub fn from_targets(
        targets: Vec<(&ServerGroup, &ServerTarget)>,
        application_path: Option<PathBuf>,
    ) -> Self {
        let mut selected_region_names = std::collections::BTreeSet::new();
        let mut selected_regions = Vec::new();
        let mut selected_targets = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut remote_addresses = Vec::new();

        for (group, target) in targets {
            if selected_region_names.insert(group.name) {
                selected_regions.push(group.name.to_string());
            }

            selected_targets.push(target.id.to_string());

            for address in target.addresses.iter().cloned() {
                if seen.insert(address.clone()) {
                    remote_addresses.push(address);
                }
            }
        }

        Self {
            selected_regions,
            selected_targets,
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
    overwatch_path_candidates()
        .into_iter()
        .find(|path| is_overwatch_executable(path))
}

pub fn default_overwatch_path() -> PathBuf {
    PathBuf::from(r"C:\Program Files (x86)\Overwatch\_retail_\Overwatch.exe")
}

pub fn is_overwatch_executable(path: &Path) -> bool {
    path.exists()
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("Overwatch.exe"))
}

fn overwatch_path_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    push_candidate(&mut candidates, default_overwatch_path());
    push_candidate(
        &mut candidates,
        PathBuf::from(r"C:\Program Files (x86)\Overwatch\Overwatch.exe"),
    );
    push_candidate(
        &mut candidates,
        PathBuf::from(r"C:\Program Files\Overwatch\_retail_\Overwatch.exe"),
    );
    push_candidate(
        &mut candidates,
        PathBuf::from(r"C:\Program Files\Overwatch\Overwatch.exe"),
    );

    for steam_library in steam_libraries() {
        push_candidate(
            &mut candidates,
            steam_library
                .join("steamapps")
                .join("common")
                .join("Overwatch")
                .join("Overwatch.exe"),
        );
        push_candidate(
            &mut candidates,
            steam_library
                .join("steamapps")
                .join("common")
                .join("Overwatch")
                .join("_retail_")
                .join("Overwatch.exe"),
        );
    }

    candidates
}

fn steam_libraries() -> Vec<PathBuf> {
    let mut libraries = Vec::new();

    for root in steam_roots() {
        push_candidate(&mut libraries, root.clone());

        let library_file = root.join("steamapps").join("libraryfolders.vdf");
        let Ok(raw) = fs::read_to_string(library_file) else {
            continue;
        };

        for library in parse_steam_library_paths(&raw) {
            push_candidate(&mut libraries, library);
        }
    }

    libraries
}

fn steam_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(program_files_x86) = env::var_os("ProgramFiles(x86)") {
        push_candidate(&mut roots, PathBuf::from(program_files_x86).join("Steam"));
    }

    if let Some(program_files) = env::var_os("ProgramFiles") {
        push_candidate(&mut roots, PathBuf::from(program_files).join("Steam"));
    }

    push_candidate(&mut roots, PathBuf::from(r"C:\Program Files (x86)\Steam"));
    push_candidate(&mut roots, PathBuf::from(r"C:\Program Files\Steam"));

    roots
}

fn parse_steam_library_paths(raw: &str) -> Vec<PathBuf> {
    raw.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('"').collect();
            (parts.len() >= 4 && parts[1].eq_ignore_ascii_case("path"))
                .then(|| PathBuf::from(parts[3].replace(r"\\", r"\")))
        })
        .collect()
}

fn push_candidate(paths: &mut Vec<PathBuf>, path: PathBuf) {
    let key = path.to_string_lossy().to_ascii_lowercase();
    if !paths
        .iter()
        .any(|candidate| candidate.to_string_lossy().to_ascii_lowercase() == key)
    {
        paths.push(path);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{FirewallPlan, default_servers, parse_steam_library_paths};

    #[test]
    fn plan_deduplicates_addresses() {
        let servers = default_servers();
        let brazil = &servers[0];
        let brazil_target = &brazil.targets[0];
        let plan = FirewallPlan::from_targets(vec![(brazil, brazil_target)], None);

        assert_eq!(plan.selected_regions, vec!["Brazil"]);
        assert_eq!(plan.selected_targets, vec![brazil_target.id]);
        assert_eq!(plan.remote_addresses, brazil_target.addresses);
    }

    #[test]
    fn parses_steam_libraryfolders_paths() {
        let raw = r#"
            "libraryfolders"
            {
                "0"
                {
                    "path"  "C:\\Program Files (x86)\\Steam"
                }
                "1"
                {
                    "path"  "D:\\SteamLibrary"
                }
            }
        "#;

        let paths = parse_steam_library_paths(raw);

        assert_eq!(
            paths,
            vec![
                PathBuf::from(r"C:\Program Files (x86)\Steam"),
                PathBuf::from(r"D:\SteamLibrary")
            ]
        );
    }
}
