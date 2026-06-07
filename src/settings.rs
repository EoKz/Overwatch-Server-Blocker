use std::env;
use std::fs;
use std::path::PathBuf;

const APP_DIR: &str = "OWServerBlocker";
const SETTINGS_FILE: &str = "settings.ini";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AppSettings {
    pub overwatch_path: Option<PathBuf>,
    pub selected_regions: Vec<String>,
    pub selected_targets: Vec<String>,
}

impl AppSettings {
    pub fn load() -> Result<Self, String> {
        let path = settings_path();
        if !path.exists() {
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;

        Ok(parse_settings(&raw))
    }

    pub fn save(&self) -> Result<(), String> {
        let path = settings_path();
        let parent = path
            .parent()
            .ok_or_else(|| format!("invalid settings path: {}", path.display()))?;

        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;

        fs::write(&path, format_settings(self))
            .map_err(|error| format!("could not write {}: {error}", path.display()))
    }
}

pub fn settings_path() -> PathBuf {
    settings_base_dir().join(APP_DIR).join(SETTINGS_FILE)
}

fn settings_base_dir() -> PathBuf {
    env::var_os("APPDATA")
        .or_else(|| env::var_os("LOCALAPPDATA"))
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

fn parse_settings(raw: &str) -> AppSettings {
    let mut settings = AppSettings::default();

    for line in raw.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(value) = line.strip_prefix("overwatch_path=") {
            let value = value.trim();
            if !value.is_empty() {
                settings.overwatch_path = Some(PathBuf::from(value));
            }
            continue;
        }

        if let Some(value) = line.strip_prefix("selected_regions=") {
            settings.selected_regions = value
                .split(',')
                .map(str::trim)
                .filter(|region| !region.is_empty())
                .map(ToString::to_string)
                .collect();
            continue;
        }

        if let Some(value) = line.strip_prefix("selected_targets=") {
            settings.selected_targets = value
                .split(',')
                .map(str::trim)
                .filter(|target| !target.is_empty())
                .map(ToString::to_string)
                .collect();
        }
    }

    settings
}

fn format_settings(settings: &AppSettings) -> String {
    let overwatch_path = settings
        .overwatch_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let selected_regions = settings.selected_regions.join(",");
    let selected_targets = settings.selected_targets.join(",");

    format!(
        "# OW Server Blocker settings\n\
         # This file is safe to delete; the app will recreate it.\n\
         overwatch_path={overwatch_path}\n\
         selected_regions={selected_regions}\n\
         selected_targets={selected_targets}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::{AppSettings, format_settings, parse_settings};

    #[test]
    fn settings_roundtrip_keeps_fields() {
        let settings = AppSettings {
            overwatch_path: Some(r"C:\Games\Overwatch\_retail_\Overwatch.exe".into()),
            selected_regions: vec!["brazil".into(), "us_west".into()],
            selected_targets: vec!["google:southamerica-east1".into(), "blizzard:las1".into()],
        };

        let raw = format_settings(&settings);
        let parsed = parse_settings(&raw);

        assert_eq!(parsed, settings);
    }

    #[test]
    fn settings_parser_ignores_empty_and_unknown_lines() {
        let parsed = parse_settings(
            "# comment\n\
             version=1\n\
             overwatch_path=C:\\Overwatch\\Overwatch.exe\n\
             selected_regions=brazil, us_east,,\n\
             selected_targets=google:southamerica-east1, blizzard:ord1,,",
        );

        assert_eq!(
            parsed,
            AppSettings {
                overwatch_path: Some(r"C:\Overwatch\Overwatch.exe".into()),
                selected_regions: vec!["brazil".into(), "us_east".into()],
                selected_targets: vec!["google:southamerica-east1".into(), "blizzard:ord1".into()],
            }
        );
    }
}
