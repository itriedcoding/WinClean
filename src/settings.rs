//! User settings persisted as JSON in `%APPDATA%\WinClean\settings.json`.

use crate::core::paths;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemeMode {
    Dark,
    Light,
}

impl Default for ThemeMode {
    fn default() -> Self {
        ThemeMode::Dark
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: ThemeMode,
    pub confirm_deletions: bool,
    /// Existing files must be confirmed item by item (large files / duplicates).
    pub review_each_item: bool,
    pub exclusions: Vec<String>,
    /// Minimum size for the Large Files page.
    pub large_file_threshold_gb: u64,
    /// Show the low storage banner below this amount of free space.
    pub low_storage_threshold_gb: u64,
    /// Include Windows / Program Files in large file scans.
    pub scan_system_folders: bool,
    /// Offer Prefetch data as a cleanup category.
    pub include_prefetch: bool,
    pub duplicate_min_size_mb: u64,
    pub start_with_windows: bool,
    pub weekly_maintenance: bool,
    pub monitor_interval_ms: u64,
    pub reduce_motion: bool,
    pub empty_recycle_after_clean: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: ThemeMode::Dark,
            confirm_deletions: true,
            review_each_item: true,
            exclusions: Vec::new(),
            large_file_threshold_gb: 1,
            low_storage_threshold_gb: 100,
            scan_system_folders: false,
            include_prefetch: false,
            duplicate_min_size_mb: 1,
            start_with_windows: false,
            weekly_maintenance: false,
            monitor_interval_ms: 1000,
            reduce_motion: false,
            empty_recycle_after_clean: false,
        }
    }
}

impl Settings {
    pub fn load() -> Self {
        let path = paths::settings_file();
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|err| {
                log::warn(
                    "settings",
                    format!("could not parse {}: {err}", path.display()),
                );
                Settings::default()
            }),
            Err(_) => Settings::default(),
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        let path = paths::settings_file();
        paths::ensure_parent(&path)?;
        let text = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string());
        std::fs::write(path, text)
    }

    pub fn exclusions(&self) -> Vec<String> {
        self.exclusions
            .iter()
            .map(|rule| rule.trim().to_string())
            .filter(|rule| !rule.is_empty())
            .collect()
    }

    pub fn add_exclusion(&mut self, rule: &str) -> bool {
        let rule = rule.trim();
        if rule.is_empty() {
            return false;
        }
        if self
            .exclusions
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(rule))
        {
            return false;
        }
        self.exclusions.push(rule.to_string());
        true
    }

    pub fn remove_exclusion(&mut self, index: usize) {
        if index < self.exclusions.len() {
            self.exclusions.remove(index);
        }
    }

    pub fn large_file_threshold_bytes(&self) -> u64 {
        self.large_file_threshold_gb
            .max(1)
            .saturating_mul(1024 * 1024 * 1024)
    }

    pub fn low_storage_threshold_bytes(&self) -> u64 {
        self.low_storage_threshold_gb
            .saturating_mul(1024 * 1024 * 1024)
    }

    pub fn duplicate_min_size_bytes(&self) -> u64 {
        self.duplicate_min_size_mb
            .max(1)
            .saturating_mul(1024 * 1024)
    }

    /// Paths the scanner will never touch, pre-expanded for fast matching.
    pub fn prepared_exclusions(&self) -> Vec<String> {
        crate::core::guard::prepare_exclusions(&self.exclusions)
    }
}

/// Lightweight, typed logging facade over the app's logger.
pub mod log {
    use crate::core::logbook::{sink, Level};

    pub fn info(area: &str, message: impl AsRef<str>) {
        sink().write(Level::Info, area, message.as_ref());
    }

    pub fn warn(area: &str, message: impl AsRef<str>) {
        sink().write(Level::Warn, area, message.as_ref());
    }

    pub fn error(area: &str, message: impl AsRef<str>) {
        sink().write(Level::Error, area, message.as_ref());
    }
}

/// Legacy state that should survive restarts but is not really a preference.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AppState {
    pub last_quick_clean: Option<u64>,
    pub bytes_freed_total: u64,
    pub last_defender_scan: Option<String>,
    pub window_width: Option<f32>,
    pub window_height: Option<f32>,
}

impl AppState {
    pub fn load() -> Self {
        std::fs::read_to_string(paths::state_file())
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        let path: PathBuf = paths::state_file();
        if paths::ensure_parent(&path).is_ok() {
            if let Ok(text) = serde_json::to_string_pretty(self) {
                let _ = std::fs::write(path, text);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let settings = Settings::default();
        assert!(settings.confirm_deletions);
        assert!(settings.review_each_item);
        assert_eq!(settings.low_storage_threshold_gb, 100);
        assert_eq!(settings.large_file_threshold_bytes(), 1024 * 1024 * 1024);
        assert!(!settings.scan_system_folders);
        assert!(!settings.start_with_windows);
    }

    #[test]
    fn exclusions_are_deduplicated() {
        let mut settings = Settings::default();
        assert!(settings.add_exclusion(r"C:\Windows\Temp\Keep"));
        assert!(!settings.add_exclusion(r"c:\windows\temp\keep"));
        assert!(!settings.add_exclusion("   "));
        assert_eq!(settings.exclusions().len(), 1);
        settings.remove_exclusion(0);
        assert!(settings.exclusions().is_empty());
    }

    #[test]
    fn settings_round_trip_through_json() {
        let mut settings = Settings::default();
        settings.theme = ThemeMode::Light;
        settings.large_file_threshold_gb = 2;
        settings.add_exclusion(r"C:\Temp\Keep");
        let text = serde_json::to_string(&settings).unwrap();
        let restored: Settings = serde_json::from_str(&text).unwrap();
        assert_eq!(restored.theme, ThemeMode::Light);
        assert_eq!(restored.large_file_threshold_gb, 2);
        assert_eq!(restored.exclusions, vec![r"C:\Temp\Keep".to_string()]);
    }

    #[test]
    fn missing_fields_fall_back_to_defaults() {
        let restored: Settings = serde_json::from_str(r#"{"theme":"Light"}"#).unwrap();
        assert_eq!(restored.theme, ThemeMode::Light);
        assert!(restored.confirm_deletions);
    }
}
