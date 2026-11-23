//! Portable fallback used when building or testing on a non-Windows host.
//! Every function reports "unsupported" instead of pretending to work.

use super::ProcessSample;
use crate::core::scanner::RecycleBinInfo;
use crate::model::{
    DefenderScanKind, DefenderScanOutcome, DefenderStatus, InstalledApp, StartupEntry, Volume,
};
use std::path::Path;
use std::sync::atomic::AtomicBool;

pub fn is_elevated() -> bool {
    false
}

pub fn relaunch_elevated() -> Result<(), String> {
    Err("Administrator elevation is only available on Windows".to_string())
}

pub fn os_version() -> String {
    format!(
        "{} {} (preview host)",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

pub fn computer_name() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".to_string())
}

pub fn user_name() -> String {
    std::env::var("USER").unwrap_or_else(|_| "user".to_string())
}

pub fn local_offset_seconds() -> i64 {
    0
}

pub fn volumes() -> Vec<Volume> {
    Vec::new()
}

pub fn recycle_bin_info() -> Option<RecycleBinInfo> {
    None
}

pub fn empty_recycle_bin() -> Result<u64, String> {
    Err("The Recycle Bin is only available on Windows".to_string())
}

pub struct ProcessSampler;

impl ProcessSampler {
    pub fn new() -> Self {
        Self
    }

    pub fn sample(&mut self) -> ProcessSample {
        ProcessSample {
            processes: Vec::new(),
            stats: crate::model::SystemStats {
                cpu: 0.0,
                mem_used: 0,
                mem_total: 0,
                process_count: 0,
                thread_count: 0,
                uptime_secs: 0,
                elevated: false,
            },
        }
    }
}

impl Default for ProcessSampler {
    fn default() -> Self {
        Self::new()
    }
}

pub fn kill_process(_pid: u32) -> Result<(), String> {
    Err("Process management is only available on Windows".to_string())
}

pub fn startup_entries() -> Vec<StartupEntry> {
    Vec::new()
}

pub fn set_startup_enabled(_entry: &StartupEntry, _enabled: bool) -> Result<(), String> {
    Err("Startup management is only available on Windows".to_string())
}

pub fn installed_apps() -> Vec<InstalledApp> {
    Vec::new()
}

pub fn defender_status() -> DefenderStatus {
    DefenderStatus {
        available: false,
        error: Some("Microsoft Defender is only available on Windows".to_string()),
        ..Default::default()
    }
}

pub fn defender_threats() -> Result<Vec<crate::model::Threat>, String> {
    Err("Microsoft Defender is only available on Windows".to_string())
}

pub fn defender_threat_active(_id: i64) -> Result<bool, String> {
    Err("Microsoft Defender is only available on Windows".to_string())
}

pub fn defender_scan(
    _kind: &DefenderScanKind,
    _cancel: &AtomicBool,
    _progress: &mut dyn FnMut(Option<f32>, String),
) -> Result<DefenderScanOutcome, String> {
    Err("Microsoft Defender is only available on Windows".to_string())
}

pub fn remove_threat(_id: i64) -> Result<(), String> {
    Err("Microsoft Defender is only available on Windows".to_string())
}

pub fn update_defender_signatures() -> Result<String, String> {
    Err("Microsoft Defender is only available on Windows".to_string())
}

pub fn open_windows_security() -> Result<(), String> {
    Err("Windows Security is only available on Windows".to_string())
}

pub fn open_url(url: &str) -> Result<(), String> {
    Err(format!("Cannot open {url} on this host"))
}

pub fn open_folder(path: &Path) -> Result<(), String> {
    Err(format!("Cannot open {} on this host", path.display()))
}

pub fn reveal_in_explorer(path: &Path) -> Result<(), String> {
    Err(format!("Cannot reveal {} on this host", path.display()))
}

pub fn autostart_enabled() -> bool {
    false
}

pub fn set_autostart(_enabled: bool) -> Result<(), String> {
    Err("Autostart is only available on Windows".to_string())
}

pub fn maintenance_task_installed() -> bool {
    false
}

pub fn set_maintenance_task(_enabled: bool) -> Result<(), String> {
    Err("Scheduled maintenance is only available on Windows".to_string())
}
