//! Shared data types used by the scanning engine, platform layer and the UI.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;

/// Classification of recoverable storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Category {
    WindowsTemp,
    UserTemp,
    BrowserCache,
    ThumbnailCache,
    CrashDumps,
    WindowsLogs,
    ErrorReports,
    WindowsUpdateCache,
    DeliveryOptimization,
    Prefetch,
    RecycleBin,
    LargeFile,
    Duplicate,
}

/// How careful the user should be with a category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Risk {
    Safe,
    Caution,
    Review,
}

impl Risk {
    pub fn label(self) -> &'static str {
        match self {
            Risk::Safe => "Safe",
            Risk::Caution => "Caution",
            Risk::Review => "Review",
        }
    }
}

impl Category {
    /// Every category that the cleaning scanner can target.
    pub const CLEANABLE: [Category; 11] = [
        Category::WindowsTemp,
        Category::UserTemp,
        Category::BrowserCache,
        Category::ThumbnailCache,
        Category::CrashDumps,
        Category::WindowsLogs,
        Category::ErrorReports,
        Category::WindowsUpdateCache,
        Category::DeliveryOptimization,
        Category::Prefetch,
        Category::RecycleBin,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Category::WindowsTemp => "Windows temporary files",
            Category::UserTemp => "User temporary files",
            Category::BrowserCache => "Browser caches",
            Category::ThumbnailCache => "Thumbnail & icon caches",
            Category::CrashDumps => "Crash dumps",
            Category::WindowsLogs => "Windows log files",
            Category::ErrorReports => "Error reporting queue",
            Category::WindowsUpdateCache => "Windows Update cache",
            Category::DeliveryOptimization => "Delivery Optimization cache",
            Category::Prefetch => "Prefetch data",
            Category::RecycleBin => "Recycle Bin",
            Category::LargeFile => "Large files",
            Category::Duplicate => "Duplicate files",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Category::WindowsTemp => "Windows Temp",
            Category::UserTemp => "User Temp",
            Category::BrowserCache => "Browser Cache",
            Category::ThumbnailCache => "Thumbnails",
            Category::CrashDumps => "Crash Dumps",
            Category::WindowsLogs => "Log Files",
            Category::ErrorReports => "Error Reports",
            Category::WindowsUpdateCache => "Update Cache",
            Category::DeliveryOptimization => "Delivery Cache",
            Category::Prefetch => "Prefetch",
            Category::RecycleBin => "Recycle Bin",
            Category::LargeFile => "Large File",
            Category::Duplicate => "Duplicate",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Category::WindowsTemp => "Scratch files left behind by Windows and installers in the system temp folder.",
            Category::UserTemp => "Temporary files created by your own programs and installers.",
            Category::BrowserCache => "Cached web pages, scripts and images from Chrome, Edge, Firefox and Brave. Never touches bookmarks, history or passwords.",
            Category::ThumbnailCache => "Thumbnail and icon databases Windows rebuilds automatically.",
            Category::CrashDumps => "Memory dumps written when an application or Windows component crashed.",
            Category::WindowsLogs => "Diagnostic logs written by Windows components and update servicing.",
            Category::ErrorReports => "Queued Windows Error Reporting archives and crash metadata.",
            Category::WindowsUpdateCache => "Downloaded update payloads that Windows has already installed.",
            Category::DeliveryOptimization => "Peer-to-peer update delivery cache.",
            Category::Prefetch => "Application launch traces. Windows rebuilds them; keeping them can speed up launches.",
            Category::RecycleBin => "Files you already deleted and that are still occupying disk space.",
            Category::LargeFile => "Files larger than your threshold. Review before deleting — these are often personal data.",
            Category::Duplicate => "Byte-identical copies of the same file, usually from repeated downloads or backups.",
        }
    }

    pub fn risk(self) -> Risk {
        match self {
            Category::WindowsTemp
            | Category::UserTemp
            | Category::BrowserCache
            | Category::ThumbnailCache
            | Category::CrashDumps
            | Category::ErrorReports
            | Category::DeliveryOptimization => Risk::Safe,
            Category::WindowsLogs | Category::WindowsUpdateCache | Category::RecycleBin => {
                Risk::Caution
            }
            Category::Prefetch | Category::LargeFile | Category::Duplicate => Risk::Review,
        }
    }

    /// Items pre-selected by the cleanup engine. Deliberately conservative.
    pub fn default_selected(self) -> bool {
        !matches!(
            self,
            Category::Prefetch
                | Category::WindowsLogs
                | Category::LargeFile
                | Category::Duplicate
                | Category::RecycleBin
        )
    }

    pub fn icon(self) -> &'static str {
        match self {
            Category::WindowsTemp | Category::UserTemp => "temp",
            Category::BrowserCache => "browser",
            Category::ThumbnailCache => "image",
            Category::CrashDumps => "crash",
            Category::WindowsLogs => "log",
            Category::ErrorReports => "alert",
            Category::WindowsUpdateCache | Category::DeliveryOptimization => "update",
            Category::Prefetch => "clock",
            Category::RecycleBin => "trash",
            Category::LargeFile => "file",
            Category::Duplicate => "copy",
        }
    }
}

/// A single candidate item discovered by a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub path: PathBuf,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub category: Category,
    /// Friendly bucket used for grouping in the results view (e.g. "Google Chrome").
    pub group: String,
    /// Short explanation of why this item is listed.
    pub note: String,
    /// True when the item requires a special cleaner (for example the Recycle Bin).
    pub special: bool,
}

impl Finding {
    pub fn key(&self) -> String {
        self.path
            .to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase()
            .trim_end_matches('\\')
            .to_string()
    }

    pub fn location(&self) -> String {
        self.path
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| self.path.to_string_lossy().to_string())
    }

    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| self.path.to_string_lossy().to_string())
    }
}

/// Aggregated category totals produced by a scan.
#[derive(Debug, Clone)]
pub struct CategoryTotal {
    pub category: Category,
    pub bytes: u64,
    pub items: usize,
}

/// Live progress emitted while a scan or clean job runs.
#[derive(Debug, Clone, Default)]
pub struct ScanProgress {
    pub stage: String,
    pub files: u64,
    pub dirs: u64,
    pub bytes_found: u64,
    pub current: String,
    /// Known percentage when the underlying operation reports one (Defender scans).
    pub percent: Option<f32>,
}

/// Final outcome of a scan job.
#[derive(Debug, Clone, Default)]
pub struct ScanSummary {
    pub files_scanned: u64,
    pub dirs_scanned: u64,
    pub errors: u64,
    pub bytes_found: u64,
    pub items_found: usize,
    pub elapsed: std::time::Duration,
    pub cancelled: bool,
    pub categories: Vec<CategoryTotal>,
}

/// Messages sent from background scan jobs to the UI thread.
#[derive(Debug)]
pub enum ScanEvent {
    Progress(ScanProgress),
    Findings(Vec<Finding>),
    Stage(String),
    Done(ScanSummary),
    Failed(String),
}

/// Result of deleting a set of findings.
#[derive(Debug, Clone, Default)]
pub struct CleanReport {
    pub removed: usize,
    pub skipped: usize,
    pub failed: usize,
    pub bytes_freed: u64,
    pub errors: Vec<(PathBuf, String)>,
    pub skipped_items: Vec<(PathBuf, String)>,
    /// Paths that were actually deleted, used to update the results list.
    pub removed_items: Vec<PathBuf>,
    pub elapsed: std::time::Duration,
}

/// Progress for a cleaning job.
#[derive(Debug, Clone, Default)]
pub struct CleanProgress {
    pub done: usize,
    pub total: usize,
    pub bytes_freed: u64,
    pub current: String,
}

#[derive(Debug)]
pub enum CleanEvent {
    Progress(CleanProgress),
    Done(CleanReport),
    Failed(String),
}

/// A fixed or removable volume.
#[derive(Debug, Clone)]
pub struct Volume {
    pub mount: String,
    pub label: String,
    pub total: u64,
    pub free: u64,
    pub fixed: bool,
}

impl Volume {
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.free)
    }
}

/// Windows Defender status snapshot.
#[derive(Debug, Clone, Default)]
pub struct DefenderStatus {
    pub available: bool,
    pub antivirus_enabled: bool,
    pub realtime_enabled: bool,
    pub antispyware_enabled: bool,
    pub signature_version: String,
    pub signature_age_days: Option<i64>,
    pub last_quick_scan: Option<String>,
    pub last_full_scan: Option<String>,
    pub tamper_protection: bool,
    pub error: Option<String>,
}

/// A detected threat (from Defender detections, or local heuristics).
#[derive(Debug, Clone)]
pub struct Threat {
    pub id: i64,
    pub name: String,
    pub severity: ThreatSeverity,
    pub status: String,
    pub path: String,
    pub detected_at: String,
    pub source: ThreatSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Severe,
}

impl ThreatSeverity {
    pub fn label(self) -> &'static str {
        match self {
            ThreatSeverity::Low => "Low",
            ThreatSeverity::Medium => "Medium",
            ThreatSeverity::High => "High",
            ThreatSeverity::Severe => "Severe",
        }
    }

    pub fn from_name(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        if lower.contains("severe") {
            ThreatSeverity::Severe
        } else if lower.contains("high") {
            ThreatSeverity::High
        } else if lower.contains("moderate") || lower.contains("medium") {
            ThreatSeverity::Medium
        } else {
            ThreatSeverity::Low
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatSource {
    Defender,
    Heuristic,
}

/// A startup program, service-ish entry or scheduled task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupKind {
    RegistryRun,
    StartupFolder,
    ScheduledTask,
}

impl StartupKind {
    pub fn label(&self) -> &'static str {
        match self {
            StartupKind::RegistryRun => "Registry",
            StartupKind::StartupFolder => "Startup folder",
            StartupKind::ScheduledTask => "Task",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StartupEntry {
    pub id: String,
    pub name: String,
    pub command: String,
    pub location: String,
    pub kind: StartupKind,
    pub enabled: bool,
    pub scope: String,
    pub suspicious: bool,
    pub reason: String,
    /// Registry hive hint for reversible disabling (`HKCU`, `HKLM`, `HKLM32`).
    pub hive: String,
    /// Registry value name for reversible disabling.
    pub value_name: String,
    /// Registry key path for reversible disabling.
    pub key_path: String,
}

/// A running process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe: Option<PathBuf>,
    pub memory: u64,
    pub cpu: f32,
    pub status: String,
    pub suspicious: bool,
    pub reason: String,
}

/// System wide counters for the monitor.
#[derive(Debug, Clone, Default)]
pub struct SystemStats {
    pub cpu: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub process_count: usize,
    pub thread_count: usize,
    pub uptime_secs: u64,
    pub elevated: bool,
}

impl SystemStats {
    pub fn mem_percent(&self) -> f32 {
        crate::format::percent(self.mem_used, self.mem_total)
    }
}

/// An application registered in Windows' uninstall registry.
#[derive(Debug, Clone)]
pub struct InstalledApp {
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub install_date: String,
    pub uninstall: String,
    pub size: u64,
}

/// Which Microsoft Defender scan to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefenderScanKind {
    Quick,
    Full,
    Custom(PathBuf),
}

impl DefenderScanKind {
    pub fn label(&self) -> &'static str {
        match self {
            DefenderScanKind::Quick => "Quick scan",
            DefenderScanKind::Full => "Full system scan",
            DefenderScanKind::Custom(_) => "Custom scan",
        }
    }
}

/// Outcome of a Defender command line scan.
#[derive(Debug, Clone, Default)]
pub struct DefenderScanOutcome {
    pub exit_code: i32,
    pub cancelled: bool,
    pub output_tail: String,
}

/// A recommended, quantified cleanup action for the storage page.
#[derive(Debug, Clone)]
pub struct Recommendation {
    pub title: String,
    pub detail: String,
    pub bytes: u64,
    pub action: RecommendationAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendationAction {
    OpenQuickClean,
    OpenDeepClean,
    OpenLargeFiles,
    OpenRecycleBin,
    OpenStorageAnalyzer,
}

/// Health indicators shown on the dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Good,
    Warning,
    Critical,
}

#[derive(Debug, Clone)]
pub struct HealthCheck {
    pub title: String,
    pub detail: String,
    pub state: HealthState,
    /// Points deducted from the 100 point score.
    pub deduction: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_selection_is_conservative() {
        assert!(Category::UserTemp.default_selected());
        assert!(Category::BrowserCache.default_selected());
        assert!(!Category::RecycleBin.default_selected());
        assert!(!Category::LargeFile.default_selected());
        assert!(!Category::Prefetch.default_selected());
        assert!(!Category::WindowsLogs.default_selected());
    }

    #[test]
    fn severity_parsing() {
        assert_eq!(ThreatSeverity::from_name("Severe"), ThreatSeverity::Severe);
        assert_eq!(
            ThreatSeverity::from_name("Moderate"),
            ThreatSeverity::Medium
        );
        assert_eq!(ThreatSeverity::from_name("Low"), ThreatSeverity::Low);
    }

    #[test]
    fn finding_key_is_case_insensitive() {
        let finding = Finding {
            path: PathBuf::from("C:/Windows/Temp/A.tmp"),
            size: 4,
            modified: None,
            category: Category::WindowsTemp,
            group: "Windows".into(),
            note: String::new(),
            special: false,
        };
        assert_eq!(finding.key(), r"c:\windows\temp\a.tmp");
        assert_eq!(finding.name(), "A.tmp");
        assert_eq!(finding.location(), r"C:/Windows/Temp");
    }
}
