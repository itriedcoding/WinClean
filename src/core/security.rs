//! Local, offline security heuristics.
//!
//! These rules never execute a file and never upload anything. They flag the
//! patterns most commonly used by commodity malware and leave the final verdict
//! to Microsoft Defender, which is the authoritative engine on the machine.

use crate::format;
use crate::model::{ProcessInfo, StartupEntry, Threat, ThreatSeverity, ThreatSource};
use std::path::Path;
use std::time::SystemTime;

/// Windows binaries that malware frequently impersonates.
pub const SYSTEM_BINARIES: [&str; 11] = [
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "explorer.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "dwm.exe",
];

const EXECUTABLE_EXTENSIONS: [&str; 9] =
    ["exe", "scr", "pif", "bat", "cmd", "vbs", "js", "jse", "ps1"];

fn is_executable(path: &Path) -> bool {
    let ext = format::extension(path);
    EXECUTABLE_EXTENSIONS.contains(&ext.as_str())
}

fn lower(text: &str) -> String {
    text.to_ascii_lowercase().replace('/', "\\")
}

fn path_of_command(command: &str) -> String {
    let trimmed = command.trim();
    let cleaned = if let Some(rest) = trimmed.strip_prefix('"') {
        match rest.find('"') {
            Some(end) => rest[..end].to_string(),
            None => rest.to_string(),
        }
    } else {
        trimmed
            .split(" -")
            .next()
            .unwrap_or(trimmed)
            .trim()
            .to_string()
    };
    lower(&cleaned)
}

fn is_system_binary_path(path: &str) -> bool {
    let system32 = lower(
        &crate::core::paths::windows_dir()
            .join("System32")
            .to_string_lossy(),
    );
    let syswow64 = lower(
        &crate::core::paths::windows_dir()
            .join("SysWOW64")
            .to_string_lossy(),
    );
    path.starts_with(&format!("{system32}\\")) || path.starts_with(&format!("{syswow64}\\"))
}

/// Double extensions such as `invoice.pdf.exe`.
fn has_double_extension(path: &str) -> bool {
    let file_name = path.rsplit('\\').next().unwrap_or(path);
    let parts: Vec<&str> = file_name.split('.').collect();
    if parts.len() < 3 {
        return false;
    }
    let last = parts[parts.len() - 1].to_ascii_lowercase();
    let previous = parts[parts.len() - 2].to_ascii_lowercase();
    let exec = EXECUTABLE_EXTENSIONS.contains(&last.as_str());
    let decoy = matches!(
        previous.as_str(),
        "pdf"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "txt"
            | "zip"
            | "rar"
            | "mp4"
            | "mp3"
            | "csv"
    );
    exec && decoy
}

/// Evaluates one startup entry. Returns the severity and a short explanation.
pub fn startup_risk(name: &str, command: &str) -> Option<(ThreatSeverity, String)> {
    let command_lower = lower(command);
    let path = path_of_command(command);
    let file_name = path.rsplit('\\').next().unwrap_or(&path).to_string();

    if command_lower.contains("-enc")
        || command_lower.contains("-encodedcommand")
        || command_lower.contains("frombase64string")
    {
        return Some((
            ThreatSeverity::High,
            "Runs an encoded or obfuscated command".to_string(),
        ));
    }
    if command_lower.contains("downloadstring")
        || command_lower.contains("invoke-webrequest")
        || command_lower.contains("urlcache")
        || command_lower.contains("bitsadmin /transfer")
        || command_lower.contains("mshta http")
        || command_lower.contains("rundll32 javascript:")
    {
        return Some((
            ThreatSeverity::High,
            "Downloads and runs code from the internet".to_string(),
        ));
    }
    if is_executable(Path::new(&path)) {
        if path.contains("\\temp\\") || path.contains("\\tmp\\") {
            return Some((
                ThreatSeverity::High,
                "Executable starts from a temporary folder".to_string(),
            ));
        }
        if path.contains("\\downloads\\") {
            return Some((
                ThreatSeverity::Medium,
                "Executable starts from the Downloads folder".to_string(),
            ));
        }
        if SYSTEM_BINARIES.contains(&file_name.as_str()) && !is_system_binary_path(&path) {
            return Some((
                ThreatSeverity::High,
                format!("{file_name} is impersonated outside System32"),
            ));
        }
    }
    if has_double_extension(&path) {
        return Some((
            ThreatSeverity::High,
            "Double file extension used to disguise an executable".to_string(),
        ));
    }
    if name.to_ascii_lowercase().contains(".pdf")
        || name.to_ascii_lowercase().contains(".jpg")
        || name.to_ascii_lowercase().contains(".doc")
    {
        if is_executable(Path::new(&path)) {
            return Some((
                ThreatSeverity::Medium,
                "Document name points to an executable".to_string(),
            ));
        }
    }
    None
}

/// Evaluates one running process by name and executable location.
pub fn process_risk(name: &str, exe: Option<&Path>) -> Option<String> {
    let exe_path = exe.map(|p| lower(&p.to_string_lossy()));
    let name_lower = name.to_ascii_lowercase();
    if let Some(path) = exe_path {
        if SYSTEM_BINARIES.contains(&name_lower.as_str()) && !is_system_binary_path(&path) {
            return Some(format!(
                "Uses the name of a Windows process but runs from {path}"
            ));
        }
        if path.contains("\\temp\\") || path.contains("\\tmp\\") {
            return Some("Runs from a temporary folder".to_string());
        }
        if has_double_extension(&path) {
            return Some("Double file extension used to disguise an executable".to_string());
        }
        if path.contains("\\downloads\\") && path.ends_with(".exe") {
            return Some("Runs directly from the Downloads folder".to_string());
        }
    }
    None
}

/// Builds heuristic threat entries for the security page.
pub fn heuristic_threats(startups: &[StartupEntry], processes: &[ProcessInfo]) -> Vec<Threat> {
    let mut threats = Vec::new();
    let detected_at = format::date_time(SystemTime::now(), crate::platform::local_offset_seconds());

    for (index, entry) in startups.iter().enumerate() {
        if let Some((severity, reason)) = startup_risk(&entry.name, &entry.command) {
            threats.push(Threat {
                id: -((index as i64) + 1),
                name: format!("Suspicious startup entry: {}", entry.name),
                severity,
                status: reason,
                path: entry.command.clone(),
                detected_at: detected_at.clone(),
                source: ThreatSource::Heuristic,
            });
        }
    }
    for (index, process) in processes.iter().enumerate() {
        if let Some(reason) = process_risk(&process.name, process.exe.as_deref()) {
            threats.push(Threat {
                id: -((index as i64) + 100_000),
                name: format!("Suspicious process: {} (PID {})", process.name, process.pid),
                severity: ThreatSeverity::Medium,
                status: reason,
                path: process
                    .exe
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| process.name.clone()),
                detected_at: detected_at.clone(),
                source: ThreatSource::Heuristic,
            });
        }
    }
    threats
}

/// Sort helper: most severe threats first.
pub fn sort_threats(threats: &mut [Threat]) {
    threats.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.name.cmp(&b.name)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn flags_executables_in_temp() {
        let risk = startup_risk("Updater", r"C:\Users\bob\AppData\Local\Temp\upd.exe");
        let (severity, reason) = risk.expect("temp executable must be flagged");
        assert_eq!(severity, ThreatSeverity::High);
        assert!(reason.contains("temporary"));
    }

    #[test]
    fn flags_encoded_powershell() {
        let risk = startup_risk(
            "WindowsHelper",
            r"powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
        );
        assert!(risk.is_some());
        assert_eq!(risk.unwrap().0, ThreatSeverity::High);
    }

    #[test]
    fn flags_double_extension() {
        let risk = startup_risk("Invoice", r"C:\Users\bob\Downloads\invoice.pdf.exe");
        assert!(risk.is_some());
    }

    #[test]
    fn allows_normal_startup_entries() {
        assert!(startup_risk("Steam", r"C:\Program Files (x86)\Steam\steam.exe").is_none());
        assert!(startup_risk(
            "OneDrive",
            r"C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background"
        )
        .is_none());
    }

    #[test]
    fn flags_masqueraded_system_process() {
        let reason = process_risk(
            "lsass.exe",
            Some(Path::new(r"C:\Users\bob\AppData\Roaming\lsass.exe")),
        );
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("Windows process"));
        assert!(process_risk(
            "lsass.exe",
            Some(Path::new(r"C:\Windows\System32\lsass.exe"))
        )
        .is_none());
    }

    #[test]
    fn builds_heuristic_threats_only_for_risky_entries() {
        let startups = vec![
            StartupEntry {
                id: "a".into(),
                name: "Good".into(),
                command: r"C:\Program Files\Good\good.exe".into(),
                location: "HKCU".into(),
                kind: crate::model::StartupKind::RegistryRun,
                enabled: true,
                scope: "User".into(),
                suspicious: false,
                reason: String::new(),
                hive: "HKCU".into(),
                value_name: "Good".into(),
                key_path: "Run".into(),
            },
            StartupEntry {
                id: "b".into(),
                name: "Bad".into(),
                command: r"C:\Users\bob\AppData\Local\Temp\bad.exe".into(),
                location: "HKCU".into(),
                kind: crate::model::StartupKind::RegistryRun,
                enabled: true,
                scope: "User".into(),
                suspicious: true,
                reason: "temporary".into(),
                hive: "HKCU".into(),
                value_name: "Bad".into(),
                key_path: "Run".into(),
            },
        ];
        let threats = heuristic_threats(&startups, &[]);
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].source, ThreatSource::Heuristic);
        assert!(threats[0].id < 0);
        let _ = PathBuf::new();
    }
}
