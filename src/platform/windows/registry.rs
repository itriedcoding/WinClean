//! Registry backed features: Windows version, startup entries (with reversible
//! enable/disable through `StartupApproved`) and installed applications.

use super::powershell;
use crate::core::paths;
use crate::core::security;
use crate::model::{InstalledApp, StartupEntry, StartupKind};
use serde_json::Value;
use std::path::Path;
use winreg::enums::*;
use winreg::{RegKey, RegValue};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APPROVED_RUN: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
const APPROVED_RUN32: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";
const APPROVED_STARTUP_FOLDER: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";
const WOW64_RUN: &str = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";

pub fn os_version() -> String {
    let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    else {
        return "Windows".to_string();
    };
    let product: String = key
        .get_value("ProductName")
        .unwrap_or_else(|_| "Windows".to_string());
    let display: String = key.get_value("DisplayVersion").unwrap_or_default();
    let build: String = key.get_value("CurrentBuildNumber").unwrap_or_default();
    let ubr: u32 = key.get_value("UBR").unwrap_or(0);
    let build_number: u32 = build.parse().unwrap_or(0);

    let mut product = product;
    if build_number >= 22_000 {
        product = product.replace("Windows 10", "Windows 11");
    }
    let mut label = product;
    if !display.is_empty() {
        label.push_str(&format!(" · {display}"));
    }
    if build_number > 0 {
        label.push_str(&format!(" · build {build_number}"));
        if ubr > 0 {
            label.push_str(&format!(".{ubr}"));
        }
    }
    label
}

struct RunSource {
    root: isize,
    key_path: &'static str,
    approved_path: &'static str,
    hive: &'static str,
    scope: &'static str,
    flags: u32,
}

fn run_sources() -> Vec<RunSource> {
    vec![
        RunSource {
            root: HKEY_CURRENT_USER,
            key_path: RUN_KEY,
            approved_path: APPROVED_RUN,
            hive: "HKCU",
            scope: "Current user",
            flags: KEY_READ,
        },
        RunSource {
            root: HKEY_LOCAL_MACHINE,
            key_path: RUN_KEY,
            approved_path: APPROVED_RUN,
            hive: "HKLM",
            scope: "All users",
            flags: KEY_READ,
        },
        RunSource {
            root: HKEY_LOCAL_MACHINE,
            key_path: WOW64_RUN,
            approved_path: APPROVED_RUN32,
            hive: "HKLM32",
            scope: "All users (32-bit)",
            flags: KEY_READ,
        },
    ]
}

fn approved_state(approved: &Option<RegKey>, value_name: &str) -> bool {
    let Some(key) = approved else {
        return true;
    };
    match key.get_raw_value(value_name) {
        Ok(raw) => raw
            .bytes
            .first()
            .map(|first| *first == 2 || *first == 6)
            .unwrap_or(true),
        Err(_) => true,
    }
}

fn classify(name: &str, command: &str) -> (bool, String) {
    match security::startup_risk(name, command) {
        Some((severity, reason)) => (true, format!("{} risk · {reason}", severity.label())),
        None => (false, String::new()),
    }
}

pub fn startup_entries() -> Vec<StartupEntry> {
    let mut entries = Vec::new();

    for source in run_sources() {
        let root = RegKey::predef(source.root);
        let Ok(key) = root.open_subkey_with_flags(source.key_path, KEY_READ) else {
            continue;
        };
        let approved = root
            .open_subkey_with_flags(source.approved_path, KEY_READ)
            .ok();
        for item in key.enum_values().flatten() {
            let (value_name, _) = item;
            let command: String = match key.get_value(&value_name) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let command = paths::expand_env(&command);
            if command.trim().is_empty() {
                continue;
            }
            let enabled = approved_state(&approved, &value_name);
            let (suspicious, reason) = classify(&value_name, &command);
            entries.push(StartupEntry {
                id: format!("reg|{}|{}|{}", source.hive, source.key_path, value_name),
                name: value_name.clone(),
                command,
                location: "Registry Run key".to_string(),
                kind: StartupKind::RegistryRun,
                enabled,
                scope: source.scope.to_string(),
                suspicious,
                reason,
                hive: source.hive.to_string(),
                value_name,
                key_path: source.key_path.to_string(),
            });
        }
    }

    let roaming_startup =
        paths::roaming_appdata().join(r"Microsoft\Windows\Start Menu\Programs\Startup");
    entries.extend(startup_folder_entries(
        &roaming_startup,
        HKEY_CURRENT_USER,
        "HKCU",
        "Current user",
    ));

    let common_startup =
        paths::program_data().join(r"Microsoft\Windows\Start Menu\Programs\Startup");
    entries.extend(startup_folder_entries(
        &common_startup,
        HKEY_LOCAL_MACHINE,
        "HKLM",
        "All users",
    ));

    entries.extend(scheduled_task_entries());
    entries.sort_by(|a, b| {
        b.suspicious.cmp(&a.suspicious).then(
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase()),
        )
    });
    entries
}

fn startup_folder_entries(
    dir: &Path,
    hive: isize,
    hive_label: &str,
    scope: &str,
) -> Vec<StartupEntry> {
    let mut entries = Vec::new();
    let Ok(items) = std::fs::read_dir(dir) else {
        return entries;
    };
    let approved = RegKey::predef(hive)
        .open_subkey_with_flags(APPROVED_STARTUP_FOLDER, KEY_READ)
        .ok();
    for item in items.flatten() {
        let path = item.path();
        let file_name = item.file_name().to_string_lossy().to_string();
        if file_name.starts_with('.') || file_name.eq_ignore_ascii_case("desktop.ini") {
            continue;
        }
        let display_name = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().to_string())
            .unwrap_or_else(|| file_name.clone());
        let command = path.to_string_lossy().to_string();
        let enabled = approved_state(&approved, &file_name);
        let (suspicious, reason) = classify(&display_name, &command);
        entries.push(StartupEntry {
            id: format!("folder|{hive_label}|{file_name}"),
            name: display_name,
            command,
            location: format!("Startup folder · {}", dir.display()),
            kind: StartupKind::StartupFolder,
            enabled,
            scope: scope.to_string(),
            suspicious,
            reason,
            hive: hive_label.to_string(),
            value_name: file_name,
            key_path: String::new(),
        });
    }
    entries
}

fn scheduled_task_entries() -> Vec<StartupEntry> {
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue';
$items = @(Get-ScheduledTask | Where-Object {
    $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' -and
    ($_.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' -or $_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' })
} | Select-Object -First 40);
$rows = foreach ($task in $items) {
    [pscustomobject]@{
        name = [string]$task.TaskName;
        path = [string]$task.TaskPath;
        state = [string]$task.State;
        action = [string](@($task.Actions)[0].Execute)
    }
}
ConvertTo-Json -InputObject @($rows) -Compress -Depth 3
"#;
    let Ok(text) = powershell(script) else {
        return Vec::new();
    };
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Vec::new();
    }
    let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
        return Vec::new();
    };
    let items: Vec<Value> = match value {
        Value::Array(values) => values,
        other => vec![other],
    };
    let mut entries = Vec::new();
    for item in items {
        let name = item["name"].as_str().unwrap_or_default().to_string();
        if name.is_empty() {
            continue;
        }
        let task_path = item["path"].as_str().unwrap_or("\\").to_string();
        let action = item["action"].as_str().unwrap_or_default().to_string();
        let state = item["state"].as_str().unwrap_or("Ready").to_string();
        let command = if action.is_empty() {
            format!("Scheduled task {task_path}{name}")
        } else {
            action.clone()
        };
        let (mut suspicious, mut reason) = classify(&name, &command);
        if !suspicious && !action.is_empty() {
            let lower = action.to_ascii_lowercase().replace('/', "\\");
            if lower.contains("\\temp\\") || lower.contains("\\tmp\\") {
                suspicious = true;
                reason = "High risk · Task runs an executable from a temporary folder".to_string();
            }
        }
        entries.push(StartupEntry {
            id: format!("task|{task_path}{name}"),
            name,
            command,
            location: format!("Scheduled task · {task_path}"),
            kind: StartupKind::ScheduledTask,
            enabled: state != "Disabled",
            scope: "System".to_string(),
            suspicious,
            reason,
            hive: "TASK".to_string(),
            value_name: String::new(),
            key_path: task_path,
        });
    }
    entries
}

fn approval_bytes(enabled: bool) -> RegValue {
    let mut bytes = vec![if enabled { 2u8 } else { 3u8 }];
    bytes.extend_from_slice(&[0u8; 11]);
    RegValue {
        bytes,
        vtype: REG_BINARY,
    }
}

pub fn set_startup_enabled(entry: &StartupEntry, enabled: bool) -> Result<(), String> {
    match entry.kind {
        StartupKind::RegistryRun => {
            let (hive, approved_path) = match entry.hive.as_str() {
                "HKLM" => (HKEY_LOCAL_MACHINE, APPROVED_RUN),
                "HKLM32" => (HKEY_LOCAL_MACHINE, APPROVED_RUN32),
                _ => (HKEY_CURRENT_USER, APPROVED_RUN),
            };
            let (key, _) = RegKey::predef(hive)
                .create_subkey_with_flags(approved_path, KEY_SET_VALUE | KEY_READ)
                .map_err(|err| {
                    format!(
                        "Cannot update startup approval (administrator rights may be required): {err}"
                    )
                })?;
            key.set_raw_value(&entry.value_name, &approval_bytes(enabled))
                .map_err(|err| format!("Cannot save the startup state: {err}"))?;
            Ok(())
        }
        StartupKind::StartupFolder => {
            let hive = if entry.hive == "HKLM" {
                HKEY_LOCAL_MACHINE
            } else {
                HKEY_CURRENT_USER
            };
            let (key, _) = RegKey::predef(hive)
                .create_subkey_with_flags(APPROVED_STARTUP_FOLDER, KEY_SET_VALUE | KEY_READ)
                .map_err(|err| {
                    format!(
                        "Cannot update startup approval (administrator rights may be required): {err}"
                    )
                })?;
            key.set_raw_value(&entry.value_name, &approval_bytes(enabled))
                .map_err(|err| format!("Cannot save the startup state: {err}"))?;
            Ok(())
        }
        StartupKind::ScheduledTask => Err(
            "Scheduled tasks are managed by Task Scheduler and are listed for information only."
                .to_string(),
        ),
    }
}

pub fn installed_apps() -> Vec<InstalledApp> {
    let mut apps = Vec::new();
    collect_apps(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        KEY_READ | KEY_WOW64_64KEY,
        &mut apps,
    );
    collect_apps(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        KEY_READ | KEY_WOW64_32KEY,
        &mut apps,
    );
    collect_apps(
        HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        KEY_READ,
        &mut apps,
    );

    apps.sort_by(|a, b| {
        b.size.cmp(&a.size).then(
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase()),
        )
    });
    let mut seen = std::collections::HashSet::new();
    apps.retain(|app| seen.insert(app.name.to_ascii_lowercase()));
    apps
}

fn collect_apps(root: isize, path: &str, flags: u32, out: &mut Vec<InstalledApp>) {
    let Ok(uninstall) = RegKey::predef(root).open_subkey_with_flags(path, flags) else {
        return;
    };
    for name in uninstall.enum_keys().flatten() {
        let Ok(key) = uninstall.open_subkey_with_flags(&name, flags) else {
            continue;
        };
        let display: String = key.get_value("DisplayName").unwrap_or_default();
        let display = display.trim().to_string();
        if display.is_empty() {
            continue;
        }
        let system_component: u32 = key.get_value("SystemComponent").unwrap_or(0);
        if system_component == 1 {
            continue;
        }
        if key.get_value::<String, _>("ParentKeyName").is_ok() {
            continue;
        }
        let size_kb: u32 = key.get_value("EstimatedSize").unwrap_or(0);
        out.push(InstalledApp {
            name: display,
            publisher: key.get_value("Publisher").unwrap_or_default(),
            version: key.get_value("DisplayVersion").unwrap_or_default(),
            install_date: key.get_value("InstallDate").unwrap_or_default(),
            uninstall: key.get_value("UninstallString").unwrap_or_default(),
            size: size_kb as u64 * 1024,
        });
    }
}
