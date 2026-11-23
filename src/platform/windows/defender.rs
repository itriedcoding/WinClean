//! Microsoft Defender integration.
//!
//! Scans are delegated to `MpCmdRun.exe` (the same engine the Windows Security
//! UI uses) and results are read back from Defender's own detection store.
//! WinClean never claims a threat was removed without re-querying Defender.

use super::{powershell, run_command, shell_execute, CREATE_NO_WINDOW};
use crate::core::paths;
use crate::format;
use crate::model::{
    DefenderScanKind, DefenderScanOutcome, DefenderStatus, Threat, ThreatSeverity, ThreatSource,
};
use serde_json::Value;
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const STATUS_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop';
$s = Get-MpComputerStatus;
$q = ''; if ($s.QuickScanStartTime) { $q = $s.QuickScanStartTime.ToString('yyyy-MM-dd HH:mm') }
$f = ''; if ($s.FullScanStartTime) { $f = $s.FullScanStartTime.ToString('yyyy-MM-dd HH:mm') }
[pscustomobject]@{
  antivirus = [bool]$s.AntivirusEnabled;
  realtime = [bool]$s.RealTimeProtectionEnabled;
  antispyware = [bool]$s.AntispywareEnabled;
  signature = [string]$s.AntivirusSignatureVersion;
  age = [int]$s.AntivirusSignatureAge;
  quick = [string]$q;
  full = [string]$f;
  tamper = [bool]$s.IsTamperProtected
} | ConvertTo-Json -Compress
"#;

const THREATS_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue';
$threats = @(Get-MpThreat);
$detections = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 200);
$rows = foreach ($d in $detections) {
  $t = $threats | Where-Object { $_.ThreatID -eq $d.ThreatID } | Select-Object -First 1;
  [pscustomobject]@{
    id = [long]$d.ThreatID;
    name = [string]$t.ThreatName;
    severity = [int]$t.SeverityID;
    active = [bool]$t.IsActive;
    status = [int]$d.ThreatStatusErrorCode;
    time = [string]$d.InitialDetectionTime;
    path = [string](@($d.Resources) -join '; ')
  }
}
ConvertTo-Json -InputObject @($rows) -Compress -Depth 3
"#;

pub fn defender_status() -> DefenderStatus {
    match powershell(STATUS_SCRIPT) {
        Ok(text) => match serde_json::from_str::<Value>(text.trim()) {
            Ok(value) => DefenderStatus {
                available: true,
                antivirus_enabled: value["antivirus"].as_bool().unwrap_or(false),
                realtime_enabled: value["realtime"].as_bool().unwrap_or(false),
                antispyware_enabled: value["antispyware"].as_bool().unwrap_or(false),
                signature_version: value["signature"].as_str().unwrap_or_default().to_string(),
                signature_age_days: value["age"].as_i64().map(|age| age.max(0)),
                last_quick_scan: non_empty(value["quick"].as_str()),
                last_full_scan: non_empty(value["full"].as_str()),
                tamper_protection: value["tamper"].as_bool().unwrap_or(false),
                error: None,
            },
            Err(err) => DefenderStatus {
                available: false,
                error: Some(format!("Unexpected Defender response: {err}")),
                ..Default::default()
            },
        },
        Err(err) => DefenderStatus {
            available: false,
            error: Some(err),
            ..Default::default()
        },
    }
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(|text| text.trim())
        .filter(|text| !text.is_empty())
        .map(|text| text.to_string())
}

pub fn defender_threats() -> Result<Vec<Threat>, String> {
    let text = powershell(THREATS_SCRIPT)?;
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }
    let value: Value = serde_json::from_str(trimmed)
        .map_err(|err| format!("Could not read Defender detections: {err}"))?;
    let items: Vec<&Value> = match &value {
        Value::Array(values) => values.iter().collect(),
        Value::Object(_) => vec![&value],
        _ => Vec::new(),
    };
    Ok(items.iter().filter_map(|item| parse_threat(item)).collect())
}

fn parse_threat(item: &Value) -> Option<Threat> {
    let id = item["id"]
        .as_i64()
        .or_else(|| item["id"].as_str().and_then(|text| text.parse().ok()))?;
    let name = item["name"]
        .as_str()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "Unnamed Defender detection".to_string());
    let severity_id = item["severity"].as_i64().unwrap_or(0);
    let severity = match severity_id {
        5 => ThreatSeverity::Severe,
        4 => ThreatSeverity::High,
        2 | 3 => ThreatSeverity::Medium,
        _ => ThreatSeverity::Low,
    };
    let active = item["active"].as_bool().unwrap_or(false);
    let code = item["status"].as_i64().unwrap_or(0);
    let mut status = if active {
        "Active — action required".to_string()
    } else {
        "Handled by Microsoft Defender".to_string()
    };
    if code != 0 {
        status.push_str(&format!(" (code {code})"));
    }
    Some(Threat {
        id,
        name,
        severity,
        status,
        path: item["path"].as_str().unwrap_or_default().to_string(),
        detected_at: item["time"].as_str().unwrap_or_default().to_string(),
        source: ThreatSource::Defender,
    })
}

/// Confirms with Defender whether a threat is still active.
pub fn defender_threat_active(id: i64) -> Result<bool, String> {
    let script = format!(
        "$t = @(Get-MpThreat | Where-Object {{ $_.ThreatID -eq {id} -and $_.IsActive }}); $t.Count"
    );
    let output = powershell(&script)?;
    Ok(output.trim().parse::<i64>().unwrap_or(0) > 0)
}

/// Asks Defender to remove a threat and verifies the outcome with Defender.
pub fn remove_threat(id: i64) -> Result<(), String> {
    if id <= 0 {
        return Err("This entry is a local heuristic, not a Defender detection.".to_string());
    }
    let script = format!("Remove-MpThreat -ThreatID {id} -ErrorAction Stop");
    powershell(&script)?;
    if defender_threat_active(id)? {
        Err(
            "Microsoft Defender still reports this threat as active. Run WinClean as administrator and try again."
                .to_string(),
        )
    } else {
        Ok(())
    }
}

fn mpcmdrun() -> Option<PathBuf> {
    let platform = paths::program_data().join(r"Microsoft\Windows Defender\Platform");
    let mut best: Option<(u64, PathBuf)> = None;
    if let Ok(entries) = std::fs::read_dir(&platform) {
        for entry in entries.flatten() {
            let candidate = entry.path().join("MpCmdRun.exe");
            if !candidate.is_file() {
                continue;
            }
            let key = version_key(&entry.file_name().to_string_lossy());
            if best
                .as_ref()
                .map(|(current, _)| key > *current)
                .unwrap_or(true)
            {
                best = Some((key, candidate));
            }
        }
    }
    if let Some((_, path)) = best {
        return Some(path);
    }
    let legacy = paths::program_files().join(r"Windows Defender\MpCmdRun.exe");
    legacy.is_file().then_some(legacy)
}

fn version_key(text: &str) -> u64 {
    let mut value = 0u64;
    for part in text.split('.').take(4) {
        value = value
            .saturating_mul(100_000)
            .saturating_add(part.parse::<u64>().unwrap_or(0));
    }
    value
}

/// Runs a Defender scan, streaming progress percentages and stage text.
pub fn defender_scan(
    kind: &DefenderScanKind,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(Option<f32>, String),
) -> Result<DefenderScanOutcome, String> {
    let executable = mpcmdrun().ok_or_else(|| {
        "Microsoft Defender's command line scanner (MpCmdRun.exe) was not found. Windows Security may be managed by another antivirus product.".to_string()
    })?;

    let mut command = Command::new(&executable);
    command.arg("-Scan");
    match kind {
        DefenderScanKind::Quick => {
            command.args(["-ScanType", "1"]);
        }
        DefenderScanKind::Full => {
            command.args(["-ScanType", "2"]);
        }
        DefenderScanKind::Custom(path) => {
            command.args(["-ScanType", "3", "-ScanPath"]);
            command.arg(path);
        }
    }

    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|err| format!("Could not start Microsoft Defender: {err}"))?;

    let (tx, rx) = mpsc::channel::<String>();

    let stdout_reader = child.stdout.take().map(|mut pipe| {
        let tx = tx.clone();
        thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            loop {
                match pipe.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        let chunk = String::from_utf8_lossy(&buffer[..read]).to_string();
                        if tx.send(chunk).is_err() {
                            break;
                        }
                    }
                }
            }
        })
    });
    let stderr_reader = child.stderr.take().map(|mut pipe| {
        let tx = tx.clone();
        thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            loop {
                match pipe.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        let chunk = String::from_utf8_lossy(&buffer[..read]).to_string();
                        if tx.send(chunk).is_err() {
                            break;
                        }
                    }
                }
            }
        })
    });
    drop(tx);

    let started = Instant::now();
    let mut percent: Option<f32> = None;
    let mut tail = String::new();
    let mut cancelled = false;
    let mut exit_code = -1;

    loop {
        while let Ok(chunk) = rx.try_recv() {
            tail.push_str(&chunk);
            trim_tail(&mut tail);
            if let Some(found) = parse_percent(&chunk) {
                percent = Some(found);
            }
            progress(percent, last_stage(&tail));
        }

        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            let _ = child.kill();
            if let Ok(status) = child.wait() {
                exit_code = status.code().unwrap_or(-1);
            }
            break;
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code().unwrap_or(-1);
                break;
            }
            Ok(None) => {}
            Err(err) => return Err(format!("Defender scan failed: {err}")),
        }

        if started.elapsed() > Duration::from_secs(4 * 60 * 60) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("The scan exceeded the four hour safety limit.".to_string());
        }
        thread::sleep(Duration::from_millis(140));
    }

    if let Some(reader) = stdout_reader {
        let _ = reader.join();
    }
    if let Some(reader) = stderr_reader {
        let _ = reader.join();
    }
    while let Ok(chunk) = rx.try_recv() {
        tail.push_str(&chunk);
        trim_tail(&mut tail);
        if let Some(found) = parse_percent(&chunk) {
            percent = Some(found);
        }
    }
    progress(percent, last_stage(&tail));

    if cancelled {
        return Ok(DefenderScanOutcome {
            exit_code,
            cancelled: true,
            output_tail: tail,
        });
    }

    match exit_code {
        0 | 2 => Ok(DefenderScanOutcome {
            exit_code,
            cancelled: false,
            output_tail: tail,
        }),
        other => Err(format!(
            "Microsoft Defender returned an error (exit code {other}). {}",
            last_stage(&tail)
        )),
    }
}

fn trim_tail(text: &mut String) {
    let count = text.chars().count();
    if count > 1_500 {
        *text = text.chars().skip(count - 1_500).collect();
    }
}

fn last_stage(text: &str) -> String {
    text.split(['\r', '\n'])
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .last()
        .map(|line| format::ellipsize(line, 140))
        .unwrap_or_else(|| "Scanning…".to_string())
}

fn parse_percent(text: &str) -> Option<f32> {
    let bytes = text.as_bytes();
    let mut found = None;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'%' {
            continue;
        }
        let mut start = index;
        while start > 0 && bytes[start - 1].is_ascii_digit() {
            start -= 1;
        }
        if start == index {
            continue;
        }
        if let Ok(value) = text[start..index].parse::<u32>() {
            if value <= 100 {
                found = Some(value as f32);
            }
        }
    }
    found
}

pub fn update_defender_signatures() -> Result<String, String> {
    let executable = mpcmdrun().ok_or_else(|| {
        "Microsoft Defender's command line scanner (MpCmdRun.exe) was not found.".to_string()
    })?;
    let executable_text = executable.to_string_lossy().to_string();
    let output = run_command(
        &executable_text,
        &["-SignatureUpdate"],
        Duration::from_secs(300),
    )?;
    if output.code == 0 {
        let tail = last_stage(&output.stdout);
        Ok(if tail.starts_with(' ') || tail.is_empty() {
            "Defender signatures are up to date.".to_string()
        } else {
            tail
        })
    } else {
        Err(format!(
            "Signature update failed (exit code {}). {}",
            output.code,
            output.tail()
        ))
    }
}

pub fn open_windows_security() -> Result<(), String> {
    unsafe {
        shell_execute("open", "windowsdefender://threatsettings", None)
            .or_else(|_| shell_execute("open", "ms-settings:windowsdefender", None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_progress_percentages() {
        assert_eq!(parse_percent("Scanning 42%"), Some(42.0));
        assert_eq!(parse_percent("no progress"), None);
        assert_eq!(parse_percent("150%"), None);
        assert_eq!(parse_percent("progress 7%\r"), Some(7.0));
    }

    #[test]
    fn stage_reports_the_last_line() {
        assert_eq!(last_stage("one\r\ntwo  \r\n"), "two");
        assert!(last_stage("").contains("Scanning"));
    }

    #[test]
    fn version_keys_sort_numeric() {
        assert!(version_key("4.18.24090.11") > version_key("4.18.23110.2"));
        assert!(version_key("4.18.1.0") > version_key("4.9.9.9"));
    }
}
