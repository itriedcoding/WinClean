//! Windows integration: elevation, drives, Recycle Bin, shell helpers and
//! scheduled maintenance. All Win32 calls are confined to this module tree.

pub(crate) mod defender;
pub(crate) mod processes;
pub(crate) mod registry;

pub use defender::*;
pub use processes::*;
pub use registry::*;

use crate::core::paths;
use crate::core::scanner::RecycleBinInfo;
use crate::format;
use crate::model::Volume;
use std::ffi::OsStr;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::Storage::FileSystem::{
    GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDriveStringsW, GetVolumeInformationW,
};
use windows::Win32::System::SystemInformation::{
    GetLocalTime, GlobalMemoryStatusEx, MEMORYSTATUSEX,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::{
    SHEmptyRecycleBinW, SHQueryRecycleBinW, ShellExecuteW, SHERB_NOCONFIRMATION,
    SHERB_NOPROGRESSUI, SHERB_NOSOUND, SHQUERYRBINFO,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
use winreg::RegKey;

pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const MAINTENANCE_TASK: &str = "WinClean Maintenance";

// ---------------------------------------------------------------------------
// String / command helpers
// ---------------------------------------------------------------------------

pub(crate) fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub(crate) fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub(crate) fn pcw(buffer: &[u16]) -> PCWSTR {
    PCWSTR(buffer.as_ptr())
}

pub(crate) struct CommandOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn tail(&self) -> String {
        let text = if self.stderr.trim().is_empty() {
            &self.stdout
        } else {
            &self.stderr
        };
        format::ellipsize(text.trim(), 400)
    }
}

/// Runs a program with hidden console, piped output and a hard timeout.
pub(crate) fn run_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<CommandOutput, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|err| format!("Could not start {program}: {err}"))?;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_reader = stdout_pipe.map(|mut pipe| {
        thread::spawn(move || {
            let mut buffer = Vec::new();
            let _ = pipe.read_to_end(&mut buffer);
            String::from_utf8_lossy(&buffer).to_string()
        })
    });
    let stderr_reader = stderr_pipe.map(|mut pipe| {
        thread::spawn(move || {
            let mut buffer = Vec::new();
            let _ = pipe.read_to_end(&mut buffer);
            String::from_utf8_lossy(&buffer).to_string()
        })
    });

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(err) => return Err(format!("{program} failed: {err}")),
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "{program} did not finish within {} seconds",
                timeout.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(40));
    };

    let stdout = stdout_reader
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let stderr = stderr_reader
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();

    Ok(CommandOutput {
        code: status.code().unwrap_or(-1),
        stdout: strip_nuls(&stdout),
        stderr: strip_nuls(&stderr),
    })
}

fn strip_nuls(text: &str) -> String {
    text.replace('\0', "")
}

/// Runs a PowerShell snippet and returns its trimmed standard output.
pub(crate) fn powershell(script: &str) -> Result<String, String> {
    let wrapped = format!(
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $ProgressPreference = 'SilentlyContinue'; {script}"
    );
    let output = run_command(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &wrapped,
        ],
        Duration::from_secs(35),
    )?;
    if output.code != 0 && output.stdout.trim().is_empty() {
        let detail = output.tail();
        return Err(if detail.is_empty() {
            format!("PowerShell exited with code {}", output.code)
        } else {
            detail
        });
    }
    Ok(output.stdout.trim().to_string())
}

pub(crate) unsafe fn shell_execute(
    verb: &str,
    file: &str,
    params: Option<&str>,
) -> Result<(), String> {
    let verb_w = wide(verb);
    let file_w = wide(file);
    let params_w = params.map(wide);
    let param_ptr = params_w
        .as_ref()
        .map(|buffer| pcw(buffer))
        .unwrap_or(PCWSTR::null());
    let result = ShellExecuteW(
        HWND::default(),
        pcw(&verb_w),
        pcw(&file_w),
        param_ptr,
        PCWSTR::null(),
        SW_SHOWNORMAL,
    );
    let code = result.0 as isize;
    if code > 32 {
        Ok(())
    } else {
        Err(format!(
            "Windows rejected the request (ShellExecute code {code})"
        ))
    }
}

pub fn open_url(url: &str) -> Result<(), String> {
    unsafe { shell_execute("open", url, None) }
}

pub fn open_folder(path: &Path) -> Result<(), String> {
    let existing = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(path).to_path_buf()
    };
    Command::new("explorer.exe")
        .arg(&existing)
        .spawn()
        .map(|_| ())
        .map_err(|err| format!("Could not open {}: {err}", existing.display()))
}

pub fn reveal_in_explorer(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return open_folder(path);
    }
    // `explorer.exe` needs the literal `/select,"<path>"` command line. Passing
    // the whole string as a single escaped argument makes Explorer open the wrong
    // folder (or Documents), so hand it to the process unquoted via raw_arg.
    let argument = format!("/select,\"{}\"", path.display());
    Command::new("explorer.exe")
        .raw_arg(argument)
        .spawn()
        .map(|_| ())
        .map_err(|err| format!("Could not reveal {}: {err}", path.display()))
}

// ---------------------------------------------------------------------------
// Elevation
// ---------------------------------------------------------------------------

pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

pub fn relaunch_elevated() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|err| format!("Cannot locate WinClean: {err}"))?;
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().to_string())
        .collect();
    let params = args
        .iter()
        .map(|arg| {
            if arg.contains(' ') && !arg.starts_with('"') {
                format!("\"{arg}\"")
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    unsafe {
        shell_execute(
            "runas",
            &exe.to_string_lossy(),
            if params.is_empty() {
                None
            } else {
                Some(&params)
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Machine identity and time
// ---------------------------------------------------------------------------

pub fn computer_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".to_string())
}

pub fn user_name() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "User".to_string())
}

pub fn local_offset_seconds() -> i64 {
    let local = unsafe { GetLocalTime() };
    let local_unix = format::unix_from_civil(
        local.wYear as i32,
        local.wMonth as u32,
        local.wDay as u32,
        local.wHour as u32,
        local.wMinute as u32,
        local.wSecond as u32,
    );
    let utc_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let offset = local_unix - utc_unix;
    ((offset as f64) / 60.0).round() as i64 * 60
}

pub fn memory_status() -> (u64, u64) {
    unsafe {
        let mut status = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        if GlobalMemoryStatusEx(&mut status).is_ok() {
            (
                status.ullTotalPhys.saturating_sub(status.ullAvailPhys),
                status.ullTotalPhys,
            )
        } else {
            (0, 0)
        }
    }
}

// ---------------------------------------------------------------------------
// Drives
// ---------------------------------------------------------------------------

pub fn volumes() -> Vec<Volume> {
    let mut buffer = vec![0u16; 512];
    let length = unsafe { GetLogicalDriveStringsW(Some(&mut buffer)) } as usize;
    if length == 0 {
        return Vec::new();
    }
    let mut volumes = Vec::new();
    let mut start = 0usize;
    for index in 0..length.min(buffer.len()) {
        if buffer[index] != 0 {
            continue;
        }
        if index > start {
            let root = String::from_utf16_lossy(&buffer[start..index]);
            if let Some(volume) = volume_info(&root) {
                volumes.push(volume);
            }
        }
        start = index + 1;
    }
    volumes
}

fn volume_info(root: &str) -> Option<Volume> {
    let root_w = wide(root);
    let drive_type = unsafe { GetDriveTypeW(pcw(&root_w)) };
    if !matches!(drive_type, DRIVE_FIXED | DRIVE_REMOVABLE) {
        return None;
    }
    let mut available = 0u64;
    let mut total = 0u64;
    let mut total_free = 0u64;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            pcw(&root_w),
            Some(&mut available),
            Some(&mut total),
            Some(&mut total_free),
        )
    };
    if ok.is_err() || total == 0 {
        return None;
    }
    let _ = available;

    let mut label_buffer = vec![0u16; 128];
    let mut filesystem_buffer = vec![0u16; 64];
    let has_label = unsafe {
        GetVolumeInformationW(
            pcw(&root_w),
            Some(&mut label_buffer),
            None,
            None,
            None,
            Some(&mut filesystem_buffer),
        )
    }
    .is_ok();
    let label = if has_label {
        String::from_utf16_lossy(&label_buffer)
            .trim_end_matches('\0')
            .trim()
            .to_string()
    } else {
        String::new()
    };

    Some(Volume {
        mount: root.to_string(),
        label: if label.is_empty() {
            "Local Disk".to_string()
        } else {
            label
        },
        total,
        free: total_free,
        fixed: drive_type == DRIVE_FIXED,
    })
}

// ---------------------------------------------------------------------------
// Recycle Bin
// ---------------------------------------------------------------------------

pub fn recycle_bin_info() -> Option<RecycleBinInfo> {
    unsafe {
        let mut info = SHQUERYRBINFO {
            cbSize: std::mem::size_of::<SHQUERYRBINFO>() as u32,
            i64Size: 0,
            i64NumItems: 0,
        };
        if SHQueryRecycleBinW(PCWSTR::null(), &mut info).is_ok() && info.i64Size > 0 {
            return Some(RecycleBinInfo {
                bytes: info.i64Size as u64,
                items: info.i64NumItems.max(0) as u64,
            });
        }
    }
    None
}

pub fn empty_recycle_bin() -> Result<u64, String> {
    let before = recycle_bin_info().map(|info| info.bytes).unwrap_or(0);
    let flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND;
    unsafe {
        SHEmptyRecycleBinW(HWND::default(), PCWSTR::null(), flags)
            .map_err(|err| format!("Windows could not empty the Recycle Bin: {err}"))?;
    }
    let after = recycle_bin_info().map(|info| info.bytes).unwrap_or(0);
    Ok(before.saturating_sub(after))
}

// ---------------------------------------------------------------------------
// Autostart and scheduled maintenance
// ---------------------------------------------------------------------------

pub fn autostart_enabled() -> bool {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(RUN_KEY, KEY_READ)
        .and_then(|key| key.get_value::<String, _>("WinClean"))
        .is_ok()
}

pub fn set_autostart(enabled: bool) -> Result<(), String> {
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(RUN_KEY)
        .map_err(|err| format!("Cannot open the autostart registry key: {err}"))?;
    if enabled {
        let exe =
            std::env::current_exe().map_err(|err| format!("Cannot locate WinClean: {err}"))?;
        key.set_value("WinClean", &format!("\"{}\"", exe.display()))
            .map_err(|err| format!("Cannot enable autostart: {err}"))?;
    } else {
        match key.delete_value("WinClean") {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(format!("Cannot disable autostart: {err}")),
        }
    }
    Ok(())
}

pub fn maintenance_task_installed() -> bool {
    run_command(
        "schtasks.exe",
        &["/Query", "/TN", MAINTENANCE_TASK],
        Duration::from_secs(12),
    )
    .map(|output| output.code == 0)
    .unwrap_or(false)
}

pub fn set_maintenance_task(enabled: bool) -> Result<(), String> {
    if enabled {
        let exe =
            std::env::current_exe().map_err(|err| format!("Cannot locate WinClean: {err}"))?;
        let command = format!("\"{}\" --maintenance", exe.display());
        let output = run_command(
            "schtasks.exe",
            &[
                "/Create",
                "/TN",
                MAINTENANCE_TASK,
                "/TR",
                &command,
                "/SC",
                "WEEKLY",
                "/D",
                "SUN",
                "/ST",
                "03:00",
                "/F",
            ],
            Duration::from_secs(30),
        )?;
        if output.code == 0 {
            Ok(())
        } else {
            Err(format!(
                "Task Scheduler refused the request: {}",
                output.tail()
            ))
        }
    } else {
        let output = run_command(
            "schtasks.exe",
            &["/Delete", "/TN", MAINTENANCE_TASK, "/F"],
            Duration::from_secs(30),
        )?;
        if output.code == 0 || !maintenance_task_installed() {
            Ok(())
        } else {
            Err(format!(
                "Task Scheduler refused the request: {}",
                output.tail()
            ))
        }
    }
}

/// Opens the folder that holds WinClean's own data.
pub fn open_app_data() -> Result<(), String> {
    open_folder(&paths::app_data_dir())
}

/// Absolute path of the running executable.
pub fn current_executable() -> Option<PathBuf> {
    std::env::current_exe().ok()
}
