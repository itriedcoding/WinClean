//! Process sampling and control via the Tool Help API and PSAPI.

use super::{is_elevated, memory_status};
use crate::model::{ProcessInfo, SystemStats};
use crate::platform::ProcessSample;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, FILETIME};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::Win32::System::Threading::{
    GetProcessTimes, GetSystemTimes, OpenProcess, QueryFullProcessImageNameW, TerminateProcess,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};

fn filetime_to_u64(time: FILETIME) -> u64 {
    (time.dwHighDateTime as u64) << 32 | time.dwLowDateTime as u64
}

/// Stateful process sampler. CPU usage is a delta between two samples.
pub struct ProcessSampler {
    previous_cpu: HashMap<u32, u64>,
    exe_cache: HashMap<u32, Option<PathBuf>>,
    previous_total: u64,
    previous_idle: u64,
    system_cpu: f32,
}

impl ProcessSampler {
    pub fn new() -> Self {
        Self {
            previous_cpu: HashMap::new(),
            exe_cache: HashMap::new(),
            previous_total: 0,
            previous_idle: 0,
            system_cpu: 0.0,
        }
    }

    pub fn sample(&mut self) -> ProcessSample {
        let (kernel, user, idle) = system_times();
        let total = kernel.saturating_add(user);
        let delta_total = total.saturating_sub(self.previous_total);
        let delta_idle = idle.saturating_sub(self.previous_idle);
        if self.previous_total > 0 && delta_total > 0 {
            self.system_cpu =
                (delta_total.saturating_sub(delta_idle) as f64 / delta_total as f64 * 100.0) as f32;
        }
        self.previous_total = total;
        self.previous_idle = idle;

        let mut next_cpu: HashMap<u32, u64> = HashMap::new();
        let mut processes: Vec<ProcessInfo> = Vec::new();
        let mut thread_count = 0usize;

        unsafe {
            if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                let mut entry = PROCESSENTRY32W {
                    dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                    ..Default::default()
                };
                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        let pid = entry.th32ProcessID;
                        if pid != 0 {
                            let name_slice = &entry.szExeFile;
                            let length = name_slice
                                .iter()
                                .position(|ch| *ch == 0)
                                .unwrap_or(name_slice.len());
                            let name = String::from_utf16_lossy(&name_slice[..length]);
                            thread_count += entry.cntThreads as usize;

                            let (cpu_time, memory, exe_path) =
                                process_details(pid, &mut self.exe_cache);
                            let previous = self.previous_cpu.get(&pid).copied().unwrap_or(cpu_time);
                            let delta = cpu_time.saturating_sub(previous);
                            let cpu = if delta_total > 0 {
                                (delta as f64 / delta_total as f64 * 100.0) as f32
                            } else {
                                0.0
                            };
                            next_cpu.insert(pid, cpu_time);
                            let risk =
                                crate::core::security::process_risk(&name, exe_path.as_deref());
                            processes.push(ProcessInfo {
                                pid,
                                name,
                                exe: exe_path,
                                memory,
                                cpu,
                                status: if pid <= 4 {
                                    "System".to_string()
                                } else {
                                    "Running".to_string()
                                },
                                suspicious: risk.is_some(),
                                reason: risk.unwrap_or_default(),
                            });
                        }
                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snapshot);
            }
        }

        self.previous_cpu = next_cpu;
        let active_pids: HashSet<u32> = processes.iter().map(|process| process.pid).collect();
        self.exe_cache.retain(|pid, _| active_pids.contains(pid));

        processes.sort_by(|a, b| {
            b.cpu
                .partial_cmp(&a.cpu)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.memory.cmp(&a.memory))
        });

        let (mem_used, mem_total) = memory_status();
        let stats = SystemStats {
            cpu: self.system_cpu,
            mem_used,
            mem_total,
            process_count: processes.len(),
            thread_count,
            uptime_secs: unsafe { GetTickCount64() } / 1000,
            elevated: is_elevated(),
        };

        ProcessSample { processes, stats }
    }
}

impl Default for ProcessSampler {
    fn default() -> Self {
        Self::new()
    }
}

fn system_times() -> (u64, u64, u64) {
    unsafe {
        let mut idle = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)).is_ok() {
            (
                filetime_to_u64(kernel),
                filetime_to_u64(user),
                filetime_to_u64(idle),
            )
        } else {
            (0, 0, 0)
        }
    }
}

/// Opens one handle and reads CPU time, working set and image path.
fn process_details(
    pid: u32,
    cache: &mut HashMap<u32, Option<PathBuf>>,
) -> (u64, u64, Option<PathBuf>) {
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return (0, 0, cache.get(&pid).cloned().unwrap_or(None));
        };

        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let mut cpu = 0u64;
        if GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok() {
            cpu = filetime_to_u64(kernel) + filetime_to_u64(user);
        }

        let mut memory = 0u64;
        let mut counters = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };
        if GetProcessMemoryInfo(
            handle,
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
        .is_ok()
        {
            memory = counters.WorkingSetSize as u64;
        }

        let path = match cache.get(&pid) {
            Some(cached) => cached.clone(),
            None => {
                let mut buffer = vec![0u16; 1024];
                let mut size = buffer.len() as u32;
                let found = QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_WIN32,
                    PWSTR(buffer.as_mut_ptr()),
                    &mut size,
                )
                .is_ok()
                .then(|| {
                    let path = String::from_utf16_lossy(&buffer[..size as usize]);
                    PathBuf::from(path)
                });
                cache.insert(pid, found.clone());
                found
            }
        };

        let _ = CloseHandle(handle);
        (cpu, memory, path)
    }
}

pub fn kill_process(pid: u32) -> Result<(), String> {
    if pid <= 4 {
        return Err("Windows core system processes cannot be terminated.".to_string());
    }
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|_| {
            "Access denied — run WinClean as administrator to stop this process".to_string()
        })?;
        let result = TerminateProcess(handle, 1)
            .map_err(|err| format!("Windows refused to end the process: {err}"));
        let _ = CloseHandle(handle);
        result
    }
}
