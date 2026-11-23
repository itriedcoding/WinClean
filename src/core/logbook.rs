//! Operation log. Every cleaning and security action is appended to a rotating
//! text file and kept in memory for the Settings view.

use crate::core::paths;
use crate::format;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

pub const MAX_ENTRIES: usize = 600;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Success,
    Warn,
    Error,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Success => "OK",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub time: SystemTime,
    pub level: Level,
    pub area: String,
    pub message: String,
}

struct Inner {
    file: Option<File>,
    entries: VecDeque<LogEntry>,
    written: u64,
}

pub struct LogSink {
    path: PathBuf,
    inner: Mutex<Inner>,
}

impl LogSink {
    pub fn new(path: PathBuf) -> Self {
        let file = open_log(&path);
        Self {
            path,
            inner: Mutex::new(Inner {
                file,
                entries: VecDeque::with_capacity(MAX_ENTRIES),
                written: 0,
            }),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write(&self, level: Level, area: &str, message: impl AsRef<str>) {
        let message = message.as_ref().to_string();
        let entry = LogEntry {
            time: SystemTime::now(),
            level,
            area: area.to_string(),
            message: message.clone(),
        };
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.entries.push_back(entry);
        while inner.entries.len() > MAX_ENTRIES {
            inner.entries.pop_front();
        }
        let stamp = format::date_time(SystemTime::now(), crate::platform::local_offset_seconds());
        let line = format!("{stamp} [{:<5}] [{}] {}\n", level.label(), area, message);
        let mut written_now = 0u64;
        if let Some(file) = inner.file.as_mut() {
            if file.write_all(line.as_bytes()).is_ok() {
                written_now = line.len() as u64;
                let _ = file.flush();
            }
        }
        inner.written += written_now;
        if cfg!(debug_assertions) {
            eprint!("{line}");
        }
        if inner.written > MAX_FILE_BYTES {
            inner.file = None;
            let rotated = self.path.with_file_name("winclean.previous.log");
            let _ = std::fs::rename(&self.path, rotated);
            inner.file = open_log(&self.path);
            inner.written = 0;
        }
    }

    pub fn info(&self, area: &str, message: impl AsRef<str>) {
        self.write(Level::Info, area, message);
    }

    pub fn success(&self, area: &str, message: impl AsRef<str>) {
        self.write(Level::Success, area, message);
    }

    pub fn warn(&self, area: &str, message: impl AsRef<str>) {
        self.write(Level::Warn, area, message);
    }

    pub fn error(&self, area: &str, message: impl AsRef<str>) {
        self.write(Level::Error, area, message);
    }

    /// Most recent entries, newest last.
    pub fn recent(&self, limit: usize) -> Vec<LogEntry> {
        let inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        };
        let skip = inner.entries.len().saturating_sub(limit);
        inner.entries.iter().skip(skip).cloned().collect()
    }

    pub fn clear_view(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.entries.clear();
        }
    }
}

fn open_log(path: &Path) -> Option<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok()?;
    }
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_FILE_BYTES {
            let previous = path.with_file_name("winclean.previous.log");
            let _ = std::fs::rename(path, previous);
        }
    }
    OpenOptions::new().create(true).append(true).open(path).ok()
}

/// Global sink used by background jobs and the UI.
pub fn sink() -> &'static LogSink {
    static SINK: OnceLock<LogSink> = OnceLock::new();
    SINK.get_or_init(|| LogSink::new(paths::log_dir().join("winclean.log")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_sink(name: &str) -> (LogSink, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "winclean-log-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.log");
        (LogSink::new(path.clone()), dir)
    }

    #[test]
    fn writes_entries_to_disk_and_memory() {
        let (sink, dir) = temp_sink("basic");
        sink.info("scan", "started");
        sink.error("clean", "failed to delete C:\\x");
        let entries = sink.recent(10);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "started");
        assert_eq!(entries[1].level, Level::Error);
        let text = fs::read_to_string(sink.path()).unwrap();
        assert!(text.contains("started"));
        assert!(text.contains("[ERROR]"));
        assert!(text.contains("failed to delete"));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn memory_is_capped() {
        let (sink, dir) = temp_sink("cap");
        for i in 0..(MAX_ENTRIES + 25) {
            sink.info("test", format!("entry {i}"));
        }
        let entries = sink.recent(MAX_ENTRIES + 100);
        assert_eq!(entries.len(), MAX_ENTRIES);
        assert_eq!(
            entries.last().unwrap().message,
            format!("entry {}", MAX_ENTRIES + 24)
        );
        fs::remove_dir_all(dir).ok();
    }
}
