//! Deletion engine. Every path passes the safety policy first; failures are
//! collected per item instead of aborting the run.

use crate::core::guard;
use crate::core::paths;
use crate::model::Category;
pub use crate::model::{CleanEvent, CleanProgress, CleanReport, Finding};
use crate::settings::log;
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct CleanOptions {
    /// Roots accepted by the scan that produced the findings.
    pub allowed_roots: Vec<PathBuf>,
    pub exclusions: Vec<String>,
    /// Set only after the user approved personal files in the confirmation dialog.
    pub approve_personal: bool,
}

pub struct CleanHandle {
    pub cancel: Arc<AtomicBool>,
    pub rx: Receiver<CleanEvent>,
    pub join: Option<JoinHandle<()>>,
}

impl CleanHandle {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// Deletes the selected findings in the background.
pub fn spawn_clean(items: Vec<Finding>, options: CleanOptions) -> CleanHandle {
    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::channel();
    let thread_cancel = cancel.clone();
    let join = thread::Builder::new()
        .name("winclean-clean".into())
        .spawn(move || {
            run_clean(items, options, thread_cancel, tx);
        })
        .expect("failed to start clean thread");
    CleanHandle {
        cancel,
        rx,
        join: Some(join),
    }
}

fn run_clean(
    items: Vec<Finding>,
    options: CleanOptions,
    cancel: Arc<AtomicBool>,
    tx: Sender<CleanEvent>,
) {
    let started = Instant::now();
    let exclusions = guard::prepare_exclusions(&options.exclusions);
    let policy = guard::DeletePolicy {
        allowed_roots: &options.allowed_roots,
        exclusions: &exclusions,
        allow_personal: options.approve_personal,
    };
    let total = items.len();
    let mut report = CleanReport::default();
    let mut deleted_parents: HashSet<PathBuf> = HashSet::new();
    let mut last_update = Instant::now() - Duration::from_secs(1);

    for (index, item) in items.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let display = item.path.to_string_lossy().to_string();

        if item.special || item.category == Category::RecycleBin {
            match crate::platform::empty_recycle_bin() {
                Ok(freed) => {
                    report.removed += 1;
                    report.bytes_freed += freed;
                    report.removed_items.push(item.path.clone());
                    log::info(
                        "clean",
                        format!(
                            "Emptied the Recycle Bin and freed {}",
                            crate::format::bytes(freed)
                        ),
                    );
                }
                Err(err) => {
                    report.failed += 1;
                    report.errors.push((item.path.clone(), err.clone()));
                    log::warn("clean", format!("Recycle Bin was not emptied: {err}"));
                }
            }
            continue;
        }

        if let Err(refusal) = policy.evaluate(&item.path, item.category) {
            report.skipped += 1;
            report
                .skipped_items
                .push((item.path.clone(), refusal.message().to_string()));
            log::warn(
                "clean",
                format!("Skipped {}: {}", display, refusal.message()),
            );
            continue;
        }

        match delete_file(&item.path) {
            Ok(freed) => {
                report.removed += 1;
                report.bytes_freed += freed;
                report.removed_items.push(item.path.clone());
                if let Some(parent) = item.path.parent() {
                    deleted_parents.insert(parent.to_path_buf());
                }
                log::info(
                    "clean",
                    format!("Deleted {} ({})", display, crate::format::bytes(freed)),
                );
            }
            Err(err) => {
                report.failed += 1;
                let reason = friendly_error(&err);
                report.errors.push((item.path.clone(), reason.clone()));
                log::warn("clean", format!("Could not delete {display}: {reason}"));
            }
        }

        if last_update.elapsed() >= Duration::from_millis(90) || index + 1 == total {
            last_update = Instant::now();
            let _ = tx.send(CleanEvent::Progress(CleanProgress {
                done: index + 1,
                total,
                bytes_freed: report.bytes_freed,
                current: display,
            }));
        }
    }

    // Remove now-empty folders inside the cleaned roots (never outside them).
    if !cancel.load(Ordering::Relaxed) {
        let mut attempts = 0usize;
        for parent in deleted_parents {
            attempts += prune_empty_parents(&parent, &options.allowed_roots, 6);
            if attempts > 4_000 {
                break;
            }
        }
    }

    report.elapsed = started.elapsed();
    log::info(
        "clean",
        format!(
            "Cleanup finished: {} removed, {} skipped, {} failed, {} freed in {}",
            report.removed,
            report.skipped,
            report.failed,
            crate::format::bytes(report.bytes_freed),
            crate::format::duration(report.elapsed)
        ),
    );
    let _ = tx.send(CleanEvent::Done(report));
}

/// Deletes one file, clearing the read-only flag when necessary.
///
/// Windows frequently reports a sharing violation for a file that Defender, an
/// indexer or the owning application is still touching, so a short retry loop is
/// used instead of failing on the first attempt. Deep cache trees can also exceed
/// `MAX_PATH`, which is handled through the extended-length path prefix.
fn delete_file(path: &Path) -> io::Result<u64> {
    let target = extended_path(path);
    let metadata = std::fs::symlink_metadata(&target)?;
    if metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is a folder",
        ));
    }
    let size = metadata.len();
    if metadata.permissions().readonly() {
        let mut permissions = metadata.permissions();
        permissions.set_readonly(false);
        let _ = std::fs::set_permissions(&target, permissions);
    }

    let mut last_error = None;
    for attempt in 0..4 {
        match std::fs::remove_file(&target) {
            Ok(()) => return Ok(size),
            Err(error) => {
                let retryable = !matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::InvalidInput
                );
                last_error = Some(error);
                if !retryable || attempt == 3 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(45));
            }
        }
    }
    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "the file could not be removed")))
}

/// Adds the `\\?\` prefix for paths longer than the classic Windows limit.
#[cfg(windows)]
fn extended_path(path: &Path) -> PathBuf {
    let text = path.as_os_str().to_string_lossy();
    if text.len() < 248 || text.starts_with(r"\\?\") {
        return path.to_path_buf();
    }
    if let Some(unc) = text.strip_prefix(r"\\") {
        return PathBuf::from(format!(r"\\?\UNC\{unc}"));
    }
    PathBuf::from(format!(r"\\?\{text}"))
}

#[cfg(not(windows))]
fn extended_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

/// Removes empty parent folders, stopping at the first non-empty or protected folder.
fn prune_empty_parents(start: &Path, allowed_roots: &[PathBuf], max_levels: usize) -> usize {
    let mut removed = 0usize;
    let mut current = start.to_path_buf();
    for _ in 0..max_levels {
        if guard::is_protected(&current) || guard::is_personal(&current) {
            break;
        }
        if guard::skip_directory_name(
            &current
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
        ) {
            break;
        }
        let allowed = allowed_roots.iter().any(|root| {
            let root = guard::normalize(root);
            let path = guard::normalize(&current);
            path != root && guard::is_within(&path, &root)
        });
        if !allowed {
            break;
        }
        match std::fs::remove_dir(&current) {
            Ok(()) => {
                removed += 1;
                match current.parent() {
                    Some(parent) => current = parent.to_path_buf(),
                    None => break,
                }
            }
            Err(_) => break,
        }
    }
    removed
}

fn friendly_error(err: &io::Error) -> String {
    match err.kind() {
        io::ErrorKind::PermissionDenied => {
            "Access denied — the file is locked or needs administrator rights".to_string()
        }
        io::ErrorKind::NotFound => "File no longer exists".to_string(),
        _ => {
            #[cfg(windows)]
            {
                // 32 = sharing violation, 33 = lock violation.
                match err.raw_os_error() {
                    Some(32) | Some(33) => {
                        return "File is in use by another program".to_string();
                    }
                    _ => {}
                }
            }
            err.to_string()
        }
    }
}

/// Human readable summary used by the CLI maintenance mode.
pub fn summarize(report: &CleanReport) -> String {
    format!(
        "{} items removed, {} freed, {} skipped, {} failed",
        report.removed,
        crate::format::bytes(report.bytes_freed),
        report.skipped,
        report.failed
    )
}

/// The scan roots that a cleanup run may delete inside.
pub fn cleanup_allowed_roots(settings: &crate::settings::Settings) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = crate::core::scanner::cleanup_roots(settings)
        .into_iter()
        .map(|root| root.path)
        .collect();
    // Browser cache folders and temp folders are the only cleanup targets; the
    // drive roots are added for large-file and duplicate findings by the caller.
    roots.sort();
    roots.dedup();
    roots
}

/// Root list for large file / duplicate deletions.
pub fn volume_roots() -> Vec<PathBuf> {
    crate::platform::volumes()
        .into_iter()
        .filter(|volume| volume.fixed)
        .map(|volume| PathBuf::from(volume.mount))
        .collect()
}

#[allow(dead_code)]
fn _paths_marker() -> PathBuf {
    paths::temp_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Category;
    use std::fs;
    use std::time::SystemTime;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "winclean-clean-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn drain(handle: CleanHandle) -> CleanReport {
        let mut report = CleanReport::default();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            match handle.rx.recv_timeout(Duration::from_millis(500)) {
                Ok(CleanEvent::Done(done)) => {
                    report = done;
                    break;
                }
                Ok(_) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => break,
            }
        }
        report
    }

    fn finding(path: PathBuf, size: u64, category: Category) -> Finding {
        Finding {
            path,
            size,
            modified: None,
            category,
            group: "Test".into(),
            note: String::new(),
            special: false,
        }
    }

    #[test]
    fn deletes_files_and_prunes_empty_folders() {
        let root = scratch("delete");
        let nested = root.join("a").join("b");
        fs::create_dir_all(&nested).unwrap();
        fs::write(root.join("one.tmp"), vec![0u8; 4096]).unwrap();
        fs::write(nested.join("two.tmp"), vec![0u8; 2048]).unwrap();

        let items = vec![
            finding(root.join("one.tmp"), 4096, Category::UserTemp),
            finding(nested.join("two.tmp"), 2048, Category::UserTemp),
        ];
        let handle = spawn_clean(
            items,
            CleanOptions {
                allowed_roots: vec![root.clone()],
                exclusions: Vec::new(),
                approve_personal: false,
            },
        );
        let report = drain(handle);
        assert_eq!(report.removed, 2);
        assert_eq!(report.failed, 0);
        assert_eq!(report.bytes_freed, 6144);
        assert!(!root.join("one.tmp").exists());
        assert!(!nested.exists(), "empty parents are pruned");

        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn refuses_paths_outside_the_allowed_roots() {
        let root = scratch("outside");
        let other = scratch("outside-other");
        fs::write(other.join("keep.txt"), b"keep").unwrap();
        let items = vec![finding(other.join("keep.txt"), 4, Category::UserTemp)];
        let handle = spawn_clean(
            items,
            CleanOptions {
                allowed_roots: vec![root.clone()],
                exclusions: Vec::new(),
                approve_personal: false,
            },
        );
        let report = drain(handle);
        assert_eq!(report.removed, 0);
        assert_eq!(report.skipped, 1);
        assert!(other.join("keep.txt").exists());
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(other).ok();
    }

    #[test]
    fn refuses_protected_system_paths() {
        let items = vec![finding(
            PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts"),
            100,
            Category::WindowsTemp,
        )];
        let handle = spawn_clean(
            items,
            CleanOptions {
                allowed_roots: vec![PathBuf::from(r"C:\Windows")],
                exclusions: Vec::new(),
                approve_personal: false,
            },
        );
        let report = drain(handle);
        assert_eq!(report.removed, 0);
        assert_eq!(report.skipped, 1);
        assert!(report.skipped_items[0].1.contains("Protected"));
    }

    #[test]
    fn honours_exclusion_rules() {
        let root = scratch("exclusion");
        let file = root.join("keep.tmp");
        fs::write(&file, b"data").unwrap();
        let handle = spawn_clean(
            vec![finding(file.clone(), 4, Category::UserTemp)],
            CleanOptions {
                allowed_roots: vec![root.clone()],
                exclusions: vec![file.to_string_lossy().to_string()],
                approve_personal: false,
            },
        );
        let report = drain(handle);
        assert_eq!(report.skipped, 1);
        assert!(file.exists());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn missing_file_is_reported_as_failure_not_crash() {
        let root = scratch("missing");
        let handle = spawn_clean(
            vec![finding(root.join("gone.tmp"), 1, Category::UserTemp)],
            CleanOptions {
                allowed_roots: vec![root.clone()],
                exclusions: Vec::new(),
                approve_personal: false,
            },
        );
        let report = drain(handle);
        assert_eq!(report.failed, 1);
        assert_eq!(report.removed, 0);
        fs::remove_dir_all(root).ok();
    }
}
