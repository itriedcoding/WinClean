//! The scanning engine.
//!
//! Design rules:
//! * Metadata only — file contents are never executed or opened except for duplicate
//!   hashing, which reads bytes in bounded chunks.
//! * Cancellable at any moment, including between directory entries.
//! * Bounded threads (at most 4) so a scan never saturates the machine.
//! * Findings stream to the UI in batches; nothing large is held in memory.

use crate::core::duplicates;
use crate::core::guard;
use crate::core::paths;
use crate::format;
use crate::model::{Category, CategoryTotal, Finding};
pub use crate::model::{ScanEvent, ScanProgress, ScanSummary};
use crate::settings::Settings;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

/// Which files inside a target are interesting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    All,
    Extensions(&'static [&'static str]),
}

impl Filter {
    fn matches(&self, path: &Path) -> bool {
        match self {
            Filter::All => true,
            Filter::Extensions(exts) => {
                let ext = format::extension(path);
                exts.iter().any(|candidate| *candidate == ext)
            }
        }
    }
}

/// A directory tree that the scanner walks for one category.
#[derive(Debug, Clone)]
pub struct WalkRoot {
    pub path: PathBuf,
    pub category: Category,
    pub group: String,
    pub note: String,
    pub filter: Filter,
    pub max_depth: usize,
    pub min_size: u64,
    pub skip_system_trees: bool,
}

impl WalkRoot {
    pub fn new(path: PathBuf, category: Category, group: impl Into<String>) -> Self {
        Self {
            path,
            category,
            group: group.into(),
            note: category.description().to_string(),
            filter: Filter::All,
            max_depth: 24,
            min_size: 1,
            skip_system_trees: false,
        }
    }

    pub fn filter(mut self, filter: Filter) -> Self {
        self.filter = filter;
        self
    }

    pub fn depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.note = note.into();
        self
    }

    pub fn skip_system(mut self) -> Self {
        self.skip_system_trees = true;
        self
    }
}

/// Recycle Bin size snapshot (queried by the platform layer and handed to the scanner).
#[derive(Debug, Clone, Copy, Default)]
pub struct RecycleBinInfo {
    pub bytes: u64,
    pub items: u64,
}

/// Everything a scan run needs.
#[derive(Debug, Clone)]
pub struct ScanSpec {
    pub roots: Vec<WalkRoot>,
    pub duplicate_roots: Vec<PathBuf>,
    pub duplicate_min_size: u64,
    pub find_duplicates: bool,
    pub exclusions: Vec<String>,
    pub recycle_bin: Option<RecycleBinInfo>,
    pub threads: usize,
}

impl ScanSpec {
    pub fn new(settings: &Settings) -> Self {
        Self {
            roots: Vec::new(),
            duplicate_roots: Vec::new(),
            duplicate_min_size: settings.duplicate_min_size_bytes(),
            find_duplicates: false,
            exclusions: settings.exclusions(),
            recycle_bin: None,
            threads: scan_threads(),
        }
    }

    pub fn with_cleanup(mut self, settings: &Settings) -> Self {
        self.roots.extend(cleanup_roots(settings));
        self
    }

    pub fn with_large_files(mut self, settings: &Settings) -> Self {
        let threshold = settings.large_file_threshold_bytes();
        for volume in crate::platform::volumes() {
            if !volume.fixed {
                continue;
            }
            let mut root = WalkRoot::new(
                PathBuf::from(&volume.mount),
                Category::LargeFile,
                format!("{} large files", volume.mount),
            );
            root.min_size = threshold;
            root.max_depth = 64;
            root.skip_system_trees = !settings.scan_system_folders;
            root.note = "Larger than your size threshold — review before deleting".to_string();
            self.roots.push(root);
        }
        self
    }

    pub fn with_duplicates(mut self, settings: &Settings, all_drives: bool) -> Self {
        self.find_duplicates = true;
        self.duplicate_min_size = settings.duplicate_min_size_bytes();
        if all_drives {
            for volume in crate::platform::volumes() {
                if volume.fixed {
                    self.duplicate_roots.push(PathBuf::from(volume.mount));
                }
            }
        } else {
            let profile = paths::user_profile();
            for name in [
                "Documents",
                "Downloads",
                "Desktop",
                "Pictures",
                "Videos",
                "Music",
            ] {
                let candidate = profile.join(name);
                if candidate.is_dir() {
                    self.duplicate_roots.push(candidate);
                }
            }
        }
        self
    }

    pub fn with_recycle_bin(mut self, info: RecycleBinInfo) -> Self {
        if info.bytes > 0 {
            self.recycle_bin = Some(info);
        }
        self
    }

    pub fn total_roots(&self) -> usize {
        self.roots.len() + self.duplicate_roots.len()
    }
}

pub fn scan_threads() -> usize {
    thread::available_parallelism()
        .map(|n| n.get().clamp(1, 4))
        .unwrap_or(2)
}

/// Builds every cleanup target for the current machine.
pub fn cleanup_roots(settings: &Settings) -> Vec<WalkRoot> {
    let win = paths::windows_dir();
    let local = paths::local_appdata();
    let roaming = paths::roaming_appdata();
    let program_data = paths::program_data();
    let mut roots: Vec<WalkRoot> = Vec::new();

    // --- Temporary files -----------------------------------------------------
    roots.push(
        WalkRoot::new(win.join("Temp"), Category::WindowsTemp, "Windows")
            .note("Scratch space used by Windows components and installers"),
    );
    let mut user_temp = vec![local.join("Temp")];
    let env_temp = paths::temp_dir();
    if !user_temp
        .iter()
        .any(|p| guard::normalize(p) == guard::normalize(&env_temp))
    {
        user_temp.push(env_temp);
    }
    for temp in user_temp {
        roots.push(
            WalkRoot::new(temp, Category::UserTemp, "Your account")
                .note("Temporary files written by your applications"),
        );
    }

    // --- Browser caches ------------------------------------------------------
    for cache in browser_cache_dirs(&local, &roaming) {
        let mut root = WalkRoot::new(cache.path, Category::BrowserCache, cache.group)
            .depth(8)
            .note("Cached web content — bookmarks, history and passwords are untouched");
        root.category = Category::BrowserCache;
        roots.push(root);
    }
    let inet_cache = local.join("Microsoft\\Windows\\INetCache");
    if inet_cache.is_dir() {
        roots.push(
            WalkRoot::new(inet_cache, Category::BrowserCache, "Windows web cache")
                .depth(6)
                .note("Legacy internet cache used by Windows components"),
        );
    }

    // --- Thumbnails ----------------------------------------------------------
    roots.push(
        WalkRoot::new(
            local.join("Microsoft\\Windows\\Explorer"),
            Category::ThumbnailCache,
            "Explorer",
        )
        .filter(Filter::Extensions(&["db"]))
        .depth(1)
        .note("Thumbnail and icon databases, rebuilt automatically by Explorer"),
    );

    // --- Crash dumps ---------------------------------------------------------
    roots.push(
        WalkRoot::new(
            local.join("CrashDumps"),
            Category::CrashDumps,
            "Applications",
        )
        .filter(Filter::Extensions(&["dmp", "mdmp"]))
        .depth(2),
    );
    roots.push(
        WalkRoot::new(win.join("Minidump"), Category::CrashDumps, "Windows")
            .filter(Filter::Extensions(&["dmp", "mdmp"]))
            .depth(1),
    );
    roots.push(
        WalkRoot::new(
            win.join("LiveKernelReports"),
            Category::CrashDumps,
            "Windows",
        )
        .filter(Filter::Extensions(&["dmp", "mdmp"]))
        .depth(3),
    );
    let memory_dmp = win.join("MEMORY.DMP");
    if memory_dmp.is_file() {
        roots.push(
            WalkRoot::new(win.clone(), Category::CrashDumps, "Windows")
                .filter(Filter::Extensions(&["dmp"]))
                .depth(0)
                .note("Kernel crash dump written by Windows"),
        );
    }

    // --- Error reporting -----------------------------------------------------
    roots.push(
        WalkRoot::new(
            program_data.join("Microsoft\\Windows\\WER"),
            Category::ErrorReports,
            "Windows Error Reporting",
        )
        .depth(3),
    );
    roots.push(
        WalkRoot::new(
            local.join("Microsoft\\Windows\\WER"),
            Category::ErrorReports,
            "Windows Error Reporting",
        )
        .depth(3),
    );

    // --- Windows logs --------------------------------------------------------
    roots.push(
        WalkRoot::new(win.join("Logs"), Category::WindowsLogs, "Windows")
            .filter(Filter::Extensions(&[
                "log", "etl", "txt", "cab", "evtx.bak",
            ]))
            .depth(4)
            .note("Diagnostic logs; Windows recreates them as needed"),
    );

    // --- Update caches -------------------------------------------------------
    let software_distribution = win.join("SoftwareDistribution\\Download");
    if software_distribution.is_dir() {
        roots.push(
            WalkRoot::new(
                software_distribution,
                Category::WindowsUpdateCache,
                "Windows Update",
            )
            .depth(8)
            .note("Already-installed update payloads; Windows re-downloads if required"),
        );
    }
    let delivery_cache = win.join(
        "ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache",
    );
    if delivery_cache.is_dir() {
        roots.push(
            WalkRoot::new(
                delivery_cache,
                Category::DeliveryOptimization,
                "Delivery Optimization",
            )
            .depth(6),
        );
    }

    // --- Prefetch (opt-in) ---------------------------------------------------
    if settings.include_prefetch {
        roots.push(
            WalkRoot::new(win.join("Prefetch"), Category::Prefetch, "Windows")
                .filter(Filter::Extensions(&["pf"]))
                .depth(1)
                .note("Launch traces; removing them can slow the next launches"),
        );
    }

    roots.retain(|root| root.path.is_dir());
    roots
}

struct BrowserCache {
    path: PathBuf,
    group: String,
}

/// Enumerates cache folders for the browsers that are actually installed.
fn browser_cache_dirs(local: &Path, roaming: &Path) -> Vec<BrowserCache> {
    const PROFILE_CACHES: [&str; 8] = [
        "Cache",
        "Code Cache",
        "GPUCache",
        "DawnCache",
        "GrShaderCache",
        "ShaderCache",
        "Service Worker\\CacheStorage",
        "Service Worker\\ScriptCache",
    ];
    let mut found = Vec::new();
    let browsers = [
        ("Google", "Chrome", "Google Chrome"),
        ("Microsoft", "Edge", "Microsoft Edge"),
        ("BraveSoftware", "Brave-Browser", "Brave"),
        ("Vivaldi", "Vivaldi", "Vivaldi"),
        ("Chromium", "Chromium", "Chromium"),
    ];
    for (vendor, product, label) in browsers {
        let user_data = local.join(vendor).join(product).join("User Data");
        if !user_data.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&user_data) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let profile_name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if matches!(
                    profile_name.to_ascii_lowercase().as_str(),
                    "crashpad"
                        | "browsermetrics"
                        | "shadercache"
                        | "grshadercache"
                        | "graphitedawncache"
                ) {
                    continue;
                }
                for cache in PROFILE_CACHES {
                    let candidate = path.join(cache);
                    if candidate.is_dir() {
                        found.push(BrowserCache {
                            path: candidate,
                            group: format!("{label} · {profile_name}"),
                        });
                    }
                }
            }
        }
    }

    // Opera stores its cache directly under the product folder.
    for (relative, label) in [
        ("Opera Software\\Opera Stable\\Cache", "Opera"),
        ("Opera Software\\Opera GX Stable\\Cache", "Opera GX"),
    ] {
        let candidate = local.join(relative);
        if candidate.is_dir() {
            found.push(BrowserCache {
                path: candidate,
                group: label.to_string(),
            });
        }
    }

    // Firefox keeps one cache2 folder per profile.
    let firefox_profiles = local.join("Mozilla\\Firefox\\Profiles");
    if let Ok(entries) = std::fs::read_dir(&firefox_profiles) {
        for entry in entries.flatten() {
            let cache = entry.path().join("cache2");
            if cache.is_dir() {
                let profile = entry.file_name().to_string_lossy().to_string();
                found.push(BrowserCache {
                    path: cache,
                    group: format!("Mozilla Firefox · {profile}"),
                });
            }
        }
    }

    // A few profiles live under Roaming rather than Local.
    let roaming_firefox = roaming.join("Mozilla\\Firefox\\Profiles");
    if roaming_firefox.is_dir() {
        // Nothing cache-like lives there in modern builds; intentionally ignored.
    }

    found.sort_by(|a, b| a.group.cmp(&b.group));
    found
}

// ---------------------------------------------------------------------------
// Job handle
// ---------------------------------------------------------------------------

pub struct ScanHandle {
    pub cancel: Arc<AtomicBool>,
    pub rx: Receiver<ScanEvent>,
    pub join: Option<JoinHandle<()>>,
}

impl ScanHandle {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// Starts a scan on a background thread. Events must be drained by the caller.
pub fn spawn_scan(spec: ScanSpec) -> ScanHandle {
    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::channel();
    let thread_cancel = cancel.clone();
    let join = thread::Builder::new()
        .name("winclean-scan".into())
        .spawn(move || {
            let reporter = Reporter::new(tx, thread_cancel.clone());
            let started = Instant::now();
            let exclusions = Arc::new(guard::prepare_exclusions(&spec.exclusions));

            let mut roots: Vec<WalkRoot> = spec.roots.clone();
            roots.retain(|root| root.path.is_dir());

            if !roots.is_empty() {
                reporter.stage("Scanning cleanup locations");
                walk_roots(&roots, &exclusions, &thread_cancel, spec.threads, &reporter);
            }

            if let Some(info) = spec.recycle_bin {
                reporter.push_finding(Finding {
                    path: PathBuf::from("shell:RecycleBin"),
                    size: info.bytes,
                    modified: None,
                    category: Category::RecycleBin,
                    group: "Recycle Bin".to_string(),
                    note: format!(
                        "{} deleted item(s) still using disk space",
                        format::count(info.items)
                    ),
                    special: true,
                });
            }

            if spec.find_duplicates && !thread_cancel.load(Ordering::Relaxed) {
                reporter.stage("Finding duplicate files");
                duplicates::scan_duplicates(
                    &spec.duplicate_roots,
                    spec.duplicate_min_size,
                    &exclusions,
                    &thread_cancel,
                    spec.threads,
                    &reporter,
                );
            }

            let summary = reporter.finish(started.elapsed(), thread_cancel.load(Ordering::Relaxed));
            reporter.done(summary);
        })
        .expect("failed to start scan thread");

    ScanHandle {
        cancel,
        rx,
        join: Some(join),
    }
}

// ---------------------------------------------------------------------------
// Progress reporter shared with the scan workers
// ---------------------------------------------------------------------------

pub struct Reporter {
    tx: Mutex<Sender<ScanEvent>>,
    cancel: Arc<AtomicBool>,
    batch: Mutex<Vec<Finding>>,
    totals: Mutex<HashMap<Category, (u64, usize)>>,
    last_progress: Mutex<Instant>,
    files: AtomicU64,
    dirs: AtomicU64,
    errors: AtomicU64,
    bytes: AtomicU64,
    stage: Mutex<String>,
}

impl Reporter {
    pub fn new(tx: Sender<ScanEvent>, cancel: Arc<AtomicBool>) -> Self {
        Self {
            tx: Mutex::new(tx),
            cancel,
            batch: Mutex::new(Vec::with_capacity(256)),
            totals: Mutex::new(HashMap::new()),
            last_progress: Mutex::new(Instant::now() - Duration::from_secs(1)),
            files: AtomicU64::new(0),
            dirs: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            stage: Mutex::new(String::new()),
        }
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn send(&self, event: ScanEvent) {
        if let Ok(tx) = self.tx.lock() {
            let _ = tx.send(event);
        }
    }

    pub fn stage(&self, stage: impl Into<String>) {
        let stage = stage.into();
        if let Ok(mut current) = self.stage.lock() {
            *current = stage.clone();
        }
        self.send(ScanEvent::Stage(stage));
    }

    pub fn push_finding(&self, finding: Finding) {
        {
            let mut totals = match self.totals.lock() {
                Ok(t) => t,
                Err(poisoned) => poisoned.into_inner(),
            };
            let entry = totals.entry(finding.category).or_insert((0, 0));
            entry.0 += finding.size;
            entry.1 += 1;
        }
        self.bytes.fetch_add(finding.size, Ordering::Relaxed);
        let should_flush = {
            let mut batch = match self.batch.lock() {
                Ok(b) => b,
                Err(poisoned) => poisoned.into_inner(),
            };
            batch.push(finding);
            batch.len() >= 192
        };
        if should_flush {
            self.flush();
        }
    }

    pub fn flush(&self) {
        let drained: Vec<Finding> = {
            let mut batch = match self.batch.lock() {
                Ok(b) => b,
                Err(poisoned) => poisoned.into_inner(),
            };
            if batch.is_empty() {
                return;
            }
            batch.drain(..).collect()
        };
        self.send(ScanEvent::Findings(drained));
    }

    /// Throttled progress notification (max ~6 per second).
    pub fn progress(&self, current: &Path) {
        let now = Instant::now();
        let should_send = {
            let mut last = match self.last_progress.lock() {
                Ok(l) => l,
                Err(poisoned) => poisoned.into_inner(),
            };
            if now.duration_since(*last) >= Duration::from_millis(160) {
                *last = now;
                true
            } else {
                false
            }
        };
        if !should_send {
            return;
        }
        let stage = self
            .stage
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|p| p.into_inner().clone());
        self.send(ScanEvent::Progress(ScanProgress {
            stage,
            files: self.files.load(Ordering::Relaxed),
            dirs: self.dirs.load(Ordering::Relaxed),
            bytes_found: self.bytes.load(Ordering::Relaxed),
            current: current.to_string_lossy().to_string(),
            percent: None,
        }));
    }

    pub fn note_dir(&self) {
        self.dirs.fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_file(&self) -> u64 {
        self.files.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn finish(&self, elapsed: Duration, cancelled: bool) -> ScanSummary {
        self.flush();
        let categories = self
            .totals
            .lock()
            .map(|totals| {
                let mut list: Vec<CategoryTotal> = totals
                    .iter()
                    .map(|(category, (bytes, items))| CategoryTotal {
                        category: *category,
                        bytes: *bytes,
                        items: *items,
                    })
                    .collect();
                list.sort_by(|a, b| b.bytes.cmp(&a.bytes));
                list
            })
            .unwrap_or_default();
        ScanSummary {
            files_scanned: self.files.load(Ordering::Relaxed),
            dirs_scanned: self.dirs.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            bytes_found: self.bytes.load(Ordering::Relaxed),
            items_found: categories.iter().map(|c| c.items).sum(),
            elapsed,
            cancelled,
            categories,
        }
    }

    fn done(&self, summary: ScanSummary) {
        self.send(ScanEvent::Done(summary));
    }
}

// ---------------------------------------------------------------------------
// Parallel directory walker
// ---------------------------------------------------------------------------

struct QueueState {
    queue: VecDeque<(PathBuf, usize, usize)>,
    active: usize,
    done: bool,
}

struct Queue {
    state: Mutex<QueueState>,
    cv: Condvar,
    cancel: Arc<AtomicBool>,
}

impl Queue {
    fn new(cancel: Arc<AtomicBool>) -> Self {
        Self {
            state: Mutex::new(QueueState {
                queue: VecDeque::new(),
                active: 0,
                done: false,
            }),
            cv: Condvar::new(),
            cancel,
        }
    }

    fn push(&self, items: Vec<(PathBuf, usize, usize)>) {
        if items.is_empty() {
            return;
        }
        if let Ok(mut state) = self.state.lock() {
            state.queue.extend(items);
        }
        self.cv.notify_all();
    }

    fn pop(&self) -> Option<(PathBuf, usize, usize)> {
        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        loop {
            if state.done {
                return None;
            }
            if self.cancel.load(Ordering::Relaxed) {
                state.queue.clear();
                state.done = true;
                drop(state);
                self.cv.notify_all();
                return None;
            }
            if let Some(item) = state.queue.pop_front() {
                state.active += 1;
                return Some(item);
            }
            if state.active == 0 {
                state.done = true;
                self.cv.notify_all();
                return None;
            }
            state = match self.cv.wait_timeout(state, Duration::from_millis(120)) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    fn complete(&self) {
        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.active = state.active.saturating_sub(1);
        if state.active == 0 && state.queue.is_empty() {
            state.done = true;
            drop(state);
            self.cv.notify_all();
        }
    }
}

fn is_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
                meta.file_type().is_symlink()
                    || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            }
            #[cfg(not(windows))]
            {
                meta.file_type().is_symlink()
            }
        })
        .unwrap_or(false)
}

fn is_system_tree(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    matches!(
        name.as_str(),
        "windows"
            | "program files"
            | "program files (x86)"
            | "programdata"
            | "recovery"
            | "$recycle.bin"
    )
}

/// Walks every root and emits each matching file as a repair finding.
pub fn walk_roots(
    roots: &[WalkRoot],
    exclusions: &Arc<Vec<String>>,
    cancel: &Arc<AtomicBool>,
    threads: usize,
    reporter: &Reporter,
) {
    for_each_file(
        roots,
        exclusions,
        cancel,
        threads,
        reporter,
        |path, metadata, root| {
            reporter.push_finding(Finding {
                path: path.to_path_buf(),
                size: metadata.len(),
                modified: metadata.modified().ok(),
                category: root.category,
                group: root.group.clone(),
                note: root.note.clone(),
                special: false,
            });
        },
    );
}

/// Generic parallel walk used by cleanup scans and by duplicate detection.
pub fn for_each_file<F>(
    roots: &[WalkRoot],
    exclusions: &Arc<Vec<String>>,
    cancel: &Arc<AtomicBool>,
    threads: usize,
    reporter: &Reporter,
    visit: F,
) where
    F: Fn(&Path, &std::fs::Metadata, &WalkRoot) + Sync,
{
    if roots.is_empty() {
        return;
    }
    let queue = Arc::new(Queue::new(cancel.clone()));
    let initial: Vec<(PathBuf, usize, usize)> = roots
        .iter()
        .enumerate()
        .map(|(index, root)| (root.path.clone(), 0usize, index))
        .collect();
    queue.push(initial);

    let worker_count = threads.clamp(1, 4);

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let queue = Arc::clone(&queue);
            let cancel = cancel.clone();
            let visit = &visit;
            scope.spawn(move || {
                walker_loop(&queue, roots, exclusions, &cancel, reporter, visit);
            });
        }
    });
}

fn walker_loop<F>(
    queue: &Queue,
    roots: &[WalkRoot],
    exclusions: &[String],
    cancel: &AtomicBool,
    reporter: &Reporter,
    visit: &F,
) where
    F: Fn(&Path, &std::fs::Metadata, &WalkRoot) + Sync,
{
    while let Some((dir, depth, root_index)) = queue.pop() {
        if cancel.load(Ordering::Relaxed) {
            queue.complete();
            break;
        }
        let root = &roots[root_index];
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                reporter.note_error();
                queue.complete();
                continue;
            }
        };
        reporter.note_dir();

        let mut children: Vec<(PathBuf, usize, usize)> = Vec::new();
        for entry in entries.flatten() {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => {
                    reporter.note_error();
                    continue;
                }
            };

            if file_type.is_dir() {
                if is_link(&path)
                    || guard::skip_directory_name(&entry.file_name().to_string_lossy())
                {
                    continue;
                }
                if root.skip_system_trees && depth == 0 && is_system_tree(&path) {
                    continue;
                }
                if guard::is_excluded(&path, exclusions) {
                    continue;
                }
                if depth + 1 >= root.max_depth {
                    continue;
                }
                children.push((path, depth + 1, root_index));
                continue;
            }

            if !file_type.is_file() {
                continue;
            }
            let file_number = reporter.note_file();
            if file_number % 96 == 0 {
                reporter.progress(&path);
            }
            if guard::is_excluded(&path, exclusions) {
                continue;
            }
            if !root.filter.matches(&path) {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => {
                    reporter.note_error();
                    continue;
                }
            };
            let size = metadata.len();
            if size < root.min_size {
                continue;
            }
            if guard::is_protected(&path) {
                continue;
            }
            visit(&path, &metadata, root);
        }

        queue.push(children);
        queue.complete();
    }
}

/// Counts files and bytes in a folder tree without allocating findings.
/// Used by the storage analyzer for its treemap.
pub fn folder_sizes(root: &Path, max_depth: usize, cancel: &AtomicBool) -> Vec<(PathBuf, u64)> {
    let mut totals: HashMap<PathBuf, u64> = HashMap::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    let mut visited = 0u64;
    while let Some((dir, depth)) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited % 2_048 == 0 && cancel.load(Ordering::Relaxed) {
                break;
            }
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                if is_link(&path)
                    || guard::skip_directory_name(&entry.file_name().to_string_lossy())
                {
                    continue;
                }
                if depth < max_depth {
                    stack.push((path.clone(), depth + 1));
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            // Attribute the file to its top-level folder beneath `root`.
            let bucket = match path.strip_prefix(root) {
                Ok(relative) => {
                    let mut components = relative.components();
                    match (components.next(), components.next()) {
                        (Some(first), Some(_)) => root.join(first.as_os_str()),
                        _ => root.to_path_buf(),
                    }
                }
                Err(_) => root.to_path_buf(),
            };
            *totals.entry(bucket).or_insert(0) += meta.len();
        }
    }
    let mut list: Vec<(PathBuf, u64)> = totals.into_iter().collect();
    list.sort_by(|a, b| b.1.cmp(&a.1));
    list
}

#[allow(dead_code)]
fn modified_now() -> Option<SystemTime> {
    Some(SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "winclean-test-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn collect(handle: ScanHandle) -> (Vec<Finding>, ScanSummary) {
        let mut findings = Vec::new();
        let mut summary = ScanSummary::default();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            match handle.rx.recv_timeout(Duration::from_millis(500)) {
                Ok(ScanEvent::Findings(batch)) => findings.extend(batch),
                Ok(ScanEvent::Done(done)) => {
                    summary = done;
                    break;
                }
                Ok(_) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => break,
            }
        }
        (findings, summary)
    }

    #[test]
    fn finds_temp_files_and_skips_exclusions() {
        let root = scratch_dir("scan");
        let nested = root.join("sub");
        fs::create_dir_all(&nested).unwrap();
        fs::write(root.join("a.tmp"), vec![7u8; 2048]).unwrap();
        fs::write(nested.join("b.log"), vec![1u8; 512]).unwrap();
        fs::write(root.join("keep.tmp"), vec![2u8; 128]).unwrap();
        let empty = root.join("empty");
        fs::create_dir_all(&empty).unwrap();
        fs::write(empty.join("c.tmp"), vec![3u8; 1024]).unwrap();

        let mut spec = ScanSpec {
            roots: vec![WalkRoot::new(root.clone(), Category::UserTemp, "Test")],
            duplicate_roots: Vec::new(),
            duplicate_min_size: 1,
            find_duplicates: false,
            exclusions: vec![root.join("keep.tmp").to_string_lossy().to_string()],
            recycle_bin: None,
            threads: 2,
        };
        spec.threads = 2;

        let (findings, summary) = collect(spawn_scan(spec));
        let names: Vec<String> = findings.iter().map(|f| f.name()).collect();
        assert!(names.contains(&"a.tmp".to_string()));
        assert!(names.contains(&"b.log".to_string()));
        assert!(names.contains(&"c.tmp".to_string()));
        assert!(!names.contains(&"keep.tmp".to_string()));
        assert!(!summary.cancelled);
        assert_eq!(summary.items_found, 3);
        assert_eq!(summary.bytes_found, 2048 + 512 + 1024);

        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn respects_size_threshold_and_filter() {
        let root = scratch_dir("threshold");
        fs::write(root.join("small.dmp"), vec![0u8; 10]).unwrap();
        fs::write(root.join("big.dmp"), vec![0u8; 4096]).unwrap();
        fs::write(root.join("note.txt"), vec![0u8; 8192]).unwrap();

        let mut walk = WalkRoot::new(root.clone(), Category::CrashDumps, "Test")
            .filter(Filter::Extensions(&["dmp"]));
        walk.min_size = 1024;
        let spec = ScanSpec {
            roots: vec![walk],
            duplicate_roots: Vec::new(),
            duplicate_min_size: 1,
            find_duplicates: false,
            exclusions: Vec::new(),
            recycle_bin: None,
            threads: 1,
        };
        let (findings, _) = collect(spawn_scan(spec));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].name(), "big.dmp");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn duplicate_scan_groups_identical_files() {
        let root = scratch_dir("dupes");
        let content = vec![42u8; 100_000];
        {
            let mut a = fs::File::create(root.join("one.bin")).unwrap();
            a.write_all(&content).unwrap();
            a.sync_all().unwrap();
        }
        {
            let mut b = fs::File::create(root.join("two.bin")).unwrap();
            b.write_all(&content).unwrap();
            b.sync_all().unwrap();
        }
        fs::write(root.join("three.bin"), vec![9u8; 100_000]).unwrap();
        // Give antivirus/real-time filters a moment to release the freshly written
        // files before hashing them, as they would on a real machine.
        std::thread::sleep(std::time::Duration::from_millis(250));

        let spec = ScanSpec {
            roots: Vec::new(),
            duplicate_roots: vec![root.clone()],
            duplicate_min_size: 1024,
            find_duplicates: true,
            exclusions: Vec::new(),
            recycle_bin: None,
            threads: 2,
        };
        let (findings, _) = collect(spawn_scan(spec));
        let dupes: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.category == Category::Duplicate)
            .collect();
        // Only the redundant copy is reported; the keeper is never pre-selected.
        assert_eq!(
            dupes.len(),
            1,
            "exactly one redundant copy should be reported, got: {dupes:#?}"
        );
        assert!(
            dupes[0].note.starts_with("Identical to "),
            "{}",
            dupes[0].note
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cancellation_stops_the_scan() {
        let root = scratch_dir("cancel");
        for i in 0..50 {
            fs::write(root.join(format!("{i}.tmp")), vec![0u8; 64]).unwrap();
        }
        let spec = ScanSpec {
            roots: vec![WalkRoot::new(root.clone(), Category::UserTemp, "Test")],
            duplicate_roots: Vec::new(),
            duplicate_min_size: 1,
            find_duplicates: false,
            exclusions: Vec::new(),
            recycle_bin: None,
            threads: 1,
        };
        let handle = spawn_scan(spec);
        handle.cancel();
        let (_, summary) = collect(handle);
        assert!(summary.cancelled);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn recycle_bin_is_reported_as_special_item() {
        let spec = ScanSpec {
            roots: Vec::new(),
            duplicate_roots: Vec::new(),
            duplicate_min_size: 1,
            find_duplicates: false,
            exclusions: Vec::new(),
            recycle_bin: Some(RecycleBinInfo {
                bytes: 5 * 1024 * 1024,
                items: 12,
            }),
            threads: 1,
        };
        let (findings, _) = collect(spawn_scan(spec));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].special);
        assert_eq!(findings[0].size, 5 * 1024 * 1024);
    }
}
