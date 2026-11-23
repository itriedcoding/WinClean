//! Background job wrappers. UI code polls these once per frame and never blocks.

use crate::core::clean::{spawn_clean, CleanEvent, CleanHandle, CleanOptions};
use crate::core::scanner::{
    spawn_scan, ScanEvent, ScanHandle, ScanProgress, ScanSpec, ScanSummary,
};
use crate::model::{
    CleanProgress, CleanReport, DefenderScanKind, DefenderStatus, Finding, InstalledApp,
    StartupEntry, Threat,
};
use crate::platform;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

pub struct ScanSession {
    handle: ScanHandle,
    finished: bool,
    pub progress: ScanProgress,
    pub stage: String,
}

#[derive(Default)]
pub struct ScanTick {
    pub findings: Vec<Finding>,
    pub done: Option<ScanSummary>,
    pub progress: Option<ScanProgress>,
    pub stage: Option<String>,
    pub failed: Option<String>,
}

impl ScanSession {
    pub fn start(spec: ScanSpec) -> Self {
        Self {
            handle: spawn_scan(spec),
            finished: false,
            progress: ScanProgress::default(),
            stage: String::new(),
        }
    }

    pub fn cancel(&self) {
        self.handle.cancel();
    }

    pub fn finished(&self) -> bool {
        self.finished
    }

    pub fn poll(&mut self) -> ScanTick {
        let mut tick = ScanTick::default();
        loop {
            match self.handle.rx.try_recv() {
                Ok(ScanEvent::Findings(batch)) => tick.findings.extend(batch),
                Ok(ScanEvent::Progress(progress)) => {
                    self.progress = progress.clone();
                    self.stage = progress.stage.clone();
                    tick.progress = Some(progress);
                }
                Ok(ScanEvent::Stage(stage)) => {
                    self.stage = stage.clone();
                    tick.stage = Some(stage);
                }
                Ok(ScanEvent::Done(summary)) => {
                    self.finished = true;
                    tick.done = Some(summary);
                }
                Ok(ScanEvent::Failed(error)) => {
                    self.finished = true;
                    tick.failed = Some(error);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.finished = true;
                    break;
                }
            }
        }
        tick
    }
}

impl Drop for ScanSession {
    fn drop(&mut self) {
        if !self.finished {
            self.handle.cancel();
        }
    }
}

pub struct CleanSession {
    handle: CleanHandle,
    finished: bool,
    pub progress: CleanProgress,
}

#[derive(Default)]
pub struct CleanTick {
    pub progress: Option<CleanProgress>,
    pub done: Option<CleanReport>,
}

impl CleanSession {
    pub fn start(items: Vec<Finding>, options: CleanOptions) -> Self {
        Self {
            handle: spawn_clean(items, options),
            finished: false,
            progress: CleanProgress::default(),
        }
    }

    pub fn finished(&self) -> bool {
        self.finished
    }

    pub fn cancel(&self) {
        self.handle.cancel();
    }

    pub fn poll(&mut self) -> CleanTick {
        let mut tick = CleanTick::default();
        loop {
            match self.handle.rx.try_recv() {
                Ok(CleanEvent::Progress(progress)) => {
                    self.progress = progress.clone();
                    tick.progress = Some(progress);
                }
                Ok(CleanEvent::Done(report)) => {
                    self.finished = true;
                    tick.done = Some(report);
                }
                Ok(CleanEvent::Failed(error)) => {
                    self.finished = true;
                    tick.done = Some(CleanReport {
                        errors: vec![(PathBuf::new(), error)],
                        ..Default::default()
                    });
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.finished = true;
                    break;
                }
            }
        }
        tick
    }
}

impl Drop for CleanSession {
    fn drop(&mut self) {
        if !self.finished {
            self.handle.cancel();
        }
    }
}

pub enum SecurityEvent {
    Progress(Option<f32>, String),
    Threats(Result<Vec<Threat>, String>),
    ScanFinished(Result<bool, String>),
}

pub struct SecurityJob {
    cancel: Arc<AtomicBool>,
    rx: Receiver<SecurityEvent>,
    join: Option<JoinHandle<()>>,
}

impl SecurityJob {
    /// Runs a Defender scan and then reloads the detection list.
    pub fn start_scan(kind: DefenderScanKind) -> Self {
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let thread_cancel = cancel.clone();
        let join = thread::Builder::new()
            .name("winclean-defender".into())
            .spawn(move || {
                let progress_tx = tx.clone();
                let progress_cancel = thread_cancel.clone();
                let mut report = |percent: Option<f32>, stage: String| {
                    let _ = progress_tx.send(SecurityEvent::Progress(percent, stage));
                    let _ = &progress_cancel;
                };
                let outcome = platform::defender_scan(&kind, &thread_cancel, &mut report);
                match outcome {
                    Ok(result) => {
                        let cancelled = result.cancelled;
                        let _ = tx.send(SecurityEvent::Progress(
                            if cancelled { None } else { Some(100.0) },
                            if cancelled {
                                "Scan cancelled".to_string()
                            } else {
                                "Scan complete — verifying with Microsoft Defender".to_string()
                            },
                        ));
                        // Threats first: the UI finishes the job when the scan result arrives.
                        let _ = tx.send(SecurityEvent::Threats(platform::defender_threats()));
                        let _ = tx.send(SecurityEvent::ScanFinished(Ok(cancelled)));
                    }
                    Err(error) => {
                        let _ = tx.send(SecurityEvent::Threats(platform::defender_threats()));
                        let _ = tx.send(SecurityEvent::ScanFinished(Err(error)));
                    }
                }
            })
            .expect("failed to start Defender job");
        Self {
            cancel,
            rx,
            join: Some(join),
        }
    }

    /// Reloads Defender detections without starting a new scan.
    pub fn start_refresh() -> Self {
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let join = thread::Builder::new()
            .name("winclean-threats".into())
            .spawn(move || {
                let _ = tx.send(SecurityEvent::Threats(platform::defender_threats()));
            })
            .expect("failed to start threat job");
        Self {
            cancel,
            rx,
            join: Some(join),
        }
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn poll(&self) -> Vec<SecurityEvent> {
        let mut events = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(event) => events.push(event),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }
        events
    }
}

impl Drop for SecurityJob {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            if join.is_finished() {
                let _ = join.join();
            } else {
                self.cancel.store(true, Ordering::Relaxed);
            }
        }
    }
}

pub struct StatusJob {
    rx: Receiver<DefenderStatus>,
}

impl StatusJob {
    pub fn start() -> Self {
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("winclean-status".into())
            .spawn(move || {
                let _ = tx.send(platform::defender_status());
            })
            .ok();
        Self { rx }
    }

    pub fn poll(&self) -> Option<DefenderStatus> {
        self.rx.try_recv().ok()
    }
}

pub enum StartupEvent {
    Loaded(Vec<StartupEntry>),
    Failed(String),
}

pub struct StartupJob {
    rx: Receiver<StartupEvent>,
}

impl StartupJob {
    pub fn start() -> Self {
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("winclean-startup".into())
            .spawn(move || {
                let entries = platform::startup_entries();
                let _ = tx.send(StartupEvent::Loaded(entries));
            })
            .ok();
        Self { rx }
    }

    pub fn poll(&self) -> Vec<StartupEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.rx.try_recv() {
            events.push(event);
        }
        events
    }
}

pub struct AppsJob {
    rx: Receiver<Vec<InstalledApp>>,
}

impl AppsJob {
    pub fn start() -> Self {
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("winclean-apps".into())
            .spawn(move || {
                let _ = tx.send(platform::installed_apps());
            })
            .ok();
        Self { rx }
    }

    pub fn poll(&self) -> Option<Vec<InstalledApp>> {
        self.rx.try_recv().ok()
    }
}

pub struct FolderScanJob {
    cancel: Arc<AtomicBool>,
    rx: Receiver<Vec<(PathBuf, u64)>>,
}

impl FolderScanJob {
    pub fn start(root: PathBuf, depth: usize) -> Self {
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let thread_cancel = cancel.clone();
        thread::Builder::new()
            .name("winclean-storage".into())
            .spawn(move || {
                let sizes = crate::core::scanner::folder_sizes(&root, depth, &thread_cancel);
                let _ = tx.send(sizes);
            })
            .ok();
        Self { cancel, rx }
    }

    pub fn poll(&self) -> Option<Vec<(PathBuf, u64)>> {
        self.rx.try_recv().ok()
    }
}

impl Drop for FolderScanJob {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
