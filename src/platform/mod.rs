//! Operating system integration. The rest of the app only talks to this module,
//! which keeps every `unsafe` call and every Windows API in one place.

use crate::model::{ProcessInfo, SystemStats};

/// One monitor tick: process list plus machine wide counters.
#[derive(Debug, Clone, Default)]
pub struct ProcessSample {
    pub processes: Vec<ProcessInfo>,
    pub stats: SystemStats,
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[cfg(not(windows))]
mod fallback;
#[cfg(not(windows))]
pub use fallback::*;
