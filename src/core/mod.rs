//! Platform independent engine: scanning, cleaning, duplicate detection,
//! security heuristics, storage analysis and logging.

pub mod clean;
pub mod duplicates;
pub mod guard;
pub mod logbook;
pub mod paths;
pub mod scanner;
pub mod security;
pub mod storage;
