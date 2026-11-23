//! Duplicate file detection: size grouping, partial hashing, then full BLAKE3
//! hashing only for the files that could actually be identical.

use crate::core::scanner::{self, Reporter, WalkRoot};
use crate::format;
use crate::model::{Category, Finding};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const PARTIAL_BYTES: u64 = 32 * 1024;

/// Finds duplicate files below `roots` and reports every redundant copy.
pub fn scan_duplicates(
    roots: &[PathBuf],
    min_size: u64,
    exclusions: &Arc<Vec<String>>,
    cancel: &Arc<AtomicBool>,
    threads: usize,
    reporter: &Reporter,
) {
    let walk_roots: Vec<WalkRoot> = roots
        .iter()
        .filter(|root| root.is_dir())
        .map(|root| {
            let mut walk = WalkRoot::new(root.clone(), Category::Duplicate, "Duplicate scan")
                .skip_system()
                .depth(64)
                .note("Byte-identical copy of another file");
            walk.min_size = min_size.max(1);
            walk
        })
        .collect();
    if walk_roots.is_empty() {
        return;
    }

    // Step 1 — group every candidate by exact byte size.
    let by_size: Mutex<HashMap<u64, Vec<PathBuf>>> = Mutex::new(HashMap::new());
    scanner::for_each_file(
        &walk_roots,
        exclusions,
        cancel,
        threads,
        reporter,
        |path, metadata, _root| {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            if let Ok(mut map) = by_size.lock() {
                map.entry(metadata.len())
                    .or_default()
                    .push(path.to_path_buf());
            }
        },
    );

    if cancel.load(Ordering::Relaxed) {
        return;
    }

    let mut groups: Vec<(u64, Vec<PathBuf>)> = by_size
        .into_inner()
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .collect();
    groups.sort_by(|a, b| b.0.cmp(&a.0));

    let candidate_count: usize = groups.iter().map(|(_, paths)| paths.len()).sum();
    if candidate_count == 0 {
        return;
    }
    reporter.stage(format!(
        "Comparing {} candidate files",
        format::count(candidate_count as u64)
    ));

    let mut checked = 0usize;
    for (size, paths) in groups {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        // Step 2 — cheap partial hash to eliminate files that differ early.
        let mut partial: HashMap<[u8; 32], Vec<PathBuf>> = HashMap::new();
        for path in paths {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            checked += 1;
            if checked % 8 == 0 {
                reporter.progress(&path);
            }
            if let Some(hash) = hash_file(&path, Some(PARTIAL_BYTES), cancel) {
                partial.entry(hash).or_default().push(path);
            }
        }

        // Step 3 — full hash only for the surviving groups.
        for (_, bucket) in partial.into_iter().filter(|(_, paths)| paths.len() > 1) {
            let mut exact: HashMap<[u8; 32], Vec<PathBuf>> = HashMap::new();
            for path in bucket {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                checked += 1;
                reporter.progress(&path);
                if let Some(hash) = hash_file(&path, None, cancel) {
                    exact.entry(hash).or_default().push(path);
                }
            }
            for (_, mut copies) in exact.into_iter().filter(|(_, paths)| paths.len() > 1) {
                copies.sort_by_key(|path| {
                    std::fs::metadata(path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(u64::MAX)
                });
                let keeper = copies[0].clone();
                let keeper_name = keeper
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| keeper.to_string_lossy().to_string());
                let count = copies.len();
                for copy in copies.iter().skip(1) {
                    reporter.push_finding(Finding {
                        path: copy.clone(),
                        size,
                        modified: std::fs::metadata(copy).and_then(|m| m.modified()).ok(),
                        category: Category::Duplicate,
                        group: format!("{} copies · {}", count, format::bytes(size)),
                        note: format!("Identical to {keeper_name}"),
                        special: false,
                    });
                }
            }
        }
    }
}

/// Hashes a file in 64 KiB chunks, optionally stopping after `limit` bytes.
fn hash_file(path: &Path, limit: Option<u64>, cancel: &AtomicBool) -> Option<[u8; 32]> {
    let file = std::fs::File::open(path).ok()?;
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut remaining = limit.unwrap_or(u64::MAX);
    while remaining > 0 {
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        let want = if remaining >= buffer.len() as u64 {
            buffer.len()
        } else {
            remaining as usize
        };
        match reader.read(&mut buffer[..want]) {
            Ok(0) => break,
            Ok(read) => {
                hasher.update(&buffer[..read]);
                remaining -= read as u64;
            }
            Err(_) => return None,
        }
    }
    Some(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hash_detects_identical_content_only() {
        let dir = std::env::temp_dir().join(format!("winclean-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        let c = dir.join("c.bin");
        let mut file = std::fs::File::create(&a).unwrap();
        file.write_all(&vec![1u8; 200_000]).unwrap();
        std::fs::write(&b, vec![1u8; 200_000]).unwrap();
        std::fs::write(&c, vec![2u8; 200_000]).unwrap();
        let cancel = AtomicBool::new(false);

        let ha = hash_file(&a, None, &cancel).unwrap();
        let hb = hash_file(&b, None, &cancel).unwrap();
        let hc = hash_file(&c, None, &cancel).unwrap();
        assert_eq!(ha, hb);
        assert_ne!(ha, hc);

        // Partial hash of the first 32 KiB is also identical for equal prefixes.
        let pa = hash_file(&a, Some(PARTIAL_BYTES), &cancel).unwrap();
        let pb = hash_file(&b, Some(PARTIAL_BYTES), &cancel).unwrap();
        assert_eq!(pa, pb);

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn missing_files_are_skipped() {
        let cancel = AtomicBool::new(false);
        assert!(hash_file(Path::new("definitely-not-here.bin"), None, &cancel).is_none());
    }
}
