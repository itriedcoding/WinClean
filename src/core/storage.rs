//! Storage analysis: low-space detection, quantified recommendations and the
//! dashboard health score. All numbers come from real scans, never guesses.

use crate::format;
use crate::model::{
    DefenderStatus, HealthCheck, HealthState, Recommendation, RecommendationAction, Volume,
};

pub fn lowest_free_volume(volumes: &[Volume]) -> Option<&Volume> {
    volumes
        .iter()
        .filter(|volume| volume.fixed && volume.total > 0)
        .min_by_key(|volume| volume.free)
}

pub fn is_low_storage(volume: &Volume, threshold_bytes: u64) -> bool {
    volume.free < threshold_bytes
}

pub fn free_percent(volume: &Volume) -> f32 {
    format::percent(volume.free, volume.total)
}

/// Quantities produced by the last scan, used to build recommendations.
#[derive(Debug, Clone, Default)]
pub struct StorageInsight {
    pub cleanup_bytes: u64,
    pub browser_bytes: u64,
    pub update_cache_bytes: u64,
    pub recycle_bytes: u64,
    pub large_file_bytes: u64,
    pub duplicate_bytes: u64,
    pub executable_temp_count: usize,
}

/// Ordered, quantified recommendations. Safe actions are listed first.
pub fn recommendations(insight: &StorageInsight, largest_threshold: u64) -> Vec<Recommendation> {
    let mut list = Vec::new();
    if insight.cleanup_bytes > 0 {
        list.push(Recommendation {
            title: "Clean temporary files and caches".to_string(),
            detail: "Temporary files, browser caches, crash dumps and error reports found by the last scan."
                .to_string(),
            bytes: insight.cleanup_bytes,
            action: RecommendationAction::OpenQuickClean,
        });
    }
    if insight.browser_bytes > 0 {
        list.push(Recommendation {
            title: "Clear browser caches".to_string(),
            detail: "Cached web content only — bookmarks, history and passwords are kept."
                .to_string(),
            bytes: insight.browser_bytes,
            action: RecommendationAction::OpenQuickClean,
        });
    }
    if insight.update_cache_bytes > 0 {
        list.push(Recommendation {
            title: "Remove Windows Update leftovers".to_string(),
            detail: "Update payloads that have already been installed.".to_string(),
            bytes: insight.update_cache_bytes,
            action: RecommendationAction::OpenDeepClean,
        });
    }
    if insight.recycle_bytes > 0 {
        list.push(Recommendation {
            title: "Empty the Recycle Bin".to_string(),
            detail: "Files you deleted earlier are still occupying disk space.".to_string(),
            bytes: insight.recycle_bytes,
            action: RecommendationAction::OpenRecycleBin,
        });
    }
    if insight.duplicate_bytes > 0 {
        list.push(Recommendation {
            title: "Review duplicate files".to_string(),
            detail: "Byte-identical copies of the same file; keep one and remove the rest."
                .to_string(),
            bytes: insight.duplicate_bytes,
            action: RecommendationAction::OpenDeepClean,
        });
    }
    if insight.large_file_bytes > 0 {
        list.push(Recommendation {
            title: "Review large files".to_string(),
            detail: format!(
                "Files larger than {} — often videos, installers or backups you no longer need.",
                format::bytes(largest_threshold)
            ),
            bytes: insight.large_file_bytes,
            action: RecommendationAction::OpenLargeFiles,
        });
    }
    list.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    list
}

/// Input for the dashboard health score.
pub struct HealthInput<'a> {
    pub volumes: &'a [Volume],
    pub threshold_bytes: u64,
    pub cleanup_bytes: u64,
    pub recycle_bytes: u64,
    pub startup_enabled: usize,
    pub defender: Option<&'a DefenderStatus>,
}

pub fn health_checks(input: &HealthInput<'_>) -> Vec<HealthCheck> {
    let mut checks = Vec::new();

    match lowest_free_volume(input.volumes) {
        Some(volume) => {
            let percent = free_percent(volume);
            let (state, deduction) = if percent < 5.0 {
                (HealthState::Critical, 30)
            } else if percent < 10.0 || volume.free < input.threshold_bytes {
                (HealthState::Warning, 12)
            } else {
                (HealthState::Good, 0)
            };
            checks.push(HealthCheck {
                title: "Free disk space".to_string(),
                detail: format!(
                    "{} ({}) free of {} on {}",
                    format::bytes(volume.free),
                    format::percent(volume.free, volume.total).round() as u32,
                    format::bytes(volume.total),
                    volume.mount.trim_end_matches('\\')
                ),
                state,
                deduction,
            });
        }
        None => checks.push(HealthCheck {
            title: "Free disk space".to_string(),
            detail: "No fixed drive reported".to_string(),
            state: HealthState::Warning,
            deduction: 5,
        }),
    }

    if let Some(status) = input.defender {
        if !status.available {
            checks.push(HealthCheck {
                title: "Microsoft Defender".to_string(),
                detail: status
                    .error
                    .clone()
                    .unwrap_or_else(|| "Status unavailable on this system".to_string()),
                state: HealthState::Warning,
                deduction: 0,
            });
        } else {
            let (state, deduction) = if !status.antivirus_enabled {
                (HealthState::Critical, 25)
            } else if !status.realtime_enabled {
                (HealthState::Warning, 15)
            } else if status.signature_age_days.unwrap_or(0) > 7 {
                (HealthState::Warning, 8)
            } else {
                (HealthState::Good, 0)
            };
            let detail = if !status.antivirus_enabled {
                "Antivirus protection is turned off".to_string()
            } else if !status.realtime_enabled {
                "Real-time protection is turned off".to_string()
            } else {
                match status.signature_age_days {
                    Some(days) if days > 0 => {
                        format!("Real-time protection on · signatures {} day(s) old", days)
                    }
                    _ => "Real-time protection on · signatures up to date".to_string(),
                }
            };
            checks.push(HealthCheck {
                title: "Microsoft Defender".to_string(),
                detail,
                state,
                deduction,
            });
        }
    }

    let cleanup_state = if input.cleanup_bytes > 8 * 1024 * 1024 * 1024 {
        (HealthState::Warning, 8)
    } else if input.cleanup_bytes > 1024 * 1024 * 1024 {
        (HealthState::Warning, 4)
    } else {
        (HealthState::Good, 0)
    };
    checks.push(HealthCheck {
        title: "Temporary files".to_string(),
        detail: format!(
            "{} of recoverable temporary data",
            format::bytes(input.cleanup_bytes)
        ),
        state: cleanup_state.0,
        deduction: cleanup_state.1,
    });

    let startup_state = if input.startup_enabled > 20 {
        (HealthState::Warning, 6)
    } else if input.startup_enabled > 12 {
        (HealthState::Warning, 3)
    } else {
        (HealthState::Good, 0)
    };
    checks.push(HealthCheck {
        title: "Startup applications".to_string(),
        detail: format!("{} apps launch at sign-in", input.startup_enabled),
        state: startup_state.0,
        deduction: startup_state.1,
    });

    let recycle_state = if input.recycle_bytes > 10 * 1024 * 1024 * 1024 {
        (HealthState::Warning, 5)
    } else {
        (HealthState::Good, 0)
    };
    checks.push(HealthCheck {
        title: "Recycle Bin".to_string(),
        detail: format!(
            "{} waiting to be emptied",
            format::bytes(input.recycle_bytes)
        ),
        state: recycle_state.0,
        deduction: recycle_state.1,
    });

    checks
}

pub fn score(checks: &[HealthCheck]) -> u32 {
    let deductions: u32 = checks.iter().map(|check| check.deduction).sum();
    100u32.saturating_sub(deductions).min(100)
}

/// Storage buckets for the dashboard visualization. The three segments always
/// add up to `total` so the bar can be drawn proportionally.
pub fn stacked_segments(volume: &Volume, cleanup_bytes: u64) -> Vec<(&'static str, u64)> {
    let reclaimable = cleanup_bytes.min(volume.free).min(volume.used());
    let other_used = volume.used().saturating_sub(reclaimable);
    vec![
        ("Reclaimable", reclaimable),
        ("In use", other_used),
        ("Free", volume.free),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(free: u64, total: u64) -> Volume {
        Volume {
            mount: "C:\\".into(),
            label: "System".into(),
            total,
            free,
            fixed: true,
        }
    }

    #[test]
    fn detects_low_storage() {
        let small = volume(50 * 1024 * 1024 * 1024, 500 * 1024 * 1024 * 1024);
        assert!(is_low_storage(&small, 100 * 1024 * 1024 * 1024));
        let large = volume(200 * 1024 * 1024 * 1024, 500 * 1024 * 1024 * 1024);
        assert!(!is_low_storage(&large, 100 * 1024 * 1024 * 1024));
    }

    #[test]
    fn picks_the_fullest_volume() {
        let volumes = vec![volume(200, 500), volume(10, 500)];
        assert_eq!(lowest_free_volume(&volumes).unwrap().free, 10);
    }

    #[test]
    fn recommendations_are_sorted_by_size_and_quantified() {
        let insight = StorageInsight {
            cleanup_bytes: 4_000,
            browser_bytes: 1_000,
            update_cache_bytes: 9_000,
            recycle_bytes: 2_000,
            large_file_bytes: 50_000,
            duplicate_bytes: 300,
            executable_temp_count: 0,
        };
        let list = recommendations(&insight, 1024 * 1024 * 1024);
        assert_eq!(list.len(), 6);
        assert!(list[0].bytes >= list[1].bytes);
        assert_eq!(list[0].bytes, 50_000);
        assert_eq!(list[0].action, RecommendationAction::OpenLargeFiles);
        assert!(list.iter().all(|rec| rec.bytes > 0));
    }

    #[test]
    fn health_score_reflects_real_problems() {
        let volumes = vec![volume(4 * 1024 * 1024 * 1024, 500 * 1024 * 1024 * 1024)];
        let defender = DefenderStatus {
            available: true,
            antivirus_enabled: true,
            realtime_enabled: true,
            antispyware_enabled: true,
            signature_version: "1.0".into(),
            signature_age_days: Some(1),
            last_quick_scan: None,
            last_full_scan: None,
            tamper_protection: true,
            error: None,
        };
        let checks = health_checks(&HealthInput {
            volumes: &volumes,
            threshold_bytes: 100 * 1024 * 1024 * 1024,
            cleanup_bytes: 0,
            recycle_bytes: 0,
            startup_enabled: 4,
            defender: Some(&defender),
        });
        let score = score(&checks);
        assert!(score <= 88, "low free space must be deducted, got {score}");
        assert!(checks.iter().any(|c| c.state == HealthState::Critical));
    }

    #[test]
    fn perfect_system_scores_100() {
        let volumes = vec![volume(300 * 1024 * 1024 * 1024, 500 * 1024 * 1024 * 1024)];
        let defender = DefenderStatus {
            available: true,
            antivirus_enabled: true,
            realtime_enabled: true,
            antispyware_enabled: true,
            signature_version: "1.0".into(),
            signature_age_days: Some(0),
            last_quick_scan: None,
            last_full_scan: None,
            tamper_protection: true,
            error: None,
        };
        let checks = health_checks(&HealthInput {
            volumes: &volumes,
            threshold_bytes: 100 * 1024 * 1024 * 1024,
            cleanup_bytes: 0,
            recycle_bytes: 0,
            startup_enabled: 3,
            defender: Some(&defender),
        });
        assert_eq!(score(&checks), 100);
    }
}
