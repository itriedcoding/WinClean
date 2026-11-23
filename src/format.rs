//! Human readable formatting helpers shared by the UI and the CLI.
//!
//! Deliberately dependency free: civil date conversion is implemented here so the
//! binary does not need a calendar crate for a handful of labels.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Formats a byte count using Windows conventions (binary units, "GB" labels).
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

/// Compact form used inside charts and table cells, e.g. `1.4G`.
pub fn bytes_short(n: u64) -> String {
    let formatted = bytes(n);
    match formatted.split_once(' ') {
        Some((value, unit)) if unit != "B" => format!("{value}{}", &unit[..1]),
        Some((value, unit)) => format!("{value}{unit}"),
        None => formatted,
    }
}

/// Adds thousands separators to an integer count.
pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Formats a duration as `1m 04s` or `840ms`.
pub fn duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs == 0 {
        return format!("{} ms", d.as_millis());
    }
    if secs < 60 {
        return format!("{}.{} s", secs, d.subsec_millis() / 100);
    }
    let minutes = secs / 60;
    let remaining = secs % 60;
    if minutes < 60 {
        format!("{minutes}m {remaining:02}s")
    } else {
        format!("{}h {:02}m", minutes / 60, minutes % 60)
    }
}

/// Formats an absolute timestamp for the given UTC offset in seconds.
pub fn date_time(t: SystemTime, tz_offset_secs: i64) -> String {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(err) => -(err.duration().as_secs() as i64),
    };
    let (year, month, day, hour, minute, second) = civil_from_unix(secs + tz_offset_secs);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

/// Date only variant.
pub fn date(t: SystemTime, tz_offset_secs: i64) -> String {
    let full = date_time(t, tz_offset_secs);
    full[..10].to_string()
}

/// Relative label such as `3 days ago` for display in tables.
pub fn relative(t: SystemTime) -> String {
    match SystemTime::now().duration_since(t) {
        Ok(age) => {
            let secs = age.as_secs();
            if secs < 60 {
                "just now".to_string()
            } else if secs < 3_600 {
                format!("{} min ago", secs / 60)
            } else if secs < 86_400 {
                format!("{} hours ago", secs / 3_600)
            } else if secs < 2_592_000 {
                format!("{} days ago", secs / 86_400)
            } else {
                format!("{} months ago", secs / 2_592_000)
            }
        }
        Err(_) => "in the future".to_string(),
    }
}

/// Returns `(year, month, day, hour, minute, second)` in UTC for a unix timestamp.
pub fn civil_from_unix(unix_secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = (secs_of_day / 3_600) as u32;
    let minute = ((secs_of_day % 3_600) / 60) as u32;
    let second = (secs_of_day % 60) as u32;
    (year, month, day, hour, minute, second)
}

/// Converts a civil UTC timestamp into a unix timestamp (inverse of the above).
pub fn unix_from_civil(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> i64 {
    let y = if month <= 2 {
        year as i64 - 1
    } else {
        year as i64
    };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if month > 2 {
        month as u64 - 3
    } else {
        month as u64 + 9
    };
    let doy = (153 * mp + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    days * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64
}

/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if month <= 2 { year + 1 } else { year };
    (year as i32, month, day)
}

/// `used / total` as a rounded percentage, guarding against division by zero.
pub fn percent(part: u64, total: u64) -> f32 {
    if total == 0 {
        0.0
    } else {
        (part as f64 / total as f64 * 100.0) as f32
    }
}

/// Truncates a path for display in a fixed-width cell.
pub fn ellipsize(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_string();
    }
    let keep = max_chars.saturating_sub(1);
    let mut out: String = text.chars().take(keep).collect();
    out.push('…');
    out
}

/// File extension lowercased, without the dot.
pub fn extension(path: &std::path::Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bytes_with_binary_units() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1024), "1.00 KB");
        assert_eq!(bytes(1024 * 1024), "1.00 MB");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
        assert_eq!(bytes(150 * 1024 * 1024 * 1024), "150 GB");
    }

    #[test]
    fn short_form_is_compact() {
        assert_eq!(bytes_short(1536), "1.50K");
        assert_eq!(bytes_short(42), "42B");
    }

    #[test]
    fn counts_get_separators() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1234), "1,234");
        assert_eq!(count(1234567), "1,234,567");
    }

    #[test]
    fn duration_switches_units() {
        assert_eq!(duration(Duration::from_millis(840)), "840 ms");
        assert_eq!(duration(Duration::from_secs(4)), "4.0 s");
        assert_eq!(duration(Duration::from_secs(64)), "1m 04s");
        assert_eq!(duration(Duration::from_secs(3_700)), "1h 01m");
    }

    #[test]
    fn civil_dates_match_known_values() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_from_unix(1_700_000_000), (2023, 11, 14, 22, 13, 20));
        assert_eq!(civil_from_unix(-86_400), (1969, 12, 31, 0, 0, 0));
    }

    #[test]
    fn unix_and_civil_are_inverse() {
        for sample in [0i64, 1_700_000_000, 1_999_999_999, -86_400] {
            let (y, m, d, h, mi, s) = civil_from_unix(sample);
            assert_eq!(unix_from_civil(y, m, d, h, mi, s), sample);
        }
    }

    #[test]
    fn percent_handles_zero_total() {
        assert_eq!(percent(0, 0), 0.0);
        assert!((percent(1, 4) - 25.0).abs() < f32::EPSILON);
    }

    #[test]
    fn ellipsize_respects_budget() {
        assert_eq!(ellipsize("short", 10), "short");
        assert_eq!(ellipsize("truncated text", 6), "trunc…");
    }
}
