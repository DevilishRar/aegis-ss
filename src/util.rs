
use chrono::{DateTime, Utc};

pub const FILETIME_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;

pub fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn filetime_to_iso(ft: u64) -> String {
    if ft <= FILETIME_EPOCH_OFFSET {
        return "n/a".to_string();
    }
    let secs = (ft - FILETIME_EPOCH_OFFSET) / 10_000_000;
    match DateTime::<Utc>::from_timestamp(secs as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        None => "n/a".to_string(),
    }
}

pub fn filetime_to_unix(ft: u64) -> f64 {
    if ft <= FILETIME_EPOCH_OFFSET {
        return 0.0;
    }
    (ft - FILETIME_EPOCH_OFFSET) as f64 / 10_000_000.0
}

pub fn is_random_exe(name_lower: &str) -> bool {
    let stem = match name_lower.strip_suffix(".exe") {
        Some(s) => s,
        None => return false,
    };
    (8..=16).contains(&stem.len())
        && stem
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}


pub fn path_risk_reason(path: &str) -> Option<String> {
    let low = path.to_lowercase();
    const MARKERS: &[&str] = &[
        "\\appdata\\local\\temp",
        "\\appdata\\local\\packages\\",
        "\\downloads\\",
        "\\desktop\\",
        "\\appdata\\roaming\\",
    ];
    for m in MARKERS {
        if low.contains(m) {
            return Some(format!("path under {}", m.trim_matches('\\')));
        }
    }
    let in_trusted_root = low.contains("\\windows\\") || low.contains("\\program files");
    if low.len() >= 3 && low.as_bytes()[1] == b':' {
        let drive = low.as_bytes()[0].to_ascii_uppercase() as char;
        if drive.is_ascii_alphabetic() && drive != 'C' {
            return Some(format!("runs from drive {}: (often removable/secondary)", drive));
        }
    }
    let name = low.rsplit('\\').next().unwrap_or(&low);
    if !in_trusted_root && is_random_exe(name) {
        return Some("random-looking 8-16 char executable name".to_string());
    }
    None
}
