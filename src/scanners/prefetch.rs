
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::models::{AuditFinding, ModuleResult, Status};
use crate::util::now_iso;

const MODULE_ID: &str = "prefetch";
const MODULE_NAME: &str = "Prefetch Recency and Wipe Detection";
const PREFETCH_DIR: &str = r"C:\Windows\Prefetch";
const WIPE_MAX_COUNT: usize = 15;

pub fn scan(_window_hours: f64) -> ModuleResult {
    let t0 = Instant::now();
    let mut res = ModuleResult::new(MODULE_ID, MODULE_NAME, true);
    let dir = Path::new(PREFETCH_DIR);

    let entries: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path())
            .filter(|p| p.extension().map(|e| e.eq_ignore_ascii_case("pf")).unwrap_or(false))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            res.findings.push(AuditFinding::new(
                MODULE_ID, Status::Info, now_iso(), PREFETCH_DIR.into(),
                "access denied".into(),
                "Prefetch requires elevation; use Elevate for a deep read.".into(),
            ));
            res.elapsed_ms = t0.elapsed().as_millis();
            return res.finalize();
        }
        Err(e) => {
            res.findings.push(AuditFinding::new(
                MODULE_ID, Status::Info, now_iso(), PREFETCH_DIR.into(),
                format!("io: {}", e),
                "Prefetch unavailable (disabled or non-standard location).".into(),
            ));
            res.elapsed_ms = t0.elapsed().as_millis();
            return res.finalize();
        }
    };

    let mut stats: Vec<(PathBuf, u64)> = entries
        .into_iter()
        .filter_map(|p| p.metadata().ok()
            .and_then(|m| m.modified().ok())
            .map(|t| (p, t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))))
        .collect();

    let uptime = crate::selfcheck::uptime_seconds();
    if stats.len() < WIPE_MAX_COUNT {
        res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Flagged, now_iso(), PREFETCH_DIR.into(),
            format!("pf_count={} threshold={}", stats.len(), WIPE_MAX_COUNT),
            "Very few Prefetch files. Consistent with a recent wipe ('cleaner' tool).".into(),
        ));
    } else if let Some(oldest) = stats.iter().map(|(_, m)| *m).min() {
        let boot_estimate = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
            .saturating_sub(uptime);
        if uptime > 3600 && oldest > boot_estimate + 1800 {
            res.findings.push(AuditFinding::new(
                MODULE_ID, Status::Flagged, now_iso(), PREFETCH_DIR.into(),
                format!("oldest_pf_epoch={} boot+30m={}", oldest, boot_estimate + 1800),
                "Oldest Prefetch file is newer than boot+30min while uptime>1h. Prefetch was likely purged.".into(),
            ));
        } else {
            res.findings.push(AuditFinding::new(
                MODULE_ID, Status::Clean, now_iso(), PREFETCH_DIR.into(),
                format!("pf_count={}", stats.len()),
                "Prefetch population looks normal; no mass-wipe signature.".into(),
            ));
        }
    }

    stats.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    for (path, mtime) in stats.into_iter().take(25) {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        let exe = name.split('-').next().unwrap_or(name);
        let ts = chrono::DateTime::<chrono::Utc>::from_timestamp(mtime as i64, 0)
            .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_else(|| "n/a".into());
        res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Info, ts, path.to_string_lossy().into_owned(),
            format!("file={}", name),
            format!("Prefetch record for {}. Name parsed from the .pf filename; run-count lives in the MAM-compressed body and is not decoded here.", exe),
        ));
    }
    if res.findings.is_empty() {
        res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Clean, now_iso(), PREFETCH_DIR.into(),
            "0 pf files".into(),
            "No Prefetch records present.".into(),
        ));
    }
    res.elapsed_ms = t0.elapsed().as_millis();
    res.finalize()
}
