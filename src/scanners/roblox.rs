
use std::time::Instant;

use crate::models::{AuditFinding, ModuleResult, Status};
use crate::util::now_iso;

const MODULE_ID: &str = "roblox";
const MODULE_NAME: &str = "Roblox Client and Timeline Integrity";
const PROXY_DLLS: &[&str] = &["dxgi.dll", "d3d11.dll", "version.dll", "winmm.dll", "winhttp.dll", "d3d9.dll"];

fn file_time_iso(path: &std::path::Path) -> String {
    path.metadata()
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| {
            chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, 0)
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| "n/a".into())
        })
        .unwrap_or_else(|| "n/a".into())
}

pub fn scan(_window_hours: f64) -> ModuleResult {
    let t0 = Instant::now();
    let mut res = ModuleResult::new(MODULE_ID, MODULE_NAME, false);
    let local = std::env::var("LOCALAPPDATA").unwrap_or_default();

    let versions_root = std::path::Path::new(&local).join("Roblox").join("Versions");
    match std::fs::read_dir(&versions_root) {
        Err(_) => {
            res.findings.push(AuditFinding::new(
                MODULE_ID, Status::Info, now_iso(), versions_root.to_string_lossy().into_owned(),
                "not installed".into(),
                "Roblox not found under %LocalAppData%.".into(),
            ));
        }
        Ok(rd) => {
            for entry in rd.flatten() {
                let vdir = entry.path();
                if !vdir.is_dir() {
                    continue;
                }
                let player = vdir.join("RobloxPlayerBeta.exe");
                if player.is_file() {
                    res.findings.push(AuditFinding::new(
                        MODULE_ID, Status::Info, file_time_iso(&player),
                        player.to_string_lossy().into_owned(),
                        format!("version_dir={}", entry.file_name().to_string_lossy()),
                        "Official client bootstrapper present.".into(),
                    ));
                }
                for dll in PROXY_DLLS {
                    let candidate = vdir.join(dll);
                    if candidate.is_file() {
                        let size = candidate.metadata().map(|m| m.len()).unwrap_or(0);
                        res.findings.push(AuditFinding::new(
                            MODULE_ID, Status::Flagged, file_time_iso(&candidate),
                            candidate.to_string_lossy().into_owned(),
                            format!("proxy_dll={} size={}B", dll, size),
                            "Proxy DLL inside the Roblox client directory. Classic internal-executor sideload pattern; legitimate clients do not ship these.".into(),
                        ));
                    }
                }
            }
        }
    }

    let logs_dir = std::path::Path::new(&local).join("Roblox").join("logs");
    let mut latest: Option<std::path::PathBuf> = None;
    if let Ok(rd) = std::fs::read_dir(&logs_dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().map(|e| e.eq_ignore_ascii_case("log")).unwrap_or(false) {
                let better = match &latest {
                    None => true,
                    Some(cur) => p.metadata().and_then(|m| m.modified()).ok()
                        > cur.metadata().and_then(|m| m.modified()).ok(),
                };
                if better {
                    latest = Some(p);
                }
            }
        }
    }
    match latest {
        Some(p) => res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Info, file_time_iso(&p), p.to_string_lossy().into_owned(),
            format!("log={}", p.file_name().and_then(|n| n.to_str()).unwrap_or("?")),
            "Latest Roblox session log. Use this timestamp to anchor the match timeline against BAM and USN findings.".into(),
        )),
        None => res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Info, now_iso(), logs_dir.to_string_lossy().into_owned(),
            "no logs".into(),
            "No Roblox session logs found.".into(),
        )),
    }

    if res.findings.is_empty() {
        res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Clean, now_iso(),
            versions_root.to_string_lossy().into_owned(),
            "nothing found".into(),
            "Roblox directories audited; no proxy DLLs detected.".into(),
        ));
    }
    res.elapsed_ms = t0.elapsed().as_millis();
    res.finalize()
}
