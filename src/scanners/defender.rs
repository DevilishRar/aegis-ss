
use std::time::Instant;

use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

use crate::models::{AuditFinding, ModuleResult, Status};
use crate::scan::deep_enabled;
use crate::util::now_iso;

const MODULE_ID: &str = "defender";
const MODULE_NAME: &str = "Defender Exclusions and Threat History";
const EXCL_ROOT: &str = r"SOFTWARE\Microsoft\Windows Defender\Exclusions";

fn exclusion_risk(name: &str) -> Option<String> {
    let low = name.to_lowercase();
    const HINTS: &[&str] = &["\\downloads", "\\temp", "\\desktop", "\\appdata", "roblox", "executor", "troj"];
    for h in HINTS {
        if low.contains(h) {
            return Some(format!("exclusion touches {}", h.trim_start_matches('\\')));
        }
    }
    let seg = low.trim_end_matches('\\').rsplit('\\').next().unwrap_or(&low);
    if (8..=16).contains(&seg.len())
        && seg.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return Some("exclusion folder name looks randomized".to_string());
    }
    None
}

fn read_exclusions() -> Vec<AuditFinding> {
    let mut out = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    for sub in ["Paths", "Processes"] {
        let path = format!(r"{}\{}", EXCL_ROOT, sub);
        let key = match hklm.open_subkey_with_flags(&path, KEY_READ) {
            Ok(k) => k,
            Err(_) => continue,
        };
        for (name, _data) in key.enum_values().flatten() {
            let kind = sub.trim_end_matches('s').to_lowercase();
            let risk = exclusion_risk(&name);
            out.push(AuditFinding::new(
                MODULE_ID,
                if risk.is_some() { Status::Flagged } else { Status::Info },
                now_iso(),
                name.clone(),
                format!("{}-exclusion={}", kind, name),
                match &risk {
                    Some(r) => format!("Defender {} exclusion. Risk: {}.", kind, r),
                    None => format!("Defender {} exclusion (non-standard; review on the call).", kind),
                },
            ));
        }
    }
    out
}


fn read_threat_events_deep() -> Vec<AuditFinding> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut out = Vec::new();
    let query = "*[System[(EventID=1116 or EventID=1117) and TimeCreated[timediff(@SystemTime) <= 86400000]]]";
    let result = Command::new("wevtutil")
        .args(["qe", "Microsoft-Windows-Windows Defender/Operational",
               &format!("/q:{}", query), "/f:text", "/c:200", "/rd:true"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let text = match result {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(e) => {
            out.push(AuditFinding::new(
                MODULE_ID, Status::Info, now_iso(), "wevtutil".into(),
                format!("io: {}", e),
                "Defender threat events unavailable on this host.".into(),
            ));
            return out;
        }
    };
    let mut current_id = String::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Event ID:") {
            current_id = rest.trim().to_string();
        } else if t.starts_with("Detection Name:") || t.starts_with("Name:") {
            let val = t.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
            if !val.is_empty() && !current_id.is_empty() {
                let flagged = ["hacktool", "troj", "gamehack", "cheat"]
                    .iter().any(|k| val.to_lowercase().contains(k));
                out.push(AuditFinding::new(
                    MODULE_ID,
                    if flagged { Status::Flagged } else { Status::Warning },
                    now_iso(),
                    "Defender/Operational".into(),
                    format!("event_id={} name={}", current_id, val),
                    "Defender detection in the last 24h (deep scan).".into(),
                ));
                current_id.clear();
            }
        }
    }
    if out.is_empty() {
        out.push(AuditFinding::new(
            MODULE_ID, Status::Clean, now_iso(), "Defender/Operational".into(),
            "no 1116/1117 in 24h".into(),
            "No Defender threat detections in the last 24 hours.".into(),
        ));
    }
    out
}

pub fn scan(_window_hours: f64) -> ModuleResult {
    let t0 = Instant::now();
    let mut res = ModuleResult::new(MODULE_ID, MODULE_NAME, true);
    res.findings = read_exclusions();
    if deep_enabled() {
        res.findings.extend(read_threat_events_deep());
    } else {
        res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Info, now_iso(), "Defender/Operational".into(),
            "skipped (fast mode)".into(),
            "Threat-event history needs wevtutil; enable Deep scan to include it.".into(),
        ));
    }
    if res.findings.is_empty() {
        res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Clean, now_iso(), EXCL_ROOT.into(),
            "no exclusions".into(),
            "No Defender path or process exclusions found.".into(),
        ));
    }
    res.elapsed_ms = t0.elapsed().as_millis();
    res.finalize()
}
