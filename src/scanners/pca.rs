
use std::time::Instant;

use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

use crate::models::{AuditFinding, ModuleResult, Status};
use crate::util::{now_iso, path_risk_reason};

const MODULE_ID: &str = "pca";
const MODULE_NAME: &str = "PCA / MuiCache Residual Evidence";
const MAX_FINDINGS: usize = 60;

fn scan_key(hive: winreg::HKEY, path: &str, note: &str) -> Vec<AuditFinding> {
    let mut out = Vec::new();
    let root = RegKey::predef(hive);
    let key = match root.open_subkey_with_flags(path, KEY_READ) {
        Ok(k) => k,
        Err(_) => return out,
    };
    for value in key.enum_values().flatten() {
        let (name, data) = value;
        let low = name.to_lowercase();
        if !(low.ends_with(".exe") || low.ends_with(".dll") || low.ends_with(".msi")
            || low.ends_with(".bat") || low.ends_with(".ps1")) {
            continue;
        }
        let data_preview: String = String::from_utf8_lossy(&data.bytes).chars().take(120).collect();
        if let Some(reason) = path_risk_reason(&name) {
            out.push(AuditFinding::new(
                MODULE_ID,
                Status::Warning,
                now_iso(),
                name.clone(),
                format!("{}; risk={}; data={}", note, reason, data_preview),
                format!("Cached compatibility record of a binary in a risky location ({}). Survives deletion of the file.", reason),
            ));
        } else if out.len() < MAX_FINDINGS {
            out.push(AuditFinding::new(
                MODULE_ID,
                Status::Info,
                now_iso(),
                name.clone(),
                note.to_string(),
                "Cached compatibility record. Informational unless correlated with other flags.".into(),
            ));
        }
        if out.len() >= MAX_FINDINGS {
            break;
        }
    }
    out
}

pub fn scan(_window_hours: f64) -> ModuleResult {
    let t0 = Instant::now();
    let mut res = ModuleResult::new(MODULE_ID, MODULE_NAME, false);
    res.findings = scan_key(HKEY_CURRENT_USER,
        r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", "MuiCache");
    res.findings.extend(scan_key(HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
        "AppCompatStore"));
    if res.findings.is_empty() {
        res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Clean, now_iso(), "MuiCache+AppCompat".into(),
            "no cached binaries".into(),
            "No cached executable records found in MuiCache / AppCompat Store.".into(),
        ));
    }
    res.elapsed_ms = t0.elapsed().as_millis();
    res.finalize()
}
