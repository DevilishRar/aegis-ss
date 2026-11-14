
use std::time::Instant;

use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

use crate::models::{AuditFinding, ModuleResult, Status};
use crate::util::{filetime_to_iso, filetime_to_unix, now_iso, path_risk_reason};

const MODULE_ID: &str = "bam";
const MODULE_NAME: &str = "BAM / DAM Execution History";

fn read_hive(svc: &str, cutoff_unix: f64) -> Vec<AuditFinding> {
    let mut out = Vec::new();
    let base_path = format!(r"SYSTEM\CurrentControlSet\Services\{}\State\UserSettings", svc);
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let sid_root = match hklm.open_subkey_with_flags(&base_path, KEY_READ) {
        Ok(k) => k,
        Err(_) => {
            out.push(AuditFinding::new(
                MODULE_ID,
                Status::Info,
                now_iso(),
                base_path,
                "key not present or denied".into(),
                format!("{} hive not readable (Server SKU or needs elevation).", svc.to_uppercase()),
            ));
            return out;
        }
    };
    for sid in sid_root.enum_keys().flatten() {
        let sid_key = match sid_root.open_subkey_with_flags(&sid, KEY_READ) {
            Ok(k) => k,
            Err(_) => continue,
        };
        for value in sid_key.enum_values().flatten() {
            let (name, data) = value;
            if data.bytes.len() < 8 {
                continue;
            }
            let ft = u64::from_le_bytes(data.bytes[..8].try_into().unwrap());
            let ts = filetime_to_unix(ft);
            if ts < cutoff_unix {
                continue;
            }
            let risk = path_risk_reason(&name);
            let status = if risk.is_some() { Status::Flagged } else { Status::Info };
            out.push(AuditFinding::new(
                MODULE_ID,
                status,
                filetime_to_iso(ft),
                name.clone(),
                format!("{} SID={} FILETIME={}", svc.to_uppercase(), sid, ft),
                match &risk {
                    Some(r) => format!("Launched within the window; risk: {}.", r),
                    None => "Launched within the window.".to_string(),
                },
            ));
        }
    }
    out
}

pub fn scan(window_hours: f64) -> ModuleResult {
    let t0 = Instant::now();
    let mut res = ModuleResult::new(MODULE_ID, MODULE_NAME, false);
    let cutoff = chrono::Utc::now().timestamp() as f64 - window_hours * 3600.0;
    res.findings = read_hive("bam", cutoff);
    res.findings.extend(read_hive("dam", cutoff));
    if res.findings.is_empty() {
        res.findings.push(AuditFinding::new(
            MODULE_ID,
            Status::Clean,
            now_iso(),
            "bam+dam".into(),
            "no values inside window".into(),
            format!("No executables launched in the last {:.1}h recorded by BAM/DAM.", window_hours),
        ));
    }
    res.elapsed_ms = t0.elapsed().as_millis();
    res.finalize()
}
