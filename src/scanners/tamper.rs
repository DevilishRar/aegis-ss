
use std::time::Instant;

use crate::ffi;
use crate::models::{AuditFinding, ModuleResult, Status};
use crate::scan::deep_enabled;
use crate::util::now_iso;

const MODULE_ID: &str = "tamper";
const MODULE_NAME: &str = "Event Log Tamper and Service Integrity";
const WATCH_SERVICES: &[&str] = &["SysMain", "EventLog", "DPS", "PcaSvc"];

fn service_state(name: &str) -> Option<u32> {
    let wide_name = ffi::wide(name);
    unsafe {
        let scm = ffi::OpenSCManagerW(std::ptr::null(), std::ptr::null(), ffi::SC_MANAGER_CONNECT);
        if scm == 0 || scm == ffi::INVALID_HANDLE_VALUE {
            return None;
        }
        let svc = ffi::OpenServiceW(scm, wide_name.as_ptr(), ffi::SERVICE_QUERY_STATUS);
        if svc == 0 || svc == ffi::INVALID_HANDLE_VALUE {
            ffi::CloseServiceHandle(scm);
            return None;
        }
        let mut status = ffi::SERVICE_STATUS {
            dwServiceType: 0, dwCurrentState: 0, dwControlsAccepted: 0,
            dwWin32ExitCode: 0, dwServiceSpecificExitCode: 0, dwCheckPoint: 0, dwWaitHint: 0,
        };
        let ok = ffi::QueryServiceStatus(svc, &mut status);
        ffi::CloseServiceHandle(svc);
        ffi::CloseServiceHandle(scm);
        if ok == ffi::FALSE {
            None
        } else {
            Some(status.dwCurrentState)
        }
    }
}


fn query_log_clears_deep() -> Vec<AuditFinding> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut out = Vec::new();
    for (log, id, text) in [
        ("Security", 1102, "Security audit log cleared in the last 24h. Classic anti-forensics."),
        ("System", 104, "System log cleared in the last 24h."),
    ] {
        let query = format!("*[System[(EventID={}) and TimeCreated[timediff(@SystemTime) <= 86400000]]]", id);
        let result = Command::new("wevtutil")
            .args(["qe", log, &format!("/q:{}", query), "/f:text", "/c:10", "/rd:true"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        match result {
            Ok(o) => {
                let text_out = String::from_utf8_lossy(&o.stdout);
                let lines: Vec<&str> = text_out.lines().filter(|l| !l.trim().is_empty()).collect();
                if lines.is_empty() {
                    continue;
                }
                out.push(AuditFinding::new(
                    MODULE_ID, Status::Flagged, now_iso(), format!("{} event {}", log, id),
                    format!("event_id={} entries={}", id, lines.len()),
                    text.to_string(),
                ));
            }
            Err(e) => out.push(AuditFinding::new(
                MODULE_ID, Status::Info, now_iso(), log.into(),
                format!("io: {}", e),
                format!("{} log needs elevation.", log),
            )),
        }
    }
    if out.is_empty() {
        out.push(AuditFinding::new(
            MODULE_ID, Status::Clean, now_iso(), "EventLog".into(),
            "1102/104 not observed".into(),
            "No audit-log-clear events in the last 24h.".into(),
        ));
    }
    out
}

pub fn scan(_window_hours: f64) -> ModuleResult {
    let t0 = Instant::now();
    let mut res = ModuleResult::new(MODULE_ID, MODULE_NAME, true);

    if deep_enabled() {
        res.findings = query_log_clears_deep();
    } else {
        res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Info, now_iso(), "EventLog".into(),
            "skipped (fast mode)".into(),
            "Log-clear detection (1102/104) needs wevtutil; enable Deep scan to include it.".into(),
        ));
    }

    let mut running = Vec::new();
    for svc in WATCH_SERVICES {
        match service_state(svc) {
            Some(ffi::SERVICE_RUNNING) => running.push(*svc),
            Some(_) => {
                let watch = *svc == "SysMain" || *svc == "DPS";
                res.findings.push(AuditFinding::new(
                    MODULE_ID,
                    if watch { Status::Warning } else { Status::Info },
                    now_iso(),
                    format!("service:{}", svc),
                    "state=not running".into(),
                    if watch {
                        format!("{} is not running. It feeds {}; stopping it suppresses forensic breadcrumbs.",
                                svc, if *svc == "SysMain" { "Prefetch" } else { "diagnostics" })
                    } else {
                        format!("{} is not running.", svc)
                    },
                ));
            }
            None => res.findings.push(AuditFinding::new(
                MODULE_ID, Status::Info, now_iso(), format!("service:{}", svc),
                "query failed".into(),
                format!("{} state could not be queried.", svc),
            )),
        }
    }
    res.findings.push(AuditFinding::new(
        MODULE_ID, Status::Info, now_iso(), "services".into(),
        format!("running={}", running.join(",")),
        format!("Critical forensic services running: {}.", if running.is_empty() { "none".into() } else { running.join(", ") }),
    ));

    res.elapsed_ms = t0.elapsed().as_millis();
    res.finalize()
}
