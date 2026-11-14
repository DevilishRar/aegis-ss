





use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::Instant;

use crate::models::{ModuleResult, SystemSnapshot};
use crate::scanners::{bam, defender, pca, prefetch, process, roblox, tamper, usn};
use crate::util::now_iso;

static DEEP: AtomicBool = AtomicBool::new(false);

pub fn deep_enabled() -> bool {
    DEEP.load(Ordering::Relaxed)
}

#[derive(Clone, Debug)]
pub enum ScanEvent {
    ModuleDone(ModuleResult),
    Finished(SystemSnapshot),
}

struct Scanner {
    id: &'static str,
    f: fn(f64) -> ModuleResult,
}

const SCANNERS: &[Scanner] = &[
    Scanner { id: "bam", f: bam::scan },
    Scanner { id: "prefetch", f: prefetch::scan },
    Scanner { id: "usn", f: usn::scan },
    Scanner { id: "defender", f: defender::scan },
    Scanner { id: "tamper", f: tamper::scan },
    Scanner { id: "pca", f: pca::scan },
    Scanner { id: "process", f: process::scan },
    Scanner { id: "roblox", f: roblox::scan },
];

pub const MODULE_COUNT: usize = 8;

fn build_snapshot_shell() -> SystemSnapshot {
    SystemSnapshot {
        captured_utc: now_iso(),
        hostname: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "?".into()),
        username: std::env::var("USERNAME").unwrap_or_else(|_| "?".into()),
        os_caption: std::env::consts::OS.to_string(),
        boot_uptime_seconds: crate::selfcheck::uptime_seconds(),
        elevated: crate::selfcheck::is_elevated(),
        results: Vec::with_capacity(MODULE_COUNT),
    }
}


pub fn start_scan(window_hours: f64, deep: bool) -> Receiver<ScanEvent> {
    DEEP.store(deep, Ordering::Relaxed);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _t_total = Instant::now();
        let (mod_tx, mod_rx) = mpsc::channel::<ModuleResult>();

        std::thread::scope(|s| {
            for scanner in SCANNERS {
                let mod_tx = mod_tx.clone();
                s.spawn(move || {
                    let result = std::panic::catch_unwind(|| (scanner.f)(window_hours))
                        .unwrap_or_else(|_| {
                            let mut r = ModuleResult::new(scanner.id, scanner.id, false);
                            r.error = "scanner panicked (isolated from the rest of the audit)".to_string();
                            r.finalize()
                        });
                    let _ = mod_tx.send(result);
                });
            }
            drop(mod_tx);
        });

        let mut snapshot = build_snapshot_shell();
        while let Ok(result) = mod_rx.recv() {
            let _ = tx.send(ScanEvent::ModuleDone(result.clone()));
            snapshot.results.push(result);
        }
        snapshot.results.sort_by(|a, b| a.module_id.cmp(&b.module_id));
        let _ = tx.send(ScanEvent::Finished(snapshot));
    });
    rx
}


pub fn run_scan(window_hours: f64, deep: bool) -> (SystemSnapshot, u128) {
    let t0 = Instant::now();
    let rx = start_scan(window_hours, deep);
    let mut snapshot = None;
    while let Ok(ev) = rx.recv() {
        if let ScanEvent::Finished(s) = ev {
            snapshot = Some(s);
        }
    }
    (snapshot.unwrap_or_else(build_snapshot_shell), t0.elapsed().as_millis())
}
