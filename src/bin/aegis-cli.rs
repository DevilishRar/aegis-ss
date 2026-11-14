

use aegis_ss_core::models::Status;
use aegis_ss_core::redact;
use aegis_ss_core::scan::run_scan;
use aegis_ss_core::selfcheck;

fn arg_value(flag: &str) -> Option<String> {
    let mut args = std::env::args();
    while let Some(a) = args.next() {
        if a == flag {
            return args.next();
        }
        if let Some(v) = a.strip_prefix(&format!("{}=", flag)) {
            return Some(v.to_string());
        }
    }
    None
}

fn has_flag(flag: &str) -> bool {
    std::env::args().any(|a| a == flag)
}

fn main() {
    let deep = has_flag("--deep");
    let redact_enabled = has_flag("--redact");
    let window_hours: f64 = arg_value("--window-hours").and_then(|v| v.parse().ok()).unwrap_or(2.0);
    let json_path = arg_value("--json");
    let bench: Option<usize> = arg_value("--bench").and_then(|v| v.parse().ok());

    if let Some(n) = bench {
        let mut samples = Vec::with_capacity(n);
        for _ in 0..n {
            let (_snap, ms) = run_scan(window_hours, deep);
            samples.push(ms);
        }
        samples.sort_unstable();
        let sum: u128 = samples.iter().sum();
        println!("bench n={} deep={} window={}h", n, deep, window_hours);
        println!("  min: {} ms", samples[0]);
        println!("  p50: {} ms", samples[samples.len() / 2]);
        println!("  p90: {} ms", samples[(samples.len() * 9) / 10]);
        println!("  max: {} ms", samples[samples.len() - 1]);
        println!("  mean: {:.1} ms", sum as f64 / n as f64);
        return;
    }

    let (snap, total_ms) = run_scan(window_hours, deep);
    let snap = if redact_enabled { redact::redact_snapshot(&snap) } else { snap };
    let counts = snap.counts();

    println!("AEGIS-SS (Rust) - forensic integrity scan");
    println!("captured: {}   host: {}   user: {}", snap.captured_utc, snap.hostname, snap.username);
    println!("elevation: {}   uptime: {}s   modules: {}", if snap.elevated { "ADMIN" } else { "STANDARD USER" }, snap.boot_uptime_seconds, snap.results.len());
    match selfcheck::check_no_network() {
        (true, d) => println!("network self-test: ISOLATED ({})", d),
        (false, d) => println!("network self-test: OPEN - {}", d),
    }
    println!("scan wall time: {} ms\n", total_ms);

    for r in &snap.results {
        println!("[{}] {} ({} ms{})",
            r.status, r.module_name, r.elapsed_ms,
            if r.requires_admin { ", admin-preferred" } else { "" });
        for f in &r.findings {
            if f.status != Status::Clean {
                println!("    [{}] {} - {}\n      raw: {}", f.status, f.artifact_path, f.human_explanation, f.raw_evidence);
            }
        }
    }

    println!("\nVERDICT: {}   flags={} warnings={} info={} clean={}",
        snap.overall_status(), counts.3, counts.2, counts.1, counts.0);

    if let Some(path) = json_path {
        match serde_json::to_string_pretty(&snap) {
            Ok(json) => match std::fs::write(&path, json) {
                Ok(_) => println!("report written to {}", path),
                Err(e) => eprintln!("failed to write report: {}", e),
            },
            Err(e) => eprintln!("serialization failed: {}", e),
        }
    }
}
