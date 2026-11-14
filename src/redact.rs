








use crate::models::{AuditFinding, ModuleResult, SystemSnapshot};

const USER: &str = "%USER%";
const PROFILE: &str = "%USERPROFILE%";
const SID_TOKEN: &str = "%SID%";

fn replace_ci(haystack: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return haystack.to_string();
    }
    let h_lower = haystack.to_lowercase();
    let n_lower = needle.to_lowercase();
    let mut out = String::with_capacity(haystack.len());
    let mut i = 0;
    while let Some(found) = h_lower[i..].find(&n_lower) {
        let abs = i + found;
        out.push_str(&haystack[i..abs]);
        out.push_str(replacement);
        i = abs + needle.len();
    }
    out.push_str(&haystack[i..]);
    out
}

pub(crate) fn redact_text_with(text: &str, username: &str, userprofile: &str) -> String {
    let mut out = text.to_string();
    if !userprofile.is_empty() {
        out = replace_ci(&out, userprofile, PROFILE);
    }
    if !username.is_empty() {
        out = replace_ci(&out, username, USER);
    }
    let mut lower = out.to_lowercase();
    loop {
        match lower.find("s-1-") {
            Some(start) => {
                let bytes = out.as_bytes();
                let mut end = start + 4;
                while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'-') {
                    end += 1;
                }
                let mut replacement = String::with_capacity(out.len() + SID_TOKEN.len());
                replacement.push_str(&out[..start]);
                replacement.push_str(SID_TOKEN);
                replacement.push_str(&out[end..]);
                out = replacement;
                lower = out.to_lowercase();
            }
            None => break,
        }
    }
    out
}

pub fn redact_text(text: &str) -> String {
    let username = std::env::var("USERNAME").unwrap_or_default();
    let userprofile = std::env::var("USERPROFILE").unwrap_or_default();
    redact_text_with(text, &username, &userprofile)
}

fn redact_finding(f: &AuditFinding) -> AuditFinding {
    AuditFinding {
        module_id: f.module_id.clone(),
        status: f.status,
        timestamp_utc: f.timestamp_utc.clone(),
        artifact_path: redact_text(&f.artifact_path),
        raw_evidence: redact_text(&f.raw_evidence),
        human_explanation: f.human_explanation.clone(),
    }
}

fn redact_module(r: &ModuleResult) -> ModuleResult {
    ModuleResult {
        module_id: r.module_id.clone(),
        module_name: r.module_name.clone(),
        status: r.status,
        findings: r.findings.iter().map(redact_finding).collect(),
        elapsed_ms: r.elapsed_ms,
        requires_admin: r.requires_admin,
        error: r.error.clone(),
    }
}

pub fn redact_snapshot(snap: &SystemSnapshot) -> SystemSnapshot {
    SystemSnapshot {
        captured_utc: snap.captured_utc.clone(),
        hostname: snap.hostname.clone(),
        username: USER.to_string(),
        os_caption: snap.os_caption.clone(),
        boot_uptime_seconds: snap.boot_uptime_seconds,
        elevated: snap.elevated,
        results: snap.results.iter().map(redact_module).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_profile_and_sid() {
        let raw = r"HKLM\...\UserSettings\S-1-5-21-100-200-300-1001\bad.exe launched by PC under C:\Users\PC\AppData\Local\Temp\bad.exe";
        let red = redact_text_with(raw, "PC", r"C:\Users\PC");
        assert!(red.contains("%USERPROFILE%"));
        assert!(red.contains("%SID%"));
        assert!(!red.contains("\\Users\\PC\\"));
        assert!(!red.contains("S-1-5-21"));
    }

    #[test]
    fn leaves_unrelated_text_alone() {
        let s = "nothing to hide here";
        assert_eq!(redact_text_with(s, "PC", r"C:\Users\PC"), s);
    }
}
