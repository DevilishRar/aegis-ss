
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub enum Status {
    Clean,
    Info,
    Warning,
    Flagged,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Clean => "CLEAN",
            Status::Info => "INFO",
            Status::Warning => "WARNING",
            Status::Flagged => "FLAGGED",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AuditFinding {
    pub module_id: String,
    pub status: Status,
    pub timestamp_utc: String,
    pub artifact_path: String,
    pub raw_evidence: String,
    pub human_explanation: String,
}

impl AuditFinding {
    pub fn new(module: &str, status: Status, ts: String, path: String, raw: String, expl: String) -> Self {
        Self {
            module_id: module.to_string(),
            status,
            timestamp_utc: ts,
            artifact_path: path,
            raw_evidence: raw,
            human_explanation: expl,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ModuleResult {
    pub module_id: String,
    pub module_name: String,
    pub status: Status,
    pub findings: Vec<AuditFinding>,
    pub elapsed_ms: u128,
    pub requires_admin: bool,
    pub error: String,
}

impl ModuleResult {
    pub fn new(module_id: &str, module_name: &str, requires_admin: bool) -> Self {
        Self {
            module_id: module_id.to_string(),
            module_name: module_name.to_string(),
            status: Status::Clean,
            findings: Vec::new(),
            elapsed_ms: 0,
            requires_admin,
            error: String::new(),
        }
    }

    pub fn finalize(mut self) -> Self {
        self.status = self
            .findings
            .iter()
            .map(|f| f.status)
            .max()
            .unwrap_or(if self.error.is_empty() { Status::Clean } else { Status::Info });
        self
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SystemSnapshot {
    pub captured_utc: String,
    pub hostname: String,
    pub username: String,
    pub os_caption: String,
    pub boot_uptime_seconds: u64,
    pub elevated: bool,
    pub results: Vec<ModuleResult>,
}

impl SystemSnapshot {
    pub fn overall_status(&self) -> Status {
        self.results.iter().map(|r| r.status).max().unwrap_or(Status::Clean)
    }

    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let mut c = (0, 0, 0, 0);
        for r in &self.results {
            match r.status {
                Status::Clean => c.0 += 1,
                Status::Info => c.1 += 1,
                Status::Warning => c.2 += 1,
                Status::Flagged => c.3 += 1,
            }
        }
        c
    }
}
