


#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::mpsc::{Receiver, TryIter};
use std::time::Duration;

use eframe::egui;
use aegis_ss_core::models::{AuditFinding, ModuleResult, Status, SystemSnapshot};
use aegis_ss_core::redact;
use aegis_ss_core::scan::{start_scan, ScanEvent, MODULE_COUNT};
use aegis_ss_core::selfcheck;

const BG: egui::Color32 = egui::Color32::from_rgb(20, 19, 17);
const PANEL: egui::Color32 = egui::Color32::from_rgb(27, 26, 23);
const PANEL_ALT: egui::Color32 = egui::Color32::from_rgb(34, 33, 29);
const TEXT: egui::Color32 = egui::Color32::from_rgb(231, 228, 220);
const MUTED: egui::Color32 = egui::Color32::from_rgb(160, 156, 144);
const HAIRLINE: egui::Color32 = egui::Color32::from_rgb(42, 41, 37);
const PRIMARY: egui::Color32 = egui::Color32::from_rgb(63, 94, 117);
const EMERALD: egui::Color32 = egui::Color32::from_rgb(63, 169, 123);
const INFO: egui::Color32 = egui::Color32::from_rgb(78, 143, 168);
const AMBER: egui::Color32 = egui::Color32::from_rgb(201, 146, 46);
const CRIMSON: egui::Color32 = egui::Color32::from_rgb(184, 74, 63);
const ON_ACCENT: egui::Color32 = egui::Color32::from_rgb(12, 10, 9);

fn status_color(s: Status) -> egui::Color32 {
    match s {
        Status::Clean => EMERALD,
        Status::Info => INFO,
        Status::Warning => AMBER,
        Status::Flagged => CRIMSON,
    }
}

fn status_word(s: Status) -> &'static str {
    match s {
        Status::Clean => "CLEAN",
        Status::Info => "INFO",
        Status::Warning => "WARNING",
        Status::Flagged => "FLAGGED",
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Page {
    Overview,
    Execution,
    Deletion,
    Processes,
    DefenderRoblox,
    Audit,
}

fn page_from_str(s: &str) -> Option<Page> {
    match s.to_ascii_lowercase().as_str() {
        "overview" => Some(Page::Overview),
        "execution" | "bam" | "pca" => Some(Page::Execution),
        "deletion" | "usn" | "prefetch" => Some(Page::Deletion),
        "processes" | "overlays" => Some(Page::Processes),
        "defender" | "roblox" | "defender-roblox" => Some(Page::DefenderRoblox),
        "audit" | "trust" => Some(Page::Audit),
        _ => None,
    }
}

const PAGES: &[(Page, &str, &[&str])] = &[
    (Page::Overview, "Overview", &["bam", "pca", "usn", "prefetch", "tamper", "process", "defender", "roblox"]),
    (Page::Execution, "Execution history", &["bam", "pca"]),
    (Page::Deletion, "Deletions and tampering", &["usn", "prefetch", "tamper"]),
    (Page::Processes, "Processes and overlays", &["process"]),
    (Page::DefenderRoblox, "Defender and Roblox", &["defender", "roblox"]),
];

struct AegisApp {
    page: Page,
    snapshot: Option<SystemSnapshot>,
    partial: Vec<ModuleResult>,
    scanning: bool,
    deep: bool,
    redact_export: bool,
    rx: Option<Receiver<ScanEvent>>,
    done: usize,
    filter: String,
    selected: Option<AuditFinding>,
    selected_row: Option<usize>,
    status_line: String,
    net_isolated: bool,
    net_detail: String,
    self_sha256: String,
    elevated: bool,
    show_net_popup: bool,
    scan_elapsed_ms: Option<u128>,
    scan_started: Option<std::time::Instant>,
}

impl Default for AegisApp {
    fn default() -> Self {
        let audit = selfcheck::audit();
        Self {
            page: Page::Overview,
            snapshot: None,
            partial: Vec::new(),
            scanning: false,
            deep: false,
            redact_export: true,
            rx: None,
            done: 0,
            filter: String::new(),
            selected: None,
            selected_row: None,
            status_line: "Idle. Press Run full audit.".into(),
            net_isolated: audit.network_isolated,
            net_detail: audit.network_detail,
            self_sha256: audit.self_sha256,
            elevated: audit.elevated,
            show_net_popup: false,
            scan_elapsed_ms: None,
            scan_started: None,
        }
    }
}

fn load_findings(snapshot: &SystemSnapshot, modules: &[&str]) -> Vec<AuditFinding> {
    snapshot
        .results
        .iter()
        .filter(|r| modules.contains(&r.module_id.as_str()))
        .flat_map(|r| r.findings.clone())
        .collect()
}

fn page_severity(snapshot: Option<&SystemSnapshot>, modules: &[&str]) -> Status {
    snapshot
        .map(|s| {
            s.results
                .iter()
                .filter(|r| modules.contains(&r.module_id.as_str()))
                .map(|r| r.status)
                .max()
                .unwrap_or(Status::Clean)
        })
        .unwrap_or(Status::Info)
}

fn reveal_in_explorer(path: &str) {
    if path.is_empty()
        || path.starts_with("hwnd:")
        || path.starts_with("service:")
        || path.starts_with("pid:")
    {
        return;
    }
    let target = if std::path::Path::new(path).exists() {
        path.to_string()
    } else {
        std::path::Path::new(path)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    let _ = std::process::Command::new("explorer.exe")
        .arg(format!("/select,{}", target))
        .spawn();
}

impl eframe::App for AegisApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BG;
        visuals.window_fill = PANEL;
        visuals.extreme_bg_color = BG;
        visuals.faint_bg_color = PANEL_ALT;
        visuals.widgets.noninteractive.bg_fill = PANEL;
        visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, HAIRLINE);
        visuals.widgets.inactive.bg_fill = PANEL_ALT;
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, HAIRLINE);
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(43, 42, 38);
        visuals.widgets.active.bg_fill = PRIMARY;
        visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0_f32, HAIRLINE);
        visuals.selection.bg_fill = egui::Color32::from_rgb(46, 67, 84);
        ctx.set_visuals(visuals);

        if let Some(rx) = self.rx.take() {
            let mut finished: Option<SystemSnapshot> = None;
            {
                let events: TryIter<'_, ScanEvent> = rx.try_iter();
                for ev in events {
                    match ev {
                        ScanEvent::ModuleDone(r) => {
                            self.done += 1;
                            self.partial.push(r);
                        }
                        ScanEvent::Finished(s) => finished = Some(s),
                    }
                }
            }
            if let Some(s) = finished {
                self.snapshot = Some(s);
                self.partial.clear();
                self.scanning = false;
                self.scan_elapsed_ms = self.scan_started.map(|t| t.elapsed().as_millis());
                self.status_line = format!("Audit complete in {} ms.", self.scan_elapsed_ms.unwrap_or(0));
            } else {
                self.rx = Some(rx);
            }
        }

        if self.scanning {
            if let Some(started) = self.scan_started {
                if started.elapsed() > Duration::from_secs(30) {
                    self.scanning = false;
                    self.rx = None;
                    self.status_line = "Scan watchdog fired after 30s. Relaunch or file an issue; no results kept.".into();
                }
            }
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("AEGIS-SS").size(18.0).strong().color(TEXT));
                        ui.label(egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).small().color(MUTED));
                    });
                    ui.label(egui::RichText::new("Screenshare integrity audit").small().color(MUTED));
                });
                ui.add_space(24.0);
                ui.vertical(|ui| {
                    let utc = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
                    let local = chrono::Local::now().format("%H:%M:%S local");
                    ui.label(egui::RichText::new(utc.to_string()).monospace().color(TEXT));
                    ui.label(egui::RichText::new(local.to_string()).monospace().color(MUTED));
                });
                ui.add_space(16.0);
                let up = selfcheck::uptime_seconds();
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new(format!("{:02}:{:02}:{:02}", up / 3600, (up % 3600) / 60, up % 60)).monospace().size(18.0).color(TEXT));
                    ui.label(egui::RichText::new("uptime since boot").small().color(MUTED));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new("Live clock. Recordings cannot forge this.").small().color(MUTED));
                });
            });
            ui.add_space(8.0);
            ui.separator();
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let run_label = if self.scanning { "Scanning" } else { "Run full audit" };
                if ui.add_enabled(!self.scanning, egui::Button::new(egui::RichText::new(run_label).strong().color(TEXT)).fill(PRIMARY).min_size(egui::Vec2::new(150.0, 30.0))).clicked() {
                    self.start_scan();
                }
                ui.checkbox(&mut self.deep, "Deep scan").on_hover_text("Adds wevtutil event history and batched Authenticode verification. About 100 ms extra.");
                ui.checkbox(&mut self.redact_export, "Redact export").on_hover_text("Masks %USERPROFILE%, username and SIDs in the exported report.");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(self.snapshot.is_some(), egui::Button::new("Export local report")).clicked() {
                        self.export_report();
                    }
                    if ui.button("NET").clicked() {
                        self.show_net_popup = !self.show_net_popup;
                    }
                    ui.label(egui::RichText::new(if self.net_isolated { "0 sockets" } else { "sockets open" }).monospace().color(if self.net_isolated { EMERALD } else { CRIMSON }));
                    ui.separator();
                    ui.label(egui::RichText::new(if self.elevated { "Administrator" } else { "Standard user" }).monospace().color(MUTED));
                    if !self.elevated && ui.button("Elevate").on_hover_text("Relaunch as Administrator via UAC for USN, Prefetch and Security log access").clicked() {
                        relaunch_elevated();
                    }
                });
            });
            ui.add_space(6.0);
            if let Some(snap) = &self.snapshot {
                let counts = snap.counts();
                let overall = snap.overall_status();
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("VERDICT").small().color(MUTED));
                    ui.label(egui::RichText::new(status_word(overall)).size(20.0).strong().color(status_color(overall)));
                    ui.separator();
                    ui.label(chip(&format!("{} FLAGGED", counts.3), status_color(Status::Flagged)));
                    ui.label(chip(&format!("{} WARNINGS", counts.2), status_color(Status::Warning)));
                    ui.label(chip(&format!("{} INFO", counts.1), status_color(Status::Info)));
                    ui.label(chip(&format!("{} CLEAN", counts.0), status_color(Status::Clean)));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(format!("{} ms  {}", self.scan_elapsed_ms.unwrap_or(0), snap.captured_utc)).monospace().small().color(MUTED));
                    });
                });
            } else if self.scanning {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("SCANNING").strong().color(TEXT));
                    ui.add(egui::ProgressBar::new(self.done as f32 / MODULE_COUNT as f32).desired_width(260.0));
                    let elapsed = self.scan_started.map(|t| t.elapsed().as_secs_f32()).unwrap_or(0.0);
                    ui.label(egui::RichText::new(format!("{}/{} modules  {:.1}s", self.done, MODULE_COUNT, elapsed)).monospace().color(MUTED));
                });
            } else {
                ui.label(egui::RichText::new("No data yet. Press Run full audit.").color(MUTED));
            }
            ui.add_space(8.0);
        });

        egui::SidePanel::left("side").resizable(false).default_width(232.0).show(ctx, |ui| {
            ui.add_space(12.0);
            ui.label(egui::RichText::new("PAGES").small().color(MUTED).strong());
            ui.add_space(2.0);
            for (page, label, modules) in PAGES {
                let severity = page_severity(self.snapshot.as_ref(), modules);
                let count = self.snapshot.as_ref().map(|s| load_findings(s, modules).len());
                let selected = self.page == *page;
                ui.horizontal(|ui| {
                    if ui.selectable_label(selected, egui::RichText::new(format!("   {}", label)).color(if selected { TEXT } else { MUTED })).clicked() {
                        self.page = *page;
                        self.selected_row = None;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(c) = count {
                            ui.label(egui::RichText::new(c.to_string()).monospace().small().color(MUTED));
                        }
                        ui.label(egui::RichText::new("o").color(status_color(severity)));
                    });
                });
            }
            ui.add_space(4.0);
            if ui.selectable_label(self.page == Page::Audit, egui::RichText::new("   Trust audit").color(if self.page == Page::Audit { TEXT } else { MUTED })).clicked() {
                self.page = Page::Audit;
            }
            ui.separator();
            ui.label(egui::RichText::new("Read-only. Zero network.\nReports are signals, not verdicts.").small().color(MUTED));
            ui.separator();
            ui.label(egui::RichText::new(&self.status_line).small().color(MUTED));
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.page {
            Page::Overview => self.overview_page(ui),
            Page::Execution => self.table_page(ui, &["bam", "pca"], "Execution history. Sources: BAM/DAM registry hives and PCA/MuiCache residual records."),
            Page::Deletion => self.table_page(ui, &["usn", "prefetch", "tamper"], "Deletions and tampering. Sources: USN journal (FSCTL), Prefetch metadata, Event Log and service state."),
            Page::Processes => self.table_page(ui, &["process"], "Active processes from non-standard paths, unsigned binaries (deep scan) and click-through overlay windows."),
            Page::DefenderRoblox => self.table_page(ui, &["defender", "roblox"], "Defender path/process exclusions and threat events, plus the Roblox client directory and session logs."),
            Page::Audit => self.audit_page(ui),
        });

        if self.show_net_popup {
            egui::Window::new("Network self-check").collapsible(false).show(ctx, |ui| {
                ui.label(&self.net_detail);
                ui.separator();
                ui.label(egui::RichText::new(format!("SHA-256 of this executable\n{}", self.self_sha256)).monospace().small());
                if ui.button("Close").clicked() {
                    self.show_net_popup = false;
                }
            });
        }

        ctx.request_repaint_after(Duration::from_millis(if self.scanning { 50 } else { 1000 }));
    }
}

fn chip(label: &str, color: egui::Color32) -> egui::RichText {
    egui::RichText::new(format!(" {} ", label)).monospace().size(11.0).strong().background_color(color).color(ON_ACCENT)
}

impl AegisApp {
    fn start_scan(&mut self) {
        self.scanning = true;
        self.done = 0;
        self.snapshot = None;
        self.partial.clear();
        self.selected = None;
        self.selected_row = None;
        self.scan_started = Some(std::time::Instant::now());
        self.status_line = "Scanning.".into();
        self.rx = Some(start_scan(2.0, self.deep));
    }

    fn export_report(&mut self) {
        let Some(snap) = &self.snapshot else { return };
        let export = if self.redact_export { redact::redact_snapshot(snap) } else { snap.clone() };
        let desktop = std::env::var("USERPROFILE").map(|p| format!("{}\\Desktop", p)).unwrap_or_else(|_| ".".into());
        let path = format!("{}\\aegis_ss_report.json", desktop);
        match serde_json::to_string_pretty(&export).map(|j| std::fs::write(&path, j)) {
            Ok(Ok(_)) => self.status_line = format!("Report written to {} ({})", path, if self.redact_export { "redacted" } else { "full detail" }),
            Ok(Err(e)) => self.status_line = format!("Export failed: {}", e),
            Err(e) => self.status_line = format!("Serialization failed: {}", e),
        }
    }

    fn overview_page(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Overview").size(17.0).strong());
        ui.label(egui::RichText::new("Artifacts across every module, in time order. Red rows deserve verbal explanation on the call.").small().color(MUTED));
        ui.add_space(8.0);
        let Some(snap) = &self.snapshot else {
            ui.label(egui::RichText::new("No data yet. Press Run full audit; results appear here within seconds.").color(MUTED));
            return;
        };
        let findings: Vec<AuditFinding> = snap.results.iter().flat_map(|r| r.findings.clone()).collect();
        let flagged = findings.iter().filter(|f| f.status == Status::Flagged).count();
        let warnings = findings.iter().filter(|f| f.status == Status::Warning).count();
        let clean_modules = snap.results.iter().filter(|r| r.status == Status::Clean).count();

        ui.horizontal(|ui| {
            stat_block(ui, flagged.to_string(), "FLAGGED ARTIFACTS", status_color(Status::Flagged));
            ui.separator();
            stat_block(ui, warnings.to_string(), "WARNINGS", status_color(Status::Warning));
            ui.separator();
            stat_block(ui, clean_modules.to_string(), "CLEAN MODULES", status_color(Status::Clean));
            ui.separator();
            stat_block(ui, findings.len().to_string(), "ARTIFACTS AUDITED", TEXT);
        });
        ui.add_space(8.0);
        ui.separator();

        let mut timed: Vec<AuditFinding> = findings;
        timed.retain(|f| f.timestamp_utc != "n/a" && !f.timestamp_utc.is_empty());
        timed.sort_by(|a, b| a.timestamp_utc.cmp(&b.timestamp_utc));

        ui.label(egui::RichText::new(format!("Timeline  ({} timestamped artifacts)", timed.len())).strong());
        ui.add_space(2.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("timeline_grid").num_columns(4).striped(true).spacing([16.0, 4.0]).show(ui, |ui| {
                for f in &timed {
                    ui.label(egui::RichText::new(&f.timestamp_utc).monospace().size(12.0).color(MUTED));
                    ui.label(egui::RichText::new(format!("[{}]", f.module_id.to_uppercase())).monospace().size(12.0).color(status_color(f.status)));
                    ui.label(egui::RichText::new(status_word(f.status)).monospace().size(12.0).strong().color(status_color(f.status)));
                    if ui.selectable_label(self.selected.as_ref().map(|s| s.artifact_path == f.artifact_path).unwrap_or(false), egui::RichText::new(clip(&f.artifact_path, 96)).monospace().size(12.0).color(TEXT)).clicked() {
                        self.selected = Some(f.clone());
                    }
                    ui.end_row();
                }
            });
        });
        self.detail_pane(ui);
    }

    fn table_page(&mut self, ui: &mut egui::Ui, modules: &[&str], subtitle: &str) {
        ui.label(egui::RichText::new(subtitle).small().color(MUTED));
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Filter:").small().color(MUTED));
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("path, process, evidence").desired_width(380.0));
            if ui.button("Open folder location").clicked() {
                if let Some(f) = &self.selected {
                    reveal_in_explorer(&f.artifact_path);
                }
            }
        });
        ui.add_space(2.0);

        let Some(snap) = &self.snapshot else {
            ui.label(egui::RichText::new("No data yet. Press Run full audit to fill this page.").color(MUTED));
            return;
        };
        let findings = load_findings(snap, modules);
        let needle = self.filter.to_lowercase();
        let shown = findings.iter().filter(|f| {
            needle.is_empty() || format!("{} {} {} {}", f.timestamp_utc, f.artifact_path, f.raw_evidence, f.human_explanation).to_lowercase().contains(&needle)
        }).count();
        ui.label(egui::RichText::new(format!("{} of {} rows", shown, findings.len())).small().color(MUTED));
        ui.separator();

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("STATUS").small().strong().color(MUTED));
            ui.add_space(2.0);
            ui.label(egui::RichText::new("MODULE").small().strong().color(MUTED));
            ui.add_space(52.0);
            ui.label(egui::RichText::new("ARTIFACT / EVIDENCE").small().strong().color(MUTED));
        });
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new(format!("rows_{}", modules.join("_"))).num_columns(3).striped(true).spacing([12.0, 5.0]).show(ui, |ui| {
                for (i, f) in findings.iter().enumerate() {
                    if !needle.is_empty() {
                        let hay = format!("{} {} {} {}", f.timestamp_utc, f.artifact_path, f.raw_evidence, f.human_explanation).to_lowercase();
                        if !hay.contains(&needle) {
                            continue;
                        }
                    }
                    let selected = self.selected_row == Some(i);
                    if ui.selectable_label(selected, egui::RichText::new(status_word(f.status)).monospace().size(12.0).strong().color(status_color(f.status))).clicked() {
                        self.selected_row = Some(i);
                        self.selected = Some(f.clone());
                    }
                    ui.label(egui::RichText::new(f.module_id.to_uppercase()).monospace().size(12.0).color(MUTED));
                    ui.label(egui::RichText::new(format!("{}  {}", f.timestamp_utc, clip(&f.artifact_path, 88))).monospace().size(12.0).color(TEXT));
                    ui.end_row();
                }
            });
        });
        self.detail_pane(ui);
    }

    fn detail_pane(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.separator();
        ui.label(egui::RichText::new("INSPECTOR").small().strong().color(MUTED));
        match &self.selected {
            Some(f) => {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(status_word(f.status)).strong().color(status_color(f.status)));
                    ui.label(egui::RichText::new(&f.timestamp_utc).monospace().color(MUTED));
                });
                ui.label(egui::RichText::new(&f.artifact_path).monospace().color(TEXT));
                ui.label(egui::RichText::new("Evidence").small().color(MUTED));
                ui.label(egui::RichText::new(&f.raw_evidence).monospace().size(11.0).color(MUTED));
                ui.label(egui::RichText::new("Why it matters").small().color(MUTED));
                ui.label(&f.human_explanation);
            }
            None => {
                ui.label(egui::RichText::new("Select a row to inspect it.").color(MUTED));
            }
        }
    }

    fn audit_page(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Trust audit. Runtime facts about this process, not promises.").color(MUTED));
        ui.add_space(8.0);
        ui.columns(2, |cols| {
            cols[0].label(egui::RichText::new("WHAT IT DOES").strong().color(EMERALD));
            for line in [
                "Reads registry keys below HKLM\\Services\\bam, dam, Defender exclusions, MuiCache and AppCompatFlags.",
                "Lists Prefetch metadata under C:\\Windows\\Prefetch.",
                "Reads the USN journal over FSCTL_READ_USN_JOURNAL.",
                "Enumerates processes with Toolhelp32.",
                "Detects click-through layered topmost windows with EnumWindows.",
                "Checks service state with the Service Control Manager.",
                "Deep scan: wevtutil queries and one batched Get-AuthenticodeSignature call.",
            ] {
                cols[0].label(egui::RichText::new(format!("  {}", line)).small());
                cols[0].add_space(2.0);
            }
            cols[1].label(egui::RichText::new("WHAT IT NEVER DOES").strong().color(CRIMSON));
            for line in [
                "Opens any network connection or DNS lookup.",
                "Writes to the registry.",
                "Modifies, quarantines or deletes files.",
                "Injects into other processes or hooks APIs.",
                "Sends telemetry, crash reports or update checks.",
                "Starts, stops or reconfigures services.",
                "Writes anything except an explicit report export.",
            ] {
                cols[1].label(egui::RichText::new(format!("  {}", line)).small());
                cols[1].add_space(2.0);
            }
        });
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);
        ui.label(egui::RichText::new(format!("PID {}  |  network isolated: {}  |  elevation: {}", std::process::id(), if self.net_isolated { "yes" } else { "no" }, if self.elevated { "administrator" } else { "standard user" })).monospace().small().color(MUTED));
        ui.label(egui::RichText::new(format!("SHA-256  {}", self.self_sha256)).monospace().small());
        ui.add_space(4.0);
        ui.label(egui::RichText::new("Queries per module are documented in TRUST.md. Every finding carries its raw evidence.").small().color(MUTED));
    }
}

fn stat_block(ui: &mut egui::Ui, value: String, label: &str, color: egui::Color32) {
    ui.vertical(|ui| {
        ui.label(egui::RichText::new(value).monospace().size(26.0).strong().color(color));
        ui.label(egui::RichText::new(label).size(9.0).color(MUTED));
    });
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let tail: String = s.chars().skip(s.chars().count().saturating_sub(max - 3)).collect();
        format!("...{}", tail)
    }
}

#[link(name = "shell32")]
extern "system" {
    #[link_name = "ShellExecuteW"]
    fn shell_execute_w(hwnd: isize, lpOperation: *const u16, lpFile: *const u16,
                       lpParameters: *const u16, lpDirectory: *const u16, nShowCmd: i32) -> isize;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn relaunch_elevated() {
    let exe = wide(&std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "aegis-ss.exe".into()));
    let verb = wide("runas");
    let params: Vec<u16> = std::iter::once(0).collect();
    unsafe {
        let rc = shell_execute_w(0, verb.as_ptr(), exe.as_ptr(), params.as_ptr(), std::ptr::null(), 1);
        if rc > 32 {
            std::process::exit(0);
        }
    }
}

fn main() -> eframe::Result<()> {
    let mut scan_on_start = false;
    let mut start_page = Page::Overview;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--scan-on-start" => scan_on_start = true,
            "--start-page" => {
                if let Some(v) = args.next() {
                    start_page = page_from_str(&v).unwrap_or(Page::Overview);
                }
            }
            _ => {}
        }
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1360.0, 860.0])
            .with_min_inner_size([1024.0, 640.0])
            .with_title("Aegis-SS"),
        ..Default::default()
    };
    let mut app = AegisApp::default();
    app.page = start_page;
    if scan_on_start {
        app.start_scan();
    }
    eframe::run_native(
        "Aegis-SS",
        options,
        Box::new(|_cc| Ok(Box::new(app))),
    )
}
