

use std::time::Instant;

use crate::ffi;
use crate::models::{AuditFinding, ModuleResult, Status};
use crate::scan::deep_enabled;
use crate::util::{now_iso, path_risk_reason};

const MODULE_ID: &str = "process";
const MODULE_NAME: &str = "Active Processes, Overlays and Signatures";
const MAX_SIG_CHECKS: usize = 40;

struct ProcInfo {
    pid: u32,
    name: String,
    exe: Option<String>,
}

fn enumerate_processes() -> Vec<ProcInfo> {
    let mut out = Vec::new();
    let snap = unsafe { ffi::CreateToolhelp32Snapshot(ffi::TH32CS_SNAPPROCESS, 0) };
    if snap == ffi::INVALID_HANDLE_VALUE || snap == 0 {
        return out;
    }
    let mut entry = ffi::PROCESSENTRY32W {
        dwSize: std::mem::size_of::<ffi::PROCESSENTRY32W>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; 260],
    };
    let mut ok = unsafe { ffi::Process32FirstW(snap, &mut entry) };
    while ok != ffi::FALSE {
        let name = ffi::utf16_buf_to_string(&entry.szExeFile);
        let pid = entry.th32ProcessID;
        let exe = query_exe_path(pid);
        out.push(ProcInfo { pid, name, exe });
        entry.dwSize = std::mem::size_of::<ffi::PROCESSENTRY32W>() as u32;
        ok = unsafe { ffi::Process32NextW(snap, &mut entry) };
    }
    unsafe { ffi::CloseHandle(snap) };
    out
}

fn query_exe_path(pid: u32) -> Option<String> {
    unsafe {
        let h = ffi::OpenProcess(ffi::PROCESS_QUERY_LIMITED_INFORMATION, ffi::FALSE, pid);
        if h == 0 || h == ffi::INVALID_HANDLE_VALUE {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = ffi::QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
        ffi::CloseHandle(h);
        if ok == ffi::FALSE {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..size as usize]))
    }
}

struct OverlayWindow {
    hwnd: isize,
    title: String,
    class: String,
    exstyle: i32,
}

unsafe extern "system" fn enum_proc(hwnd: ffi::HWND, lparam: isize) -> ffi::BOOL {
    let overlays = &mut *(lparam as *mut Vec<OverlayWindow>);
    if ffi::IsWindowVisible(hwnd) == ffi::FALSE {
        return ffi::TRUE;
    }
    let ex = ffi::GetWindowLongW(hwnd, ffi::GWL_EXSTYLE);
    if (ex & ffi::WS_EX_TOPMOST) != 0 && (ex & ffi::WS_EX_LAYERED) != 0 && (ex & ffi::WS_EX_TRANSPARENT) != 0 {
        let mut tbuf = [0u16; 256];
        let mut cbuf = [0u16; 256];
        let tlen = ffi::GetWindowTextW(hwnd, tbuf.as_mut_ptr(), 256);
        let clen = ffi::GetClassNameW(hwnd, cbuf.as_mut_ptr(), 256);
        overlays.push(OverlayWindow {
            hwnd,
            title: String::from_utf16_lossy(&tbuf[..tlen.max(0) as usize]),
            class: String::from_utf16_lossy(&cbuf[..clen.max(0) as usize]),
            exstyle: ex,
        });
    }
    ffi::TRUE
}

fn enum_overlays() -> Vec<OverlayWindow> {
    let mut overlays = Vec::new();
    unsafe {
        ffi::EnumWindows(Some(enum_proc), &mut overlays as *mut Vec<OverlayWindow> as isize);
    }
    overlays
}


fn authenticode_batch(paths: &[String]) -> Vec<(String, String)> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    if paths.is_empty() {
        return Vec::new();
    }
    let quoted: Vec<String> = paths.iter().map(|p| format!("'{}'", p.replace('\'', "''"))).collect();
    let script = format!(
        "foreach ($p in @({})) {{ try {{ $s = (Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop).Status }} catch {{ $s = 'Unreadable' }}; Write-Output ('AEGIS|' + $p + '|' + $s) }}",
        quoted.join(",")
    );
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let mut map = Vec::new();
    if let Ok(o) = out {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            if let Some(rest) = line.strip_prefix("AEGIS|") {
                if let Some((p, s)) = rest.rsplit_once('|') {
                    map.push((p.to_string(), s.trim().to_string()));
                }
            }
        }
    }
    map
}

pub fn scan(_window_hours: f64) -> ModuleResult {
    let t0 = Instant::now();
    let mut res = ModuleResult::new(MODULE_ID, MODULE_NAME, false);

    let processes = enumerate_processes();
    let mut suspicious: Vec<(u32, String, String, String)> = Vec::new();
    for p in &processes {
        if let Some(exe) = &p.exe {
            if let Some(reason) = path_risk_reason(exe) {
                suspicious.push((p.pid, p.name.clone(), exe.clone(), reason));
            }
        }
    }
    for (pid, name, exe, reason) in &suspicious {
        res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Warning, now_iso(), exe.clone(),
            format!("pid={} name={} reason={}", pid, name, reason),
            format!("Process runs from a risky location ({}). Verify its signer in deep scan mode.", reason),
        ));
    }

    if deep_enabled() {
        let paths: Vec<String> = suspicious.iter().take(MAX_SIG_CHECKS).map(|s| s.2.clone()).collect();
        for (path, status) in authenticode_batch(&paths) {
            if status != "Valid" {
                res.findings.push(AuditFinding::new(
                    MODULE_ID, Status::Flagged, now_iso(), path,
                    format!("authenticode_status={}", status),
                    "Unsigned or invalidly signed executable running right now. High interest for staff.".into(),
                ));
            }
        }
    } else if !suspicious.is_empty() {
        res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Info, now_iso(), "Authenticode".into(),
            "skipped (fast mode)".into(),
            "Signature verification of the flagged subset runs in Deep scan mode (batched PowerShell).".into(),
        ));
    }

    for o in enum_overlays() {
        res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Warning, now_iso(), format!("hwnd:0x{:x}", o.hwnd),
            format!("title='{}' class='{}' exstyle=0x{:x}", o.title, o.class, o.exstyle),
            "Click-through transparent topmost layered window (ESP-overlay pattern). Discord and FPS counters can match; verify visually on the call.".into(),
        ));
    }

    if res.findings.is_empty() {
        res.findings.push(AuditFinding::new(
            MODULE_ID, Status::Clean, now_iso(), "processes+windows".into(),
            "0 suspicious processes, 0 overlay candidates".into(),
            "No risky-location processes and no click-through overlay windows detected.".into(),
        ));
    }
    res.elapsed_ms = t0.elapsed().as_millis();
    res.finalize()
}
