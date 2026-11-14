




use std::ffi::c_void;
use std::time::Instant;

use crate::ffi;
use crate::models::{AuditFinding, ModuleResult, Status};
use crate::util::{filetime_to_iso, filetime_to_unix, now_iso};

const MODULE_ID: &str = "usn";
const MODULE_NAME: &str = "USN Journal Deletion / Rename Tail";
const VOLUME: &str = r"\\.\C:";
const WATCH_EXT: &[&str] = &[".exe", ".dll", ".sys", ".lua", ".luau", ".asi", ".zip"];
const REASON_MASK: u32 = ffi::USN_REASON_FILE_DELETE | ffi::USN_REASON_RENAME_OLD_NAME | ffi::USN_REASON_RENAME_NEW_NAME;
const MAX_RECORDS_SCANNED: usize = 100_000;
const MAX_CHUNKS: usize = 512;
const MAX_FINDINGS: usize = 250;
const RECENT_SECS: f64 = 3600.0;

#[derive(Clone)]
struct UsnHit {
    reason: u32,
    usn: i64,
    filetime: u64,
    filename: String,
}

fn reason_label(r: u32) -> &'static str {
    if r & ffi::USN_REASON_FILE_DELETE != 0 {
        "FILE_DELETE"
    } else if r & ffi::USN_REASON_RENAME_OLD_NAME != 0 {
        "RENAME_OLD_NAME"
    } else {
        "RENAME_NEW_NAME"
    }
}

fn scan_journal_chunked(cutoff_unix: f64) -> Result<(Vec<UsnHit>, usize), String> {
    let volume = ffi::wide(VOLUME);
    let handle = unsafe {
        ffi::CreateFileW(volume.as_ptr(), ffi::GENERIC_READ, ffi::FILE_SHARE_ALL,
                         std::ptr::null_mut(), ffi::OPEN_EXISTING, 0, 0)
    };
    if handle == ffi::INVALID_HANDLE_VALUE {
        return Err("CreateFileW on \\\\.\\C: failed (needs elevation)".to_string());
    }

    let mut journal = ffi::USN_JOURNAL_DATA_V0::default();
    let mut br: u32 = 0;
    let ok = unsafe {
        ffi::DeviceIoControl(handle, ffi::FSCTL_QUERY_USN_JOURNAL, std::ptr::null_mut(), 0,
                             &mut journal as *mut ffi::USN_JOURNAL_DATA_V0 as *mut c_void,
                             std::mem::size_of::<ffi::USN_JOURNAL_DATA_V0>() as u32,
                             &mut br, std::ptr::null_mut())
    };
    if ok == ffi::FALSE {
        unsafe { ffi::CloseHandle(handle) };
        return Err("FSCTL_QUERY_USN_JOURNAL failed (needs elevation)".to_string());
    }

    let mut hits = Vec::new();
    let mut scanned = 0usize;
    let mut start_usn = journal.FirstUsn;
    let mut chunks = 0usize;
    let mut chunk = vec![0u8; 64 * 1024];

    loop {
        if scanned >= MAX_RECORDS_SCANNED || chunks >= MAX_CHUNKS || start_usn >= journal.NextUsn {
            break;
        }
        chunks += 1;
        let prev_usn = start_usn;
        let req = ffi::READ_USN_JOURNAL_DATA_V0 {
            StartUsn: start_usn,
            ReasonMask: REASON_MASK,
            ReturnOnlyOnClose: 0,
            Timeout: 0,
            BytesToWaitFor: 0,
            UsnJournalID: journal.UsnJournalID,
        };
        let ok = unsafe {
            ffi::DeviceIoControl(handle, ffi::FSCTL_READ_USN_JOURNAL,
                                 &req as *const ffi::READ_USN_JOURNAL_DATA_V0 as *mut c_void,
                                 std::mem::size_of::<ffi::READ_USN_JOURNAL_DATA_V0>() as u32,
                                 chunk.as_mut_ptr() as *mut c_void,
                                 chunk.len() as u32,
                                 &mut br, std::ptr::null_mut())
        };
        if ok == ffi::FALSE || br < 8 {
            break;
        }
        start_usn = i64::from_le_bytes(chunk[..8].try_into().unwrap());
        if start_usn == prev_usn {
            break;
        }

        let mut offset = 8usize;
        while offset + 60 <= br as usize {
            let rec_len = u32::from_le_bytes(chunk[offset..offset + 4].try_into().unwrap()) as usize;
            if rec_len < 60 || offset + rec_len > br as usize {
                break;
            }
            let major = u16::from_le_bytes(chunk[offset + 4..offset + 6].try_into().unwrap());
            let rec = &chunk[offset..offset + rec_len];
            if major == 2 {
                scanned += 1;
                let usn = i64::from_le_bytes(rec[24..32].try_into().unwrap());
                let filetime = u64::from_le_bytes(rec[32..40].try_into().unwrap());
                let reason = u32::from_le_bytes(rec[40..44].try_into().unwrap());
                let name_len = u16::from_le_bytes(rec[56..58].try_into().unwrap()) as usize;
                let name_off = u16::from_le_bytes(rec[58..60].try_into().unwrap()) as usize;
                if name_off + name_len <= rec.len() {
                    let units: Vec<u16> = rec[name_off..name_off + name_len].chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    let filename = String::from_utf16_lossy(&units);
                    let ext_ok = filename
                        .rfind('.')
                        .map(|i| WATCH_EXT.iter().any(|e| filename[i..].eq_ignore_ascii_case(e)))
                        .unwrap_or(false);
                    let ts_unix = filetime_to_unix(filetime);
                    if ext_ok && ts_unix >= cutoff_unix {
                        hits.push(UsnHit { reason, usn, filetime, filename });
                        if hits.len() > MAX_FINDINGS * 4 {
                            break;
                        }
                    }
                }
            }
            offset += rec_len;
        }
        if start_usn == 0 {
            break;
        }
    }

    unsafe { ffi::CloseHandle(handle) };
    Ok((hits, scanned))
}

pub fn scan(_window_hours: f64) -> ModuleResult {
    let t0 = Instant::now();
    let mut res = ModuleResult::new(MODULE_ID, MODULE_NAME, true);
    let cutoff = chrono::Utc::now().timestamp() as f64 - RECENT_SECS;

    match scan_journal_chunked(cutoff) {
        Ok((hits, scanned)) => {
            for hit in hits.into_iter().take(MAX_FINDINGS) {
                res.findings.push(AuditFinding::new(
                    MODULE_ID,
                    Status::Warning,
                    filetime_to_iso(hit.filetime),
                    hit.filename.clone(),
                    format!("usn={} reason={}", hit.usn, reason_label(hit.reason)),
                    format!("USN journal records {} for a watched extension. Recent binary deletions or renames right before a screenshare deserve explanation.", reason_label(hit.reason)),
                ));
            }
            if res.findings.is_empty() {
                res.findings.push(AuditFinding::new(
                    MODULE_ID,
                    Status::Clean,
                    now_iso(),
                    "C: usn tail".into(),
                    format!("scanned_records={} hits={}", scanned, 0),
                    "No recent deletes or renames of watched extensions in the USN tail.".into(),
                ));
            }
        }
        Err(e) => {
            res.findings.push(AuditFinding::new(
                MODULE_ID,
                Status::Info,
                now_iso(),
                "C:".into(),
                e,
                "USN journal read needs elevation. Elevate and rescan for the deep view.".into(),
            ));
        }
    }
    res.elapsed_ms = t0.elapsed().as_millis();
    res.finalize()
}
