
use std::ffi::c_void;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::ffi;

pub fn self_sha256() -> String {
    match std::env::current_exe() {
        Ok(p) => hash_file(&p).unwrap_or_else(|_| "n/a".to_string()),
        Err(_) => "n/a".to_string(),
    }
}

pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let data = fs::read(path)?;
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}


pub fn check_no_network() -> (bool, String) {
    let pid = unsafe { ffi::GetCurrentProcessId() };
    let mut size: u32 = 0;
    let rc = unsafe {
        ffi::GetExtendedTcpTable(std::ptr::null_mut(), &mut size, ffi::FALSE,
                                 ffi::AF_INET, ffi::TCP_TABLE_OWNER_PID_ALL, 0)
    };
    if rc != ffi::ERROR_INSUFFICIENT_BUFFER || size == 0 {
        return (false, format!("socket census unavailable (rc={}); unknown, not failure", rc));
    }
    let mut buf = vec![0u8; size as usize];
    let rc2 = unsafe {
        ffi::GetExtendedTcpTable(buf.as_mut_ptr() as *mut c_void, &mut size, ffi::FALSE,
                                 ffi::AF_INET, ffi::TCP_TABLE_OWNER_PID_ALL, 0)
    };
    if rc2 != ffi::NO_ERROR {
        return (false, format!("socket census failed (rc={})", rc2));
    }
    let header = buf.as_ptr() as *const ffi::MIB_TCPTABLE_OWNER_PID;
    let count = unsafe { (*header).dwNumEntries } as usize;
    let row_size = std::mem::size_of::<ffi::MIB_TCPROW_OWNER_PID>();
    let rows_base = unsafe { buf.as_ptr().add(4) as *const ffi::MIB_TCPROW_OWNER_PID };
    let mut ours = 0usize;
    for i in 0..count {
        let row = unsafe { &*(rows_base.cast::<u8>().add(i * row_size) as *const ffi::MIB_TCPROW_OWNER_PID) };
        if row.dwOwningPid == pid {
            ours += 1;
        }
    }
    if ours == 0 {
        (true, format!("0 TCP sockets owned by PID {}", pid))
    } else {
        (false, format!("PID {} owns {} TCP socket(s)", pid, ours))
    }
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut token: ffi::HANDLE = 0;
        if ffi::OpenProcessToken(-1, ffi::TOKEN_QUERY, &mut token) == ffi::FALSE {
            return false;
        }
        let mut elev = ffi::TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let ok = ffi::GetTokenInformation(
            token,
            ffi::TOKEN_ELEVATION_CLASS,
            &mut elev as *mut ffi::TOKEN_ELEVATION as *mut c_void,
            std::mem::size_of::<ffi::TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        ffi::CloseHandle(token);
        ok != ffi::FALSE && elev.TokenIsElevated != 0
    }
}

pub fn uptime_seconds() -> u64 {
    unsafe { ffi::GetTickCount64() / 1000 }
}

pub struct SelfAudit {
    pub network_isolated: bool,
    pub network_detail: String,
    pub self_sha256: String,
    pub pid: u32,
    pub elevated: bool,
    pub uptime_seconds: u64,
}

pub fn audit() -> SelfAudit {
    let (ok, detail) = check_no_network();
    SelfAudit {
        network_isolated: ok,
        network_detail: detail,
        self_sha256: self_sha256(),
        pid: unsafe { ffi::GetCurrentProcessId() },
        elevated: is_elevated(),
        uptime_seconds: uptime_seconds(),
    }
}
