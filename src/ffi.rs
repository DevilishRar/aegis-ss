

#![allow(non_snake_case)]
use std::ffi::c_void;

pub type HANDLE = isize;
pub type BOOL = i32;
pub type HWND = isize;
pub const INVALID_HANDLE_VALUE: HANDLE = -1;
pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

#[link(name = "kernel32")]
extern "system" {
    pub fn GetTickCount64() -> u64;
    pub fn GetCurrentProcessId() -> u32;
    pub fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> HANDLE;
    pub fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    pub fn Process32NextW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    pub fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: BOOL, dwProcessId: u32) -> HANDLE;
    pub fn QueryFullProcessImageNameW(hProcess: HANDLE, dwFlags: u32, lpExeName: *mut u16, lpdwSize: *mut u32) -> BOOL;
    pub fn CreateFileW(lpFileName: *const u16, dwDesiredAccess: u32, dwShareMode: u32,
                       lpSecurityAttributes: *mut c_void, dwCreationDisposition: u32,
                       dwFlagsAndAttributes: u32, hTemplateFile: HANDLE) -> HANDLE;
    pub fn DeviceIoControl(hDevice: HANDLE, dwIoControlCode: u32,
                           lpInBuffer: *mut c_void, nInBufferSize: u32,
                           lpOutBuffer: *mut c_void, nOutBufferSize: u32,
                           lpBytesReturned: *mut u32, lpOverlapped: *mut c_void) -> BOOL;
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;
}

#[link(name = "user32")]
extern "system" {
    pub fn EnumWindows(lpEnumFunc: EnumWindowsProc, lParam: isize) -> BOOL;
    pub fn IsWindowVisible(hWnd: HWND) -> BOOL;
    pub fn GetWindowLongW(hWnd: HWND, nIndex: i32) -> i32;
    pub fn GetWindowTextW(hWnd: HWND, lpString: *mut u16, nMaxCount: i32) -> i32;
    pub fn GetClassNameW(hWnd: HWND, lpClassName: *mut u16, nMaxCount: i32) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    pub fn OpenSCManagerW(lpMachineName: *const u16, lpDatabaseName: *const u16, dwDesiredAccess: u32) -> HANDLE;
    pub fn OpenServiceW(hSCManager: HANDLE, lpServiceName: *const u16, dwDesiredAccess: u32) -> HANDLE;
    pub fn QueryServiceStatus(hService: HANDLE, lpServiceStatus: *mut SERVICE_STATUS) -> BOOL;
    pub fn CloseServiceHandle(hSCObject: HANDLE) -> BOOL;
    pub fn OpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: u32, TokenHandle: *mut HANDLE) -> BOOL;
    pub fn GetTokenInformation(TokenHandle: HANDLE, TokenInformationClass: i32,
                               TokenInformation: *mut c_void, TokenInformationLength: u32,
                               ReturnLength: *mut u32) -> BOOL;
}

#[link(name = "iphlpapi")]
extern "system" {
    pub fn GetExtendedTcpTable(pTcpTable: *mut c_void, pdwSize: *mut u32,
                               bOrder: BOOL, ulAf: u32, tableClass: u32,
                               reserved: u32) -> u32;
}

pub type EnumWindowsProc = Option<unsafe extern "system" fn(HWND, isize) -> BOOL>;

pub const TH32CS_SNAPPROCESS: u32 = 0x00000002;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const GENERIC_READ: u32 = 0x8000_0000;
pub const FILE_SHARE_ALL: u32 = 0x00000001 | 0x00000002 | 0x00000004;
pub const OPEN_EXISTING: u32 = 3;

pub const GWL_EXSTYLE: i32 = -20;
pub const WS_EX_TOPMOST: i32 = 0x00000008;
pub const WS_EX_TRANSPARENT: i32 = 0x00000020;
pub const WS_EX_LAYERED: i32 = 0x00080000;

pub const SC_MANAGER_CONNECT: u32 = 0x0001;
pub const SERVICE_QUERY_STATUS: u32 = 0x0004;
pub const SERVICE_RUNNING: u32 = 4;

pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_ELEVATION_CLASS: i32 = 20;

pub const AF_INET: u32 = 2;
pub const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
pub const NO_ERROR: u32 = 0;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

#[repr(C)]
pub struct PROCESSENTRY32W {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ProcessID: u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase: i32,
    pub dwFlags: u32,
    pub szExeFile: [u16; 260],
}

#[repr(C)]
pub struct SERVICE_STATUS {
    pub dwServiceType: u32,
    pub dwCurrentState: u32,
    pub dwControlsAccepted: u32,
    pub dwWin32ExitCode: u32,
    pub dwServiceSpecificExitCode: u32,
    pub dwCheckPoint: u32,
    pub dwWaitHint: u32,
}

#[repr(C)]
pub struct TOKEN_ELEVATION {
    pub TokenIsElevated: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MIB_TCPROW_OWNER_PID {
    pub dwState: u32,
    pub dwLocalAddr: u32,
    pub dwLocalPort: u32,
    pub dwRemoteAddr: u32,
    pub dwRemotePort: u32,
    pub dwOwningPid: u32,
}

#[repr(C)]
pub struct MIB_TCPTABLE_OWNER_PID {
    pub dwNumEntries: u32,
    pub table: [MIB_TCPROW_OWNER_PID; 1],
}


pub const FSCTL_QUERY_USN_JOURNAL: u32 = 0x0009_00F4;
pub const FSCTL_READ_USN_JOURNAL: u32 = 0x0009_00BB;
pub const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;
pub const USN_REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
pub const USN_REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct USN_JOURNAL_DATA_V0 {
    pub UsnJournalID: u64,
    pub FirstUsn: i64,
    pub NextUsn: i64,
    pub LowestValidUsn: i64,
    pub MaxUsn: i64,
    pub MaximumSize: u64,
    pub AllocationDelta: u64,
}

#[repr(C)]
pub struct READ_USN_JOURNAL_DATA_V0 {
    pub StartUsn: i64,
    pub ReasonMask: u32,
    pub ReturnOnlyOnClose: u32,
    pub Timeout: u32,
    pub BytesToWaitFor: u32,
    pub UsnJournalID: u64,
}

pub fn utf16_buf_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
