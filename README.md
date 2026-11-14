# AEGIS-SS

Transparent, read only, zero network integrity auditor for Windows. Built for
competitive screenshare sessions. Source is fully readable. Binaries are
SHA256 checked. Every release lists exact build inputs.

> AEGIS-SS produces signals. It does not produce verdicts. A flagged artifact
> means something deserves an explanation on the call, nothing more.

## Overview

| Area | Detail |
|---|---|
| Language | Rust, pinned toolchain 1.99.1 in `rust-toolchain.toml` |
| Crates | `eframe`, `winreg`, `serde`, `chrono`, `sha2`. No network stack anywhere |
| Network | None. The self check proves the process owns zero sockets |
| Registry writes | None. All hive access is read only |
| File writes | None except an explicit export click you perform |
| Processes spawned | None on the fast path. Deep scan uses wevtutil and one batched PowerShell call |
| Platforms | Windows 10 and Windows 11 |

## The eight modules

| # | Module | What it surfaces |
|---|---|---|
| 1 | BAM and DAM | Programs executed within the window from HKLM BAM and DAM hives |
| 2 | Prefetch | Recent prefetch records and a purge heuristic |
| 3 | USN journal | Deletes and renames of watched extensions via FSCTL, last 60 minutes |
| 4 | Defender | Path and process exclusions, plus threat events 1116 and 1117 in deep scan |
| 5 | Tampering | Security log event 1102, System log event 104, and service state SysMain DPS EventLog PcaSvc |
| 6 | PCA and MuiCache | Residual records of binaries that were deleted afterwards |
| 7 | Processes | Risky launch paths, click through overlay windows, signatures in deep scan |
| 8 | Roblox | Proxy DLL presence in the client directory, newest session log anchor |

## Elevation

The tool runs fine as a standard user. Elevated, it reads more and reports more.

| Privilege | What it unlocks |
|---|---|
| Standard user | Modules 1 2 6 7 8. Service state in module 5 |
| Administrator via UAC | Everything above plus full USN journal, Prefetch listing, Security 1102 and System 104, Defender operational threat history. Deep scan shows visibly more findings |

Deep scan runs about 90 to 100 milliseconds. Fast scan runs about 5 to 13 milliseconds. Neither number is a marketing target. Measure on your own machine with `aegis-cli --bench`.

## Download

Binaries live under Releases. Each release contains `aegis-ss.exe`, `aegis-cli.exe`, `SHA256SUMS.txt`, `RELEASE-MANIFEST.txt` and a `VERIFICATION.md` describing what was actually tested.

PowerShell check:

    (Get-FileHash .\aegis-ss.exe -Algorithm SHA256).Hash

Compare the hash to SHA256SUMS.txt in the same release.

## Build from source

    rustup toolchain install 1.99.1
    cargo build --release --locked
    cargo test --release --locked
    .\target\release\aegis-cli.exe --bench 20

Expected wall time on a modern machine: under 20 milliseconds for a full fast scan.

## What this is not

AEGIS-SS does not ban anyone. It does not contact anyone. It does not phone home. It does not decide cheating. It prints artifacts a human moderator reads on a call. Moderation decisions remain with people.

## Credits

Built by the community. MIT license. No affiliation with or endorsement by Roblox, Discord, or Microsoft.
