# VERIFICATION

What was actually tested and how. Host: Windows 11 Pro build 26300. Standard user. Elevated runs used UAC interactively. Date: 2026-11-14.

## Build and static gates

* cargo build --release --locked on rustc 1.99.1. Clean. Zero warnings
* cargo test --release --locked. Redact tests pass
* scripts/source-audit.ps1. OK. No network or write capable API usage in src
* scripts/build_release.ps1. Produces dist/aegis-ss.exe, dist/aegis-cli.exe, dist/SHA256SUMS.txt, dist/RELEASE-MANIFEST.txt

## Scanner core, CLI, standard user

* Full scan about 5 to 13 milliseconds including all eight modules. Zero child processes on the fast path
* Deep scan about 80 to 101 milliseconds. Adds wevtutil history and one batched Get AuthenticodeSignature call

## Scanner core, CLI, elevated

* Deep run completed with exit code 0
* BAM module read 39 findings, mostly HarddiskVolume3 game paths on the D drive. That is the secondary drive heuristic working as written. Expect similar noise on gamer machines
* Defender exclusions found including the VRChat EasyAntiCheat folder. Game added anti cheat folders will be flagged. This is expected behavior, not a bug
* Prefetch readable. Services SysMain EventLog DPS PcaSvc running. USN module returned in zero milliseconds with no hang

## GUI

* Launches and renders: wordmark, live UTC and local clock, uptime block, NET isolation chip, elevation chip, run and deep scan controls, verdict strip with stat chips, sidebar with per page severity dots and counts
* Every page rendered in its post scan state using the scan on start dev path: Overview with timeline grid, Deletions and tampering, Processes and overlays, Defender and Roblox, Trust audit
* Window closes cleanly via the close message every time it was launched
* Screenshots for review used PrintWindow, which captures only the target window and nothing else on screen
* Mouse clicking on a live desktop proved unreliable on the test machine. The no click path above replaced manual mouse testing for this build. Human click testing is pending a clean VM

## Elevation output difference

Unprivileged run: modules 1 and 2 report INFO because BAM and Prefetch are closed to standard users. Event log ID 1102 and System ID 104 are not visible. Defender operational threat log is unavailable. USN journal open fails and degrades to INFO.

Elevated run: all of the above become readable. The deep scan output grows noticeably. This is the expected behavior and the reason staff should ensure the player elevates before judging results on a call.

## Export and redaction

* Export writes a JSON report to the Desktop only when you click it
* Redacted export contains zero occurrences of the user profile path. Username becomes %USER%. SIDs become %SID%. Findings are unchanged

## Known issues

* BAM secondary drive heuristic flags games on D and E drives. Noisy for gamers. Needs a config toggle or signer based allow listing
* Defender game added exclusions are flagged as expected. Users will ask about this. Documentation will need a dedicated page
* SHA256 of the running executable was read at runtime on the test machine but not yet cross checked across machines

## Not tested

* Clean VM pass. Elevated and standard. All pages by hand
* Windows 10
* Code signing and Microsoft submission
* Closed beta false positive rate

## Ship verdict

Closed beta: yes after the clean VM pass and the game exclusion documentation page. Public release: no. Not until beta feedback and signing are done.
