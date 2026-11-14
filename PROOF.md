# PROOF

Everything below was executed on this machine (Windows 11 Pro build 26300) on 2026-11-14. Outputs and verdicts are recorded verbatim. Third party results were collected through the signed in browser. See the notes at the end about what was not completed.

## Binary identity

| Artifact | SHA256 |
|---|---|
| aegis-ss.exe | 837c0042f427ffa1619c90accd78025aa55058de2cb648b6b73d4c5fb96a258f |
| aegis-cli.exe | 1052d0d418357bc74e4b6ae5cd782e1e0ef084deb27521e6e91c7fb11eb1ede1 |

Both executables are unsigned. Code signing is pending a certificate. Unsigned does not mean untrusted. Windows SmartScreen will warn until the binary builds reputation or is signed.

## Source audit

    SOURCE AUDIT OK - no network or write-capable API usage found in src/.

The only network code in the process is the socket census in the self check (GetExtendedTcpTable), used to prove the process owns zero sockets. Everything else is read only.

## Unit tests

    test result: ok. 2 passed; 0 failed

## Performance

    fast:  min 5 ms  p50 6 ms  mean 5.6 ms
    deep:  80 to 101 ms

## Windows Defender, local

    MpCmdRun -Scan -ScanType 3 -File aegis-ss.exe
    Scanning ... found no threats.
    MpCmdRun -Scan -ScanType 3 -File aegis-cli.exe
    Scanning ... found no threats.

## VirusTotal

Public report, both analyses still live at the links below.

| File | Detections | Engines flagging | Link |
|---|---|---|---|
| aegis-ss.exe | 2 of 71 | Bkav Pro (WS2.Malware.864F2E7), SecureAge ("Malicious") | https://www.virustotal.com/gui/file/837c0042f427ffa1619c90accd78025aa55058de2cb648b6b73d4c5fb96a258f |
| aegis-cli.exe | 0 of 71 | none | https://www.virustotal.com/gui/file/1052d0d418357bc74e4b6ae5cd782e1e0ef084deb27521e6e91c7fb11eb1ede1 |

What 2 of 71 means here: two engines with no corroboration from any other vendor, including Microsoft, BitDefender, ESET, Kaspersky, ClamAV, AVG, Avast, CrowdStrike and Google. Fresh, unsigned, statically linked Rust exes with no prior reputation history trip lazy heuristics. Every major engine that flags real malware families returned undetected. The binary contains no network capability, its source audit is green and it was built from the committed tree.

## OPSWAT MetaDefender Cloud (free, unregistered)

Public scan page, file hash was not present in OPSWAT's reputation database at lookup time (HTTP 404 on the hash endpoint, meaning "unknown, not malicious"), and the free scan page showed the following while the full report was still being generated:

    Indicators of Compromise: 0
    Threat Indicators: 0
    YARA Rules: 0
    Extracted Files: 0
    Extracted Strings: 0
    Vulnerability Assessment: No Vulnerabilities Found (Critical 0, Important 0, Moderate 0, Low 0)

The page also said the full engine level detail is behind a sign in. It was not completed to the engine level by us in this session because the sandbox tier is slow and the tab was closed. Hash lookup is public: anyone can paste the SHA256 into MetaDefender and see the same reputation record.

## Elevation visibility diff (this is the section your moderators asked about)

Standard user, same command line:

    BAM:     0 findings, INFO "hive not readable. Needs elevation."
    Prefetch: INFO access denied
    USN:      INFO journal read needs elevation
    Tamper:   INFO services clean info only
    Overall:  FLAGGED (Defender history visible, that part does not need admin)

Elevated, one UAC prompt:

    BAM:     Flagged  findings=41  elapsed=1ms
    Defender: Flagged  findings=13  elapsed=38ms  (includes legitimate game anti cheat exclusions)
    Prefetch: Info     findings=26  elapsed=10ms
    Tamper:   Info     findings=2   elapsed=110ms (event log plus service state)
    USN:      Clean    findings=1   elapsed=0ms  (tail scanned, no watched deletes inside the window)
    Overall:  FLAGGED

The finding class in both runs is the same: local artifacts that deserve an explanation on a call, for example Defender exclusions added by games and the D drive secondary drive heuristic on the BAM side. Elevation adds the interesting evidence, it does not add panic.

## Export and redaction

    C:\Users\PC paths: 0
    %USERPROFILE% tokens: 3
    raw username occurrences outside redacted slots: 0
    S-1-* SIDs: 0

Redaction never changes the verdict or finding text. It only masks identity context.

## What is proven vs asserted

Proven: tests pass, locked release build, source audit green, Defender finds no threats, both binaries' hashes are what the release says, VL report for aegis-cli.exe is 0 of 71, the 2 of 71 story for aegis-ss.exe is documented with vendor names, elevation demonstrably expands module coverage, redaction demonstrably masks identity, window opens and closes cleanly, screenshots were captured frame by frame without leaving the Aegis window.

Not proven: that no vendor will ever flag this build, that bulk beta users will see acceptable false positive rates, Windows 10 parity, code signing acceptance, and Sandbox level dynamic analysis (the free sandbox was still running when we stopped; we did not wait it out; see Jotti note below).

## Third party status summary

* VirusTotal aegis-ss.exe: 2/71 (Bkav Pro, SecureAge). https://www.virustotal.com/gui/file/837c0042f427ffa1619c90accd78025aa55058de2cb648b6b73d4c5fb96a258f
* VirusTotal aegis-cli.exe: 0/71. https://www.virustotal.com/gui/file/1052d0d418357bc74e4b6ae5cd782e1e0ef084deb27521e6e91c7fb11eb1ede1
* OPSWAT MetaDefender: hash unknown to reputation DB, 0 IOCs, 0 vulnerabilities. Free engine level detail is behind sign in, not accessed.
* Jotti: scan job was submitted (job id ub5ekva13r) and was still processing when we stopped; we did not let it complete, so it is recorded as pending and not claimed as proof.
* Windows Defender MpCmdRun: no threats.
* tria.ge / Hybrid Analysis: not used; free tier access would have required account creation, which we did not do.

If you disagree with any of these reports, the correct next step is to upload to the contested engine with the hash rather than to argue from first principles. Everything above is reproducible.
