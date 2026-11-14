# PROOF

What was verified, what was observed, and what still requires your input. Everything below was executed on a real machine running Windows 11 Pro build 26300 on 2026-11-14. Command outputs are pasted verbatim.

## Binary identity

| Artifact | SHA256 |
|---|---|
| aegis-ss.exe | 837c0042f427ffa1619c90accd78025aa55058de2cb648b6b73d4c5fb96a258f |
| aegis-cli.exe | 1052d0d418357bc74e4b6ae5cd782e1e0ef084deb27521e6e91c7fb11eb1ede1 |

Both executables are unsigned. Code signing is pending a certificate. Unsigned does not mean untrusted, but it does mean Windows SmartScreen will warn on first run until the binary builds reputation or gets signed.

## Windows Defender scan, local

Command:

    MpCmdRun.exe -Scan -ScanType 3 -File dist\aegis-ss.exe
    MpCmdRun.exe -Scan -ScanType 3 -File dist\aegis-cli.exe

Verbatim output:

    Scan starting...
    Scan finished.
    Scanning ...\dist\aegis-ss.exe found no threats.
    Scan starting...
    Scan finished.
    Scanning ...\dist\aegis-cli.exe found no threats.

Signature status: NotSigned (both). Authenticode does not apply until signing exists.

## Source audit

scripts/source-audit.ps1 (automated, run on every build and in CI):

    SOURCE AUDIT OK - no network or write-capable API usage found in src/.

No network imports, no TcpStream, no raw socket creation, no registry write calls. The only network code in the process is GetExtendedTcpTable in the self check, used to prove this process owns zero sockets. Every other operation is read only.

## Unit tests

    test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Two redaction tests pass. They prove the export path masks USERPROFILE, username tokens, and SIDs.

## Performance

aeaegis-cli --bench, standard user, same machine:

    n=20  min 5 ms  p50 6 ms  mean 5.6 ms  deep n/a
    deep run: 80-101 ms wall

## Elevation increases visibility (verbatim diff)

Standard user, aegis-cli --deep:

    BAM:     0 findings, INFO "hive not readable. Needs elevation."
    Prefetch: INFO access denied
    USN:      INFO journal read needs elevation
    Overall:  FLAGGED (Defender history still visible)

Elevated via interactive UAC, same command:

    BAM:     Flagged  findings=41  elapsed=1ms
    Defender: Flagged  findings=13  elapsed=38ms  (exclusions incl. game anti cheat folders)
    Prefetch: Info     findings=26  elapsed=10ms
    USN:      Clean    findings=1   elapsed=0ms  (tail scanned, no watched deletes in window)
    Tamper:   Info     findings=2   elapsed=110ms (event log + service state read fine)
    Overall:  Flagged

Why it matters: the BAM hive, the Prefetch directory, the USN journal, the Security log 1102 and System log 104, and the Defender operational threat history are all ACL protected. Standard user gets the subset; Administrator gets the full picture. That is why the GUI has an Elevate button and why staff should insist on elevation during a call.

## Third party scanners (pending your action)

Hash lookup works without uploading the file, but a fresh binary has no history to look up. Static engines and sandboxes need the file itself. A network scan uploads the binary. Uploading is fine because the release is public by design, but it was not done in this session because the browser relay is not connected and no API keys are present on this machine.

What is needed to finish this section:

1. Fix or enable the browse extension, or log into these services and upload manually, or hand me a VirusTotal API key.
2. Upload or hash submit aegis-ss.exe and aegis-cli.exe to:
   * VirusTotal (static + sandbox)
   * tria.ge
   * Hybrid Analysis (Falcon Sandbox)
   * Jotti or any free multi engine scanner that serves the RBLX community
3. Goal result: zero or near zero detections across engines. Many legitimate game tooling binaries trip heuristic engines. If any engine flags the binary, the release notes will name it and link the report.

If any scanner flags the binary, do not panic. Check which engine and which signature. Heuristic names like Trojan GenericKD or Suspicious Packer rarely indicate actual compromise. The source is reviewable precisely so that reviewers do not have to guess.

## What is proven vs what is asserted

Proven: tests pass, build compiles clean locked and lto, source audit is green, Defender finds no threats locally, hash values are what they are, elevation demonstrably expands module coverage, export redaction demonstrably masks identity, window closes cleanly, screenshots were captured only of the app window.

Not proven yet: that no AV vendor will flag this binary, that the tool behaves identically on every Windows 10 and 11 build, that the click through UI is ergonomic for moderators, that signing will pass EV validation, that beta testers will report acceptable false positive rates.

This file will be updated with third party scan results as they land.
