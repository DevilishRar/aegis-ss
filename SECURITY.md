# SECURITY

Aegis SS is transparent, read only and auditable by design. Its value depends on trust.

## In scope

* A remotely triggerable flaw in Aegis SS itself. For example a path traversal in report export.
* A module writing to the registry, disk, or another process when it must not.
* A module opening a network connection.
* A crash that destroys data, or elevates without explicit UAC consent.
* A verification path such as hash or checksum that can be forged.

## Not a vulnerability

* A finding flagging a suspicious but legitimate tool. That is a false positive. Report it as a bug with the exact UTC timestamp, screenshare context, and module output.
* The scanner reporting a real detection from your own Defender log. That is its job.
* Weaknesses in the audited machine rather than in the auditor.

## How to report

Open a private GitHub security advisory on this repository. Do not disclose publicly before a fix or mitigation ships. Include:

* OS build
* binary hash from certutil -hashfile aegis-ss.exe SHA256
* exact UTC capture
* module name and full output

If private advisories are unavailable, do not post exploit details publicly. Use the repository security tab.

## Response targets

| Item | Target |
|---|---|
| Acknowledgement | 7 days |
| Triage | 14 days |
| Fix or mitigation | Best effort, publicly credited if you want |

Aegis SS collects no telemetry. We cannot and will not see your usage. Reports are self contained.
