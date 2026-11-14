# CONTRIBUTING

## Non negotiables

* Read only. No registry writes. No service control changes. No file deletion.
* Zero network. No sockets. No HTTP. No DNS. No telemetry. No auto update. No crash reporter.
* Transparent. No obfuscation. No packed binaries. No opaque generated blobs. Generated code must be reviewable via cargo expand.
* Evidence not vibes. A scanner must land its raw evidence with the finding.
* False positives matter as much as misses. If you add a heuristic, document exactly what benign things fire it.

## Build

    rustup toolchain install 1.99.1
    cargo build --release --locked
    cargo test --release --locked
    .\target\release\aegis-cli.exe --bench 20

## Pull request checklist

* cargo test --release passes
* cargo build --release --locked passes
* Benchmark delta in the PR description under a stated machine and mode
* New finding class documents false positive risk
* scripts/source-audit.ps1 clean
* Docs updated

## Code review bar

* Straight line logic over cleverness.
* The published copy carries no comments at all. Contributions must not add them.
* Hand written FFI cites the exact Windows documentation or observed behavior.
* No new dependency without a paragraph on why and what it transitively pulls in.
