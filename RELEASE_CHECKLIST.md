# RELEASE

From code to trusted binary. Gates do not get skipped.

## Hard gates

* cargo test --release passes
* cargo build --release --locked passes
* scripts/source-audit.ps1 clean
* scripts/ui-smoke.ps1 passes in a clean VM or dedicated session. Never on a live multi window desktop. Screenshots reviewed then deleted. No aegis ss process left running afterwards
* Elevated run completed on a fresh Windows 11 VM. USN, Prefetch, Security 1102, Defender 1116 and 1117 all read correctly
* Same matrix on Windows 10 if you claim it
* aegis-cli --bench 20 recorded in the release notes with machine, elevation mode and OS build
* README numbers updated to match what you measured
* Export redaction spot checked. USERPROFILE, username and SIDs masked
* Binary submitted to the Microsoft false positive program if flagged

## Versioning

* Bump the version in Cargo.toml. rust toolchain.toml stays pinned to the compiler you release with
* Tag vMAJOR.MINOR.PATCH on the merge commit

## Build and sign

    .\scripts\build_release.ps1

Outputs dist/aegis-ss.exe, dist/aegis-cli.exe, dist/SHA256SUMS.txt, dist/RELEASE-MANIFEST.txt.

If you hold a code signing certificate:

    signtool sign /sha1 THUMBPRINT /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com dist\aegis-ss.exe dist\aegis-cli.exe

Rehash after signing and refresh SHA256SUMS.txt. Run the build script again to regenerate it.

## Cut the release

1. Push the tag
2. CI builds from the tag with the pinned toolchain and locked mode
3. CI uploads the dist artifacts as release assets
4. Release notes carry: what changed, what was measured with exact machine and mode, known false positives, elevated vs standard behavior, upgrade notes
5. Submit binaries to the Microsoft false positive program if flagged

## Launch path

| Stage | Audience | Exit condition |
|---|---|---|
| Alpha | maintainer only | all hard gates pass |
| Closed beta | 10 to 20 moderators with a support channel | 4 consecutive clean weeks with false positive reports handled |
| Public | everyone | beta exit plus signed artifacts plus published hashes |

Aegis SS cannot be proven unbypassable. No such thing exists. Say what it does. It raises the cost of hiding tampering and it shows its work.
