$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$pin = (Select-String -Path rust-toolchain.toml -Pattern 'channel\s*=\s*"([^"]+)"').Matches.Groups[1].Value
if (-not $pin) { throw 'Could not read pinned toolchain from rust-toolchain.toml' }
$actual = (rustc --version)
if ($actual -notmatch [regex]::Escape($pin)) {
    throw "rustc is not the pinned toolchain. Expected $pin, got: $actual. Run: rustup toolchain install $pin"
}

Write-Host "[1/4] toolchain OK: $actual"
Write-Host "[2/4] cargo build --release --locked"
cargo build --release --locked

New-Item -ItemType Directory -Force -Path dist | Out-Null
Copy-Item target\release\aegis-ss.exe dist\aegis-ss.exe -Force
Copy-Item target\release\aegis-cli.exe dist\aegis-cli.exe -Force

$hashLines = @()
foreach ($name in 'aegis-ss.exe', 'aegis-cli.exe') {
    $h = (Get-FileHash -Algorithm SHA256 -Path (Join-Path dist $name)).Hash.ToLower()
    $hashLines += "$h  $name"
    Write-Host "$name  $h"
}
Set-Content -Path dist\SHA256SUMS.txt -Value ($hashLines -join "`n") -Encoding ascii

$manifest = @(
    'AEGIS-SS release manifest',
    'created_utc=' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'),
    'rustc=' + $actual,
    'cargo=' + (cargo --version),
    'profile=lto=fat, codegen-units=1, opt-level=3, strip=symbols',
    'commands=cargo build --release --locked',
    '',
    'See SHA256SUMS.txt for artifact hashes.'
) -join "`n"
Set-Content -Path dist\RELEASE-MANIFEST.txt -Value $manifest -Encoding ascii
Write-Host '[4/4] dist ready: aegis-ss.exe, aegis-cli.exe, SHA256SUMS.txt, RELEASE-MANIFEST.txt'
