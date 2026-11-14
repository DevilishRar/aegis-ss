$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$src  = Join-Path $root 'src'

$patterns = @(
    'std::net',
    'TcpStream',
    'UdpSocket',
    'tokio::net',
    'reqwest',
    'hyper::',
    'WinHttpOpen',
    'WinHttpConnect',
    'InternetOpenUrl',
    'InternetConnect',
    'HttpOpenRequest',
    'WSAConnect',
    'RegSetValueEx',
    'RegCreateKeyEx',
    'set_value(',
    'create_subkey(',
    'DeleteVolume'
)

$hits = @()
foreach ($p in $patterns) {
    $matches = Get-ChildItem -Path $src -Recurse -File -Include *.rs |
        Select-String -Pattern $p -SimpleMatch
    foreach ($m in $matches) {
        if ($m.Line -match 'GetExtendedTcpTable|socket census|own 0|no network') { continue }
        $hits += ("{0}:{1}: {2}" -f $m.Path, $m.LineNumber, $m.Line.Trim())
    }
}

if ($hits.Count -gt 0) {
    Write-Host 'SOURCE AUDIT FAILED - forbidden API usage found:' -ForegroundColor Red
    $hits | ForEach-Object { Write-Host $_ }
    exit 1
}
Write-Host 'SOURCE AUDIT OK - no network or write-capable API usage found in src/.' -ForegroundColor Green
exit 0
