param(
    [string]$ExePath = 'target\release\aegis-ss.exe',
    [string]$ArtifactsDir = 'artifacts',
    [string]$Arguments = '',
    [string[]]$Click = @(),
    [switch]$AllowDesktopClicks,
    [switch]$NoClose
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root
if (-not (Test-Path $ExePath)) { throw "Not found: $ExePath - run cargo build --release first" }
$ArtifactsDir = Join-Path $root $ArtifactsDir
New-Item -ItemType Directory -Force -Path $ArtifactsDir | Out-Null

Add-Type -AssemblyName System.Drawing
Add-Type @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class AegisUser32 {
  public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  public const int SW_RESTORE = 9; public const uint WM_CLOSE = 0x0010;
  public const uint LEFTDOWN = 0x0002, LEFTUP = 0x0004;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, StringBuilder sb, int nMaxCount);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
  [DllImport("user32.dll", SetLastError = true)] public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
  [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, UIntPtr dwExtraInfo);

  public static IntPtr FindAppWindow(uint targetPid) {
    IntPtr found = IntPtr.Zero; long bestArea = 0;
    EnumWindows((h, l) => {
      uint pid; GetWindowThreadProcessId(h, out pid);
      if (pid != targetPid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256); GetWindowText(h, sb, 256);
      if (sb.Length == 0) return true;
      RECT r; GetWindowRect(h, out r);
      long area = (long)(r.Right - r.Left) * (r.Bottom - r.Top);
      if (area > bestArea) { bestArea = area; found = h; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
'@

function Capture-Window($hwnd, $path) {
    $rect = New-Object AegisUser32+RECT
    [AegisUser32]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
    $w = $rect.Right - $rect.Left; $h = $rect.Bottom - $rect.Top
    if ($w -le 0 -or $h -le 0) { throw "Window has invalid rect (${w}x${h})" }
    $bmp = New-Object Drawing.Bitmap($w, $h)
    $gfx = [Drawing.Graphics]::FromImage($bmp)
    $hdc = $gfx.GetHdc()
    if (-not [AegisUser32]::PrintWindow($hwnd, $hdc, [uint32]2)) {
        $gfx.ReleaseHdc($hdc); $gfx.Dispose(); $bmp.Dispose()
        throw 'PrintWindow failed; is the window minimized?'
    }
    $gfx.ReleaseHdc($hdc)
    $bmp.Save($path, [Drawing.Imaging.ImageFormat]::Png)
    $gfx.Dispose(); $bmp.Dispose()
}

if ($Click.Count -gt 0 -and -not $AllowDesktopClicks) {
    throw 'Coordinate clicks are disabled. Re-run with -AllowDesktopClicks only inside a clean VM / dedicated test session.'
}

$procArgs = if ($Arguments) { $Arguments -split '\s+' } else { [string[]]@() }
$proc = Start-Process -FilePath $ExePath -PassThru -ArgumentList $procArgs
$hwnd = [IntPtr]::Zero
for ($i = 0; $i -lt 100; $i++) {
    $hwnd = [AegisUser32]::FindAppWindow([uint32]$proc.Id)
    if ($hwnd -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 100
}
if ($hwnd -eq [IntPtr]::Zero) { Stop-Process -Id $proc.Id -Force; throw 'App window never appeared' }

[AegisUser32]::ShowWindow($hwnd, [AegisUser32]::SW_RESTORE) | Out-Null
[AegisUser32]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 600
Capture-Window $hwnd (Join-Path $ArtifactsDir 'ui-smoke-00-launch.png')
Write-Host ("launched pid {0} hwnd=0x{1:x}; screenshot: {2}" -f $proc.Id, $hwnd.ToInt64(), (Join-Path $ArtifactsDir 'ui-smoke-00-launch.png'))

$i = 0
foreach ($c in $Click) {
    $parts = $c.Split(',')
    $relX = [int]$parts[0]; $relY = [int]$parts[1]; $label = if ($parts.Count -ge 3) { $parts[2].Trim() } else { "click$i" }
    $rect = New-Object AegisUser32+RECT
    [AegisUser32]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
    $x = $rect.Left + $relX; $y = $rect.Top + $relY
    [AegisUser32]::SetCursorPos($x, $y) | Out-Null
    [AegisUser32]::mouse_event([AegisUser32]::LEFTDOWN, 0, 0, 0, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 60
    [AegisUser32]::mouse_event([AegisUser32]::LEFTUP, 0, 0, 0, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 800
    $proc.Refresh()
    if ($proc.HasExited) { throw "Process exited after click '$label' - smoke test FAILED" }
    $newhwnd = [AegisUser32]::FindAppWindow([uint32]$proc.Id)
    if ($newhwnd -ne [IntPtr]::Zero) { $hwnd = $newhwnd }
    $i++
    $safe = ($label -replace '[^A-Za-z0-9_-]', '_')
    Capture-Window $hwnd (Join-Path $ArtifactsDir ("ui-smoke-{0:d2}-{1}.png" -f $i, $safe))
    Write-Host "click '$label' at window-relative ($relX,$relY) - still alive"
}

if (-not $NoClose) {
    [AegisUser32]::SendMessage($hwnd, [AegisUser32]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    if (-not $proc.WaitForExit(10000)) { Stop-Process -Id $proc.Id -Force } else { Write-Host 'window closed cleanly' }
} else {
    Write-Host 'window left open (--NoClose)'
}
Write-Host 'UI SMOKE OK'
