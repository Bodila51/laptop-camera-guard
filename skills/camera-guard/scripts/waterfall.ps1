# Filming visual: a fast, colourful waterfall of real system file paths (read-only), and every few seconds a blurred
# EXAMPLE frame drawn in the terminal. The frames are demo images, not anything found on this PC. Ctrl+C to stop.
# Usage: powershell -ExecutionPolicy Bypass -File waterfall.ps1 [-Batch 3] [-Every 5]
#   -Batch: lines per 15 ms tick (3 = ~100 lines/s, 6 = ~200)   -Every: seconds between example frames (0 = none)
param([int]$Batch = 3, [int]$Every = 5)

[Console]::OutputEncoding = [Text.Encoding]::UTF8
$base = 'https://raw.githubusercontent.com/Bodila51/laptop-camera-guard/main/skills/camera-guard/demo'
$dir = Join-Path $env:TEMP 'camera-guard-demo'
New-Item -ItemType Directory -Force $dir | Out-Null
$arts = foreach ($n in 1..4) {
    $f = Join-Path $dir "example_0$n.ans"
    if (-not (Test-Path $f)) { try { Invoke-WebRequest "$base/example_0$n.ans" -OutFile $f -UseBasicParsing } catch {} }
    if (Test-Path $f) { [IO.File]::ReadAllText($f, [Text.Encoding]::UTF8) }
}

$c = 'Cyan', 'Green', 'Yellow', 'Magenta', 'Red', 'White', 'DarkCyan', 'DarkGreen', 'Blue'
$t = 'SCAN', 'HASH', 'REG', 'CAM', 'MIC', 'NET', 'PROC', 'SIG'
$i = 0; $k = 0; $sw = [Diagnostics.Stopwatch]::StartNew()
while ($true) {
    Get-ChildItem C:\Windows\System32 -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $i++
        Write-Host ("{0} [{1,-4}] 0x{2:X8}  {3}" -f (Get-Date -f HH:mm:ss.fff), $t[$i % 8], $_.Length, $_.FullName) -ForegroundColor $c[(Get-Random 9)]
        if ($i % $Batch -eq 0) { Start-Sleep -Milliseconds 15 }
        if ($Every -gt 0 -and $arts -and $sw.Elapsed.TotalSeconds -ge $Every) {
            $k++
            Write-Host ""
            Write-Host ("[CAM ] webcam_capture_{0:D2}.jpg   EXAMPLE - demo frame, not from this computer" -f $k) -ForegroundColor Red
            [Console]::Write($arts[$k % @($arts).Count])
            Start-Sleep -Milliseconds 1500
            $sw.Restart()
        }
    }
}
