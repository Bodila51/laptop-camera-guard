# Filming visual: a fast, colourful, READ-ONLY stream of the real checks a camera/mic audit does on this PC
# (privacy log, devices, drivers, loaded camera/audio modules, services, tasks, autoruns, connections, event log),
# with a blurred frame from Desktop\camera-photos drawn in the terminal every few seconds (your own demo photos, not findings).
# The checks run in a background job; the screen replays what they found in a loop, so it never pauses.
# Usage: powershell -ExecutionPolicy Bypass -File waterfall.ps1 [-Batch 3] [-Every 5]
#   -Batch: lines per 15 ms tick (3 = ~100 lines/s, 6 = ~200)   -Every: seconds between example frames (0 = none)
param([int]$Batch = 3, [int]$Every = 5)

$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
# Blurred frames come from your own photos in Desktop\camera-photos (jpg/png); nothing is downloaded.
Add-Type -AssemblyName System.Drawing
function ToArt($path) {
    try { $img = [Drawing.Image]::FromFile($path) } catch { return }
    $W = 110; $H = 62; $e = [char]27; $hb = [char]0x2580
    $bm = New-Object Drawing.Bitmap $W, $H; $g = [Drawing.Graphics]::FromImage($bm); $g.InterpolationMode = 'HighQualityBicubic'; $g.DrawImage($img, 0, 0, $W, $H); $g.Dispose(); $img.Dispose()
    $sb = New-Object Text.StringBuilder
    for ($y = 0; $y -lt $H; $y += 2) {
        for ($x = 0; $x -lt $W; $x++) {
            $a = $bm.GetPixel($x, $y); $b = $bm.GetPixel($x, $y + 1)
            $v = foreach ($c in $a.R, $a.G, $a.B, $b.R, $b.G, $b.B) { [int][Math]::Min(255, [Math]::Pow($c / 255.0, 0.75) * 255 * 1.35) }
            [void]$sb.Append("$e[38;2;$($v[0]);$($v[1]);$($v[2])m$e[48;2;$($v[3]);$($v[4]);$($v[5])m$hb")
        }
        [void]$sb.Append("$e[0m`n")
    }
    $bm.Dispose(); $sb.ToString()
}
$photos = Join-Path ([Environment]::GetFolderPath('Desktop')) 'camera-photos'

$job = Start-Job {
    $ErrorActionPreference = 'SilentlyContinue'
    function E($tag, $col, $text) { "$tag`t$col`t$text" }
    function FT($v) { if ($v -and [int64]$v -gt 0) { [DateTime]::FromFileTime([int64]$v).ToString('yyyy-MM-dd HH:mm:ss') } else { '-' } }
    E 'START' 'Yellow' 'camera / microphone access audit - read only'
    foreach ($hive in 'HKCU', 'HKLM') {
        foreach ($cap in 'webcam', 'microphone') {
            $root = "${hive}:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$cap"
            E 'REG' 'DarkCyan' "open $hive\...\ConsentStore\$cap"
            Get-ChildItem $root -Recurse | ForEach-Object {
                $p = Get-ItemProperty $_.PSPath
                $name = $_.PSChildName -replace '#', '\'
                if ($null -eq $p.LastUsedTimeStart) { E 'REG' 'DarkGray' "$cap  $name  (no usage record)"; return }
                E ($cap.Substring(0, 3).ToUpper()) ($(if ($cap -eq 'webcam') { 'Yellow' } else { 'Green' })) ("{0}  last used {1} -> {2}" -f $name, (FT $p.LastUsedTimeStart), (FT $p.LastUsedTimeStop))
            }
        }
    }
    Get-PnpDevice -Class Camera, Image, AudioEndpoint, MEDIA | ForEach-Object { E 'DEVICE' 'White' ("{0,-14} {1}  [{2}]" -f $_.Class, $_.FriendlyName, $_.Status) }
    Get-ChildItem C:\Windows\System32\drivers -File | ForEach-Object {
        E 'DRIVER' ($(if ($_.Name -match 'cam|usbvideo|ks|audio|hdaud') { 'Yellow' } else { 'DarkGreen' })) ("{0,-36} {1,10:N0} B  {2}" -f $_.Name, $_.Length, $_.LastWriteTime.ToString('yyyy-MM-dd'))
    }
    $camDll = '^(mf|ksproxy|avicap|vidcap|frameserver|windows\.media\.capture|audioses|mmdevapi|wasapi|ksuser)'
    Get-Process | Sort-Object ProcessName | ForEach-Object {
        $pn = $_.ProcessName
        E 'PROC' 'DarkCyan' ("{0} (pid {1})  scanning loaded modules" -f $pn, $_.Id)
        $_.Modules | ForEach-Object {
            if ($_.ModuleName -match $camDll) { E 'MODULE' 'Magenta' ("{0} -> {1}  camera/audio stack" -f $pn, $_.ModuleName) }
            else { E 'MODULE' 'DarkGray' ("{0} -> {1}" -f $pn, $_.ModuleName) }
        }
    }
    Get-CimInstance Win32_Service | ForEach-Object { E 'SERVICE' ($(if ($_.State -eq 'Running') { 'Green' } else { 'DarkGray' })) ("{0,-32} {1,-8} {2}" -f $_.Name, $_.State, $_.PathName) }
    Get-ScheduledTask | ForEach-Object { E 'TASK' 'DarkYellow' ("{0}{1}  ->  {2}" -f $_.TaskPath, $_.TaskName, ($_.Actions | Select-Object -First 1).Execute) }
    foreach ($r in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run') {
        (Get-ItemProperty $r).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { E 'AUTORUN' 'Red' ("{0}  ->  {1}" -f $_.Name, $_.Value) }
    }
    Get-NetTCPConnection | ForEach-Object { E 'NET' 'DarkYellow' ("{0,-12} {1}:{2} -> {3}:{4}  {5}" -f $_.State, $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, (Get-Process -Id $_.OwningProcess).ProcessName) }
    Get-ChildItem "$env:APPDATA\AnyDesk", "$env:ProgramData\AnyDesk", "$env:APPDATA\TeamViewer", "$env:USERPROFILE\Downloads" -File | ForEach-Object { E 'FILE' 'Gray' ("{0}  {1}" -f $_.FullName, $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) }
    Get-WinEvent -LogName System -MaxEvents 1500 | ForEach-Object { E 'EVENT' 'DarkGray' ("{0}  id {1,-5} {2}" -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $_.Id, $_.ProviderName) }
}

$arts = @(Get-ChildItem $photos -File | Where-Object Extension -match '^\.(jpe?g|png|bmp)$' | ForEach-Object { ToArt $_.FullName })

$home_ = [regex]::Escape($env:USERPROFILE)
$buf = New-Object Collections.Generic.List[string]
while ($buf.Count -lt 30 -and $job.State -eq 'Running') { Receive-Job $job | ForEach-Object { $buf.Add($_) }; Start-Sleep -Milliseconds 50 }
Receive-Job $job | ForEach-Object { $buf.Add($_) }
$i = 0; $k = 0; $sw = [Diagnostics.Stopwatch]::StartNew()
while ($true) {
    if ($i % 200 -eq 0 -and $job.HasMoreData) { Receive-Job $job | ForEach-Object { $buf.Add($_) } }
    $tag, $col, $text = $buf[$i % $buf.Count] -split "`t", 3
    $text = ($text -replace $home_, '~') -replace '\b(\d{1,3}\.){3}\d{1,3}\b', '<ip>'
    $w = [Math]::Max(40, $Host.UI.RawUI.WindowSize.Width - 24); if ($text.Length -gt $w) { $text = $text.Substring(0, $w) }
    Write-Host ((Get-Date).ToString('HH:mm:ss.fff') + ' ') -NoNewline -ForegroundColor DarkGray
    Write-Host ("[{0,-7}] " -f $tag) -NoNewline -ForegroundColor Cyan
    Write-Host $text -ForegroundColor $col
    $i++
    if ($i % $Batch -eq 0) { Start-Sleep -Milliseconds 15 }
    if ($Every -gt 0 -and $arts -and $sw.Elapsed.TotalSeconds -ge $Every) {
        $k++; Write-Host ''
        [Console]::Write($arts[$k % @($arts).Count])
        $sw.Restart()
    }
}
