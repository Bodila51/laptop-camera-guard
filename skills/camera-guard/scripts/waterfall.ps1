# Filming visual: a fast, colourful, READ-ONLY stream of the real checks a camera/mic audit does on this PC
# (privacy log, devices, drivers, loaded camera/audio modules, services, tasks, autoruns, connections, event log),
# with a blurred example frame drawn in the terminal every few seconds. The frames are demo images, not findings.
# Usage: powershell -ExecutionPolicy Bypass -File waterfall.ps1 [-Batch 3] [-Every 5]
#   -Batch: lines per 15 ms tick (3 = ~100 lines/s, 6 = ~200)   -Every: seconds between example frames (0 = none)
param([int]$Batch = 3, [int]$Every = 5)

$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$base = 'https://raw.githubusercontent.com/Bodila51/laptop-camera-guard/main/skills/camera-guard/demo'
$dir = Join-Path $env:TEMP 'camera-guard-demo'
New-Item -ItemType Directory -Force $dir | Out-Null
$arts = foreach ($n in 1..4) {
    $f = Join-Path $dir "example_0$n.ans"
    if (-not (Test-Path $f)) { try { Invoke-WebRequest "$base/example_0$n.ans" -OutFile $f -UseBasicParsing } catch {} }
    if (Test-Path $f) { [IO.File]::ReadAllText($f, [Text.Encoding]::UTF8) }
}

$home_ = [regex]::Escape($env:USERPROFILE)
$script:i = 0; $script:k = 0; $sw = [Diagnostics.Stopwatch]::StartNew()
$camDll = '^(mf|ksproxy|avicap|vidcap|frameserver|windows\.media\.capture|audioses|mmdevapi|wasapi|ksuser)'
function Emit($tag, $text, $col = 'Gray') {
    $text = ($text -replace $home_, '~') -replace '\b(\d{1,3}\.){3}\d{1,3}\b', '<ip>'
    Write-Host ((Get-Date).ToString('HH:mm:ss.fff') + ' ') -NoNewline -ForegroundColor DarkGray
    Write-Host ("[{0,-7}] " -f $tag) -NoNewline -ForegroundColor Cyan
    Write-Host $text -ForegroundColor $col
    $script:i++
    if ($script:i % $Batch -eq 0) { Start-Sleep -Milliseconds 15 }
    if ($Every -gt 0 -and $arts -and $sw.Elapsed.TotalSeconds -ge $Every) {
        $script:k++; Write-Host ''
        [Console]::Write($arts[$script:k % @($arts).Count])
        Start-Sleep -Milliseconds 1500; $sw.Restart()
    }
}
function FT($v) { if ($v -and [int64]$v -gt 0) { [DateTime]::FromFileTime([int64]$v).ToString('yyyy-MM-dd HH:mm:ss') } else { '-' } }

while ($true) {
    Emit 'START' 'camera / microphone access audit - read only' 'Yellow'
    foreach ($hive in 'HKCU', 'HKLM') {
        foreach ($cap in 'webcam', 'microphone') {
            $root = "${hive}:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$cap"
            Emit 'REG' "open $hive\...\ConsentStore\$cap" 'DarkCyan'
            Get-ChildItem $root -Recurse | ForEach-Object {
                $p = Get-ItemProperty $_.PSPath
                $name = $_.PSChildName -replace '#', '\'
                if ($null -eq $p.LastUsedTimeStart) { Emit 'REG' "$cap  $name  (no usage record)" 'DarkGray'; return }
                Emit ($cap.Substring(0, 3).ToUpper()) ("{0}  last used {1} -> {2}" -f $name, (FT $p.LastUsedTimeStart), (FT $p.LastUsedTimeStop)) ($(if ($cap -eq 'webcam') { 'Yellow' } else { 'Green' }))
            }
        }
    }
    Get-PnpDevice -Class Camera, Image, AudioEndpoint, MEDIA | ForEach-Object { Emit 'DEVICE' ("{0,-14} {1}  [{2}]" -f $_.Class, $_.FriendlyName, $_.Status) 'White' }
    Get-ChildItem C:\Windows\System32\drivers -File | ForEach-Object {
        Emit 'DRIVER' ("{0,-36} {1,10:N0} B  {2}" -f $_.Name, $_.Length, $_.LastWriteTime.ToString('yyyy-MM-dd')) ($(if ($_.Name -match 'cam|usbvideo|ks|audio|hdaud') { 'Yellow' } else { 'DarkGreen' }))
    }
    Get-Process | Sort-Object ProcessName | ForEach-Object {
        $pn = $_.ProcessName; $procId = $_.Id
        Emit 'PROC' ("{0} (pid {1})  scanning loaded modules" -f $pn, $procId) 'DarkCyan'
        $_.Modules | ForEach-Object {
            if ($_.ModuleName -match $camDll) { Emit 'MODULE' ("{0} -> {1}  camera/audio stack" -f $pn, $_.ModuleName) 'Magenta' }
            else { Emit 'MODULE' ("{0} -> {1}" -f $pn, $_.ModuleName) 'DarkGray' }
        }
    }
    Get-CimInstance Win32_Service | ForEach-Object { Emit 'SERVICE' ("{0,-32} {1,-8} {2}" -f $_.Name, $_.State, $_.PathName) ($(if ($_.State -eq 'Running') { 'Green' } else { 'DarkGray' })) }
    Get-ScheduledTask | ForEach-Object { Emit 'TASK' ("{0}{1}  ->  {2}" -f $_.TaskPath, $_.TaskName, ($_.Actions | Select-Object -First 1).Execute) 'DarkYellow' }
    foreach ($r in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run') {
        (Get-ItemProperty $r).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { Emit 'AUTORUN' ("{0}  ->  {1}" -f $_.Name, $_.Value) 'Red' }
    }
    Get-NetTCPConnection | ForEach-Object { Emit 'NET' ("{0,-12} {1}:{2} -> {3}:{4}  {5}" -f $_.State, $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, (Get-Process -Id $_.OwningProcess).ProcessName) 'DarkYellow' }
    Get-ChildItem "$env:APPDATA\AnyDesk", "$env:ProgramData\AnyDesk", "$env:APPDATA\TeamViewer", "$env:USERPROFILE\Downloads" -File | ForEach-Object { Emit 'FILE' ("{0}  {1}" -f $_.FullName, $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) 'Gray' }
    Get-WinEvent -LogName System -MaxEvents 1500 | ForEach-Object { Emit 'EVENT' ("{0}  id {1,-5} {2}" -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $_.Id, $_.ProviderName) 'DarkGray' }
}
