# camera-guard live scan: a fast, colourful, READ-ONLY walk through every place Windows keeps traces of
# camera/microphone access, remote access and autostarts. Every printed line is a real check on this machine.
# Changes nothing. Usage: powershell -ExecutionPolicy Bypass -File scan-live.ps1 [-Delay 8]
param([int]$Delay = 8, [switch]$Demo)
# -Demo: after the real scan, show clearly-labelled EXAMPLE images (from %USERPROFILE%\.camera-guard\demo\)
# to illustrate what a webcam-capture finding would look like. They are not findings from this machine.

$ErrorActionPreference = 'SilentlyContinue'
$Host.UI.RawUI.WindowTitle = 'camera-guard'
$home_ = [regex]::Escape($env:USERPROFILE)
function Mask([string]$s) { ($s -replace $home_, '~') -replace '\b\d{9,10}\b', '<id>' -replace '\b(\d{1,3}\.){3}\d{1,3}\b', '<ip>' }
function Line($tag, $text, $color = 'Gray') {
    $t = (Get-Date).ToString('HH:mm:ss.fff')
    Write-Host "$t " -NoNewline -ForegroundColor DarkGray
    Write-Host ("[{0,-8}] " -f $tag) -NoNewline -ForegroundColor Cyan
    Write-Host (Mask $text) -ForegroundColor $color
    if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
}
function Head($text) { Write-Host ""; Write-Host ">>> $text" -ForegroundColor Magenta; Start-Sleep -Milliseconds 150 }
function FT($v) { if ($v -and [int64]$v -gt 0) { [DateTime]::FromFileTime([int64]$v).ToString('yyyy-MM-dd HH:mm') } else { '-' } }

$found = [ordered]@{ camera = 0; mic = 0; suspicious = 0; remote = 0; unsigned = 0 }
Clear-Host
Write-Host "camera-guard  ·  who has been using your camera and microphone" -ForegroundColor Yellow
Write-Host "read-only scan · nothing is changed" -ForegroundColor DarkGray

Head 'Camera & microphone devices'
Get-PnpDevice -Class Camera, Image, AudioEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
    Line 'DEVICE' ("{0,-8} {1} [{2}]" -f $_.Class, $_.FriendlyName, $_.Status) 'White'
}

Head 'Windows access log (CapabilityAccessManager)'
$base = 'SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'
foreach ($hive in 'HKCU', 'HKLM') {
    foreach ($cap in 'webcam', 'microphone') {
        $root = "${hive}:\$base\$cap"
        if (-not (Test-Path $root)) { continue }
        Line 'REG' "$hive\...\ConsentStore\$cap  ->  $((Get-ItemProperty $root).Value)" 'DarkCyan'
        Get-ChildItem $root -Recurse | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            if ($null -eq $p.LastUsedTimeStart) { return }
            $name = $_.PSChildName -replace '#', '\'
            $start = FT $p.LastUsedTimeStart; $stop = FT $p.LastUsedTimeStop
            # Suspicious = ran from Temp/Downloads. A removed file (old app version after an update) is shown grey.
            $odd = $name -match '\\(Temp|Downloads)\\'
            $gone = $name -match '^[A-Z]:\\' -and -not (Test-Path $name)
            if ($cap -eq 'webcam') { $found.camera++ } else { $found.mic++ }
            if ($odd) { $found.suspicious++ }
            $col = if ($odd) { 'Red' } elseif ($gone) { 'DarkGray' } elseif ($cap -eq 'webcam') { 'Yellow' } else { 'Green' }
            if ($gone) { $name += '  (file removed)' }
            $live = if ($p.LastUsedTimeStop -eq 0 -and $p.LastUsedTimeStart -gt 0) { '  (no stop time)' } else { '' }
            Line ($cap.ToUpper().Substring(0, [Math]::Min(6, $cap.Length))) ("{0}  last {1} -> {2}{3}" -f $name, $start, $stop, $live) $col
        }
    }
}

Head 'Remote-access tools'
$ra = @("$env:APPDATA\AnyDesk", "$env:ProgramData\AnyDesk", "$env:APPDATA\TeamViewer", "${env:ProgramFiles}\TeamViewer", "${env:ProgramFiles(x86)}\TeamViewer", "$env:APPDATA\RustDesk")
foreach ($p in $ra) {
    if (-not (Test-Path $p)) { Line 'REMOTE' "not found: $p" 'DarkGray'; continue }
    Line 'REMOTE' "present: $p" 'Yellow'
    Get-ChildItem $p -Recurse -Include connection_trace.txt, Connections_incoming.txt | ForEach-Object {
        Get-Content $_.FullName -Encoding Unicode | Where-Object { $_ -match '\S' } | ForEach-Object {
            $found.remote++; Line 'SESSION' ($_ -replace '\s+', ' ') 'Red'
        }
    }
}
Get-ChildItem "$env:USERPROFILE\Downloads" -Filter '*anydesk*.exe' | ForEach-Object { Line 'REMOTE' "downloaded: $($_.FullName)  ($($_.LastWriteTime.ToString('yyyy-MM-dd')))" 'Yellow' }

Head 'Autostart (Run keys, Startup folders)'
foreach ($r in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
    if (-not (Test-Path $r)) { continue }
    (Get-ItemProperty $r).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
        $exe = ($_.Value -replace '^"([^"]+)".*', '$1') -replace '\s+-.*$', ''
        $sig = (Get-AuthenticodeSignature $exe).Status
        if ($sig -ne 'Valid') { $found.unsigned++ }
        Line 'AUTORUN' ("{0}  ->  {1}  [{2}]" -f $_.Name, $exe, $sig) ($(if ($sig -eq 'Valid') { 'Green' } else { 'Red' }))
    }
}

Head 'Running processes: signatures'
Get-Process | Where-Object { $_.Path } | Sort-Object ProcessName -Unique | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.Path
    $who = if ($sig.SignerCertificate) { ($sig.SignerCertificate.Subject -replace '^CN="?([^",]+).*', '$1') } else { '-' }
    $col = if ($sig.Status -eq 'Valid') { 'DarkGreen' } else { $found.unsigned++; 'Red' }
    Line 'PROC' ("{0,-28} {1,-10} {2}" -f $_.ProcessName, $sig.Status, $who) $col
}

Head 'Live internet connections'
Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' } | ForEach-Object {
    $n = (Get-Process -Id $_.OwningProcess).ProcessName
    Line 'NET' ("{0,-24} -> {1}:{2}" -f $n, $_.RemoteAddress, $_.RemotePort) 'DarkYellow'
}

Head 'Sleep / wake history (when the PC was in use)'
Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1, 42, 107 } -MaxEvents 40 | ForEach-Object {
    $what = switch ($_.Id) { 42 { 'sleep' } 1 { 'wake' } 107 { 'resume' } }
    Line 'POWER' ("{0}  {1}" -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $what) 'DarkGray'
}

Head 'Browser sites allowed camera / microphone'
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Preferences", "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Preferences" | ForEach-Object {
    try { $j = Get-Content $_.FullName -Raw | ConvertFrom-Json } catch { return }
    foreach ($k in 'media_stream_camera', 'media_stream_mic') {
        $ex = $j.profile.content_settings.exceptions.$k
        if ($ex) { $ex.PSObject.Properties | ForEach-Object { Line 'SITE' ("{0,-6} {1}  setting={2}" -f ($k -replace 'media_stream_', ''), ($_.Name -replace ',\*$', ''), $_.Value.setting) 'Yellow' } }
    }
}

Head 'Windows Defender history'
$d = Get-MpThreatDetection
Line 'DEFENDER' ("detections on record: {0}" -f @($d).Count) ($(if (@($d).Count) { 'Red' } else { 'Green' }))

Write-Host ""
Write-Host "================ RESULT ================" -ForegroundColor Yellow
Write-Host ("apps that used the camera:      {0}" -f $found.camera) -ForegroundColor White
Write-Host ("apps that used the microphone:  {0}" -f $found.mic) -ForegroundColor White
Write-Host ("remote-access sessions logged:  {0}" -f $found.remote) -ForegroundColor ($(if ($found.remote) { 'Red' } else { 'Green' }))
Write-Host ("unsigned programs running/auto: {0}" -f $found.unsigned) -ForegroundColor ($(if ($found.unsigned) { 'Yellow' } else { 'Green' }))
Write-Host ("suspicious camera/mic entries:  {0}" -f $found.suspicious) -ForegroundColor ($(if ($found.suspicious) { 'Red' } else { 'Green' }))
Write-Host "Note: this shows who accessed the camera/mic and when. It cannot prove nobody ever did." -ForegroundColor DarkGray

if ($Demo) {
    $dir = Join-Path $env:USERPROFILE '.camera-guard\demo'
    $imgs = Get-ChildItem $dir -Include *.jpg, *.jpeg, *.png -Recurse
    Write-Host ""
    Write-Host "EXAMPLE ONLY: what a webcam-capture finding would look like (demo images, not from this PC)" -ForegroundColor Red
    foreach ($i in $imgs) { Line 'EXAMPLE' ("webcam_capture_{0}.jpg  (demo)" -f $i.BaseName) 'Red'; Start-Sleep -Milliseconds 250 }
    if ($imgs) {
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing
        $f = New-Object Windows.Forms.Form
        $f.Text = 'camera-guard · EXAMPLE'; $f.BackColor = 'Black'; $f.WindowState = 'Maximized'; $f.FormBorderStyle = 'None'; $f.KeyPreview = $true
        $f.Add_KeyDown({ $f.Close() }); $f.Add_Click({ $f.Close() })
        $flow = New-Object Windows.Forms.FlowLayoutPanel; $flow.Dock = 'Fill'; $flow.BackColor = 'Black'
        foreach ($i in $imgs) {
            $pb = New-Object Windows.Forms.PictureBox
            $pb.Image = [Drawing.Image]::FromFile($i.FullName); $pb.SizeMode = 'Zoom'; $pb.Width = 600; $pb.Height = 340; $pb.Margin = 12
            $pb.Add_Click({ $f.Close() })
            $flow.Controls.Add($pb)
        }
        $lbl = New-Object Windows.Forms.Label
        $lbl.Text = 'EXAMPLE · demo images · not from this computer'; $lbl.ForeColor = 'Red'; $lbl.BackColor = 'Black'
        $lbl.Font = New-Object Drawing.Font('Segoe UI', 18, [Drawing.FontStyle]::Bold); $lbl.Dock = 'Bottom'; $lbl.Height = 50; $lbl.TextAlign = 'MiddleCenter'
        $f.Controls.Add($flow); $f.Controls.Add($lbl)
        [void]$f.ShowDialog()
    }
}
