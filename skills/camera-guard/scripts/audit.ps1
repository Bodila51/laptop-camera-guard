<#
camera-guard audit.ps1 - READ-ONLY webcam/microphone access audit for Windows.
Reads the CapabilityAccessManager ConsentStore, cross-checks each app, writes
JSON to %USERPROFILE%\.camera-guard\audit.json and prints a table.
It changes nothing: no registry writes, no settings changes, no network calls,
nothing is sent anywhere. The only file written is the JSON report above.
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $env:USERPROFILE '.camera-guard')
)
$ErrorActionPreference = 'SilentlyContinue'
$notes = New-Object System.Collections.Generic.List[string]
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { $notes.Add('Not running as admin: Security log (4624 sign-ins) and some logs skipped.') }

function Convert-FileTime($v) {
    if ($null -eq $v -or [int64]$v -le 0) { return $null }
    try { return [DateTime]::FromFileTimeUtc([int64]$v).ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { return $null }
}

# ---------- 1. ConsentStore ----------
$entries = New-Object System.Collections.Generic.List[object]
foreach ($cap in 'webcam', 'microphone') {
    foreach ($hive in 'HKCU', 'HKLM') {
        $base = "${hive}:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$cap"
        if (-not (Test-Path $base)) { $notes.Add("Key missing (not proof of no use): $base"); continue }
        $keys = @(Get-Item $base) + @(Get-ChildItem $base -Recurse)
        foreach ($k in $keys) {
            $p = Get-ItemProperty -Path $k.PSPath
            if ($null -eq $p.LastUsedTimeStart -and $null -eq $p.LastUsedTimeStop -and $null -eq $p.Value) { continue }
            $name = $k.PSChildName
            if ($name -eq $cap) { continue }
            $parent = Split-Path $k.PSParentPath -Leaf
            $nonPackaged = ($k.Name -like '*\NonPackaged\*')
            $path = $null
            if ($nonPackaged) { $path = $name.Replace('#', '\') }
            $start = [int64]($p.LastUsedTimeStart); $stop = [int64]($p.LastUsedTimeStop)
            $state = 'No recorded use'
            if ($start -gt 0 -and $stop -eq 0) { $state = 'Possibly in use now - verify' }
            elseif ($start -gt 0) { $state = 'Last use recorded' }
            $entries.Add([pscustomobject]@{
                Capability = $cap; Hive = $hive; Name = $name; NonPackaged = $nonPackaged
                ExePath = $path; Permission = $p.Value
                LastStartUtc = Convert-FileTime $start; LastStopUtc = Convert-FileTime $stop
                State = $state; _start = $start
            })
        }
    }
}

# ---------- 2. Per-exe cross-checks ----------
$procs = @{}
Get-Process | ForEach-Object { try { if ($_.Path) { $procs[$_.Path.ToLower()] = $_.Id } } catch {} }
$startup = @()
$startup += Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "$($_.Name)=$($_.Value)" } }
$startup += Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "$($_.Name)=$($_.Value)" } }
$tasks = @(); try { $tasks = @(Get-ScheduledTask | ForEach-Object { $t = $_; $t.Actions | ForEach-Object { [pscustomobject]@{ Task = $t.TaskName; Exe = $_.Execute } } }) } catch {}
$svcs = @(); try { $svcs = @(Get-CimInstance Win32_Service | Select-Object Name, PathName) } catch {}
$threats = @(); try { $threats = @(Get-MpThreatDetection | Select-Object InitialDetectionTime, ThreatID, Resources) } catch { $notes.Add('Defender detection history unavailable.') }

foreach ($e in $entries) {
    $flags = New-Object System.Collections.Generic.List[string]
    $exists = $null; $sig = $null; $signer = $null; $conns = $null
    if ($e.ExePath) {
        $exists = Test-Path -LiteralPath $e.ExePath
        $lp = $e.ExePath.ToLower()
        if ($lp -match '\\appdata\\|\\temp\\|\\downloads\\|\\users\\public\\') { $flags.Add('path in user-writable location') }
        elseif ($lp -match '^c:\\(program files|windows)') { $flags.Add('path in Program Files/Windows (normal)') }
        if (-not $exists) { $flags.Add('file no longer exists') }
        else {
            $s = Get-AuthenticodeSignature -LiteralPath $e.ExePath
            $sig = [string]$s.Status
            if ($s.SignerCertificate) { $signer = ($s.SignerCertificate.Subject -split ',')[0] -replace '^CN=', '' }
            if ($sig -ne 'Valid') { $flags.Add("signature: $sig") }
        }
        $short = [IO.Path]::GetFileName($e.ExePath)
        if ($startup | Where-Object { $_ -like "*$short*" }) { $flags.Add('in Run key (autostart)') }
        if ($tasks | Where-Object { $_.Exe -like "*$short*" }) { $flags.Add('scheduled task points to it') }
        if ($svcs | Where-Object { $_.PathName -like "*$short*" }) { $flags.Add('service points to it') }
        if ($threats | Where-Object { $_.Resources -like "*$short*" }) { $flags.Add('Defender detection mentions it') }
        if ($procs.ContainsKey($lp)) {
            $procId = $procs[$lp]
            $c = @(Get-NetTCPConnection -OwningProcess $procId -State Established)
            $conns = $c.Count
            if ($c.Count -gt 0) { $flags.Add("$($c.Count) established TCP connection(s) now") }
        }
    }
    if ($e.State -like 'Possibly*') { $flags.Add('Stop=0: verify it is really running') }

    # Verdict
    $verdict = 'Clean'
    $fl = $flags -join '; '
    $unsigned = ($e.ExePath -and $exists -and $sig -ne 'Valid')
    $userDir = ($fl -match 'user-writable')
    $active = ($fl -match 'autostart|scheduled task|service points|established TCP')
    if ($fl -match 'Defender' -or $fl -match 'HashMismatch' -or ($userDir -and $unsigned -and $active)) { $verdict = 'Suspicious' }
    elseif ($unsigned -or $userDir -or ($e.State -like 'Possibly*')) { $verdict = 'Check this' }

    $e | Add-Member -NotePropertyName Exists -NotePropertyValue $exists
    $e | Add-Member -NotePropertyName Signature -NotePropertyValue $sig
    $e | Add-Member -NotePropertyName Signer -NotePropertyValue $signer
    $e | Add-Member -NotePropertyName Connections -NotePropertyValue $conns
    $e | Add-Member -NotePropertyName Flags -NotePropertyValue ($flags -join '; ')
    $e | Add-Member -NotePropertyName Verdict -NotePropertyValue $verdict
}

# ---------- 3. Remote-access tools ----------
$remote = New-Object System.Collections.Generic.List[object]
$ra = @(
    @{ N = 'AnyDesk'; D = @("$env:APPDATA\AnyDesk", "$env:ProgramData\AnyDesk"); F = 'connection_trace.txt' },
    @{ N = 'TeamViewer'; D = @("${env:ProgramFiles(x86)}\TeamViewer", "$env:ProgramFiles\TeamViewer"); F = 'Connections_incoming.txt' },
    @{ N = 'RustDesk'; D = @("$env:APPDATA\RustDesk", "$env:ProgramFiles\RustDesk", "$env:ProgramData\RustDesk"); F = '*.log' }
)
foreach ($r in $ra) {
    foreach ($d in $r.D) {
        if (Test-Path $d) {
            $log = Get-ChildItem $d -Recurse -Filter $r.F -ErrorAction SilentlyContinue | Select-Object -First 3
            $remote.Add([pscustomobject]@{
                Tool = $r.N; Dir = $d
                IncomingLogs = @($log | ForEach-Object { [pscustomobject]@{ File = $_.FullName; Modified = $_.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'); Lines = (Get-Content $_.FullName -Tail 15 -ErrorAction SilentlyContinue) } })
            })
        }
    }
}
# Other common remote tools by process/installed name (presence only)
foreach ($n in 'AnyDesk', 'TeamViewer', 'RustDesk', 'ScreenConnect', 'LogMeIn', 'UltraVNC', 'tightvnc', 'Splashtop', 'mstsc') {
    if (Get-Process -Name $n -ErrorAction SilentlyContinue 2>$null) { $remote.Add([pscustomobject]@{ Tool = $n; Dir = '(running process)'; IncomingLogs = @() }) }
}

# ---------- 4. Power/sign-in events ----------
$power = @()
try {
    $power = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1, 12, 13, 42, 107, 6005, 6006 ; StartTime = (Get-Date).AddDays(-14) } -MaxEvents 60 -ErrorAction Stop |
        ForEach-Object { [pscustomobject]@{ TimeUtc = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); Id = $_.Id; Source = $_.ProviderName } })
} catch { $notes.Add('System power events unavailable.') }
$logons = @()
if ($isAdmin) {
    try {
        $logons = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 50 -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ TimeUtc = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } })
    } catch { $notes.Add('Security log 4624 not readable.') }
}

# ---------- 5. Chrome site permissions ----------
$chrome = New-Object System.Collections.Generic.List[object]
$cd = "$env:LOCALAPPDATA\Google\Chrome\User Data"
if (Test-Path $cd) {
    foreach ($pf in (Get-ChildItem $cd -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
        $f = Join-Path $pf.FullName 'Preferences'
        if (-not (Test-Path $f)) { continue }
        try {
            $j = Get-Content $f -Raw | ConvertFrom-Json
            $ex = $j.profile.content_settings.exceptions
            foreach ($kind in 'media_stream_camera', 'media_stream_mic') {
                if ($ex.$kind) {
                    foreach ($site in $ex.$kind.PSObject.Properties) {
                        $chrome.Add([pscustomobject]@{ Profile = $pf.Name; Kind = $kind; Site = $site.Name; Setting = $site.Value.setting })
                    }
                }
            }
        } catch { $notes.Add("Chrome prefs unreadable: $($pf.Name)") }
    }
}

# ---------- Output ----------
$entOut = @($entries.ToArray() | Select-Object Capability, Hive, Name, NonPackaged, ExePath, Permission, LastStartUtc, LastStopUtc, State, Exists, Signature, Signer, Connections, Flags, Verdict)
$result = [pscustomobject]@{
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    IsAdmin = $isAdmin
    Entries = $entOut
    RemoteAccess = $remote.ToArray()
    PowerEvents = $power
    Logons4624 = $logons
    ChromeMediaPermissions = $chrome.ToArray()
    Defender = @($threats)
    Notes = $notes.ToArray()
    Disclaimer = 'Shows who accessed and when. Cannot prove nobody ever watched. An attacker with admin rights can wipe logs.'
}
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = Join-Path $OutDir 'audit.json'
$result | ConvertTo-Json -Depth 6 | Set-Content -Path $out -Encoding UTF8

Write-Output ''
Write-Output 'Camera/microphone access (latest first):'
$entries | Sort-Object _start -Descending | Format-Table Verdict, Capability, Name, LastStartUtc, LastStopUtc, Permission, State -AutoSize | Out-String -Width 220 | Write-Output
Write-Output "Flags per entry are in the JSON. Remote-access tools found: $($remote.Count). Chrome site rules: $($chrome.Count)."
if ($notes.Count) { Write-Output 'Notes:'; $notes | ForEach-Object { Write-Output " - $_" } }
Write-Output "Report saved: $out"
