---
name: camera-guard
description: Audit which apps and sessions accessed the laptop webcam and microphone (Windows ConsentStore, macOS TCC), cross-check them for a Clean / Check this / Suspicious verdict, and help lock the devices down. Read-only until the user approves each change.
disable-model-invocation: true
---

# camera-guard

Audit who accessed the webcam and microphone, and when. Then, only if the user wants it, lock them down.

## Ground rules

- Everything is READ-ONLY until the user says yes to each specific change. Ask one change at a time.
- Never send files, hashes or paths to third parties (VirusTotal etc.) without an explicit yes.
- Never print the user's email, real name or account name in the report or chat. Replace `C:\Users\<name>\` with `%USERPROFILE%\`.
- Save the report outside the repo, in `%USERPROFILE%\.camera-guard\` (macOS: `~/.camera-guard/`).
- Be honest: this shows who accessed the devices and when. It cannot prove nobody ever watched. An attacker with admin rights can wipe logs. A missing registry key is not proof of "never used".

## Windows

### 1. Collect (no admin needed)

Run the bundled script (read-only, writes only `%USERPROFILE%\.camera-guard\audit.json`):

```
powershell -ExecutionPolicy Bypass -File <skill-dir>\scripts\audit.ps1
```

It reads, in both HKCU and HKLM, `...\CapabilityAccessManager\ConsentStore\webcam` and `\microphone` recursively, including the `NonPackaged` subkey (in exe names `#` stands for `\`).

Interpreting `LastUsedTimeStart` / `LastUsedTimeStop` (FILETIME, converted to UTC):
- Start > 0: last recorded use of the device by that app.
- Start > 0 and Stop = 0: possibly in use right now. Verify (is the process running? is the camera light on?).
- Key missing: does not mean never used.

Also ask the user to look at Settings > Privacy & security > Camera / Microphone > Recent activity (Windows 11, last 7 days) and compare.

### 2. Cross-checks (per app, used for the verdict)

The script gathers these; explain them to the user:
1. File path: Program Files / Windows is normal; AppData, Temp, Downloads, Public is a flag.
2. Authenticode signature (`Get-AuthenticodeSignature`): Valid / NotSigned / HashMismatch.
3. Does the file still exist? (Old versions of auto-updating apps legitimately disappear.)
4. Camera use vs sign-in / wake times: System log power events (1, 12, 13, 42, 107, 6005, 6006); Security 4624 sign-ins need admin. Use at times the user was not there is a flag.
5. Remote-access tools present and their incoming-connection logs: AnyDesk `connection_trace.txt` (`%APPDATA%\AnyDesk`, `%ProgramData%\AnyDesk`), TeamViewer `Connections_incoming.txt`, RustDesk logs. Ask the user whether each connection was theirs.
6. Startup items (Run keys), scheduled tasks, services pointing to the same exe.
7. Windows Defender detection history (`Get-MpThreatDetection`).
8. Current network connections of that process (`Get-NetTCPConnection` + `OwningProcess`).
9. Chrome site permissions for camera/mic (`Preferences` > `profile.content_settings.exceptions.media_stream_camera` / `media_stream_mic`). List allowed sites and ask which are unexpected.

Admin-only parts (Security log) are skipped with a note when not elevated. Offer to re-run as admin; do not elevate on your own.

### 3. Verdict

Per app and overall:
- **Clean**: known path, valid signature, use matches times the user was present, nothing else flagged.
- **Check this**: one soft flag (unsigned, user-writable path, Stop=0, unexpected hour, remote-access tool installed). Ask the user.
- **Suspicious**: Defender detection, hash mismatch, or an unsigned exe in a user-writable path that also autostarts or has live connections, or camera use while the user was away plus an unexplained remote session.

Always end the verdict with the honest note from the ground rules. Do not claim the machine is "safe".

## macOS

1. Control Center shows a privacy indicator (orange mic dot, green camera dot) when a device is live.
2. System Settings > Privacy & Security > Camera / Microphone: shows permissions per app, NOT history. Review and ask which to revoke.
3. Look for access in the TCC log: `log show --last 24h --info --debug --predicate 'process == "tccd"'` and search for `kTCCServiceCamera` / `kTCCServiceMicrophone`.
4. Review `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` for items the user does not recognize (list only; do not unload anything without a yes).
5. Recommend Objective-See OverSight (free) for future alerts. Offer the link; do not install it for them.
6. Facts to share: per Apple, the camera on modern FaceTime HD cameras cannot activate without the indicator light (the iSeeYou bypass worked only on pre-2008 iSight cameras). Apple silicon and T2 MacBooks disconnect the built-in microphone in hardware when the lid is closed.

## Lock-down options (each only after the user says yes)

1. Per-app camera/mic permissions (Windows Settings > Privacy & security; macOS Privacy & Security).
2. Browser site permissions (Chrome: Settings > Privacy and security > Site settings > Camera / Microphone; remove unexpected sites).
3. Windows Device Manager > Cameras > Disable device (reversible).
4. BIOS/UEFI camera and microphone disable. Model-specific (e.g. Lenovo, Dell); suggest also setting a BIOS password so it cannot be flipped back. Walk the user through it, do not do it for them.
5. Physical camera cover.
6. Caveat to state: Microsoft notes that apps with their own drivers can bypass the Windows privacy toggles, so the hardware options (3-5) are the stronger ones.

## Optional follow-up: camera alarm (not implemented yet)

Future monitoring idea: a scheduled task that re-reads the ConsentStore and alerts when an app not on the user's allow-list starts using the camera/mic. Describe it if asked; do not build or install it here.

## Output

Give a short table (app, device, last use UTC, verdict, why), the overall verdict, the honest note, and the path of the saved report. Then offer lock-down options one at a time.
