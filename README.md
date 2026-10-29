# camera-guard

A [Claude Code](https://claude.com/claude-code) skill that audits which apps accessed your laptop webcam and microphone, cross-checks them, and helps you lock the devices down.

- Windows: reads the CapabilityAccessManager ConsentStore (webcam + microphone, HKCU and HKLM, including non-packaged apps), then checks file path, signature, autostart entries, remote-access tool logs, Defender history, live network connections and Chrome site permissions.
- macOS: guided checks (privacy indicator, TCC log, LaunchAgents) and lock-down advice.
- Read-only until you approve each change. Nothing is uploaded anywhere.

## Install

Copy the skill folder into your Claude Code skills directory.

Windows (PowerShell):

```powershell
Copy-Item -Recurse skills\camera-guard $env:USERPROFILE\.claude\skills\
```

macOS:

```sh
mkdir -p ~/.claude/skills && cp -R skills/camera-guard ~/.claude/skills/
```

Then run `/camera-guard` in Claude Code. The skill is manual-only (`disable-model-invocation: true`).

You can also run the Windows collector alone:

```powershell
powershell -ExecutionPolicy Bypass -File skills\camera-guard\scripts\audit.ps1
```

It writes `%USERPROFILE%\.camera-guard\audit.json` and prints a table. It changes no settings and no registry values. Some checks (Security log sign-ins) need admin and are skipped with a note otherwise.

## Honest limits

- It shows who accessed the camera/mic and when, according to Windows and macOS records. It cannot prove nobody ever watched.
- An attacker with admin rights can wipe or forge logs.
- A missing registry key does not mean "never used".
- Apps with their own drivers can bypass Windows privacy toggles.
- Verdicts (Clean / Check this / Suspicious) are heuristics, not malware detection. A signed app can still be abused; an unsigned one is often harmless.
- macOS keeps permissions, not a usage history; the TCC log is only as long as the unified log retains.

## Roadmap

A "camera alarm" (scheduled alert when a non-allow-listed app starts using the camera/mic) is planned, not implemented.

## License

MIT
