#!/bin/bash
# Filming visual for macOS: opens Terminal windows one after another (cascaded), each one instantly streaming a
# different part of the real, read-only camera/mic audit of this Mac. The first window also shows the demo frames.
# Usage: bash windows.sh [number of windows, default 6]
# First run: macOS asks once to let Terminal control Terminal - click OK.
N=${1:-6}
RAW=https://raw.githubusercontent.com/Bodila51/laptop-camera-guard/main/skills/camera-guard/scripts/waterfall.sh
curl -fsSL "$RAW" -o /tmp/wf.sh
# Each window shows a different set of checks (tags from waterfall.sh).
SETS=("START|PROC|DEVICE|LOG" "LAUNCHD|LAUNCH" "PROC" "APP|FILE|TCC" "NET|LAUNCHD" "LOG|POWER|DEVICE|PROC")
for ((i = 0; i < N; i++)); do
  g=${SETS[$((i % ${#SETS[@]}))]}
  if [ $i -eq 0 ]; then cmd="clear; bash /tmp/wf.sh 0.01 5 '$g'"; else cmd="clear; NOCHECK=1 bash /tmp/wf.sh 0.01 0 '$g'"; fi
  x=$((30 + i * 70)); y=$((40 + i * 45))
  osascript >/dev/null <<OSA
tell application "Terminal"
  activate
  do script "$cmd"
  set current settings of front window to settings set "Pro"
  set bounds of front window to {$x, $y, $((x + 820)), $((y + 480))}
end tell
OSA
  sleep 0.7
done
