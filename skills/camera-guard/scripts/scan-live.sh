#!/bin/bash
# camera-guard live scan for macOS: a fast, colourful, READ-ONLY walk through the places macOS keeps traces of
# camera/microphone access, remote access and autostarts. Every printed line is a real check on this Mac.
# Changes nothing. Usage: bash scan-live.sh [--delay 0.01] [--demo]
# --demo: after the real scan, show clearly-labelled EXAMPLE images (from ~/.camera-guard/demo/, downloaded from
# the repo if empty) to illustrate what a webcam-capture finding would look like. They are not findings from this Mac.

DELAY=0.01; DEMO=0
while [ $# -gt 0 ]; do
  case "$1" in --delay) DELAY="$2"; shift ;; --demo) DEMO=1 ;; esac; shift
done
REPO=https://raw.githubusercontent.com/Bodila51/laptop-camera-guard/main/skills/camera-guard/demo

C0=$'\e[0m'; GRAY=$'\e[90m'; CYAN=$'\e[36m'; RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'
MAG=$'\e[35m'; WHITE=$'\e[97m'; DCYAN=$'\e[2;36m'; DYEL=$'\e[2;33m'
mask() { sed -E "s#$HOME#~#g; s/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/<ip>/g; s/\b[0-9]{9,10}\b/<id>/g"; }
line() { # tag colour text
  printf '%s%s %s[%-8s] %s%s%s\n' "$GRAY" "$(date +%H:%M:%S)" "$CYAN" "$1" "$2" "$(printf '%s' "$3" | mask)" "$C0"
  sleep "$DELAY"
}
head_() { echo; echo "${MAG}>>> $1${C0}"; sleep 0.15; }
CAM=0; MIC=0; REMOTE=0; UNSIGNED=0; SUSP=0

clear
echo "${YELLOW}camera-guard  ·  who has been using your camera and microphone${C0}"
echo "${GRAY}read-only scan · nothing is changed${C0}"

head_ 'Camera & microphone devices'
system_profiler SPCameraDataType SPAudioDataType 2>/dev/null | grep -E '^\s{4}[^ ].*:$' | sed 's/:$//; s/^ *//' |
  while IFS= read -r d; do line DEVICE "$WHITE" "$d"; done

head_ 'Privacy database (TCC): apps allowed camera / microphone'
TCC="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
rows=$(sqlite3 "$TCC" "select service, client, auth_value, last_modified from access where service in ('kTCCServiceCamera','kTCCServiceMicrophone')" 2>/dev/null)
if [ -z "$rows" ]; then
  line TCC "$GRAY" "TCC.db not readable (Terminal needs Full Disk Access to read it) - skipped"
else
  while IFS='|' read -r svc app auth ts; do
    when=$(date -r "$ts" '+%Y-%m-%d %H:%M' 2>/dev/null)
    state=$([ "$auth" = 2 ] && echo allowed || echo denied)
    if [ "$svc" = kTCCServiceCamera ]; then CAM=$((CAM+1)); col=$YELLOW; tag=WEBCAM; else MIC=$((MIC+1)); col=$GREEN; tag=MICROP; fi
    case "$app" in /tmp/*|/private/tmp/*|*/Downloads/*) SUSP=$((SUSP+1)); col=$RED ;; esac
    line "$tag" "$col" "$app  $state  (changed $when)"
  done <<< "$rows"
fi

head_ 'Unified log: camera / microphone requests (last 2h)'
log show --last 2h --style compact --predicate 'eventMessage CONTAINS "kTCCServiceCamera" OR eventMessage CONTAINS "kTCCServiceMicrophone"' 2>/dev/null |
  grep -v '^Timestamp' | tail -n 150 | cut -c1-170 | while IFS= read -r l; do
    case "$l" in *Camera*) line LOG "$YELLOW" "$l" ;; *) line LOG "$DCYAN" "$l" ;; esac
  done

head_ 'Remote-access tools'
for p in /Applications/AnyDesk.app /Applications/TeamViewer.app /Applications/RustDesk.app \
         "$HOME/Library/Application Support/AnyDesk" "$HOME/Library/Application Support/TeamViewer" "/Library/Application Support/TeamViewer"; do
  if [ -e "$p" ]; then line REMOTE "$YELLOW" "present: $p"; else line REMOTE "$GRAY" "not found: $p"; fi
done
for f in "$HOME/Library/Application Support/AnyDesk/connection_trace.txt" "/Library/Application Support/AnyDesk/connection_trace.txt"; do
  [ -f "$f" ] && while IFS= read -r l; do [ -n "$l" ] && { REMOTE=$((REMOTE+1)); line SESSION "$RED" "$l"; }; done < <(iconv -f UTF-16 -t UTF-8 "$f" 2>/dev/null || cat "$f")
done
ls "$HOME/Downloads" 2>/dev/null | grep -i -E 'anydesk|teamviewer|rustdesk' | while IFS= read -r f; do line REMOTE "$YELLOW" "downloaded: ~/Downloads/$f"; done

head_ 'Autostart (LaunchAgents, LaunchDaemons)'
for d in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
  for pl in "$d"/*.plist; do
    [ -e "$pl" ] || continue
    exe=$(/usr/libexec/PlistBuddy -c 'Print :Program' "$pl" 2>/dev/null || /usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$pl" 2>/dev/null)
    if [ -n "$exe" ] && codesign -v "$exe" 2>/dev/null; then line AUTORUN "$GREEN" "$(basename "$pl")  ->  $exe  [signed]"
    else UNSIGNED=$((UNSIGNED+1)); line AUTORUN "$RED" "$(basename "$pl")  ->  ${exe:--}  [not verified]"; fi
  done
done

head_ 'Running processes: signatures'
ps -axo comm= | grep '^/' | sort -u | head -n 120 | while IFS= read -r exe; do
  who=$(codesign -dv "$exe" 2>&1 | grep -m1 '^Authority=' | cut -d= -f2)
  if codesign -v "$exe" 2>/dev/null; then line PROC "$GREEN" "$(basename "$exe")  valid  ${who:--}"
  else line PROC "$RED" "$(basename "$exe")  not verified"; fi
done

head_ 'Live internet connections'
lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1 {print $1, $9}' | sort -u | grep -v -E '127\.0\.0\.1|\[::1\]' |
  while IFS= read -r l; do line NET "$DYEL" "$l"; done

head_ 'Sleep / wake history (when the Mac was in use)'
pmset -g log 2>/dev/null | grep -E ' (Sleep|Wake|DarkWake) ' | tail -n 40 | cut -c1-110 | while IFS= read -r l; do line POWER "$GRAY" "$l"; done

head_ 'Browser sites allowed camera / microphone'
for prefs in "$HOME/Library/Application Support/Google/Chrome/"*/Preferences "$HOME/Library/Application Support/Microsoft Edge/"*/Preferences; do
  [ -f "$prefs" ] || continue
  for k in media_stream_camera media_stream_mic; do
    plutil -extract "profile.content_settings.exceptions.$k" json -o - "$prefs" 2>/dev/null | grep -o '"[^"]*,\*"' | tr -d '"' | sed 's/,\*$//' |
      while IFS= read -r site; do line SITE "$YELLOW" "${k#media_stream_}  $site"; done
  done
done

echo
echo "${YELLOW}================ RESULT ================${C0}"
echo "${WHITE}apps allowed the camera:        $CAM${C0}"
echo "${WHITE}apps allowed the microphone:    $MIC${C0}"
[ "$REMOTE" -gt 0 ] && c=$RED || c=$GREEN; echo "${c}remote-access sessions logged:  $REMOTE${C0}"
[ "$UNSIGNED" -gt 0 ] && c=$YELLOW || c=$GREEN; echo "${c}unverified autostart items:     $UNSIGNED${C0}"
[ "$SUSP" -gt 0 ] && c=$RED || c=$GREEN; echo "${c}suspicious camera/mic entries:  $SUSP${C0}"
echo "${GRAY}Note: this shows who accessed the camera/mic and when. It cannot prove nobody ever did.${C0}"

if [ "$DEMO" = 1 ]; then
  dir="$HOME/.camera-guard/demo"; mkdir -p "$dir"
  ls "$dir"/*.jpg >/dev/null 2>&1 || for n in 1 2 3 4; do curl -fsSL "$REPO/example_0$n.jpg" -o "$dir/example_0$n.jpg"; done
  echo
  echo "${RED}EXAMPLE ONLY: what a webcam-capture finding would look like (demo images, not from this Mac)${C0}"
  for f in "$dir"/*.jpg "$dir"/*.png; do [ -e "$f" ] && { line EXAMPLE "$RED" "webcam_capture_$(basename "${f%.*}").jpg  (demo)"; sleep 0.25; }; done
  open -a Preview "$dir"/*.jpg 2>/dev/null
fi
