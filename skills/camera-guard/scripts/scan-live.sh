#!/bin/bash
# camera-guard live scan for macOS: a fast, colourful, READ-ONLY walk through the places macOS keeps traces of
# camera/microphone access, remote access and autostarts. Every printed line is a real check on this Mac.
# Changes nothing. Usage: bash scan-live.sh [--delay 0.01] [--demo]
# --demo: draw your own photos from ~/Desktop/camera-photos between sections (demo frames, not findings from this Mac).

DELAY=0.01; DEMO=0
while [ $# -gt 0 ]; do
  case "$1" in --delay) DELAY="$2"; shift ;; --demo) DEMO=1 ;; esac; shift
done

C0=$'\e[0m'; GRAY=$'\e[90m'; CYAN=$'\e[36m'; RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'
MAG=$'\e[35m'; WHITE=$'\e[97m'; DCYAN=$'\e[2;36m'; DYEL=$'\e[2;33m'
mask() { sed -E "s#$HOME#~#g; s/([0-9]{1,3}\.){3}[0-9]{1,3}/<ip>/g; s/[0-9]{9,10}/<id>/g"; }
line() { # tag colour text
  printf '%s%s %s[%-8s] %s%s%s\n' "$GRAY" "$(date +%H:%M:%S)" "$CYAN" "$1" "$2" "$(printf '%s' "$3" | mask)" "$C0"
  sleep "$DELAY"
}
# Blurred frames come from your own photos in ~/Desktop/camera-photos (jpg/png/heic); nothing is downloaded.
# Each photo is shrunk with sips and turned into coloured half-blocks by perl (256 colours unless the terminal has truecolor).
make_frames() { # out-dir
  local i=0 f
  for f in "$HOME/Desktop/camera-photos"/*; do
    case "$f" in *.jpg|*.JPG|*.jpeg|*.JPEG|*.png|*.PNG|*.heic|*.HEIC) ;; *) continue ;; esac
    i=$((i+1)); sips -s format bmp -z 62 110 "$f" --out "$1/f$i.bmp" >/dev/null 2>&1 || continue
    TC=$([ "$COLORTERM" = truecolor ] && echo 1) perl -e 'local $/; open F, "<", $ARGV[0] or exit; binmode F; $d=<F>;
      ($off)=unpack("V",substr($d,10,4)); ($w,$h,$bpp)=unpack("l<l<x2v",substr($d,18,12)); $bp=$bpp/8; $row=int(($w*$bp+3)/4)*4; $td=$h<0; $h=abs $h;
      sub L { my $v=$_[0]/255; $v=($v**0.75)*255*1.35; $v>255?255:int $v }
      sub px { my($x,$y)=@_; $y=$td?$y:$h-1-$y; my $o=$off+$y*$row+$x*$bp; my($b,$g,$r)=map { L($_) } unpack("CCC",substr($d,$o,3));
        $ENV{TC} ? "2;$r;$g;$b" : "5;".(16+36*int($r/255*5+.5)+6*int($g/255*5+.5)+int($b/255*5+.5)) }
      binmode STDOUT, ":utf8"; for($y=0;$y<$h-1;$y+=2){ for $x (0..$w-1){ printf "\e[38;%sm\e[48;%sm\x{2580}", px($x,$y), px($x,$y+1) } print "\e[0m\n" }' "$1/f$i.bmp" > "$1/frame_$i.ans.part" &&
      mv "$1/frame_$i.ans.part" "$1/frame_$i.ans"
    rm -f "$1/f$i.bmp"
  done
}
SEC=0; ART=()
if [ "$DEMO" = 1 ]; then
  AD="${TMPDIR:-/tmp}/camera-guard-frames-scan"; mkdir -p "$AD"; rm -f "$AD"/frame_*.ans; make_frames "$AD"
  for f in "$AD"/frame_*.ans; do [ -e "$f" ] && ART+=("$f"); done
fi
# With --demo, a blurred example frame is drawn in the terminal before every second section.
head_() {
  SEC=$((SEC+1))
  if [ ${#ART[@]} -gt 0 ] && [ $((SEC % 2)) = 0 ]; then echo; cat "${ART[$(( (SEC/2) % ${#ART[@]} ))]}"; sleep 1.5; fi
  echo; echo "${MAG}>>> $1${C0}"; sleep 0.15
}
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

head_ 'Webcam-sized images in hidden / temp folders (shown here only, never sent anywhere)'
# Draws an image in the terminal with coloured half-blocks (sips converts it to a small BMP, perl prints it).
show_image() {
  local bmp="${TMPDIR:-/tmp}/cg_preview.bmp"
  sips -s format bmp -z 62 110 "$1" --out "$bmp" >/dev/null 2>&1 || return
  perl -e 'local $/; open F, "<", $ARGV[0] or exit; binmode F; $d=<F>; ($off)=unpack("V",substr($d,10,4)); ($w,$h,$bpp)=unpack("l<l<x2v",substr($d,18,12));
    $bp=$bpp/8; $row=int(($w*$bp+3)/4)*4; $td=$h<0; $h=abs $h;
    sub px { my($x,$y)=@_; $y=$td?$y:$h-1-$y; my $o=$off+$y*$row+$x*$bp; my($b,$g,$r)=unpack("CCC",substr($d,$o,3)); "$r;$g;$b" }
    binmode STDOUT, ":utf8"; for($y=0;$y<$h-1;$y+=2){ for $x (0..$w-1){ printf "\e[38;2;%sm\e[48;2;%sm\x{2580}", px($x,$y), px($x,$y+1) } print "\e[0m\n" }' "$bmp"
  rm -f "$bmp"
}
IMG=0; SHOWN=0
while IFS= read -r f; do
  case "$f" in *.avi|*.mp4|*.mov|*.wav|*.m4a|*.webm) line MEDIA "$YELLOW" "$f  $(stat -f '%z bytes  %Sm' -t '%Y-%m-%d %H:%M' "$f")"; continue ;; esac
  wh=$(sips -g pixelWidth -g pixelHeight "$f" 2>/dev/null | awk '/pixelWidth/{w=$2}/pixelHeight/{h=$2}END{print w"x"h}')
  case " 640x480 320x240 800x600 1280x720 1280x960 1920x1080 1280x800 1600x1200 " in
    *" $wh "*) IMG=$((IMG+1)); line IMAGE "$RED" "$f  $wh  webcam-sized image in a hidden folder - check it"
               [ $SHOWN -lt 8 ] && { show_image "$f"; SHOWN=$((SHOWN+1)); } ;;
    *) line IMAGE "$GRAY" "$f  $wh  (not a webcam size)" ;;
  esac
done < <(find "${TMPDIR:-/tmp}" /tmp /Users/Shared "$HOME/Library/Application Support" "$HOME/.local" "$HOME/.config" -maxdepth 5 \
          \( -name Caches -o -name 'Code Cache' -o -name GPUCache -o -name Google -o -name Firefox -o -name 'camera-guard*' \) -prune -o \
          -type f -mtime -60 \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.bmp' -o -iname '*.avi' -o -iname '*.mp4' -o -iname '*.mov' -o -iname '*.wav' -o -iname '*.m4a' -o -iname '*.webm' \) -size +15k -print 2>/dev/null)

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
[ "$IMG" -gt 0 ] && c=$RED || c=$GREEN; echo "${c}webcam-sized hidden images:     $IMG${C0}"
[ "$SUSP" -gt 0 ] && c=$RED || c=$GREEN; echo "${c}suspicious camera/mic entries:  $SUSP${C0}"
echo "${GRAY}Note: this shows who accessed the camera/mic and when. It cannot prove nobody ever did.${C0}"
