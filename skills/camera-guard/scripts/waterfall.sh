#!/bin/bash
# Filming visual for macOS: a fast, colourful, READ-ONLY stream of the real checks a camera/mic audit does on this Mac
# (devices, privacy database, camera/mic/TCC log, launch items, processes, open files, connections, power log),
# with a blurred example frame drawn in the terminal every few seconds. The frames are demo images, not findings.
# Usage: bash waterfall.sh [sleep-per-line, default 0.01 = ~100 lines/s] [seconds between frames, default 5, 0 = none]
SLEEP=${1:-0.01}; EVERY=${2:-5}
BASE=https://raw.githubusercontent.com/Bodila51/laptop-camera-guard/main/skills/camera-guard/demo
DIR="${TMPDIR:-/tmp}/camera-guard-demo"; mkdir -p "$DIR"
# Terminal.app may lack 24-bit colour; iTerm2 and others set COLORTERM=truecolor.
SUF=.256.ans; [ "$COLORTERM" = truecolor ] && SUF=.ans
for n in 1 2 3 4; do [ -s "$DIR/example_0$n$SUF" ] || curl -fsSL "$BASE/example_0$n$SUF" -o "$DIR/example_0$n$SUF"; done

checks() { # prints TAG|text lines
  echo "START|camera / microphone access audit - read only"
  system_profiler SPCameraDataType SPAudioDataType 2>/dev/null | sed -E '/^\s*$/d; s/^ +//; s/^/DEVICE|/'
  echo "TCC|open ~/Library/Application Support/com.apple.TCC/TCC.db"
  sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
    "select service, client, auth_value, datetime(last_modified,'unixepoch') from access" 2>/dev/null | sed 's/^/TCC|/' ||
    echo "TCC|no Full Disk Access - privacy database skipped"
  for d in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
    ls -l "$d" 2>/dev/null | sed "1d; s#^#LAUNCH|$d  #"
  done
  launchctl list 2>/dev/null | sed '1d; s/^/LAUNCHD|/'
  ps -axo pid,user,comm 2>/dev/null | sed '1d; s/^/PROC|/'
  lsof -nP 2>/dev/null | grep -E 'AppleCamera|VDC|cmio|CoreMediaIO|CoreAudio|AVFCapture|IOAudio' | head -n 400 | awk '{print "MODULE|"$1" pid "$2" -> "$NF}'
  lsof -nP -i 2>/dev/null | sed '1d' | awk '{print "NET|"$1" pid "$2"  "$8"  "$9" "$10}'
  ls -la /Applications 2>/dev/null | sed '1,3d; s/^/APP|/'
  ls -la "$HOME/Downloads" 2>/dev/null | sed '1,3d; s/^/FILE|/'
  log show --last 6h --style compact --predicate 'subsystem == "com.apple.TCC" OR process == "tccd" OR eventMessage CONTAINS[c] "camera" OR eventMessage CONTAINS[c] "microphone"' 2>/dev/null |
    sed '1d' | head -n 3000 | cut -c1-180 | sed 's/^/LOG|/'
  pmset -g log 2>/dev/null | grep -E ' (Sleep|Wake|DarkWake) ' | tail -n 300 | cut -c1-140 | sed 's/^/POWER|/'
}

while :; do checks; done |
  SLEEP=$SLEEP EVERY=$EVERY DIR=$DIR SUF=$SUF perl -MTime::HiRes=sleep,time -ne '
  BEGIN { $|=1; $last=time; $h=$ENV{HOME};
          %col=(START=>93,DEVICE=>97,TCC=>33,LAUNCH=>31,LAUNCHD=>36,PROC=>32,MODULE=>35,NET=>33,APP=>90,FILE=>37,LOG=>36,POWER=>90);
          for $n (1..4) { local $/; open my $f, "<", "$ENV{DIR}/example_0$n$ENV{SUF}" or next; push @art, <$f> } }
  chomp; ($t,$x)=split /\|/, $_, 2; $x =~ s/\Q$h\E/~/g; $x =~ s/\b(\d{1,3}\.){3}\d{1,3}\b/<ip>/g;
  $c=$col{$t}||37; $c=93 if $x =~ /camera|microphone|kTCCServiceCamera|kTCCServiceMicrophone/i;
  @l=localtime; printf "\e[90m%02d:%02d:%02d.%03d \e[36m[%-7s] \e[%dm%s\e[0m\n", @l[2,1,0], (time*1000)%1000, $t, $c, $x;
  sleep $ENV{SLEEP};
  if ($ENV{EVERY} > 0 && @art && time-$last >= $ENV{EVERY}) { $k++; print "\n", $art[$k % @art]; sleep 1.5; $last=time }'
