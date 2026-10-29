#!/bin/bash
# Filming visual for macOS: a fast, colourful, READ-ONLY stream of the real checks a camera/mic audit does on this Mac
# (devices, privacy database, camera/mic/TCC log, launch items, processes, open files, connections, power log),
# with a blurred frame from ~/Desktop/camera-photos drawn every few seconds (your own demo photos, not findings).
# Usage: bash waterfall.sh [sleep-per-line, default 0.01 = ~100 lines/s] [seconds between frames, default 5, 0 = none] [tags]
# NOCHECK=1 replays the stream another window is already writing instead of running the checks again.
SLEEP=${1:-0.01}; EVERY=${2:-5}; ONLY=${3:-.*}  # ONLY: regex of tags to show (used by windows.sh)
DIR="${TMPDIR:-/tmp}/camera-guard-frames"; mkdir -p "$DIR"
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
[ -z "$NOCHECK" ] && { rm -f "$DIR"/frame_*.ans; make_frames "$DIR" & }

checks() { # prints TAG|text lines; fast checks first so lines start instantly
  echo "START|camera / microphone access audit - read only"
  ps -axo pid,user,comm 2>/dev/null | sed '1d; s/^/PROC|/'
  launchctl list 2>/dev/null | sed '1d; s/^/LAUNCHD|/'
  for d in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
    ls -l "$d" 2>/dev/null | sed "1d; s#^#LAUNCH|$d  #"
  done
  ls -la /Applications 2>/dev/null | sed '1,3d; s/^/APP|/'
  echo "TCC|open ~/Library/Application Support/com.apple.TCC/TCC.db"
  sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db"     "select service, client, auth_value, datetime(last_modified,'unixepoch') from access" 2>/dev/null | sed 's/^/TCC|/'
  lsof -nP -i 2>/dev/null | sed '1d' | awk '{print "NET|"$1" pid "$2"  "$8"  "$9" "$10}'
  ls -la "$HOME/Downloads" 2>/dev/null | sed '1,3d; s/^/FILE|/'
  system_profiler SPCameraDataType SPAudioDataType 2>/dev/null | sed -E '/^[[:space:]]*$/d; s/^ +//; s/^/DEVICE|/'
  log show --last 6h --style compact --predicate 'subsystem == "com.apple.TCC" OR process == "tccd" OR eventMessage CONTAINS[c] "camera" OR eventMessage CONTAINS[c] "microphone"' 2>/dev/null |
    sed '1d' | head -n 3000 | cut -c1-180 | sed 's/^/LOG|/'
  pmset -g log 2>/dev/null | grep -E ' (Sleep|Wake|DarkWake) ' | tail -n 300 | cut -c1-140 | sed 's/^/POWER|/'
}

# Checks run in the background into a file; the screen replays that file in a loop, so it never pauses.
OUT="$DIR/stream.txt"
if [ -z "$NOCHECK" ]; then
  : > "$OUT"; checks >> "$OUT" 2>/dev/null &
  CHK=$!; trap 'kill $CHK 2>/dev/null' EXIT
fi
n=0; while [ "$(wc -l < "$OUT")" -lt 20 ] && [ $n -lt 25 ]; do sleep 0.02; n=$((n+1)); done

SLEEP=$SLEEP EVERY=$EVERY DIR=$DIR OUT=$OUT ONLY=$ONLY perl -MTime::HiRes=sleep,time -e '
  $|=1; $last=time; $h=$ENV{HOME};
  %col=(START=>93,DEVICE=>97,TCC=>33,LAUNCH=>31,LAUNCHD=>36,PROC=>32,MODULE=>35,NET=>33,APP=>90,FILE=>37,LOG=>36,POWER=>90);
  sub load { @art=(); for $p (sort glob("$ENV{DIR}/frame_*.ans")) { local $/; open my $f, "<", $p or next; push @art, <$f> } }
  open my $in, "<", $ENV{OUT} or die; my @buf; my $i=0;
  while (1) {
    while (defined(my $l = <$in>)) { chomp $l; push @buf, $l if length $l && (split /\|/, $l)[0] =~ /^(?:$ENV{ONLY})$/ }
    seek $in, 0, 1;  # clear EOF so lines appended later are read
    if (!@buf) { sleep 0.05; next }
    $_ = $buf[$i++ % @buf];
    ($t,$x)=split /\|/, $_, 2; $x =~ s/\Q$h\E/~/g; $x =~ s/\b(\d{1,3}\.){3}\d{1,3}\b/<ip>/g;
    $c=$col{$t}||37; $c=93 if $x =~ /camera|microphone|kTCCServiceCamera|kTCCServiceMicrophone/i;
    @l=localtime; printf "\e[90m%02d:%02d:%02d.%03d \e[36m[%-7s] \e[%dm%s\e[0m\n", @l[2,1,0], (time*1000)%1000, $t, $c, $x;
    sleep $ENV{SLEEP};
    load() if time-$last >= $ENV{EVERY};
    if ($ENV{EVERY} > 0 && @art && time-$last >= $ENV{EVERY}) { $k++; print "\n", $art[$k % @art]; $last=time }
  }'
