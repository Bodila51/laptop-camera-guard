#!/bin/bash
# Filming visual for macOS: a fast, colourful waterfall of real system file paths (read-only), and every few seconds
# a blurred EXAMPLE frame drawn in the terminal. The frames are demo images, not anything found on this Mac. Ctrl+C to stop.
# Usage: bash waterfall.sh [sleep-per-line, default 0.01 = ~100 lines/s] [seconds between frames, default 5, 0 = none]
SLEEP=${1:-0.01}; EVERY=${2:-5}
BASE=https://raw.githubusercontent.com/Bodila51/laptop-camera-guard/main/skills/camera-guard/demo
DIR="${TMPDIR:-/tmp}/camera-guard-demo"; mkdir -p "$DIR"
# Terminal.app may lack 24-bit colour; iTerm2 and others set COLORTERM=truecolor.
SUF=.256.ans; [ "$COLORTERM" = truecolor ] && SUF=.ans
for n in 1 2 3 4; do [ -s "$DIR/example_0$n$SUF" ] || curl -fsSL "$BASE/example_0$n$SUF" -o "$DIR/example_0$n$SUF"; done

while :; do find /System/Library /usr/lib /Applications -type f 2>/dev/null; done |
  SLEEP=$SLEEP EVERY=$EVERY DIR=$DIR SUF=$SUF perl -MTime::HiRes=sleep,time -ne '
  BEGIN { $|=1; @c=(31..36,91..96); @t=qw(SCAN HASH REG CAM MIC NET PROC SIG); $last=time;
          for $n (1..4) { local $/; open my $f, "<", "$ENV{DIR}/example_0$n$ENV{SUF}" or next; push @art, <$f> } }
  chomp; $i++; @l=localtime;
  printf "\e[90m%02d:%02d:%02d.%03d \e[36m[%-4s] \e[%dm0x%08X  %s\e[0m\n", @l[2,1,0], (time*1000)%1000, $t[$i%8], $c[rand @c], (-s $_)||0, $_;
  sleep $ENV{SLEEP};
  if ($ENV{EVERY} > 0 && @art && time-$last >= $ENV{EVERY}) {
    $k++; print "\n";
    print $art[$k % @art]; sleep 1.5; $last=time;
  }'
