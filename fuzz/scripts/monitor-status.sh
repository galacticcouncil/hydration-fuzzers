#!/usr/bin/env bash
# One-screen status of the running fuzzer for the monitor notification (Discord markdown): AFL
# progress, what the corpus is made of (action mix), and the latest coverage figures if a report
# exists. Prints to stdout; pipe into notify-discord.sh to send. Read-only, a few seconds.
set -euo pipefail
export LLVM_PROFILE_FILE=/dev/null   # the soak binary must not drop coverage profiles
cd "$(dirname "$0")/.."
OUT=targets/runtime/output/hydration-fuzz-runtime
SOAK=./target/release/hydration-fuzz-soak
now=$(date -u '+%Y-%m-%d %H:%M UTC')

# --- AFL instances
n=0; execs=0; rate=0; corpus=""; stab=""; run=0; crashes=0; hangs=0
for s in "$OUT"/afl/*/fuzzer_stats; do
	[ -f "$s" ] || continue
	n=$((n + 1))
	v() { awk -v k="$1" '$1==k {print $3}' "$s"; }
	execs=$((execs + $(v execs_done)))
	rate=$(python3 -c "print(round($rate + $(v execs_per_sec), 2))")
	corpus="$corpus$(v corpus_count) / "
	stab="$stab$(v stability | tr -d '%') "
	r=$(v run_time); [ "$r" -gt "$run" ] && run=$r
	hangs=$((hangs + $(v saved_hangs)))
done
alive=$(pgrep -fc "afl-fuzz -c0" || true)
newest=$(ls -d "$OUT"/crashes/*/ 2>/dev/null | sort | tail -1)
[ -n "$newest" ] && crashes=$(find "$newest" -type f ! -name 'README*' | wc -l)
age=$(( ($(date +%s) - $(stat -c %Y "$OUT"/afl/mainaflfuzzer/fuzzer_stats 2>/dev/null || date +%s)) / 60 ))
k() { python3 -c "n=$1; print(f'{n/1000:.1f}k' if n >= 1000 else n)"; }

echo "## hydration-fuzz status · $now"
if [ "$n" -eq 0 ]; then
	echo "**Runtime fuzzer** · no fuzzer_stats found (not started here?)"
else
	health="🟢"; [ "$alive" -lt "$n" ] && health="🔴"; [ "$age" -gt 20 ] && health="🟡"
	printf "**Runtime fuzzer** %s %d/%d alive · up %dh%02dm · %s execs · %s execs/s · stability %s · crashes %d · hangs %d\n" \
		"$health" "$alive" "$n" $((run / 3600)) $(((run % 3600) / 60)) "$(k "$execs")" "$rate" \
		"$(echo "$stab" | awk '{s=0; for(i=1;i<=NF;i++) s+=$i; printf "%.1f%%", s/NF}')" "$crashes" "$hangs"
	echo "corpus per instance: ${corpus% / } · stats updated ${age} min ago"
fi

# --- corpus composition (decode only), as a two-column monospace table
if [ -x "$SOAK" ] && [ -d "$OUT/corpus" ]; then
	"$SOAK" stats "$OUT/corpus" 2>/dev/null | awk '
		NR==1 {n=$1; per=$(NF-2)}
		/^  flag actor/ {split($NF,a,"/"); fa=int(100*a[1]/a[2])}
		/^  flag circuit/ {split($NF,a,"/"); fc=int(100*a[1]/a[2])}
		/^  flag solve/ {split($NF,a,"/"); fs=int(100*a[1]/a[2])}
		/^ *[0-9]+ +[0-9.]+% +[A-Za-z]/ {k++; if (k<=14) {name[k]=$3; pct[k]=$2}}
		END {
			printf "**Corpus mix** · %d inputs · %s actions each · single-actor %d%% · circuit-breaker off %d%% · solve each block %d%%\n", n, per, fa, fc, fs
			print "```"
			for (i=1; i<=k && i<=14; i+=2) printf "%-16s %5s   %-16s %5s\n", name[i], pct[i], (i+1<=k?name[i+1]:""), (i+1<=k?pct[i+1]:"")
			print "```"
		}'
fi

# --- coverage, if a report exists
C=targets/runtime/output/coverage
if [ -f "$C/report.txt" ] && [ -f "$C/by_component.txt" ]; then
	when=$(date -u -r "$C/report.txt" '+%Y-%m-%d %H:%M')
	awk -v when="$when" '/^TOTAL/ {printf "**Coverage** (%s UTC) · lines %s · regions %s · functions %s\n", when, $10, $4, $7}' "$C/report.txt"
	echo '```'
	for c in omnipool stableswap xyk route-executor runtime/evm liquidation hsm ice intent dca; do
		awk -v k="$c" '$NF==k {printf "%-15s %6s  %s\n", k, $1, $2; exit}' "$C/by_component.txt"
	done
	echo '```'
fi
