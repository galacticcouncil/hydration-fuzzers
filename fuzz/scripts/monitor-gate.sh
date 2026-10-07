#!/usr/bin/env bash
# Cheap pre-check for the periodic monitor: exit 0 when the agent run is needed, 1 when it isn't.
# Needed = at least one crash file not yet in fuzz/monitor/state/processed.tsv (by sha1 or path),
# or the runtime fuzzer looks dead/stalled (no afl-fuzz process, or fuzzer_stats older than STALL_MIN).
# Prints the reason. Usage in the scheduler: fuzz/scripts/monitor-gate.sh && pi --print ...
set -euo pipefail
cd "$(dirname "$0")/.."
STATE=monitor/state/processed.tsv
STALL_MIN=${STALL_MIN:-20}
new=0
for d in targets/runtime/output/hydration-fuzz-runtime/crashes targets/ice-solver/output/hydration-fuzz-ice-solver/crashes; do
	[ -d "$d" ] || continue
	while IFS= read -r f; do
		rel=${f#./}
		h=$(sha1sum "$f" | cut -c1-40)
		if [ -f "$STATE" ] && grep -qF -e "$h" -e "$rel" "$STATE"; then
			continue
		fi
		new=$((new + 1))
		[ "$new" -le 5 ] && echo "new: $rel"
	done < <(find "$d" -type f ! -name 'README*' 2>/dev/null)
done
stale=0
if ! pgrep -f "afl-fuzz" >/dev/null; then
	echo "fuzzer: no afl-fuzz process"
	stale=1
else
	for s in targets/runtime/output/hydration-fuzz-runtime/afl/*/fuzzer_stats; do
		[ -f "$s" ] || continue
		age=$(( ($(date +%s) - $(awk '/^last_update/{print $3}' "$s")) / 60 ))
		if [ "$age" -gt "$STALL_MIN" ]; then
			echo "stalled: $s last updated ${age} min ago"
			stale=1
		fi
	done
fi
if [ "$new" -gt 0 ] || [ "$stale" -eq 1 ]; then
	echo "run monitor: $new new crash file(s), stale=$stale"
	exit 0
fi
echo "nothing to do: 0 new crash files, fuzzer alive"
exit 1
