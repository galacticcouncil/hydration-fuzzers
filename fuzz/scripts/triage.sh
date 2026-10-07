#!/usr/bin/env bash
# Replay every crash file in DIR (or the newest AFL crash dir) and print one line per file:
#   <file> :: <first VIOLATION / panic line, or REPLAYS CLEAN>
# then a histogram by violation kind. Pass the same FUZZ_* env as the fuzz run to see what AFL saw.
#   scripts/triage.sh [DIR] [-a]      -a: include files already listed in triage.log (default: only new ones)
#   REPLAY_TIMEOUT=60 (seconds per input, default 300); TRIAGE_LOG=<path> (default targets/runtime/output/triage.log)
set -euo pipefail
export LLVM_PROFILE_FILE=/dev/null   # the soak binary must not drop coverage profiles
cd "$(dirname "$0")/.."
DIR=${1:-$(ls -td targets/runtime/output/hydration-fuzz-runtime/crashes/*/ | head -1)}
ALL=${2:-}
LOG=${TRIAGE_LOG:-targets/runtime/output/triage.log}
mkdir -p "$(dirname "$LOG")"; touch "$LOG"
echo "dir: $DIR ($(ls "$DIR" | wc -l) files)"
for f in "$DIR"/*; do
	[ -f "$f" ] || continue
	key="$DIR/$(basename "$f")"
	[ -z "$ALL" ] && grep -qF "$key ::" "$LOG" && continue
	v=$(timeout "${REPLAY_TIMEOUT:-300}" ./target/release/hydration-fuzz-soak replay "$f" 2>&1 \
		| grep -E 'VIOLATION|panicked at|: ok$' | grep -v 'action.rs:2' | head -1 \
		| sed -E 's/^.*: ok$/REPLAYS CLEAN/; s/.*known issue, action rolled back: /KNOWN /' | cut -c1-220 || true)
	echo "$key :: ${v:-NO OUTPUT}" | tee -a "$LOG"
done
echo
echo "by kind (this dir):"
grep -F "$DIR/" "$LOG" | sed 's/.* :: //' \
	| sed -E 's/^(KNOWN )?VIOLATION\[([a-z_]+)\].*/\1\2/; s/^thread .main. panicked at ([^:]+:[0-9]+).*/panic \1/' \
	| sort | uniq -c | sort -rn
