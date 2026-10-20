#!/usr/bin/env bash
# Coverage-preserving corpus minimisation (afl-cmin's greedy algorithm) with afl-showmap in forkserver mode.
#   scripts/cmin.sh SRC_DIR DST_DIR [JOBS]        (run from fuzz/, after `just build-afl`)
# Why not `cargo afl cmin`: its initial single-input test run has no forkserver, and a persistent-mode target
# (ziggy::fuzz!) SIGSTOPs itself after the first iteration there, so the test times out with no tuples and
# cmin aborts ("no instrumentation output detected"). The batch runs (-I filelist) use the forkserver and work.
set -euo pipefail
SRC=$(realpath "$1"); DST=$(realpath -m "$2"); JOBS=${3:-8}
BIN=targets/runtime/target/afl/release/hydration-fuzz-runtime
[ -x "$BIN" ] || { echo "no AFL binary at $BIN; run: just build-afl" >&2; exit 1; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
find "$SRC" -type f | sort > "$T/all"
echo "== tracing $(wc -l < "$T/all") inputs with $JOBS afl-showmap jobs (~1 s per input per job)"
split -n "l/$JOBS" -d "$T/all" "$T/list."
mkdir -p "$T/traces"
for l in "$T"/list.*; do
	(cd targets/runtime && AFL_FORKSRV_INIT_TMOUT=60000 cargo afl showmap -m none -t 30000 -Z -I "$l" -o "$T/traces" \
		-- ./target/afl/release/hydration-fuzz-runtime > "$l.log" 2>&1) || echo "showmap job $l failed, see $l.log" &
done
wait
python3 - "$SRC" "$DST" "$T/traces" <<'PY'
import os, shutil, sys
src, dst, traces = sys.argv[1:]
best = {}  # tuple -> (size, name): smallest input that exercises it
names = os.listdir(traces)
for n in names:
    size = os.path.getsize(os.path.join(src, n))
    with open(os.path.join(traces, n)) as f:
        for t in f:
            t = t.strip()
            if t and (t not in best or size < best[t][0]):
                best[t] = (size, n)
keep = sorted({n for _, n in best.values()})
os.makedirs(dst, exist_ok=True)
for n in keep:
    shutil.copy(os.path.join(src, n), os.path.join(dst, n))
print(f"== {len(names)} traced, {len(best)} tuples -> {len(keep)} inputs kept in {dst}")
PY
