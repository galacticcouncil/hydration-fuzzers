#!/usr/bin/env bash
# Coverage-preserving corpus minimisation (afl-cmin's greedy algorithm) with afl-showmap in forkserver mode.
#   scripts/cmin.sh SRC_DIR DST_DIR [JOBS]        (run from fuzz/, after `just build-afl`)
# Why not `cargo afl cmin`: its initial single-input test run has no forkserver, and a persistent-mode target
# (ziggy::fuzz!) SIGSTOPs itself after the first iteration there, so the test times out with no tuples and
# cmin aborts ("no instrumentation output detected"). The batch runs (-I filelist) use the forkserver and work.
set -euo pipefail
SRC=$(realpath "$1"); DST=$(realpath -m "$2"); JOBS=${3:-8}
# AFL_BIN=<path> overrides; otherwise the workspace target dir (fuzz/target, cargo's default for a workspace
# member), the per-crate one older cargo-afl layouts used, then anything named like it under those or CARGO_TARGET_DIR.
BIN=${AFL_BIN:-}
for c in target/afl/release/hydration-fuzz-runtime targets/runtime/target/afl/release/hydration-fuzz-runtime; do
	[ -n "$BIN" ] || [ ! -x "$c" ] || BIN=$c
done
if [ -z "$BIN" ]; then
	BIN=$(find target targets/runtime/target "${CARGO_TARGET_DIR:-/nonexistent}" -type f -perm -u+x -name hydration-fuzz-runtime -path '*afl*' 2>/dev/null | head -1 || true)
fi
if [ -z "$BIN" ] || ! [ -x "$BIN" ]; then
	echo "no AFL binary: looked for */afl/*/hydration-fuzz-runtime under fuzz/target, fuzz/targets/runtime/target and" \
	     "CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-<unset>}. Run: just build-afl, or set AFL_BIN=<path>" >&2
	exit 1
fi
BIN=$(realpath "$BIN")
# Oracles off: cmin only needs edges, and try_state/accounting are most of the per-input time. EVM edge
# hashing stays on (those edges are part of what the seeds must preserve).
export FUZZ_KNOWN_PANICS='VIOLATION[|Transfer - ' FUZZ_ORACLE_TRY_STATE=0 FUZZ_ORACLE_DIFFERENTIAL=0 \
	FUZZ_ORACLE_ACCOUNTING=0 FUZZ_ORACLE_CONSERVATION=0 FUZZ_ORACLE_ERC20=0 FUZZ_ORACLE_AAVE=0 \
	FUZZ_ORACLE_EVM_PANIC=0 FUZZ_ORACLE_ICE=0 FUZZ_MAX_BLOCK_MS=600000
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
find "$SRC" -type f | sort > "$T/all"
echo "== tracing $(wc -l < "$T/all") inputs with $JOBS afl-showmap jobs; progress: ls $T/traces | wc -l"
split -n "l/$JOBS" -d "$T/all" "$T/list."
mkdir -p "$T/traces"
for l in "$T"/list.*; do
	(cd targets/runtime && AFL_FORKSRV_INIT_TMOUT=60000 cargo afl showmap -m none -t 30000 -Z -I "$l" -o "$T/traces" \
		-- "$BIN" > "$l.log" 2>&1) || echo "showmap job $l failed, see $l.log" &
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
