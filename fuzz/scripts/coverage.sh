#!/usr/bin/env bash
# Source-based coverage of the runtime fuzz target over a corpus.
#   scripts/coverage.sh [CORPUS_DIR]        default: targets/runtime/output/hydration-fuzz-runtime/corpus
# Output: targets/runtime/output/coverage/{html/index.html,lcov}
#
# Not `cargo ziggy cover`: that uses -Zprofile (gone from rustc), needs a third build, runs the corpus in one
# process that dies on the first panic, and its -Clink-dead-code leaves nameless entries llvm-cov refuses.
# Report via llvm-profdata/llvm-cov, not grcov.
set -euo pipefail
cd "$(dirname "$0")/../targets/runtime"
CORPUS=$(realpath "${1:-output/hydration-fuzz-runtime/corpus}")
JOBS=${JOBS:-4}
BIN=target/afl/release/hydration-fuzz-runtime
LLVM_BIN="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin"   # rustup component add llvm-tools-preview
OUT=output/coverage

# Single build: the AFL target carries -Cinstrument-coverage on top of AFL's instrumentation
# (RUSTFLAGS="-Cinstrument-coverage" cargo ziggy build --no-honggfuzz --release) and FUZZ_REPLAY_ARGS=1
# switches it from the fork-server loop to "replay argv in one process".
[ -x "$BIN" ] || { echo "no AFL target at $BIN; build it first (see README §4)"; exit 1; }

echo "== replay $(ls "$CORPUS" | wc -l) inputs with $JOBS jobs"
rm -rf profraw; mkdir -p profraw
# Oracles off / muted: we want reached code, not findings. A panic that still escapes ends only its chunk.
export FUZZ_KNOWN_PANICS='VIOLATION[|Transfer - ' FUZZ_ORACLE_TRY_STATE=0 FUZZ_ORACLE_DIFFERENTIAL=0 \
	FUZZ_ORACLE_ACCOUNTING=0 FUZZ_ORACLE_CONSERVATION=0 FUZZ_ORACLE_ERC20=0 FUZZ_ORACLE_AAVE=0 \
	FUZZ_ORACLE_EVM_PANIC=0 FUZZ_ORACLE_ICE=0 FUZZ_MAX_BLOCK_MS=600000 FUZZ_EVM_COVERAGE=0 FUZZ_REPLAY_ARGS=1
ls "$CORPUS" | sed "s|^|$CORPUS/|" | xargs -P "$JOBS" -n 200 sh -c \
	'LLVM_PROFILE_FILE=profraw/%4m.profraw '"$BIN"' "$@" > /dev/null 2>&1 || echo "chunk ended early (exit $?)"' _

echo "== report"
rm -rf "$OUT"; mkdir -p "$OUT"
"$LLVM_BIN/llvm-profdata" merge -sparse profraw/*.profraw -o "$OUT/all.profdata"

IGNORE='(\.cargo/|/rustc/|/target/)'
"$LLVM_BIN/llvm-cov" report "$BIN" -instr-profile="$OUT/all.profdata" -ignore-filename-regex="$IGNORE" > "$OUT/report.txt"
"$LLVM_BIN/llvm-cov" export "$BIN" -instr-profile="$OUT/all.profdata" -ignore-filename-regex="$IGNORE" -format=lcov > "$OUT/lcov"
"$LLVM_BIN/llvm-cov" show "$BIN" -instr-profile="$OUT/all.profdata" -ignore-filename-regex="$IGNORE" \
	-format=html -output-dir="$OUT/html" -show-line-counts-or-regions > /dev/null
# Line coverage aggregated by pallet / component (read by monitor-status.sh).
{
	echo "# line coverage by component, corpus = $CORPUS ($(ls "$CORPUS" | wc -l) inputs), $(date -u '+%Y-%m-%d %H:%M UTC')"
	awk '$1 ~ /(hydration-node|hydration-fuzzers)\// {f=$1; sub(".*workspace/gc/","",f); g=f;
		if (g ~ /^hydration-node\/pallets\//) { split(g,a,"/"); g="pallet " a[3] }
		else if (g ~ /^hydration-node\/runtime\/hydradx\/src\/evm\//) g="runtime/evm";
		else if (g ~ /^hydration-node\/runtime\//) g="runtime (other)";
		else if (g ~ /^hydration-node\/math\//) g="math";
		else if (g ~ /^hydration-node\/ice\//) g="ice solver";
		else if (g ~ /^hydration-node\/precompiles\//) g="precompiles";
		else if (g ~ /^hydration-node\/traits\//) g="traits";
		else if (g ~ /^hydration-fuzzers\//) g="fuzz harness"; else g="other";
		L[g]+=$8; M[g]+=$9}
		END {for (g in L) if (L[g]>0) printf "%6.1f%%  %6d/%-6d  %s\n", 100*(L[g]-M[g])/L[g], L[g]-M[g], L[g], g}' "$OUT/report.txt" | sort -rn
} > "$OUT/by_component.txt"
echo "done: $OUT/report.txt (per-file), $OUT/by_component.txt, $OUT/html/index.html, $OUT/lcov"
