# Hydration runtime fuzzer — from scratch to fuzzing

Step-by-step runbook. For design, oracles and internals see [AGENTS.md](AGENTS.md).

Everything below is run from this directory (`hydration-fuzzers/fuzz`) unless stated otherwise.
`hydration-node` must be checked out next to `hydration-fuzzers` (`../../hydration-node`); the fuzzer compiles
whatever runtime is checked out there.

`just --list` shows one target per step below (`just setup`, `build`, `build-afl`, `snapshot`, `test`, `soak`, `fuzz`,
`restart`, `stats`, `triage`, `replay`, `cover`); the sections keep the raw commands so you can see what each does.

## Quick start on a new machine

```bash
# 1. both repos side by side (the fuzzer depends on ../hydration-node by relative path)
mkdir gc && cd gc
git clone <hydration-node>  hydration-node
git clone <hydration-fuzzers> hydration-fuzzers
cd hydration-fuzzers/fuzz

# 2. toolchain + tools (rustup installs the pinned nightly on first cargo call; apt/pacman: clang protobuf
#    binutils libunwind python3 curl just)
just setup                       # ziggy 1.2.1, cargo-afl, grcov, llvm-tools, AFL++ runtime

# 3. binaries (~1.5 h cold for both; the two builds can run back to back)
just build                       # soak runner + snapshot tool
just build-afl                   # AFL target (AFL + coverage instrumented)

# 4. starting state: scrape current mainnet (network; builds the node's scraper first, ~30-60 min cold),
#    then patch it into the fuzzer's state
just scrape 0x<block hash>       # pin a finalized block for reproducibility; `just scrape` = latest finalized
just snapshot                    # data/scrape/SNAPSHOT -> data/SNAPSHOT (actors funded, EVM bound, params)
just test                        # 6 self-tests against it
#    (offline fallback: with no scrape present, `just snapshot` uses the node repo's committed April-2026 snapshot)

# 5. fuzz
just seeds && just fuzz          # Ctrl+C to stop; `just restart && just fuzz` for a clean restart later
just stats                       # progress;  just status  = the one-screen summary;  just triage = crashes
```

Keep the block hash with the snapshot (findings only reproduce against the same state); `.env` with `DISCORD_WEBHOOK=…` plus `pi` enables the monitor
(`MONITOR.md`). Nothing else is machine-specific: the `justfile` already works around the known host quirks
(`MAKEFLAGS`, RocksDB on new GCC, no wasm build).

## 0. Prerequisites

```bash
# Rust: the pinned nightly is picked up automatically from ./rust-toolchain
rustup show                                                  # should mention nightly-2025-06-27 once inside fuzz/

# fuzzing tools (ziggy must be 1.2.1 to match the lib pin in Cargo.toml)
cargo install --locked ziggy@1.2.1 cargo-afl grcov
env -u MAKEFLAGS cargo afl config --build --force           # builds the AFL++ runtime for this nightly

# system packages (Arch names): clang, protobuf, binutils, libunwind
```

Every `cargo` command in this runbook is prefixed with the same environment. Define it once per shell:

```bash
export E='env -u MAKEFLAGS SKIP_WASM_BUILD=1 CXXFLAGS=-include\ cstdint'
```

| Variable | Why |
|---|---|
| `env -u MAKEFLAGS` | a parallel `MAKEFLAGS` in the shell breaks AFL++'s `make` |
| `SKIP_WASM_BUILD=1` | the fuzzer only needs the native runtime; without it every build also compiles the wasm runtime and forces a full rebuild |
| `CXXFLAGS="-include cstdint"` | RocksDB 8 does not compile on GCC ≥ 13 without it |

Keep the git dependency pins in `Cargo.lock` equal to `../../hydration-node/Cargo.lock` (polkadot-sdk fork, moonbeam
evm/frontier, ORML). If the runtime fails to compile with trait-signature errors after the node moved, realign:

```bash
for f in ../../hydration-node/Cargo.lock Cargo.lock; do
  grep -oE 'source = "git\+[^"]+' $f | sed 's/source = "git+//' | sort | uniq -c; done
cargo update -p frame-support --precise <polkadot-sdk commit from the node lock>
cargo update -p evm           --precise <moonbeam evm commit from the node lock>
```

## 1. Build

```bash
$E cargo build --release            # soak runner, snapshot tool, ~5 min incremental, ~1.5 h cold
```

The AFL-instrumented target is built separately in step 4; it is a second full compile of the runtime.

## 2. Create the snapshot from mainnet

The fuzzer starts every input from one fixed state: `data/SNAPSHOT`, a v4 `scraper` snapshot of mainnet storage
plus Substrate-side patches (funded actors, EVM bindings, parameters). Contracts are never deployed or modified; the
EVM state is exactly what mainnet has.

### 2a. Scrape mainnet with the node's `scraper` (`just scrape [BLOCK_HASH]` does all of this)

```bash
cd ../../hydration-node
cargo build --release -p scraper

# Pick a block: finalized head is fine; pass --at <hash> to pin one (recommended, so the snapshot is reproducible).
# --slim drops user accounts and keeps protocol/pool/contract/dev accounts (17-25 MB instead of >100 MB).
# No --pallet filter: the fuzzer needs every pallet (EVM, Parameters, Liquidation, Dispatcher, ICE, ...).
mkdir -p /tmp/hydra-scrape
./target/release/scraper save-storage \
    --uri wss://rpc.hydradx.cloud:443 \
    --at <BLOCK_HASH> \
    --slim \
    --path /tmp/hydra-scrape
# -> /tmp/hydra-scrape/SNAPSHOT
cd -
```

A full (non-slim) scrape also works and loads fine (~6× larger); use it only if you need user accounts that slim drops
(e.g. money-market positions of specific users).

### 2b. Patch it into the fuzzer's starting state (`just snapshot`)

```bash
./target/release/hydration-fuzz-snapshot /tmp/hydra-scrape/SNAPSHOT data/SNAPSHOT
```

With no arguments it uses `../../hydration-node/integration-tests/snapshots/ice/SNAPSHOT_uni` (April 2026 mainnet,
slim, has Aave + Uniswap) as the source, which is enough to try things out without network access.

What the patch does (all on the Substrate side): runs the pending runtime migrations the node's own tests run, endows
the 20 fuzzer actors (`[i; 32]`, i < 20) with HDX, WETH (EVM gas) and every tradeable asset, gives them aTokens/HOLLAR
by impersonated transfer from the treasury (those can't be minted), binds their EVM addresses, sets
`Dispatcher::AaveManagerAccount`, lifts the circuit-breaker lockdown the endowment triggers, produces one block, saves.

Sanity check — loads the snapshot, runs one scenario over every venue, settles two intents:

```bash
$E cargo test --release -p hydration-fuzz-harness
```

`data/SNAPSHOT` is gitignored. Keep a copy of the scrape with its block hash somewhere; findings are only
reproducible against the same snapshot.

## 3. Soak run (no AFL, fastest way to see it working)

```bash
FUZZ_SECONDS=600 ./target/release/hydration-fuzz-soak
```

Seeded random scenarios through the same harness and oracles as the AFL target; findings are written to
`findings/<id>.bin` with the replay command printed inline. Useful variables: `FUZZ_SEED`, `FUZZ_ITERS`,
`FUZZ_VERBOSE=1` (every action, call, result, timing), `FUZZ_SNAPSHOT=<path>`.

## 4. Coverage-guided fuzzing with AFL++

```bash
cd targets/runtime
RUSTFLAGS=-Cinstrument-coverage $E cargo ziggy build --no-honggfuzz --release   # AFL + coverage instrumented, ~2 h cold
../../target/release/hydration-fuzz-soak seeds seeds 64  # 64 valid seed inputs for the corpus

FUZZ_KNOWN_PANICS='Transfer - source sent incorrect amount|Transfer - dest received incorrect amount' \
FUZZ_MAX_BLOCK_MS=20000 \
RUSTFLAGS=-Cinstrument-coverage LLVM_PROFILE_FILE=/dev/null \
$E AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 \
  cargo ziggy fuzz --no-honggfuzz --release -j 4 -t 22 -g 768 -G 4096 -i seeds
```

- `RUSTFLAGS=-Cinstrument-coverage` on every build *and* fuzz command (fuzz rebuilds first): the one AFL binary also
  carries LLVM coverage counters, so `scripts/coverage.sh` needs no extra build. Changing `RUSTFLAGS` triggers a full rebuild.
  `LLVM_PROFILE_FILE=/dev/null` stops the fuzzing children from writing profiles.
- `-g 768` keeps inputs long enough for ~12+ actions per scenario (AFL otherwise drifts to 3–4); `-G 4096` caps at the 48-action bound.
- `-j` = parallel instances (each is its own process with its own copy of the state; ~0.5 GB each).
- `--no-honggfuzz` always: honggfuzz is not supported for this target.
- `FUZZ_MAX_BLOCK_MS=20000`: the instrumented binary is 2–3× slower than the soak binary, so the default 2 s
  block-time oracle produces false crashes under AFL. AFL's own `-t` catches real hangs.
- `FUZZ_KNOWN_PANICS`: `|`-separated substrings of panics already reported; a matching action is rolled back
  instead of saved as a crash. Add new ones as findings get triaged, or the crash dir fills with duplicates and
  hides anything new.
- Other oracle switches (`FUZZ_ORACLE_*`) are listed in AGENTS.md.

Watch it:

```bash
grep -E "execs_per_sec|corpus_count|saved_crashes|stability" output/hydration-fuzz-runtime/afl/*/fuzzer_stats
tail -f output/hydration-fuzz-runtime/logs/afl.log
```

Expect 1–3 execs/s per instance. The first minute(s) are AFL's "dry run" of the corpus; nothing is fuzzed until it
finishes. `saved_crashes` in `fuzzer_stats` is cumulative over resumed runs — judge a run by its own crash directory.

## 5. Triage a crash

```bash
cd fuzz
./target/release/hydration-fuzz-soak replay targets/runtime/output/hydration-fuzz-runtime/crashes/<ts>/<file>
```

Prints every action, extrinsic, result and timing, then the violation (`VIOLATION[<oracle>] ...`) or panic with its
location. Pass the same `FUZZ_KNOWN_PANICS` / `FUZZ_ORACLE_*` as the run to see exactly what AFL saw; drop them to
see everything. A crash that replays clean was almost certainly the block-time oracle under load.

To triage a whole directory in one go (newest dir by default; appends to `targets/runtime/output/triage.log`
and skips files already triaged; prints a histogram by violation kind):

```bash
FUZZ_KNOWN_PANICS='…same as the run…' FUZZ_MAX_BLOCK_MS=20000 scripts/triage.sh [DIR]
```

The classification rules (known / noise / new) and the root-cause procedure are in AGENTS.md, "Triaging crashes".

Confirmed reproducers live under `findings/<name>/*.bin` (gitignored); replay the same way.

## 6. Restarting

AFL resumes from `output/hydration-fuzz-runtime/afl/` and re-executes the whole queue on start. With a large queue
that is a long dry run on every restart. For a clean restart:

```bash
cd targets/runtime                                   # stop the run first (Ctrl+C)
mv output/hydration-fuzz-runtime/afl    output/hydration-fuzz-runtime/afl.old
rm -rf output/hydration-fuzz-runtime/corpus          # a sync copy of afl/'s queue
# then the `cargo ziggy fuzz ... -i seeds` command from step 4
```

To keep an old queue instead, minimise it once and feed it back with `-i`:
`$E cargo ziggy minimize --release -e afl-plus-plus -i output/hydration-fuzz-runtime/corpus.old -o seeds_min` and then `-i seeds_min`.

After changing harness code, rebuild both binaries (`$E cargo build --release` and
`RUSTFLAGS=-Cinstrument-coverage $E cargo ziggy build --no-honggfuzz --release` in `targets/runtime`); a running AFL keeps using the old target
until restarted.

## 7. Coverage report

```bash
scripts/coverage.sh [CORPUS_DIR]  # default: targets/runtime/output/hydration-fuzz-runtime/corpus
# -> targets/runtime/output/coverage/{report.txt,by_component.txt,html/index.html,lcov}
```

Needs `rustup component add llvm-tools-preview` once. No extra build: it replays the corpus through the AFL binary
from step 4 (`FUZZ_REPLAY_ARGS=1`, `JOBS=4` parallel, all oracles muted so every input contributes) and reports with
`llvm-profdata`/`llvm-cov`. Do not use `cargo ziggy cover` (relies on `-Zprofile`, gone from rustc). The report
covers Rust (node pallets, runtime, harness); EVM bytecode coverage feeds AFL's guidance but is not in it.

To cover everything the fuzzer ever found rather than the current shared corpus, point it at a merged directory of
all instances' queues (`output/hydration-fuzz-runtime/afl/*/queue/`, deduplicated by content).

## 8. ICE solver target

Same workflow from `targets/ice-solver` (its `target/` is a symlink to the runtime target's, so only the small binary
is rebuilt). No chain execution: inputs become intents solved against simulator state captured once, checked by the
ICE oracle. Tens of execs/s.

## 9. Unattended monitoring

`MONITOR.md` is the instruction file for the monitor job: `pi --print @fuzz/MONITOR.md "…"` from the repo root,
by hand or on any schedule, inspects the running fuzzer, triages new crashes and sends one Discord message; the scripts it uses live in `scripts/`: `monitor-gate.sh`, `monitor-status.sh`,
`notify-discord.sh` and `triage.sh` (`just gate|status|notify-status|triage`).


## Known findings baked into the default known-panics list

See "Findings so far" in AGENTS.md. As of 2026-10-02: aToken transfers are ±1 wei vs the `pallet-currencies`
try-runtime assert (mute: the two `Transfer - ...` strings above); the Uniswap v3 partial-fill leak
(`VIOLATION[router_leftover] 222->1001`); the Omnipool simulator's missing in-block slip-fee state
(`FUZZ_ORACLE_DIFFERENTIAL=0` until fixed in `amm-simulator`).
