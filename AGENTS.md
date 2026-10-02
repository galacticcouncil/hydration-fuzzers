# hydration-fuzzers

Coverage-guided fuzzing of the Hydration (HydraDX) parachain runtime. Built on
[ziggy](https://github.com/srlabs/ziggy) + AFL++, modelled on SRLabs' substrate-runtime-fuzzer.

| Dir | What |
|---|---|
| `fuzz/` | **The primary fuzzer (v2).** Harness + AFL target + seeded soak runner + ICE solver target + snapshot builder. See `fuzz/AGENTS.md`. |
| `runtime-fuzzer/` | Legacy v1 fuzzer (raw `RuntimeCall` decoding only). Kept for reference. See `runtime-fuzzer/AGENTS.md`. |
| `prepare-snapshot/` | Legacy: builds v1's `MOCK_SNAPSHOT`. Replaced by `fuzz/snapshot`. See `prepare-snapshot/AGENTS.md`. |
| `fuzzerbot/` | Python (poetry). Watches the crash dir, replays via `just crash`, posts the panic to Discord. |

## Hard dependency: sibling `hydration-node` checkout

All Rust crates use `path = "../../hydration-node/..."` (runtime, pallets, `scraper`, `runtime-mock`).
The fuzzer always tests **whatever is checked out in `../hydration-node`**, not a pinned version.

When the node moves, the fuzzer's `Cargo.lock` usually has to follow it. Git deps must be pinned to the
**same commits as `../hydration-node/Cargo.lock`**, or the runtime fails to compile with trait-signature
mismatches. Compare the pins:

```bash
for f in ../hydration-node/Cargo.lock runtime-fuzzer/Cargo.lock; do
  grep -oE 'source = "git\+[^"]+' $f | sed 's/source = "git+//' | sort | uniq -c; done
# then align, e.g.:
cargo update -p frame-support --precise <polkadot-sdk commit>   # moves every crate from that git source
cargo update -p evm           --precise <moonbeam evm commit>
```

## Scope decisions

- **Honggfuzz is not used.** Always pass `--no-honggfuzz` to `cargo ziggy build|fuzz`.
  Its release build fails to link `polkadot-cli` (a `cdylib`) with `undefined hidden symbol`, and
  honggfuzz ≥0.5.61 can't build under ziggy 1.2.1 at all. The justfile targets still call plain
  `cargo ziggy build|fuzz`, so they try honggfuzz and fail.
- Docker (`runtime-fuzzer/Dockerfile`) is broken: the build context doesn't include `../hydration-node`.
  Build natively.

## Host environment gotchas (this machine: Arch, GCC 15, binutils 2.47, LLVM 22)

| Symptom | Cause | Fix |
|---|---|---|
| `cargo afl config --build` → `No rule to make target 'afl-cc'` | user shell exports `MAKEFLAGS=-j8`, races AFL++'s `make clean install` | `env -u MAKEFLAGS ...` |
| `librocksdb-sys`: `'uint64_t' has not been declared` | RocksDB 8.1 vs GCC 13+ (pulled in via `scraper` → `hydradx` node crate) | `CXXFLAGS="-include cstdint"` |
| afl-fuzz refuses to start (core_pattern) | core dumps piped to systemd-coredump | `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` (or `sudo cargo afl system-config`) |
| Slow build that also compiles wasm | runtime build.rs builds the wasm blob | `SKIP_WASM_BUILD=1`; the fuzzer only uses the native runtime |

A cold AFL build of `runtime-fuzzer` takes **~110 min** on 16 cores (it compiles the whole node, because `scraper`
depends on `hydradx` node, `polkadot-cli` and friends). `fuzz/` doesn't depend on `scraper`, so it skips the node,
but a cold instrumented build is still long. Run it in the background.

## Conventions

- Don't commit `runtime-fuzzer/output/`, `target/`, or crash files (already gitignored).
- `data/MOCK_SNAPSHOT*` **are** tracked (~7 MB / 1.4 MB) even though `.gitignore` lists `MOCK_SNAPSHOT`.
- The toolchains differ per crate: `runtime-fuzzer` uses `nightly-2025-06-27`, `prepare-snapshot` uses
  `nightly-2024-12-19`, and `hydration-node` uses `1.88.0`. AFL++ runtime artifacts are per-rustc
  (`~/.local/share/afl.rs/rustc-<ver>/`), so run `cargo afl config --build` from inside `runtime-fuzzer/`.
