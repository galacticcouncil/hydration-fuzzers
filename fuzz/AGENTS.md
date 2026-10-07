# fuzz/ — Hydration fuzzing v2

Step-by-step runbook (prereqs, mainnet scrape → snapshot, start fuzzing, triage, restart): [README.md](README.md).

The primary fuzzer. Design: `../docs/fuzzing-v2-proposal.md`. One Cargo workspace, one lockfile:

| Crate | What |
|---|---|
| `harness/` | Everything fuzzer-agnostic: snapshot load/save, `Engine` (overlay reset per input), `Scenario`/`Action` model (`arbitrary`), block production, oracles, EVM tracing (revert oracle + AFL coverage bridge), ICE actions. |
| `targets/runtime/` | ziggy/AFL++ target: `Engine::run(bytes)`. |
| `targets/soak/` | Plain binary: seeded random bytes → the same `Engine::run`. Also `replay` (any input, incl. AFL crashes) and `seeds`. |
| `targets/ice-solver/` | ziggy/AFL++ target: bytes → intents → `ice_solver::v4::Solver` on simulator state captured once. No chain execution. |
| `snapshot/` | Builds `data/SNAPSHOT` (mainnet state + Substrate-side patches). |

Depends on the sibling `../../hydration-node` checkout by path (runtime 447 @ `c08bba368` when written). Git dep pins in
`Cargo.lock` must match `../../hydration-node/Cargo.lock` (see `../AGENTS.md`). The harness does **not** depend on
`scraper` or `ice-solver-bench`, so no node / rocksdb / libp2p is compiled.

## Environment (every cargo / ziggy command here)

```bash
export SKIP_WASM_BUILD=1 CXXFLAGS="-include cstdint"   # no wasm blob; rocksdb-free anyway but keep it identical
env -u MAKEFLAGS ...                                    # AFL++'s make breaks with the user's MAKEFLAGS=-j8
```

**Always pass the same env.** A bare `cargo build` without `SKIP_WASM_BUILD=1` builds the wasm runtime and then
forces a full runtime rebuild (~10 min release, much longer for AFL). Don't add a `.cargo/config.toml [env]` for this
either: it changes every unit's fingerprint and rebuilds the world.

## Build & run

```bash
cd fuzz
# release build of all binaries (~50 min cold, seconds incremental). Profile keeps debug-assertions + overflow-checks.
env -u MAKEFLAGS SKIP_WASM_BUILD=1 CXXFLAGS="-include cstdint" cargo build --release

# 1. starting state (reads ../../hydration-node/integration-tests/snapshots/ice/SNAPSHOT_uni, writes data/SNAPSHOT, ~5 s)
./target/release/hydration-fuzz-snapshot [SRC] [DST]

# 2. soak (no AFL). FUZZ_SECONDS=60 FUZZ_ITERS=0 FUZZ_SEED=<clock> FUZZ_LEN=512 FUZZ_OUT=findings/ FUZZ_VERBOSE=0
FUZZ_SECONDS=600 ./target/release/hydration-fuzz-soak
./target/release/hydration-fuzz-soak replay findings/<id>.bin      # verbose: every action, call, result, timing
./target/release/hydration-fuzz-soak replay targets/runtime/output/hydration-fuzz-runtime/crashes/<file>

# self-checks (one scenario over every venue against data/SNAPSHOT, ABI encoding, amount resolution)
env -u MAKEFLAGS SKIP_WASM_BUILD=1 CXXFLAGS="-include cstdint" cargo test --release -p hydration-fuzz-harness

# 3. AFL (from the target dir; ziggy uses ./target/afl and ./output relative to cwd)
cd targets/runtime
env -u MAKEFLAGS SKIP_WASM_BUILD=1 CXXFLAGS="-include cstdint" cargo ziggy build --no-honggfuzz --release
../../target/release/hydration-fuzz-soak seeds seeds 64            # initial corpus
env -u MAKEFLAGS SKIP_WASM_BUILD=1 CXXFLAGS="-include cstdint" \
  AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 \
  cargo ziggy fuzz --no-honggfuzz --release -j 4 -t 22 -G 4096 -i seeds
grep -E "execs_per_sec|corpus_count|saved_crashes|stability" output/*/afl/*/fuzzer_stats

# 4. ICE solver target: same, from targets/ice-solver (its target/ is a symlink to ../runtime/target so the
#    instrumented deps are shared; only the small bin is rebuilt).
```

A cold instrumented (`cargo ziggy build --release`) build took ~1.5 h here while a release build ran alongside.
Incremental rebuilds after harness edits: ~2 min. `cargo ziggy fuzz` rebuilds first, so give it the same env.

Don't run the AFL binary directly (persistent mode SIGSTOPs itself); replay crashes with the soak binary.

## Scenario model (`harness/src/action.rs`)

Input bytes → `Scenario { flags, actions }` via `arbitrary` (≤ 48 actions; byte-carrying fields such as raw calls, calldata and raw solutions are capped at 256 bytes so one action cannot swallow the input). AFL drifts toward short inputs (3–4 actions). Long scenarios come from long seeds (`just seeds`: up to 1536 bytes, ≈25 actions) and from AFL mutating them; `-g 768` in `just fuzz` only stops AFL from shrinking below ~768 bytes, and AFL meets it by zero-padding short inputs. Zero bytes decode to an empty `Raw`, which the decoder treats as end of input (otherwise padding showed up as dozens of `Raw` no-ops per input, 35 % of all actions in one run). `flags.solve_each_block` settles intents at every block end; `flags.circuit_breaker_off` lifts
trade/liquidity limits for every asset. Actors are `[i;32]`, i < 20, EVM identity `H160([i;20])` (bound in the
snapshot). Amounts: `Frac(f)` = f/255 of the actor's balance, `Units{m,e}` = human-scale, `Raw(u128)`.
All asset/pool/contract choices index tables read from the snapshot at startup (`tables.rs`).

| Action | Dispatch |
|---|---|
| `Raw{origin, call}` | SCALE `RuntimeCall` (depth 64), same skip filters as `runtime-fuzzer` (System, XTokens, Timestamp, ParachainSystem, zero-fee XCM execute, looked up through batch/proxy/multisig/dispatcher wrappers) and the 2 s block-weight cap. origin%100<15 → none. |
| `Lapse(u16)` | finalize, skip `n` blocks (6 s each, interest accrues), initialize. |
| Omnipool/Stable/Xyk Sell/Buy/Add/Remove | typed pallet calls |
| `Router{hops}` | Router sell/buy; empty hops = stored route, else explicit route over Omnipool/Stableswap/XYK/Aave/HSM/UniswapV3/LBP |
| `AaveTrade` | Router with a single `PoolType::Aave` hop (supply = underlying→aToken, withdraw = reverse) |
| `AavePool{op}` | `EVM::call` to the pool: supply/withdraw/borrow/repay/setUserUseReserveAsCollateral/liquidationCall (auto-approve) |
| `UniswapTrade`, `UniswapQuote` | Router `PoolType::UniswapV3(fee)`; quoter `quoteExactInputSingle` |
| `HsmTrade`, `HsmArbitrage`, `GigaStake/Unstake`, `Liquidate` | pallet calls |
| `OtcPlace/OtcFill`, `Dca` | pallet calls |
| `EvmCall{target, calldata}` | `pallet_evm::call` signed by the actor; target = known contract or any H160; calldata = ABI (selector table) or raw |
| `Impersonate` | `Executor::call` as any address from the users table (no signature) |
| `DispatchEvm` | `Dispatcher::dispatch_evm_call(EVM::call)` |
| `SubmitIntent`, `RemoveIntent`, `SolveAndSubmit`, `SubmitSolution(raw)` | pallet-intent; production solver via `pallet_ice::Pallet::run` + `submit_solution(none)`; SCALE-fuzzed `Solution` |
| `AaveLifecycle { who, reserve, amount, lapse }` | related ops on one actor/reserve: supply `amount` of the underlying → advance `lapse` blocks → withdraw `amount` of the *live* aToken balance (router Aave path both ways). A failed supply isn't fatal. |
| `IceRound { intents: Vec<IntentSpec>, lapse, mutate }` | self-contained ICE round: up to 6 `SubmitIntent`s → advance `lapse` blocks → solver + settlement (`ice_settlement` oracle). With `mutate`, a nudged copy of the solver's solution (one amount ±1/×2 or score+1) is submitted first: the pallet must reject it, or the accepted solution must pass the independent oracle (`ice_validator`). Raised settlement frequency ~10× (51 settlements / 3-min soak vs 4). |

No action ever deploys or modifies a contract.

## Oracles (`harness/src/oracle.rs`, `evm.rs`, `ice.rs`) — any violation panics

| Oracle | Env (default) | Notes |
|---|---|---|
| panic / debug_assert / overflow | always | release profile keeps debug-assertions + overflow-checks |
| block time ≤ 2 s | `FUZZ_MAX_BLOCK_MS` (2000) | |
| `try_state` | `FUZZ_ORACLE_TRY_STATE` (1) | pallets that pass on the pristine snapshot (83/83 today) after every block; slow ones (>5 ms: Omnipool, 90 ms) only after the last block |
| accounting | `FUZZ_ORACLE_ACCOUNTING` (1) | net Swapped3 inputs/outputs with `swapper == actor` vs actual balance deltas; exact, ±2 wei per event for contract-ledger (aToken) assets |
| conservation | `FUZZ_ORACLE_CONSERVATION` (1) | per traded asset, Σ balance deltas over actor + router account + pool accounts of every hop (Omnipool protocol, stableswap pool, XYK pair, Uniswap pool + swap router contracts) + fees burned or paid outside that set (from `Swapped3.fees`) must be 0; skipped when a hop mints/burns (Aave, HSM, LBP). Also `router_leftover`: the router account must end flat for both assets. Catches funds stranded in a pass-through account on the first trade (the Uniswap partial-fill leak) |
| differential | `FUZZ_ORACLE_DIFFERENTIAL` (1) | single-venue trades: `amm_simulator` prediction must not beat execution (sell: sim_out ≤ out+1; buy: sim_in+1 ≥ in) |
| ERC20 ↔ Substrate | `FUZZ_ORACLE_ERC20` (1) | `balanceOf(asset_address)` == `Currencies::free_balance` for the trade's assets/actor |
| Aave | `FUZZ_ORACLE_AAVE` (1) | after `AavePool` actions: aToken `totalSupply == rayMul(scaledTotalSupply, normalizedIncome)` ±1; HF ≥ 1 after a successful borrow/withdraw/collateral toggle |
| EVM Panic / INVALID | `FUZZ_ORACLE_EVM_PANIC` (1), `FUZZ_EVM_PANIC_IGNORE` (`11`) | every call frame's exit via `evm::tracing`; 0x11 ignored by default (solmate-style tokens such as HOLLAR revert with it on insufficient balance) |
| ICE | `FUZZ_ORACLE_ICE` (1) | vendored `ice-fuzz` oracle: solver solutions (limits, bounds), accepted fuzzed solutions (limits + conservation). Plus `ice_settlement` after every accepted `submit_solution`: each owner's `free + reserved` drops by exactly the resolved `amount_in` and free rises by exactly `amount_out` (±2 wei for contract-ledger assets); the holding pot and `FeeReceiver` never lose funds; all-or-nothing intents are removed, partial ones have their filled amount increased |
| known issues | `FUZZ_KNOWN_PANICS` (`Transfer - source sent incorrect amount\|Transfer - dest received incorrect amount`) | a panic containing one of these `\|`-separated substrings rolls the action back (own storage layer) instead of crashing; set `FUZZ_KNOWN_PANICS=` to crash on them |

`FUZZ_EVM_COVERAGE` (1 in AFL builds, 0 otherwise): the EVM step hook hashes `(contract, pc)` into `__afl_area_ptr`.
Measured with `afl-showmap` on one Aave-heavy input: 24.2k tuples without, 38.9k with.

## Snapshot pipeline (`snapshot/`)

Base: `hydration-node/integration-tests/snapshots/ice/SNAPSHOT_uni` (v4, slim, has Aave + the one Uniswap v3 pool).
Patch, all Substrate-side:
1. `hydra_live_ext` steps: relay-parent offset override, ema-oracle v1 + stableswap v2 migrations, register Aave wraps for ICE.
2. Endow the 20 actors with 10M units of HDX, WETH, every sufficient asset and every asset traded by a venue
   (stableswap share assets excluded: minting them desyncs `ShareIssuance`). ERC20-ledger assets (aTokens, HOLLAR)
   can't be minted: each actor gets 1/40 of the treasury's balance by impersonated `transfer`.
3. Lift the circuit breaker's deposit lockdown the minting triggers and release the reserved deposits.
4. `bind_evm_address` for every actor; `Dispatcher::AaveManagerAccount = actor 19`.
5. Produce one block (runtime-upgrade migrations run once here, not per scenario); `commit_all`; save v4.

Startup (`Tables::read`, ~2 s): registry, Omnipool assets, stableswap pools, XYK pools, HSM collaterals,
Aave reserves (`get_reserves_list`/`get_reserve_data`), Uniswap pools (registered ICE targets + factory `getPool` over
ERC20 pairs), known contracts (`EVM.AccountCodes` + precompiles + ERC20 mappings), users (actors, treasury, bound EVM
accounts with Aave collateral).

## Throughput (2026-09-30, 16 cores)

- soak (release, 1 process, idle box): 4.2 scenarios/s (≈15–25 actions each, 508 in 120 s); 6 processes in
  parallel: 3.7–3.8/s each, ~22.6/s total (9469 scenarios in 7 min). Costs: EVM trades
  15–70 ms each, Omnipool try_state 90 ms per scenario, block init ~17 ms. It's single-threaded: run one process per
  core with different `FUZZ_SEED`/`FUZZ_OUT`.
- AFL runtime target (`-j 4`, 10 min): 1.54 execs/s per instance, stability 99.1–99.5 %, corpus 44–68 per
  instance from 64 seeds, bitmap 8.4 %, 0 crashes / 0 hangs (the known aToken asserts are rolled back).
- AFL ice-solver target (`-j 2`, 8 min): 23–59 execs/s per instance, corpus 447, 0 crashes.

## Deviations from the proposal

- No `scraper` dependency: v4 snapshot read/write is ~30 lines in `harness/src/lib.rs`. No node crates in the build.
- `ice-solver-bench` is not a dependency (it pulls frame-remote-externalities → sc-network/libp2p); its 136-line
  `oracle.rs` is vendored as `harness/src/ice_oracle.rs`. Intents are generated with `arbitrary`, not `gen.rs`.
- Base snapshot is the node repo's `SNAPSHOT_uni`, not a fresh `scraper save-storage --slim`; no node-side scraper
  changes were needed (all try_state checks pass on it). It has 0 XYK pools and only 13 Omnipool assets, so XYK
  actions are inert until a snapshot with XYK state is used.
- Block production: para and relay slots are derived from the timestamp (one 6 s slot per block); the legacy
  `slot = block` moves backwards on mainnet state. The sproof uses `ParachainInfo::parachain_id()`.
- `EvmCall` goes through the `pallet_evm::call` extrinsic; revert data is taken from `evm::tracing` `Exit` events of
  every frame (covers calls nested in Router/Liquidation/HSM too), not from the extrinsic result.
- EVM `Panic(0x11)` ignored by default (see oracle table). Aave supply check uses `getReserveNormalizedIncome`
  (the stored `liquidityIndex` is stale between updates, so the literal proposal check would false-positive).
  No reserve-solvency / Uniswap tick invariants / metamorphic / ghost-ledger oracles yet.
- Known-issue rollback (`FUZZ_KNOWN_PANICS`) was added so the pallet-currencies aToken rounding asserts don't stop
  AFL exploring every Aave path.
- The Uniswap and XYK differential checks are inert on this snapshot: their simulators only read pools registered in
  `ICE.SolverRouting`, and none are. Omnipool, Stableswap and Aave differentials are live.
- Scenario flags: `circuit_breaker_off`, `solve_each_block` (solver + settlement at every block end that has valid intents), `actor: Option<u8>` (single-actor mode: every acting account is this actor; victims/impersonated senders stay fuzzed); transaction-pause is reachable only via `Raw`.
- The ice-solver target doesn't mutate simulator state yet (only intents).

## Monitoring (unattended runs)

[MONITOR.md](MONITOR.md) is the instruction file for the monitor job: one agent run (`pi --print @fuzz/MONITOR.md …`
from the repository root, fired by hand or on a schedule) that inspects the running fuzzer, triages new crashes
and sends one Discord message. The scripts it calls live in `scripts/`:

| Piece | Role |
|---|---|
| `scripts/monitor-gate.sh` (`just gate`) | the agent's first step: exit 0 only if there are crash files not in the state (by sha1/path) or the fuzzer looks dead/stalled; otherwise the run is just "send status, done" |
| `scripts/monitor-status.sh` (`just status`) | the Discord-markdown status block (AFL progress, corpus action mix, last coverage); the agent pastes its output verbatim as the first part of every message |
| `scripts/notify-discord.sh` | the only way to send: message on stdin, URL from `DISCORD_WEBHOOK` / `DISCORD_WEBHOOK_FILE` (repo-root `.env` with `DISCORD_WEBHOOK=…`, gitignored) / `~/.config/hydration-fuzz/discord-webhook`; never prints the URL |
| `scripts/triage.sh` (`just triage`) | replay + classify a crash dir, appends to `targets/runtime/output/triage.log` |
| `monitor/` (gitignored) | the memory between runs: `state/processed.tsv` (triaged inputs by sha1), `state/categories.tsv` (failure categories, notified or pending), `state/health.json`, `reports/<utc>.md` |

The agent run is read-only with respect to builds, oracles, snapshots and the fuzzer itself; it only replays,
classifies, writes its state/report and notifies. Known categories are seeded as already-notified so only a
new category produces crash details in the message.

## Triaging crashes (procedure for an agent)

Goal: turn a crash directory into "known / noise / new", root-cause the new ones, and keep the fuzzer looking for
something else. Replay is read-only and does not disturb a running fuzzer; triage while it runs.

1. **Find the right directory.** Each `cargo ziggy fuzz` launch gets its own
   `targets/runtime/output/hydration-fuzz-runtime/crashes/<unix-ms>/`. Triage the newest one. Ignore
   `saved_crashes` in `fuzzer_stats`: it is cumulative over resumed runs (see "Pitfalls").
2. **Get the run's env.** `cat /proc/$(pgrep -f "afl-fuzz -c0" | head -1)/environ | tr '\0' '\n' | grep ^FUZZ_`.
   Replaying with a *different* env changes what fires (muted panics, oracles off, block-time limit).
3. **Replay everything, one line per file:** `FUZZ_… scripts/triage.sh [DIR]` (defaults to the newest dir; appends to
   `targets/runtime/output/triage.log` and skips files already in it; `-a` redoes all). Each line is the first
   `VIOLATION[<oracle>] …` / `panicked at <file:line>`, `KNOWN …` (rolled back by `FUZZ_KNOWN_PANICS`), or
   `REPLAYS CLEAN`. The histogram at the end is the summary to report.
4. **Classify each kind:**
   - `KNOWN …` or a message already in "Findings so far": duplicate, nothing to do except make sure the string is in
     the run's `FUZZ_KNOWN_PANICS` (otherwise it keeps flooding the directory and hides new ones).
   - `REPLAYS CLEAN`: re-run that file with the oracle switches the run had (`FUZZ_ORACLE_DIFFERENTIAL=1` etc.).
     Still clean ⇒ the block-time oracle fired under AFL load (the instrumented binary is 2–3× slower than the replay
     binary). Noise; run with `FUZZ_MAX_BLOCK_MS=20000`.
   - `VIOLATION[differential] Some(Omnipool) …`: known simulator slip-fee gap. Stableswap/Aave/Uniswap differential
     violations are *not* known; treat as new.
   - `panicked at …hydration-node/…`: a runtime assert/overflow — new unless listed. Note whether it fired inside an
     action (rolled back when known) or inside `finalize_block` (hooks: `on_idle`/`on_finalize`, known ones drop the scenario, others crash).
   - anything else: new.
5. **Root-cause a new one.** `./target/release/hydration-fuzz-soak replay <file>` prints every action with its
   extrinsic, result, timing, and for trades `spent/received/predicted`. Read the trace backwards from the violation:
   the triggering action, then earlier actions on the same assets/accounts/pool (leftovers, prior partial fills,
   state drift between intent submission and solving). Then open the pallet/executor code on the path
   (`hydration-node/pallets/<pallet>/src/lib.rs`, `runtime/hydradx/src/evm/*_trade_executor.rs`,
   `pallets/ice/amm-simulator/src/*.rs`) and explain the number: an oracle message always contains both sides
   (event vs balance, simulated vs executed, before vs after); the difference should be derivable from code.
   `RUST_BACKTRACE=1` on the replay gives the frames for a runtime panic. Rule of thumb: an oracle is only "wrong"
   if you can name the rounding/fee/mint term it ignores; otherwise the runtime is.
6. **Decide and record:**
   - Real finding: copy the file to `findings/<short-name>/`, add it to "Findings so far" (what, where in node code,
     reproducer path, severity), then add its violation prefix to `FUZZ_KNOWN_PANICS` for the next restart.
   - Oracle bug / tolerance: fix the oracle (`harness/src/oracle.rs`, `ice.rs`), rebuild the soak binary
     (`$E cargo build --release -p hydration-fuzz-soak`, ~1 min), confirm the reproducer is clean, rebuild the AFL
     target before the next restart.
   - Noise: adjust the env.
7. **Report** the histogram, one paragraph per new kind (mechanism, code location, reproducer command), and the
   restart env to use.

### Pitfalls

- `afl/` holds the resumed queue and counters. Restarting without moving it replays the whole queue (dry run of
  thousands of inputs, 0.5–1 s each) and keeps the old `saved_crashes` numbers. "200 crashes immediately after a
  restart" is that counter, not 200 new crashes.
- Files named `sync:<instance>,src:N` were imported from another instance's queue during the dry run; they are old
  inputs re-evaluated by a new binary, typically a known finding under a renamed oracle.
- Every crash in a directory tends to descend from one or two seeds (`src:N`); AFL re-finds a crash it has already
  found until it is muted. Dozens of files ≠ dozens of bugs.
- A known panic inside an action is rolled back; inside a block hook (`on_idle`/`on_finalize`, e.g. fee-processor
  converting aToken fees) it cannot be, so the scenario is dropped (`known issue in block hook, scenario dropped`).
- Contract-ledger assets (aTokens, HOLLAR) are ±1 wei per transfer by construction; the oracles allow 2 wei per
  swap. A 1-wei mismatch on those is not a finding.
- Replay must run from `fuzz/` with the same `data/SNAPSHOT` the fuzzer used; a different snapshot changes amounts.
- Inputs are raw bytes decoded by `arbitrary`; adding an `Action` variant or a `Flags` field changes what old bytes
  mean (enum selectors are `x % N`). After such a change the AFL corpus is just re-evaluated, but saved reproducers
  under `findings/` go stale: regenerate them with an unmuted soak
  (`FUZZ_KNOWN_PANICS='' FUZZ_ORACLE_DIFFERENTIAL=1 FUZZ_KEEP_GOING=1 FUZZ_OUT=<dir> just soak 420`, then sort by
  the printed panic key) and re-verify each with `replay`. Done last on 2026-10-07 for the lifecycle/single-actor change.

## Findings so far

- **pallet-currencies try-runtime asserts fail on aToken transfers** (1 wei ray rounding): `currencies/src/lib.rs:358/359`
  and `fungibles.rs:388/392`, "Transfer - source sent / dest received incorrect amount". Reached via Router Aave
  withdraw, Stableswap `add_assets_liquidity` with an aToken, GigaHdx stake. Rolled back when raised inside an action;
  still a crash when raised from block hooks (e.g. a DCA execution in `on_initialize`). Reproducers in
  `findings/known-atoken-rounding/`: `FUZZ_KNOWN_PANICS= ./target/release/hydration-fuzz-soak replay <file>`.
- **Swapped3 for a UniswapV3 router buy under-reports `amount_in` by 1 wei** (HOLLAR spent = event + 1). Currently
  inside the ±2 contract-ledger tolerance; set the tolerance to 0 in `oracle::check_trade` to reproduce.
- **Uniswap v3 router sell: Swapped3 `outputs` far below what the user receives.** aDOT(1001)→HOLLAR(222) sell
  after another actor's large HOLLAR→aDOT swap: event says out 6.10e18, the seller's HOLLAR balance rose 6.38e21
  (3 reproducers, all the same shape). Either the event reports the quote instead of the executed amount or the
  swap pays out something extra (e.g. leftovers of an earlier trade). Not root-caused.
  `./target/release/hydration-fuzz-soak replay findings/uniswap-sell-accounting/<file>`.
- **amm-simulator Omnipool prediction beats execution** (differential oracle; 6 reproducers, sells and buys):
  e.g. sell 222→38 simulated out 9.638e20 vs executed 9.604e20 (+0.35 %); buy 35→38 simulated in 3.237e18 vs executed
  3.516e18 (−8 %); first one found after `Lapse(9523)` on the 2nd buy of the block. The ICE solver relies on this
  simulator, so it can over-promise. Not root-caused. `findings/omnipool-differential/<file>`.
- EVM `Panic(0x11)` in HOLLAR (`0xc0df4c54…`) on HSM buy when the buyer lacks collateral: expected solmate behaviour,
  hence the default ignore.

## Known limitations / next steps

- Throughput is EVM-bound; profile `evm` with debug-assertions off for the interpreter only, or cache simulator
  snapshots per block.
- `Ethereum::transact` (signed) not covered; DCA intents not generated; no corpus minimisation / CI job yet.
- Aave users come from bound EVM accounts with collateral (first 400 scanned, capped at 64; 64 found on this
  snapshot). Liquidations are reachable only once fuzzed trades move the EMA-fed prices far enough.
