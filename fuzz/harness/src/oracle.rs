//! Oracles. Every violation is a `panic!` so AFL records a crash and the soak runner a reproducer.
//! Each oracle is switchable with an env var (see `Config::from_env`).

use crate::evm::{encode, view, word, Token};
use crate::tables::{Reserve, Tables};
use crate::{log, AccountId, AssetId, Balance, Runtime, RuntimeEvent};
use frame_support::traits::{PalletsInfoAccess, TryState, TryStateSelect};
use hydradx_runtime::evm::precompiles::erc20_mapping::HydraErc20Mapping;
use hydradx_runtime::ice_simulator_provider as provider;
use hydradx_traits::amm::{AmmSimulator, TradeResult};
use hydradx_traits::evm::{Erc20Mapping, InspectEvmAccounts};
use hydradx_traits::router::{PoolType, Trade as Hop};
use pallet_broadcast::types::{Destination, Filler};
use orml_traits::MultiCurrency;
use sp_core::{H160, U256};
use std::time::Duration;

pub struct Config {
	pub try_state: bool,
	/// Pallets whose try_state passes on the pristine snapshot; only these are checked.
	/// Cheap ones run after every block, slow ones (Omnipool walks all positions) once per scenario.
	pub try_state_pallets: Vec<Vec<u8>>,
	pub try_state_slow: Vec<Vec<u8>>,
	pub accounting: bool,
	/// Per-asset conservation across actor, router, pool accounts and fee destinations; router ends flat.
	pub conservation: bool,
	pub differential: bool,
	pub erc20: bool,
	pub aave: bool,
	pub evm_revert: bool,
	pub evm_panic_ignore: &'static [u64],
	pub evm_coverage: bool,
	pub ice: bool,
	pub max_block_time: Duration,
	/// Panic substrings of already-reported issues; such an action is rolled back, not a crash.
	pub known_panics: Vec<String>,
}

fn flag(name: &str, default: bool) -> bool {
	std::env::var(name).map(|v| v == "1").unwrap_or(default)
}

impl Config {
	/// `FUZZ_ORACLE_<NAME>=0|1` toggles one oracle.
	pub fn from_env() -> Self {
		let ignore: Vec<u64> = // 0x11 (checked arithmetic) is how solmate-style tokens (GHO/HOLLAR) revert on insufficient
		// balance, so it is expected on fuzzed amounts; set FUZZ_EVM_PANIC_IGNORE= to check it too.
		std::env::var("FUZZ_EVM_PANIC_IGNORE")
			.unwrap_or_else(|_| "11".into())
			.split(',')
			.filter_map(|s| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
			.collect();
		// pallet-currencies' try-runtime transfer asserts fire on 1-wei aToken rounding (reported).
		let known = std::env::var("FUZZ_KNOWN_PANICS")
			.unwrap_or_else(|_| "Transfer - source sent incorrect amount|Transfer - dest received incorrect amount".into());
		Config {
			known_panics: known.split('|').filter(|s| !s.is_empty()).map(str::to_string).collect(),
			try_state: flag("FUZZ_ORACLE_TRY_STATE", true),
			try_state_pallets: vec![],
			try_state_slow: vec![],
			accounting: flag("FUZZ_ORACLE_ACCOUNTING", true),
			conservation: flag("FUZZ_ORACLE_CONSERVATION", true),
			differential: flag("FUZZ_ORACLE_DIFFERENTIAL", true),
			erc20: flag("FUZZ_ORACLE_ERC20", true),
			aave: flag("FUZZ_ORACLE_AAVE", true),
			evm_revert: flag("FUZZ_ORACLE_EVM_PANIC", true),
			evm_panic_ignore: Box::leak(ignore.into_boxed_slice()),
			// Only useful when AFL's map exists; the step hook costs per opcode otherwise.
			evm_coverage: flag("FUZZ_EVM_COVERAGE", cfg!(fuzzing)),
			ice: flag("FUZZ_ORACLE_ICE", true),
			max_block_time: Duration::from_millis(
				std::env::var("FUZZ_MAX_BLOCK_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(2000),
			),
		}
	}
}

pub fn violation(kind: &str, detail: String) -> ! {
	panic!("VIOLATION[{kind}] {detail}")
}

// ---------- try_state ----------

type AllPallets = hydradx_runtime::AllPalletsWithSystem;

/// try_state of each pallet on the pristine snapshot, keeping the ones that pass. Slim snapshots
/// drop accounts some invariants depend on; those pallets are reported and skipped.
pub fn passing_try_state_pallets() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
	let n = frame_system::Pallet::<Runtime>::block_number();
	let prev = std::panic::take_hook();
	std::panic::set_hook(Box::new(|_| {}));
	let mut ok = vec![];
	let mut failing = vec![];
	let mut slow = vec![];
	for info in <AllPallets as PalletsInfoAccess>::infos() {
		let name = info.name.as_bytes().to_vec();
		let t0 = std::time::Instant::now();
		let r = std::panic::catch_unwind(|| {
			<AllPallets as TryState<u32>>::try_state(n, TryStateSelect::Only(vec![name.clone()]))
		});
		match r {
			Ok(Ok(())) if t0.elapsed() > Duration::from_millis(5) => slow.push(name),
			Ok(Ok(())) => ok.push(name),
			_ => failing.push(info.name),
		}
	}
	std::panic::set_hook(prev);
	let names = |v: &[Vec<u8>]| v.iter().map(|n| String::from_utf8_lossy(n).into_owned()).collect::<Vec<_>>();
	eprintln!("try_state: {} pallets per block, once per scenario (slow): {:?}", ok.len(), names(&slow));
	if !failing.is_empty() {
		eprintln!("try_state fails on the pristine snapshot, not checked: {failing:?}");
	}
	(ok, slow)
}

pub fn after_block(cfg: &Config, block: u32, last: bool) {
	if !cfg.try_state {
		return;
	}
	let mut pallets = cfg.try_state_pallets.clone();
	if last {
		pallets.extend(cfg.try_state_slow.iter().cloned());
	}
	if let Err(e) = <AllPallets as TryState<u32>>::try_state(block, TryStateSelect::Only(pallets)) {
		violation("try_state", format!("block {block}: {e:?}"));
	}
}

// ---------- trades: accounting, differential, ERC20 ----------

pub struct Trade {
	pub who: AccountId,
	pub asset_in: AssetId,
	pub asset_out: AssetId,
	/// Venue to run the differential simulator on (single-hop trades only).
	pub sim: Option<PoolType<AssetId>>,
	pub sell: bool,
	pub amount: Balance,
	/// Every hop; pool accounts are derived from it for the conservation check.
	pub route: Vec<Hop<AssetId>>,
	/// EVM contracts holding pool funds (Uniswap pool + swap router), as parties to the trade.
	pub evm_accounts: Vec<H160>,
}

impl Trade {
	pub fn new(who: AccountId, asset_in: AssetId, asset_out: AssetId, pool: PoolType<AssetId>, sell: bool, amount: Balance) -> Self {
		Trade {
			who,
			asset_in,
			asset_out,
			sim: Some(pool),
			sell,
			amount,
			route: vec![Hop { pool, asset_in, asset_out }],
			evm_accounts: vec![],
		}
	}
}

/// Accounts a trade may move funds through, router account first. `true` when a hop mints or
/// burns one of the traded assets (Aave, HSM), which makes per-asset conservation inapplicable.
fn counterparties(tr: &Trade) -> (Vec<AccountId>, bool) {
	let mut v = vec![pallet_route_executor::Pallet::<Runtime>::router_account()];
	let mut mint_burn = false;
	for h in &tr.route {
		match h.pool {
			PoolType::Omnipool => v.push(pallet_omnipool::Pallet::<Runtime>::protocol_account()),
			PoolType::Stableswap(id) => v.push(pallet_stableswap::Pallet::<Runtime>::pool_account(id)),
			PoolType::XYK => v.push(pallet_xyk::Pallet::<Runtime>::pair_account_from_assets(h.asset_in, h.asset_out)),
			PoolType::UniswapV3(_) => {}
			PoolType::Aave | PoolType::HSM | PoolType::LBP => mint_burn = true,
		}
	}
	v.extend(tr.evm_accounts.iter().map(|a| pallet_evm_accounts::Pallet::<Runtime>::truncated_account_id(*a)));
	let mut seen = std::collections::BTreeSet::new();
	v.retain(|a| *a != tr.who && seen.insert(a.clone()));
	(v, mint_burn)
}

fn bal(asset: AssetId, who: &AccountId) -> Balance {
	hydradx_runtime::Currencies::free_balance(asset, who)
}

fn events_since(n: usize) -> Vec<RuntimeEvent> {
	frame_system::Pallet::<Runtime>::read_events_no_consensus()
		.skip(n)
		.map(|r| r.event)
		.collect()
}

fn event_count() -> usize {
	frame_system::Pallet::<Runtime>::event_count() as usize
}

pub fn check_trade(cfg: &Config, tr: Trade, dispatch: impl FnOnce() -> bool) {
	if tr.asset_in == tr.asset_out {
		dispatch();
		return;
	}
	let predicted = tr.sim.filter(|_| cfg.differential).and_then(|p| simulate(p, &tr));
	let (in0, out0) = (bal(tr.asset_in, &tr.who), bal(tr.asset_out, &tr.who));
	let assets = [tr.asset_in, tr.asset_out];
	let (parties, mint_burn) = counterparties(&tr);
	let before: Vec<[Balance; 2]> = parties.iter().map(|p| assets.map(|a| bal(a, p))).collect();
	let ev0 = event_count();
	if !dispatch() {
		return;
	}
	let (in1, out1) = (bal(tr.asset_in, &tr.who), bal(tr.asset_out, &tr.who));
	let spent = in0 as i128 - in1 as i128;
	let received = out1 as i128 - out0 as i128;
	log!("  spent {spent} received {received} predicted {predicted:?}");

	// This trader's Swapped3 events: net amounts per traded asset, and fees that left the parties
	// (burned or paid to an outside account), which conservation has to add back.
	let (mut swaps, mut aave) = (0i128, false);
	let (mut net_in, mut net_out) = (0i128, 0i128);
	let mut fees_out = [0i128; 2];
	for e in events_since(ev0) {
		let RuntimeEvent::Broadcast(pallet_broadcast::Event::Swapped3 {
			swapper,
			inputs,
			outputs,
			fees,
			filler_type,
			..
		}) = e
		else {
			continue;
		};
		if swapper != tr.who {
			continue;
		}
		swaps += 1;
		aave |= matches!(filler_type, Filler::AAVE);
		for a in inputs {
			net_in += (a.asset == tr.asset_in) as i128 * a.amount as i128;
			net_out -= (a.asset == tr.asset_out) as i128 * a.amount as i128;
		}
		for a in outputs {
			net_out += (a.asset == tr.asset_out) as i128 * a.amount as i128;
			net_in -= (a.asset == tr.asset_in) as i128 * a.amount as i128;
		}
		for f in fees {
			let Some(i) = assets.iter().position(|a| *a == f.asset) else { continue };
			let outside = match &f.destination {
				Destination::Burned => true,
				Destination::Account(acc) => *acc != tr.who && !parties.contains(acc),
			};
			fees_out[i] += outside as i128 * f.amount as i128;
		}
	}
	// Contract-ledger assets (aTokens) are ray-rounded on every transfer: allow 2 wei per swap.
	// Exact for everything else.
	let tol = if aave || is_contract_ledger(tr.asset_in) || is_contract_ledger(tr.asset_out) { 2 * swaps } else { 0 };

	if cfg.accounting && swaps > 0 && ((net_in - spent).abs() > tol || (net_out - received).abs() > tol) {
		violation(
			"accounting",
			format!(
				"{}->{}: Swapped3 says in {net_in} out {net_out}, balances moved in {spent} out {received}",
				tr.asset_in, tr.asset_out
			),
		);
	}

	if cfg.conservation {
		let actor = [-spent, received];
		for (i, a) in assets.iter().enumerate() {
			let deltas: Vec<i128> = parties.iter().zip(&before).map(|(p, b)| bal(*a, p) as i128 - b[i] as i128).collect();
			// The router account only passes funds through; anything left behind is stranded.
			if deltas[0].abs() > tol {
				violation(
					"router_leftover",
					format!("{}->{}: router account balance of asset {a} changed by {}", tr.asset_in, tr.asset_out, deltas[0]),
				);
			}
			let sum = actor[i] + deltas.iter().sum::<i128>() + fees_out[i];
			if !mint_burn && sum.abs() > tol {
				violation(
					"conservation",
					format!(
						"{}->{}: asset {a} not conserved: actor {} parties {deltas:?} fees out {} sum {sum}",
						tr.asset_in, tr.asset_out, actor[i], fees_out[i]
					),
				);
			}
		}
	}

	if let Some(p) = predicted {
		// The solver trusts the simulator: it must never promise more than execution delivers.
		if tr.sell && p.amount_out as i128 > received + 1 {
			violation(
				"differential",
				format!(
					"{:?} sell {} {}->{}: simulated out {} > executed {received}",
					tr.sim, tr.amount, tr.asset_in, tr.asset_out, p.amount_out
				),
			);
		}
		if !tr.sell && (p.amount_in as i128) + 1 < spent {
			violation(
				"differential",
				format!(
					"{:?} buy {} {}->{}: simulated in {} < executed {spent}",
					tr.sim, tr.amount, tr.asset_in, tr.asset_out, p.amount_in
				),
			);
		}
	}

	if cfg.erc20 {
		erc20_consistent(tr.asset_in, &tr.who);
		erc20_consistent(tr.asset_out, &tr.who);
	}
}

pub fn is_contract_ledger(a: AssetId) -> bool {
	pallet_asset_registry::Assets::<Runtime>::get(a)
		.is_some_and(|d| matches!(d.asset_type, pallet_asset_registry::AssetType::Erc20))
}

fn sim<S: AmmSimulator>(tr: &Trade) -> Option<TradeResult> {
	let snap = S::snapshot();
	let r = if tr.sell {
		S::simulate_sell(tr.asset_in, tr.asset_out, tr.amount, 0, &snap)
	} else {
		S::simulate_buy(tr.asset_in, tr.asset_out, tr.amount, Balance::MAX, &snap)
	};
	r.ok().map(|(_, r)| r)
}

fn simulate(pool: PoolType<AssetId>, tr: &Trade) -> Option<TradeResult> {
	use amm_simulator::*;
	match pool {
		PoolType::Omnipool => sim::<omnipool::Simulator<provider::Omnipool<Runtime>>>(tr),
		PoolType::Stableswap(_) => sim::<stableswap::Simulator<provider::Stableswap<Runtime>>>(tr),
		PoolType::XYK => sim::<xyk::Simulator<provider::Xyk<Runtime>>>(tr),
		PoolType::Aave => sim::<aave::Simulator<provider::Aave<Runtime>>>(tr),
		PoolType::UniswapV3(_) => sim::<uniswap_v3::Simulator<provider::UniswapV3<Runtime>>>(tr),
		_ => None,
	}
}

/// The ERC20 view of an asset (precompile or bound contract) must agree with the Substrate one.
pub fn erc20_consistent(asset: AssetId, who: &AccountId) {
	let token = HydraErc20Mapping::asset_address(asset);
	let evm = pallet_evm_accounts::Pallet::<Runtime>::evm_address(who);
	let Some(out) = view(token, encode("balanceOf(address)", &[Token::Address(evm)])) else { return };
	let erc20 = word(&out, 0).unwrap_or_default();
	let substrate = U256::from(bal(asset, who));
	if erc20 != substrate {
		violation("erc20", format!("asset {asset} {who:?}: balanceOf {erc20} != free_balance {substrate}"));
	}
}

// ---------- EVM / Aave ----------

/// Whether the last `EVM::call` in this block executed without reverting.
pub fn last_evm_call_succeeded() -> bool {
	frame_system::Pallet::<Runtime>::read_events_no_consensus()
		.filter_map(|r| match r.event {
			RuntimeEvent::EVM(pallet_evm::Event::Executed { .. }) => Some(true),
			RuntimeEvent::EVM(pallet_evm::Event::ExecutedFailed { .. }) => Some(false),
			_ => None,
		})
		.last()
		.unwrap_or(false)
}

const RAY: u128 = 1_000_000_000_000_000_000_000_000_000;

fn ray_mul(a: U256, b: U256) -> U256 {
	(a * b + U256::from(RAY / 2)) / U256::from(RAY)
}

fn call_u256(contract: H160, sig: &str, args: &[Token]) -> Option<U256> {
	view(contract, encode(sig, args)).and_then(|v| word(&v, 0))
}

pub fn after_aave_action(cfg: &Config, t: &Tables, r: &Reserve, user: H160, check_hf: bool) {
	if !cfg.aave {
		return;
	}
	if check_hf {
		// Aave itself validated HF >= 1 for this action, with the same prices, in the same block.
		if let Some(d) = view(t.aave_pool, encode("getUserAccountData(address)", &[Token::Address(user)])) {
			let (debt, hf) = (word(&d, 1).unwrap_or_default(), word(&d, 5).unwrap_or_default());
			if !debt.is_zero() && hf < U256::from(10u128.pow(18)) {
				violation("aave_hf", format!("{user:?} health factor {hf} < 1 after a successful user action"));
			}
		}
	}
	let a = Token::Address(r.underlying);
	let (Some(supply), Some(scaled), Some(income)) = (
		call_u256(r.atoken, "totalSupply()", &[]),
		call_u256(r.atoken, "scaledTotalSupply()", &[]),
		call_u256(t.aave_pool, "getReserveNormalizedIncome(address)", &[a]),
	) else {
		return;
	};
	let expected = ray_mul(scaled, income);
	if supply.abs_diff(expected) > U256::one() {
		violation(
			"aave_supply",
			format!("aToken {:?}: totalSupply {supply} != scaled {scaled} x income {income} = {expected}", r.atoken),
		);
	}
}
