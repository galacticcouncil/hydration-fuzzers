//! ICE actions: intents interleaved with arbitrary chain activity, the real solver run in-harness
//! (like `ice-fuzz` tier 2), and fuzzed solutions thrown straight at the pallet's validator.

use crate::{log, oracle, AccountId, AssetId, Balance, Runtime, RuntimeOrigin};
use codec::DecodeLimit;
use crate::ice_oracle::{check_solution, SolverIntent, Violation};
use hydradx_traits::amm::{SimulatorConfig, SimulatorSet};
use ice_support::{DcaParams, IntentData, IntentDataInput, Partial, Solution, SwapParams};
use orml_traits::{MultiCurrency, NamedMultiReservableCurrency};
use std::collections::BTreeMap;

pub type SolverV4 = ice_solver::v4::Solver<amm_simulator::HydrationSimulator<hydradx_runtime::HydrationSimulatorConfig>>;
pub type State = <<hydradx_runtime::HydrationSimulatorConfig as SimulatorConfig>::Simulators as SimulatorSet>::State;

/// Must run inside externalities: reads pool state from storage.
pub fn initial_state() -> State {
	<<hydradx_runtime::HydrationSimulatorConfig as SimulatorConfig>::Simulators as SimulatorSet>::initial_state()
}

pub fn submit_intent(who: AccountId, asset_in: AssetId, asset_out: AssetId, amount_in: Balance, amount_out: Balance, partial: bool, kind: IntentKind) {
	let swap = SwapParams { asset_in, asset_out, amount_in, amount_out, partial };
	let data = match kind {
		IntentKind::Swap => IntentDataInput::Swap(swap),
		// 1..=256 s; blocks are 6 s, so the window is open at a same-block solve and closes within an `IceRound`.
		IntentKind::MatchFirst { window } => IntentDataInput::MatchFirstSwap { swap, match_window: (1 + u64::from(window)) * 1000 },
		IntentKind::Dca { period, budget, slip } => IntentDataInput::Dca(DcaParams {
			asset_in,
			asset_out,
			amount_in,
			amount_out,
			slippage: sp_runtime::Permill::from_percent(u32::from(slip) % 51),
			budget: budget.map(|n| amount_in.saturating_mul(1 + u128::from(n) % 4)),
			period: 15 + u32::from(period),
		}),
	};
	let input = pallet_intent::types::IntentInput { data, deadline: None, on_resolved: None };
	let r = pallet_intent::Pallet::<Runtime>::submit_intent(RuntimeOrigin::signed(who), input);
	log!("  submit_intent => {r:?}");
}

pub fn remove_intent(who: AccountId, back: u8) {
	let ids: Vec<u128> = pallet_intent::AccountIntents::<Runtime>::iter_key_prefix(&who).collect();
	let Some(id) = ids.get(back as usize % ids.len().max(1)).copied() else { return };
	let r = pallet_intent::Pallet::<Runtime>::remove_intent(RuntimeOrigin::signed(who), id);
	log!("  remove_intent {id} => {r:?}");
}

fn valid_intents(cfg: &oracle::Config) -> Vec<SolverIntent> {
	let list = pallet_intent::Pallet::<Runtime>::get_valid_intents();
	if cfg.ice {
		check_conditional(&list);
	}
	list.into_iter().map(|(id, i)| SolverIntent { id, data: i.data }).collect()
}

/// `ice_conditional`: a match-first swap inside its window, or a DCA ahead of its slot, is offered
/// to the solver only against opposite flow. The pallet's coverage rule is rate-dependent; the
/// sound necessary condition checked here is that *some* other intent on the reverse pair is
/// stored at all. Also: the solver only knows plain swaps, so no other variant may leak out.
fn check_conditional(list: &[(u128, pallet_intent::types::Intent)]) {
	let now = pallet_timestamp::Pallet::<Runtime>::get();
	let block = frame_system::Pallet::<Runtime>::block_number();
	let stored: BTreeMap<u128, IntentData> = pallet_intent::Intents::<Runtime>::iter().map(|(id, i)| (id, i.data)).collect();
	for (id, view) in list {
		if !matches!(view.data, IntentData::Swap(_)) {
			oracle::violation("ice_conditional", format!("intent {id} offered to the solver as {:?}, not a plain swap", view.data));
			continue;
		}
		let waiting = match stored.get(id) {
			Some(IntentData::MatchFirstSwap { match_until, .. }) => now < *match_until,
			Some(IntentData::Dca(d)) => block < d.last_execution_block.saturating_add(d.period),
			_ => false,
		};
		if !waiting {
			continue;
		}
		let (ai, ao) = (view.data.asset_in(), view.data.asset_out());
		if !stored.iter().any(|(j, d)| j != id && d.asset_in() == ao && d.asset_out() == ai) {
			oracle::violation("ice_conditional", format!("waiting intent {id} ({ai}->{ao}) offered with no reverse-pair intent stored"));
		}
	}
}

fn fee() -> sp_runtime::Permill {
	pallet_ice::ProtocolFee::<Runtime>::get()
}

fn report(kind: &str, v: Vec<Violation>) {
	if let Some(first) = v.first() {
		oracle::violation(kind, format!("[{}] {} (+{} more)", first.kind, first.detail, v.len() - 1));
	}
}

/// Run the production solver on the current (possibly heavily drifted) state. Returns the valid
/// intents it saw and the solution, if any.
pub fn solve(cfg: &oracle::Config) -> Option<(Vec<SolverIntent>, Solution)> {
	let originals = valid_intents(cfg);
	log!("  {} valid intents ({} stored)", originals.len(), pallet_intent::Intents::<Runtime>::iter_keys().count());
	if originals.is_empty() {
		return None;
	}
	let fee = fee();
	let block = frame_system::Pallet::<Runtime>::block_number();
	let call = pallet_ice::Pallet::<Runtime>::run(block, move |intents, limits, state| {
		SolverV4::solve_with_limits(intents, limits.into_iter().collect(), state, fee).ok()
	});
	let Some(pallet_ice::Call::submit_solution { solution }) = call else {
		log!("  solver: no solution for {} intents", originals.len());
		return None;
	};
	Some((originals, solution))
}

/// Submit the solver's own solution: it must respect every limit (not re-checked on chain) and settle.
pub fn submit_solver_solution(cfg: &oracle::Config, originals: &[SolverIntent], solution: Solution) {
	if cfg.ice {
		report("ice_solution", check_solution(originals, &solution, fee(), false));
	}
	let r = settle(cfg, &solution);
	log!("  submit_solution (solver) => {:?}", r.map(|_| ()));
}

pub fn solve_and_submit(cfg: &oracle::Config) {
	if let Some((originals, solution)) = solve(cfg) {
		submit_solver_solution(cfg, &originals, solution);
	}
}

/// A solution that is not the solver's (fuzzed or mutated): the pallet is expected to reject it;
/// if it accepts, the solution must still satisfy the independent oracle, else the validator is the bug.
fn submit_fuzzed(cfg: &oracle::Config, label: &str, originals: &[SolverIntent], solution: &Solution) {
	let r = settle(cfg, solution);
	log!("  submit_solution ({label}) => {:?}", r.map(|_| ()));
	if r.is_ok() && cfg.ice {
		report("ice_validator", check_solution(originals, solution, fee(), true));
	}
}

/// The solver's solution with one field nudged (a near-valid solution is a much better validator
/// probe than random bytes): `m` picks the resolved intent and the kind of nudge.
pub fn submit_mutated(cfg: &oracle::Config, originals: &[SolverIntent], solution: &Solution, m: u8) {
	let mut s = solution.clone();
	let n = s.resolved_intents.len();
	if n == 0 {
		return;
	}
	let r = &mut s.resolved_intents[usize::from(m) % n];
	let kind = (m / 8) % 5;
	if let ice_support::IntentData::Swap(sw) = &mut r.data {
		match kind {
			0 => sw.amount_out = sw.amount_out.saturating_add(1),
			1 => sw.amount_out = sw.amount_out.saturating_mul(2),
			2 => sw.amount_in = sw.amount_in.saturating_sub(1),
			3 => sw.amount_out = sw.amount_out.saturating_sub(1),
			_ => s.score = s.score.saturating_add(1),
		}
	} else {
		s.score = s.score.saturating_add(1);
	}
	log!("  mutated solution: intent #{} nudge {kind}", usize::from(m) % n);
	submit_fuzzed(cfg, "mutated", originals, &s);
}

type Currencies = hydradx_runtime::Currencies;

/// What `settle` recorded about a resolved intent before `submit_solution`.
enum Pre {
	Swap(Partial),
	Dca { last: u32, budget: Balance },
}

/// Which `IntentDataInput` a `SubmitIntent` builds; the rest of the action is shared.
#[derive(crate::arbitrary::Arbitrary, Debug, Clone, Copy)]
pub enum IntentKind {
	Swap,
	/// Match-first swap, offered only against opposite flow for `(1 + window)` seconds.
	MatchFirst { window: u8 },
	/// ICE DCA: `amount_in` per trade every `15 + period` blocks, `budget` = 1..=4 trades (None = rolling),
	/// slippage `slip % 51` %. Settles early only against opposite flow (`DcaEarlyWindow`).
	Dca { period: u8, budget: Option<u8>, slip: u8 },
}

fn free(asset: AssetId, who: &AccountId) -> i128 {
	<Currencies as MultiCurrency<AccountId>>::free_balance(asset, who) as i128
}

fn reserved(asset: AssetId, who: &AccountId) -> i128 {
	<Currencies as NamedMultiReservableCurrency<AccountId>>::reserved_balance_named(&pallet_intent::NAMED_RESERVE_ID, asset, who) as i128
}

/// `submit_solution` plus the settlement oracle: each owner pays exactly the resolved `amount_in`
/// out of their reserve and receives exactly `amount_out`; fully filled intents are gone; the
/// holding pot and the fee receiver never lose funds.
fn settle(cfg: &oracle::Config, solution: &Solution) -> Result<(), ()> {
	if !cfg.ice {
		return pallet_ice::Pallet::<Runtime>::submit_solution(RuntimeOrigin::none(), solution.clone()).map(|_| ()).map_err(|_| ());
	}
	let pot = pallet_ice::Pallet::<Runtime>::get_pallet_account();
	let fee_receiver = <Runtime as pallet_ice::Config>::FeeReceiver::get();
	// (owner, asset) -> expected change of free balance and of free + reserved.
	let mut expect: BTreeMap<(AccountId, AssetId), (i128, i128)> = BTreeMap::new();
	// A DCA fill may unreserve the rest of its budget (last trade) or re-reserve from free (rolling):
	// free of `asset_in` is unpredictable for these keys, free + reserved still is.
	let mut free_unknown: Vec<(AccountId, AssetId)> = vec![];
	let mut pre: Vec<(u128, AccountId, Option<Pre>)> = vec![];
	for r in &solution.resolved_intents {
		let Some(owner) = pallet_intent::Pallet::<Runtime>::intent_owner(r.id) else { continue };
		let (ai, ao, x, y) = (r.data.asset_in(), r.data.asset_out(), r.data.amount_in() as i128, r.data.amount_out() as i128);
		// The resolved amount leaves the owner's named reserve (free is untouched); for ERC20-backed
		// assets the funds moved at submit time but the reserve counter still drops here.
		expect.entry((owner.clone(), ai)).or_default().1 -= x;
		let e_out = expect.entry((owner.clone(), ao)).or_default();
		e_out.0 += y;
		e_out.1 += y;
		let state = pallet_intent::Intents::<Runtime>::get(r.id).map(|i| match i.data {
			IntentData::Dca(d) => {
				free_unknown.push((owner.clone(), ai));
				Pre::Dca { last: d.last_execution_block, budget: d.remaining_budget }
			}
			other => Pre::Swap(other.swap().map(|s| s.partial).unwrap_or(Partial::No)),
		});
		pre.push((r.id, owner, state));
	}
	let assets: Vec<AssetId> = { let mut a: Vec<_> = expect.keys().map(|k| k.1).collect(); a.sort(); a.dedup(); a };
	let before: BTreeMap<(AccountId, AssetId), (i128, i128)> = expect
		.keys()
		.map(|k| (k.clone(), (free(k.1, &k.0), free(k.1, &k.0) + reserved(k.1, &k.0))))
		.collect();
	let pot0: Vec<i128> = assets.iter().map(|a| free(*a, &pot)).collect();
	let fee0: Vec<i128> = assets.iter().map(|a| free(*a, &fee_receiver)).collect();

	if let Err(e) = pallet_ice::Pallet::<Runtime>::submit_solution(RuntimeOrigin::none(), solution.clone()) {
		log!("  submit_solution rejected: {:?}", e.error);
		return Err(());
	}

	let dca = pre.iter().filter(|(_, _, s)| matches!(s, Some(Pre::Dca { .. }))).count();
	log!("  settled {} intents ({dca} DCA)", pre.len());
	for (k, (d_free, d_total)) in &expect {
		let (f0, t0) = before[k];
		let (f1, t1) = (free(k.1, &k.0), free(k.1, &k.0) + reserved(k.1, &k.0));
		let tol = if oracle::is_contract_ledger(k.1) { 2 } else { 0 };
		let free_ok = free_unknown.contains(k) || (f1 - f0 - d_free).abs() <= tol;
		if !free_ok || (t1 - t0 - d_total).abs() > tol {
			oracle::violation(
				"ice_settlement",
				format!(
					"owner {:?} asset {}: free moved {} (expected {d_free}), free+reserved moved {} (expected {d_total})",
					k.0, k.1, f1 - f0, t1 - t0
				),
			);
		}
	}
	for (i, a) in assets.iter().enumerate() {
		if free(*a, &pot) < pot0[i] {
			oracle::violation("ice_settlement", format!("holding pot lost asset {a}: {} -> {}", pot0[i], free(*a, &pot)));
		}
		if free(*a, &fee_receiver) < fee0[i] {
			oracle::violation("ice_settlement", format!("fee receiver lost asset {a}: {} -> {}", fee0[i], free(*a, &fee_receiver)));
		}
	}
	for (id, owner, state) in pre {
		let still = pallet_intent::Intents::<Runtime>::get(id);
		match (state, still) {
			(Some(Pre::Swap(Partial::No)), Some(_)) => oracle::violation("ice_settlement", format!("all-or-nothing intent {id} of {owner:?} still stored after resolution")),
			(Some(Pre::Swap(Partial::Yes(filled))), Some(i)) => {
				let now = i.data.swap().map(|s| s.partial).unwrap_or(Partial::No);
				if !matches!(now, Partial::Yes(f) if f > filled) {
					oracle::violation("ice_settlement", format!("partial intent {id} of {owner:?} filled amount did not increase: {filled} -> {now:?}"));
				}
			}
			(Some(Pre::Dca { last, budget }), Some(i)) => {
				let IntentData::Dca(d) = i.data else {
					oracle::violation("ice_settlement", format!("DCA intent {id} of {owner:?} changed variant after resolution"));
					continue;
				};
				// A fill consumes its slot (early ones too) and spends one trade of budget; a rolling
				// re-reserve may top it back up, never above.
				if d.last_execution_block <= last || d.remaining_budget > budget || d.remaining_budget < d.amount_in {
					oracle::violation("ice_settlement", format!("DCA intent {id} of {owner:?}: last block {last} -> {}, budget {budget} -> {} (per trade {})", d.last_execution_block, d.remaining_budget, d.amount_in));
				}
			}
			_ => {}
		}
	}
	Ok(())
}

/// A fuzzed solution the pallet accepts must still satisfy the independent oracle, otherwise
/// the validator is the bug.
pub fn submit_raw_solution(cfg: &oracle::Config, bytes: &[u8]) {
	let Ok(mut solution) = Solution::decode_with_depth_limit(16, &mut &bytes[..]) else { return };
	let originals = valid_intents(cfg);
	// Point the fuzzed solution at intents that exist, so it gets past the id check.
	for (r, o) in solution.resolved_intents.iter_mut().zip(originals.iter()) {
		r.id = o.id;
	}
	submit_fuzzed(cfg, "raw", &originals, &solution);
}
