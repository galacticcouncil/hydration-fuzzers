//! Scenario model: fuzz bytes -> `Scenario { flags, actions }` via `arbitrary`, and execution.

use crate::evm::{self as e, Token};
use crate::oracle::{self, Trade};
use crate::tables::{pick, u, Tables};
use crate::{actor, actor_evm, block, ice, log, AccountId, AssetId, Balance, Runtime, RuntimeCall, RuntimeOrigin};
use arbitrary::{Arbitrary, Unstructured};
use codec::DecodeLimit;
use frame_support::dispatch::GetDispatchInfo;
use frame_support::weights::constants::WEIGHT_REF_TIME_PER_SECOND;
use hydradx_traits::router::{PoolType, Trade as Hop};
use orml_traits::MultiCurrency;
use sp_core::{H160, U256};
use sp_runtime::traits::Dispatchable;
use std::time::{Duration, Instant};

/// Length-prefixed bytes (unlike `Vec<u8>`'s per-element continuation bytes), so a SCALE-encoded
/// call stays contiguous in the input and AFL can splice it.
#[derive(Clone)]
pub struct Bytes(pub Vec<u8>);

impl<'a> Arbitrary<'a> for Bytes {
	fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
		// Capped so one raw call / calldata / solution cannot swallow the rest of the input and end
		// the scenario early (a SCALE call or ABI calldata rarely exceeds ~200 bytes).
		let n = (u.arbitrary::<u16>()? as usize % 256).min(u.len());
		Ok(Bytes(u.bytes(n)?.to_vec()))
	}
}

impl std::fmt::Debug for Bytes {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "0x{}", self.0.iter().map(|b| format!("{b:02x}")).collect::<String>())
	}
}

#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum Amount {
	/// f/255 of the relevant balance.
	Frac(u8),
	/// m * 10^(decimals - 4 + e%8): human-scale amounts.
	Units { m: u16, e: u8 },
	Raw(u128),
}

impl Amount {
	pub fn resolve(self, balance: Balance, decimals: u8) -> Balance {
		match self {
			Amount::Frac(f) => balance / 255 * f as u128 + balance % 255 * f as u128 / 255,
			Amount::Units { m, e } => {
				(m as u128).saturating_mul(10u128.saturating_pow((decimals as u32 + (e % 8) as u32).saturating_sub(4)))
			}
			Amount::Raw(x) => x,
		}
	}
}

#[derive(Arbitrary, Debug, Clone, Copy)]
pub struct Flags {
	pub circuit_breaker_off: bool,
	/// Run the solver and settle at the end of every block that has valid intents.
	pub solve_each_block: bool,
	/// Single-actor mode: every acting account (`who`, `origin`, the liquidator) is this actor.
	/// Victims, impersonated EVM senders and other targets stay as fuzzed.
	pub actor: Option<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum Action {
	Raw { origin: u8, call: Bytes },
	Lapse(u16),
	OmnipoolSell { who: u8, asset_in: u16, asset_out: u16, amount: Amount },
	OmnipoolBuy { who: u8, asset_in: u16, asset_out: u16, amount: Amount },
	OmnipoolAdd { who: u8, asset: u16, amount: Amount },
	/// Removes from one of the most recently created positions.
	OmnipoolRemove { who: u8, back: u8, amount: Amount },
	StableSell { who: u8, pool: u8, i_in: u8, i_out: u8, amount: Amount },
	StableBuy { who: u8, pool: u8, i_in: u8, i_out: u8, amount: Amount },
	StableAdd { who: u8, pool: u8, i: u8, amount: Amount },
	StableRemove { who: u8, pool: u8, i: u8, shares: Amount },
	XykSell { who: u8, pool: u16, flip: bool, amount: Amount },
	XykBuy { who: u8, pool: u16, flip: bool, amount: Amount },
	XykAdd { who: u8, pool: u16, amount: Amount },
	XykRemove { who: u8, pool: u16, shares: Amount },
	/// Router trade. Empty `hops` = use the on-chain stored route.
	Router { who: u8, sell: bool, asset_in: u16, asset_out: u16, amount: Amount, hops: Vec<(u8, u16)> },
	/// Router trade on a single Aave hop: supply (underlying -> aToken) or withdraw.
	AaveTrade { who: u8, reserve: u8, supply: bool, amount: Amount },
	AavePool { who: u8, op: AaveOp, reserve: u8, other: u8, user: u8, amount: Amount },
	UniswapTrade { who: u8, pool: u8, zero_for_one: bool, sell: bool, amount: Amount },
	UniswapQuote { pool: u8, zero_for_one: bool, amount: Amount },
	HsmTrade { who: u8, collateral: u8, sell: bool, hollar_in: bool, amount: Amount },
	HsmArbitrage { collateral: u8 },
	GigaStake { who: u8, amount: Amount },
	GigaUnstake { who: u8, amount: Amount },
	Liquidate { collateral: u8, debt: u8, user: u8, amount: Amount },
	OtcPlace { who: u8, asset_in: u16, asset_out: u16, amount_in: Amount, amount_out: Amount, partial: bool },
	OtcFill { who: u8, back: u8, partial: Option<Amount> },
	Dca { who: u8, sell: bool, asset_in: u16, asset_out: u16, amount: Amount, total: Amount, period: u8 },
	EvmCall { who: u8, target: Target, data: Calldata, value: u64, gas: u32 },
	Impersonate { from: u16, target: Target, data: Calldata, gas: u32 },
	DispatchEvm { who: u8, target: Target, data: Calldata },
	/// `limit` picks the min-out policy relative to the router quote: 0..=5 loose (half), 6 at spot,
	/// 7..=8 tight (up to 5% under spot), 9 impossible (double). Random limits never solve.
	SubmitIntent { who: u8, asset_in: u16, asset_out: u16, amount_in: Amount, limit: u8, partial: bool },
	SolveAndSubmit,
	SubmitSolution(Bytes),
	RemoveIntent { who: u8, back: u8 },
	/// Related Aave operations on one actor/reserve: supply `amount` of the underlying, advance
	/// `lapse` blocks (0 = same block), withdraw `amount` resolved against the live aToken balance.
	/// A failed supply is not fatal; the withdrawal then runs on whatever aTokens the actor holds.
	AaveLifecycle { who: u8, reserve: u8, amount: Amount, lapse: u8 },
	/// Self-contained ICE round: submit up to 6 intents (each as `SubmitIntent`), advance `lapse`
	/// blocks, run the solver and settle. With `mutate`, a nudged copy of the solver's solution is
	/// thrown at the pallet validator first.
	IceRound { intents: Vec<IntentSpec>, lapse: u8, mutate: Option<u8> },
}

#[derive(Arbitrary, Debug, Clone, Copy)]
pub struct IntentSpec {
	pub who: u8,
	pub asset_in: u16,
	pub asset_out: u16,
	pub amount_in: Amount,
	pub limit: u8,
	pub partial: bool,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum AaveOp {
	Supply,
	Withdraw,
	Borrow,
	Repay,
	SetCollateral(bool),
	LiquidationCall(bool),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum Target {
	Known(u16),
	Any([u8; 20]),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum Calldata {
	Abi { selector: u8, args: Vec<Arg> },
	Raw(Bytes),
}

#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum Arg {
	User(u16),
	Contract(u16),
	Amount(Amount),
	Word([u8; 32]),
	Bool(bool),
}

/// Selectors the ABI generator knows. Contracts on chain are fixed; this only shapes calldata.
const SIGNATURES: &[&str] = &[
	"transfer(address,uint256)",
	"approve(address,uint256)",
	"transferFrom(address,address,uint256)",
	"balanceOf(address)",
	"totalSupply()",
	"allowance(address,address)",
	"supply(address,uint256,address,uint16)",
	"withdraw(address,uint256,address)",
	"borrow(address,uint256,uint256,uint16,address)",
	"repay(address,uint256,uint256,address)",
	"repayWithATokens(address,uint256,uint256)",
	"liquidationCall(address,address,address,uint256,bool)",
	"setUserUseReserveAsCollateral(address,bool)",
	"setUserEMode(uint8)",
	"flashLoanSimple(address,address,uint256,bytes,uint16)",
	"getUserAccountData(address)",
	"getReserveData(address)",
	"scaledTotalSupply()",
	"scaledBalanceOf(address)",
	"exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
	"exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))",
	"quoteExactInputSingle((address,address,uint256,uint24,uint160))",
	"quoteExactOutputSingle((address,address,uint256,uint24,uint160))",
	"getPool(address,address,uint24)",
	"slot0()",
	"liquidity()",
	"swap(address,bool,int256,uint160,bytes)",
	"flash(address,uint256,uint256,bytes)",
	"collect(address,int24,int24,uint128,uint128)",
	"deposit()",
	"permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
];

#[derive(Debug)]
pub struct Scenario {
	pub flags: Flags,
	pub actions: Vec<Action>,
}

impl Scenario {
	pub fn decode(data: &[u8]) -> Option<Self> {
		let mut u = Unstructured::new(data);
		let flags = Flags::arbitrary(&mut u).ok()?;
		let mut actions = Vec::new();
		while !u.is_empty() && actions.len() < crate::MAX_ACTIONS {
			match Action::arbitrary(&mut u) {
				// Zero bytes decode to variant 0 with empty fields: an empty raw call. AFL pads inputs
				// (-g min length, block inserts) with constant bytes, which would otherwise append
				// dozens of these no-ops; treat the first one as end of input instead.
				Ok(Action::Raw { call, .. }) if call.0.is_empty() => break,
				Ok(a) => actions.push(a),
				Err(_) => break,
			}
		}
		(!actions.is_empty()).then_some(Scenario { flags, actions })
	}
}

// ---------- execution ----------

pub fn execute(s: &Scenario, t: &Tables, cfg: &oracle::Config, first_block: u32) {
	let mut block = first_block;
	let t0 = Instant::now();
	block::initialize_block(block, None);
	log!("  init block {block}: {:?}", t0.elapsed());
	if s.flags.circuit_breaker_off {
		disable_circuit_breaker(t);
	}
	crate::set_actor_override(s.flags.actor);
	struct ResetActor;
	impl Drop for ResetActor {
		fn drop(&mut self) {
			crate::set_actor_override(None);
		}
	}
	let _reset = ResetActor;
	let mut started = Instant::now();
	let mut weight = 0u64;
	// Finalize the current block and start a new one `n + 1` blocks later; false = scenario dropped.
	let mut advance = |n: u16, block: &mut u32, started: &mut Instant, weight: &mut u64| -> bool {
		if s.flags.solve_each_block {
			guarded(cfg, || ice::solve_and_submit(cfg));
		}
		if !end_block(cfg, *block, started.elapsed(), false) {
			return false;
		}
		*block += 1 + u32::from(n);
		block::initialize_block(*block, None);
		*started = Instant::now();
		*weight = 0;
		true
	};
	for a in &s.actions {
		log!("> {a:?}");
		let t0 = Instant::now();
		match a {
			Action::Lapse(n) => {
				if !advance(*n, &mut block, &mut started, &mut weight) {
					return;
				}
			}
			Action::AaveLifecycle { who, reserve, amount, lapse } => {
				let supply = Action::AaveTrade { who: *who, reserve: *reserve, supply: true, amount: *amount };
				guarded(cfg, || run_one(&supply, t, cfg, &mut weight));
				if *lapse > 0 && !advance(u16::from(*lapse) - 1, &mut block, &mut started, &mut weight) {
					return;
				}
				let withdraw = Action::AaveTrade { who: *who, reserve: *reserve, supply: false, amount: *amount };
				guarded(cfg, || run_one(&withdraw, t, cfg, &mut weight));
			}
			Action::IceRound { intents, lapse, mutate } => {
				for i in intents.iter().take(6) {
					let a = Action::SubmitIntent { who: i.who, asset_in: i.asset_in, asset_out: i.asset_out, amount_in: i.amount_in, limit: i.limit, partial: i.partial };
					guarded(cfg, || run_one(&a, t, cfg, &mut weight));
				}
				if *lapse > 0 && !advance(u16::from(*lapse) - 1, &mut block, &mut started, &mut weight) {
					return;
				}
				guarded(cfg, || {
					if let Some((originals, solution)) = ice::solve() {
						if let Some(m) = mutate {
							ice::submit_mutated(cfg, &originals, &solution, *m);
						}
						ice::submit_solver_solution(cfg, &originals, solution);
					}
				});
			}
			a => guarded(cfg, || run_one(a, t, cfg, &mut weight)),
		}
		log!("  ({:?})", t0.elapsed());
	}
	if s.flags.solve_each_block {
		guarded(cfg, || ice::solve_and_submit(cfg));
	}
	let _ = end_block(cfg, block, started.elapsed(), true);
}

fn run_one(a: &Action, t: &Tables, cfg: &oracle::Config, weight: &mut u64) {
	match a {
			Action::Raw { origin, call } => {
				let Ok(call) = RuntimeCall::decode_with_depth_limit(64, &mut &call.0[..]) else { return };
				if !raw_allowed(&call) {
					log!("  skipped by filter");
					return;
				}
				let info = call.get_dispatch_info();
				*weight = weight.saturating_add(info.call_weight.ref_time() + info.extension_weight.ref_time());
				if *weight >= 2 * WEIGHT_REF_TIME_PER_SECOND {
					log!("  skipped: block weight");
					return;
				}
				let origin = if origin % 100 < 15 {
					RuntimeOrigin::none()
				} else {
					RuntimeOrigin::signed(actor(*origin))
				};
				log!("  call: {call:?}");
				let r = call.dispatch(origin);
				log!("  => {:?}", r.map(|_| ()).map_err(|e| e.error));
			}
			a => run(a, t, cfg),
	}
}

const SENTINEL: &[u8] = b":fuzz:action-layer:";

/// Run one action in its own storage layer. A panic whose message matches a known, already
/// reported issue (`oracle::Config::known_panics`) rolls the action back instead of ending the
/// scenario, so one noisy debug_assert doesn't stop the fuzzer from exploring past it.
fn guarded(cfg: &oracle::Config, f: impl FnOnce()) {
	use sp_io::storage;
	if cfg.known_panics.is_empty() {
		return f();
	}
	storage::set(SENTINEL, &[0]);
	storage::start_transaction();
	storage::set(SENTINEL, &[1]);
	thread_local!(static AT: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) });
	let hook = std::panic::take_hook();
	std::panic::set_hook(Box::new(|i| {
		let at = i.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
		AT.with(|a| *a.borrow_mut() = at);
	}));
	let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
	std::panic::set_hook(hook);
	match r {
		Ok(()) => storage::commit_transaction(),
		Err(p) => {
			let msg = p.downcast_ref::<String>().map(String::as_str).or_else(|| p.downcast_ref::<&str>().copied()).unwrap_or("");
			if !cfg.known_panics.iter().any(|k| msg.contains(k.as_str())) {
				// Re-raise with the original location (our silent hook swallowed it).
				panic!("{msg}\n  at {}", AT.with(|a| a.borrow().clone()));
			}
			log!("  known issue, action rolled back: {msg}");
			// Unwinding leaves the dispatch's own transaction layers open; drop them and ours.
			while storage::get(SENTINEL).as_deref() == Some(&[1][..]) {
				storage::rollback_transaction();
			}
		}
	}
	storage::clear(SENTINEL);
}

/// Finalize the block and run the per-block oracles. A known panic raised from a block hook
/// (`on_idle`/`on_finalize`, e.g. fee-processor converting aToken fees) cannot be rolled back like an
/// action, so the scenario is dropped instead: returns `false` and the caller stops.
fn end_block(cfg: &oracle::Config, block: u32, elapsed: Duration, last: bool) -> bool {
	if elapsed > cfg.max_block_time {
		oracle::violation("block_time", format!("block {block} took {elapsed:?}"));
	}
	let t0 = Instant::now();
	let hook = std::panic::take_hook();
	std::panic::set_hook(Box::new(|_| {}));
	let r = std::panic::catch_unwind(block::finalize_block);
	std::panic::set_hook(hook);
	if let Err(p) = r {
		let msg = p.downcast_ref::<String>().map(String::as_str).or_else(|| p.downcast_ref::<&str>().copied()).unwrap_or("");
		if cfg.known_panics.iter().any(|k| msg.contains(k.as_str())) {
			log!("  known issue in block hook, scenario dropped: {msg}");
			return false;
		}
		std::panic::resume_unwind(p);
	}
	let t1 = Instant::now();
	oracle::after_block(cfg, block, last);
	log!("  finalize {:?}, try_state {:?}", t1 - t0, t1.elapsed());
	true
}

fn disable_circuit_breaker(t: &Tables) {
	use pallet_circuit_breaker::Pallet as CB;
	for &a in t.assets.iter() {
		let _ = CB::<Runtime>::set_trade_volume_limit(RuntimeOrigin::root(), a, (10_000, 1));
		let _ = CB::<Runtime>::set_add_liquidity_limit(RuntimeOrigin::root(), a, None);
		let _ = CB::<Runtime>::set_remove_liquidity_limit(RuntimeOrigin::root(), a, None);
	}
}

/// Same skip rules as the legacy runtime-fuzzer, so its coverage carries over.
pub fn raw_allowed(call: &RuntimeCall) -> bool {
	!find_call(call, &|c| {
		matches!(
			c,
			RuntimeCall::System(_) | RuntimeCall::XTokens(_) | RuntimeCall::Timestamp(_) | RuntimeCall::ParachainSystem(_)
		) || is_zero_fee_xcm_execute(c)
	})
}

fn is_zero_fee_xcm_execute(c: &RuntimeCall) -> bool {
	use staging_xcm::v5::{Asset, Fungibility, Instruction};
	let RuntimeCall::PolkadotXcm(pallet_xcm::Call::execute { message, .. }) = c else { return false };
	let staging_xcm::VersionedXcm::V5(xcm) = message.as_ref() else { return false };
	xcm.0.iter().any(|i| {
		matches!(i, Instruction::BuyExecution { fees: Asset { fun: Fungibility::Fungible(0), .. }, .. })
	})
}

fn find_call(call: &RuntimeCall, f: &dyn Fn(&RuntimeCall) -> bool) -> bool {
	match call {
		RuntimeCall::Utility(
			pallet_utility::Call::batch { calls }
			| pallet_utility::Call::force_batch { calls }
			| pallet_utility::Call::batch_all { calls },
		) => calls.iter().any(|c| find_call(c, f)),
		RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 { call, .. })
		| RuntimeCall::Utility(pallet_utility::Call::as_derivative { call, .. })
		| RuntimeCall::Proxy(pallet_proxy::Call::proxy { call, .. })
		| RuntimeCall::Dispatcher(pallet_dispatcher::Call::dispatch_with_extra_gas { call, .. })
		| RuntimeCall::Dispatcher(pallet_dispatcher::Call::dispatch_evm_call { call })
		| RuntimeCall::Dispatcher(pallet_dispatcher::Call::dispatch_with_fee_payer { call })
		| RuntimeCall::Dispatcher(pallet_dispatcher::Call::dispatch_as_treasury { call })
		| RuntimeCall::Dispatcher(pallet_dispatcher::Call::dispatch_as_aave_manager { call })
		| RuntimeCall::Dispatcher(pallet_dispatcher::Call::dispatch_as_emergency_admin { call }) => find_call(call, f),
		c => f(c),
	}
}

pub fn bal(asset: AssetId, who: &AccountId) -> Balance {
	hydradx_runtime::Currencies::free_balance(asset, who)
}

fn dispatch(call: RuntimeCall, origin: RuntimeOrigin) -> bool {
	log!("  call: {call:?}");
	let r = call.dispatch(origin);
	log!("  => {:?}", r.map(|_| ()).map_err(|e| e.error));
	r.is_ok()
}

/// Dispatch a signed trade and run the per-trade oracles on it.
fn trade(cfg: &oracle::Config, trade: Trade, call: RuntimeCall) {
	let who = trade.who.clone();
	oracle::check_trade(cfg, trade, || dispatch(call, RuntimeOrigin::signed(who)));
}

fn pool_kind(t: &Tables, k: u8) -> PoolType<AssetId> {
	match k % 7 {
		0 => PoolType::Omnipool,
		1 => PoolType::Stableswap(pick(&t.stable_pools, k / 7).map(|p| p.0).unwrap_or_default()),
		2 => PoolType::XYK,
		3 => PoolType::Aave,
		4 => PoolType::HSM,
		5 => PoolType::UniswapV3(pick(&t.uni_pools, k / 7).map(|p| p.fee).unwrap_or(3000)),
		_ => PoolType::LBP,
	}
}

fn route(t: &Tables, asset_in: AssetId, asset_out: AssetId, hops: &[(u8, u16)]) -> Vec<Hop<AssetId>> {
	let mut from = asset_in;
	let n = hops.len().min(hydradx_traits::router::MAX_NUMBER_OF_TRADES as usize);
	hops[..n]
		.iter()
		.enumerate()
		.map(|(i, (k, a))| {
			let to = if i + 1 == n { asset_out } else { pick(&t.assets, *a).unwrap_or_default() };
			let hop = Hop {
				pool: pool_kind(t, *k),
				asset_in: from,
				asset_out: to,
			};
			from = to;
			hop
		})
		.collect()
}

/// Uniswap pool contracts on the route plus the swap router, which hold the EVM side of the funds.
fn evm_parties(t: &Tables, route: &[Hop<AssetId>]) -> Vec<H160> {
	let mut v: Vec<H160> = route
		.iter()
		.filter(|h| matches!(h.pool, PoolType::UniswapV3(_)))
		.filter_map(|h| {
			t.uni_pools
				.iter()
				.find(|p| (p.token0, p.token1) == (h.asset_in, h.asset_out) || (p.token1, p.token0) == (h.asset_in, h.asset_out))
				.map(|p| p.address)
		})
		.collect();
	if !v.is_empty() {
		v.extend(t.uniswap.get(1).copied());
	}
	v
}

fn router_call(sell: bool, asset_in: AssetId, asset_out: AssetId, amount: Balance, route: Vec<Hop<AssetId>>) -> RuntimeCall {
	let route = route.try_into().unwrap_or_default();
	RuntimeCall::Router(if sell {
		pallet_route_executor::Call::sell {
			asset_in,
			asset_out,
			amount_in: amount,
			min_amount_out: 0,
			route,
		}
	} else {
		pallet_route_executor::Call::buy {
			asset_in,
			asset_out,
			amount_out: amount,
			max_amount_in: Balance::MAX,
			route,
		}
	})
}

fn target(t: &Tables, tg: &Target) -> H160 {
	match tg {
		Target::Known(i) => pick(&t.contracts, *i).unwrap_or_default(),
		Target::Any(a) => H160(*a),
	}
}

fn calldata(t: &Tables, who: H160, data: &Calldata) -> Vec<u8> {
	match data {
		Calldata::Raw(b) => b.0.clone(),
		Calldata::Abi { selector, args } => {
			let sig = SIGNATURES[*selector as usize % SIGNATURES.len()];
			let args: Vec<Token> = args
				.iter()
				.take(8)
				.map(|a| match a {
					Arg::User(i) => Token::Address(pick(&t.users, *i).unwrap_or(who)),
					Arg::Contract(i) => Token::Address(pick(&t.contracts, *i).unwrap_or_default()),
					Arg::Amount(a) => u(a.resolve(u128::MAX, 18)),
					Arg::Word(w) => Token::Uint(U256::from_big_endian(w)),
					Arg::Bool(b) => Token::Bool(*b),
				})
				.collect();
			e::encode(sig, &args)
		}
	}
}

fn evm_call(source: H160, target: H160, input: Vec<u8>, value: U256, gas: u64) -> RuntimeCall {
	RuntimeCall::EVM(pallet_evm::Call::call {
		source,
		target,
		input,
		value,
		gas_limit: gas,
		max_fee_per_gas: {
			use pallet_evm::FeeCalculator;
			<Runtime as pallet_evm::Config>::FeeCalculator::min_gas_price().0
		},
		max_priority_fee_per_gas: None,
		nonce: None,
		access_list: vec![],
		authorization_list: vec![],
	})
}

fn run(a: &Action, t: &Tables, cfg: &oracle::Config) {
	use Action::*;
	match a {
		OmnipoolSell { who, asset_in, asset_out, amount } | OmnipoolBuy { who, asset_in, asset_out, amount } => {
			let (Some(ai), Some(ao)) = (pick(&t.omnipool, *asset_in), pick(&t.omnipool, *asset_out)) else { return };
			let w = actor(*who);
			let sell = matches!(a, OmnipoolSell { .. });
			let amt = if sell {
				amount.resolve(bal(ai, &w), t.decimals(ai))
			} else {
				amount.resolve(bal(ao, &w), t.decimals(ao))
			};
			let call = if sell {
				pallet_omnipool::Call::sell {
					asset_in: ai,
					asset_out: ao,
					amount: amt,
					min_buy_amount: 0,
				}
			} else {
				pallet_omnipool::Call::buy {
					asset_out: ao,
					asset_in: ai,
					amount: amt,
					max_sell_amount: Balance::MAX,
				}
			};
			trade(cfg, Trade::new(w, ai, ao, PoolType::Omnipool, sell, amt), RuntimeCall::Omnipool(call));
		}
		OmnipoolAdd { who, asset, amount } => {
			let Some(asset) = pick(&t.omnipool, *asset) else { return };
			let w = actor(*who);
			let amount = amount.resolve(bal(asset, &w), t.decimals(asset));
			dispatch(
				RuntimeCall::Omnipool(pallet_omnipool::Call::add_liquidity { asset, amount }),
				RuntimeOrigin::signed(w),
			);
		}
		OmnipoolRemove { who, back, amount } => {
			let next = hydradx_runtime::Omnipool::next_position_id();
			let Some(position_id) = next.checked_sub(1 + (*back % 8) as u128) else { return };
			let w = actor(*who);
			let shares = pallet_omnipool::Pallet::<Runtime>::load_position(position_id, w.clone())
				.map(|p| p.shares)
				.unwrap_or_default();
			let amount = amount.resolve(shares, 12);
			dispatch(
				RuntimeCall::Omnipool(pallet_omnipool::Call::remove_liquidity { position_id, amount }),
				RuntimeOrigin::signed(w),
			);
		}
		StableSell { who, pool, i_in, i_out, amount } | StableBuy { who, pool, i_in, i_out, amount } => {
			let Some((pool_id, assets)) = pick(&t.stable_pools, *pool) else { return };
			let (Some(ai), Some(ao)) = (pick(&assets, *i_in), pick(&assets, *i_out)) else { return };
			let w = actor(*who);
			let sell = matches!(a, StableSell { .. });
			let call = if sell {
				let amount_in = amount.resolve(bal(ai, &w), t.decimals(ai));
				(
					amount_in,
					pallet_stableswap::Call::sell {
						pool_id,
						asset_in: ai,
						asset_out: ao,
						amount_in,
						min_buy_amount: 0,
					},
				)
			} else {
				let amount_out = amount.resolve(bal(ao, &w), t.decimals(ao));
				(
					amount_out,
					pallet_stableswap::Call::buy {
						pool_id,
						asset_out: ao,
						asset_in: ai,
						amount_out,
						max_sell_amount: Balance::MAX,
					},
				)
			};
			trade(
				cfg,
				Trade::new(w, ai, ao, PoolType::Stableswap(pool_id), sell, call.0),
				RuntimeCall::Stableswap(call.1),
			);
		}
		StableAdd { who, pool, i, amount } => {
			let Some((pool_id, assets)) = pick(&t.stable_pools, *pool) else { return };
			let Some(asset_id) = pick(&assets, *i) else { return };
			let w = actor(*who);
			let amount = amount.resolve(bal(asset_id, &w), t.decimals(asset_id));
			let assets = vec![hydradx_traits::stableswap::AssetAmount { asset_id, amount }];
			dispatch(
				RuntimeCall::Stableswap(pallet_stableswap::Call::add_assets_liquidity {
					pool_id,
					assets: assets.try_into().unwrap(),
					min_shares: 0,
				}),
				RuntimeOrigin::signed(w),
			);
		}
		StableRemove { who, pool, i, shares } => {
			let Some((pool_id, assets)) = pick(&t.stable_pools, *pool) else { return };
			let Some(asset_id) = pick(&assets, *i) else { return };
			let w = actor(*who);
			let share_amount = shares.resolve(bal(pool_id, &w), 18);
			dispatch(
				RuntimeCall::Stableswap(pallet_stableswap::Call::remove_liquidity_one_asset {
					pool_id,
					asset_id,
					share_amount,
					min_amount_out: 0,
				}),
				RuntimeOrigin::signed(w),
			);
		}
		XykSell { who, pool, flip, amount } | XykBuy { who, pool, flip, amount } => {
			let Some((mut ai, mut ao)) = pick(&t.xyk_pools, *pool) else { return };
			if *flip {
				std::mem::swap(&mut ai, &mut ao);
			}
			let w = actor(*who);
			let sell = matches!(a, XykSell { .. });
			let (amt, call) = if sell {
				let amount = amount.resolve(bal(ai, &w), t.decimals(ai));
				(
					amount,
					pallet_xyk::Call::sell {
						asset_in: ai,
						asset_out: ao,
						amount,
						max_limit: 0,
						discount: false,
					},
				)
			} else {
				let amount = amount.resolve(bal(ao, &w), t.decimals(ao));
				(
					amount,
					pallet_xyk::Call::buy {
						asset_out: ao,
						asset_in: ai,
						amount,
						max_limit: Balance::MAX,
						discount: false,
					},
				)
			};
			trade(cfg, Trade::new(w, ai, ao, PoolType::XYK, sell, amt), RuntimeCall::XYK(call));
		}
		XykAdd { who, pool, amount } => {
			let Some((asset_a, asset_b)) = pick(&t.xyk_pools, *pool) else { return };
			let w = actor(*who);
			let amount_a = amount.resolve(bal(asset_a, &w), t.decimals(asset_a));
			dispatch(
				RuntimeCall::XYK(pallet_xyk::Call::add_liquidity {
					asset_a,
					asset_b,
					amount_a,
					amount_b_max_limit: Balance::MAX,
				}),
				RuntimeOrigin::signed(w),
			);
		}
		XykRemove { who, pool, shares } => {
			let Some((asset_a, asset_b)) = pick(&t.xyk_pools, *pool) else { return };
			let w = actor(*who);
			let pair = pallet_xyk::Pallet::<Runtime>::pair_account_from_assets(asset_a, asset_b);
			let share = pallet_xyk::Pallet::<Runtime>::share_token(pair);
			let share_amount = shares.resolve(bal(share, &w), 12);
			dispatch(
				RuntimeCall::XYK(pallet_xyk::Call::remove_liquidity {
					asset_a,
					asset_b,
					share_amount,
				}),
				RuntimeOrigin::signed(w),
			);
		}
		Router { who, sell, asset_in, asset_out, amount, hops } => {
			let (Some(ai), Some(ao)) = (pick(&t.assets, *asset_in), pick(&t.assets, *asset_out)) else { return };
			let w = actor(*who);
			let amt = if *sell {
				amount.resolve(bal(ai, &w), t.decimals(ai))
			} else {
				amount.resolve(bal(ao, &w), t.decimals(ao))
			};
			let r = route(t, ai, ao, hops);
			let mut tr = Trade::new(w, ai, ao, PoolType::Omnipool, *sell, amt);
			tr.sim = match r.as_slice() {
				[single] => Some(single.pool),
				_ => None,
			};
			tr.evm_accounts = evm_parties(t, &r);
			tr.route = r.clone();
			trade(cfg, tr, router_call(*sell, ai, ao, amt, r));
		}
		AaveTrade { who, reserve, supply, amount } => {
			let Some(r) = pick(&t.reserves, *reserve) else { return };
			let (Some(u_asset), Some(a_asset)) = (r.asset, r.atoken_asset) else { return };
			let (ai, ao) = if *supply { (u_asset, a_asset) } else { (a_asset, u_asset) };
			let w = actor(*who);
			let amt = amount.resolve(bal(ai, &w), t.decimals(ai));
			let hop = vec![Hop {
				pool: PoolType::Aave,
				asset_in: ai,
				asset_out: ao,
			}];
			trade(cfg, Trade::new(w, ai, ao, PoolType::Aave, true, amt), router_call(true, ai, ao, amt, hop));
		}
		AavePool { who, op, reserve, other, user, amount } => aave_pool(t, cfg, *who, *op, *reserve, *other, *user, *amount),
		UniswapTrade { who, pool, zero_for_one, sell, amount } => {
			let Some(p) = pick(&t.uni_pools, *pool) else { return };
			let (ai, ao) = if *zero_for_one { (p.token0, p.token1) } else { (p.token1, p.token0) };
			let w = actor(*who);
			let amt = if *sell {
				amount.resolve(bal(ai, &w), t.decimals(ai))
			} else {
				amount.resolve(bal(ao, &w), t.decimals(ao))
			};
			let pool = PoolType::UniswapV3(p.fee);
			let hop = vec![Hop {
				pool,
				asset_in: ai,
				asset_out: ao,
			}];
			let mut tr = Trade::new(w, ai, ao, pool, *sell, amt);
			tr.evm_accounts = evm_parties(t, &hop);
			trade(cfg, tr, router_call(*sell, ai, ao, amt, hop));
		}
		UniswapQuote { pool, zero_for_one, amount } => {
			let (Some(p), Some(quoter)) = (pick(&t.uni_pools, *pool), t.uniswap.get(2).copied()) else { return };
			let (ai, ao) = if *zero_for_one { (p.token0, p.token1) } else { (p.token1, p.token0) };
			let map = <hydradx_runtime::evm::precompiles::erc20_mapping::HydraErc20Mapping as hydradx_traits::evm::Erc20Mapping<AssetId>>::asset_address;
			let amt = amount.resolve(u128::MAX, t.decimals(ai));
			let data = e::encode(
				"quoteExactInputSingle((address,address,uint256,uint24,uint160))",
				&[Token::Address(map(ai)), Token::Address(map(ao)), u(amt), u(p.fee as u128), u(0)],
			);
			let r = e::call_as(actor_evm(0), quoter, data, U256::zero(), 2_000_000);
			log!("  quote => {:?}", r.exit_reason);
		}
		HsmTrade { who, collateral, sell, hollar_in, amount } => {
			let Some(c) = pick(&t.hsm_collaterals, *collateral) else { return };
			let (ai, ao) = if *hollar_in { (t.hollar, c) } else { (c, t.hollar) };
			let w = actor(*who);
			let (amt, call) = if *sell {
				let amount_in = amount.resolve(bal(ai, &w), t.decimals(ai));
				(
					amount_in,
					pallet_hsm::Call::sell {
						asset_in: ai,
						asset_out: ao,
						amount_in,
						slippage_limit: 0,
					},
				)
			} else {
				let amount_out = amount.resolve(bal(ao, &w), t.decimals(ao));
				(
					amount_out,
					pallet_hsm::Call::buy {
						asset_in: ai,
						asset_out: ao,
						amount_out,
						slippage_limit: Balance::MAX,
					},
				)
			};
			trade(cfg, Trade::new(w, ai, ao, PoolType::HSM, *sell, amt), RuntimeCall::HSM(call));
		}
		HsmArbitrage { collateral } => {
			let Some(collateral_asset_id) = pick(&t.hsm_collaterals, *collateral) else { return };
			dispatch(
				RuntimeCall::HSM(pallet_hsm::Call::execute_arbitrage {
					collateral_asset_id,
					arbitrage: None,
				}),
				RuntimeOrigin::none(),
			);
		}
		GigaStake { who, amount } => {
			let w = actor(*who);
			let amount = amount.resolve(bal(0, &w), 12);
			dispatch(RuntimeCall::GigaHdx(pallet_gigahdx::Call::giga_stake { amount }), RuntimeOrigin::signed(w));
		}
		GigaUnstake { who, amount } => {
			let w = actor(*who);
			let gigahdx_amount = amount.resolve(bal(0, &w), 12);
			dispatch(
				RuntimeCall::GigaHdx(pallet_gigahdx::Call::giga_unstake { gigahdx_amount }),
				RuntimeOrigin::signed(w),
			);
		}
		Liquidate { collateral, debt, user, amount } => {
			let (Some(c), Some(d)) = (pick(&t.reserves, *collateral), pick(&t.reserves, *debt)) else { return };
			let (Some(collateral_asset), Some(debt_asset)) = (c.asset, d.asset) else { return };
			let user = pick(&t.users, *user).unwrap_or_default();
			let debt_to_cover = amount.resolve(u128::MAX, t.decimals(debt_asset));
			dispatch(
				RuntimeCall::Liquidation(pallet_liquidation::Call::liquidate {
					collateral_asset,
					debt_asset,
					user,
					debt_to_cover,
					route: Default::default(),
				}),
				RuntimeOrigin::signed(actor(0)),
			);
		}
		OtcPlace { who, asset_in, asset_out, amount_in, amount_out, partial } => {
			let (Some(ai), Some(ao)) = (pick(&t.assets, *asset_in), pick(&t.assets, *asset_out)) else { return };
			let w = actor(*who);
			// OTC `asset_in` is what the maker wants; it sells `asset_out`.
			let amount_out = amount_out.resolve(bal(ao, &w), t.decimals(ao));
			let amount_in = amount_in.resolve(u128::MAX, t.decimals(ai));
			dispatch(
				RuntimeCall::OTC(pallet_otc::Call::place_order {
					asset_in: ai,
					asset_out: ao,
					amount_in,
					amount_out,
					partially_fillable: *partial,
				}),
				RuntimeOrigin::signed(w),
			);
		}
		OtcFill { who, back, partial } => {
			let Some(order_id) = hydradx_runtime::OTC::next_order_id().checked_sub(1 + (*back % 8) as u32) else { return };
			let Some(order) = hydradx_runtime::OTC::orders(order_id) else { return };
			let w = actor(*who);
			let call = match partial {
				None => pallet_otc::Call::fill_order { order_id },
				Some(a) => pallet_otc::Call::partial_fill_order {
					order_id,
					amount_in: a.resolve(bal(order.asset_in, &w), t.decimals(order.asset_in)),
				},
			};
			dispatch(RuntimeCall::OTC(call), RuntimeOrigin::signed(w));
		}
		Dca { who, sell, asset_in, asset_out, amount, total, period } => {
			let (Some(ai), Some(ao)) = (pick(&t.assets, *asset_in), pick(&t.assets, *asset_out)) else { return };
			let w = actor(*who);
			let amt = amount.resolve(bal(ai, &w), t.decimals(ai));
			let order = if *sell {
				pallet_dca::types::Order::Sell {
					asset_in: ai,
					asset_out: ao,
					amount_in: amt,
					min_amount_out: 0,
					route: Default::default(),
				}
			} else {
				pallet_dca::types::Order::Buy {
					asset_in: ai,
					asset_out: ao,
					amount_out: amount.resolve(bal(ao, &w), t.decimals(ao)),
					max_amount_in: Balance::MAX,
					route: Default::default(),
				}
			};
			let schedule = pallet_dca::types::Schedule {
				owner: w.clone(),
				period: u32::from(*period),
				total_amount: total.resolve(bal(ai, &w), t.decimals(ai)),
				max_retries: None,
				stability_threshold: None,
				slippage: None,
				order,
			};
			dispatch(
				RuntimeCall::DCA(pallet_dca::Call::schedule {
					schedule,
					start_execution_block: None,
				}),
				RuntimeOrigin::signed(w),
			);
		}
		EvmCall { who, target: tg, data, value, gas } => {
			let source = actor_evm(*who);
			let input = calldata(t, source, data);
			// Keep under the block gas limit, or every call dies in validation.
			let call = evm_call(source, target(t, tg), input, U256::from(*value), 21_000 + u64::from(*gas) % 5_000_000);
			dispatch(call, RuntimeOrigin::signed(actor(*who)));
		}
		Impersonate { from, target: tg, data, gas } => {
			let from = pick(&t.users, *from).unwrap_or_default();
			let r = e::call_as(from, target(t, tg), calldata(t, from, data), U256::zero(), u64::from(*gas) % 10_000_000);
			log!("  impersonate {from:?} => {:?}", r.exit_reason);
		}
		DispatchEvm { who, target: tg, data } => {
			let source = actor_evm(*who);
			let inner = evm_call(source, target(t, tg), calldata(t, source, data), U256::zero(), 1_000_000);
			dispatch(
				RuntimeCall::Dispatcher(pallet_dispatcher::Call::dispatch_evm_call { call: Box::new(inner) }),
				RuntimeOrigin::signed(actor(*who)),
			);
		}
		SubmitIntent { who, asset_in, asset_out, amount_in, limit, partial } => {
			let (Some(ai), Some(ao)) = (pick(&t.omnipool, *asset_in), pick(&t.omnipool, *asset_out)) else { return };
			let w = actor(*who);
			let ed = |a: AssetId| <hydradx_runtime::AssetRegistry as hydradx_traits::registry::Inspect>::existential_deposit(a).unwrap_or(1).max(1);
			// Frac amounts are meant to be realistic: keep them above the ED the pallet requires. Units/Raw stay as fuzzed.
			let amount_in = match amount_in {
				Amount::Frac(_) => amount_in.resolve(bal(ai, &w), t.decimals(ai)).max(ed(ai)),
				_ => amount_in.resolve(bal(ai, &w), t.decimals(ai)),
			};
			let quote = pallet_route_executor::Pallet::<Runtime>::calculate_expected_amount_out(
				&pallet_route_executor::Pallet::<Runtime>::get_route_or_default(ai, ao, &Default::default()),
				amount_in,
			)
			.ok();
			let amount_out = match (limit % 10, quote) {
				(0..=5, Some(q)) => q / 2,
				(6, Some(q)) => q,
				(7 | 8, Some(q)) => q.saturating_mul(1000 - (1 + u128::from(*limit) % 50)) / 1000,
				(9, Some(q)) => q.saturating_mul(2),
				(0..=8, None) => 1,
				_ => u128::MAX / 4,
			}
			.max(ed(ao));
			log!("  quote {quote:?} -> min out {amount_out}");
			ice::submit_intent(w, ai, ao, amount_in, amount_out, *partial);
		}
		SolveAndSubmit => ice::solve_and_submit(cfg),
		SubmitSolution(b) => ice::submit_raw_solution(cfg, &b.0),
		RemoveIntent { who, back } => ice::remove_intent(actor(*who), *back),
		Raw { .. } | Lapse(_) | AaveLifecycle { .. } | IceRound { .. } => unreachable!(),
	}
}

#[allow(clippy::too_many_arguments)]
fn aave_pool(t: &Tables, cfg: &oracle::Config, who: u8, op: AaveOp, reserve: u8, other: u8, user: u8, amount: Amount) {
	let Some(r) = pick(&t.reserves, reserve) else { return };
	let pool = t.aave_pool;
	let me = actor_evm(who);
	let w = actor(who);
	let dec = r.asset.map(|a| t.decimals(a)).unwrap_or(18);
	let held = r.asset.map(|a| bal(a, &w)).unwrap_or_default();
	let addr = Token::Address;
	let (data, approve) = match op {
		AaveOp::Supply => {
			let amt = amount.resolve(held, dec);
			(e::encode("supply(address,uint256,address,uint16)", &[addr(r.underlying), u(amt), addr(me), u(0)]), Some(amt))
		}
		AaveOp::Withdraw => {
			let amt = amount.resolve(u128::MAX, dec);
			(e::encode("withdraw(address,uint256,address)", &[addr(r.underlying), u(amt), addr(me)]), None)
		}
		AaveOp::Borrow => {
			let amt = amount.resolve(held.max(10u128.pow(dec as u32)), dec);
			(
				e::encode(
					"borrow(address,uint256,uint256,uint16,address)",
					&[addr(r.underlying), u(amt), u(2), u(0), addr(me)],
				),
				None,
			)
		}
		AaveOp::Repay => {
			let amt = amount.resolve(held, dec);
			(
				e::encode("repay(address,uint256,uint256,address)", &[addr(r.underlying), u(amt), u(2), addr(me)]),
				Some(amt),
			)
		}
		AaveOp::SetCollateral(on) => (
			e::encode("setUserUseReserveAsCollateral(address,bool)", &[addr(r.underlying), Token::Bool(on)]),
			None,
		),
		AaveOp::LiquidationCall(receive_atoken) => {
			let Some(debt) = pick(&t.reserves, other) else { return };
			let victim = pick(&t.users, user).unwrap_or_default();
			let amt = amount.resolve(u128::MAX, dec);
			(
				e::encode(
					"liquidationCall(address,address,address,uint256,bool)",
					&[addr(r.underlying), addr(debt.underlying), addr(victim), u(amt), Token::Bool(receive_atoken)],
				),
				Some(amt),
			)
		}
	};
	if let Some(amt) = approve {
		let token = match op {
			AaveOp::LiquidationCall(_) => pick(&t.reserves, other).map(|d| d.underlying).unwrap_or_default(),
			_ => r.underlying,
		};
		e::call_as(me, token, e::encode("approve(address,uint256)", &[addr(pool), u(amt)]), U256::zero(), 200_000);
	}
	let hf_checked = matches!(op, AaveOp::Borrow | AaveOp::Withdraw | AaveOp::SetCollateral(_));
	let ok = dispatch(evm_call(me, pool, data, U256::zero(), 1_500_000), RuntimeOrigin::signed(w));
	let succeeded = ok && oracle::last_evm_call_succeeded();
	oracle::after_aave_action(cfg, t, &r, me, hf_checked && succeeded);
}
