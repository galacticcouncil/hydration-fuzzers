//! Build the fuzzer's starting state: mainnet snapshot + Substrate-side patches only.
//!
//! usage: hydration-fuzz-snapshot [SRC] [DST]
//!   SRC default ../../hydration-node/integration-tests/snapshots/ice/SNAPSHOT_uni
//!   DST default fuzz/data/SNAPSHOT

use frame_support::traits::OnRuntimeUpgrade;
use harness::*;

fn main() {
	let mut args = std::env::args().skip(1);
	let src = args.next().unwrap_or_else(|| {
		concat!(env!("CARGO_MANIFEST_DIR"), "/../../../hydration-node/integration-tests/snapshots/ice/SNAPSHOT_uni").into()
	});
	let dst = args.next().unwrap_or_else(default_snapshot_path);

	let mut ext = load_snapshot(&src);
	ext.execute_with(patch);
	save_snapshot(ext, &dst);

	let engine = Engine::new(&dst);
	println!("wrote {dst}\n  {}", engine.tables.summary());
	let mut engine = engine;
	engine.ext.execute_with(|| {
		use orml_traits::MultiCurrency;
		let b = |a| hydradx_runtime::Currencies::free_balance(a, &actor(2));
		println!("  sanity, actor 2 balances: HDX {} USDT(10) {} 22 {} WETH {}", b(0), b(10), b(22), b(20));
	});
}

fn patch() {
	type R = Runtime;
	// What `hydra_live_ext` (integration-tests) does after loading a snapshot.
	hydradx_runtime::Parameters::set_relay_parent_offset_override(true);
	pallet_ema_oracle::migrations::v1::MigrateV0ToV1::<R>::on_runtime_upgrade();
	pallet_stableswap::migrations::v2::MigrateV1ToV2::<R>::on_runtime_upgrade();
	register_aave_wraps();

	let t = tables::Tables::read();
	let mut assets = vec![0, hydradx_runtime::evm::WETH_ASSET_ID];
	// Every asset some venue trades, so typed actions rarely die on a zero balance.
	assets.extend(t.sufficient.iter().copied());
	assets.extend(t.omnipool.iter().copied());
	assets.extend(t.stable_pools.iter().flat_map(|(_, a)| a.iter().copied()));
	assets.extend(t.hsm_collaterals.iter().copied());
	assets.extend(t.reserves.iter().filter_map(|r| r.asset));
	// Stableswap share assets are tracked by the pallet (ShareIssuance); minting them here would
	// desync it and trip stableswap's issuance debug_assert on the first touch.
	assets.retain(|a| !t.stable_pools.iter().any(|(pool, _)| pool == a));
	assets.sort();
	assets.dedup();
	let mut skipped = std::collections::BTreeSet::new();
	for i in 0..ACTORS {
		let who = actor(i);
		for &a in &assets {
			// 10M whole units: enough to move any pool, still far from u128 overflow.
			let amount = 10u128.pow(t.decimals(a) as u32).saturating_mul(10_000_000);
			// ERC20-backed assets (aTokens etc.) can't be minted from Substrate; they are reached by trading.
			if hydradx_runtime::Currencies::update_balance(RuntimeOrigin::root(), who.clone(), a, amount as i128).is_err() {
				skipped.insert(a);
			}
		}
		let r = hydradx_runtime::EVMAccounts::bind_evm_address(RuntimeOrigin::signed(who));
		if r.is_err() {
			eprintln!("bind {i}: {r:?}");
		}
	}
	println!("endowed {} assets, not mintable: {skipped:?}", assets.len() - skipped.len());
	fund_erc20_from_treasury(&t);
	// Minting that much trips the circuit breaker's deposit limit: the asset goes into lockdown and
	// the deposit is reserved. Lift the lockdown and release the deposits (both are root calls on chain).
	for &a in &assets {
		let _ = hydradx_runtime::CircuitBreaker::force_lift_lockdown(RuntimeOrigin::root(), a);
		for i in 0..ACTORS {
			let _ = hydradx_runtime::CircuitBreaker::release_deposit(RuntimeOrigin::root(), actor(i), a);
		}
	}
	pallet_dispatcher::AaveManagerAccount::<R>::put(actor(AAVE_MANAGER_ACTOR));

	// Pending mainnet intents make every solver run in the fuzzer solve 30+ intents over all venues
	// (~1 s each, usually with no solution), and after a slim scrape their reserved funds may be gone.
	// Default: cancel them all, the fuzzer submits its own. FUZZ_KEEP_MAINNET_INTENTS=1 keeps the
	// consistent ones (full scrape), cancelling only those whose reserved funds are missing.
	{
		let keep = std::env::var("FUZZ_KEEP_MAINNET_INTENTS").map(|v| v == "1").unwrap_or(false);
		use orml_traits::NamedMultiReservableCurrency;
		let ids: Vec<u128> = pallet_intent::Intents::<R>::iter_keys().collect();
		let mut cancelled = 0;
		for id in &ids {
			let (Some(owner), Some(intent)) = (pallet_intent::Pallet::<R>::intent_owner(*id), pallet_intent::Intents::<R>::get(*id)) else { continue };
			let reserved = <hydradx_runtime::Currencies as NamedMultiReservableCurrency<AccountId>>::reserved_balance_named(
				&pallet_intent::NAMED_RESERVE_ID, intent.data.asset_in(), &owner);
			if !keep || reserved < intent.data.amount_in() {
				// `cancel_intent` is #[transactional]: outside a dispatch it needs a storage layer.
				match frame_support::storage::transactional::with_storage_layer(|| pallet_intent::Pallet::<R>::cancel_intent(owner.clone(), *id)) {
					Ok(()) => cancelled += 1,
					Err(_) => {
						// Reserved funds already gone (slim scrape): drop the entries directly.
						pallet_intent::Intents::<R>::remove(*id);
						pallet_intent::AccountIntents::<R>::remove(&owner, *id);
						pallet_intent::AccountIntentCount::<R>::mutate(&owner, |c| *c = c.saturating_sub(1));
						cancelled += 1;
					}
				}
			}
		}
		println!("pending mainnet intents: {} kept, {cancelled} cancelled{}", ids.len() - cancelled, if keep { " (reserved funds missing)" } else { " (default; FUZZ_KEEP_MAINNET_INTENTS=1 keeps them)" });
	}

	// Mainnet runs with async backing and leaves pending (unincluded) blocks in state; the fuzzer's fake
	// relay proof declares async backing off, under which the runtime requires that segment to be empty
	// (`no space left for the block in the unincluded segment`). Treat every pending block as included.
	cumulus_pallet_parachain_system::UnincludedSegment::<R>::kill();
	cumulus_pallet_parachain_system::AggregatedUnincludedSegment::<R>::kill();

	// Produce one block so runtime-upgrade migrations run here once, not in every scenario.
	let b = frame_system::Pallet::<R>::block_number() + 1;
	block::initialize_block(b, None);
	block::finalize_block();
}

/// ERC20-kind assets (aTokens, HOLLAR) can't be minted; hand each actor 1/40 of the treasury's
/// holding by an impersonated `transfer` (the integration tests fund from the treasury too).
fn fund_erc20_from_treasury(t: &tables::Tables) {
	use harness::evm::{call_as, encode, succeeded, Token};
	use hydradx_runtime::evm::precompiles::erc20_mapping::HydraErc20Mapping;
	use hydradx_traits::evm::{Erc20Mapping, InspectEvmAccounts};
	use orml_traits::MultiCurrency;
	let treasury = hydradx_runtime::TreasuryAccount::get();
	let from = pallet_evm_accounts::Pallet::<Runtime>::evm_address(&treasury);
	let mut funded = vec![];
	for &a in &t.erc20 {
		let share = hydradx_runtime::Currencies::free_balance(a, &treasury) / 40;
		if share == 0 {
			continue;
		}
		let token = HydraErc20Mapping::asset_address(a);
		let ok = (0..ACTORS).all(|i| {
			let data = encode("transfer(address,uint256)", &[Token::Address(actor_evm(i)), Token::Uint(share.into())]);
			succeeded(&call_as(from, token, data, 0.into(), 2_000_000))
		});
		funded.push((a, ok));
	}
	println!("erc20 funded from treasury (asset, ok): {funded:?}");
}

/// Copied from integration-tests `register_aave_wraps`: opt every Aave reserve into ICE routing.
fn register_aave_wraps() {
	use hydradx_runtime::evm::aave_trade_executor::AaveTradeExecutor;
	use hydradx_runtime::evm::precompiles::erc20_mapping::HydraErc20Mapping;
	use hydradx_traits::evm::Erc20Mapping;
	use ice_support::{RoutingState, RoutingTarget};

	let pool = pallet_liquidation::BorrowingContract::<Runtime>::get();
	let Ok(reserves) = AaveTradeExecutor::<Runtime>::get_reserves_list(pool) else { return };
	let wraps: Vec<(AssetId, AssetId)> = reserves
		.into_iter()
		.filter_map(|reserve| {
			let data = AaveTradeExecutor::<Runtime>::get_reserve_data(pool, reserve).ok()?;
			Some((
				HydraErc20Mapping::address_to_asset(reserve)?,
				HydraErc20Mapping::address_to_asset(data.atoken_address)?,
			))
		})
		.collect();
	for chunk in wraps.chunks(ice_support::MAX_ROUTING_BATCH as usize) {
		hydradx_runtime::ICE::update_routing(
			RuntimeOrigin::root(),
			RoutingTarget::AaveWraps(chunk.to_vec().try_into().unwrap()),
			Some(RoutingState::Included),
		)
		.unwrap();
	}
}
