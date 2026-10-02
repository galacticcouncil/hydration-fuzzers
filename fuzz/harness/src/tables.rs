//! Lookup tables read from the snapshot at startup. Typed actions index into these, so the fuzzer
//! never wastes inputs on asset ids / pools / contracts that don't exist.

use crate::evm::{encode, view, word, word_addr, Token};
use crate::{AccountId, AssetId, Runtime};
use frame_support::storage::migration::storage_key_iter;
use frame_support::Blake2_128Concat;
use hydradx_runtime::evm::aave_trade_executor::AaveTradeExecutor;
use hydradx_runtime::evm::precompiles::erc20_mapping::HydraErc20Mapping;
use hydradx_traits::evm::{Erc20Mapping, InspectEvmAccounts};
use sp_core::{H160, U256};
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct Reserve {
	pub underlying: H160,
	pub asset: Option<AssetId>,
	pub atoken: H160,
	pub atoken_asset: Option<AssetId>,
	pub variable_debt: H160,
}

#[derive(Clone, Debug)]
pub struct UniPool {
	pub address: H160,
	pub token0: AssetId,
	pub token1: AssetId,
	pub fee: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Tables {
	pub assets: Vec<AssetId>,
	pub decimals: Vec<(AssetId, u8)>,
	pub sufficient: Vec<AssetId>,
	/// Registry assets whose ledger lives in a contract (aTokens, HOLLAR, ...).
	pub erc20: Vec<AssetId>,
	pub omnipool: Vec<AssetId>,
	pub stable_pools: Vec<(AssetId, Vec<AssetId>)>,
	pub xyk_pools: Vec<(AssetId, AssetId)>,
	pub hsm_collaterals: Vec<AssetId>,
	pub hollar: AssetId,
	pub aave_pool: H160,
	pub reserves: Vec<Reserve>,
	pub uniswap: Vec<H160>,
	pub uni_pools: Vec<UniPool>,
	/// Every address with code, plus precompiles/ERC20 mappings of registry assets.
	pub contracts: Vec<H160>,
	/// EVM identities worth impersonating / liquidating: aToken holders from the snapshot + actors.
	pub users: Vec<H160>,
}

pub fn pick<T: Clone>(v: &[T], i: impl Into<u64>) -> Option<T> {
	(!v.is_empty()).then(|| v[(i.into() % v.len() as u64) as usize].clone())
}

impl Tables {
	pub fn read() -> Self {
		let mut t = Tables::default();
		for (id, d) in pallet_asset_registry::Assets::<Runtime>::iter() {
			t.assets.push(id);
			t.decimals.push((id, d.decimals.unwrap_or(12)));
			if d.is_sufficient {
				t.sufficient.push(id);
			}
			if matches!(d.asset_type, pallet_asset_registry::AssetType::Erc20) {
				t.erc20.push(id);
			}
		}
		t.omnipool = pallet_omnipool::Assets::<Runtime>::iter_keys().collect();
		t.stable_pools = pallet_stableswap::Pools::<Runtime>::iter()
			.map(|(id, p)| (id, p.assets.into_inner()))
			.collect();
		t.xyk_pools = storage_key_iter::<AccountId, (AssetId, AssetId), Blake2_128Concat>(b"XYK", b"PoolAssets")
			.map(|(_, v)| v)
			.collect();
		t.hsm_collaterals = pallet_hsm::Collaterals::<Runtime>::iter_keys().collect();
		t.hollar = <Runtime as pallet_hsm::Config>::HollarId::get();

		t.aave_pool = pallet_liquidation::BorrowingContract::<Runtime>::get();
		for underlying in AaveTradeExecutor::<Runtime>::get_reserves_list(t.aave_pool).unwrap_or_default() {
			let Ok(d) = AaveTradeExecutor::<Runtime>::get_reserve_data(t.aave_pool, underlying) else { continue };
			t.reserves.push(Reserve {
				underlying,
				asset: HydraErc20Mapping::address_to_asset(underlying),
				atoken: d.atoken_address,
				atoken_asset: HydraErc20Mapping::address_to_asset(d.atoken_address),
				variable_debt: d.variable_debt_token_address,
			});
		}

		t.uniswap = [
			pallet_parameters::Pallet::<Runtime>::uniswap_v3_factory(),
			pallet_parameters::Pallet::<Runtime>::uniswap_v3_swap_router(),
			pallet_parameters::Pallet::<Runtime>::uniswap_v3_quoter(),
		]
		.into_iter()
		.flatten()
		.collect();
		use amm_simulator::uniswap_v3::DataProvider;
		for address in hydradx_runtime::ice_simulator_provider::UniswapV3::<Runtime>::pools() {
			let get = |sig| view(address, encode(sig, &[]));
			let (Some(t0), Some(t1), Some(fee)) = (get("token0()"), get("token1()"), get("fee()")) else { continue };
			let (Some(a0), Some(a1)) = (
				word_addr(&t0, 0).and_then(HydraErc20Mapping::address_to_asset),
				word_addr(&t1, 0).and_then(HydraErc20Mapping::address_to_asset),
			) else {
				continue;
			};
			t.uni_pools.push(UniPool {
				address,
				token0: a0,
				token1: a1,
				fee: word(&fee, 0).unwrap_or_default().low_u32(),
			});
		}

		// Registered pools are opt-in for ICE and may be empty; probe the factory over ERC20 pairs too.
		use hydradx_runtime::evm::uniswap_v3_trade_executor::UniswapV3;
		let mut seen: BTreeSet<H160> = t.uni_pools.iter().map(|p| p.address).collect();
		for (i, &a) in t.erc20.iter().enumerate() {
			for &b in &t.erc20[i + 1..] {
				for fee in [100, 500, 3000, 10000] {
					if let Ok(Some(address)) = UniswapV3::find_pool(a, b, fee) {
						if seen.insert(address) {
							let (token0, token1) = if HydraErc20Mapping::asset_address(a) < HydraErc20Mapping::asset_address(b) { (a, b) } else { (b, a) };
							t.uni_pools.push(UniPool { address, token0, token1, fee });
						}
					}
				}
			}
		}

		let mut contracts: BTreeSet<H160> = pallet_evm::AccountCodes::<Runtime>::iter_keys().collect();
		contracts.extend(t.assets.iter().map(|a| HydraErc20Mapping::asset_address(*a)));
		use hydradx_runtime::evm::precompiles::{CALLPERMIT, DISPATCH_ADDR, FLASH_LOAN_RECEIVER, LOCK_MANAGER};
		contracts.extend([DISPATCH_ADDR, CALLPERMIT, FLASH_LOAN_RECEIVER, LOCK_MANAGER, t.aave_pool]);
		contracts.extend(t.uniswap.iter().copied());
		for r in &t.reserves {
			contracts.extend([r.underlying, r.atoken, r.variable_debt]);
		}
		t.contracts = contracts.into_iter().collect();

		let mut users: BTreeSet<H160> = (0..crate::ACTORS).map(crate::actor_evm).collect();
		// Real money-market users: bound EVM accounts with collateral (aToken ledgers are contract
		// storage, so Substrate storage can't list holders directly).
		users.insert(pallet_evm_accounts::Pallet::<Runtime>::evm_address(&hydradx_runtime::TreasuryAccount::get()));
		let mut found = 0;
		for h in pallet_evm_accounts::AccountExtension::<Runtime>::iter_keys().take(400) {
			let data = view(t.aave_pool, encode("getUserAccountData(address)", &[Token::Address(h)]));
			if data.and_then(|d| word(&d, 0)).is_some_and(|c| !c.is_zero()) {
				users.insert(h);
				found += 1;
				if found >= 64 {
					break;
				}
			}
		}
		t.users = users.into_iter().collect();
		t
	}

	pub fn decimals(&self, asset: AssetId) -> u8 {
		self.decimals.iter().find(|(a, _)| *a == asset).map(|(_, d)| *d).unwrap_or(12)
	}

	pub fn summary(&self) -> String {
		format!(
			"assets {} (sufficient {}, erc20 {}) | omnipool {} | stableswap {} | xyk {} | hsm {} | aave reserves {} | uni pools {} | contracts {} | users {}",
			self.assets.len(),
			self.sufficient.len(),
			self.erc20.len(),
			self.omnipool.len(),
			self.stable_pools.len(),
			self.xyk_pools.len(),
			self.hsm_collaterals.len(),
			self.reserves.len(),
			self.uni_pools.len(),
			self.contracts.len(),
			self.users.len()
		)
	}
}

pub fn u(x: u128) -> Token {
	Token::Uint(U256::from(x))
}
