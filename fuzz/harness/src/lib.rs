//! Fuzz harness for the Hydration runtime. Fuzzer-agnostic: `targets/runtime` drives it from AFL,
//! `targets/soak` from a seeded RNG. Both feed bytes to [`Engine::run`].

pub mod action;
pub mod block;
pub mod evm;
pub mod ice;
pub mod ice_oracle;
pub mod oracle;
pub mod tables;

use codec::{Compact, Decode, Encode};
use sp_core::{H160, H256};
use sp_io::TestExternalities;
use sp_runtime::traits::Header as _;
use sp_runtime::StateVersion;
use std::sync::atomic::{AtomicBool, Ordering};

/// Re-exported so the binaries don't repeat the dependency list.
pub use {
	amm_simulator, arbitrary, codec, frame_support, frame_system, hydradx_runtime, hydradx_traits, ice_solver,
	ice_support, orml_traits, pallet_dispatcher, pallet_evm_accounts, pallet_ema_oracle, pallet_ice, pallet_liquidation, pallet_stableswap, sp_runtime,
};

pub use hydradx_runtime::{Runtime, RuntimeCall, RuntimeEvent, RuntimeOrigin};
pub use primitives::{AccountId, AssetId, Balance};
pub type Header = sp_runtime::generic::Header<u32, sp_runtime::traits::BlakeTwo256>;

/// Fuzzer-controlled accounts `[i; 32]`; their EVM identity is `H160([i; 20])`.
pub const ACTORS: u8 = 20;
/// Actor that the snapshot step makes `Dispatcher::AaveManagerAccount`.
pub const AAVE_MANAGER_ACTOR: u8 = 19;
/// Upper bound on actions per scenario; keeps a single input's runtime bounded.
pub const MAX_ACTIONS: usize = 48;

pub fn actor(i: u8) -> AccountId {
	[i % ACTORS; 32].into()
}

pub fn actor_evm(i: u8) -> H160 {
	H160([i % ACTORS; 20])
}

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(v: bool) {
	VERBOSE.store(v, Ordering::Relaxed);
}

pub fn verbose() -> bool {
	VERBOSE.load(Ordering::Relaxed)
}

#[macro_export]
macro_rules! log {
	($($t:tt)*) => { if $crate::verbose() { println!($($t)*) } };
}

/// Snapshot format v4, as written by `scraper` / `frame-remote-externalities`.
/// Re-implemented here so the harness doesn't depend on `scraper` (which drags in the whole node).
#[derive(Encode, Decode)]
struct Snapshot {
	version: Compact<u16>,
	state_version: StateVersion,
	raw_storage: Vec<(Vec<u8>, (Vec<u8>, i32))>,
	storage_root: H256,
	header: Header,
}

pub fn load_snapshot(path: &str) -> TestExternalities {
	let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read snapshot {path}: {e}"));
	assert_eq!(bytes.first(), Some(&0x10), "{path}: not a v4 snapshot");
	let s = Snapshot::decode(&mut &bytes[..]).expect("decode snapshot");
	TestExternalities::from_raw_snapshot(s.raw_storage, s.storage_root, s.state_version)
}

pub fn save_snapshot(mut ext: TestExternalities, path: &str) {
	ext.commit_all().expect("commit_all");
	let state_version = ext.state_version;
	let (raw_storage, storage_root) = ext.into_raw_snapshot();
	let header = Header::new(0, Default::default(), Default::default(), Default::default(), Default::default());
	let s = Snapshot {
		version: Compact(4),
		state_version,
		raw_storage,
		storage_root,
		header,
	};
	std::fs::write(path, s.encode()).expect("write snapshot");
}

pub fn default_snapshot_path() -> String {
	std::env::var("FUZZ_SNAPSHOT").unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../data/SNAPSHOT").into())
}

/// Loaded state + tables. Created once per process (before the AFL fork server); each scenario
/// runs in a fresh overlay on top of the untouched backend, so nothing is ever cloned.
pub struct Engine {
	pub ext: TestExternalities,
	pub tables: tables::Tables,
	pub oracles: oracle::Config,
	/// Block number the snapshot is at + 1.
	pub first_block: u32,
}

impl Engine {
	pub fn new(path: &str) -> Self {
		let mut ext = load_snapshot(path);
		let (tables, first_block) = ext.execute_with(|| (tables::Tables::read(), frame_system::Pallet::<Runtime>::block_number() + 1));
		// Reading tables runs EVM views; drop whatever they left in the overlay.
		ext.overlay = Default::default();
		let mut engine = Engine {
			ext,
			tables,
			oracles: oracle::Config::from_env(),
			first_block,
		};
		(engine.oracles.try_state_pallets, engine.oracles.try_state_slow) =
			engine.ext.execute_with(oracle::passing_try_state_pallets);
		engine.ext.overlay = Default::default();
		engine
	}

	/// Run one input. Panics on any oracle violation.
	pub fn run(&mut self, data: &[u8]) {
		if let Some(scenario) = action::Scenario::decode(data) {
			self.run_scenario(&scenario);
		}
	}

	pub fn run_scenario(&mut self, scenario: &action::Scenario) {
		self.ext.overlay = Default::default();
		let (tables, oracles, first_block) = (&self.tables, &self.oracles, self.first_block);
		self.ext
			.execute_with(|| evm::with_listeners(oracles, || action::execute(scenario, tables, oracles, first_block)));
	}
}

#[cfg(test)]
mod tests {
	use super::action::{Action, Amount, Flags, Scenario};

	/// One scenario touching every venue kind against the real snapshot (skipped if absent).
	#[test]
	fn scenario_runs_on_snapshot() {
		let path = super::default_snapshot_path();
		if !std::path::Path::new(&path).exists() {
			eprintln!("no snapshot at {path}; run the snapshot bin first");
			return;
		}
		super::set_verbose(std::env::var("FUZZ_VERBOSE").is_ok());
		let mut engine = super::Engine::new(&path);
		assert!(!engine.tables.omnipool.is_empty());
		let amount = Amount::Frac(3);
		let s = Scenario {
			flags: Flags { circuit_breaker_off: true, solve_each_block: true },
			actions: vec![
				Action::OmnipoolSell { who: 1, asset_in: 0, asset_out: 1, amount },
				Action::StableSell { who: 2, pool: 0, i_in: 0, i_out: 1, amount },
				Action::Lapse(3),
				Action::AaveTrade { who: 3, reserve: 0, supply: true, amount },
				Action::Router { who: 4, sell: true, asset_in: 0, asset_out: 5, amount, hops: vec![] },
				Action::SubmitIntent { who: 5, asset_in: 0, asset_out: 1, amount_in: amount, limit: 0, partial: true },
				Action::SolveAndSubmit,
			],
		};
		engine.run_scenario(&s);
		// Overlay reset: a second run starts from the same state and must behave identically.
		engine.run_scenario(&s);
	}

	#[test]
	fn slip_fee_config_on_snapshot() {
		let path = super::default_snapshot_path();
		if !std::path::Path::new(&path).exists() {
			return;
		}
		let mut engine = super::Engine::new(&path);
		let cfg = engine.ext.execute_with(pallet_omnipool::pallet::SlipFee::<hydradx_runtime::Runtime>::get);
		eprintln!("Omnipool::SlipFee = {cfg:?}");
	}

	#[test]
	fn amount_resolves() {
		assert_eq!(Amount::Frac(255).resolve(1000, 12), 1000);
		assert_eq!(Amount::Frac(0).resolve(1000, 12), 0);
		assert_eq!(Amount::Units { m: 5, e: 4 }.resolve(0, 12), 5 * 10u128.pow(12));
		assert_eq!(Amount::Frac(128).resolve(u128::MAX, 0), u128::MAX / 255 * 128 + u128::MAX % 255 * 128 / 255);
	}

	#[test]
	fn abi_encoding() {
		use super::evm::{encode, selector, Token};
		assert_eq!(selector("transfer(address,uint256)"), [0xa9, 0x05, 0x9c, 0xbb]);
		let d = encode("approve(address,uint256)", &[Token::Address([1; 20].into()), Token::Bool(true)]);
		assert_eq!(d.len(), 4 + 64);
		assert_eq!(&d[4 + 12..4 + 32], &[1; 20]);
		assert_eq!(d[4 + 63], 1);
	}
}
