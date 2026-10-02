//! Pure ICE solver target: AFL bytes -> intents -> `SolverV4::solve` against simulator state
//! captured once from the snapshot. No chain execution, so it is fast and coverage lands in the solver.

use harness::arbitrary::{self, Arbitrary, Unstructured};
use harness::ice_oracle::{check_solution, SolverIntent};
use harness::ice_support::{IntentData, Partial, SwapData};
use harness::codec::Encode;
use harness::{action::Amount, ice::SolverV4, tables::pick, AssetId};

#[derive(Arbitrary, Debug)]
struct RawIntent {
	asset_in: u16,
	asset_out: u16,
	amount_in: Amount,
	amount_out: Amount,
	partial: bool,
}

fn intents(data: &[u8], assets: &[(AssetId, u8)]) -> Vec<SolverIntent> {
	let mut u = Unstructured::new(data);
	let mut out = vec![];
	while let Ok(r) = RawIntent::arbitrary(&mut u) {
		if out.len() >= 64 {
			break;
		}
		let ((ai, di), (ao, dout)) = (pick(assets, r.asset_in).unwrap(), pick(assets, r.asset_out).unwrap());
		out.push(SolverIntent {
			id: out.len() as u128 + 1,
			data: IntentData::Swap(SwapData {
				asset_in: ai,
				asset_out: ao,
				amount_in: r.amount_in.resolve(10u128.pow(di as u32 + 6), di).max(1),
				amount_out: r.amount_out.resolve(10u128.pow(dout as u32 + 6), dout).max(1),
				partial: if r.partial { Partial::Yes(0) } else { Partial::No },
			}),
		});
	}
	out
}

fn main() {
	let mut ext = std::panic::AssertUnwindSafe(harness::load_snapshot(&harness::default_snapshot_path()));
	let (state, fee, assets): (harness::ice::State, _, Vec<(AssetId, u8)>) = ext.execute_with(|| {
		let t = harness::tables::Tables::read();
		let assets = t.omnipool.iter().map(|a| (*a, t.decimals(*a))).collect();
		(harness::ice::initial_state(), harness::pallet_ice::ProtocolFee::<harness::Runtime>::get(), assets)
	});
	ziggy::fuzz!(|data: &[u8]| {
		let intents = intents(data, &assets);
		if intents.is_empty() {
			return;
		}
		// The solver reads a few registry values (EDs) from storage; it never writes.
		ext.execute_with(|| {
			let a = SolverV4::solve(intents.clone(), state.clone(), fee).ok();
			if let Some(sol) = &a {
				if let Some(v) = check_solution(&intents, sol, fee, true).first() {
					panic!("VIOLATION[ice_{}] {}", v.kind, v.detail);
				}
			}
			// Collators must agree: identical input, byte-identical solution.
			let b = SolverV4::solve(intents, state.clone(), fee).ok();
			assert!(a.encode() == b.encode(), "VIOLATION[ice_nondeterministic]");
		});
	});
}
