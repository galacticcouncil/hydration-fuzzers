extern crate polkadot_primitives;

use codec::{DecodeLimit, Encode};
use cumulus_primitives_core::relay_chain::Header;
use frame_support::traits::{StorageInfo, StorageInfoTrait, Time};
use frame_support::{
    dispatch::GetDispatchInfo,
    pallet_prelude::Weight,
    traits::{IntegrityTest, TryState, TryStateSelect},
    weights::constants::WEIGHT_REF_TIME_PER_SECOND,
};
use hydradx_runtime::*;
use primitives::constants::time::SLOT_DURATION;
use sp_consensus_aura::{Slot, AURA_ENGINE_ID};
use sp_core::H256;
use sp_runtime::traits::BlockNumberProvider;
use sp_runtime::{
    traits::{Dispatchable, Header as _},
    Digest, DigestItem, StateVersion,
};
use std::{
    collections::BTreeMap,
    io::Write,
    iter,
    path::PathBuf,
    time::{Duration, Instant},
};

type FuzzedRuntime = hydradx_runtime::Runtime;
type Balance = <FuzzedRuntime as pallet_balances::Config>::Balance;
type RuntimeOrigin = <FuzzedRuntime as frame_system::Config>::RuntimeOrigin;
type AccountId = <FuzzedRuntime as frame_system::Config>::AccountId;

/// The maximum number of blocks per fuzzer input.
/// If set to 0, then there is no limit at all.
/// Feel free to set this to a low number (e.g. 4) when you begin your fuzzing campaign and then set
/// it back to 32 once you have good coverage.
const MAX_BLOCKS_PER_INPUT: usize = 32;

/// The maximum number of extrinsics per block.
/// If set to 0, then there is no limit at all.
/// Feel free to set this to a low number (e.g. 8) when you begin your fuzzing campaign and then set
/// it back to 0 once you have good coverage.
const MAX_EXTRINSICS_PER_BLOCK: usize = 0;

/// Max number of seconds a block should run for.
#[cfg(not(feature = "fuzzing"))]
const MAX_TIME_FOR_BLOCK: u64 = 6;

// We do not skip more than DEFAULT_STORAGE_PERIOD to avoid pallet_transaction_storage from
// panicking on finalize.
// Set to number of blocks in two months
//const MAX_BLOCK_LAPSE: u32 = 864_000;
const MAX_BLOCK_LAPSE: u32 = 1000;

// Extrinsic delimiter: `********`
const DELIMITER: [u8; 8] = [42; 8];

const SNAPSHOT_PATH: &str = "data/MOCK_SNAPSHOT";

// We won't analyse those native Substrate pallets
#[cfg(not(feature = "fuzzing"))]
const BLACKLISTED_CALLS: [&str; 8] = [
    "RuntimeCall::System",
    "RuntimeCall::Utility",
    "RuntimeCall::Proxy",
    "RuntimeCall::Uniques",
    "RuntimeCall::Balances",
    "RuntimeCall::Timestamp",
    // to prevent false negatives from debug_assert_ne
    "RuntimeCall::XTokens",
    "RuntimeCall::Referenda",
];

const OMNIPOOL_ASSETS: [u32; 74] = [
    100, 1000771, 0, 10, 1001, 4, 21, 28, 20, 1000198, 30, 101, 34, 16, 11, 1000085, 1000099,
    1000766, 14, 1006, 6, 1000796, 19, 1000795, 35, 36, 31, 33, 15, 1000794, 2, 13, 1002, 32,
    1000745, 27, 1000625, 29, 102, 1000753, 5, 18, 7, 1000624, 26, 3370, 1003, 1000190, 690, 22,
    1005, 24, 1000626, 8, 1000809, 1000100, 1004, 1000767, 1000765, 1, 252525, 12, 1000081, 3, 17,
    25, 1000746, 69, 23, 1000851, 9, 1000752, 1000189, 1007,
];

struct Data<'a> {
    data: &'a [u8],
    pointer: usize,
    size: usize,
}

#[allow(clippy::absurd_extreme_comparisons)]
impl<'a> Data<'a> {
    fn size_limit_reached(&self) -> bool {
        !(MAX_BLOCKS_PER_INPUT == 0 || MAX_EXTRINSICS_PER_BLOCK == 0)
            && self.size >= MAX_BLOCKS_PER_INPUT * MAX_EXTRINSICS_PER_BLOCK
    }
}

impl<'a> Iterator for Data<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() <= self.pointer || self.size_limit_reached() {
            return None;
        }
        let next_delimiter = self.data[self.pointer..]
            .windows(DELIMITER.len())
            .position(|window| window == DELIMITER);
        let next_pointer = match next_delimiter {
            Some(delimiter) => self.pointer + delimiter,
            None => self.data.len(),
        };
        let res = Some(&self.data[self.pointer..next_pointer]);
        self.pointer = next_pointer + DELIMITER.len();
        self.size += 1;
        res
    }
}

fn recursively_find_call(call: RuntimeCall, matches_on: fn(RuntimeCall) -> bool) -> bool {
    if let RuntimeCall::Utility(
        pallet_utility::Call::batch { calls }
        | pallet_utility::Call::force_batch { calls }
        | pallet_utility::Call::batch_all { calls },
    ) = call
    {
        for call in calls {
            if recursively_find_call(call.clone(), matches_on) {
                return true;
            }
        }
    } else if let RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 {
        call, ..
    })
    | RuntimeCall::Utility(pallet_utility::Call::as_derivative { call, .. })
    | RuntimeCall::Proxy(pallet_proxy::Call::proxy { call, .. }) = call
    {
        return recursively_find_call(*call.clone(), matches_on);
    } else if let RuntimeCall::Dispatcher(pallet_dispatcher::Call::dispatch_with_extra_gas {
        call,
        ..
    }) = &call
    {
        return recursively_find_call(*call.clone(), matches_on);
    } else if matches_on(call) {
        return true;
    }
    false
}
fn try_specific_extrinsic(identifier: u8, data: &[u8], assets: &[u32]) -> Option<RuntimeCall> {
    for handler in extrinsics_handlers() {
        if let Some(call) = handler.try_extrinsic(identifier, data, assets) {
            return Some(call);
        }
    }
    None
}

pub fn main() {
    let original_data = std::fs::read(SNAPSHOT_PATH).unwrap();
    let snapshot = scraper::get_snapshot_from_bytes::<Block>(original_data)
        .expect("Failed to create snapshot");
    let (backend, state_version, root) =
        scraper::construct_backend_from_snapshot::<Block>(snapshot)
            .expect("Failed to create backend");

    let assets: Vec<u32> = OMNIPOOL_ASSETS.to_vec();
    let accounts: Vec<AccountId> = (0..20).map(|i| [i; 32].into()).collect();

    ziggy::fuzz!(|data: &[u8]| {
        process_input(
            backend.clone(),
            state_version,
            root,
            data,
            assets.clone(),
            accounts.clone(),
        );
    });
}

fn process_input(
    backend: sp_trie::PrefixedMemoryDB<sp_core::Blake2Hasher>,
    state_version: StateVersion,
    root: H256,
    data: &[u8],
    assets: Vec<u32>,
    accounts: Vec<AccountId>,
) {
    // We build the list of extrinsics we will execute
    let mut extrinsic_data = data;

    let extrinsics: Vec<(u8, u8, RuntimeCall)> =
        iter::from_fn(|| DecodeLimit::decode_with_depth_limit(64, &mut extrinsic_data).ok())
            .filter(|(_, _, x): &(_, _, RuntimeCall)| {
                !recursively_find_call(x.clone(), |call| {
                    matches!(call.clone(), RuntimeCall::System(_))
                })
            })
            .collect();

    if extrinsics.is_empty() {
        return;
    }

    //let mut externalities = scraper::create_externalities_from_snapshot::<Block>(&snapshot).expect("Failed to create ext");
    let mut externalities =
        scraper::create_externalities_with_backend::<Block>(backend.clone(), root, state_version);

    //let mut block: u32 = 8_338_378;
    let mut block: u32 = 0;

    externalities.execute_with(|| {
        block = System::current_block_number() + 1;
        #[cfg(not(feature = "fuzzing"))]
        println!("Starting snapshot block :{:?}", block);
    });

    assert_ne!(block, 0, "block number is 0");

    let mut elapsed: Duration = Duration::ZERO;
    let mut weight: Weight = Weight::zero();

    let dummy_header: Header = Header {
        parent_hash: Default::default(),
        number: block,
        state_root: Default::default(),
        extrinsics_root: Default::default(),
        digest: Default::default(),
    };

    externalities.execute_with(|| {
        // initialize_block(block, None);
        initialize_block(block, Some(&dummy_header));

        // Calls that need to be executed in the first block go here
        for (lapse, origin, extrinsic) in extrinsics {
            if recursively_find_call(extrinsic.clone(), |call| {
                matches!(&call, RuntimeCall::XTokens(..))
                    || matches!(call.clone(), RuntimeCall::PolkadotXcm(pallet_xcm::Call::execute { message, .. })
                        if matches!(message.as_ref(), staging_xcm::VersionedXcm::V4(staging_xcm::v4::Xcm(msg))
                            if msg.iter().any(|m| matches!(m, staging_xcm::opaque::v4::prelude::BuyExecution { fees: staging_xcm::v4::Asset { fun, .. }, .. }
                                if *fun == staging_xcm::v4::Fungibility::Fungible(0)
                            ))
                        )
                    )
                    || matches!(&call, RuntimeCall::Timestamp(..))
                    || matches!(&call, RuntimeCall::ParachainSystem(..))
            }) {
                #[cfg(not(feature = "fuzzing"))]
                println!("    Skipping because of custom filter");
                continue;
            }
            // If lapse is positive, then we finalize the block and initialize a new one.
            if lapse > 0 {
                println!("  lapse:       {:?}", lapse);

                // Finalize current block
                let prev_header = finalize_block(elapsed);

                // We update our state variables
                block += u32::from(lapse);
                weight = Weight::zero();
                elapsed = Duration::ZERO;

                // We start the next block
                initialize_block(block, Some(&prev_header));
            }

            weight = weight.saturating_add(extrinsic.get_dispatch_info().weight);
            if weight.ref_time() >= 2 * WEIGHT_REF_TIME_PER_SECOND {
                #[cfg(not(feature = "fuzzing"))]
                println!("Skipping because of max weight {weight}");
                continue;
            }

            // We use given list of accounts to choose from, not a random account from the system
            let origin_account = accounts[origin as usize % accounts.len()].clone();

            #[cfg(not(feature = "fuzzing"))]
            println!("\n    origin:     {origin:?}");
            #[cfg(not(feature = "fuzzing"))]
            println!("    call:       {extrinsic:?}");

            let now = Instant::now(); // We get the current time for timing purposes.
            #[allow(unused_variables)]
            // let's also dispatch as None, but only 15% of the time.
            let res = if origin % 100 < 15 {
                extrinsic.clone().dispatch(RuntimeOrigin::none())
            } else {
                extrinsic
                    .clone()
                    .dispatch(RuntimeOrigin::signed(origin_account))
            };
            elapsed += now.elapsed();

            #[cfg(not(feature = "fuzzing"))]
            println!("    result:     {:?}", &res);
        }

        // We end the final block
        finalize_block(elapsed)
    });

    // After execution of all blocks.
    // Check that the consumer/provider state is valid.
    // for acc in frame_system::Account::<FuzzedRuntime>::iter() {
    //     let acc_consumers = acc.1.consumers;
    //     let acc_providers = acc.1.providers;
    //     if acc_consumers > 0 && acc_providers == 0 {
    //         panic!("Invalid state");
    //     }
    // }
    //
    // #[cfg(not(feature = "fuzzing"))]
    // println!("Running integrity tests\n");
    // // We run all developer-defined integrity tests
    // <AllPalletsWithSystem as IntegrityTest>::integrity_test();
}

fn initialize_block(block: u32, prev_header: Option<&Header>) {
    #[cfg(not(feature = "fuzzing"))]
    println!("\ninitializing block {block}");

    let last_block = System::current_block_number();
    assert!(
        last_block < block,
        "last block is not less than current block : {:?} {:?}",
        last_block,
        block
    );
    let last_timestamp = Timestamp::now();
    let block_diff = block - last_block;
    let new_timestamp = last_timestamp + u64::from(block_diff) * SLOT_DURATION;

    let pre_digest = Digest {
        logs: vec![DigestItem::PreRuntime(
            AURA_ENGINE_ID,
            Slot::from(u64::from(block)).encode(),
        )],
    };

    let parent_header = &Header::new(
        block,
        H256::default(),
        H256::default(),
        prev_header.map(Header::hash).unwrap_or_default(),
        pre_digest,
    );
    Executive::initialize_block(parent_header);

    #[cfg(not(feature = "fuzzing"))]
    println!(" setting timestamp");
    Timestamp::set(RuntimeOrigin::none(), new_timestamp).unwrap();

    #[cfg(not(feature = "fuzzing"))]
    println!("  setting parachain validation data");
    let parachain_validation_data = {
        use cumulus_primitives_core::relay_chain::HeadData;
        use cumulus_primitives_parachain_inherent::ParachainInherentData;
        use cumulus_test_relay_sproof_builder::RelayStateSproofBuilder;

        let parent_head = HeadData(prev_header.unwrap_or(parent_header).encode());
        let sproof_builder = RelayStateSproofBuilder {
            para_id: 2_034.into(),
            current_slot: cumulus_primitives_core::relay_chain::Slot::from(2 * u64::from(block)),
            included_para_head: Some(parent_head.clone()),
            ..Default::default()
        };

        let (relay_parent_storage_root, relay_chain_state) =
            sproof_builder.into_state_root_and_proof();
        ParachainInherentData {
            validation_data: polkadot_primitives::PersistedValidationData {
                parent_head,
                relay_parent_number: block,
                relay_parent_storage_root,
                max_pov_size: 1000,
            },
            relay_chain_state,
            downward_messages: Vec::default(),
            horizontal_messages: BTreeMap::default(),
        }
    };
    ParachainSystem::set_validation_data(RuntimeOrigin::none(), parachain_validation_data).unwrap();
}

fn finalize_block(elapsed: Duration) -> Header {
    #[cfg(not(feature = "fuzzing"))]
    println!("\n  time spent: {elapsed:?}");
    assert!(elapsed.as_secs() <= 2, "block execution took too much time");

    #[cfg(not(feature = "fuzzing"))]
    println!("finalizing block");
    Executive::finalize_block()
}

pub trait TryExtrinsic<Call, AssetId> {
    fn try_extrinsic(&self, identifier: u8, data: &[u8], assets: &[AssetId]) -> Option<Call>;
}

pub fn extrinsics_handlers() -> Vec<Box<dyn TryExtrinsic<RuntimeCall, u32>>> {
    vec![Box::new(OmnipoolHandler {}), Box::new(StableswapHandler {})]
}

pub struct OmnipoolHandler;

impl TryExtrinsic<RuntimeCall, u32> for OmnipoolHandler {
    fn try_extrinsic(&self, identifier: u8, data: &[u8], assets: &[u32]) -> Option<RuntimeCall> {
        match identifier {
            0 if data.len() > 18 => {
                let asset_in = assets[data[0] as usize % assets.len()];
                let asset_out = assets[data[1] as usize % assets.len()];
                let amount = u128::from_ne_bytes(data[2..18].try_into().ok()?);
                Some(RuntimeCall::Omnipool(pallet_omnipool::Call::sell {
                    asset_in,
                    asset_out,
                    amount,
                    min_buy_amount: 0,
                }))
            }
            1 if data.len() > 18 => {
                let asset_in = assets[data[0] as usize % assets.len()];
                let asset_out = assets[data[1] as usize % assets.len()];
                let amount = u128::from_ne_bytes(data[2..18].try_into().ok()?);
                Some(RuntimeCall::Omnipool(pallet_omnipool::Call::buy {
                    asset_in,
                    asset_out,
                    amount,
                    max_sell_amount: u128::MAX,
                }))
            }
            2 if data.len() > 17 => {
                let asset = assets[data[0] as usize % assets.len()];
                let amount = u128::from_ne_bytes(data[1..17].try_into().ok()?);
                Some(RuntimeCall::Omnipool(
                    pallet_omnipool::Call::add_liquidity { asset, amount },
                ))
            }
            _ => None,
        }
    }
}

pub struct StableswapHandler;

const POOL_IDS: [u32; 5] = [100, 101, 102, 690, 4200]; //TODO: get th values from stableswap storage

const STABLEPOOL_ASSETS: [u32; 11] = [10, 18, 21, 23, 11, 19, 1007, 1000809, 22, 15, 1001];

impl TryExtrinsic<RuntimeCall, u32> for StableswapHandler {
    fn try_extrinsic(&self, identifier: u8, data: &[u8], assets: &[u32]) -> Option<RuntimeCall> {
        match identifier {
            10 if data.len() > 19 => {
                let pool_id = POOL_IDS[data[0] as usize % POOL_IDS.len()];
                let asset_in = STABLEPOOL_ASSETS[data[1] as usize % STABLEPOOL_ASSETS.len()];
                let asset_out = STABLEPOOL_ASSETS[data[2] as usize % STABLEPOOL_ASSETS.len()];
                let amount_in = u128::from_ne_bytes(data[3..19].try_into().ok()?);
                Some(RuntimeCall::Stableswap(pallet_stableswap::Call::sell {
                    pool_id,
                    asset_in,
                    asset_out,
                    amount_in,
                    min_buy_amount: 0,
                }))
            }
            11 if data.len() > 19 => {
                let pool_id = POOL_IDS[data[0] as usize % POOL_IDS.len()];
                let asset_in = STABLEPOOL_ASSETS[data[1] as usize % STABLEPOOL_ASSETS.len()];
                let asset_out = STABLEPOOL_ASSETS[data[2] as usize % STABLEPOOL_ASSETS.len()];
                let amount_out = u128::from_ne_bytes(data[3..19].try_into().ok()?);
                Some(RuntimeCall::Stableswap(pallet_stableswap::Call::buy {
                    pool_id,
                    asset_in,
                    asset_out,
                    amount_out,
                    max_sell_amount: u128::MAX,
                }))
            }
            12 if data.len() > 19 => {
                let pool_id = POOL_IDS[data[0] as usize % POOL_IDS.len()];
                let asset_id = STABLEPOOL_ASSETS[data[1] as usize % STABLEPOOL_ASSETS.len()];
                let _asset_out = STABLEPOOL_ASSETS[data[2] as usize % STABLEPOOL_ASSETS.len()];
                let shares = u128::from_ne_bytes(data[3..19].try_into().ok()?);
                Some(RuntimeCall::Stableswap(
                    pallet_stableswap::Call::add_liquidity_shares {
                        pool_id,
                        shares,
                        asset_id,
                        max_asset_amount: u128::MAX,
                    },
                ))
            }
            _ => None,
        }
    }
}
