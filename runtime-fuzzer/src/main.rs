extern crate polkadot_primitives;

use codec::{DecodeLimit, Encode};
use cumulus_primitives_core::relay_chain::Header;
use frame_support::traits::{StorageInfo, StorageInfoTrait};
use frame_support::{
    dispatch::GetDispatchInfo, pallet_prelude::Weight,
    traits::{IntegrityTest, TryState, TryStateSelect},
    weights::constants::WEIGHT_REF_TIME_PER_SECOND,
};
use hydradx_runtime::*;
use primitives::constants::time::SLOT_DURATION;
use sp_consensus_aura::{Slot, AURA_ENGINE_ID};
use sp_core::H256;
use sp_runtime::{
    traits::{Dispatchable, Header as _},
    Digest, DigestItem,
};
use std::{collections::BTreeMap, io::Write, path::PathBuf, time::{Duration, Instant}};

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

/// Constants for the fee-memory mapping
#[cfg(not(feature = "fuzzing"))]
const FILENAME_MEMORY_MAP: &str = "memory_map.output";

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
    // We ensure that on each run, the mapping is a fresh one
    #[cfg(not(any(feature = "fuzzing", feature = "coverage")))]
    if std::fs::remove_file(FILENAME_MEMORY_MAP).is_err() {
        // println!("Can't remove the map file, but it's not a problem.");
    }

    let original_data = std::fs::read(SNAPSHOT_PATH).unwrap();
    let snapshot = scraper::get_snapshot_from_bytes::<Block>(original_data)
        .expect("Failed to create snapshot");
    let (backend, state_version, root) =
        scraper::construct_backend_from_snapshot::<Block>(snapshot)
            .expect("Failed to create backend");
    let assets: Vec<u32> = OMNIPOOL_ASSETS.to_vec();
    let accounts: Vec<AccountId> = (0..20).map(|i| [i; 32].into()).collect();

    ziggy::fuzz!(|data: &[u8]| {
        let iteratable = Data {
            data,
            pointer: 0,
            size: 0,
        };

        // Max weight for a block.
        let max_weight: Weight = Weight::from_parts(WEIGHT_REF_TIME_PER_SECOND * 2, 0);

        let mut block_count = 0;
        let mut extrinsics_in_block = 0;

        let extrinsics: Vec<(Option<u32>, usize, RuntimeCall)> = iteratable
            .filter_map(|data| {
                // We have reached the limit of block we want to decode
                #[allow(clippy::absurd_extreme_comparisons)]
                if MAX_BLOCKS_PER_INPUT != 0 && block_count >= MAX_BLOCKS_PER_INPUT {
                    return None;
                }
                // Min lengths required for the data
                // - lapse is u32 (4 bytes),
                // - origin is u16 (2 bytes)
                // - structured fuzzer (1 byte)
                // -> 7 bytes minimum
                let min_data_len = 4 + 2 + 1;
                if data.len() <= min_data_len {
                    return None;
                }
                let lapse: u32 = u32::from_ne_bytes(data[0..4].try_into().unwrap());
                let origin: usize = u16::from_ne_bytes(data[4..6].try_into().unwrap()) as usize;
                let specific_extrinsic: u8 = data[6];
                let mut encoded_extrinsic: &[u8] = &data[7..];

                // If the lapse is in the range [1, MAX_BLOCK_LAPSE] it is valid.
                let maybe_lapse = match lapse {
                    1..=MAX_BLOCK_LAPSE => Some(lapse),
                    _ => None,
                };
                // We have reached the limit of extrinsics for this block
                #[allow(clippy::absurd_extreme_comparisons)]
                if maybe_lapse.is_none()
                    && MAX_EXTRINSICS_PER_BLOCK != 0
                    && extrinsics_in_block >= MAX_EXTRINSICS_PER_BLOCK
                {
                    return None;
                }

                let maybe_extrinsic = if let Some(extrinsic) =
                    try_specific_extrinsic(specific_extrinsic, encoded_extrinsic, &assets)
                {
                    Ok(extrinsic)
                } else {
                    DecodeLimit::decode_all_with_depth_limit(32, &mut encoded_extrinsic)
                };

                if let Ok(decoded_extrinsic) = maybe_extrinsic {
                    if maybe_lapse.is_some() {
                        block_count += 1;
                        extrinsics_in_block = 1;
                    } else {
                        extrinsics_in_block += 1;
                    }
                    // We have reached the limit of block we want to decode
                    if MAX_BLOCKS_PER_INPUT != 0 && block_count >= MAX_BLOCKS_PER_INPUT {
                        return None;
                    }

                    Some((maybe_lapse, origin, decoded_extrinsic))
                } else {
                    None
                }
            })
            .collect();

        if extrinsics.is_empty() {
            return;
        }

        // Start block
        let mut block: u32 = 8_151_183;
        let mut elapsed: Duration = Duration::ZERO;
        let mut weight: Weight = Weight::zero();

        //let mut externalities = scraper::create_externalities_from_snapshot::<Block>(&snapshot).expect("Failed to create ext");
        let mut externalities = scraper::create_externalities_with_backend::<Block>(
            backend.clone(),
            root,
            state_version,
        );

        let dummy_header: Header<u32, BlakeTwo256> = Header {
            parent_hash: Default::default(),
            number: block_number,
            state_root: Default::default(),
            extrinsics_root: Default::default(),
            digest: Default::default(),
        };

        externalities.execute_with(|| {
            initialize_block(block, dummy_header);

            // Calls that need to be executed in the first block go here
            for (maybe_lapse, origin, extrinsic) in extrinsics {
                if recursively_find_call(extrinsic.clone(), |call| {
                    matches!(&call, RuntimeCall::XTokens(..))
                        || matches!(&call, RuntimeCall::Timestamp(..))
                        || matches!(&call, RuntimeCall::ParachainSystem(..))
                }) {
                    #[cfg(not(feature = "fuzzing"))]
                    println!("    Skipping because of custom filter");
                    continue;
                }
                // If the lapse is in the range [0, MAX_BLOCK_LAPSE] we finalize the block and
                // initialize a new one.
                if let Some(lapse) = maybe_lapse {
                    #[cfg(not(feature = "fuzzing"))]
                    println!("  lapse:       {:?}", lapse);
                    // We end the current block
                    let prev_header = finalize_block(elapsed);

                    // We update our state variables
                    block += lapse;
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
                let origin_account = accounts[origin % accounts.len()].clone();

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
                        .dispatch(RuntimeOrigin::signed(origin_account.clone()))
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
        for acc in frame_system::Account::<FuzzedRuntime>::iter() {
            let acc_consumers = acc.1.consumers;
            let acc_providers = acc.1.providers;
            if acc_consumers > 0 && acc_providers == 0 {
                panic!("Invalid state");
            }
        }

        #[cfg(not(feature = "fuzzing"))]
        println!("Running integrity tests\n");
        // We run all developer-defined integrity tests
        <AllPalletsWithSystem as IntegrityTest>::integrity_test();
    });
}

fn initialize_block(block: u32, prev_header: Option<&Header>) {
    #[cfg(not(feature = "fuzzing"))]
    println!("\ninitializing block {block}");

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
    Timestamp::set(RuntimeOrigin::none(), u64::from(block) * SLOT_DURATION).unwrap();

    #[cfg(not(feature = "fuzzing"))]
    println!("  setting parachain validation data");
    let parachain_validation_data = {
        use cumulus_primitives_core::relay_chain::HeadData;
        use cumulus_primitives_parachain_inherent::ParachainInherentData;
        use cumulus_test_relay_sproof_builder::RelayStateSproofBuilder;

        let parent_head = HeadData(prev_header.unwrap_or(parent_header).encode());
        let sproof_builder = RelayStateSproofBuilder {
            para_id: 100.into(),
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

use frame_remote_externalities::RemoteExternalities;
use frame_support::{pallet_prelude::Get, StoragePrefixedMap};
#[cfg(not(any(feature = "fuzzing", feature = "coverage")))]
use frame_support::{dispatch::DispatchResultWithPostInfo, traits::Currency};
use sp_io::TestExternalities;
#[cfg(not(any(feature = "fuzzing", feature = "coverage")))]
use stats_alloc::{StatsAlloc, INSTRUMENTED_SYSTEM};
#[cfg(not(any(feature = "fuzzing", feature = "coverage")))]
use std::{
    alloc::System,
    collections::HashMap,
    fmt::{self, Display, Formatter},
    fs::OpenOptions,
    io::prelude::*,
    ops::Add,
};

/// A type to represent a big integer. This is mainly used to avoid overflow
#[cfg(not(any(feature = "fuzzing", feature = "coverage")))]
type DeltaSize = i128;

/// Represents the different statistics that will be captured during the analysis
///
/// # Fields
/// - `fee`: Fees used to execute the extrinsic
/// - `balance_delta`: The difference of balance before and after executing an extrinsic
/// - `reserve_delta`: The difference of the reserved balance while executing an extrinsic
/// - `lock_delta`: The difference of the locked balance before and after executing an extrinsic
/// - `memory_delta`: Memory used to execute a specific extrinsic, based on the allocator stats
/// - `elapsed`: Time spent to execute the extrinsic
#[cfg(not(any(feature = "fuzzing", feature = "coverage")))]
#[derive(Copy, Clone, Debug)]
pub struct MappingData {
    fee: Balance,
    balance_delta: DeltaSize,
    reserve_delta: DeltaSize,
    lock_delta: DeltaSize,
    memory_delta: DeltaSize,
    elapsed: u128,
}

/// This struct is used to record important information about the memory allocator, timer,
/// and balance before processing an extrinsic **BEFORE** the executing of the extrinsic. It will
/// be used to calculate the deltas in a later stage.
///
/// # Fields
/// - `balance_before`: A struct holding information about weights, fees, and size before the
///   extrinsic execution.
/// - `reserved_before`: A struct holding information about reserved memory before the extrinsic
///   execution.
/// - `locked_before`: A struct holding information about locked memory before the extrinsic
///   execution.
/// - `allocated_before`: A struct holding information about allocated memory before the extrinsic
///   execution.
/// - `deallocated_before`: A struct holding information about deallocated memory before the
///   extrinsic execution.
/// - `timer`: An optional `Instant` capturing the time before the extrinsic execution starts.
#[cfg(not(any(feature = "fuzzing", feature = "coverage")))]
pub struct ExtrinsicInfoSnapshot {
    balance_before: DeltaSize,
    reserved_before: DeltaSize,
    locked_before: DeltaSize,
    allocated_before: DeltaSize,
    deallocated_before: DeltaSize,
    timer: Option<Instant>,
}

/// `MemoryMapper` is responsible for mapping different statistics captured during the analysis
/// of extrinsics' execution. It holds data such as fees, balance deltas, memory usage, and elapsed
/// time for each extrinsic. The `MemoryMapper` works in conjunction with `ExtrinsicInfoSnapshot`
/// to record important information about the memory allocator, timer, and balance before
/// processing an extrinsic.
///
/// # Fields
/// - `map`: The map between an extrinsic' string and its associated statistics
/// - `snapshot`: Backup of statistics used to calculate deltas
/// - `extrinsic_name`. Full name of the executed extrinsic with its parameters and origins
/// - `allocator`. Struct pointing to the memory allocator
#[cfg(not(any(feature = "fuzzing", feature = "coverage")))]
pub struct MemoryMapper<'a> {
    map: HashMap<String, MappingData>,
    snapshot: ExtrinsicInfoSnapshot,
    extrinsic_name: String,
    allocator: Option<&'a StatsAlloc<System>>,
}

/// `MapHelper` is a utility struct that simplifies the management of a memory map, providing
/// features such as `save`. It works in conjunction with `MemoryMapper`, providing an easier way to
/// interact with the data stored in the `MemoryMapper` instance.
///
/// # Fields
/// - `mapper`: Reference to the `MemoryMapper` instance for which `MapHelper` acts as a helper
#[cfg(not(any(feature = "fuzzing", feature = "coverage")))]
pub struct MapHelper<'a> {
    mapper: MemoryMapper<'a>,
}

#[cfg(not(any(feature = "fuzzing", feature = "coverage")))]
impl Display for MappingData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            ";{};{};{};{};{};{}\n",
            self.fee,
            self.balance_delta,
            self.reserve_delta,
            self.lock_delta,
            self.memory_delta,
            self.elapsed
        )
    }
}

#[cfg(not(any(feature = "fuzzing", feature = "coverage")))]
impl MemoryMapper<'_> {
    fn new() -> Self {
        MemoryMapper {
            map: HashMap::new(),
            snapshot: ExtrinsicInfoSnapshot {
                balance_before: 0,
                reserved_before: 0,
                locked_before: 0,
                allocated_before: 0,
                deallocated_before: 0,
                timer: None,
            },
            allocator: None,
            extrinsic_name: String::new(),
        }
    }
}

#[cfg(not(any(feature = "fuzzing", feature = "coverage")))]
impl MapHelper<'_> {
    fn save(&self) {
        let inner_save = || -> std::io::Result<()> {
            let mut map_file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(FILENAME_MEMORY_MAP)?;
            // Skip writing if extrinsic_name contains any blocklisted calls
            for (extrinsic_name, extrinsic_infos) in self.mapper.map.iter() {
                if BLACKLISTED_CALLS
                    .iter()
                    .any(|&call| extrinsic_name.contains(call))
                {
                    continue;
                }
                let _ = map_file.write(
                    &extrinsic_name
                        .clone()
                        .add(&extrinsic_infos.to_string())
                        .into_bytes(),
                )?;
            }
            Ok(())
        };

        if let Err(_err) = inner_save() {
            eprintln!("Failed to save {} ({:?})", &FILENAME_MEMORY_MAP, _err);
        } else {
            println!(
                "Map saved in {}.\nYou can now run `cargo stardust memory`",
                &FILENAME_MEMORY_MAP
            );
        }
    }
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
