mod accounts;

use std::collections::HashMap;
use codec::{DecodeLimit, Encode};
use hydradx_runtime::*;
use sp_runtime::{
    traits::{Dispatchable, Header},
};
use std::path::PathBuf;
use frame_support::traits::{StorageInfo, StorageInfoTrait};
use frame_remote_externalities::RemoteExternalities;
use hydradx_runtime::Tokens;
use orml_traits::MultiCurrency;
use pallet_asset_registry::AssetDetails;
use primitives::constants::currency::UNITS;
use sp_core::storage::Storage;
use sp_io::TestExternalities;
use accounts::*;

/// Types from the fuzzed runtime.
type FuzzedRuntime = hydradx_runtime::Runtime;

type Balance = <FuzzedRuntime as pallet_balances::Config>::Balance;
type RuntimeOrigin = <FuzzedRuntime as frame_system::Config>::RuntimeOrigin;
type AccountId = <FuzzedRuntime as frame_system::Config>::AccountId;

const SNAPSHOT_PATH: &str = "data/MOCK_SNAPSHOT";
const MAINNET_SNAPSHOT_PATH: &str = "data/MAINNET";
const PARA_ID: u32 = 2034;

fn get_storage_prefixes_to_copy() -> Vec<Vec<u8>>{
    let info: Vec<Vec<StorageInfo>> = vec![
        pallet_omnipool::Pallet::<FuzzedRuntime>::storage_info(),
        pallet_asset_registry::Pallet::<FuzzedRuntime>::storage_info(),
        pallet_stableswap::Pallet::<FuzzedRuntime>::storage_info(),
        pallet_ema_oracle::Pallet::<FuzzedRuntime>::storage_info(),
        pallet_dynamic_fees::Pallet::<FuzzedRuntime>::storage_info(),
        pallet_evm::Pallet::<FuzzedRuntime>::storage_info(),
        pallet_transaction_multi_payment::Pallet::<FuzzedRuntime>::storage_info(),
        pallet_xyk::Pallet::<FuzzedRuntime>::storage_info(),
    ];
    let exclude = vec!["Omnipool:Positions", "MultiTransactionPayment:AccountCurrencyMap"];
    let mut result = vec![];
    for i in info {
        for entry in i {
            let  pallet_name= entry.pallet_name;
            let storagE_name = entry.storage_name;
            let name = format!("{}:{}", String::from_utf8_lossy(&pallet_name), String::from_utf8_lossy(&storagE_name));
            println!("name: {:?}", name);
            if !exclude.contains(&name.as_str()){
                let prefix = entry.prefix;
                result.push(prefix.clone());
            }else{
                println!("excluded: {:?}", name);
            }
        }
    }
    result
}

pub fn get_storage_under_prefix(
    ext: &mut RemoteExternalities<hydradx_runtime::Block>,
    prefix: &[u8],
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();

    ext.execute_with(|| {
        let mut key = prefix.to_vec();

        loop {
            match sp_io::storage::next_key(&key) {
                Some(next_key) => {
                    // Check if key still belongs to our prefix
                    if !next_key.starts_with(prefix) {
                        break;
                    }

                    key = next_key.clone();

                    if let Some(value) = sp_io::storage::get(&key) {
                        result.push((key.clone(), value.to_vec()));
                    }
                }
                None => break,
            }
        }
    });

    result
}

fn genesis_storage(nonnative_balances : Vec<(AccountId, AssetId, Balance)>, native_balances: Vec<(AccountId,Balance)>, assets: &RegistryState) -> TestExternalities {
    // ensure asset ids are unique
    let mut asset_ids = assets.iter().map(|x| x.0).collect::<Vec<_>>();
    asset_ids.sort();
    asset_ids.dedup();

    let storage: Storage = {
        use sp_runtime::app_crypto::ByteArray;
        use sp_runtime::BuildStorage;

        let initial_authorities: Vec<(primitives::AccountId, AuraId)> = vec![
            ([0; 32].into(), AuraId::from_slice(&[0; 32]).unwrap()),
            ([1; 32].into(), AuraId::from_slice(&[1; 32]).unwrap()),
        ];

        RuntimeGenesisConfig {
            system: Default::default(),
            session: SessionConfig {
                keys: initial_authorities
                    .iter()
                    .map(|x| {
                        (
                            x.0.clone(),
                            x.0.clone(),
                            hydradx_runtime::opaque::SessionKeys { aura: x.1.clone() },
                        )
                    })
                    .collect::<Vec<_>>(),
                non_authority_keys: Default::default(),
            },
            aura: Default::default(),
            collator_selection: CollatorSelectionConfig {
                invulnerables: initial_authorities.iter().cloned().map(|(acc, _)| acc).collect(),
                candidacy_bond: 10_000 * UNITS,
                ..Default::default()
            },
            balances: BalancesConfig {
                balances: native_balances,
            },
            council: CouncilConfig {
                members: get_council_members(),
                phantom: Default::default(),
            },
            technical_committee: TechnicalCommitteeConfig {
                members: get_technical_committee(),
                phantom: Default::default(),
            },
            vesting: VestingConfig { vesting: vec![] },
            asset_registry: AssetRegistryConfig{
                registered_assets: asset_ids.iter().map(|asset_id| (Some(*asset_id), None, 0,None, None, None,true)).collect::<Vec<_>>(),
                ..Default::default()
            },
            multi_transaction_payment: MultiTransactionPaymentConfig::default(),
            tokens: TokensConfig {
                balances: nonnative_balances,
            },
            treasury: Default::default(),
            elections: Default::default(),
            genesis_history: GenesisHistoryConfig::default(),
            claims: ClaimsConfig {
                claims: Default::default(),
            },
            parachain_info: ParachainInfoConfig {
                parachain_id: PARA_ID.into(),
                ..Default::default()
            },
            aura_ext: Default::default(),
            polkadot_xcm: Default::default(),
            ema_oracle: Default::default(),
            duster: DusterConfig {
                account_blacklist: vec![],
                reward_account: Some(get_duster_reward_account()),
                dust_account: Some(get_duster_dest_account()),
            },
            omnipool_warehouse_lm: Default::default(),
            omnipool_liquidity_mining: Default::default(),
            evm_chain_id: hydradx_runtime::EVMChainIdConfig {
                chain_id: 2_222_222u32.into(),
                ..Default::default()
            },
            ethereum: Default::default(),
            evm: Default::default(),
            xyk_warehouse_lm: Default::default(),
            xyk_liquidity_mining: Default::default(),
        }
            .build_storage()
            .unwrap()
    };

    let mut externalities = TestExternalities::new(storage);

    externalities

}

fn load_registry_state(ext: &mut RemoteExternalities<hydradx_runtime::Block>) -> Vec<(AssetId, AssetDetails<<FuzzedRuntime as  pallet_asset_registry::Config>::StringLimit>)>{
    let mut result= vec![];
    ext.execute_with(|| {
        let registry = pallet_asset_registry::Assets::<FuzzedRuntime>::iter_keys();
        for r in registry {
            let asset = pallet_asset_registry::Assets::<FuzzedRuntime>::get(r).expect("asset not found");
            if !asset.is_sufficient {
                continue;
            }
            if asset.decimals.is_none(){
                continue;
            }
            result.push((r, asset));
        }
    });
    result
}

type RegistryState = Vec<(AssetId, AssetDetails<<FuzzedRuntime as pallet_asset_registry::Config>::StringLimit>)>;

fn load_account_balance(ext: &mut RemoteExternalities<hydradx_runtime::Block>, account: AccountId, asset_ids: &RegistryState) -> Vec<(AccountId, AssetId, Balance)>{
    let mut result = vec![];
    ext.execute_with(|| {
        for (asset_id, _) in asset_ids {
            let balance = Tokens::free_balance(*asset_id, &account);
            if balance > 0 {
                result.push((account.clone(), *asset_id, balance));
            }
        }
    });
    result
}

fn load_balances_for_important_accounts(ext: &mut RemoteExternalities<hydradx_runtime::Block>, asset_ids: &RegistryState) -> Vec<(AccountId, AssetId, Balance)>{
    let accounts = get_important_accounts();
    let mut result = vec![];
    for acc in &accounts {
        let balances = load_account_balance(ext, acc.clone(), &asset_ids);
        result.extend(
            balances
        )
    }
    result
}

fn get_pool_accounts(ext: &mut RemoteExternalities<hydradx_runtime::Block>) -> Vec<AccountId>{
    let mut result = vec![];
    ext.execute_with(|| {
        let pools = pallet_stableswap::Pools::<FuzzedRuntime>::iter_keys();
        for r in pools {
            let acc = pallet_stableswap::Pallet::<FuzzedRuntime>::pool_account(r);
            result.push(acc);
        }
    });
    result
}

fn load_pools_balances(ext: &mut RemoteExternalities<hydradx_runtime::Block>, asset_ids: &RegistryState) -> Vec<(AccountId, AssetId, Balance)>{
    let pool_accounts = get_pool_accounts(ext);
    let mut result = vec![];
    for acc in &pool_accounts {
        let balances = load_account_balance(ext, acc.clone(), asset_ids);
        result.extend(
            balances
        )
    }
    result
}

fn load_native_balances(ext: &mut RemoteExternalities<hydradx_runtime::Block>) -> Vec<(AccountId, Balance)>{
    let accounts = get_important_accounts();
    let pool_accounts = get_pool_accounts(ext);
    let mut result = vec![];
    for acc in &accounts {
        let balance = ext.execute_with(|| pallet_balances::Pallet::<FuzzedRuntime>::free_balance(acc.clone()));
        if balance > 0 {
            result.push((acc.clone(), balance));
        }
    }
    for acc in &pool_accounts{
        let balance = ext.execute_with(|| pallet_balances::Pallet::<FuzzedRuntime>::free_balance(acc.clone()));
        if balance > 0 {
            result.push((acc.clone(), balance));
        }
    }
    result
}

fn endow_native_accounts() -> Vec<(AccountId, Balance)>{
    let mut result = vec![];
    let accounts = get_fuzzer_accounts();
    for acc in &accounts {
        result.push((acc.clone(), 1_000_000_000_000_000_000u128));
    }
    result
}

fn endow_nonnative_accounts(assets_ids: &RegistryState) -> Vec<(AccountId, AssetId, Balance)>{
    let mut result = vec![];
    let accounts = get_fuzzer_accounts();

    for (asset_id, details) in assets_ids {
        for acc in &accounts {
            if !details.is_sufficient {
                continue;
            }
            let Some(decimals) = details.decimals else{
                println!("decimals not set for asset {:?}", asset_id);
                continue;
            };
            let balance = 1_000_000 * 10u128.pow(decimals as u32);
            result.push((acc.clone(), *asset_id, balance));
        }
    }

    result
}

pub fn main() {
    let mut ext_mainnet = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use frame_remote_externalities::*;

            let snapshot_config = SnapshotConfig::from(String::from(MAINNET_SNAPSHOT_PATH));
            let offline_config = OfflineConfig {
                state_snapshot: snapshot_config,
            };
            let mode = Mode::Offline(offline_config);

            let builder = Builder::<hydradx_runtime::Block>::new().mode(mode);

            builder.build().await.unwrap()
        });

    // Load balances of some important accounts
    let registry_state = load_registry_state(&mut ext_mainnet);
    let mut nonnative_balances = load_balances_for_important_accounts(&mut ext_mainnet, &registry_state);
    let pool_balances = load_pools_balances(&mut ext_mainnet, &registry_state);
    let fuzzer_funded_accounts = endow_nonnative_accounts(&registry_state);
    nonnative_balances.extend(pool_balances);
    nonnative_balances.extend(fuzzer_funded_accounts);

    let mut native_balances = load_native_balances(&mut ext_mainnet);
    let fuzzer_funded_accounts = endow_native_accounts();
    native_balances.extend(fuzzer_funded_accounts);

    // Copy storage
    let prefixes = get_storage_prefixes_to_copy();
    let mut storage_pairs = vec![];
    for prefix in prefixes {
        let r = get_storage_under_prefix(&mut ext_mainnet, &prefix);
        storage_pairs.extend(r);
    }

    let mut mocked_externalities = genesis_storage(nonnative_balances, native_balances, &registry_state);
    mocked_externalities.execute_with(|| {
        for (key, value) in storage_pairs {
            sp_io::storage::set(&key, &value);
        }
    });
    mocked_externalities.commit_all().unwrap();
    mocked_externalities.execute_with(|| {
        let assets = pallet_omnipool::Assets::<FuzzedRuntime>::iter_keys();
        for a in assets {
            let asset = pallet_omnipool::Assets::<FuzzedRuntime>::get(a);
            //println!("{:?}: {:?}", a, asset);
        }

        let registry = pallet_asset_registry::Assets::<FuzzedRuntime>::iter_keys();
        for r in registry {
            let asset = pallet_asset_registry::Assets::<FuzzedRuntime>::get(r);
            //println!("{:?}: {:?}", r, asset);
        }

        let pools = pallet_stableswap::Pools::<FuzzedRuntime>::iter_keys();
        for r in pools {
            let asset = pallet_stableswap::Pools::<FuzzedRuntime>::get(r);
            //println!("{:?}: {:?}", r, asset);
        }

        let c = pallet_transaction_multi_payment::AcceptedCurrencies::<FuzzedRuntime>::iter_keys();
        for r in c {
            let asset = pallet_transaction_multi_payment::AcceptedCurrencies::<FuzzedRuntime>::get(r);
            //println!("{:?}: {:?}", r, asset);
        }
    });

    let snapshot_path = PathBuf::from(SNAPSHOT_PATH);
    scraper::save_externalities::<hydradx_runtime::Block>(mocked_externalities, snapshot_path).unwrap();
}
