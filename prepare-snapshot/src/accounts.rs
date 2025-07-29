use crate::FuzzedRuntime;

pub fn get_technical_committee() -> Vec<primitives::AccountId> {
    (0..3).map(|i| [i; 32].into()).collect()
}

pub fn get_duster_reward_account() -> primitives::AccountId {
    [99; 32].into()
}

pub fn get_duster_dest_account() -> primitives::AccountId {
    [100; 32].into()
}

pub fn get_omnipool_position_owner() -> primitives::AccountId {
    [0; 32].into()
}

pub fn get_fuzzer_accounts() -> Vec<primitives::AccountId> {
    (0..20).map(|i| [i; 32].into()).collect()
}

pub fn get_important_accounts() -> Vec<primitives::AccountId> {
    vec![pallet_omnipool::Pallet::<FuzzedRuntime>::protocol_account()]
}
