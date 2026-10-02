//! Block production, ported from `runtime-fuzzer/src/main.rs`.

use crate::{Header, Runtime, RuntimeOrigin};
use codec::Encode;
use hydradx_runtime::{Executive, ParachainSystem, System, Timestamp};
use primitives::constants::time::SLOT_DURATION;
use sp_consensus_aura::{Slot, AURA_ENGINE_ID};
use sp_core::H256;
use sp_runtime::traits::Header as _;
use sp_runtime::{Digest, DigestItem};
use std::collections::BTreeMap;

pub fn initialize_block(block: u32, prev_header: Option<&Header>) {
	let last_block = System::block_number();
	assert!(last_block < block, "block {block} not after {last_block}");
	let last_timestamp = pallet_timestamp::Now::<Runtime>::get();
	let new_timestamp = last_timestamp + u64::from(block - last_block) * SLOT_DURATION;

	// Executive::initialize_block requires current + 1 == block.
	System::set_block_number(block - 1);

	// One 6 s slot per block, derived from the timestamp (Aura asserts slot == now / SLOT_DURATION;
	// mainnet slots are wall-clock based, so the legacy `slot = block` would move backwards).
	let slot = new_timestamp / SLOT_DURATION;
	let pre_digest = Digest {
		logs: vec![DigestItem::PreRuntime(AURA_ENGINE_ID, Slot::from(slot).encode())],
	};
	let header = Header::new(
		block,
		H256::default(),
		H256::default(),
		prev_header.map(Header::hash).unwrap_or_default(),
		pre_digest,
	);
	Executive::initialize_block(&header);

	Timestamp::set(RuntimeOrigin::none(), new_timestamp).unwrap();

	use cumulus_primitives_core::relay_chain::HeadData;
	use cumulus_primitives_parachain_inherent::ParachainInherentData;
	use cumulus_test_relay_sproof_builder::RelayStateSproofBuilder;

	let parent_head = HeadData(prev_header.unwrap_or(&header).encode());
	let sproof_builder = RelayStateSproofBuilder {
		// Slim snapshots may lack ParachainInfo; the proof must use whatever id the runtime reads.
		para_id: hydradx_runtime::ParachainInfo::parachain_id(),
		// Relay slots are 6 s too; one fresh relay slot per block keeps the velocity check happy.
		current_slot: cumulus_primitives_core::relay_chain::Slot::from(new_timestamp / 6_000),
		included_para_head: Some(parent_head.clone()),
		..Default::default()
	};
	let (relay_parent_storage_root, relay_chain_state) = sproof_builder.into_state_root_and_proof();
	let data = ParachainInherentData {
		validation_data: polkadot_primitives::PersistedValidationData {
			parent_head,
			relay_parent_number: block,
			relay_parent_storage_root,
			max_pov_size: 1000,
		},
		relay_chain_state,
		downward_messages: Vec::default(),
		horizontal_messages: BTreeMap::default(),
		collator_peer_id: None,
		relay_parent_descendants: Vec::default(),
	};
	ParachainSystem::set_validation_data(RuntimeOrigin::none(), data).unwrap();
}

pub fn finalize_block() -> Header {
	Executive::finalize_block()
}
