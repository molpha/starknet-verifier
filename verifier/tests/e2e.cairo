//! End-to-end contract test.
//!
//! Deploys the `Verifier` contract, registers the 10 fixture nodes through the
//! real `add_node` path (each gated by a freshly-produced Schnorr proof-of-
//! possession), then verifies the unmodified EVM fixture payload through the
//! public `verify` entrypoint. This exercises storage, registry versioning,
//! node selection, plain-sum aggregation, and Schnorr verification together.

use snforge_std::{start_cheat_caller_address, stop_cheat_caller_address};
use starknet::ContractAddress;
use verifier::interface::{DataUpdate, IVerifierDispatcherTrait, SchnorrProof, SchnorrSignature};
use verifier::secp256k1_utils as ec;
use super::fixtures::{compressed, fixture_nodes};
use super::support::{
    ADMIN, deploy, deploy_with_params, fixture_data_update, fixture_node_registration,
    fixture_signature, register_fixture_nodes, tampered_data_update,
};

#[test]
fn register_nodes_and_verify_evm_fixture() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);

    assert(dispatcher.get_registry_version() == 10, 'registry version');
    assert(dispatcher.get_total_nodes() == 10, 'total nodes');
    assert(dispatcher.verify(fixture_data_update(), fixture_signature()), 'fixture must verify');
}

#[test]
fn remove_node_updates_set_and_aggregate() {
    let dispatcher = deploy();
    let address = dispatcher.contract_address;
    register_fixture_nodes(dispatcher, 10);

    // Remove the node at 1-based index 5 (array slot 4).
    let removed_slot: u32 = 4;
    let nodes = fixture_nodes();
    let (rprefix, rx, _) = *nodes.at(removed_slot);
    let (rpx, rpy) = ec::decompress(@compressed(rprefix, rx));
    let removed_id = ec::point_eth_address(rpx, rpy);
    assert(dispatcher.is_node(removed_id), 'should be node first');

    start_cheat_caller_address(address, ADMIN());
    dispatcher.remove_node(removed_id);
    stop_cheat_caller_address(address);

    assert(dispatcher.get_registry_version() == 11, 'version after remove');
    assert(dispatcher.get_total_nodes() == 9, 'total after remove');
    assert(!dispatcher.is_node(removed_id), 'removed must be gone');

    // The running aggregate must equal the plain sum of the remaining 9 keys.
    let mut acc_x: u256 = 0;
    let mut acc_y: u256 = 0;
    let mut have = false;
    let mut j: u32 = 0;
    while j < nodes.len() {
        if j != removed_slot {
            let (p, x, _) = *nodes.at(j);
            let (px, py) = ec::decompress(@compressed(p, x));
            if !have {
                acc_x = px;
                acc_y = py;
                have = true;
            } else {
                let (nx, ny) = ec::add_coords(acc_x, acc_y, px, py);
                acc_x = nx;
                acc_y = ny;
            }
        }
        j += 1;
    }
    let (agg_x, agg_y) = dispatcher.get_aggregate_key();
    assert(agg_x == acc_x && agg_y == acc_y, 'aggregate after remove');
}

#[test]
fn verify_rejects_tampered_value() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);
    assert(
        !dispatcher.verify(tampered_data_update(), fixture_signature()), 'tampered must fail',
    );
}

#[test]
#[should_panic]
fn non_admin_cannot_add_node() {
    let dispatcher = deploy();
    let comp: ByteArray = "";
    let pop = SchnorrProof { signature: 0, commitment: 0 };
    dispatcher.add_node(comp, pop);
}

#[test]
#[should_panic]
fn non_admin_cannot_remove_node() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 1);
    let (_, _, node) = fixture_node_registration(dispatcher, 0);
    dispatcher.remove_node(node);
}

#[test]
#[should_panic]
fn non_admin_cannot_transfer_admin() {
    let dispatcher = deploy();
    let new_admin: ContractAddress = 0x1234.try_into().unwrap();
    dispatcher.transfer_protocol_admin(new_admin);
}

#[test]
#[should_panic]
fn add_node_rejects_invalid_pop() {
    let dispatcher = deploy();
    let address = dispatcher.contract_address;
    let (comp, _, _) = fixture_node_registration(dispatcher, 0);
    let invalid_pop = SchnorrProof { signature: 1, commitment: 1 };

    start_cheat_caller_address(address, ADMIN());
    dispatcher.add_node(comp, invalid_pop);
    stop_cheat_caller_address(address);
}

#[test]
#[should_panic]
fn add_node_rejects_duplicate_node() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 1);
    let address = dispatcher.contract_address;
    let (comp, pop, _) = fixture_node_registration(dispatcher, 0);

    start_cheat_caller_address(address, ADMIN());
    dispatcher.add_node(comp, pop);
    stop_cheat_caller_address(address);
}

#[test]
#[should_panic]
fn constructor_rejects_zero_protocol_admin() {
    let zero_admin: ContractAddress = 0.try_into().unwrap();
    let _dispatcher = deploy_with_params(zero_admin, 2);
}

#[test]
#[should_panic]
fn verify_rejects_zero_signatures_required() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);
    let update = fixture_data_update();
    let bad_update = DataUpdate {
        feed_id: update.feed_id,
        registry_version: update.registry_version,
        signatures_required: 0,
        value: update.value,
        canonical_timestamp: update.canonical_timestamp,
    };

    dispatcher.verify(bad_update, fixture_signature());
}

#[test]
#[should_panic]
fn verify_rejects_nonexistent_registry_version() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);
    let update = fixture_data_update();
    let bad_update = DataUpdate {
        feed_id: update.feed_id,
        registry_version: update.registry_version + 1,
        signatures_required: update.signatures_required,
        value: update.value,
        canonical_timestamp: update.canonical_timestamp,
    };

    dispatcher.verify(bad_update, fixture_signature());
}

#[test]
#[should_panic]
fn verify_rejects_signer_outside_selection_bitmap() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);
    let sig = fixture_signature();
    let bad_sig = SchnorrSignature {
        signature: sig.signature,
        commitment: sig.commitment,
        signers_bitmap: sig.signers_bitmap | 1,
    };

    dispatcher.verify(fixture_data_update(), bad_sig);
}

#[test]
#[should_panic]
fn verify_rejects_bitmap_bit_above_node_count() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);
    let sig = fixture_signature();
    let bad_sig = SchnorrSignature {
        signature: sig.signature,
        commitment: sig.commitment,
        signers_bitmap: sig.signers_bitmap | 1024,
    };

    dispatcher.verify(fixture_data_update(), bad_sig);
}

#[test]
#[should_panic]
fn verify_rejects_insufficient_signers() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);
    let sig = fixture_signature();
    let bad_sig = SchnorrSignature {
        signature: sig.signature, commitment: sig.commitment, signers_bitmap: 2,
    };

    dispatcher.verify(fixture_data_update(), bad_sig);
}

#[test]
fn historical_payload_still_verifies_after_signer_removal() {
    let dispatcher = deploy();
    let address = dispatcher.contract_address;
    register_fixture_nodes(dispatcher, 10);
    assert(dispatcher.verify(fixture_data_update(), fixture_signature()), 'pre-remove verify');

    // Slot 7 is 1-based node index 8, whose bit is set in the fixture signer bitmap.
    let (_, _, signer_node) = fixture_node_registration(dispatcher, 7);
    start_cheat_caller_address(address, ADMIN());
    dispatcher.remove_node(signer_node);
    stop_cheat_caller_address(address);

    assert(dispatcher.get_registry_version() == 11, 'version after signer remove');
    assert(!dispatcher.is_node(signer_node), 'signer removed from current');
    assert(dispatcher.verify(fixture_data_update(), fixture_signature()), 'old version verifies');
}
