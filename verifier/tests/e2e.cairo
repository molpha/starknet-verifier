//! End-to-end contract test.
//!
//! Deploys the `Verifier` contract, registers the 10 fixture nodes through the
//! real `add_node` path (each gated by a freshly-produced Schnorr proof-of-
//! possession), then verifies the unmodified EVM fixture payload through the
//! public `verify` entrypoint. This exercises storage, registry versioning,
//! node selection, plain-sum aggregation, and Schnorr verification together.

use snforge_std::{start_cheat_caller_address, stop_cheat_caller_address};
use verifier::interface::IVerifierDispatcherTrait;
use verifier::secp256k1_utils as ec;
use super::fixtures::{compressed, fixture_nodes};
use super::support::{
    ADMIN, deploy, fixture_data_update, fixture_signature, register_fixture_nodes,
    tampered_data_update,
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
