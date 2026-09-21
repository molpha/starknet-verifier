//! Gas benchmarks for the deployed `Verifier` contract.
//!
//! Each test performs exactly one call to the function under measurement (after
//! any setup), so `snforge test benchmarks --gas-report` yields per-selector
//! L2 gas with min / max / avg across scenarios.
//!
//! Run from `verifier/`:
//!   snforge test benchmarks --gas-report
//!   snforge test benchmarks --gas-report --detailed-resources
//!
//! `bench_gas_snapshot` runs every selector in one test so `snforge test
//! bench_gas_snapshot --gas-report` prints a single consolidated table. The
//! current numbers live in the repo README rather than here, so there is one
//! place to update when they move.
//!
//! Signer-scaling benchmarks (`bench_verify_N_signers`) use deterministic
//! payloads that pass every structural and selection check; the signature bytes
//! are placeholders, so the full aggregation + Schnorr path is still measured
//! and the call ends in `R_BAD_SIGNATURE`.
//!
//! Setup: 18-node registry, redundancy_buffer from the fixture, EVM fixture
//! source_id/timestamp. `signatures_required` = 3 for ≤5 signers, else
//! `signer_count - buffer`; `group_size` = min(signatures_required + buffer, 18),
//! matching the contract.
//!
//! Cost is not linear in signer count: `node_group_bitmap::derive` takes a
//! different branch when `group_size ≤ n/2`, `> n/2`, or `= n`. Aggregation and
//! Schnorr dominate, but the selection path shifts the total.

use snforge_std::{start_cheat_caller_address, stop_cheat_caller_address};
use verifier::interface::IVerifierDispatcherTrait;
use verifier::secp256k1_utils as ec;
use verifier::verify_codes;
use super::fixtures::{NODE_COUNT, compressed, fixture_nodes};
use super::support::{
    ADMIN, BENCH_NODE_COUNT, NO_MAX_AGE, call_verify_bench, deploy, fixture_attestation,
    register_fixture_nodes, register_nodes, run_verify_bench, tampered_attestation,
};

#[test]
fn bench_verify_3_signers() {
    run_verify_bench(3);
}

#[test]
fn bench_verify_5_signers() {
    run_verify_bench(5);
}

#[test]
fn bench_verify_9_signers() {
    run_verify_bench(9);
}

#[test]
fn bench_verify_12_signers() {
    run_verify_bench(12);
}

#[test]
fn bench_verify_18_signers() {
    run_verify_bench(18);
}

/// All signer-count scenarios on one 18-node registry → single `verify` gas table.
#[test]
fn bench_verify_signer_scaling() {
    let dispatcher = deploy();
    register_nodes(dispatcher, BENCH_NODE_COUNT);
    call_verify_bench(dispatcher, 3);
    call_verify_bench(dispatcher, 5);
    call_verify_bench(dispatcher, 9);
    call_verify_bench(dispatcher, 12);
    call_verify_bench(dispatcher, 18);
}

#[test]
fn bench_verify_success() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, NODE_COUNT);
    let (ok, code) = dispatcher.verify(fixture_attestation(), NO_MAX_AGE);
    assert(ok && code == verify_codes::R_OK, 'must verify');
}

#[test]
fn bench_verify_reject_tampered() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, NODE_COUNT);
    let (ok, code) = dispatcher.verify(tampered_attestation(), NO_MAX_AGE);
    assert(!ok && code == verify_codes::R_BAD_SIGNATURE, 'must reject');
}

#[test]
fn bench_add_node_first() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 1);
    assert(dispatcher.get_total_nodes() == 1, 'one node');
}

#[test]
fn bench_add_node_last() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, NODE_COUNT);
    assert(dispatcher.get_registry_version() == NODE_COUNT, 'version');
}

/// Identity and 0-based index of the fixture node used by the removal benches.
fn removal_target(index: u32) -> felt252 {
    let nodes = fixture_nodes();
    let (prefix, x, _) = *nodes.at(index);
    let (px, py) = ec::decompress(@compressed(prefix, x));
    ec::point_eth_address(px, py)
}

#[test]
fn bench_remove_node() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, NODE_COUNT);

    let address = dispatcher.contract_address;
    let removed_index: u32 = 4;
    let removed_id = removal_target(removed_index);

    start_cheat_caller_address(address, ADMIN());
    dispatcher.remove_node(removed_id, removed_index);
    stop_cheat_caller_address(address);

    assert(dispatcher.get_total_nodes() == NODE_COUNT - 1, 'one fewer node');
}

#[test]
fn bench_set_redundancy_buffer() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, NODE_COUNT);
    let address = dispatcher.contract_address;

    start_cheat_caller_address(address, ADMIN());
    dispatcher.set_redundancy_buffer(4);
    stop_cheat_caller_address(address);

    assert(dispatcher.get_redundancy_buffer() == 4, 'buffer updated');
}

#[test]
fn bench_view_get_total_nodes() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, NODE_COUNT);
    assert(dispatcher.get_total_nodes() == NODE_COUNT, 'total nodes');
}

#[test]
fn bench_view_get_aggregate_key() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, NODE_COUNT);
    let (_x, _y) = dispatcher.get_aggregate_key();
}

/// One-shot snapshot: all selectors in a single test for a consolidated gas report.
#[test]
fn bench_gas_snapshot() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, NODE_COUNT);

    let (ok, _) = dispatcher.verify(fixture_attestation(), NO_MAX_AGE);
    assert(ok, 'ok');
    let (rejected, _) = dispatcher.verify(tampered_attestation(), NO_MAX_AGE);
    assert(!rejected, 'reject');
    assert(dispatcher.get_total_nodes() == NODE_COUNT, 'total');
    let (_x, _y) = dispatcher.get_aggregate_key();

    let address = dispatcher.contract_address;
    let removed_index: u32 = 4;
    let removed_id = removal_target(removed_index);

    start_cheat_caller_address(address, ADMIN());
    dispatcher.remove_node(removed_id, removed_index);
    stop_cheat_caller_address(address);
}
