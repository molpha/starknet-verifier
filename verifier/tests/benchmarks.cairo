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
//! Baseline (snforge 0.61, fixture: 10 nodes, redundancy_buffer=2,
//! signatures_required=3, 5 signers in bitmap 0x38a):
//!   verify (success)     ~24,711,400 L2 gas
//!   verify (tampered)    ~24,711,500 L2 gas
//!   add_node (first)     ~22,751,716 L2 gas
//!   add_node (10th)      ~25,626,976 L2 gas
//!   remove_node          ~5,068,667 L2 gas
//!   get_total_nodes      ~48,770 L2 gas
//!   get_aggregate_key    ~115,980 L2 gas
//!
//! `bench_gas_snapshot` runs every selector in one test so `snforge test
//! bench_gas_snapshot --gas-report` prints a single consolidated table.
//!
//! Signer-scaling benchmarks (`bench_verify_N_signers`) use deterministic
//! payloads that pass all structural/selection checks; signature bytes are
//! placeholders so the full aggregation + Schnorr path is measured.
//!
//! Setup: 18-node registry, redundancy_buffer=2, EVM fixture feed_id/timestamp.
//! `signatures_required` = 3 for ≤5 signers, else `signer_count - 2`.
//! `group_size` = min(signatures_required + 2, 18) — matches the contract.
//!
//! Measured L2 gas (`verify` only, snforge 0.61):
//!   | Signers | L2 gas    | group_size |
//!   |---------|-----------|------------|
//!   | 3       | 24,469,138| 5          |
//!   | 5       | 24,871,970| 5          |
//!   | 9       | 27,487,149| 9          |
//!   | 12      | 26,560,466| 12         |
//!   | 18      | 25,540,671| 18         |
//!
//! Cost is not strictly linear in signer count: `node_group_bitmap::derive`
//! uses different algorithms when `group_size ≤ n/2`, `> n/2`, or `= n`.
//! Aggregation + Schnorr still dominate; selection path shifts the total.
//!
//! Run:
//!   snforge test bench_verify_signer_scaling --gas-report

use verifier::interface::IVerifierDispatcherTrait;
use verifier::secp256k1_utils as ec;
use super::fixtures::{compressed, fixture_nodes};
use super::support::{
    ADMIN, BENCH_NODE_COUNT, call_verify_bench, deploy, fixture_data_update, fixture_signature,
    register_fixture_nodes, register_nodes, run_verify_bench, tampered_data_update,
};
use snforge_std::{start_cheat_caller_address, stop_cheat_caller_address};

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
fn bench_verify_success_10_nodes() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);
    assert(dispatcher.verify(fixture_data_update(), fixture_signature()), 'must verify');
}

#[test]
fn bench_verify_reject_tampered_10_nodes() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);
    assert(
        !dispatcher.verify(tampered_data_update(), fixture_signature()), 'must reject',
    );
}

#[test]
fn bench_add_node_first() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 1);
    assert(dispatcher.get_total_nodes() == 1, 'one node');
}

#[test]
fn bench_add_node_tenth() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);
    assert(dispatcher.get_registry_version() == 10, 'version');
}

#[test]
fn bench_remove_node() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);

    let address = dispatcher.contract_address;
    let nodes = fixture_nodes();
    let removed_slot: u32 = 4;
    let (rprefix, rx, _) = *nodes.at(removed_slot);
    let (rpx, rpy) = ec::decompress(@compressed(rprefix, rx));
    let removed_id = ec::point_eth_address(rpx, rpy);

    start_cheat_caller_address(address, ADMIN());
    dispatcher.remove_node(removed_id);
    stop_cheat_caller_address(address);

    assert(dispatcher.get_total_nodes() == 9, 'nine nodes');
}

#[test]
fn bench_view_get_total_nodes() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);
    assert(dispatcher.get_total_nodes() == 10, 'total nodes');
}

#[test]
fn bench_view_get_aggregate_key() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);
    let (_x, _y) = dispatcher.get_aggregate_key();
}

/// One-shot snapshot: all selectors in a single test for a consolidated gas report.
#[test]
fn bench_gas_snapshot() {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, 10);

    assert(dispatcher.verify(fixture_data_update(), fixture_signature()), 'ok');
    assert(
        !dispatcher.verify(tampered_data_update(), fixture_signature()), 'reject',
    );
    assert(dispatcher.get_total_nodes() == 10, 'total');
    let (_x, _y) = dispatcher.get_aggregate_key();

    let address = dispatcher.contract_address;
    let nodes = fixture_nodes();
    let (rprefix, rx, _) = *nodes.at(4);
    let (rpx, rpy) = ec::decompress(@compressed(rprefix, rx));
    let removed_id = ec::point_eth_address(rpx, rpy);

    start_cheat_caller_address(address, ADMIN());
    dispatcher.remove_node(removed_id);
    stop_cheat_caller_address(address);
}
