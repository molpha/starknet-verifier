//! End-to-end contract tests.
//!
//! Deploys the `Verifier` contract, registers the EVM fixture's nodes through
//! the real `add_node` path (each gated by a freshly-produced Schnorr proof-of-
//! possession), then drives the public `verify` entrypoint. This exercises
//! storage, registry versioning, node selection, plain-sum aggregation and
//! Schnorr verification together.
//!
//! `verify` is a total function, so failures are asserted on the returned
//! `(success, code)` pair rather than with `#[should_panic]`. A panicking
//! `verify` would be a bug regardless of the input — see `verify_codes`.

use snforge_std::{
    start_cheat_block_timestamp, start_cheat_caller_address, stop_cheat_block_timestamp,
    stop_cheat_caller_address,
};
use starknet::ContractAddress;
use verifier::constants::{CURVE_ORDER_Q, NODE_ACTIVE, NODE_NEVER, NODE_RETIRED, PREVIOUS_GRACE};
use verifier::interface::{
    Attestation, IVerifierDispatcher, IVerifierDispatcherTrait, SchnorrProof, SchnorrSignature,
};
use verifier::secp256k1_utils as ec;
use verifier::verify_codes;
use super::fixtures::{
    CASE1_COMMITMENT, CASE1_EXPECTED_CODE, CASE1_EXPECTED_OK, CASE1_REG_VERSION,
    CASE1_SIGNATURE, CASE1_SIGNERS_BITMAP, CASE1_SIGS_REQUIRED, CASE1_SOURCE_ID, CASE1_TIMESTAMP,
    CASE1_VALUE, CASE2_COMMITMENT, CASE2_EXPECTED_CODE, CASE2_EXPECTED_OK, CASE2_REG_VERSION,
    CASE2_SIGNATURE, CASE2_SIGNERS_BITMAP, CASE2_SIGS_REQUIRED, CASE2_SOURCE_ID, CASE2_TIMESTAMP,
    CASE2_VALUE, NODE_COUNT, REDUNDANCY_BUFFER, TIMESTAMP, compressed, fixture_nodes,
};
use super::support::{
    ADMIN, NO_MAX_AGE, add_key, deploy, deploy_with_params, fixture_attestation,
    fixture_node_registration, fixture_payload, fixture_signature, negated_fixture_node,
    register_fixture_nodes, tampered_attestation,
};
use verifier::interface::AttestationPayload;

/// Deploys and registers the full fixture node set, leaving the block clock at
/// zero so every registry version activates at time zero.
fn deployed_with_fixture_nodes() -> IVerifierDispatcher {
    let dispatcher = deploy();
    register_fixture_nodes(dispatcher, NODE_COUNT);
    dispatcher
}

fn attestation_with_signature(sig: SchnorrSignature) -> Attestation {
    Attestation { payload: fixture_payload(), signature: sig }
}

fn attestation_with_payload(payload: AttestationPayload) -> Attestation {
    Attestation { payload, signature: fixture_signature() }
}

// ---------------------------------------------------------------------------
// Happy path — cross-VM golden vectors
// ---------------------------------------------------------------------------

#[test]
fn register_nodes_and_verify_evm_fixture() {
    let dispatcher = deployed_with_fixture_nodes();

    assert(dispatcher.get_registry_version() == NODE_COUNT, 'registry version');
    assert(dispatcher.get_total_nodes() == NODE_COUNT, 'total nodes');
    assert(dispatcher.get_redundancy_buffer() == REDUNDANCY_BUFFER, 'redundancy buffer');

    let (ok, code) = dispatcher.verify(fixture_attestation(), NO_MAX_AGE);
    assert(ok, 'fixture must verify');
    assert(code == verify_codes::R_OK, 'fixture code must be R_OK');
}

#[test]
fn verifies_evm_attestation_case_1() {
    let dispatcher = deployed_with_fixture_nodes();
    let attestation = Attestation {
        payload: AttestationPayload {
            value: CASE1_VALUE(),
            source_id: CASE1_SOURCE_ID(),
            registry_version: CASE1_REG_VERSION,
            signatures_required: CASE1_SIGS_REQUIRED,
            canonical_timestamp: CASE1_TIMESTAMP,
        },
        signature: SchnorrSignature {
            signature: CASE1_SIGNATURE(),
            commitment: CASE1_COMMITMENT,
            signers_bitmap: CASE1_SIGNERS_BITMAP,
        },
    };

    let (ok, code) = dispatcher.verify(attestation, NO_MAX_AGE);
    assert(ok == CASE1_EXPECTED_OK, 'case 1 success mismatch');
    assert(code == CASE1_EXPECTED_CODE, 'case 1 code mismatch');
}

#[test]
fn verifies_evm_attestation_case_2() {
    let dispatcher = deployed_with_fixture_nodes();
    let attestation = Attestation {
        payload: AttestationPayload {
            value: CASE2_VALUE(),
            source_id: CASE2_SOURCE_ID(),
            registry_version: CASE2_REG_VERSION,
            signatures_required: CASE2_SIGS_REQUIRED,
            canonical_timestamp: CASE2_TIMESTAMP,
        },
        signature: SchnorrSignature {
            signature: CASE2_SIGNATURE(),
            commitment: CASE2_COMMITMENT,
            signers_bitmap: CASE2_SIGNERS_BITMAP,
        },
    };

    let (ok, code) = dispatcher.verify(attestation, NO_MAX_AGE);
    assert(ok == CASE2_EXPECTED_OK, 'case 2 success mismatch');
    assert(code == CASE2_EXPECTED_CODE, 'case 2 code mismatch');
}

// ---------------------------------------------------------------------------
// Reason codes
// ---------------------------------------------------------------------------

#[test]
fn verify_rejects_tampered_value_with_bad_signature() {
    let dispatcher = deployed_with_fixture_nodes();
    let (ok, code) = dispatcher.verify(tampered_attestation(), NO_MAX_AGE);
    assert(!ok, 'tampered must fail');
    assert(code == verify_codes::R_BAD_SIGNATURE, 'want R_BAD_SIGNATURE');
}

#[test]
fn verify_rejects_zero_signatures_required() {
    let dispatcher = deployed_with_fixture_nodes();
    let mut payload = fixture_payload();
    payload.signatures_required = 0;

    let (ok, code) = dispatcher.verify(attestation_with_payload(payload), NO_MAX_AGE);
    assert(!ok, 'zero sigs required must fail');
    assert(code == verify_codes::R_MALFORMED, 'want R_MALFORMED');
}

#[test]
fn verify_rejects_nonexistent_registry_version() {
    let dispatcher = deployed_with_fixture_nodes();
    let mut payload = fixture_payload();
    payload.registry_version = payload.registry_version + 1;

    let (ok, code) = dispatcher.verify(attestation_with_payload(payload), NO_MAX_AGE);
    assert(!ok, 'unknown version must fail');
    assert(code == verify_codes::R_BAD_REGISTRY_VERSION, 'want R_BAD_REGISTRY_VERSION');
}

#[test]
fn verify_rejects_signer_outside_selection_bitmap() {
    let dispatcher = deployed_with_fixture_nodes();
    let mut sig = fixture_signature();
    // Bit 0 is not in the round's derived selection group.
    sig.signers_bitmap = sig.signers_bitmap | 1;

    let (ok, code) = dispatcher.verify(attestation_with_signature(sig), NO_MAX_AGE);
    assert(!ok, 'unselected signer must fail');
    assert(code == verify_codes::R_BAD_QUORUM, 'want R_BAD_QUORUM');
}

#[test]
fn verify_rejects_bitmap_bit_above_node_count() {
    let dispatcher = deployed_with_fixture_nodes();
    let mut sig = fixture_signature();
    // Bit 12 with 12 nodes: the selection bitmap only ever sets bits below
    // node_count, so the subset test catches out-of-range bits for free.
    sig.signers_bitmap = sig.signers_bitmap | 4096;

    let (ok, code) = dispatcher.verify(attestation_with_signature(sig), NO_MAX_AGE);
    assert(!ok, 'out-of-range bit must fail');
    assert(code == verify_codes::R_BAD_QUORUM, 'want R_BAD_QUORUM');
}

#[test]
fn verify_rejects_insufficient_signers() {
    let dispatcher = deployed_with_fixture_nodes();
    let mut sig = fixture_signature();
    sig.signers_bitmap = 2;

    let (ok, code) = dispatcher.verify(attestation_with_signature(sig), NO_MAX_AGE);
    assert(!ok, 'too few signers must fail');
    assert(code == verify_codes::R_MALFORMED, 'want R_MALFORMED');
}

#[test]
fn verify_rejects_aggregate_at_infinity() {
    // A key and its own negation are both registrable — they have different
    // Ethereum addresses — and their plain sum is the point at infinity. This
    // is the one case `R_BAD_AGGREGATE` exists for.
    let dispatcher = deploy();
    let nodes = fixture_nodes();
    let (prefix, x, sk) = *nodes.at(0);
    add_key(dispatcher, compressed(prefix, x), sk);
    let (neg_comp, neg_sk) = negated_fixture_node(0);
    add_key(dispatcher, neg_comp, neg_sk);

    assert(dispatcher.get_total_nodes() == 2, 'both keys registered');

    // group_size = min(1 + 2, 2) = 2 = node_count, so both are selected.
    let attestation = Attestation {
        payload: AttestationPayload {
            value: 1,
            source_id: 2,
            registry_version: 2,
            signatures_required: 1,
            canonical_timestamp: TIMESTAMP,
        },
        signature: SchnorrSignature {
            signature: 1, commitment: 0x1, signers_bitmap: 3,
        },
    };

    let (ok, code) = dispatcher.verify(attestation, NO_MAX_AGE);
    assert(!ok, 'infinity aggregate must fail');
    assert(code == verify_codes::R_BAD_AGGREGATE, 'want R_BAD_AGGREGATE');
}

// ---------------------------------------------------------------------------
// Totality — adversarial calldata must return a code, never panic
// ---------------------------------------------------------------------------

#[test]
fn verify_rejects_oversized_commitment_without_panicking() {
    // A felt252 is wider than an Ethereum address; hashing an oversized
    // commitment would panic inside `append_address_be` without the guard.
    let dispatcher = deployed_with_fixture_nodes();
    let mut sig = fixture_signature();
    sig.commitment = 0x1_0000000000000000_0000000000000000_0000000000000000;

    let (ok, code) = dispatcher.verify(attestation_with_signature(sig), NO_MAX_AGE);
    assert(!ok, 'oversized commitment must fail');
    assert(code == verify_codes::R_MALFORMED, 'want R_MALFORMED');
}

#[test]
fn verify_rejects_out_of_range_scalar() {
    let dispatcher = deployed_with_fixture_nodes();
    let mut sig = fixture_signature();
    sig.signature = CURVE_ORDER_Q();

    let (ok, code) = dispatcher.verify(attestation_with_signature(sig), NO_MAX_AGE);
    assert(!ok, 's >= Q must fail');
    assert(code == verify_codes::R_MALFORMED, 'want R_MALFORMED');
}

#[test]
fn verify_rejects_zero_commitment_and_zero_bitmap() {
    let dispatcher = deployed_with_fixture_nodes();

    let mut zero_commitment = fixture_signature();
    zero_commitment.commitment = 0;
    let (ok1, code1) = dispatcher.verify(attestation_with_signature(zero_commitment), NO_MAX_AGE);
    assert(!ok1 && code1 == verify_codes::R_MALFORMED, 'zero commitment');

    let mut zero_bitmap = fixture_signature();
    zero_bitmap.signers_bitmap = 0;
    let (ok2, code2) = dispatcher.verify(attestation_with_signature(zero_bitmap), NO_MAX_AGE);
    assert(!ok2 && code2 == verify_codes::R_MALFORMED, 'zero bitmap');

    let mut zero_sig = fixture_signature();
    zero_sig.signature = 0;
    let (ok3, code3) = dispatcher.verify(attestation_with_signature(zero_sig), NO_MAX_AGE);
    assert(!ok3 && code3 == verify_codes::R_MALFORMED, 'zero signature');
}

#[test]
fn verify_on_empty_registry_reports_bad_quorum() {
    // Genesis exists but holds no keys — the reachable `derive` failure.
    let dispatcher = deploy();
    let mut payload = fixture_payload();
    payload.registry_version = 0;

    let (ok, code) = dispatcher.verify(attestation_with_payload(payload), NO_MAX_AGE);
    assert(!ok, 'empty registry must fail');
    assert(code == verify_codes::R_BAD_QUORUM, 'want R_BAD_QUORUM');
}

// ---------------------------------------------------------------------------
// Freshness
// ---------------------------------------------------------------------------

#[test]
fn max_age_zero_disables_the_freshness_check() {
    let dispatcher = deployed_with_fixture_nodes();
    let address = dispatcher.contract_address;

    // Far in the future relative to the fixture's canonical timestamp.
    start_cheat_block_timestamp(address, TIMESTAMP + 1_000_000);
    let (ok, code) = dispatcher.verify(fixture_attestation(), NO_MAX_AGE);
    stop_cheat_block_timestamp(address);

    assert(ok && code == verify_codes::R_OK, 'max_age 0 must not age out');
}

#[test]
fn stale_payload_is_reported_as_stale() {
    let dispatcher = deployed_with_fixture_nodes();
    let address = dispatcher.contract_address;

    start_cheat_block_timestamp(address, TIMESTAMP + 100);
    let (fresh_ok, fresh_code) = dispatcher.verify(fixture_attestation(), 200);
    let (stale_ok, stale_code) = dispatcher.verify(fixture_attestation(), 50);
    stop_cheat_block_timestamp(address);

    assert(fresh_ok && fresh_code == verify_codes::R_OK, 'inside window must pass');
    assert(!stale_ok, 'outside window must fail');
    assert(stale_code == verify_codes::R_STALE, 'want R_STALE');
}

#[test]
fn future_dated_payload_is_malformed() {
    let dispatcher = deployed_with_fixture_nodes();
    let address = dispatcher.contract_address;

    start_cheat_block_timestamp(address, TIMESTAMP - 100);
    let (ok, code) = dispatcher.verify(fixture_attestation(), 3600);
    stop_cheat_block_timestamp(address);

    assert(!ok, 'future payload must fail');
    assert(code == verify_codes::R_MALFORMED, 'want R_MALFORMED');
}

// ---------------------------------------------------------------------------
// Registry versioning
// ---------------------------------------------------------------------------

#[test]
fn payload_before_version_activation_is_not_yet_active() {
    let dispatcher = deploy();
    let address = dispatcher.contract_address;

    // Every registration stamps `activates_at` from the block clock, so
    // registering "after" the fixture round makes that round predate the
    // version it claims.
    start_cheat_block_timestamp(address, TIMESTAMP + 1000);
    register_fixture_nodes(dispatcher, NODE_COUNT);

    let (ok, code) = dispatcher.verify(fixture_attestation(), NO_MAX_AGE);
    stop_cheat_block_timestamp(address);

    assert(!ok, 'pre-activation must fail');
    assert(code == verify_codes::R_NOT_YET_ACTIVE, 'want R_NOT_YET_ACTIVE');
}

#[test]
fn superseded_version_expires_after_the_grace_window() {
    let dispatcher = deployed_with_fixture_nodes();
    let address = dispatcher.contract_address;

    // Publish a successor that activated long before the payload's timestamp,
    // putting the fixture's version well past its grace window.
    start_cheat_block_timestamp(address, 1000);
    start_cheat_caller_address(address, ADMIN());
    dispatcher.set_redundancy_buffer(REDUNDANCY_BUFFER);
    stop_cheat_caller_address(address);
    stop_cheat_block_timestamp(address);

    let (ok, code) = dispatcher.verify(fixture_attestation(), NO_MAX_AGE);
    assert(!ok, 'expired version must fail');
    assert(code == verify_codes::R_VERSION_EXPIRED, 'want R_VERSION_EXPIRED');
}

#[test]
fn superseded_version_still_verifies_inside_the_grace_window() {
    let dispatcher = deployed_with_fixture_nodes();
    let address = dispatcher.contract_address;

    // Successor activates just inside `PREVIOUS_GRACE` of the payload.
    start_cheat_block_timestamp(address, TIMESTAMP - PREVIOUS_GRACE + 1);
    start_cheat_caller_address(address, ADMIN());
    dispatcher.set_redundancy_buffer(REDUNDANCY_BUFFER);
    stop_cheat_caller_address(address);
    stop_cheat_block_timestamp(address);

    let (ok, code) = dispatcher.verify(fixture_attestation(), NO_MAX_AGE);
    assert(ok, 'in-grace must still verify');
    assert(code == verify_codes::R_OK, 'want R_OK');
}

#[test]
fn changing_the_redundancy_buffer_does_not_invalidate_history() {
    // The regression this versioning exists for: the buffer feeds `group_size`,
    // which feeds the derived selection bitmap a signature is checked against.
    // Mutating it in place would retroactively break payloads that already
    // verify, so the setter publishes a new version instead.
    let dispatcher = deployed_with_fixture_nodes();
    let address = dispatcher.contract_address;

    let (before_ok, _) = dispatcher.verify(fixture_attestation(), NO_MAX_AGE);
    assert(before_ok, 'must verify before change');

    start_cheat_block_timestamp(address, TIMESTAMP - PREVIOUS_GRACE + 1);
    start_cheat_caller_address(address, ADMIN());
    dispatcher.set_redundancy_buffer(REDUNDANCY_BUFFER + 3);
    stop_cheat_caller_address(address);
    stop_cheat_block_timestamp(address);

    assert(dispatcher.get_redundancy_buffer() == REDUNDANCY_BUFFER + 3, 'buffer updated');
    assert(dispatcher.get_registry_version() == NODE_COUNT + 1, 'version bumped');

    let (after_ok, after_code) = dispatcher.verify(fixture_attestation(), NO_MAX_AGE);
    assert(after_ok, 'must still verify after change');
    assert(after_code == verify_codes::R_OK, 'want R_OK');
}

#[test]
fn historical_payload_still_verifies_after_signer_removal() {
    let dispatcher = deployed_with_fixture_nodes();
    let address = dispatcher.contract_address;
    let (before_ok, _) = dispatcher.verify(fixture_attestation(), NO_MAX_AGE);
    assert(before_ok, 'pre-remove verify');

    // Index 7's bit is set in the fixture's signer bitmap.
    let (_, _, signer_node) = fixture_node_registration(dispatcher, 7);
    start_cheat_block_timestamp(address, TIMESTAMP - PREVIOUS_GRACE + 1);
    start_cheat_caller_address(address, ADMIN());
    dispatcher.remove_node(signer_node, 7);
    stop_cheat_caller_address(address);
    stop_cheat_block_timestamp(address);

    assert(dispatcher.get_registry_version() == NODE_COUNT + 1, 'version after remove');
    assert(!dispatcher.is_node(signer_node), 'signer removed from current');

    let (after_ok, after_code) = dispatcher.verify(fixture_attestation(), NO_MAX_AGE);
    assert(after_ok, 'old version verifies');
    assert(after_code == verify_codes::R_OK, 'want R_OK');
}

// ---------------------------------------------------------------------------
// Registry administration
// ---------------------------------------------------------------------------

#[test]
fn remove_node_updates_set_and_aggregate() {
    let dispatcher = deployed_with_fixture_nodes();
    let address = dispatcher.contract_address;

    let removed_index: u32 = 4;
    let nodes = fixture_nodes();
    let (rprefix, rx, _) = *nodes.at(removed_index);
    let (rpx, rpy) = ec::decompress(@compressed(rprefix, rx));
    let removed_id = ec::point_eth_address(rpx, rpy);
    assert(dispatcher.is_node(removed_id), 'should be node first');
    assert(dispatcher.get_node_index(removed_id) == removed_index, 'index is 0-based');

    start_cheat_caller_address(address, ADMIN());
    dispatcher.remove_node(removed_id, removed_index);
    stop_cheat_caller_address(address);

    assert(dispatcher.get_registry_version() == NODE_COUNT + 1, 'version after remove');
    assert(dispatcher.get_total_nodes() == NODE_COUNT - 1, 'total after remove');
    assert(!dispatcher.is_node(removed_id), 'removed must be gone');
    assert(dispatcher.get_node_status(removed_id) == NODE_RETIRED, 'must be retired');

    // The running aggregate must equal the plain sum of the remaining keys.
    let mut acc_x: u256 = 0;
    let mut acc_y: u256 = 0;
    let mut have = false;
    let mut j: u32 = 0;
    while j < nodes.len() {
        if j != removed_index {
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
fn node_status_tracks_lifecycle() {
    let dispatcher = deploy();
    let (comp, pop, node) = fixture_node_registration(dispatcher, 0);
    let address = dispatcher.contract_address;

    assert(dispatcher.get_node_status(node) == NODE_NEVER, 'unknown starts NEVER');

    start_cheat_caller_address(address, ADMIN());
    dispatcher.add_node(comp, pop);
    assert(dispatcher.get_node_status(node) == NODE_ACTIVE, 'registered is ACTIVE');
    dispatcher.remove_node(node, 0);
    stop_cheat_caller_address(address);

    assert(dispatcher.get_node_status(node) == NODE_RETIRED, 'removed is RETIRED');
}

#[test]
#[should_panic]
fn retired_address_cannot_be_reused() {
    // Rejoining costs a keygen and a fresh PoP, which forces key rotation —
    // the hygienic outcome, and what makes each address's membership a single
    // contiguous version interval.
    let dispatcher = deploy();
    let (comp, pop, node) = fixture_node_registration(dispatcher, 0);
    let address = dispatcher.contract_address;

    start_cheat_caller_address(address, ADMIN());
    dispatcher.add_node(comp, pop);
    dispatcher.remove_node(node, 0);
    let (comp2, pop2, _) = fixture_node_registration(dispatcher, 0);
    dispatcher.add_node(comp2, pop2);
    stop_cheat_caller_address(address);
}

#[test]
#[should_panic]
fn remove_node_rejects_wrong_index_witness() {
    let dispatcher = deployed_with_fixture_nodes();
    let address = dispatcher.contract_address;
    let (_, _, node) = fixture_node_registration(dispatcher, 3);

    start_cheat_caller_address(address, ADMIN());
    // Node 3 does not sit at index 4.
    dispatcher.remove_node(node, 4);
    stop_cheat_caller_address(address);
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
    dispatcher.remove_node(node, 0);
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
fn non_admin_cannot_set_redundancy_buffer() {
    let dispatcher = deploy();
    dispatcher.set_redundancy_buffer(5);
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
    let _dispatcher = deploy_with_params(zero_admin, REDUNDANCY_BUFFER);
}
