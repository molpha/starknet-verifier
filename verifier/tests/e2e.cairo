//! End-to-end contract test.
//!
//! Deploys the `Verifier` contract, registers the 10 fixture nodes through the
//! real `add_node` path (each gated by a freshly-produced Schnorr proof-of-
//! possession), then verifies the unmodified EVM fixture payload through the
//! public `verify` entrypoint. This exercises storage, registry versioning,
//! node selection, plain-sum aggregation, and Schnorr verification together.

use core::integer::u512_safe_div_rem_by_u256;
use core::num::traits::WideMul;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address,
    stop_cheat_caller_address,
};
use starknet::ContractAddress;
use verifier::byte_utils::{append_u256_be, keccak_bytes};
use verifier::constants::{CURVE_ORDER_Q, POP_DOMAIN};
use verifier::interface::{
    DataUpdate, IVerifierDispatcher, IVerifierDispatcherTrait, SchnorrProof, SchnorrSignature,
};
use verifier::schnorr;
use verifier::secp256k1_utils as ec;
use super::fixtures::{
    COMMITMENT, JOB_ID, SIGNATURE, SIGNERS_BITMAP, TIMESTAMP, VALUE, compressed, fixture_nodes,
};

fn ADMIN() -> ContractAddress {
    0x00ad3119.try_into().unwrap()
}

fn deploy() -> IVerifierDispatcher {
    let contract = declare("Verifier").unwrap().contract_class();
    let mut calldata: Array<felt252> = array![];
    ADMIN().serialize(ref calldata);
    let buffer: u256 = 2;
    buffer.serialize(ref calldata);
    let (address, _) = contract.deploy(@calldata).unwrap();
    IVerifierDispatcher { contract_address: address }
}

/// (a * b) mod q using a 512-bit intermediate.
fn mulmod(a: u256, b: u256, q: u256) -> u256 {
    let wide = a.wide_mul(b);
    let (_, r) = u512_safe_div_rem_by_u256(wide, q.try_into().unwrap());
    r
}

/// (a + b) mod q for a, b < q (no overflow).
fn addmod(a: u256, b: u256, q: u256) -> u256 {
    let q_minus_b = q - b;
    if a < q_minus_b {
        a + b
    } else {
        a - q_minus_b
    }
}

/// PoP digest: keccak256("MOLPHA_VALIDATOR_V1" ‖ contractAddress(32) ‖ compressed).
fn pop_digest(contract: ContractAddress, comp: @ByteArray) -> u256 {
    let mut buf: ByteArray = "";
    append_u256_be(ref buf, POP_DOMAIN());
    let addr_felt: felt252 = contract.into();
    append_u256_be(ref buf, addr_felt.into());
    buf.append(comp);
    keccak_bytes(@buf)
}

/// Produces a Schnorr signature `(s, R)` for `(px, py)` / `sk` over `message`.
/// `s = k + e·sk (mod Q)`, with a deterministic per-attempt nonce search.
fn sign(px: u256, py: u256, sk: u256, message: u256) -> SchnorrProof {
    let q = CURVE_ORDER_Q();
    let parity: u8 = (py.low % 2).try_into().unwrap();
    let mut attempt: u256 = 0;
    let proof = loop {
        let mut buf: ByteArray = "";
        append_u256_be(ref buf, message);
        append_u256_be(ref buf, px);
        append_u256_be(ref buf, py);
        append_u256_be(ref buf, attempt);
        let k = (keccak_bytes(@buf) % (q - 1)) + 1;

        let r_point = ec::mul(ec::generator(), k);
        let commitment = ec::eth_address(r_point);
        if commitment != 0 {
            let e = schnorr::challenge(px, parity, message, commitment);
            let s = addmod(k, mulmod(e, sk, q), q);
            if s != 0 && s < q && schnorr::verify(px, py, message, s, commitment) {
                break SchnorrProof { signature: s, commitment };
            }
        }
        attempt += 1;
    };
    proof
}

#[test]
fn register_nodes_and_verify_evm_fixture() {
    let dispatcher = deploy();
    let address = dispatcher.contract_address;

    start_cheat_caller_address(address, ADMIN());
    let nodes = fixture_nodes();
    let mut i: u32 = 0;
    while i < nodes.len() {
        let (prefix, x, sk) = *nodes.at(i);
        let comp = compressed(prefix, x);
        let (px, py) = ec::decompress(@comp);
        let pop = sign(px, py, sk, pop_digest(address, @comp));
        dispatcher.add_node(comp, pop);
        i += 1;
    }
    stop_cheat_caller_address(address);

    assert(dispatcher.get_registry_version() == 10, 'registry version');
    assert(dispatcher.get_total_nodes() == 10, 'total nodes');

    let data_update = DataUpdate {
        job_id: JOB_ID(),
        registry_version: 10,
        signatures_required: 3,
        value: VALUE(),
        canonical_timestamp: TIMESTAMP,
    };
    let signature = SchnorrSignature {
        signature: SIGNATURE(), commitment: COMMITMENT, signers_bitmap: SIGNERS_BITMAP,
    };

    assert(dispatcher.verify(data_update, signature), 'fixture must verify');
}

#[test]
fn remove_node_updates_set_and_aggregate() {
    let dispatcher = deploy();
    let address = dispatcher.contract_address;
    let nodes = fixture_nodes();

    start_cheat_caller_address(address, ADMIN());
    let mut i: u32 = 0;
    while i < nodes.len() {
        let (prefix, x, sk) = *nodes.at(i);
        let comp = compressed(prefix, x);
        let (px, py) = ec::decompress(@comp);
        let pop = sign(px, py, sk, pop_digest(address, @comp));
        dispatcher.add_node(comp, pop);
        i += 1;
    }

    // Remove the node at 1-based index 5 (array slot 4).
    let removed_slot: u32 = 4;
    let (rprefix, rx, _) = *nodes.at(removed_slot);
    let (rpx, rpy) = ec::decompress(@compressed(rprefix, rx));
    let removed_id = ec::point_eth_address(rpx, rpy);
    assert(dispatcher.is_node(removed_id), 'should be node first');

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
    let address = dispatcher.contract_address;

    start_cheat_caller_address(address, ADMIN());
    let nodes = fixture_nodes();
    let mut i: u32 = 0;
    while i < nodes.len() {
        let (prefix, x, sk) = *nodes.at(i);
        let comp = compressed(prefix, x);
        let (px, py) = ec::decompress(@comp);
        let pop = sign(px, py, sk, pop_digest(address, @comp));
        dispatcher.add_node(comp, pop);
        i += 1;
    }
    stop_cheat_caller_address(address);

    let data_update = DataUpdate {
        job_id: JOB_ID(),
        registry_version: 10,
        signatures_required: 3,
        value: VALUE() + 1, // tampered
        canonical_timestamp: TIMESTAMP,
    };
    let signature = SchnorrSignature {
        signature: SIGNATURE(), commitment: COMMITMENT, signers_bitmap: SIGNERS_BITMAP,
    };

    assert(!dispatcher.verify(data_update, signature), 'tampered must fail');
}
