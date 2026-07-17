//! Shared helpers for contract integration and benchmark tests.

use core::integer::u512_safe_div_rem_by_u256;
use core::num::traits::WideMul;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address,
    stop_cheat_caller_address,
};
use starknet::ContractAddress;
use verifier::bitmap;
use verifier::byte_utils::{append_u256_be, append_u32_be, append_u64_be, keccak_bytes};
use verifier::constants::{CURVE_ORDER_Q, POP_DOMAIN, SELECTION_SEED_PREFIX};
use verifier::interface::{
    DataUpdate, IVerifierDispatcher, IVerifierDispatcherTrait, SchnorrProof, SchnorrSignature,
};
use verifier::node_group_bitmap;
use verifier::schnorr;
use verifier::secp256k1_utils as ec;
use super::fixtures::{
    COMMITMENT, JOB_ID, REG_VERSION, SIGNATURE, SIGNERS_BITMAP, SIGS_REQUIRED, TIMESTAMP, VALUE,
    compressed, fixture_nodes,
};

const REDUNDANCY_BUFFER: u32 = 2;

pub fn ADMIN() -> ContractAddress {
    0x00ad3119.try_into().unwrap()
}

pub fn deploy() -> IVerifierDispatcher {
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
pub fn pop_digest(contract: ContractAddress, comp: @ByteArray) -> u256 {
    let mut buf: ByteArray = "";
    append_u256_be(ref buf, POP_DOMAIN());
    let addr_felt: felt252 = contract.into();
    append_u256_be(ref buf, addr_felt.into());
    buf.append(comp);
    keccak_bytes(@buf)
}

/// Produces a Schnorr signature `(s, R)` for `(px, py)` / `sk` over `message`.
pub fn sign(px: u256, py: u256, sk: u256, message: u256) -> SchnorrProof {
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

/// Deterministic bench-only node beyond the 10-node EVM fixture.
pub fn synthetic_node(index: u32) -> (ByteArray, u256) {
    let mut buf: ByteArray = "MOLPHA_BENCH_NODE";
    append_u32_be(ref buf, index);
    let q = CURVE_ORDER_Q();
    let sk = (keccak_bytes(@buf) % (q - 1)) + 1;
    let pt = ec::mul(ec::generator(), sk);
    let (px, py) = ec::coords(pt);
    let prefix: u8 = if py.low % 2 == 0 {
        2
    } else {
        3
    };
    (compressed(prefix, px), sk)
}

/// Registers `count` nodes: EVM fixture keys first, then deterministic synthetics.
pub fn register_nodes(dispatcher: IVerifierDispatcher, count: u32) {
    let address = dispatcher.contract_address;
    start_cheat_caller_address(address, ADMIN());
    let nodes = fixture_nodes();
    let mut i: u32 = 0;
    while i < count {
        let (comp, sk) = if i < nodes.len() {
            let (prefix, x, sk) = *nodes.at(i);
            (compressed(prefix, x), sk)
        } else {
            synthetic_node(i)
        };
        let (px, py) = ec::decompress(@comp);
        let pop = sign(px, py, sk, pop_digest(address, @comp));
        dispatcher.add_node(comp, pop);
        i += 1;
    }
    stop_cheat_caller_address(address);
}

/// Registers the first `count` fixture nodes through the real `add_node` path.
pub fn register_fixture_nodes(dispatcher: IVerifierDispatcher, count: u32) {
    register_nodes(dispatcher, count);
}

/// selectionSeed = keccak256("MOLPHA_SELECTION_V1" ‖ feedId ‖ registryVersion ‖ timestamp)
pub fn selection_seed(feed_id: u256, registry_version: u32, canonical_timestamp: u64) -> u256 {
    let mut buf: ByteArray = "";
    append_u256_be(ref buf, SELECTION_SEED_PREFIX());
    append_u256_be(ref buf, feed_id);
    append_u32_be(ref buf, registry_version);
    append_u64_be(ref buf, canonical_timestamp);
    keccak_bytes(@buf)
}

/// Fixed registry size for signer-scaling benchmarks (fair cross-comparison).
pub const BENCH_NODE_COUNT: u32 = 18;

/// Bench parameters: `(node_count, signatures_required)` for `signer_count` signers.
pub fn bench_verify_config(signer_count: u32) -> (u32, u32) {
    let node_count = BENCH_NODE_COUNT;
    let signatures_required = if signer_count > REDUNDANCY_BUFFER + 3 {
        signer_count - REDUNDANCY_BUFFER
    } else {
        3
    };
    assert(node_count >= signer_count, 'nodes lt signers');
    (node_count, signatures_required)
}

/// First `k` ascending signer indices from the derived selection bitmap.
pub fn signers_bitmap_first_k(selection_bitmap: u256, k: u32) -> u256 {
    let mut result: u256 = 0;
    let mut taken: u32 = 0;
    let mut pos: u32 = 0;
    let mut bm = selection_bitmap;
    while taken < k {
        assert(bm != 0, 'selection too small');
        if bm.low % 2 == 1 {
            result = result | bitmap::two_pow(pos);
            taken += 1;
        }
        bm = bm / 2;
        pos += 1;
    }
    result
}

/// Builds a `verify` payload that passes structural/selection checks for `signer_count`.
///
/// `group_size` matches the contract: `min(signatures_required + redundancy_buffer, node_count)`.
pub fn bench_verify_payload(signer_count: u32) -> (DataUpdate, SchnorrSignature) {
    let (node_count, signatures_required) = bench_verify_config(signer_count);
    let group_size = if signatures_required + REDUNDANCY_BUFFER > node_count {
        node_count
    } else {
        signatures_required + REDUNDANCY_BUFFER
    };
    let seed = selection_seed(JOB_ID(), node_count, TIMESTAMP);
    let selection = node_group_bitmap::derive(seed, node_count, group_size);
    let signers_bitmap = signers_bitmap_first_k(selection, signer_count);
    let data_update = DataUpdate {
        feed_id: JOB_ID(),
        registry_version: node_count,
        signatures_required,
        value: VALUE(),
        canonical_timestamp: TIMESTAMP,
    };
    // Non-zero placeholder; Schnorr check still runs at full cost.
    let schnorr_data = SchnorrSignature {
        signature: 1, commitment: 0x1, signers_bitmap,
    };
    (data_update, schnorr_data)
}

/// Calls `verify` once on an already-registered dispatcher.
pub fn call_verify_bench(dispatcher: IVerifierDispatcher, signer_count: u32) {
    let (data_update, schnorr_data) = bench_verify_payload(signer_count);
    let _valid = dispatcher.verify(data_update, schnorr_data);
}

/// Deploys, registers nodes, and calls `verify` once for a `signer_count` benchmark.
pub fn run_verify_bench(signer_count: u32) {
    let (node_count, _) = bench_verify_config(signer_count);
    let dispatcher = deploy();
    register_nodes(dispatcher, node_count);
    call_verify_bench(dispatcher, signer_count);
}

pub fn fixture_data_update() -> DataUpdate {
    DataUpdate {
        feed_id: JOB_ID(),
        registry_version: REG_VERSION,
        signatures_required: SIGS_REQUIRED,
        value: VALUE(),
        canonical_timestamp: TIMESTAMP,
    }
}

pub fn fixture_signature() -> SchnorrSignature {
    SchnorrSignature {
        signature: SIGNATURE(), commitment: COMMITMENT, signers_bitmap: SIGNERS_BITMAP,
    }
}

pub fn tampered_data_update() -> DataUpdate {
    DataUpdate {
        feed_id: JOB_ID(),
        registry_version: REG_VERSION,
        signatures_required: SIGS_REQUIRED,
        value: VALUE() + 1,
        canonical_timestamp: TIMESTAMP,
    }
}
