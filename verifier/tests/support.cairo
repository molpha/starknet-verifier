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
    Attestation, AttestationPayload, IVerifierDispatcher, IVerifierDispatcherTrait, SchnorrProof,
    SchnorrSignature,
};
use verifier::node_group_bitmap;
use verifier::schnorr;
use verifier::secp256k1_utils as ec;
use super::fixtures::{
    COMMITMENT, REDUNDANCY_BUFFER, REG_VERSION, SIGNATURE, SIGNERS_BITMAP, SIGS_REQUIRED,
    SOURCE_ID, TIMESTAMP, VALUE, compressed, fixture_nodes,
};

/// `verify`'s freshness check is opt-in; tests that are not about staleness
/// pass this to skip it, exactly as a consumer with no freshness policy would.
pub const NO_MAX_AGE: u64 = 0;

pub fn ADMIN() -> ContractAddress {
    0x00ad3119.try_into().unwrap()
}

pub fn deploy_with_params(
    initial_protocol_admin: ContractAddress, initial_redundancy_buffer: u32,
) -> IVerifierDispatcher {
    let contract = declare("Verifier").unwrap().contract_class();
    let mut calldata: Array<felt252> = array![];
    initial_protocol_admin.serialize(ref calldata);
    initial_redundancy_buffer.serialize(ref calldata);
    let (address, _) = contract.deploy(@calldata).unwrap();
    IVerifierDispatcher { contract_address: address }
}

pub fn deploy() -> IVerifierDispatcher {
    deploy_with_params(ADMIN(), REDUNDANCY_BUFFER)
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

/// PoP digest: keccak256("MOLPHA_VERIFIER_V1" ‖ contractAddress(32) ‖ compressed).
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

/// Deterministic bench-only node beyond the EVM fixture's key set.
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
///
/// Each registration bumps the registry version, so after this the current
/// version equals `count` — which is why the fixtures' `REG_VERSION` matches
/// their node count.
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

/// Registration calldata and identity for one fixture node by 0-based index.
pub fn fixture_node_registration(
    dispatcher: IVerifierDispatcher, index: u32,
) -> (ByteArray, SchnorrProof, felt252) {
    let nodes = fixture_nodes();
    let (prefix, x, sk) = *nodes.at(index);
    let comp = compressed(prefix, x);
    let (px, py) = ec::decompress(@comp);
    let pop = sign(px, py, sk, pop_digest(dispatcher.contract_address, @comp));
    let node = ec::point_eth_address(px, py);
    (comp, pop, node)
}

/// selectionSeed = keccak256("MOLPHA_SELECTION_V1" ‖ sourceId ‖ registryVersion ‖ timestamp)
pub fn selection_seed(source_id: u256, registry_version: u32, canonical_timestamp: u64) -> u256 {
    let mut buf: ByteArray = "";
    append_u256_be(ref buf, SELECTION_SEED_PREFIX());
    append_u256_be(ref buf, source_id);
    append_u32_be(ref buf, registry_version);
    append_u64_be(ref buf, canonical_timestamp);
    keccak_bytes(@buf)
}

/// Fixed registry size for signer-scaling benchmarks (fair cross-comparison).
pub const BENCH_NODE_COUNT: u32 = 18;

/// Bench parameters: `(node_count, signatures_required)` for `signer_count` signers.
pub fn bench_verify_config(signer_count: u32) -> (u32, u8) {
    let node_count = BENCH_NODE_COUNT;
    let required: u32 = if signer_count > REDUNDANCY_BUFFER + 3 {
        signer_count - REDUNDANCY_BUFFER
    } else {
        3
    };
    assert(node_count >= signer_count, 'nodes lt signers');
    (node_count, required.try_into().unwrap())
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
pub fn bench_verify_attestation(signer_count: u32) -> Attestation {
    let (node_count, signatures_required) = bench_verify_config(signer_count);
    let required32: u32 = signatures_required.into();
    let group_size = if required32 + REDUNDANCY_BUFFER > node_count {
        node_count
    } else {
        required32 + REDUNDANCY_BUFFER
    };
    let seed = selection_seed(SOURCE_ID(), node_count, TIMESTAMP);
    let selection = node_group_bitmap::derive(seed, node_count, group_size).unwrap();
    let signers_bitmap = signers_bitmap_first_k(selection, signer_count);
    Attestation {
        payload: AttestationPayload {
            value: VALUE(),
            source_id: SOURCE_ID(),
            registry_version: node_count,
            signatures_required,
            canonical_timestamp: TIMESTAMP,
        },
        // Non-zero placeholder; the Schnorr check still runs at full cost.
        signature: SchnorrSignature { signature: 1, commitment: 0x1, signers_bitmap },
    }
}

/// Calls `verify` once on an already-registered dispatcher.
pub fn call_verify_bench(dispatcher: IVerifierDispatcher, signer_count: u32) {
    let attestation = bench_verify_attestation(signer_count);
    let (_ok, _code) = dispatcher.verify(attestation, NO_MAX_AGE);
}

/// Deploys, registers nodes, and calls `verify` once for a `signer_count` benchmark.
pub fn run_verify_bench(signer_count: u32) {
    let (node_count, _) = bench_verify_config(signer_count);
    let dispatcher = deploy();
    register_nodes(dispatcher, node_count);
    call_verify_bench(dispatcher, signer_count);
}

pub fn fixture_payload() -> AttestationPayload {
    AttestationPayload {
        value: VALUE(),
        source_id: SOURCE_ID(),
        registry_version: REG_VERSION,
        signatures_required: SIGS_REQUIRED,
        canonical_timestamp: TIMESTAMP,
    }
}

pub fn fixture_signature() -> SchnorrSignature {
    SchnorrSignature {
        signature: SIGNATURE(), commitment: COMMITMENT, signers_bitmap: SIGNERS_BITMAP,
    }
}

pub fn fixture_attestation() -> Attestation {
    Attestation { payload: fixture_payload(), signature: fixture_signature() }
}

/// The fixture round with one bit of the signed value flipped.
pub fn tampered_attestation() -> Attestation {
    let mut payload = fixture_payload();
    payload.value = VALUE() + 1;
    Attestation { payload, signature: fixture_signature() }
}

/// Registers one arbitrary key through the real admin path, producing its PoP.
///
/// Used by tests that need a key set the EVM fixture does not contain — most
/// notably a key and its own negation, the pair that drives the plain sum to
/// the point at infinity.
pub fn add_key(dispatcher: IVerifierDispatcher, comp: ByteArray, sk: u256) {
    let address = dispatcher.contract_address;
    let (px, py) = ec::decompress(@comp);
    let pop = sign(px, py, sk, pop_digest(address, @comp));
    start_cheat_caller_address(address, ADMIN());
    dispatcher.add_node(comp, pop);
    stop_cheat_caller_address(address);
}

/// The negation of fixture node `index`: same x, flipped y-parity, secret key
/// `q - sk`. Registers as a distinct node, since `-P` has a different Ethereum
/// address than `P`.
pub fn negated_fixture_node(index: u32) -> (ByteArray, u256) {
    let nodes = fixture_nodes();
    let (prefix, x, sk) = *nodes.at(index);
    let flipped: u8 = if prefix == 2 {
        3
    } else {
        2
    };
    (compressed(flipped, x), CURVE_ORDER_Q() - sk)
}
