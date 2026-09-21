//! Cross-chain parity tests at the library level.
//!
//! These prove the Cairo port reconstructs exactly the bytes the Solidity and
//! Rust verifiers do: the same `(message, aggregateKey, signature, commitment)`
//! verifies on every chain, and the keccak encodings and node selection match
//! bit-for-bit. The expected values are generated from the EVM golden vectors
//! by `scripts/gen_fixtures.mjs`, so a divergence shows up here rather than as
//! a silently failing round in production.

use verifier::byte_utils::{
    append_u256_be, append_u32_be, append_u64_be, append_u8_be, keccak_bytes,
};
use verifier::constants::{MESSAGE_PREFIX, SELECTION_SEED_PREFIX};
use verifier::secp256k1_utils as ec;
use verifier::{node_group_bitmap, schnorr};
use super::fixtures::{
    AGG_X, AGG_Y, COMMITMENT, MESSAGE, NODE_COUNT, REDUNDANCY_BUFFER, REG_VERSION, SELECTION_SEED,
    SIGNATURE, SIGNERS_BITMAP, SIGS_REQUIRED, SOURCE_ID, TIMESTAMP, VALUE, compressed,
    fixture_nodes,
};

#[test]
fn keccak_is_evm_compatible() {
    // keccak256("") — pins the big-endian convention of keccak_bytes. StarkNet's
    // keccak builtin is little-endian, so this is the one test everything else
    // in this file is downstream of.
    let empty: ByteArray = "";
    let h = keccak_bytes(@empty);
    assert(
        h == u256 {
            high: 0xc5d2460186f7233c927e7db2dcc703c0, low: 0xe500b653ca82273b7bfad8045d85a470,
        },
        'keccak empty mismatch',
    );
}

#[test]
fn selection_seed_encoding_matches_evm() {
    // keccak256("MOLPHA_SELECTION_V1" ‖ sourceId ‖ u32 registryVersion
    //           ‖ u64 canonicalTimestamp) — 76 bytes.
    let mut buf: ByteArray = "";
    append_u256_be(ref buf, SELECTION_SEED_PREFIX());
    append_u256_be(ref buf, SOURCE_ID());
    append_u32_be(ref buf, REG_VERSION);
    append_u64_be(ref buf, TIMESTAMP);
    assert(keccak_bytes(@buf) == SELECTION_SEED(), 'selection seed mismatch');
}

/// The canonical 141-byte preimage, rebuilt here independently of the contract.
fn evm_message_preimage() -> ByteArray {
    let mut buf: ByteArray = "";
    append_u256_be(ref buf, MESSAGE_PREFIX());
    append_u256_be(ref buf, VALUE());
    append_u256_be(ref buf, SOURCE_ID());
    append_u32_be(ref buf, REG_VERSION);
    append_u8_be(ref buf, SIGS_REQUIRED);
    append_u64_be(ref buf, TIMESTAMP);
    append_u256_be(ref buf, SIGNERS_BITMAP);
    buf
}

#[test]
fn message_encoding_matches_evm() {
    // keccak256("MOLPHA_MESSAGE_V1" ‖ value ‖ sourceId ‖ u32 registryVersion
    //           ‖ u8 signaturesRequired ‖ u64 canonicalTimestamp ‖ signersBitmap)
    let buf = evm_message_preimage();
    assert(buf.len() == 141, 'preimage not 141 bytes');
    assert(keccak_bytes(@buf) == MESSAGE(), 'message mismatch');
}

#[test]
fn message_encoding_is_sensitive_to_field_widths() {
    // Ported from `MessageFormatSpec.t.sol`. The narrow widths are the single
    // easiest thing to get wrong in a port — encoding `signaturesRequired` as a
    // u32, as an earlier revision of this contract did, still produces a
    // perfectly well-formed digest that simply never matches anyone else's.
    let canonical = keccak_bytes(@evm_message_preimage());

    let mut wide_sigs: ByteArray = "";
    append_u256_be(ref wide_sigs, MESSAGE_PREFIX());
    append_u256_be(ref wide_sigs, VALUE());
    append_u256_be(ref wide_sigs, SOURCE_ID());
    append_u32_be(ref wide_sigs, REG_VERSION);
    append_u32_be(ref wide_sigs, SIGS_REQUIRED.into());
    append_u64_be(ref wide_sigs, TIMESTAMP);
    append_u256_be(ref wide_sigs, SIGNERS_BITMAP);
    assert(keccak_bytes(@wide_sigs) != canonical, 'u32 sigs must differ');

    let mut wide_version: ByteArray = "";
    append_u256_be(ref wide_version, MESSAGE_PREFIX());
    append_u256_be(ref wide_version, VALUE());
    append_u256_be(ref wide_version, SOURCE_ID());
    append_u256_be(ref wide_version, REG_VERSION.into());
    append_u8_be(ref wide_version, SIGS_REQUIRED);
    append_u64_be(ref wide_version, TIMESTAMP);
    append_u256_be(ref wide_version, SIGNERS_BITMAP);
    assert(keccak_bytes(@wide_version) != canonical, 'u256 version must differ');

    let mut wide_ts: ByteArray = "";
    append_u256_be(ref wide_ts, MESSAGE_PREFIX());
    append_u256_be(ref wide_ts, VALUE());
    append_u256_be(ref wide_ts, SOURCE_ID());
    append_u32_be(ref wide_ts, REG_VERSION);
    append_u8_be(ref wide_ts, SIGS_REQUIRED);
    append_u256_be(ref wide_ts, TIMESTAMP.into());
    append_u256_be(ref wide_ts, SIGNERS_BITMAP);
    assert(keccak_bytes(@wide_ts) != canonical, 'u256 timestamp must differ');
}

#[test]
fn message_encoding_is_sensitive_to_field_order() {
    // The pre-#23 layout this contract used to implement. It is a valid keccak
    // of a valid preimage; it is simply not the one anyone signs.
    let mut legacy: ByteArray = "";
    append_u256_be(ref legacy, MESSAGE_PREFIX());
    append_u256_be(ref legacy, SOURCE_ID());
    append_u32_be(ref legacy, REG_VERSION);
    append_u32_be(ref legacy, SIGS_REQUIRED.into());
    append_u256_be(ref legacy, SIGNERS_BITMAP);
    append_u256_be(ref legacy, VALUE());
    append_u64_be(ref legacy, TIMESTAMP);
    assert(keccak_bytes(@legacy) != MESSAGE(), 'legacy order must differ');
}

#[test]
fn selection_bitmap_matches_evm() {
    // derive(seed, nodeCount, groupSize = signaturesRequired + redundancyBuffer).
    // groupSize exceeds nodeCount/2 here, so this also exercises the complement
    // branch, which selects a different set than sampling the group directly.
    let group_size: u32 = SIGS_REQUIRED.into() + REDUNDANCY_BUFFER;
    let bm = node_group_bitmap::derive(SELECTION_SEED(), NODE_COUNT, group_size).unwrap();
    assert(bm == SIGNERS_BITMAP, 'selection bitmap mismatch');
}

#[test]
fn derive_reports_empty_node_set_instead_of_panicking() {
    // `verify` must never panic, so the sampler reports bad parameters as a
    // value. An empty node set is the reachable case: a registry version that
    // exists but holds no keys.
    assert(node_group_bitmap::derive(SELECTION_SEED(), 0, 0).is_none(), 'zero nodes should be None');
    assert(
        node_group_bitmap::derive(SELECTION_SEED(), 4, 5).is_none(), 'oversized group should be None',
    );
}

#[test]
fn decompress_and_aggregate_matches_evm() {
    // Plain EC sum over the fixture's signer set, reproducing the aggregate key
    // the EVM contract builds from its SSTORE2 blob. Bit `i` is node `i`.
    let nodes = fixture_nodes();
    let mut acc: Option<starknet::secp256k1::Secp256k1Point> = Option::None;
    let mut i: u32 = 0;
    while i < nodes.len() {
        if (SIGNERS_BITMAP / verifier::bitmap::two_pow(i)) % 2 == 1 {
            let (prefix, x, _sk) = *nodes.at(i);
            let (px, py) = ec::decompress(@compressed(prefix, x));
            let pt = ec::new_point(px, py).unwrap();
            acc =
                match acc {
                    Option::None => Option::Some(pt),
                    Option::Some(a) => Option::Some(ec::add(a, pt)),
                };
        }
        i += 1;
    }
    let (ax, ay) = ec::coords(acc.unwrap());
    assert(ax == AGG_X(), 'aggregate x mismatch');
    assert(ay == AGG_Y(), 'aggregate y mismatch');
}

#[test]
fn verify_trusted_accepts_evm_signature() {
    assert(
        schnorr::verify_trusted(AGG_X(), AGG_Y(), MESSAGE(), SIGNATURE(), COMMITMENT),
        'evm signature rejected',
    );
}

#[test]
fn verify_trusted_rejects_tampered_message() {
    assert(
        !schnorr::verify_trusted(AGG_X(), AGG_Y(), MESSAGE() + 1, SIGNATURE(), COMMITMENT),
        'tampered message accepted',
    );
}

#[test]
fn verify_trusted_rejects_wrong_commitment() {
    assert(
        !schnorr::verify_trusted(AGG_X(), AGG_Y(), MESSAGE(), SIGNATURE(), COMMITMENT + 1),
        'wrong commitment accepted',
    );
}

#[test]
fn schnorr_verify_rejects_oversized_commitment_without_panicking() {
    // A felt252 is wider than an Ethereum address. Hashing an oversized
    // commitment would panic inside `append_address_be`, so the guard has to sit
    // in front of it — `verify` reports malformed input, it does not trap.
    let oversized: felt252 = 0x1_0000000000000000_0000000000000000_0000000000000000;
    assert(
        !schnorr::verify(AGG_X(), AGG_Y(), MESSAGE(), SIGNATURE(), oversized),
        'oversized commitment accepted',
    );
}

#[test]
fn pop_digest_matches_the_registration_script() {
    // `scripts/add_node.mjs` produces the proof-of-possession for real
    // registrations, so its digest layout has to match the contract's byte for
    // byte. A mismatch fails loudly at `add_node` rather than silently, but it
    // fails after a deploy — cheaper to catch here.
    //
    // Expected value from:
    //   popDigest("0x0123...cdef", 0x02 ‖ 0x11 * 32)
    let mut buf: ByteArray = "";
    append_u256_be(ref buf, verifier::constants::POP_DOMAIN());
    append_u256_be(
        ref buf,
        u256 {
            high: 0x0123456789abcdef0123456789abcdef, low: 0x0123456789abcdef0123456789abcdef,
        },
    );
    buf.append_byte(2);
    append_u256_be(
        ref buf,
        u256 {
            high: 0x11111111111111111111111111111111, low: 0x11111111111111111111111111111111,
        },
    );

    assert(
        keccak_bytes(@buf) == u256 {
            high: 0x9ba95d384378425ac25a998a4737701b, low: 0x21f02e85aeff1a163d6046629b94eac5,
        },
        'pop digest mismatch',
    );
}
