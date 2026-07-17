//! Cross-chain parity tests at the library level.
//!
//! These prove the Cairo port accepts exactly the signatures the Solidity
//! verifier accepts: the same `(message, aggregateKey, signature, commitment)`
//! verifies on both chains, and the keccak encodings / node selection match
//! the EVM contract bit-for-bit.

use verifier::byte_utils::{append_u256_be, append_u32_be, append_u64_be, keccak_bytes};
use verifier::constants::{MESSAGE_PREFIX, SELECTION_SEED_PREFIX};
use verifier::secp256k1_utils as ec;
use verifier::{node_group_bitmap, schnorr};
use super::fixtures::{
    AGG_X, AGG_X8, AGG_Y, AGG_Y8, COMMITMENT, COMMITMENT8, JOB_ID, MESSAGE, MESSAGE8, REG_VERSION,
    SELECTION_SEED, SIGNATURE, SIGNATURE8, SIGNERS_BITMAP, SIGS_REQUIRED, TIMESTAMP, VALUE,
    compressed, fixture_nodes,
};

#[test]
fn keccak_is_evm_compatible() {
    // keccak256("") — pins the big-endian convention of keccak_bytes.
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
    // keccak256("MOLPHA_SELECTION_V1" ‖ feedId ‖ registryVersion ‖ canonicalTimestamp)
    let mut buf: ByteArray = "";
    append_u256_be(ref buf, SELECTION_SEED_PREFIX());
    append_u256_be(ref buf, JOB_ID());
    append_u32_be(ref buf, REG_VERSION);
    append_u64_be(ref buf, TIMESTAMP);
    assert(keccak_bytes(@buf) == SELECTION_SEED(), 'selection seed mismatch');
}

#[test]
fn message_encoding_matches_evm() {
    // keccak256("MOLPHA_MESSAGE_V1" ‖ feedId ‖ registryVersion ‖ signaturesRequired
    //           ‖ signersBitmap ‖ value ‖ canonicalTimestamp)
    let mut buf: ByteArray = "";
    append_u256_be(ref buf, MESSAGE_PREFIX());
    append_u256_be(ref buf, JOB_ID());
    append_u32_be(ref buf, REG_VERSION);
    append_u32_be(ref buf, SIGS_REQUIRED);
    append_u256_be(ref buf, SIGNERS_BITMAP);
    append_u256_be(ref buf, VALUE());
    append_u64_be(ref buf, TIMESTAMP);
    assert(keccak_bytes(@buf) == MESSAGE(), 'message mismatch');
}

#[test]
fn selection_bitmap_matches_evm() {
    // derive(seed, nodeCount=10, groupSize=signaturesRequired+redundancyBuffer=5)
    let bm = node_group_bitmap::derive(SELECTION_SEED(), 10, 5);
    assert(bm == 0x38a, 'selection bitmap mismatch');
    assert(SIGNERS_BITMAP & ~bm == 0, 'signers not subset');
}

#[test]
fn decompress_and_aggregate_matches_evm() {
    // Decompress every signing node and plain-sum the ones in signersBitmap.
    // Exercises secp256k1 point decompression (incl. y-parity) and EC add.
    let nodes = fixture_nodes();
    let (x, y) = sum_signers(@nodes, SIGNERS_BITMAP);
    assert(x == AGG_X(), 'agg x mismatch');
    assert(y == AGG_Y(), 'agg y mismatch');
}

#[test]
fn verify_trusted_accepts_evm_signature_10nodes() {
    assert(
        schnorr::verify_trusted(AGG_X(), AGG_Y(), MESSAGE(), SIGNATURE(), COMMITMENT),
        'evm sig must verify (10)',
    );
}

#[test]
fn verify_trusted_accepts_evm_signature_8nodes() {
    assert(
        schnorr::verify_trusted(AGG_X8(), AGG_Y8(), MESSAGE8(), SIGNATURE8(), COMMITMENT8),
        'evm sig must verify (8)',
    );
}

#[test]
fn verify_trusted_rejects_tampered_message() {
    let bad = MESSAGE() + 1;
    assert(
        !schnorr::verify_trusted(AGG_X(), AGG_Y(), bad, SIGNATURE(), COMMITMENT),
        'tampered must fail',
    );
}

#[test]
fn verify_trusted_rejects_wrong_commitment() {
    assert(
        !schnorr::verify_trusted(AGG_X(), AGG_Y(), MESSAGE(), SIGNATURE(), COMMITMENT + 1),
        'wrong commitment must fail',
    );
}

/// Plain-sum the public keys whose 1-based index bit is set in `bitmap`.
fn sum_signers(nodes: @Array<(u8, u256, u256)>, mut bitmap: u256) -> (u256, u256) {
    let mut acc_x: u256 = 0;
    let mut acc_y: u256 = 0;
    let mut have = false;
    let mut pos: u32 = 0;
    while bitmap != 0 {
        if bitmap.low % 2 == 1 {
            let (prefix, x, _) = *nodes.at(pos);
            let comp = compressed(prefix, x);
            let (px, py) = ec::decompress(@comp);
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
        bitmap = bitmap / 2;
        pos += 1;
    }
    (acc_x, acc_y)
}
