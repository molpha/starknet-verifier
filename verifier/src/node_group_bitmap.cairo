//! Deterministic without-replacement node selection — a faithful port of
//! `NodeGroupBitmapLib.sol`.
//!
//! PRF: `keccak256(seed ‖ SELECTION_DOMAIN ‖ counter)` over three 32-byte
//! big-endian words; `counter` starts at 0. Each 256-bit digest yields eight
//! big-endian `uint32` limbs (MSB first). A limb is rejected (to keep the
//! distribution unbiased) when `limb >= floor(0xFFFFFFFF / nCount) * nCount`;
//! otherwise `pos = limb % nCount` selects a node, skipping positions already
//! chosen. When `groupSize > nCount / 2` we instead sample `nCount - groupSize`
//! exclusions and complement the full mask.

use crate::bitmap::two_pow;
use crate::byte_utils::{append_u256_be, keccak_bytes};
use crate::constants::SELECTION_DOMAIN;

const U32_MAX: u64 = 0xFFFFFFFF;

/// Extracts big-endian `uint32` limb `w` (`0..8`, MSB first) from a 256-bit
/// digest. Equivalent to `(digest / 2^(224 - 32*w)) % 2^32` but works on the
/// native `u128` halves with constant divisors — no `two_pow` / `u256` divide.
fn limb_at(digest: u256, w: u32) -> u64 {
    let word: u128 = if w < 4 {
        digest.high
    } else {
        digest.low
    };
    let v: u128 = if w % 4 == 0 {
        word / 0x1000000000000000000000000_u128
    } else if w % 4 == 1 {
        (word / 0x10000000000000000_u128) % 0x100000000_u128
    } else if w % 4 == 2 {
        (word / 0x100000000_u128) % 0x100000000_u128
    } else {
        word % 0x100000000_u128
    };
    v.try_into().unwrap()
}

/// Full mask of `n_count` low bits.
fn full_mask(n_count: u32) -> u256 {
    if n_count == 256 {
        return u256 {
            high: 0xffffffffffffffffffffffffffffffff, low: 0xffffffffffffffffffffffffffffffff,
        };
    }
    two_pow(n_count) - 1
}

/// Selects `group_size` distinct positions in `[0, n_count)` from `seed`.
fn sample_without_replacement(seed: u256, n_count: u32, group_size: u32) -> u256 {
    let nn: u64 = n_count.into();
    let limit: u64 = (U32_MAX / nn) * nn;

    let mut bitmap: u256 = 0;
    let mut selected: u32 = 0;
    let mut counter: u256 = 0;

    while selected < group_size {
        let mut preimage: ByteArray = "";
        append_u256_be(ref preimage, seed);
        append_u256_be(ref preimage, SELECTION_DOMAIN());
        append_u256_be(ref preimage, counter);
        let digest = keccak_bytes(@preimage);
        counter += 1;

        let mut w: u32 = 0;
        while w < 8 && selected < group_size {
            // Big-endian uint32 limb w (MSB first): bits [224 - 32*w .. +32).
            let limb: u64 = limb_at(digest, w);

            if limb < limit {
                let pos: u64 = limb % nn;
                let bit = two_pow(pos.try_into().unwrap());
                if (bitmap & bit) == 0 {
                    bitmap = bitmap | bit;
                    selected += 1;
                }
            }
            w += 1;
        }
    }
    bitmap
}

/// Derives the selection bitmap. Equivalent to `NodeGroupBitmapLib.derive`.
///
/// Returns `None` for parameters the EVM library reverts on. `Verifier.verify`
/// must never panic, and an empty node set is genuinely reachable there (a
/// registry version with no nodes), so the failure is a value rather than a
/// trap; the caller maps it to `R_BAD_QUORUM`, which is what Solidity's
/// `selectionOk` returns in the same situation.
pub fn derive(seed: u256, n_count: u32, group_size: u32) -> Option<u256> {
    if n_count == 0 || n_count > 256 || group_size > n_count {
        return Option::None;
    }
    if group_size == 0 {
        return Option::Some(0);
    }
    if group_size == n_count {
        return Option::Some(full_mask(n_count));
    }
    if group_size > n_count / 2 {
        let excluded = sample_without_replacement(seed, n_count, n_count - group_size);
        return Option::Some(full_mask(n_count) ^ excluded);
    }
    Option::Some(sample_without_replacement(seed, n_count, group_size))
}
