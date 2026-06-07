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
const POW2_32: u256 = 0x100000000;

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
            let shift: u32 = 224 - 32 * w;
            let limb_u256 = (digest / two_pow(shift)) % POW2_32;
            let limb: u64 = limb_u256.try_into().unwrap();

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
pub fn derive(seed: u256, n_count: u32, group_size: u32) -> u256 {
    assert(n_count != 0, 'nodeCount is zero');
    assert(n_count <= 256, 'nCount exceeds 256');
    assert(group_size <= n_count, 'groupSize exceeds nodeCount');
    if group_size == 0 {
        return 0;
    }
    if group_size == n_count {
        return full_mask(n_count);
    }
    if group_size > n_count / 2 {
        let excluded = sample_without_replacement(seed, n_count, n_count - group_size);
        return full_mask(n_count) ^ excluded;
    }
    sample_without_replacement(seed, n_count, group_size)
}
