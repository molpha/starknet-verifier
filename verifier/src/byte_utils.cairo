//! Helpers for building `abi.encodePacked`-equivalent byte strings and hashing
//! them with EVM-compatible keccak256.
//!
//! Solidity's `keccak256(abi.encodePacked(...))` concatenates the big-endian,
//! tightly-packed representation of each argument (no padding). We rebuild that
//! exact byte string in a `ByteArray` and hash it with
//! `core::keccak::compute_keccak_byte_array`, which returns the standard
//! Ethereum keccak256 digest as a big-endian `u256`.

use core::integer::u128_byte_reverse;
use core::keccak::compute_keccak_byte_array;
use crate::constants::ADDRESS_MASK;

/// Appends the 32 big-endian bytes of `v` (a Solidity `bytes32` / `uint256`).
pub fn append_u256_be(ref ba: ByteArray, v: u256) {
    ba.append_word(v.high.into(), 16);
    ba.append_word(v.low.into(), 16);
}

/// Appends the single byte of a Solidity `uint8`.
pub fn append_u8_be(ref ba: ByteArray, v: u8) {
    ba.append_byte(v);
}

/// Appends the 4 big-endian bytes of a Solidity `uint32`.
pub fn append_u32_be(ref ba: ByteArray, v: u32) {
    ba.append_word(v.into(), 4);
}

/// Appends the 8 big-endian bytes of a Solidity `uint64`.
pub fn append_u64_be(ref ba: ByteArray, v: u64) {
    ba.append_word(v.into(), 8);
}

/// Appends the 20 big-endian bytes of a Solidity `address`.
///
/// `append_word` **panics** when `v` does not fit in 20 bytes, so every caller
/// must have already rejected `v >= 2^160`. `Verifier.verify` does this in its
/// malformed-input stage; see `is_address_sized`.
pub fn append_address_be(ref ba: ByteArray, v: felt252) {
    ba.append_word(v, 20);
}

/// Whether `v` fits in 20 bytes, i.e. is a valid Ethereum-style address.
///
/// Guards `append_address_be`. Kept here, next to the function whose
/// precondition it is, so the two cannot drift apart.
pub fn is_address_sized(v: felt252) -> bool {
    let as_u256: u256 = v.into();
    as_u256 <= ADDRESS_MASK()
}

/// EVM-compatible keccak256 over the packed bytes.
///
/// `compute_keccak_byte_array` returns the digest with the byte order reversed
/// relative to Ethereum (the StarkNet keccak builtin is little-endian). We
/// reverse all 32 bytes so the result is the same big-endian `u256` Solidity's
/// `keccak256` produces.
pub fn keccak_bytes(ba: @ByteArray) -> u256 {
    let le = compute_keccak_byte_array(ba);
    u256 { high: u128_byte_reverse(le.low), low: u128_byte_reverse(le.high) }
}
