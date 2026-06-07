//! Schnorr signature verification — a faithful port of `LibSchnorr.sol`.
//!
//! The EVM library verifies a Schnorr signature `(s, R)` for public key `P`
//! using the `ecrecover` trick from Chronicle/Scribe:
//!
//!   challenge e = keccak256(Pₓ ‖ Pₚ ‖ message ‖ commitment) mod Q
//!   ecrecover(−s·Pₓ, Pₚ+27, Pₓ, −e·Pₓ)  ==  s·G − e·P  (as an address)
//!   accept iff that recovered address equals `commitment` ( == address(R) ).
//!
//! StarkNet has native secp256k1, so instead of abusing `ecrecover` we compute
//! `T = s·G − e·P` directly and compare `ethAddress(T)` to `commitment`. This
//! is mathematically identical: the EVM `ecrecover` recovers exactly that point.

use starknet::secp256k1::Secp256k1Point;
use crate::byte_utils::{append_address_be, append_u256_be, keccak_bytes};
use crate::constants::CURVE_ORDER_Q;
use crate::secp256k1_utils as ec;

/// challenge = keccak256(Pₓ ‖ Pₚ ‖ message ‖ commitment) mod Q
pub fn challenge(px: u256, parity: u8, message: u256, commitment: felt252) -> u256 {
    let mut buf: ByteArray = "";
    append_u256_be(ref buf, px);
    buf.append_byte(parity);
    append_u256_be(ref buf, message);
    append_address_be(ref buf, commitment);
    keccak_bytes(@buf) % CURVE_ORDER_Q()
}

/// Verifies a Schnorr signature for the public key at `(px, py)` without the
/// defensive on-curve / range guards. Equivalent to
/// `LibSchnorr.verifySignatureTrusted`. Caller must ensure `signature != 0`,
/// `commitment != 0`, and that `(px, py)` is a valid curve point.
pub fn verify_trusted(
    px: u256, py: u256, message: u256, signature: u256, commitment: felt252,
) -> bool {
    let parity: u8 = (py.low % 2).try_into().unwrap();
    let e = challenge(px, parity, message, commitment);

    // T = s·G − e·P
    let s_g = ec::mul(ec::generator(), signature);
    let p = ec::new_point(px, py).unwrap();
    let e_p = ec::mul(p, e);
    let t = ec::add(s_g, ec::negate(e_p));

    ec::eth_address(t) == commitment
}

/// Defensive Schnorr verification with the same guards as
/// `LibSchnorr.verifySignature` (used for proof-of-possession at registration):
/// rejects zero signature/commitment, off-curve keys, and `s >= Q`.
pub fn verify(px: u256, py: u256, message: u256, signature: u256, commitment: felt252) -> bool {
    if signature == 0 || commitment == 0 {
        return false;
    }
    match ec::new_point(px, py) {
        Option::None => false,
        Option::Some(_) => {
            if signature >= CURVE_ORDER_Q() {
                return false;
            }
            verify_trusted(px, py, message, signature, commitment)
        },
    }
}

/// Verifies a Schnorr signature for an already-constructed point.
pub fn verify_trusted_point(
    p: Secp256k1Point, message: u256, signature: u256, commitment: felt252,
) -> bool {
    let (px, py) = ec::coords(p);
    verify_trusted(px, py, message, signature, commitment)
}
