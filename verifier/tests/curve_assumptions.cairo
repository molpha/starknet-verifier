//! Platform assumptions the totality of `verify` rests on.
//!
//! `Verifier.verify` must never revert (the cross-VM invariant the EVM contract
//! states in `IVerifier.sol` and `docs/registry-v2.md` F8). The plain-sum
//! aggregate key can legitimately reach the point at infinity — a node may
//! register a key and another node its negation, since `P` and `-P` have
//! different Ethereum addresses — and `R_BAD_AGGREGATE` is the code for that.
//!
//! A failed StarkNet syscall cannot be caught in-contract, so if `secp256_add`
//! *errored* at cancellation we could not report the code without panicking.
//! These tests pin that it does not: the infinity point is representable as
//! `(0, 0)`, `add` returns it rather than failing, and it behaves as the
//! additive identity. If a future StarkNet release changes this, these tests
//! fail loudly and `_aggregate_point` must grow an explicit cancellation
//! pre-check instead.

use verifier::constants::{CURVE_ORDER_Q, FIELD_P};
use verifier::secp256k1_utils as ec;

const ZERO: u256 = 0;

#[test]
fn infinity_is_representable_as_zero_point() {
    let p = ec::new_point(ZERO, ZERO);
    assert(p.is_some(), 'new_point(0,0) is None');
    let (x, y) = ec::coords(p.unwrap());
    assert(x == ZERO && y == ZERO, 'infinity is not (0,0)');
}

#[test]
fn add_of_point_and_its_negation_yields_infinity() {
    let (gx, gy) = ec::coords(ec::generator());
    let p = ec::new_point(gx, gy).unwrap();
    let neg = ec::new_point(gx, FIELD_P() - gy).unwrap();

    let (sx, sy) = ec::coords(ec::add(p, neg));
    assert(sx == ZERO && sy == ZERO, 'P + (-P) is not infinity');
}

#[test]
fn infinity_is_the_additive_identity() {
    let (gx, gy) = ec::coords(ec::generator());
    let p = ec::new_point(gx, gy).unwrap();
    let inf = ec::new_point(ZERO, ZERO).unwrap();

    let (ax, ay) = ec::coords(ec::add(inf, p));
    assert(ax == gx && ay == gy, 'inf + P != P');
}

#[test]
fn mul_by_curve_order_yields_infinity() {
    // `schnorr::verify_trusted_point` computes `(Q - e) * P`; a zero challenge
    // makes that `Q * P`. It must not fail the syscall.
    let (gx, gy) = ec::coords(ec::generator());
    let p = ec::new_point(gx, gy).unwrap();

    let (tx, ty) = ec::coords(ec::mul(p, CURVE_ORDER_Q()));
    assert(tx == ZERO && ty == ZERO, 'Q * P is not infinity');
}
