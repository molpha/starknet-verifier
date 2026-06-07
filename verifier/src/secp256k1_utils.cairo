//! Thin wrappers over StarkNet's native secp256k1 syscalls, plus the helpers
//! the EVM contract implements by hand in `LibSecp256k1.sol`
//! (point decompression, negation, and the Ethereum-address derivation used as
//! a node identity and as the Schnorr commitment comparison).

use starknet::SyscallResultTrait;
use starknet::secp256_trait::{Secp256PointTrait, Secp256Trait};
use starknet::secp256k1::Secp256k1Point;
use crate::byte_utils::{append_u256_be, keccak_bytes};
use crate::constants::{ADDRESS_MASK, FIELD_P};

/// Constructs a curve point from affine coordinates; `None` if not on-curve.
pub fn new_point(x: u256, y: u256) -> Option<Secp256k1Point> {
    Secp256Trait::<Secp256k1Point>::secp256_ec_new_syscall(x, y).unwrap_syscall()
}

/// Recovers a point from `x` with the given y-parity (`true` = odd y).
pub fn point_from_x(x: u256, y_parity: bool) -> Option<Secp256k1Point> {
    Secp256Trait::<Secp256k1Point>::secp256_ec_get_point_from_x_syscall(x, y_parity).unwrap_syscall()
}

/// The secp256k1 generator point G.
pub fn generator() -> Secp256k1Point {
    Secp256Trait::<Secp256k1Point>::get_generator_point()
}

/// Affine coordinates `(x, y)` of a point.
pub fn coords(p: Secp256k1Point) -> (u256, u256) {
    p.get_coordinates().unwrap_syscall()
}

/// EC point addition `a + b`.
pub fn add(a: Secp256k1Point, b: Secp256k1Point) -> Secp256k1Point {
    a.add(b).unwrap_syscall()
}

/// EC scalar multiplication `scalar · p`.
pub fn mul(p: Secp256k1Point, scalar: u256) -> Secp256k1Point {
    p.mul(scalar).unwrap_syscall()
}

/// Point negation `-p = (x, P - y)`.
pub fn negate(p: Secp256k1Point) -> Secp256k1Point {
    let (x, y) = coords(p);
    new_point(x, FIELD_P() - y).unwrap()
}

/// Ethereum address of a public key: low 160 bits of
/// `keccak256(x_be32 ‖ y_be32)`. Matches `LibSecp256k1.toAddress`.
pub fn point_eth_address(x: u256, y: u256) -> felt252 {
    let mut buf: ByteArray = "";
    append_u256_be(ref buf, x);
    append_u256_be(ref buf, y);
    let masked = keccak_bytes(@buf) & ADDRESS_MASK();
    masked.try_into().unwrap()
}

/// Ethereum address of a point.
pub fn eth_address(p: Secp256k1Point) -> felt252 {
    let (x, y) = coords(p);
    point_eth_address(x, y)
}

/// Plain EC sum of two points given as raw coordinates.
pub fn add_coords(ax: u256, ay: u256, bx: u256, by: u256) -> (u256, u256) {
    let r = add(new_point(ax, ay).unwrap(), new_point(bx, by).unwrap());
    coords(r)
}

/// Decompresses a 33-byte compressed public key (`0x02`/`0x03` prefix + 32-byte
/// big-endian x) into affine coordinates. Mirrors `LibSecp256k1.decompress`.
pub fn decompress(comp: @ByteArray) -> (u256, u256) {
    assert(comp.len() == 33, 'invalid length');
    let prefix = comp.at(0).unwrap();
    assert(prefix == 2 || prefix == 3, 'bad prefix');

    let mut x: u256 = 0;
    let mut i: usize = 1;
    while i < 33 {
        x = x * 256 + comp.at(i).unwrap().into();
        i += 1;
    }
    assert(x < FIELD_P(), 'x>=p');

    let y_is_odd = prefix == 3;
    let p = point_from_x(x, y_is_odd).unwrap();
    coords(p)
}
