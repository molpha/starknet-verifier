//! Bit utilities mirroring `BitmapLib.sol` (`popCount`) and the power-of-two
//! helpers used by node selection.

/// Hamming weight of a 256-bit value — number of set bits.
/// Equivalent to `BitmapLib.popCount`.
///
/// Uses Brian Kernighan's `x & (x - 1)` to clear the lowest set bit each step,
/// so the loop runs once per set bit instead of once per bit position — and
/// each step is an AND + subtraction instead of the costlier full-width divide.
pub fn pop_count(mut x: u256) -> u32 {
    let mut c: u32 = 0;
    while x != 0 {
        x = x & (x - 1);
        c += 1;
    }
    c
}

/// Returns `2^n` as a `u256`. Caller must ensure `n < 256`.
///
/// Exponentiation by squaring: `O(log n)` multiplications rather than `n`.
pub fn two_pow(n: u32) -> u256 {
    let mut result: u256 = 1;
    let mut base: u256 = 2;
    let mut exp = n;
    while exp != 0 {
        if exp % 2 == 1 {
            result = result * base;
        }
        exp = exp / 2;
        // Skip the final squaring (would overflow u256 for the top bit of n).
        if exp != 0 {
            base = base * base;
        }
    }
    result
}
