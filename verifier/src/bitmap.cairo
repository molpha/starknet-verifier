//! Bit utilities mirroring `BitmapLib.sol` (`popCount`) and the power-of-two
//! helpers used by node selection.

/// Hamming weight of a 256-bit value — number of set bits.
/// Equivalent to `BitmapLib.popCount`.
pub fn pop_count(mut x: u256) -> u32 {
    let mut c: u32 = 0;
    while x != 0 {
        if x.low % 2 == 1 {
            c += 1;
        }
        x = x / 2;
    }
    c
}

/// Returns `2^n` as a `u256`. Caller must ensure `n < 256`.
pub fn two_pow(mut n: u32) -> u256 {
    let mut r: u256 = 1;
    while n != 0 {
        r = r * 2;
        n -= 1;
    }
    r
}
