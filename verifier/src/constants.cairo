//! secp256k1 curve constants and Molpha domain separators.
//!
//! The domain separators are `keccak256` of their ASCII labels, matching the
//! values in `Verifier.sol` / `NodeGroupBitmapLib.sol`:
//!   MESSAGE_PREFIX        = keccak256("MOLPHA_MESSAGE_V1")
//!   SELECTION_SEED_PREFIX = keccak256("MOLPHA_SELECTION_V1")
//!   POP_DOMAIN            = keccak256("MOLPHA_VERIFIER_V1")
//!   SELECTION_DOMAIN      = keccak256("MOLPHA_SELECTION_DERIVE")

/// Field modulus P of secp256k1.
pub fn FIELD_P() -> u256 {
    u256 { high: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, low: 0xFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F }
}

/// Group order Q of secp256k1.
pub fn CURVE_ORDER_Q() -> u256 {
    u256 { high: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE, low: 0xBAAEDCE6AF48A03BBFD25E8CD0364141 }
}

/// Mask selecting the low 160 bits — the Ethereum address of a public key.
pub fn ADDRESS_MASK() -> u256 {
    u256 { high: 0xffffffff, low: 0xffffffffffffffffffffffffffffffff }
}

/// keccak256("MOLPHA_MESSAGE_V1")
pub fn MESSAGE_PREFIX() -> u256 {
    u256 { high: 0xa75523a2ab7b718d9cffd2fa97ed069f, low: 0xc12184eabee7d507854d0922f70e7fe7 }
}

/// keccak256("MOLPHA_SELECTION_V1")
pub fn SELECTION_SEED_PREFIX() -> u256 {
    u256 { high: 0x1def8159cbcfcdfd728d4197519a57c0, low: 0x6e243f0d9468b4c1e5c4a233fc5653c3 }
}

/// keccak256("MOLPHA_VERIFIER_V1")
pub fn POP_DOMAIN() -> u256 {
    u256 { high: 0x789b999d1d38ea94308dd6904bfa70cf, low: 0x9ee14dd2b978fb6d2c894c9c84150a04 }
}

/// keccak256("MOLPHA_SELECTION_DERIVE")
pub fn SELECTION_DOMAIN() -> u256 {
    u256 { high: 0x492848fe5e85d4ce2231d693a58f0820, low: 0xa4056e2822fe5dcad7c756afe044b70b }
}

/// Maximum number of registered nodes (fits one 256-bit bitmap).
pub const MAX_NODES: u32 = 256;

/// How long a superseded registry version keeps verifying after its successor
/// activates, in seconds. Matches `PREVIOUS_GRACE` in `Verifier.sol`.
///
/// Historical *rounds* stay verifiable forever; historical *versions* stop
/// being usable. Without this, threshold-many keys from any version that ever
/// existed could mint a fresh-timestamped update indefinitely, making the
/// effective trust set the union of every node set in history.
pub const PREVIOUS_GRACE: u64 = 60;

/// Node lifecycle. An address that has been registered is never reusable:
/// removal moves it to `RETIRED` and nothing moves it back. Each address's
/// membership is then a single contiguous version interval.
pub const NODE_NEVER: u8 = 0;
pub const NODE_ACTIVE: u8 = 1;
pub const NODE_RETIRED: u8 = 2;
