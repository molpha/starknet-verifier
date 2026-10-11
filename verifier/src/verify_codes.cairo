//! Result codes returned by `Verifier.verify` — a faithful port of
//! `VerifyCodes.sol`.
//!
//! Codes 0–10 are shared by the EVM, Solana and StarkNet verifiers: the same
//! payload must produce the same code on every chain. **Never renumber them.**
//! Two codes belong to mechanisms this implementation does not have; they are
//! kept so the numbering can never shift under them.

pub const R_OK: u8 = 0;
/// Reserved. Never returned by this implementation; kept so codes are never renumbered.
pub const R_FEED_WITNESS: u8 = 1;
pub const R_BAD_REGISTRY_VERSION: u8 = 2;
pub const R_MALFORMED: u8 = 3;
pub const R_NOT_YET_ACTIVE: u8 = 4;
pub const R_VERSION_EXPIRED: u8 = 5;
/// Reserved. Never returned by this implementation; kept so codes are never renumbered.
pub const R_COMPROMISED_QUORUM: u8 = 6;
pub const R_BAD_QUORUM: u8 = 7;
pub const R_BAD_AGGREGATE: u8 = 8;
pub const R_BAD_SIGNATURE: u8 = 9;
pub const R_STALE: u8 = 10;
