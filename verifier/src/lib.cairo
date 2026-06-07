//! Molpha StarkNet Verifier — a faithful Cairo port of the Molpha EVM
//! `Verifier.sol` contract.
//!
//! The protocol signs each oracle result once with a Molpha PoP-Schnorr
//! aggregate signature over secp256k1. The signed message deliberately omits
//! `chainId`, so the same `(DataUpdate, SchnorrSignature)` payload is valid on
//! every chain. This crate reproduces the EVM verification logic bit-for-bit:
//!
//!   message    = keccak256("MOLPHA_MESSAGE_V1" ‖ jobId ‖ registryVersion ‖
//!                          signaturesRequired ‖ signersBitmap ‖ value ‖
//!                          canonicalTimestamp)
//!   challenge  = keccak256(Pₓ ‖ Pₚ ‖ message ‖ commitment) mod Q
//!   accept iff  ethAddress(s·G − challenge·P) == commitment
//!
//! where `P` is the plain EC sum of the selected signers' public keys.
//!
//! The only deliberate divergence from the EVM contract is the Proof-of-
//! Possession domain separator used in `add_node`: the EVM hashes
//! `address(this)` (20 bytes); StarkNet hashes `get_contract_address()`
//! (32 bytes). PoP is checked only at registration and is never part of
//! `verify`, so this does not affect cross-chain payload verification.

pub mod constants;
pub mod byte_utils;
pub mod bitmap;
pub mod node_group_bitmap;
pub mod secp256k1_utils;
pub mod schnorr;
pub mod interface;
pub mod verifier;
