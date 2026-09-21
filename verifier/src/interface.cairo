//! Public interface and payload structs — the StarkNet analogue of
//! `IVerifier.sol`. Field names, order and widths match the EVM contract and
//! the Rust verifier's `payload.rs`.

use starknet::ContractAddress;

/// Generic Schnorr proof used for proof-of-possession.
/// * `signature`  — Schnorr scalar `s`.
/// * `commitment` — Ethereum address (low 160 bits) of the commitment point `R`.
#[derive(Drop, Serde, Copy)]
pub struct SchnorrProof {
    pub signature: u256,
    pub commitment: felt252,
}

/// Aggregated Schnorr signature over an `AttestationPayload`.
///
/// `signers_bitmap` uses 0-based bit positions: bit `i` is set iff the `i`-th
/// node registered in that registry version participated. At most 256 nodes.
/// Only `signers_bitmap` is covered by the signed message; `signature` and
/// `commitment` are the signature itself.
#[derive(Drop, Serde, Copy)]
pub struct SchnorrSignature {
    pub signature: u256,
    pub commitment: felt252,
    pub signers_bitmap: u256,
}

/// Self-contained signed result payload for one pull round.
///
/// Field order is load bearing — it is the order of the keccak preimage in
/// `_construct_message`, mirrored by `IVerifier.AttestationPayload` (Solidity)
/// and `AttestationPayload` (Rust). Never reorder, insert, or widen a field
/// without a coordinated cross-VM release.
#[derive(Drop, Serde, Copy)]
pub struct AttestationPayload {
    pub value: u256,
    pub source_id: u256,
    pub registry_version: u32,
    pub signatures_required: u8,
    pub canonical_timestamp: u64,
}

/// A payload and the aggregate signature over it.
#[derive(Drop, Serde, Copy)]
pub struct Attestation {
    pub payload: AttestationPayload,
    pub signature: SchnorrSignature,
}

#[starknet::interface]
pub trait IVerifier<TContractState> {
    /// Verifies an aggregated Schnorr signature over `attestation.payload`.
    ///
    /// Returns `(success, code)` where `code` is one of `verify_codes`. This is
    /// a total function: it **never panics**, for any calldata. A `false` result
    /// always carries the reason, and the codes match the EVM and Solana
    /// verifiers for identical inputs.
    ///
    /// `max_age` is the caller's freshness window in seconds. `0` disables the
    /// check entirely — which is not a neutral default, since a stateless
    /// verifier accepts a correctly signed payload forever.
    fn verify(
        self: @TContractState, attestation: Attestation, max_age: u64,
    ) -> (bool, u8);

    /// Registers a node from its 33-byte compressed pubkey, gated by a Schnorr
    /// proof-of-possession over the registration domain. Admin only.
    fn add_node(ref self: TContractState, compressed_pubkey: ByteArray, pop: SchnorrProof);

    /// Removes a node by its Ethereum-style identity address. `index` is the
    /// node's **0-based** position in the current registry version and is
    /// checked as a witness, matching the EVM `removeNode(address, uint256)`
    /// ABI. Admin only.
    fn remove_node(ref self: TContractState, node: felt252, index: u32);

    /// Transfers the protocol-admin role. Admin only.
    fn transfer_protocol_admin(ref self: TContractState, new_protocol_admin: ContractAddress);

    /// Sets the redundancy buffer (`groupSize = signaturesRequired + buffer`).
    /// Publishes a **new** registry version rather than mutating the current
    /// one, so a payload that already verifies keeps verifying. Admin only.
    fn set_redundancy_buffer(ref self: TContractState, new_redundancy_buffer: u32);

    /// Current registry version (number of node-set snapshots minus one).
    fn get_registry_version(self: @TContractState) -> u32;

    /// Whether `node` is currently registered (status `ACTIVE`).
    fn is_node(self: @TContractState, node: felt252) -> bool;

    /// Lifecycle status of `node`: 0 `NEVER`, 1 `ACTIVE`, 2 `RETIRED`.
    /// A retired address is never reusable.
    fn get_node_status(self: @TContractState, node: felt252) -> u8;

    /// Number of nodes in the current registry version.
    fn get_total_nodes(self: @TContractState) -> u32;

    /// Plain-sum aggregate public key over the current node set.
    fn get_aggregate_key(self: @TContractState) -> (u256, u256);

    /// 0-based index of `node` in the current version; `is_node` distinguishes
    /// "index 0" from "not registered".
    fn get_node_index(self: @TContractState, node: felt252) -> u32;

    /// The redundancy buffer of the current registry version.
    fn get_redundancy_buffer(self: @TContractState) -> u32;

    /// Activation timestamp of `registry_version`, and whether it exists.
    fn get_activates_at(self: @TContractState, registry_version: u32) -> (u64, bool);

    /// The protocol admin address.
    fn get_protocol_admin(self: @TContractState) -> ContractAddress;
}
