//! Public interface and payload structs — the StarkNet analogue of
//! `IVerifier.sol`. Field names and semantics match the EVM contract.

use starknet::ContractAddress;

/// Generic Schnorr proof used for proof-of-possession and as the aggregate
/// signature inputs.
/// * `signature`  — Schnorr scalar `s`.
/// * `commitment` — Ethereum address (low 160 bits) of the commitment point `R`.
#[derive(Drop, Serde, Copy)]
pub struct SchnorrProof {
    pub signature: u256,
    pub commitment: felt252,
}

/// Aggregated Schnorr signature over a `DataUpdate`.
/// `signers_bitmap` uses 0-based bit positions: bit `(i-1)` is set iff the
/// 1-based signer index `i` participated. At most 256 nodes.
#[derive(Drop, Serde, Copy)]
pub struct SchnorrSignature {
    pub signature: u256,
    pub commitment: felt252,
    pub signers_bitmap: u256,
}

/// Self-contained signed result payload for one pull round.
#[derive(Drop, Serde, Copy)]
pub struct DataUpdate {
    pub feed_id: u256,
    pub registry_version: u32,
    pub signatures_required: u32,
    pub value: u256,
    pub canonical_timestamp: u64,
}

#[starknet::interface]
pub trait IVerifier<TContractState> {
    /// Verifies an aggregated Schnorr signature over `data_update`.
    /// Reverts on structural failures (bad registry version, too few signers,
    /// signer outside the selection set, …); otherwise returns whether the
    /// aggregate signature itself is valid.
    fn verify(
        self: @TContractState, data_update: DataUpdate, schnorr_data: SchnorrSignature,
    ) -> bool;

    /// Registers a node from its 33-byte compressed pubkey, gated by a Schnorr
    /// proof-of-possession over the registration domain. Admin only.
    fn add_node(ref self: TContractState, compressed_pubkey: ByteArray, pop: SchnorrProof);

    /// Removes a node by its Ethereum-style identity address. Admin only.
    fn remove_node(ref self: TContractState, node: felt252);

    /// Transfers the protocol-admin role. Admin only.
    fn transfer_protocol_admin(ref self: TContractState, new_protocol_admin: ContractAddress);

    /// Sets the redundancy buffer (`groupSize = signaturesRequired + buffer`).
    /// Admin only.
    fn set_redundancy_buffer(ref self: TContractState, new_redundancy_buffer: u256);

    /// Current registry version (number of node-set snapshots minus one).
    fn get_registry_version(self: @TContractState) -> u64;

    /// Whether `node` is currently registered.
    fn is_node(self: @TContractState, node: felt252) -> bool;

    /// Number of nodes in the current registry version.
    fn get_total_nodes(self: @TContractState) -> u32;

    /// Plain-sum aggregate public key over the current node set.
    fn get_aggregate_key(self: @TContractState) -> (u256, u256);

    /// 1-based index of `node`, or 0 if not registered.
    fn get_node_index(self: @TContractState, node: felt252) -> u32;

    /// The redundancy buffer.
    fn get_redundancy_buffer(self: @TContractState) -> u256;

    /// The protocol admin address.
    fn get_protocol_admin(self: @TContractState) -> ContractAddress;
}
