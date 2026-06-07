//! Molpha Verifier — StarkNet port of `Verifier.sol`.
//!
//! Stores the mirrored node public-key set indexed by `registry_version` and
//! verifies Molpha PoP-Schnorr aggregate signatures. Holds no job, round, or
//! feed state — every input is either in the snapshot (node coordinates by
//! version) or in calldata protected by the aggregate signature.
//!
//! Storage model. The EVM contract keeps one immutable SSTORE2 blob per
//! registry version, with index 0 holding the running plain-sum aggregate key
//! and indices `1..=nodeCount` the registered nodes. We mirror that exactly with
//! per-`(version, index)` coordinate maps: every `add_node` / `remove_node`
//! creates a new immutable version (copying the prior set forward) so historical
//! rounds stay permanently verifiable, just like the EVM design.

#[starknet::contract]
pub mod Verifier {
    use starknet::secp256k1::Secp256k1Point;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use crate::byte_utils::{append_u256_be, append_u32_be, append_u64_be, keccak_bytes};
    use crate::constants::{MAX_NODES, MESSAGE_PREFIX, POP_DOMAIN, SELECTION_SEED_PREFIX};
    use crate::interface::{DataUpdate, IVerifier, SchnorrProof, SchnorrSignature};
    use crate::secp256k1_utils as ec;
    use crate::{bitmap, node_group_bitmap, schnorr};

    /// `2^32` — stride used to pack `(version, index)` into a single storage key.
    const SLOT_STRIDE: felt252 = 0x100000000;

    #[storage]
    struct Storage {
        protocol_admin: ContractAddress,
        redundancy_buffer: u256,
        // Current registry version. Valid versions are `0..=registry_version`.
        registry_version: u64,
        // version -> number of registered nodes (excludes the aggregate at index 0).
        node_count: Map<u64, u32>,
        // packed(version, index) -> affine x / y. Index 0 is the aggregate key.
        key_x: Map<felt252, u256>,
        key_y: Map<felt252, u256>,
        // node identity address -> 1-based index in the current version (0 = absent).
        node_indexes: Map<felt252, u32>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        LogNodeAdded: LogNodeAdded,
        LogNodeRemoved: LogNodeRemoved,
        LogProtocolAdminTransferred: LogProtocolAdminTransferred,
        LogRedundancyBufferUpdated: LogRedundancyBufferUpdated,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LogNodeAdded {
        #[key]
        pub node: felt252,
        pub index: u32,
        pub registry_version: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LogNodeRemoved {
        #[key]
        pub node: felt252,
        pub old_index: u32,
        pub registry_version: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LogProtocolAdminTransferred {
        #[key]
        pub previous_admin: ContractAddress,
        #[key]
        pub new_admin: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LogRedundancyBufferUpdated {
        pub new_redundancy_buffer: u256,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        initial_protocol_admin: ContractAddress,
        initial_redundancy_buffer: u256,
    ) {
        self.protocol_admin.write(initial_protocol_admin);
        self.redundancy_buffer.write(initial_redundancy_buffer);
        // Version 0 is the empty set: node_count[0] = 0 and the aggregate at
        // slot(0, 0) is the zero point — both are storage defaults.
        self.registry_version.write(0);
    }

    /// Packs `(version, index)` into one felt storage key.
    fn slot(version: u64, index: u32) -> felt252 {
        let v: felt252 = version.into();
        v * SLOT_STRIDE + index.into()
    }

    #[abi(embed_v0)]
    impl VerifierImpl of IVerifier<ContractState> {
        fn verify(
            self: @ContractState, data_update: DataUpdate, schnorr_data: SchnorrSignature,
        ) -> bool {
            // 1. Selection seed from calldata.
            let selection_seed = self
                ._selection_seed(
                    data_update.job_id,
                    data_update.registry_version,
                    data_update.canonical_timestamp,
                );

            // 2. Registry version must exist.
            let version: u64 = data_update.registry_version.into();
            assert(version <= self.registry_version.read(), 'Invalid registry version');

            // 3. Node set for that version.
            let node_count = self.node_count.read(version);
            assert(node_count >= 1, 'No nodes');

            // 4. Structural guards (mirror Verifier.sol ordering).
            assert(data_update.signatures_required != 0, 'Zero signatures required');
            assert(schnorr_data.signers_bitmap != 0, 'Zero signers bitmap');
            assert(schnorr_data.signature != 0, 'Zero signature');
            assert(schnorr_data.commitment != 0, 'Zero commitment');

            // 5. Group size = signaturesRequired + redundancyBuffer, capped to nodeCount.
            let mut grp: u256 = data_update.signatures_required.into()
                + self.redundancy_buffer.read();
            let node_count_u256: u256 = node_count.into();
            if grp > node_count_u256 {
                grp = node_count_u256;
            }
            let group_size: u32 = grp.try_into().unwrap();

            // 6. Enough signers.
            let signer_count = bitmap::pop_count(schnorr_data.signers_bitmap);
            assert(signer_count >= data_update.signatures_required, 'Not enough signatures');

            // 7. Signers must be a subset of the derived selection set.
            let selection_bitmap = node_group_bitmap::derive(
                selection_seed, node_count, group_size,
            );
            assert(schnorr_data.signers_bitmap & ~selection_bitmap == 0, 'Signer not selected');

            // 8. Plain-sum coalition key over the signers.
            let (agg_x, agg_y) = self._aggregate_coords(version, schnorr_data.signers_bitmap);

            // 9. Reconstruct the signed message.
            let message = self
                ._construct_message(
                    data_update.job_id,
                    data_update.registry_version,
                    data_update.signatures_required,
                    schnorr_data.signers_bitmap,
                    data_update.value,
                    data_update.canonical_timestamp,
                );

            // 10. Aggregate Schnorr verification.
            schnorr::verify_trusted(
                agg_x, agg_y, message, schnorr_data.signature, schnorr_data.commitment,
            )
        }

        fn add_node(ref self: ContractState, compressed_pubkey: ByteArray, pop: SchnorrProof) {
            self._only_protocol_admin();

            let (px, py) = ec::decompress(@compressed_pubkey);
            assert(!(px == 0 && py == 0), 'Invalid public key');
            let node = ec::point_eth_address(px, py);
            assert(node != 0, 'Zero address');
            self._verify_pop(px, py, @compressed_pubkey, pop);

            let version = self.registry_version.read();
            let count = self.node_count.read(version);
            assert(count < MAX_NODES, 'Max nodes reached');
            assert(self.node_indexes.read(node) == 0, 'Node already added');

            let new_index = count + 1;

            // New running aggregate = old aggregate + new pubkey.
            let (agg_x, agg_y) = if count == 0 {
                (px, py)
            } else {
                let cx = self.key_x.read(slot(version, 0));
                let cy = self.key_y.read(slot(version, 0));
                ec::add_coords(cx, cy, px, py)
            };

            let new_version = version + 1;
            self._copy_nodes_forward(version, new_version, count);
            self.key_x.write(slot(new_version, 0), agg_x);
            self.key_y.write(slot(new_version, 0), agg_y);
            self.key_x.write(slot(new_version, new_index), px);
            self.key_y.write(slot(new_version, new_index), py);
            self.node_count.write(new_version, new_index);
            self.registry_version.write(new_version);
            self.node_indexes.write(node, new_index);

            self
                .emit(
                    Event::LogNodeAdded(
                        LogNodeAdded { node, index: new_index, registry_version: new_version },
                    ),
                );
        }

        fn remove_node(ref self: ContractState, node: felt252) {
            self._only_protocol_admin();

            let index = self.node_indexes.read(node);
            assert(index != 0, 'Not node');

            let version = self.registry_version.read();
            let count = self.node_count.read(version);
            assert(index <= count, 'Bad index');

            let px = self.key_x.read(slot(version, index));
            let py = self.key_y.read(slot(version, index));

            // New aggregate = old aggregate - removed pubkey (zero point if last).
            let (agg_x, agg_y) = if count == 1 {
                (0_u256, 0_u256)
            } else {
                let cx = self.key_x.read(slot(version, 0));
                let cy = self.key_y.read(slot(version, 0));
                let neg_py = crate::constants::FIELD_P() - py;
                ec::add_coords(cx, cy, px, neg_py)
            };

            let new_version = version + 1;
            let new_count = count - 1;
            self._copy_nodes_forward(version, new_version, count);

            // Swap-and-pop: move the last node into the removed slot.
            if index != count {
                let last_x = self.key_x.read(slot(new_version, count));
                let last_y = self.key_y.read(slot(new_version, count));
                self.key_x.write(slot(new_version, index), last_x);
                self.key_y.write(slot(new_version, index), last_y);
                let moved = ec::point_eth_address(last_x, last_y);
                self.node_indexes.write(moved, index);
            }

            self.key_x.write(slot(new_version, 0), agg_x);
            self.key_y.write(slot(new_version, 0), agg_y);
            self.node_count.write(new_version, new_count);
            self.registry_version.write(new_version);
            self.node_indexes.write(node, 0);

            self
                .emit(
                    Event::LogNodeRemoved(
                        LogNodeRemoved { node, old_index: index, registry_version: new_version },
                    ),
                );
        }

        fn transfer_protocol_admin(ref self: ContractState, new_protocol_admin: ContractAddress) {
            self._only_protocol_admin();
            assert(new_protocol_admin.into() != 0_felt252, 'Zero admin');
            let previous_admin = self.protocol_admin.read();
            self.protocol_admin.write(new_protocol_admin);
            self
                .emit(
                    Event::LogProtocolAdminTransferred(
                        LogProtocolAdminTransferred {
                            previous_admin, new_admin: new_protocol_admin,
                        },
                    ),
                );
        }

        fn set_redundancy_buffer(ref self: ContractState, new_redundancy_buffer: u256) {
            self._only_protocol_admin();
            self.redundancy_buffer.write(new_redundancy_buffer);
            self
                .emit(
                    Event::LogRedundancyBufferUpdated(
                        LogRedundancyBufferUpdated { new_redundancy_buffer },
                    ),
                );
        }

        fn get_registry_version(self: @ContractState) -> u64 {
            self.registry_version.read()
        }

        fn is_node(self: @ContractState, node: felt252) -> bool {
            self.node_indexes.read(node) != 0
        }

        fn get_total_nodes(self: @ContractState) -> u32 {
            self.node_count.read(self.registry_version.read())
        }

        fn get_aggregate_key(self: @ContractState) -> (u256, u256) {
            let version = self.registry_version.read();
            (self.key_x.read(slot(version, 0)), self.key_y.read(slot(version, 0)))
        }

        fn get_node_index(self: @ContractState, node: felt252) -> u32 {
            self.node_indexes.read(node)
        }

        fn get_redundancy_buffer(self: @ContractState) -> u256 {
            self.redundancy_buffer.read()
        }

        fn get_protocol_admin(self: @ContractState) -> ContractAddress {
            self.protocol_admin.read()
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_protocol_admin(self: @ContractState) {
            assert(get_caller_address() == self.protocol_admin.read(), 'Not protocol admin');
        }

        /// selectionSeed = keccak256("MOLPHA_SELECTION_V1" ‖ jobId ‖
        ///                           registryVersion ‖ canonicalTimestamp)
        fn _selection_seed(
            self: @ContractState, job_id: u256, registry_version: u32, canonical_timestamp: u64,
        ) -> u256 {
            let mut buf: ByteArray = "";
            append_u256_be(ref buf, SELECTION_SEED_PREFIX());
            append_u256_be(ref buf, job_id);
            append_u32_be(ref buf, registry_version);
            append_u64_be(ref buf, canonical_timestamp);
            keccak_bytes(@buf)
        }

        /// message = keccak256("MOLPHA_MESSAGE_V1" ‖ jobId ‖ registryVersion ‖
        ///                     signaturesRequired ‖ signersBitmap ‖ value ‖
        ///                     canonicalTimestamp)
        fn _construct_message(
            self: @ContractState,
            job_id: u256,
            registry_version: u32,
            signatures_required: u32,
            signers_bitmap: u256,
            value: u256,
            canonical_timestamp: u64,
        ) -> u256 {
            let mut buf: ByteArray = "";
            append_u256_be(ref buf, MESSAGE_PREFIX());
            append_u256_be(ref buf, job_id);
            append_u32_be(ref buf, registry_version);
            append_u32_be(ref buf, signatures_required);
            append_u256_be(ref buf, signers_bitmap);
            append_u256_be(ref buf, value);
            append_u64_be(ref buf, canonical_timestamp);
            keccak_bytes(@buf)
        }

        /// Sums the public keys of the signers (ascending 1-based index order).
        fn _aggregate_coords(
            self: @ContractState, version: u64, mut signers_bitmap: u256,
        ) -> (u256, u256) {
            let mut acc: Option<Secp256k1Point> = Option::None;
            let mut pos: u32 = 0;
            while signers_bitmap != 0 {
                if signers_bitmap.low % 2 == 1 {
                    let signer_index = pos + 1;
                    let x = self.key_x.read(slot(version, signer_index));
                    let y = self.key_y.read(slot(version, signer_index));
                    let pt = ec::new_point(x, y).unwrap();
                    acc =
                        match acc {
                            Option::None => Option::Some(pt),
                            Option::Some(a) => Option::Some(ec::add(a, pt)),
                        };
                }
                signers_bitmap = signers_bitmap / 2;
                pos += 1;
            }
            ec::coords(acc.unwrap())
        }

        /// Copies node entries `1..=count` from `from_version` to `to_version`,
        /// preserving the immutability of historical snapshots.
        fn _copy_nodes_forward(
            ref self: ContractState, from_version: u64, to_version: u64, count: u32,
        ) {
            let mut i: u32 = 1;
            while i <= count {
                self.key_x.write(slot(to_version, i), self.key_x.read(slot(from_version, i)));
                self.key_y.write(slot(to_version, i), self.key_y.read(slot(from_version, i)));
                i += 1;
            }
        }

        /// digest = keccak256("MOLPHA_VALIDATOR_V1" ‖ contractAddress ‖
        ///                    compressedPubKey); verified with the defensive
        /// Schnorr check. NOTE: the EVM contract hashes `address(this)` as 20
        /// bytes; here the StarkNet contract address is hashed as 32 bytes. PoP
        /// is registration-only and not part of `verify`, so this divergence
        /// does not affect cross-chain payload verification.
        fn _verify_pop(
            self: @ContractState, px: u256, py: u256, comp: @ByteArray, pop: SchnorrProof,
        ) {
            let mut buf: ByteArray = "";
            append_u256_be(ref buf, POP_DOMAIN());
            let addr_felt: felt252 = get_contract_address().into();
            append_u256_be(ref buf, addr_felt.into());
            buf.append(comp);
            let digest = keccak_bytes(@buf);
            let valid = schnorr::verify(px, py, digest, pop.signature, pop.commitment);
            assert(valid, 'Invalid PoP');
        }
    }
}
