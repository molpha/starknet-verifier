//! Molpha Verifier — StarkNet port of `Verifier.sol`.
//!
//! Stores the mirrored node public-key set indexed by `registry_version` and
//! verifies Molpha PoP-Schnorr aggregate signatures. Holds no feed, round, or
//! subscription state — every input is either in the snapshot (node
//! coordinates by version) or in calldata protected by the aggregate signature.
//!
//! Storage model. Each registry version is an immutable snapshot: every
//! `add_node` / `remove_node` publishes a new version and copies the prior key
//! set forward, so historical rounds stay permanently verifiable.
//! Per-`(version, index)` coordinate maps hold the keys, with index 0 reserved
//! for the running plain-sum aggregate and indices `1..=node_count` the key
//! slots — so the `signers_bitmap` bit `i` maps to storage index `i + 1`, which
//! is the same slot as blob element `i` on EVM.
//!
//! Slots are stable. Removing a node zeroes its slot (a hole) instead of moving
//! the last node into it, so every other node keeps the bit it signs with;
//! `add_node` takes the lowest hole, else the slot after the last. `node_count`
//! is the number of slots, holes included, and trailing holes are trimmed.
//! `verify` accepts any quorum of live slots: committee selection is not part of
//! verification, and a set bit past the last slot or on a hole is `R_BAD_QUORUM`.

#[starknet::contract]
pub mod Verifier {
    use starknet::secp256k1::Secp256k1Point;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address, get_contract_address};
    use crate::byte_utils::{
        append_u256_be, append_u32_be, append_u64_be, append_u8_be, is_address_sized, keccak_bytes,
    };
    use crate::constants::{
        CURVE_ORDER_Q, MAX_NODES, MESSAGE_PREFIX, MILLIS_PER_SECOND, NODE_ACTIVE, NODE_NEVER,
        NODE_RETIRED, POP_DOMAIN, PREVIOUS_GRACE,
    };
    use crate::interface::{Attestation, AttestationPayload, IVerifier, SchnorrProof};
    use crate::{bitmap, schnorr, secp256k1_utils as ec, verify_codes};

    /// `2^32` — stride used to pack `(version, index)` into a single storage key.
    const SLOT_STRIDE: felt252 = 0x100000000;

    /// One immutable registry snapshot's header. The key set itself lives in
    /// `key_x` / `key_y` under the same version. `node_count` is the number of
    /// key slots, holes included.
    ///
    /// `exists` is an explicit sentinel because an unwritten `Map` entry reads as
    /// all-zero, and version 0 is a legitimate version; the EVM packs everything
    /// into one word and can use `entry != 0` instead.
    #[derive(Drop, Copy, Serde, starknet::Store)]
    pub struct RegistryEntry {
        pub exists: bool,
        pub is_latest: bool,
        pub node_count: u32,
        pub activates_at: u64,
    }

    #[storage]
    struct Storage {
        protocol_admin: ContractAddress,
        // Current registry version. Valid versions are `0..=registry_version`.
        registry_version: u32,
        // version -> immutable snapshot policy.
        registry_entries: Map<u32, RegistryEntry>,
        // packed(version, index) -> affine x / y. Index 0 is the running aggregate.
        key_x: Map<felt252, u256>,
        key_y: Map<felt252, u256>,
        // node identity address -> 1-based slot in the current version
        // (0 = not in the current version).
        node_indexes: Map<felt252, u32>,
        // node identity address -> NODE_NEVER | NODE_ACTIVE | NODE_RETIRED.
        node_status: Map<felt252, u8>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        LogNodeAdded: LogNodeAdded,
        LogNodeRemoved: LogNodeRemoved,
        LogProtocolAdminTransferred: LogProtocolAdminTransferred,
        RegistryAdvanced: RegistryAdvanced,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LogNodeAdded {
        #[key]
        pub node: felt252,
        /// 0-based slot within the new version: the lowest hole, else the next slot.
        pub index: u32,
        pub registry_version: u32,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LogNodeRemoved {
        #[key]
        pub node: felt252,
        /// 0-based slot the node occupied in the superseded version; now a hole,
        /// or trimmed if it was the last.
        pub old_index: u32,
        pub registry_version: u32,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LogProtocolAdminTransferred {
        #[key]
        pub previous_admin: ContractAddress,
        #[key]
        pub new_admin: ContractAddress,
    }

    /// Emitted by every registry mutation, so a watcher can follow version
    /// progression without decoding the individual operations.
    #[derive(Drop, starknet::Event)]
    pub struct RegistryAdvanced {
        #[key]
        pub registry_version: u32,
        pub node_count: u32,
        pub activates_at: u64,
    }

    #[constructor]
    fn constructor(ref self: ContractState, initial_protocol_admin: ContractAddress) {
        assert(initial_protocol_admin.into() != 0_felt252, 'Zero admin');
        self.protocol_admin.write(initial_protocol_admin);
        self.registry_version.write(0);
        // Genesis is the empty set, active from time zero.
        self
            .registry_entries
            .write(
                0, RegistryEntry { exists: true, is_latest: true, node_count: 0, activates_at: 0 },
            );
    }

    /// Packs `(version, index)` into one felt storage key.
    fn slot(version: u32, index: u32) -> felt252 {
        let v: felt252 = version.into();
        v * SLOT_STRIDE + index.into()
    }

    #[abi(embed_v0)]
    impl VerifierImpl of IVerifier<ContractState> {
        /// Total function: every path returns a code, none panics. See
        /// `verify_codes` for the cross-VM numbering, and the stage order below
        /// mirrors `Verifier.sol` exactly — each stage is observable through its
        /// code, so reordering them is a behaviour change.
        fn verify(self: @ContractState, attestation: Attestation, max_age: u64) -> (bool, u8) {
            let payload = attestation.payload;
            let sig = attestation.signature;

            // 1. Calldata-only guards, cheapest first.
            if payload.signatures_required == 0 {
                return (false, verify_codes::R_MALFORMED);
            }
            if sig.signers_bitmap == 0 {
                return (false, verify_codes::R_MALFORMED);
            }
            if sig.signature == 0 || sig.signature >= CURVE_ORDER_Q() {
                return (false, verify_codes::R_MALFORMED);
            }
            // `is_address_sized` is not redundant: a felt252 is wider than an
            // Ethereum address, and hashing an oversized one would panic.
            if sig.commitment == 0 || !is_address_sized(sig.commitment) {
                return (false, verify_codes::R_MALFORMED);
            }
            if bitmap::pop_count(sig.signers_bitmap) < payload.signatures_required.into() {
                return (false, verify_codes::R_MALFORMED);
            }

            // 2. Freshness. The caller opts in with a non-zero `max_age` and
            // picks a window wide enough to absorb sequencer clock drift.
            // `timestamp` is unix milliseconds; every clock comparison below is
            // in seconds, on its floor.
            let ts_sec = payload.timestamp / MILLIS_PER_SECOND;
            if max_age != 0 {
                let now = get_block_timestamp();
                if ts_sec > now {
                    return (false, verify_codes::R_MALFORMED);
                }
                if now - ts_sec > max_age {
                    return (false, verify_codes::R_STALE);
                }
            }

            // 3. Registry version must exist and be usable at this timestamp.
            let entry = self.registry_entries.read(payload.registry_version);
            if !entry.exists {
                return (false, verify_codes::R_BAD_REGISTRY_VERSION);
            }
            if ts_sec < entry.activates_at {
                return (false, verify_codes::R_NOT_YET_ACTIVE);
            }
            if !entry.is_latest {
                // `exists && !is_latest` implies a successor was published, so
                // `registry_version + 1` cannot overflow.
                let successor = self.registry_entries.read(payload.registry_version + 1);
                if successor.exists {
                    // Widened so the deadline cannot overflow u64.
                    let deadline: u128 = successor.activates_at.into() + PREVIOUS_GRACE.into();
                    if ts_sec.into() > deadline {
                        return (false, verify_codes::R_VERSION_EXPIRED);
                    }
                }
            }

            // 4. Plain-sum coalition key over the signers. Any quorum of live
            // slots verifies; a set bit past the last slot or on a hole names no
            // node and is the bitmap's only bound check.
            let (agg, vacant) = self._aggregate_point(payload.registry_version, sig.signers_bitmap);
            if vacant {
                return (false, verify_codes::R_BAD_QUORUM);
            }
            let agg_point = match agg {
                Option::None => { return (false, verify_codes::R_BAD_AGGREGATE); },
                Option::Some(p) => p,
            };
            let (agg_x, agg_y) = ec::coords(agg_point);
            // The sum reached the point at infinity — a signer set containing a
            // key and its negation. Both are registrable, since they have
            // different Ethereum addresses.
            if agg_x == 0 && agg_y == 0 {
                return (false, verify_codes::R_BAD_AGGREGATE);
            }

            // 5. Aggregate Schnorr verification over the reconstructed message.
            let message = construct_message(payload, sig.signers_bitmap);
            let valid = schnorr::verify_trusted_point(
                agg_point, message, sig.signature, sig.commitment,
            );
            if !valid {
                return (false, verify_codes::R_BAD_SIGNATURE);
            }

            (true, verify_codes::R_OK)
        }

        fn add_node(ref self: ContractState, compressed_pubkey: ByteArray, pop: SchnorrProof) {
            self._only_protocol_admin();

            let (px, py) = ec::decompress(@compressed_pubkey);
            assert(!(px == 0 && py == 0), 'Invalid public key');
            let node = ec::point_eth_address(px, py);
            assert(node != 0, 'Zero address');

            // Eligibility before the proof: verifying a PoP costs two scalar
            // multiplications, and there is no point paying for one to then
            // reject a duplicate. An address that has ever been registered is
            // never reusable, so a removed node must rotate keys to rejoin.
            assert(self.node_status.read(node) == NODE_NEVER, 'Node not eligible');

            let version = self.registry_version.read();
            let entry = self.registry_entries.read(version);
            let count = entry.node_count;

            // A hole is reusable, so a full table only refuses when it has none.
            let new_slot = self._first_free_slot(version, count);
            assert(new_slot <= count || count < MAX_NODES, 'Max nodes reached');

            self._verify_pop(px, py, @compressed_pubkey, pop);
            let new_count = if new_slot > count {
                count + 1
            } else {
                count
            };

            // New running aggregate = old aggregate + new pubkey. An aggregate of
            // zero means no live node yet (an empty registry, or one emptied by removals).
            let cx = self.key_x.read(slot(version, 0));
            let cy = self.key_y.read(slot(version, 0));
            let (agg_x, agg_y) = if cx == 0 && cy == 0 {
                (px, py)
            } else {
                ec::add_coords(cx, cy, px, py)
            };

            let new_version = version + 1;
            self._copy_nodes_forward(version, new_version, count);
            self.key_x.write(slot(new_version, 0), agg_x);
            self.key_y.write(slot(new_version, 0), agg_y);
            self.key_x.write(slot(new_version, new_slot), px);
            self.key_y.write(slot(new_version, new_slot), py);
            self.node_indexes.write(node, new_slot);
            self.node_status.write(node, NODE_ACTIVE);

            self._publish_registry_transition(version, new_count);

            self
                .emit(
                    Event::LogNodeAdded(
                        LogNodeAdded { node, index: new_slot - 1, registry_version: new_version },
                    ),
                );
        }

        /// `index` is the node's 0-based slot in the current version and is
        /// required as a witness: the caller must name the slot it believes the
        /// node occupies. Slots are stable, so the witness guards against a
        /// stale client naming the wrong node rather than against a swap.
        fn remove_node(ref self: ContractState, node: felt252, index: u32) {
            self._only_protocol_admin();

            assert(self.node_status.read(node) == NODE_ACTIVE, 'Node not eligible');

            let version = self.registry_version.read();
            let entry = self.registry_entries.read(version);
            let count = entry.node_count;
            assert(count != 0 && index < count, 'Index witness mismatch');

            let node_slot = index + 1;
            let px = self.key_x.read(slot(version, node_slot));
            let py = self.key_y.read(slot(version, node_slot));
            assert(ec::point_eth_address(px, py) == node, 'Index witness mismatch');

            // New aggregate = old aggregate - removed pubkey (zero point if it was the
            // only live node, i.e. the aggregate is that very key).
            let cx = self.key_x.read(slot(version, 0));
            let cy = self.key_y.read(slot(version, 0));
            let (agg_x, agg_y) = if cx == px && cy == py {
                (0_u256, 0_u256)
            } else {
                let neg_py = crate::constants::FIELD_P() - py;
                ec::add_coords(cx, cy, px, neg_py)
            };

            let new_version = version + 1;
            self._copy_nodes_forward(version, new_version, count);

            // The slot becomes a hole; no other node moves.
            self.key_x.write(slot(new_version, node_slot), 0);
            self.key_y.write(slot(new_version, node_slot), 0);

            // Trailing holes are trimmed so the table ends on a live node.
            let mut new_count = count;
            while new_count != 0
                && self.key_x.read(slot(new_version, new_count)) == 0
                && self.key_y.read(slot(new_version, new_count)) == 0 {
                new_count -= 1;
            }

            self.key_x.write(slot(new_version, 0), agg_x);
            self.key_y.write(slot(new_version, 0), agg_y);
            self.node_indexes.write(node, 0);
            self.node_status.write(node, NODE_RETIRED);

            self._publish_registry_transition(version, new_count);

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

        fn get_registry_version(self: @ContractState) -> u32 {
            self.registry_version.read()
        }

        fn is_node(self: @ContractState, node: felt252) -> bool {
            self.node_status.read(node) == NODE_ACTIVE
        }

        fn get_node_status(self: @ContractState, node: felt252) -> u8 {
            self.node_status.read(node)
        }

        fn get_total_nodes(self: @ContractState) -> u32 {
            self.registry_entries.read(self.registry_version.read()).node_count
        }

        fn get_aggregate_key(self: @ContractState) -> (u256, u256) {
            let version = self.registry_version.read();
            (self.key_x.read(slot(version, 0)), self.key_y.read(slot(version, 0)))
        }

        /// 0-based slot; check `is_node` to distinguish slot 0 from "not registered".
        fn get_node_index(self: @ContractState, node: felt252) -> u32 {
            let stored = self.node_indexes.read(node);
            if stored == 0 {
                return 0;
            }
            stored - 1
        }

        fn get_activates_at(self: @ContractState, registry_version: u32) -> (u64, bool) {
            let entry = self.registry_entries.read(registry_version);
            (entry.activates_at, entry.exists)
        }

        fn get_protocol_admin(self: @ContractState) -> ContractAddress {
            self.protocol_admin.read()
        }
    }

    /// message = keccak256("MOLPHA_MESSAGE_V1" ‖ value ‖ sourceId ‖
    ///                     u32(registryVersion) ‖ u8(signaturesRequired) ‖
    ///                     u64(timestamp, unix ms) ‖ signersBitmap)
    ///
    /// 141-byte preimage. Field order and the narrow widths are shared with
    /// `VerifierLib.constructMessage`, `compute_message_hash` and the Go node
    /// client's `buildMessage`; changing either breaks every chain at once.
    fn construct_message(payload: AttestationPayload, signers_bitmap: u256) -> u256 {
        let mut buf: ByteArray = "";
        append_u256_be(ref buf, MESSAGE_PREFIX());
        append_u256_be(ref buf, payload.value);
        append_u256_be(ref buf, payload.source_id);
        append_u32_be(ref buf, payload.registry_version);
        append_u8_be(ref buf, payload.signatures_required);
        append_u64_be(ref buf, payload.timestamp);
        append_u256_be(ref buf, signers_bitmap);
        keccak_bytes(@buf)
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_protocol_admin(self: @ContractState) {
            assert(get_caller_address() == self.protocol_admin.read(), 'Not protocol admin');
        }

        /// Common transition tail: stamps activation, retires the predecessor's
        /// `is_latest` flag and advances the version. Every mutation ends here.
        fn _publish_registry_transition(
            ref self: ContractState, previous_version: u32, node_count: u32,
        ) {
            let new_version = previous_version + 1;
            let activates_at = get_block_timestamp();

            let mut previous = self.registry_entries.read(previous_version);
            previous.is_latest = false;
            self.registry_entries.write(previous_version, previous);

            self
                .registry_entries
                .write(
                    new_version,
                    RegistryEntry { exists: true, is_latest: true, node_count, activates_at },
                );
            self.registry_version.write(new_version);

            self
                .emit(
                    Event::RegistryAdvanced(
                        RegistryAdvanced {
                            registry_version: new_version, node_count, activates_at,
                        },
                    ),
                );
        }

        /// Plain EC sum of the signers' public keys, ascending bit order,
        /// returned as a curve point so the caller avoids an extra
        /// coordinates → point round-trip. The 256-bit bitmap is walked as two
        /// native `u128` halves to keep each shift on the cheaper width.
        ///
        /// The second return value is `true` when a set bit named no live node:
        /// its slot is past the last slot or a hole, either of which reads as the
        /// zero pair. That is the bitmap's only bound check.
        ///
        /// `None` means a stored coordinate pair was not on the curve, which
        /// registration makes impossible — it is represented rather than
        /// asserted only so that `verify` stays total.
        fn _aggregate_point(
            self: @ContractState, version: u32, signers_bitmap: u256,
        ) -> (Option<Secp256k1Point>, bool) {
            let mut ok = true;
            let mut vacant = false;
            let mut acc: Option<Secp256k1Point> = Option::None;
            acc = self._accumulate_word(version, signers_bitmap.low, 0, acc, ref ok, ref vacant);
            acc = self._accumulate_word(version, signers_bitmap.high, 128, acc, ref ok, ref vacant);
            if !ok {
                return (Option::None, vacant);
            }
            (acc, vacant)
        }

        /// Adds every signer set in one 128-bit half of the bitmap into `acc`.
        /// `base` is the bit offset of the half (0 for low, 128 for high); bit
        /// `base + pos` is stored at index `base + pos + 1`.
        fn _accumulate_word(
            self: @ContractState,
            version: u32,
            mut word: u128,
            base: u32,
            mut acc: Option<Secp256k1Point>,
            ref ok: bool,
            ref vacant: bool,
        ) -> Option<Secp256k1Point> {
            let mut pos: u32 = 0;
            while word != 0 {
                if word % 2 == 1 {
                    let signer_slot = base + pos + 1;
                    let x = self.key_x.read(slot(version, signer_slot));
                    let y = self.key_y.read(slot(version, signer_slot));
                    // `new_point(0, 0)` is accepted as the point at infinity, so a hole
                    // has to be caught before it is parsed.
                    if x == 0 && y == 0 {
                        vacant = true;
                    }
                    match ec::new_point(x, y) {
                        Option::None => { ok = false; },
                        Option::Some(pt) => {
                            acc = match acc {
                                Option::None => Option::Some(pt),
                                Option::Some(a) => Option::Some(ec::add(a, pt)),
                            };
                        },
                    }
                }
                word = word / 2;
                pos += 1;
            }
            acc
        }

        /// The 1-based storage index of the lowest hole in `1..=count`, or `count + 1`
        /// when there is none.
        fn _first_free_slot(self: @ContractState, version: u32, count: u32) -> u32 {
            let mut i: u32 = 1;
            while i <= count {
                if self.key_x.read(slot(version, i)) == 0
                    && self.key_y.read(slot(version, i)) == 0 {
                    break;
                }
                i += 1;
            }
            i
        }

        /// Copies node entries `1..=count` from `from_version` to `to_version`,
        /// preserving the immutability of historical snapshots.
        ///
        /// This is O(count) storage writes per mutation, where the EVM gets away
        /// with a single SSTORE2 blob write. At `MAX_NODES` that is 512 writes
        /// on an admin-only path — a known, accepted cost, not an oversight.
        fn _copy_nodes_forward(
            ref self: ContractState, from_version: u32, to_version: u32, count: u32,
        ) {
            let mut i: u32 = 1;
            while i <= count {
                self.key_x.write(slot(to_version, i), self.key_x.read(slot(from_version, i)));
                self.key_y.write(slot(to_version, i), self.key_y.read(slot(from_version, i)));
                i += 1;
            }
        }

        /// digest = keccak256("MOLPHA_VERIFIER_V1" ‖ contractAddress ‖
        ///                    compressedPubKey), verified with the defensive
        /// Schnorr check.
        ///
        /// Binds the proof to this deployment so a PoP cannot be replayed onto
        /// another chain's verifier. NOTE: the EVM contract hashes
        /// `address(this)` as 20 bytes; here the StarkNet contract address is
        /// hashed as 32 bytes, because a StarkNet address is a felt and does not
        /// fit 20. PoP is registration-only and never part of `verify`, so this
        /// divergence does not affect cross-chain payload verification.
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
