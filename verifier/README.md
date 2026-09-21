# Molpha StarkNet Verifier

A faithful Cairo port of the Molpha EVM `Verifier.sol`. It verifies the **same**
Molpha PoP-Schnorr aggregate signatures over secp256k1, so a payload signed once
by the Molpha node network verifies on both EVM and StarkNet.

The Molpha signed message deliberately omits `chainId`, which is what makes one
signature valid on every chain. This contract reproduces the EVM verification
pipeline exactly:

```
selectionSeed   = keccak256("MOLPHA_SELECTION_V1" ‖ sourceId ‖ u32(registryVersion)
                            ‖ u64(canonicalTimestamp))                          76 bytes
selectionBitmap = deriveWithoutReplacement(selectionSeed, nodeCount, groupSize)
message         = keccak256("MOLPHA_MESSAGE_V1" ‖ value ‖ sourceId ‖ u32(registryVersion)
                            ‖ u8(signaturesRequired) ‖ u64(canonicalTimestamp)
                            ‖ signersBitmap)                                   141 bytes
X_coalition     = Σ Xᵢ   for each signer i in signersBitmap   (plain EC sum)
challenge e     = keccak256(Pₓ ‖ Pₚ ‖ message ‖ commitment) mod Q               85 bytes
accept iff        ethAddress(s·G − e·X_coalition) == commitment
```

The message field order and the narrow widths (`u32` / `u8` / `u64`, not padded
words) are load bearing. They are shared with `VerifierLib.constructMessage`,
the Rust verifier's `compute_message_hash` and the Go node client's
`buildMessage`; changing any of them breaks every chain at once.

The EVM library implements the final check with the Chronicle/Scribe
`ecrecover` trick (which recovers exactly the point `s·G − e·P`). StarkNet has
native secp256k1 syscalls, so this port computes `s·G − e·P` directly and
compares its Ethereum address to the commitment — mathematically identical, no
`ecrecover` needed.

## Source mapping

| EVM (`molpha-core-contracts/src`) | Cairo (`src`) |
|---|---|
| `Verifier.sol` | `verifier.cairo` (the `Verifier` contract) |
| `libs/VerifyCodes.sol` | `verify_codes.cairo` |
| `interfaces/IVerifier.sol` | `interface.cairo` |
| `libs/LibSchnorr.sol` | `schnorr.cairo` |
| `libs/LibSecp256k1.sol` | `secp256k1_utils.cairo` (native syscalls + helpers) |
| `libs/NodeGroupBitmapLib.sol` | `node_group_bitmap.cairo` |
| `libs/BitmapLib.sol` | `bitmap.cairo` |
| SSTORE2 pubkey blob + `PubkeyBlobLib.sol` | per-`(version, index)` storage maps in `verifier.cairo` |
| `abi.encodePacked` + `keccak256` | `byte_utils.cairo` |

### Storage model

The EVM contract keeps one immutable SSTORE2 blob per registry version. This
port mirrors that with per-`(version, index)` coordinate maps, index 0 holding
the running plain-sum aggregate key and indices `1..=nodeCount` the nodes. Every
`add_node` / `remove_node` / `set_redundancy_buffer` creates a new immutable
version, copying the prior set forward, so historical rounds stay permanently
verifiable — exactly the EVM guarantee.

The internal `+1` offset is fully compensated: the k-th registered node lands at
storage index `k + 1`, and bit `k` of `signersBitmap` reads index `k + 1`. Bit
`i` therefore names the same node as blob element `i` on EVM. The bitmap itself
is 0-based on every chain.

Each version also carries its own `redundancy_buffer`, `activates_at` and
`is_latest`. The buffer is versioned rather than mutable because it feeds
`group_size`, which feeds the derived selection bitmap a signature is checked
against — mutating it in place would retroactively invalidate payloads that
already verify. `activates_at` and `is_latest` bound the window a version is
usable in: historical *rounds* stay verifiable forever, but historical
*versions* stop being usable 60 seconds after their successor activates, so the
effective trust set is not the union of every node set that ever existed.

### `verify` never reverts

`verify(attestation, max_age) -> (bool, u8)` is a total function; every failure
is a code, not a panic. This matters because consumers call it through a
contract syscall, where a panic aborts the caller's whole transaction — over
conditions like a registry mirror lagging one version, which are transient and
expected. The codes are shared with the EVM and Solana verifiers and are
append-only.

Keeping it total is a real constraint on the implementation: `derive` returns an
`Option` rather than asserting, oversized commitments are rejected before they
reach `append_word`, and the aggregate-at-infinity case is a returned code. The
`curve_assumptions.cairo` tests pin the StarkNet syscall behaviour that makes
the last one possible without a pre-check.

### The one deliberate divergence

`add_node`'s proof-of-possession domain separator hashes the contract address.
The EVM hashes `address(this)` (20 bytes); StarkNet hashes
`get_contract_address()` (32 bytes). PoP is checked **only at registration** and
is never part of `verify`, so this does not affect cross-chain payload
verification — a node simply produces a separate PoP per chain at registration.

## Cross-chain parity tests

`tests/` drives the port with golden vectors produced by the Molpha EVM stack.
`tests/fixtures.cairo` is **generated** from
`molpha-core-contracts/test/fixtures/{fixture,attestation}.json` by
`../scripts/gen_fixtures.mjs`, so the Cairo suite is checked against the same
bytes the Solidity and Rust suites are, and the generator re-derives the message
hash and selection subset as a self-check before writing. Regenerate with
`node scripts/gen_fixtures.mjs` from the repo root.

- `curve_assumptions.cairo` — pins the secp256k1 syscall behaviour at the point
  at infinity, which `verify`'s totality depends on.
- `parity.cairo` — keccak/encoding parity, field width and order sensitivity,
  node-selection parity, and acceptance of unmodified EVM-produced signatures.
- `e2e.cairo` — deploys the contract, registers the fixture nodes through the
  real `add_node` path (each gated by a freshly produced PoP), then drives
  `verify` end-to-end: the EVM golden payloads and both `attestation.json`
  cases with their expected reason codes, every reachable failure code,
  adversarial calldata, freshness windows, and registry activation/expiry.

## Build & test

```bash
scarb build      # compiles the Verifier contract class
snforge test     # runs curve, parity, e2e, and benchmark tests
scarb run bench  # gas benchmarks (see tests/benchmarks.cairo)
```

### Gas benchmarks

`tests/benchmarks.cairo` measures L2 gas per contract selector using snforge's
`--gas-report`. Each benchmark test calls the function under measurement once
(after setup), so the report shows min / max / avg across scenarios:

```bash
scarb run bench
# consolidated table (all selectors in one test):
snforge test bench_gas_snapshot --gas-report
# verify cost vs signer count (3 / 5 / 9 / 12 / 18):
snforge test bench_verify_signer_scaling --gas-report
# per-scenario breakdown:
snforge test benchmarks --gas-report
```

Add `--trace-components gas` to see per-test call traces. Current numbers live
in the repo README, so there is one place to update when they move.

Requires Scarb 2.18 and `snforge` 0.61 (the toolchain this was developed
against).
