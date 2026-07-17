# Molpha StarkNet Verifier

A faithful Cairo port of the Molpha EVM `Verifier.sol`. It verifies the **same**
Molpha PoP-Schnorr aggregate signatures over secp256k1, so a payload signed once
by the Molpha node network verifies on both EVM and StarkNet.

The Molpha signed message deliberately omits `chainId`, which is what makes one
signature valid on every chain. This contract reproduces the EVM verification
pipeline exactly:

```
selectionSeed   = keccak256("MOLPHA_SELECTION_V1" ‖ feedId ‖ registryVersion ‖ canonicalTimestamp)
selectionBitmap = deriveWithoutReplacement(selectionSeed, nodeCount, groupSize)
message         = keccak256("MOLPHA_MESSAGE_V1" ‖ feedId ‖ registryVersion ‖
                            signaturesRequired ‖ signersBitmap ‖ value ‖ canonicalTimestamp)
X_coalition     = Σ Xᵢ   for each signer i in signersBitmap   (plain EC sum)
challenge e     = keccak256(Pₓ ‖ Pₚ ‖ message ‖ commitment) mod Q
accept iff        ethAddress(s·G − e·X_coalition) == commitment
```

The EVM library implements the final check with the Chronicle/Scribe
`ecrecover` trick (which recovers exactly the point `s·G − e·P`). StarkNet has
native secp256k1 syscalls, so this port computes `s·G − e·P` directly and
compares its Ethereum address to the commitment — mathematically identical, no
`ecrecover` needed.

## Source mapping

| EVM (`molpha-core-contracts/src`) | Cairo (`src`) |
|---|---|
| `Verifier.sol` | `verifier.cairo` (the `Verifier` contract) |
| `interfaces/IVerifier.sol` | `interface.cairo` |
| `libs/LibSchnorr.sol` | `schnorr.cairo` |
| `libs/LibSecp256k1.sol` | `secp256k1_utils.cairo` (native syscalls + helpers) |
| `libs/NodeGroupBitmapLib.sol` | `node_group_bitmap.cairo` |
| `libs/BitmapLib.sol` | `bitmap.cairo` |
| SSTORE2 pubkey blob + `PubkeyBlobLib.sol` | per-`(version, index)` storage maps in `verifier.cairo` |
| `abi.encodePacked` + `keccak256` | `byte_utils.cairo` |

### Storage model

The EVM contract keeps one immutable SSTORE2 blob per registry version, index 0
holding the running plain-sum aggregate key and indices `1..=nodeCount` the
nodes. This port mirrors that with per-`(version, index)` coordinate maps: each
`add_node` / `remove_node` creates a new immutable version (copying the prior
set forward), so historical rounds stay permanently verifiable — exactly the EVM
guarantee.

### The one deliberate divergence

`add_node`'s proof-of-possession domain separator hashes the contract address.
The EVM hashes `address(this)` (20 bytes); StarkNet hashes
`get_contract_address()` (32 bytes). PoP is checked **only at registration** and
is never part of `verify`, so this does not affect cross-chain payload
verification — a node simply produces a separate PoP per chain at registration.

## Cross-chain parity tests

`tests/` drives the port with golden vectors produced by the Molpha EVM stack
(`molpha-core-contracts/test/fixtures/fixture.json` and the 8-node compat
fixture), independently reproduced with a from-scratch secp256k1 reference:

- `parity.cairo` — keccak/encoding parity, node-selection parity, and
  acceptance of unmodified EVM-produced signatures (10- and 8-signer fixtures).
- `e2e.cairo` — deploys the contract, registers all 10 fixture nodes through the
  real `add_node` path (each gated by a freshly produced PoP), then verifies the
  unmodified EVM fixture payload end-to-end; plus a `remove_node` check.

## Build & test

```bash
scarb build      # compiles the Verifier contract class
snforge test     # runs parity, e2e, and benchmark tests (26 tests)
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

Add `--trace-components gas` to see per-test call traces. Baseline numbers are
documented in the module header of `tests/benchmarks.cairo`.

Requires Scarb 2.18 and `snforge` 0.61 (the toolchain this was developed
against).
