Molpha Starknet Verifier

Verify threshold-signed external data on Starknet using the same payload accepted by Molpha’s EVM and Solana verifiers.

The Molpha Starknet Verifier is the Cairo implementation of Molpha’s verification library. It allows Starknet applications to verify external data that has been independently fetched and threshold-signed by the Molpha network—without bridges, relayers, or Starknet-specific oracle infrastructure.

One signature. Every chain.

⸻

Status

Brebeneskul Testnet

This repository is under active development for the Brebeneskul testnet release.

	
Network	Starknet Sepolia
Audit	Not yet audited
Production Ready	No
Compatibility	EVM • Solana • Starknet

⸻

Why Molpha?

Most oracle networks operate separate infrastructure for every blockchain they support.

Molpha takes a different approach.

Data is fetched once by independent verifier nodes, threshold-signed into a common payload, and then verified natively on every supported virtual machine.

The Starknet verifier is one piece of that architecture.

                HTTP / API
                    │
                    ▼
         Molpha Verifier Network
      (independent verification)
                    │
                    ▼
       Threshold-signed payload
            ┌────────┼────────┐
            ▼        ▼        ▼
          EVM     Solana   Starknet

⸻

Features

* Native Cairo implementation
* Cross-chain compatible payload format
* Threshold Schnorr signature verification
* Historical registry versioning
* Deterministic signer selection
* Aggregate public key reconstruction
* Proof-of-Possession (PoP) node registration
* Stateless verification API

⸻

Design goals

The verifier is designed around a small set of principles:

* Cross-chain consistency — identical verification logic across supported VMs.
* Deterministic execution — identical payloads produce identical results everywhere.
* Historical correctness — previously signed payloads remain verifiable forever.
* Minimal integration surface — applications only need to verify a signed payload.
* No bridge assumptions — verification happens entirely on Starknet.

⸻

Verification flow

1. Molpha verifier nodes independently fetch external data.
2. A threshold of nodes signs the canonical payload.
3. The payload is submitted to Starknet.
4. The verifier reconstructs the aggregate public key.
5. The Schnorr signature is verified.
6. Consumer contracts trust the payload if verification succeeds.

⸻

Signed payload

Every verifier reconstructs the same keccak256 preimage from the same calldata.
The field order and the narrow integer widths are load bearing — a `u32`
`signaturesRequired`, or `value` in any position but the first, produces a
perfectly well-formed digest that simply never matches the one the nodes signed.

message = keccak256(
    keccak256("MOLPHA_MESSAGE_V1")   32 bytes
    value                            32
    sourceId                         32
    registryVersion       uint32 BE   4
    signaturesRequired    uint8        1
    canonicalTimestamp    uint64 BE    8
    signersBitmap         uint256 BE  32
)                                   = 141 bytes

`chainId` is deliberately absent: one signing ceremony produces one payload that
verifies everywhere. `signersBitmap` is 0-based — bit `i` is the `i`-th node
registered in that registry version.

⸻

Verification result

verify(attestation, max_age) -> (success, code)

`verify` is a total function. It never reverts, for any calldata, so a consumer
batching several payloads cannot lose all of them to one malformed input, and a
registry mirror that lags by a version reports that fact instead of aborting the
caller's transaction. The codes are shared with the EVM and Solana verifiers and
are append-only — never renumber them.

Code	Meaning
0	OK
2	Unknown registry version
3	Malformed input
4	Registry version not yet active at this timestamp
5	Registry version expired (superseded, past the 60s grace window)
7	Signer set is not within the round's derived selection group
8	Aggregate public key is the point at infinity
9	Schnorr signature invalid
10	Payload older than the caller's `max_age`

Codes 1 and 6 are reserved for mechanisms this implementation does not have; they
exist so the numbering can never shift under them.

`max_age` of `0` disables the freshness check entirely. That is not a neutral
default: a stateless verifier accepts a correctly signed payload forever, so
replay and ordering policy belong to the consuming contract.

⸻

Cross-chain compatibility

Unlike traditional oracle deployments, Molpha does not require a separate oracle network for every execution environment.

The same threshold-signed payload verifies natively across every supported verifier implementation.

Chain	Status
Starknet	✅
EVM	✅
Solana	✅

This enables developers to reuse the same verification model regardless of execution environment.

⸻

Historical registry versioning

Node membership changes never invalidate existing signatures.

Every registry update creates a new immutable registry version while preserving all previous public keys.

Each signed payload references the registry version it was produced against, allowing historical payloads to remain verifiable indefinitely.

⸻

Running locally

Build the contracts:

scarb build

Run the test suite:

snforge test

⸻

Test coverage

The repository includes tests for:

* Threshold signature verification
* Registry versioning, activation and expiry
* Node registration and lifecycle status
* Node removal with an index witness
* Proof-of-Possession validation
* Aggregate public key reconstruction
* Payload tampering
* Message and selection-seed encoding, including field width and order sensitivity
* Reason-code parity with the EVM verifier
* Totality: `verify` returns a code rather than panicking, on any calldata
* Cross-chain parity against the EVM golden vectors

The golden fixtures in `verifier/tests/fixtures.cairo` are generated from the EVM
verifier's own test vectors by `scripts/gen_fixtures.mjs`, so the Cairo suite is
checked against the same bytes the Solidity and Rust suites are. Regenerate with:

node scripts/gen_fixtures.mjs

⸻

Benchmarks

L2 gas measured with snforge 0.61 (`snforge test benchmarks --gas-report`).

Baseline fixture: 12 nodes, redundancy_buffer=2, signatures_required=5, 7 signers in bitmap.

Operation	L2 gas
verify (success)	~25,063,482
verify (tampered)	~25,063,582
add_node (first)	~23,478,776
add_node (12th)	~26,936,856
remove_node	~7,536,244
set_redundancy_buffer	~7,700,000
get_total_nodes	~128,620
get_aggregate_key	~115,980

`add_node`, `remove_node` and `set_redundancy_buffer` each publish a new registry version and copy the previous key set forward, so their cost grows with registry size. That is the price of keeping every historical snapshot immutable.

Verify cost vs signer count (18-node registry):

Signers	L2 gas	group_size
3	24,356,212	5
5	24,804,224	5
9	27,205,437	9
12	26,273,794	12
18	25,566,201	18

Cost is not strictly linear in signer count: signer selection uses different algorithms depending on group size relative to the registry, while aggregation and Schnorr verification dominate overall cost.

Re-run from `verifier/`:

scarb run bench
snforge test bench_gas_snapshot --gas-report
snforge test bench_verify_signer_scaling --gas-report

⸻

Benchmarks

L2 gas measured with snforge 0.61 (`snforge test benchmarks --gas-report`).

Baseline fixture: 10 nodes, redundancy_buffer=2, signatures_required=3, 5 signers in bitmap.

Operation	L2 gas
verify (success)	~24,711,400
verify (tampered)	~24,711,500
add_node (first)	~22,751,716
add_node (10th)	~25,626,976
remove_node	~5,068,667
get_total_nodes	~48,770
get_aggregate_key	~115,980

Verify cost vs signer count (18-node registry):

Signers	L2 gas	group_size
3	24,469,138	5
5	24,871,970	5
9	27,487,149	9
12	26,560,466	12
18	25,540,671	18

Cost is not strictly linear in signer count: signer selection uses different algorithms depending on group size relative to the registry, while aggregation and Schnorr verification dominate overall cost.

Re-run from `verifier/`:

scarb run bench
snforge test bench_gas_snapshot --gas-report
snforge test bench_verify_signer_scaling --gas-report

⸻

Deployment

Configure your environment:

export STARKNET_RPC_URL=...
export PROTOCOL_ADMIN=...          # constructor admin address
export REDUNDANCY_BUFFER=2         # optional, 0..256, default 2

The deploying account comes from your sncast configuration (`snfoundry.toml`),
not from environment variables.

Deploy to Starknet Sepolia:

./scripts/deploy_testnet.sh

Register a node (derives the compressed key, builds the proof-of-possession, and
invokes `add_node`):

./scripts/add_node.sh

⸻

Security

This implementation has not been independently audited.

It is intended for development, testing, and evaluation on the Brebeneskul testnet.

Please report security vulnerabilities privately before public disclosure. See SECURITY.md.

⸻

Related repositories

* Molpha Protocol
* Molpha EVM Verifier
* Molpha Solana Verifier
* Molpha SDK

⸻

License

Apache License 2.0
