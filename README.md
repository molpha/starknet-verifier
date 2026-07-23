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
* Registry versioning
* Node registration
* Node removal
* Proof-of-Possession validation
* Aggregate public key reconstruction
* Payload tampering
* Encoding compatibility
* Cross-chain parity with the EVM verifier

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
export ACCOUNT_ADDRESS=...
export PRIVATE_KEY=...

Deploy to Starknet Sepolia:

./scripts/deploy_testnet.sh

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
