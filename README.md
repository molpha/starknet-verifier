# Molpha StarkNet

StarkNet workspace for the Molpha verifier stack.

This repository contains a Cairo implementation of the Molpha verifier contract and helper scripts for deploying to Starknet Sepolia and managing node registration.

## Repository layout

- `verifier/` - Cairo contract package (`Verifier`) and tests.
- `scripts/` - operational scripts (deployment and `add_node` PoP signer helper).
- `.env.example` - environment variable template for deployment and admin flows.
- `snfoundry.toml` - `sncast` profile/configuration for testnet usage.

## Prerequisites

- [Scarb](https://docs.swmansion.com/scarb/) `2.18+`
- [Starknet Foundry](https://foundry-rs.github.io/starknet-foundry/) (`snforge`, `sncast`) `0.61+`
- Node.js `18+` (required by scripts under `scripts/`)

## Quick start

```bash
cp .env.example .env
scarb build
snforge test
```

For implementation details and parity notes, see `verifier/README.md`.

## Deploy to Starknet Sepolia

1. Import and configure your deployer account in `sncast` (see comments in `snfoundry.toml`).
2. Set `PROTOCOL_ADMIN` in `.env` (copy from `.env.example` if needed).
3. Run:

```bash
./scripts/deploy_testnet.sh
```

Successful deployments are recorded under `deployments/` (gitignored).

## Register a node (`add_node`)

`add_node` requires a secp256k1 private key for PoP generation and must be executed by the configured protocol admin account.

```bash
npm install --prefix scripts
./scripts/add_node.sh
```

You can also pass values directly:

```bash
./scripts/add_node.sh 0xVERIFIER_ADDRESS 0xNODE_PRIVATE_KEY
```

## Environment variables

Use `.env.example` as the source of truth. Main variables:

- Deployment: `PROTOCOL_ADMIN`, `REDUNDANCY_BUFFER`, `SNCAST_PROFILE`, `SNCAST_ACCOUNT`, `STARKNET_RPC_URL`
- Node registration: `VERIFIER_ADDRESS`, `NODE_PRIVATE_KEY`, `COMPRESSED_PUBKEY`

Never commit real secrets (private keys, funded account credentials, API keys).
