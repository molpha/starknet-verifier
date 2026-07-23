#!/usr/bin/env bash
# Register a validator node on a deployed Molpha Verifier (Starknet).
#
# Signs a Schnorr proof-of-possession for the node's secp256k1 key and invokes
# add_node as the protocol admin.
#
# Prerequisites:
#   - starknet-foundry 0.61+ (sncast)
#   - node.js 18+ and `npm install` in scripts/
#   - sncast account configured (must be protocol_admin)
#
# Usage:
#   cp .env.example .env   # set VERIFIER_ADDRESS, NODE_PRIVATE_KEY, STARKNET_RPC_URL
#   npm install --prefix scripts
#   ./scripts/add_node.sh
#   ./scripts/add_node.sh 0xVERIFIER 0xNODE_PRIVATE_KEY   # overrides .env
#
# Environment / CLI:
#   VERIFIER_ADDRESS    (required) deployed Verifier contract
#   NODE_PRIVATE_KEY    (required) secp256k1 secret key for the node
#   STARKNET_RPC_URL    (required) Starknet RPC endpoint (never commit API keys)
#   COMPRESSED_PUBKEY   (optional) 33-byte compressed pubkey hex
#   SNCAST_PROFILE      (optional) default testnet
#   SNCAST_ACCOUNT      (optional) account name
#   DRY_RUN             (optional) set to 1 to estimate fees only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$ROOT_DIR/.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

if [[ $# -ge 1 ]]; then VERIFIER_ADDRESS="$1"; fi
if [[ $# -ge 2 ]]; then NODE_PRIVATE_KEY="$2"; fi

SNCAST_PROFILE="${SNCAST_PROFILE:-testnet}"
DRY_RUN="${DRY_RUN:-0}"

if ! command -v sncast >/dev/null 2>&1; then
  echo "error: sncast not found. Install starknet-foundry 0.61+." >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "error: node not found (required for PoP signing)." >&2
  exit 1
fi

if [[ ! -d "$SCRIPT_DIR/node_modules" ]]; then
  echo "==> Installing script dependencies..."
  npm install --prefix "$SCRIPT_DIR" --silent
fi

if [[ -z "${VERIFIER_ADDRESS:-}" ]]; then
  echo "error: VERIFIER_ADDRESS is required (deployed Verifier contract)." >&2
  echo "  export VERIFIER_ADDRESS=0x...  or set it in .env" >&2
  exit 1
fi

if [[ -z "${NODE_PRIVATE_KEY:-}" ]]; then
  echo "error: NODE_PRIVATE_KEY is required (secp256k1 secret key for the node)." >&2
  echo "  export NODE_PRIVATE_KEY=0x...  or set it in .env" >&2
  exit 1
fi

if [[ -z "${STARKNET_RPC_URL:-}" ]]; then
  echo "error: STARKNET_RPC_URL is required (Starknet RPC endpoint)." >&2
  echo "  export STARKNET_RPC_URL=https://...  or set it in .env" >&2
  exit 1
fi

if [[ ! "$VERIFIER_ADDRESS" =~ ^0x[0-9a-fA-F]+$ ]]; then
  echo "error: VERIFIER_ADDRESS must be a hex Starknet address." >&2
  exit 1
fi

SNCAST_ARGS=(--profile "$SNCAST_PROFILE" --url "$STARKNET_RPC_URL")
if [[ -n "${SNCAST_ACCOUNT:-}" ]]; then
  SNCAST_ARGS+=(--account "$SNCAST_ACCOUNT")
fi

NODE_ARGS=(
  --verifier "$VERIFIER_ADDRESS"
  --private-key "$NODE_PRIVATE_KEY"
  --json
)
if [[ -n "${COMPRESSED_PUBKEY:-}" ]]; then
  NODE_ARGS+=(--compressed-pubkey "$COMPRESSED_PUBKEY")
fi

echo "==> Building add_node calldata (Schnorr PoP)..."
META="$(node "$SCRIPT_DIR/add_node.mjs" "${NODE_ARGS[@]}")"

COMPRESSED="$(echo "$META" | node -e "const j=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(j.compressed_pubkey)")"
NODE_ID="$(echo "$META" | node -e "const j=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(j.node_id)")"
CALLDATA="$(echo "$META" | node -e "const j=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(j.calldata.join(' '))")"

echo "    verifier:          $VERIFIER_ADDRESS"
echo "    compressed_pubkey: $COMPRESSED"
echo "    node_id:           $NODE_ID"

INVOKE_ARGS=(
  invoke
  --contract-address "$VERIFIER_ADDRESS"
  --function add_node
  --calldata $CALLDATA
)

if [[ "$DRY_RUN" == "1" ]]; then
  INVOKE_ARGS+=(--dry-run)
  echo "==> Dry run: estimating add_node fee..."
else
  echo "==> Invoking add_node on Sepolia..."
fi

OUTPUT="$(sncast "${SNCAST_ARGS[@]}" "${INVOKE_ARGS[@]}")"
echo "$OUTPUT"

if [[ "$DRY_RUN" != "1" ]]; then
  echo ""
  echo "==> Node registered (node_id=$NODE_ID)"
fi
