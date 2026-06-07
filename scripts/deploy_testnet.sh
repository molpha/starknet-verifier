#!/usr/bin/env bash
# Deploy the Molpha Verifier contract to Starknet Sepolia testnet.
#
# Prerequisites:
#   - scarb 2.18+
#   - starknet-foundry 0.61+ (sncast)
#   - A funded Sepolia account imported into sncast
#
# Setup (once):
#   sncast account import \
#     --network sepolia \
#     --name deployer \
#     --address 0xYOUR_ADDRESS \
#     --type oz
#   # Then uncomment `account` / `keystore` in snfoundry.toml, or export SNCAST_ACCOUNT.
#
# Usage:
#   cp .env.example .env   # set PROTOCOL_ADMIN
#   ./scripts/deploy_testnet.sh
#
# Environment:
#   PROTOCOL_ADMIN   (required) ContractAddress for protocol_admin constructor arg
#   REDUNDANCY_BUFFER (optional) u256 redundancy buffer, default 2
#   SNCAST_PROFILE   (optional) snfoundry profile, default testnet
#   SNCAST_ACCOUNT   (optional) account name, overrides snfoundry.toml
#   DRY_RUN          (optional) set to 1 to estimate fees without sending txs
#   DEPLOY_SALT      (optional) felt salt for deterministic address (uses --unique if unset)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$ROOT_DIR/.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

SNCAST_PROFILE="${SNCAST_PROFILE:-testnet}"
REDUNDANCY_BUFFER="${REDUNDANCY_BUFFER:-2}"
DRY_RUN="${DRY_RUN:-0}"

if ! command -v sncast >/dev/null 2>&1; then
  echo "error: sncast not found. Install starknet-foundry 0.61+:" >&2
  echo "  curl -L https://raw.githubusercontent.com/foundry-rs/starknet-foundry/master/scripts/install.sh | sh" >&2
  exit 1
fi

if ! command -v scarb >/dev/null 2>&1; then
  echo "error: scarb not found." >&2
  exit 1
fi

if [[ -z "${PROTOCOL_ADMIN:-}" ]]; then
  echo "error: PROTOCOL_ADMIN is required (Starknet address for protocol_admin)." >&2
  echo "  export PROTOCOL_ADMIN=0x...  or set it in .env" >&2
  exit 1
fi

if [[ ! "$PROTOCOL_ADMIN" =~ ^0x[0-9a-fA-F]+$ ]]; then
  echo "error: PROTOCOL_ADMIN must be a hex Starknet address (0x...)." >&2
  exit 1
fi

if [[ ! "$REDUNDANCY_BUFFER" =~ ^[0-9]+$ ]]; then
  echo "error: REDUNDANCY_BUFFER must be a non-negative integer." >&2
  exit 1
fi

SNCAST_ARGS=(--profile "$SNCAST_PROFILE")
if [[ -n "${STARKNET_RPC_URL:-}" ]]; then
  SNCAST_ARGS+=(--url "$STARKNET_RPC_URL")
fi
if [[ -n "${SNCAST_ACCOUNT:-}" ]]; then
  SNCAST_ARGS+=(--account "$SNCAST_ACCOUNT")
fi

# u256 is serialized as (low, high) felts. Buffer fits in low for typical values.
BUFFER_LOW="$REDUNDANCY_BUFFER"
BUFFER_HIGH="0"

echo "==> Building Verifier (release)..."
cd "$ROOT_DIR"
scarb --profile release build --package verifier

DEPLOY_ARGS=(
  deploy
  --package verifier
  --contract-name Verifier
  --constructor-calldata "$PROTOCOL_ADMIN" "$BUFFER_LOW" "$BUFFER_HIGH"
)

if [[ -n "${DEPLOY_SALT:-}" ]]; then
  DEPLOY_ARGS+=(--salt "$DEPLOY_SALT")
else
  DEPLOY_ARGS+=(--unique)
fi

if [[ "$DRY_RUN" == "1" ]]; then
  DEPLOY_ARGS+=(--dry-run)
  echo "==> Dry run: estimating declare + deploy fees on Sepolia..."
else
  echo "==> Declaring and deploying Verifier to Sepolia..."
  echo "    protocol_admin:    $PROTOCOL_ADMIN"
  echo "    redundancy_buffer: $REDUNDANCY_BUFFER"
fi

OUTPUT="$(sncast "${SNCAST_ARGS[@]}" "${DEPLOY_ARGS[@]}")"
echo "$OUTPUT"

if [[ "$DRY_RUN" != "1" ]]; then
  DEPLOYMENTS_DIR="$ROOT_DIR/deployments"
  mkdir -p "$DEPLOYMENTS_DIR"
  STAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
  OUT_FILE="$DEPLOYMENTS_DIR/sepolia-${STAMP}.txt"
  {
    echo "network=sepolia"
    echo "profile=$SNCAST_PROFILE"
    echo "protocol_admin=$PROTOCOL_ADMIN"
    echo "redundancy_buffer=$REDUNDANCY_BUFFER"
    echo ""
    echo "$OUTPUT"
  } >"$OUT_FILE"
  echo ""
  echo "==> Deployment record saved to $OUT_FILE"
fi
