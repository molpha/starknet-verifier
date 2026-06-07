#!/usr/bin/env node
/**
 * Build calldata for Verifier.add_node: signs a Schnorr proof-of-possession
 * and serializes (compressed_pubkey: ByteArray, pop: SchnorrProof).
 *
 * PoP digest matches verifier/src/verifier.cairo::_verify_pop:
 *   keccak256(POP_DOMAIN ‖ contractAddress_u256_be32 ‖ compressed_pubkey)
 */

import { fileURLToPath } from "node:url";
import { Point, getPublicKey } from "@noble/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3.js";

const { n: Q, p: FIELD_P } = Point.CURVE();
const POP_DOMAIN =
  0x0c067655ca151011944be1779cde5916c870c6e7b5c5db50ef488d63d7d1ff31n;

function parseHex(value, name) {
  const s = value.startsWith("0x") ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]+$/.test(s) || s.length === 0) {
    throw new Error(`${name} must be a hex string`);
  }
  return BigInt(`0x${s}`);
}

function u256BeBytes(v) {
  const buf = new Uint8Array(32);
  let x = BigInt(v);
  for (let i = 31; i >= 0; i--) {
    buf[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return buf;
}

function addressBeBytes(addr) {
  const buf = new Uint8Array(20);
  let x = BigInt(addr);
  for (let i = 19; i >= 0; i--) {
    buf[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return buf;
}

function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function bytesToBigInt(buf) {
  let x = 0n;
  for (const b of buf) x = (x << 8n) + BigInt(b);
  return x;
}

function keccakBytes(data) {
  return bytesToBigInt(keccak_256(data));
}

function mod(n, m) {
  const r = n % m;
  return r >= 0n ? r : r + m;
}

function u256ToFelts(v) {
  const low = v & ((1n << 128n) - 1n);
  const high = v >> 128n;
  return [low.toString(), high.toString()];
}

/** Cairo ByteArray Serde: [data_len, ...words, pending_word, pending_word_len] */
export function serializeByteArray(data) {
  const fullWords = Math.floor(data.length / 31);
  const felts = [String(fullWords)];
  for (let i = 0; i < fullWords; i++) {
    felts.push(bytesToBigInt(data.subarray(i * 31, (i + 1) * 31)).toString());
  }
  const pending = data.subarray(fullWords * 31);
  if (pending.length > 0) {
    felts.push(bytesToBigInt(pending).toString());
    felts.push(String(pending.length));
  } else {
    felts.push("0", "0");
  }
  return felts;
}

function ethAddressFromCoords(x, y) {
  const hash = keccak_256(concat(u256BeBytes(x), u256BeBytes(y)));
  return bytesToBigInt(hash) & ((1n << 160n) - 1n);
}

function ethAddressFromPoint(p) {
  const { x, y } = p.toAffine();
  return ethAddressFromCoords(x, y);
}

function challenge(px, py, message, commitment) {
  const parity = py & 1n;
  const buf = concat(
    u256BeBytes(px),
    Uint8Array.of(Number(parity)),
    u256BeBytes(message),
    addressBeBytes(commitment),
  );
  return keccakBytes(buf) % Q;
}

function verify(px, py, message, signature, commitment) {
  if (signature === 0n || commitment === 0n) return false;
  if (signature >= Q) return false;

  const P = Point.fromAffine({ x: mod(px, FIELD_P), y: mod(py, FIELD_P) });

  const e = challenge(px, py, message, commitment);
  const sG = Point.BASE.multiply(signature);
  const eP = P.multiply(e);
  const t = sG.add(eP.negate());
  return ethAddressFromPoint(t) === commitment;
}

/** Mirrors verifier/tests/e2e.cairo::sign */
export function signPop(px, py, sk, message) {
  for (let attempt = 0n; attempt < 10_000n; attempt++) {
    const kBuf = concat(
      u256BeBytes(message),
      u256BeBytes(px),
      u256BeBytes(py),
      u256BeBytes(attempt),
    );
    const k = (keccakBytes(kBuf) % (Q - 1n)) + 1n;

    const rPoint = Point.BASE.multiply(k);
    const commitment = ethAddressFromPoint(rPoint);
    if (commitment === 0n) continue;

    const e = challenge(px, py, message, commitment);
    const s = mod(k + e * sk, Q);
    if (s === 0n || s >= Q) continue;
    if (verify(px, py, message, s, commitment)) {
      return { signature: s, commitment };
    }
  }
  throw new Error("failed to produce a valid Schnorr PoP signature");
}

export function popDigest(contractAddress, compressed) {
  const buf = concat(
    u256BeBytes(POP_DOMAIN),
    u256BeBytes(parseHex(contractAddress, "contract address")),
    compressed,
  );
  return keccakBytes(buf);
}

export function coordsFromPrivateKey(sk) {
  const point = Point.BASE.multiply(mod(sk, Q));
  const { x, y } = point.toAffine();
  return { px: x, py: y };
}

export function compressedFromPrivateKey(sk) {
  const normalized = mod(sk, Q);
  const skBytes = u256BeBytes(normalized);
  const bytes = getPublicKey(skBytes, true);
  return Uint8Array.from(bytes);
}

export function buildAddNodeCalldata(contractAddress, privateKey, compressedHex) {
  const sk = parseHex(privateKey, "private key");
  const compressed = compressedHex
    ? Uint8Array.from(
        (compressedHex.startsWith("0x") ? compressedHex.slice(2) : compressedHex).match(
          /../g,
        ),
        (b) => parseInt(b, 16),
      )
    : compressedFromPrivateKey(sk);

  if (compressed.length !== 33) {
    throw new Error("compressed pubkey must be 33 bytes");
  }

  const { px, py } = coordsFromPrivateKey(sk);
  const digest = popDigest(contractAddress, compressed);
  const pop = signPop(px, py, sk, digest);

  const calldata = [
    ...serializeByteArray(compressed),
    ...u256ToFelts(pop.signature),
    pop.commitment.toString(),
  ];

  const nodeId = ethAddressFromCoords(px, py);

  return {
    calldata,
    compressed: `0x${Buffer.from(compressed).toString("hex")}`,
    nodeId: `0x${nodeId.toString(16).padStart(40, "0")}`,
    pop,
  };
}

function printUsage() {
  console.error(`Usage: add_node.mjs --verifier <ADDR> --private-key <HEX> [options]

Options:
  --verifier <ADDR>       Deployed Verifier contract address (required)
  --private-key <HEX>     Node secp256k1 secret key (required)
  --compressed-pubkey HEX Optional 33-byte compressed pubkey (derived from key if omitted)
  --calldata-only         Print space-separated felts for sncast --calldata
  --json                  Print JSON with calldata and metadata
`);
}

function main() {
  const args = process.argv.slice(2);
  let verifier;
  let privateKey;
  let compressedPubkey;
  let calldataOnly = false;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--verifier":
        verifier = args[++i];
        break;
      case "--private-key":
        privateKey = args[++i];
        break;
      case "--compressed-pubkey":
        compressedPubkey = args[++i];
        break;
      case "--calldata-only":
        calldataOnly = true;
        break;
      case "--json":
        json = true;
        break;
      case "-h":
      case "--help":
        printUsage();
        process.exit(0);
      default:
        throw new Error(`unknown argument: ${args[i]}`);
    }
  }

  if (!verifier || !privateKey) {
    printUsage();
    process.exit(1);
  }

  const result = buildAddNodeCalldata(verifier, privateKey, compressedPubkey);

  if (json) {
    console.log(
      JSON.stringify(
        {
          verifier,
          compressed_pubkey: result.compressed,
          node_id: result.nodeId,
          pop_signature: `0x${result.pop.signature.toString(16)}`,
          pop_commitment: `0x${result.pop.commitment.toString(16)}`,
          calldata: result.calldata,
        },
        null,
        2,
      ),
    );
  } else if (calldataOnly) {
    console.log(result.calldata.join(" "));
  } else {
    console.log(`compressed_pubkey: ${result.compressed}`);
    console.log(`node_id:           ${result.nodeId}`);
    console.log(`pop.signature:     0x${result.pop.signature.toString(16)}`);
    console.log(`pop.commitment:    0x${result.pop.commitment.toString(16)}`);
    console.log(`calldata (${result.calldata.length} felts):`);
    console.log(result.calldata.join(" "));
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (err) {
    console.error(`error: ${err.message}`);
    process.exit(1);
  }
}
