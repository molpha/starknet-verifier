#!/usr/bin/env node
/**
 * Regenerates `verifier/tests/fixtures.cairo` from the Molpha EVM golden
 * vectors, so the Cairo suite is checked against the same bytes the Solidity
 * and Rust suites are, and nobody hand-transcribes a u256 limb.
 *
 * Sources (paths relative to this repo's parent directory):
 *   molpha-core-contracts/test/fixtures/fixture.json      12-node round + keys
 *   molpha-core-contracts/test/fixtures/attestation.json  end-to-end + codes
 *
 * Usage: node scripts/gen_fixtures.mjs [path/to/molpha-core-contracts]
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { Point } from "@noble/secp256k1";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..");
const core = process.argv[2] ?? path.resolve(repo, "..", "molpha-core-contracts");

const MESSAGE_PREFIX = keccak_256(Buffer.from("MOLPHA_MESSAGE_V1"));
const SELECTION_SEED_PREFIX = keccak_256(Buffer.from("MOLPHA_SELECTION_V1"));
const SELECTION_DOMAIN = keccak_256(Buffer.from("MOLPHA_SELECTION_DERIVE"));

const strip = (s) => String(s).replace(/^0x/i, "");
const hex = (s) => Uint8Array.from(Buffer.from(strip(s), "hex"));
const u32be = (v) => Uint8Array.from([(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]);
const u8be = (v) => Uint8Array.from([Number(v) & 255]);
const ubig = (v, n) => {
  const b = Buffer.alloc(n);
  let x = BigInt(v);
  for (let i = n - 1; i >= 0; i--) { b[i] = Number(x & 255n); x >>= 8n; }
  return Uint8Array.from(b);
};
const cat = (...a) => {
  const t = new Uint8Array(a.reduce((s, x) => s + x.length, 0));
  let o = 0;
  for (const x of a) { t.set(x, o); o += x.length; }
  return t;
};
const big = (v) => (typeof v === "string" && /^0x/i.test(v) ? BigInt(v) : BigInt(v));

/** Cairo `u256 { high, low }` literal. */
const u256lit = (v) => {
  const x = BigInt(v);
  const high = (x >> 128n).toString(16).padStart(32, "0");
  const low = (x & ((1n << 128n) - 1n)).toString(16).padStart(32, "0");
  return `u256 { high: 0x${high}, low: 0x${low} }`;
};

function messageHash(p, signersBitmap) {
  return cat(
    MESSAGE_PREFIX,
    hex(p.value), hex(p.sourceId),
    u32be(p.registryVersion), u8be(p.signaturesRequired),
    ubig(p.canonicalTimestamp, 8), ubig(signersBitmap, 32),
  );
}

function selectionSeed(p) {
  return keccak_256(cat(
    SELECTION_SEED_PREFIX, hex(p.sourceId),
    u32be(p.registryVersion), ubig(p.canonicalTimestamp, 8),
  ));
}

function sampleWithoutReplacement(seed, n, g) {
  const limit = (0xFFFFFFFFn / BigInt(n)) * BigInt(n);
  let bm = 0n, selected = 0, counter = 0n;
  while (selected < g) {
    const d = Buffer.from(keccak_256(cat(seed, SELECTION_DOMAIN, ubig(counter, 32))));
    counter++;
    for (let w = 0; w < 8 && selected < g; w++) {
      const draw = BigInt(d.readUInt32BE(w * 4));
      if (draw < limit) {
        const bit = 1n << (draw % BigInt(n));
        if ((bm & bit) === 0n) { bm |= bit; selected++; }
      }
    }
  }
  return bm;
}

function deriveSelection(seed, n, g) {
  const full = (1n << BigInt(n)) - 1n;
  if (g === 0) return 0n;
  if (g === n) return full;
  if (g > Math.floor(n / 2)) return full ^ sampleWithoutReplacement(seed, n, n - g);
  return sampleWithoutReplacement(seed, n, g);
}

/** Plain EC sum of the pubkeys named by `bitmap` (bit i = node i). */
function aggregate(pubkeys, bitmap) {
  let acc = null;
  for (let i = 0; i < pubkeys.length; i++) {
    if ((BigInt(bitmap) >> BigInt(i)) & 1n) {
      const p = Point.fromHex(strip(pubkeys[i]));
      acc = acc === null ? p : acc.add(p);
    }
  }
  if (acc === null) throw new Error("empty signer set");
  const a = acc.toAffine();
  return [a.x, a.y];
}

const fixture = JSON.parse(fs.readFileSync(path.join(core, "test/fixtures/fixture.json"), "utf8"));
const attest = JSON.parse(fs.readFileSync(path.join(core, "test/fixtures/attestation.json"), "utf8"));

const d = fixture.dataUpdate;
const s = fixture.schnorrSignature;
const buffer = attest.redundancyBuffer;
const nodeCount = fixture.nodePubkeys.length;

// Self-checks: if any of these fail, the EVM fixture moved and the Cairo port
// must be re-examined, not the expectations quietly updated.
const msg = keccak_256(messageHash(d, s.signersBitmap));
const msgHex = "0x" + Buffer.from(msg).toString("hex");
if (msgHex !== fixture.messageHash.toLowerCase()) {
  throw new Error(`messageHash mismatch: computed ${msgHex}, fixture ${fixture.messageHash}`);
}
const seed = selectionSeed(d);
const groupSize = Math.min(d.signaturesRequired + buffer, nodeCount);
const selection = deriveSelection(seed, nodeCount, groupSize);
if ((BigInt(s.signersBitmap) & ~selection & ((1n << 256n) - 1n)) !== 0n) {
  throw new Error("fixture signers are not a subset of the derived selection");
}
const [aggX, aggY] = aggregate(fixture.nodePubkeys, s.signersBitmap);

const nodes = fixture.nodePubkeys.map((pk, i) => {
  const c = strip(pk);
  return { prefix: parseInt(c.slice(0, 2), 16), x: BigInt("0x" + c.slice(2)), sk: BigInt(fixture.secretKeys[i]) };
});

const cases = attest.cases.map((c) => {
  const p = c.attestation.payload;
  const sg = c.attestation.signature;
  const h = "0x" + Buffer.from(keccak_256(messageHash(p, sg.signersBitmap))).toString("hex");
  if (h !== c.expected.messageHash.toLowerCase()) {
    throw new Error(`${c.name}: messageHash mismatch`);
  }
  const sel = deriveSelection(selectionSeed(p), nodeCount, Math.min(p.signaturesRequired + buffer, nodeCount));
  if ((BigInt(sg.signersBitmap) & ~sel & ((1n << 256n) - 1n)) !== 0n) {
    throw new Error(`${c.name}: signers are not a subset of the derived selection`);
  }
  return { ...c, payload: p, sig: sg };
});

const out = [];
const w = (l = "") => out.push(l);

w("//! Golden fixtures shared by the parity and end-to-end tests.");
w("//!");
w("//! GENERATED by `scripts/gen_fixtures.mjs` — do not edit by hand. Values come");
w("//! from the Molpha EVM golden vectors");
w("//! (`molpha-core-contracts/test/fixtures/{fixture,attestation}.json`), which the");
w("//! Solidity and Rust suites assert against too. Regenerating is how a");
w("//! cross-VM change reaches this file; editing a constant to make a test pass");
w("//! would hide exactly the drift these fixtures exist to catch.");
w();
w("use verifier::byte_utils::append_u256_be;");
w();
w(`// ---- ${nodeCount}-node round (fixture.json) ----`);
w(`pub const REG_VERSION: u32 = ${d.registryVersion};`);
w(`pub const SIGS_REQUIRED: u8 = ${d.signaturesRequired};`);
w(`pub const REDUNDANCY_BUFFER: u32 = ${buffer};`);
w(`pub const NODE_COUNT: u32 = ${nodeCount};`);
w(`pub const TIMESTAMP: u64 = ${d.canonicalTimestamp};`);
w(`pub const SIGNERS_BITMAP: u256 = ${s.signersBitmap};`);
w(`pub const COMMITMENT: felt252 = 0x${strip(s.commitment).toLowerCase()};`);
w();
for (const [name, val] of [
  ["SOURCE_ID", BigInt(d.sourceId)], ["VALUE", BigInt(d.value)],
  ["SIGNATURE", BigInt(s.signature)], ["MESSAGE", BigInt(fixture.messageHash)],
  ["SELECTION_SEED", BigInt("0x" + Buffer.from(seed).toString("hex"))],
  ["AGG_X", aggX], ["AGG_Y", aggY],
]) {
  w(`pub fn ${name}() -> u256 {`);
  w(`    ${u256lit(val)}`);
  w("}");
}
w();
w(`/// (prefix, x, secret_key) for each of the ${nodeCount} fixture nodes, in index order.`);
w("pub fn fixture_nodes() -> Array<(u8, u256, u256)> {");
w("    array![");
for (const n of nodes) {
  w("        (");
  w(`            ${n.prefix},`);
  w(`            ${u256lit(n.x)},`);
  w(`            ${u256lit(n.sk)},`);
  w("        ),");
}
w("    ]");
w("}");
w();
w("/// Builds a 33-byte compressed pubkey ByteArray from prefix + x.");
w("pub fn compressed(prefix: u8, x: u256) -> ByteArray {");
w("    let mut b: ByteArray = \"\";");
w("    b.append_byte(prefix);");
w("    append_u256_be(ref b, x);");
w("    b");
w("}");
w();
w("// ---- end-to-end cases (attestation.json), same key set ----");
w("//");
w("// Each carries the code the EVM verifier returns, so the Cairo port is checked");
w("// on the `(success, code)` pair rather than just acceptance.");
cases.forEach((c, i) => {
  const n = i + 1;
  w();
  w(`/// \`${c.name}\` (kind ${c.kind}): expects (${c.expected.verifyOk}, ${c.expected.verifyCode}).`);
  w(`pub const CASE${n}_REG_VERSION: u32 = ${c.payload.registryVersion};`);
  w(`pub const CASE${n}_SIGS_REQUIRED: u8 = ${c.payload.signaturesRequired};`);
  w(`pub const CASE${n}_TIMESTAMP: u64 = ${c.payload.canonicalTimestamp};`);
  w(`pub const CASE${n}_SIGNERS_BITMAP: u256 = ${c.sig.signersBitmap};`);
  w(`pub const CASE${n}_COMMITMENT: felt252 = 0x${strip(c.sig.commitment).toLowerCase()};`);
  w(`pub const CASE${n}_EXPECTED_OK: bool = ${c.expected.verifyOk};`);
  w(`pub const CASE${n}_EXPECTED_CODE: u8 = ${c.expected.verifyCode};`);
  for (const [name, val] of [
    [`CASE${n}_SOURCE_ID`, BigInt(c.payload.sourceId)],
    [`CASE${n}_VALUE`, BigInt(c.payload.value)],
    [`CASE${n}_SIGNATURE`, BigInt(c.sig.signature)],
    [`CASE${n}_MESSAGE`, BigInt(c.expected.messageHash)],
  ]) {
    w(`pub fn ${name}() -> u256 {`);
    w(`    ${u256lit(val)}`);
    w("}");
  }
});

const target = path.join(repo, "verifier/tests/fixtures.cairo");
fs.writeFileSync(target, out.join("\n") + "\n");
console.log(`wrote ${target}`);
console.log(`  ${nodeCount} nodes, registryVersion ${d.registryVersion}, buffer ${buffer}`);
console.log(`  messageHash    ${msgHex}`);
console.log(`  selectionSeed  0x${Buffer.from(seed).toString("hex")}`);
console.log(`  selection      ${selection} (group ${groupSize}/${nodeCount}), signers ${s.signersBitmap}`);
console.log(`  aggregate      x=0x${aggX.toString(16)}`);
console.log(`  ${cases.length} end-to-end case(s): ${cases.map((c) => c.name).join(", ")}`);
