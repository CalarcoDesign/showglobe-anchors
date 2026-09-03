#!/usr/bin/env node
// The Showglobe anchoring verifier (Packet 14). The product of the
// packet: given a canonical log dump, one day's proof file, and the
// operator's published public key, it recomputes the day's Merkle root,
// checks the Ed25519 signature, and checks the OpenTimestamps proof,
// implementing SPEC.md beside this file.
//
// It imports nothing from the application and nothing outside the
// Node.js standard library, on purpose: the claim is that the light
// keeps working after we are gone, and a verifier that needs our server
// is a verifier that dies with us. Copy this file anywhere with Node 18
// or newer and it runs.
//
//   node showglobe-verify.mjs --proof <day.json> --dump <events.jsonl> \
//        --public-key <64 hex | @file> [--day YYYY-MM-DD] \
//        [--environment name] [--bitcoin-merkle-root <height>:<hex>] \
//        [--online] [--json]
//
//   node showglobe-verify.mjs --ots-info <file.ots>
//
// Exit codes: 0 the day is verified and its timestamp is confirmed
// against a block header the caller supplied (or fetched with --online);
// 2 the signature and the root verify but the timestamp is still
// pending, or no block header was supplied to check a confirmed one
// against (the output says exactly what to check); 1 rejected, with the
// reason. --online fetches one block header from a public explorer
// (mempool.space); the only thing that leaves is the block height.

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const SPEC = 'showglobe-anchor/1';
const SIGNING_PREFIX = 'showglobe-anchor/1\n';
const STATEMENT_KEYS = ['spec', 'environment', 'log_id', 'day', 'watermark', 'leaf_count', 'root', 'computed_at'];
const RECORD_KEYS = [...STATEMENT_KEYS, 'public_key', 'key_id', 'signature'];
const LEAF_KEYS = ['id', 'event_type', 'schema_version', 'occurred_at', 'recorded_at', 'authored_by', 'acting_for', 'on_behalf_of', 'context_id', 'correlation_id', 'payload'].sort();
const LEAF_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// --- RFC 8785, written independently of the platform's copy.

function canonical(value) {
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new Error('non-finite number');
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'object': {
      if (value === null) return 'null';
      if (Array.isArray(value)) {
        let out = '[';
        for (let i = 0; i < value.length; i += 1) out += (i ? ',' : '') + canonical(value[i]);
        return out + ']';
      }
      const names = Object.keys(value).sort();
      let out = '{';
      for (let i = 0; i < names.length; i += 1) {
        out += (i ? ',' : '') + JSON.stringify(names[i]) + ':' + canonical(value[names[i]]);
      }
      return out + '}';
    }
    default:
      throw new Error(`cannot canonicalize a ${typeof value}`);
  }
}

// --- RFC 6962, the recursive definition rather than an accumulator.

function sha256(...parts) {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function merkleTreeHash(hashes, lo, hi) {
  const n = hi - lo;
  if (n === 0) return sha256();
  if (n === 1) return hashes[lo];
  let k = 1;
  while (k * 2 < n) k *= 2;
  return sha256(Buffer.from([0x01]), merkleTreeHash(hashes, lo, lo + k), merkleTreeHash(hashes, lo + k, hi));
}

function leafHashOf(bytes) {
  return sha256(Buffer.from([0x00]), bytes);
}

// --- Ed25519 over a raw public key.

function publicKeyObject(hex) {
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(hex, 'hex')]), format: 'der', type: 'spki' });
}

function keyIdOf(publicKeyHex) {
  return `ed25519:${sha256(Buffer.from(publicKeyHex, 'hex')).toString('hex').slice(0, 16)}`;
}

// --- OpenTimestamps: enough of the format to read a detached
// timestamp, walk every path, and report its attestations. Tags and
// layout follow the python-opentimestamps reference serialization.

const OTS_MAGIC = Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex');
const ATTESTATION_PENDING = '83dfe30d2ef90c8e';
const ATTESTATION_BITCOIN = '0588960d73d71901';
const ATTESTATION_LITECOIN = '06869a0d73d71b45';
const MAX_MESSAGE = 4096;

class Reader {
  constructor(buf) {
    this.buf = buf;
    this.pos = 0;
  }
  byte() {
    if (this.pos >= this.buf.length) throw new Error('ots: unexpected end of data');
    return this.buf[this.pos++];
  }
  bytes(n) {
    if (this.pos + n > this.buf.length) throw new Error('ots: unexpected end of data');
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return Buffer.from(out);
  }
  varuint() {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = this.byte();
      value += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) return value;
      shift += 7;
      if (shift > 56) throw new Error('ots: varuint too long');
    }
  }
  varbytes(max) {
    const n = this.varuint();
    if (n > max) throw new Error(`ots: varbytes of ${n} exceeds ${max}`);
    return this.bytes(n);
  }
}

const OP_NAMES = { 0x02: 'sha1', 0x03: 'ripemd160', 0x08: 'sha256', 0x67: 'keccak256', 0xf0: 'append', 0xf1: 'prepend', 0xf2: 'reverse', 0xf3: 'hexlify' };

function readOp(r, tag) {
  const name = OP_NAMES[tag];
  if (!name) throw new Error(`ots: unknown op tag 0x${tag.toString(16)}`);
  if (tag === 0xf0 || tag === 0xf1) return { tag, name, arg: r.varbytes(MAX_MESSAGE) };
  return { tag, name };
}

function applyOp(op, msg) {
  switch (op.name) {
    case 'sha256': return createHash('sha256').update(msg).digest();
    case 'sha1': return createHash('sha1').update(msg).digest();
    case 'ripemd160': return createHash('ripemd160').update(msg).digest();
    case 'append': return Buffer.concat([msg, op.arg]);
    case 'prepend': return Buffer.concat([op.arg, msg]);
    case 'reverse': return Buffer.from(msg).reverse();
    case 'hexlify': return Buffer.from(msg.toString('hex'), 'utf8');
    default: throw new Error(`ots: unsupported op ${op.name}`);
  }
}

function readAttestation(r) {
  const tag = r.bytes(8).toString('hex');
  const payload = r.varbytes(8192);
  const pr = new Reader(payload);
  if (tag === ATTESTATION_PENDING) {
    const uri = pr.varbytes(1000).toString('utf8');
    if (!/^[A-Za-z0-9._\/:-]+$/.test(uri)) throw new Error('ots: pending attestation uri has forbidden characters');
    return { type: 'pending', uri };
  }
  if (tag === ATTESTATION_BITCOIN) return { type: 'bitcoin', height: pr.varuint() };
  if (tag === ATTESTATION_LITECOIN) return { type: 'litecoin', height: pr.varuint() };
  return { type: 'unknown', tag, payload: payload.toString('hex') };
}

function readTimestamp(r, msg) {
  const node = { msg, attestations: [], ops: [] };
  const step = (tag) => {
    if (tag === 0x00) {
      node.attestations.push(readAttestation(r));
    } else {
      const op = readOp(r, tag);
      const next = applyOp(op, msg);
      if (next.length > MAX_MESSAGE) throw new Error('ots: message too long');
      node.ops.push({ op, child: readTimestamp(r, next) });
    }
  };
  let tag = r.byte();
  while (tag === 0xff) {
    step(r.byte());
    tag = r.byte();
  }
  step(tag);
  return node;
}

export function parseOts(buf) {
  const r = new Reader(buf);
  if (!r.bytes(OTS_MAGIC.length).equals(OTS_MAGIC)) throw new Error('ots: bad magic header');
  const version = r.varuint();
  if (version !== 1) throw new Error(`ots: unsupported version ${version}`);
  const tag = r.byte();
  if (tag !== 0x08) throw new Error('ots: only sha256 file digests are supported');
  const digest = r.bytes(32);
  const timestamp = readTimestamp(r, digest);
  if (r.pos !== buf.length) throw new Error('ots: trailing bytes after the timestamp');
  return { digest, timestamp };
}

export function attestationsOf(node, out = []) {
  for (const a of node.attestations) out.push({ ...a, msg: node.msg });
  for (const { child } of node.ops) attestationsOf(child, out);
  return out;
}

export function describeOts(node, indent = 0) {
  const pad = ' '.repeat(indent);
  let out = '';
  for (const a of node.attestations) {
    if (a.type === 'bitcoin') out += `${pad}verify BitcoinBlockHeaderAttestation(${a.height})\n${pad}# block merkle root (explorer order) ${Buffer.from(node.msg).reverse().toString('hex')}\n`;
    else if (a.type === 'pending') out += `${pad}verify PendingAttestation(${a.uri})\n`;
    else out += `${pad}verify ${a.type}\n`;
  }
  node.ops.forEach(({ op, child }, i) => {
    const arg = op.arg ? ` ${op.arg.toString('hex')}` : '';
    out += `${pad}${node.ops.length > 1 && i === 0 ? ' -> ' : ''}${op.name}${arg}\n`;
    out += describeOts(child, node.ops.length > 1 ? indent + 4 : indent);
  });
  return out;
}

// --- Arguments.

function parseArgs(argv) {
  const args = { merkleRoots: new Map() };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      return argv[++i];
    };
    if (a === '--proof') args.proof = next();
    else if (a === '--dump') args.dump = next();
    else if (a === '--public-key') args.publicKey = next();
    else if (a === '--day') args.day = next();
    else if (a === '--environment') args.environment = next();
    else if (a === '--bitcoin-merkle-root') {
      const v = next();
      const m = v.match(/^(\d+):([0-9a-fA-F]{64})$/);
      if (!m) throw new Error('--bitcoin-merkle-root takes <height>:<64 hex>');
      args.merkleRoots.set(Number(m[1]), m[2].toLowerCase());
    } else if (a === '--online') args.online = true;
    else if (a === '--json') args.json = true;
    else if (a === '--ots-info') args.otsInfo = next();
    else if (a === '--help' || a === '-h') args.help = true;
    else throw new Error(`unknown argument ${a}`);
  }
  return args;
}

function usage() {
  return [
    'usage: node showglobe-verify.mjs --proof <day.json> --dump <events.jsonl> --public-key <hex | @file>',
    '            [--day YYYY-MM-DD] [--environment name] [--bitcoin-merkle-root <height>:<hex>] [--online] [--json]',
    '       node showglobe-verify.mjs --ots-info <file.ots>',
  ].join('\n');
}

// --- The verification itself. Returns a report; never throws for a
// rejection, only for unusable input.

export function verifyDay({ proof, dumpText, trustedPublicKey, expectDay = null, expectEnvironment = null, merkleRoots = new Map() }) {
  const checks = [];
  const fail = (code, detail) => ({ verdict: 'rejected', code, detail, checks });
  const pass = (label, detail = '') => checks.push({ ok: true, label, detail });

  // 1. Shape, spec, and key.
  if (typeof proof !== 'object' || proof === null) return fail('proof_not_object', 'the proof file is not a JSON object');
  if (proof.spec !== SPEC) return fail('spec_unsupported', `proof spec ${JSON.stringify(proof.spec)} is not ${SPEC}`);
  for (const k of RECORD_KEYS) {
    if (!(k in proof)) return fail('proof_field_missing', `the proof lacks ${k}`);
  }
  if (typeof proof.public_key !== 'string' || !HEX64.test(proof.public_key)) return fail('public_key_malformed', 'public_key is not 64 lowercase hex characters');
  if (proof.public_key !== trustedPublicKey) return fail('wrong_key', `the proof is signed by key ${keyIdOf(proof.public_key)}, not the trusted key ${keyIdOf(trustedPublicKey)}`);
  if (proof.key_id !== keyIdOf(proof.public_key)) return fail('key_id_mismatch', 'key_id does not name public_key');
  pass('key', `signed by the trusted key ${proof.key_id}`);
  if (expectDay !== null && proof.day !== expectDay) return fail('wrong_day', `the proof is for ${proof.day}, not ${expectDay}`);
  if (expectEnvironment !== null && proof.environment !== expectEnvironment) return fail('wrong_environment', `the proof is for ${proof.environment}, not ${expectEnvironment}`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(proof.day)) return fail('day_malformed', 'day is not YYYY-MM-DD');
  if (!Number.isInteger(proof.watermark) || proof.watermark < 0) return fail('watermark_malformed', 'watermark is not a non-negative integer');
  if (!Number.isInteger(proof.leaf_count) || proof.leaf_count < 0) return fail('leaf_count_malformed', 'leaf_count is not a non-negative integer');
  if (typeof proof.root !== 'string' || !HEX64.test(proof.root)) return fail('root_malformed', 'root is not 64 lowercase hex characters');
  if (typeof proof.signature !== 'string' || !HEX128.test(proof.signature)) return fail('signature_malformed', 'signature is not 128 lowercase hex characters');
  pass('labels', `day ${proof.day}, environment ${proof.environment}, log ${proof.log_id}, watermark ${proof.watermark}, ${proof.leaf_count} leaves`);

  // 2. The signature over the statement.
  const statement = {};
  for (const k of STATEMENT_KEYS) statement[k] = proof[k];
  const message = Buffer.concat([Buffer.from(SIGNING_PREFIX, 'utf8'), Buffer.from(canonical(statement), 'utf8')]);
  let signatureOk = false;
  try {
    signatureOk = cryptoVerify(null, message, publicKeyObject(proof.public_key), Buffer.from(proof.signature, 'hex'));
  } catch (err) {
    return fail('signature_unverifiable', err.message);
  }
  if (!signatureOk) return fail('bad_signature', 'the signature does not verify over the statement');
  pass('signature', 'Ed25519 signature verifies over the statement');

  // 3. The dump: canonical lines, ascending ids, the prefix to the
  // watermark, and its Merkle Tree Hash.
  const lines = dumpText.split('\n');
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  const leafHashes = [];
  let lastId = 0;
  let seen = 0;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      return fail('dump_line_unparseable', `line ${i + 1} is not JSON`);
    }
    if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return fail('dump_line_not_object', `line ${i + 1} is not a JSON object`);
    const keys = Object.keys(obj).sort();
    if (keys.length !== LEAF_KEYS.length || keys.some((k, j) => k !== LEAF_KEYS[j])) return fail('dump_line_keys', `line ${i + 1} does not carry exactly the eleven leaf keys`);
    if (!Number.isSafeInteger(obj.id) || obj.id < 1) return fail('dump_line_id', `line ${i + 1} has a malformed id`);
    if (obj.id <= lastId) return fail('dump_not_ascending', `line ${i + 1} (id ${obj.id}) does not ascend past id ${lastId}`);
    for (const k of ['occurred_at', 'recorded_at']) {
      if (typeof obj[k] !== 'string' || !LEAF_TIMESTAMP.test(obj[k])) return fail('dump_line_timestamp', `line ${i + 1}: ${k} is not a six-digit UTC timestamp`);
    }
    if (canonical(obj) !== line) return fail('dump_not_canonical', `line ${i + 1} (id ${obj.id}) is not in canonical form`);
    lastId = obj.id;
    if (obj.id > proof.watermark) continue;
    seen += 1;
    leafHashes.push(leafHashOf(Buffer.from(line, 'utf8')));
  }
  if (seen !== proof.leaf_count) return fail('leaf_count_mismatch', `the dump holds ${seen} rows at or below watermark ${proof.watermark}; the proof says ${proof.leaf_count}`);
  const root = merkleTreeHash(leafHashes, 0, leafHashes.length).toString('hex');
  if (root !== proof.root) return fail('root_mismatch', `recomputed root ${root} differs from the proof's ${proof.root}`);
  pass('root', `Merkle root ${root} recomputed from ${seen} leaves`);

  // 4. The stamp digest and the .ots header.
  const record = {};
  for (const k of RECORD_KEYS) record[k] = proof[k];
  const stampDigest = sha256(Buffer.from(canonical(record), 'utf8')).toString('hex');
  if (proof.stamp_digest !== stampDigest) return fail('stamp_digest_mismatch', `stamp_digest ${proof.stamp_digest} is not the sha256 of the record (${stampDigest})`);
  pass('stamp_digest', `stamp digest ${stampDigest} is the sha256 of the record`);
  const ts = proof.timestamp;
  if (typeof ts !== 'object' || ts === null || typeof ts.ots_base64 !== 'string') {
    return { verdict: 'pending', code: 'no_timestamp', detail: 'signature and root verify; the proof carries no timestamp yet', checks };
  }
  let parsed;
  try {
    parsed = parseOts(Buffer.from(ts.ots_base64, 'base64'));
  } catch (err) {
    return fail('ots_unparseable', err.message);
  }
  if (parsed.digest.toString('hex') !== stampDigest) return fail('ots_digest_mismatch', `the .ots header digest ${parsed.digest.toString('hex')} is not the stamp digest`);
  pass('ots_digest', 'the .ots header digest is the stamp digest');

  // 5. Attestations.
  const attestations = attestationsOf(parsed.timestamp);
  const bitcoin = attestations.filter((a) => a.type === 'bitcoin');
  const pending = attestations.filter((a) => a.type === 'pending');
  if (bitcoin.length === 0) {
    return {
      verdict: 'pending',
      code: 'timestamp_pending',
      detail: `signature and root verify; the timestamp is pending at ${pending.length} calendar(s): ${pending.map((p) => p.uri).join(', ')}`,
      checks,
      pending: pending.map((p) => p.uri),
    };
  }
  const results = [];
  for (const a of bitcoin) {
    const attested = Buffer.from(a.msg).reverse().toString('hex');
    const known = merkleRoots.get(a.height);
    if (known === undefined) {
      results.push({ height: a.height, attested_merkle_root: attested, checked: false });
      continue;
    }
    if (known !== attested) return fail('merkle_root_mismatch', `block ${a.height}: the proof attests merkle root ${attested} but the supplied header says ${known}`);
    results.push({ height: a.height, attested_merkle_root: attested, checked: true });
  }
  const checked = results.filter((r) => r.checked);
  if (checked.length === 0) {
    return {
      verdict: 'pending',
      code: 'block_header_needed',
      detail: `the proof attests Bitcoin block ${results.map((r) => r.height).join(', ')}; supply --bitcoin-merkle-root ${results[0].height}:<merkle root from a block explorer> or --online to check it`,
      checks,
      bitcoin: results,
    };
  }
  pass('bitcoin', checked.map((r) => `block ${r.height} merkle root ${r.attested_merkle_root} matches the supplied header`).join('; '));
  return { verdict: 'verified', code: 'confirmed', detail: `day ${proof.day} is signed by ${proof.key_id} and existed by Bitcoin block ${checked.map((r) => r.height).join(', ')}`, checks, bitcoin: results };
}

export { canonical as canonicalJson, merkleTreeHash, leafHashOf, keyIdOf };

async function fetchMerkleRoot(height) {
  const base = 'https://mempool.space/api';
  const hashRes = await fetch(`${base}/block-height/${height}`, { signal: AbortSignal.timeout(15000) });
  if (!hashRes.ok) throw new Error(`explorer refused block height ${height}: ${hashRes.status}`);
  const hash = (await hashRes.text()).trim();
  const blockRes = await fetch(`${base}/block/${hash}`, { signal: AbortSignal.timeout(15000) });
  if (!blockRes.ok) throw new Error(`explorer refused block ${hash}: ${blockRes.status}`);
  const block = await blockRes.json();
  return { hash, merkle_root: String(block.merkle_root).toLowerCase(), timestamp: block.timestamp };
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(err.message);
    console.error(usage());
    return 1;
  }
  if (args.help) {
    console.log(usage());
    return 0;
  }
  if (args.otsInfo) {
    const parsed = parseOts(readFileSync(args.otsInfo));
    console.log(`digest sha256 ${parsed.digest.toString('hex')}`);
    process.stdout.write(describeOts(parsed.timestamp));
    return 0;
  }
  if (!args.proof || !args.dump || !args.publicKey) {
    console.error(usage());
    return 1;
  }
  const proof = JSON.parse(readFileSync(args.proof, 'utf8'));
  const dumpText = readFileSync(args.dump, 'utf8');
  let trusted = args.publicKey.startsWith('@') ? readFileSync(args.publicKey.slice(1), 'utf8') : args.publicKey;
  trusted = trusted.trim().toLowerCase();
  if (trusted.startsWith('{')) trusted = String(JSON.parse(trusted).public_key ?? '').toLowerCase();
  if (!HEX64.test(trusted)) {
    console.error('the trusted public key must be 64 hex characters (or @file holding them, or a keys/*.json file)');
    return 1;
  }
  const merkleRoots = new Map(args.merkleRoots);
  const online = [];
  if (args.online && proof?.timestamp?.ots_base64) {
    try {
      const parsed = parseOts(Buffer.from(proof.timestamp.ots_base64, 'base64'));
      for (const a of attestationsOf(parsed.timestamp)) {
        if (a.type === 'bitcoin' && !merkleRoots.has(a.height)) {
          const header = await fetchMerkleRoot(a.height);
          merkleRoots.set(a.height, header.merkle_root);
          online.push({ height: a.height, ...header });
        }
      }
    } catch (err) {
      console.error(`online header lookup failed: ${err.message}`);
    }
  }
  const report = verifyDay({ proof, dumpText, trustedPublicKey: trusted, expectDay: args.day ?? null, expectEnvironment: args.environment ?? null, merkleRoots });
  if (online.length > 0) report.online_headers = online;
  if (args.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    for (const c of report.checks) console.log(`  [ok] ${c.label}${c.detail ? `: ${c.detail}` : ''}`);
    for (const h of online) console.log(`  [online] block ${h.height} hash ${h.hash} merkle root ${h.merkle_root} time ${new Date(h.timestamp * 1000).toISOString()}`);
    console.log(`${report.verdict.toUpperCase()} (${report.code}): ${report.detail}`);
  }
  return report.verdict === 'verified' ? 0 : report.verdict === 'pending' ? 2 : 1;
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('showglobe-verify.mjs')) {
  main().then((code) => process.exit(code), (err) => {
    console.error(err.message);
    process.exit(1);
  });
}
