#!/usr/bin/env node
// The Showglobe anchoring notary (Packet 14), the external side of the
// daily job. It runs where no secret of any kind lives: it reads the
// day's public record from the platform's read-only endpoint, checks
// the platform's own signature against the platform's own published
// key, hands the record's digest to the public OpenTimestamps
// calendars, publishes the pending proof into the proof home, upgrades
// every earlier pending proof it can, and rewrites the environment's
// index. The intended home is a scheduled workflow in a public
// repository, which makes the workflow log its own public record and
// its native failure notification a free second alarm that does not
// depend on the platform being up.
//
//   node notary.mjs --environment staging --platform https://showglobe-staging.onrender.com \
//        [--home <dir>] [--calendars <url,url>] [--wait-ms 300000] [--no-upgrade] [--no-stamp]
//
// Standard library only, one file, like the verifier beside it. Every
// outbound request is printed as one JSON line (what left: the URL, the
// byte count, the sha256 of the bytes) for the SG-PN-001 egress record.
// Exit 1 on any failure, so the workflow fails visibly.

import { createHash, createPublicKey, randomBytes, verify as cryptoVerify } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const SPEC = 'showglobe-anchor/1';
const SIGNING_PREFIX = 'showglobe-anchor/1\n';
const STATEMENT_KEYS = ['spec', 'environment', 'log_id', 'day', 'watermark', 'leaf_count', 'root', 'computed_at'];
const RECORD_KEYS = [...STATEMENT_KEYS, 'public_key', 'key_id', 'signature'];
const DEFAULT_CALENDARS = [
  'https://a.pool.opentimestamps.org',
  'https://b.pool.opentimestamps.org',
  'https://a.pool.eternitywall.com',
  'https://ots.btc.catallaxy.com',
];
const USER_AGENT = 'showglobe-notary/1';
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// --- Small shared pieces.

function sha256(...parts) {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function canonical(value) {
  if (value === null || typeof value === 'boolean') return String(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite number');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

function keyIdOf(publicKeyHex) {
  return `ed25519:${sha256(Buffer.from(publicKeyHex, 'hex')).toString('hex').slice(0, 16)}`;
}

function verifyRecord(record) {
  const statement = {};
  for (const k of STATEMENT_KEYS) statement[k] = record[k];
  const message = Buffer.concat([Buffer.from(SIGNING_PREFIX, 'utf8'), Buffer.from(canonical(statement), 'utf8')]);
  const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(record.public_key, 'hex')]), format: 'der', type: 'spki' });
  return cryptoVerify(null, message, key, Buffer.from(record.signature, 'hex'));
}

function stampDigestOf(record) {
  const ordered = {};
  for (const k of RECORD_KEYS) ordered[k] = record[k];
  return sha256(Buffer.from(canonical(ordered), 'utf8'));
}

function egress(entry) {
  console.log(JSON.stringify({ egress: true, at: new Date().toISOString(), ...entry }));
}

async function httpFetch(url, { method = 'GET', body = null, accept = 'application/json', timeoutMs = 20000 } = {}) {
  const headers = { accept, 'user-agent': USER_AGENT };
  if (body !== null) headers['content-type'] = 'application/octet-stream';
  let res;
  let error = null;
  try {
    res = await fetch(url, { method, headers, body: body ?? undefined, signal: AbortSignal.timeout(timeoutMs) });
  } catch (err) {
    error = err.message;
  }
  egress({
    method, url,
    body_bytes: body === null ? 0 : body.length,
    body_sha256: body === null ? null : sha256(body).toString('hex'),
    status: res ? res.status : null,
    error,
  });
  if (error !== null) throw new Error(`${method} ${url}: ${error}`);
  return res;
}

// --- OpenTimestamps: the detached timestamp format, read, written,
// merged, stamped, and upgraded. Tags and layout follow the
// python-opentimestamps reference implementation.

const OTS_MAGIC = Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex');
const ATTESTATION_PENDING = '83dfe30d2ef90c8e';
const ATTESTATION_BITCOIN = '0588960d73d71901';
const ATTESTATION_LITECOIN = '06869a0d73d71b45';
const MAX_MESSAGE = 4096;
const OP_NAMES = { 0x02: 'sha1', 0x03: 'ripemd160', 0x08: 'sha256', 0x67: 'keccak256', 0xf0: 'append', 0xf1: 'prepend', 0xf2: 'reverse', 0xf3: 'hexlify' };

class Reader {
  constructor(buf) { this.buf = buf; this.pos = 0; }
  byte() { if (this.pos >= this.buf.length) throw new Error('ots: unexpected end of data'); return this.buf[this.pos++]; }
  bytes(n) { if (this.pos + n > this.buf.length) throw new Error('ots: unexpected end of data'); const out = Buffer.from(this.buf.subarray(this.pos, this.pos + n)); this.pos += n; return out; }
  varuint() { let value = 0; let shift = 0; for (;;) { const b = this.byte(); value += (b & 0x7f) * 2 ** shift; if ((b & 0x80) === 0) return value; shift += 7; if (shift > 56) throw new Error('ots: varuint too long'); } }
  varbytes(max) { const n = this.varuint(); if (n > max) throw new Error(`ots: varbytes of ${n} exceeds ${max}`); return this.bytes(n); }
}

class Writer {
  constructor() { this.chunks = []; }
  byte(b) { this.chunks.push(Buffer.from([b])); }
  bytes(buf) { this.chunks.push(Buffer.from(buf)); }
  varuint(n) { let v = n; for (;;) { const b = v % 128; v = Math.floor(v / 128); if (v > 0) this.byte(b | 0x80); else { this.byte(b); return; } } }
  varbytes(buf) { this.varuint(buf.length); this.bytes(buf); }
  toBuffer() { return Buffer.concat(this.chunks); }
}

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
    return { type: 'pending', tag, uri };
  }
  if (tag === ATTESTATION_BITCOIN) return { type: 'bitcoin', tag, height: pr.varuint() };
  if (tag === ATTESTATION_LITECOIN) return { type: 'litecoin', tag, height: pr.varuint() };
  return { type: 'unknown', tag, payload };
}

function writeAttestation(w, a) {
  w.bytes(Buffer.from(a.tag, 'hex'));
  const pw = new Writer();
  if (a.type === 'pending') pw.varbytes(Buffer.from(a.uri, 'utf8'));
  else if (a.type === 'bitcoin' || a.type === 'litecoin') pw.varuint(a.height);
  else pw.bytes(a.payload);
  w.varbytes(pw.toBuffer());
}

function attestationKey(a) {
  return a.type === 'pending' ? `${a.tag}:${a.uri}` : a.type === 'unknown' ? `${a.tag}:${a.payload.toString('hex')}` : `${a.tag}:${a.height}`;
}

function opKey(op) {
  return `${op.tag}:${op.arg ? op.arg.toString('hex') : ''}`;
}

function readTimestamp(r, msg) {
  const node = { msg, attestations: [], ops: [] };
  const step = (tag) => {
    if (tag === 0x00) node.attestations.push(readAttestation(r));
    else {
      const op = readOp(r, tag);
      const next = applyOp(op, msg);
      if (next.length > MAX_MESSAGE) throw new Error('ots: message too long');
      node.ops.push({ op, child: readTimestamp(r, next) });
    }
  };
  let tag = r.byte();
  while (tag === 0xff) { step(r.byte()); tag = r.byte(); }
  step(tag);
  return node;
}

function writeTimestamp(w, node) {
  const atts = [...node.attestations].sort((a, b) => attestationKey(a).localeCompare(attestationKey(b)));
  const ops = [...node.ops].sort((a, b) => opKey(a.op).localeCompare(opKey(b.op)));
  if (atts.length === 0 && ops.length === 0) throw new Error('ots: an empty timestamp cannot be serialized');
  for (const a of atts.slice(0, -1)) { w.byte(0xff); w.byte(0x00); writeAttestation(w, a); }
  if (ops.length === 0) { w.byte(0x00); writeAttestation(w, atts[atts.length - 1]); return; }
  if (atts.length > 0) { w.byte(0xff); w.byte(0x00); writeAttestation(w, atts[atts.length - 1]); }
  for (const { op, child } of ops.slice(0, -1)) { w.byte(0xff); w.byte(op.tag); if (op.arg) w.varbytes(op.arg); writeTimestamp(w, child); }
  const last = ops[ops.length - 1];
  w.byte(last.op.tag);
  if (last.op.arg) w.varbytes(last.op.arg);
  writeTimestamp(w, last.child);
}

function parseOts(buf) {
  const r = new Reader(buf);
  if (!r.bytes(OTS_MAGIC.length).equals(OTS_MAGIC)) throw new Error('ots: bad magic header');
  if (r.varuint() !== 1) throw new Error('ots: unsupported version');
  if (r.byte() !== 0x08) throw new Error('ots: only sha256 digests are supported');
  const digest = r.bytes(32);
  const timestamp = readTimestamp(r, digest);
  if (r.pos !== buf.length) throw new Error('ots: trailing bytes');
  return { digest, timestamp };
}

function serializeOts(digest, timestamp) {
  const w = new Writer();
  w.bytes(OTS_MAGIC);
  w.varuint(1);
  w.byte(0x08);
  w.bytes(digest);
  writeTimestamp(w, timestamp);
  return w.toBuffer();
}

function mergeTimestamp(into, from) {
  if (!into.msg.equals(from.msg)) throw new Error('ots: cannot merge timestamps of different messages');
  const have = new Set(into.attestations.map(attestationKey));
  for (const a of from.attestations) if (!have.has(attestationKey(a))) { into.attestations.push(a); have.add(attestationKey(a)); }
  for (const { op, child } of from.ops) {
    const existing = into.ops.find((o) => opKey(o.op) === opKey(op));
    if (existing) mergeTimestamp(existing.child, child);
    else into.ops.push({ op, child });
  }
}

function attestationsOf(node, out = []) {
  for (const a of node.attestations) out.push({ ...a, msg: node.msg });
  for (const { child } of node.ops) attestationsOf(child, out);
  return out;
}

function prunePending(node) {
  node.attestations = node.attestations.filter((a) => a.type !== 'pending');
  for (const { child } of node.ops) prunePending(child);
  node.ops = node.ops.filter(({ child }) => child.attestations.length > 0 || child.ops.length > 0);
}

async function stampDigest(digest, calendars) {
  const nonce = randomBytes(16);
  const root = { msg: digest, attestations: [], ops: [] };
  const withNonce = { msg: Buffer.concat([digest, nonce]), attestations: [], ops: [] };
  root.ops.push({ op: { tag: 0xf0, name: 'append', arg: nonce }, child: withNonce });
  const commitment = { msg: sha256(withNonce.msg), attestations: [], ops: [] };
  withNonce.ops.push({ op: { tag: 0x08, name: 'sha256' }, child: commitment });
  const accepted = [];
  const refused = [];
  for (const cal of calendars) {
    try {
      const res = await httpFetch(`${cal.replace(/\/$/, '')}/digest`, { method: 'POST', body: commitment.msg, accept: 'application/vnd.opentimestamps.v1', timeoutMs: 15000 });
      if (!res.ok) { refused.push({ calendar: cal, status: res.status }); continue; }
      const body = Buffer.from(await res.arrayBuffer());
      mergeTimestamp(commitment, readTimestamp(new Reader(body), commitment.msg));
      accepted.push(cal);
    } catch (err) {
      refused.push({ calendar: cal, error: err.message });
    }
  }
  if (accepted.length === 0) throw new Error(`no calendar accepted the digest: ${JSON.stringify(refused)}`);
  return { timestamp: root, accepted, refused };
}

async function upgradeTimestamp(node) {
  let changed = false;
  async function visit(n) {
    for (const a of n.attestations.filter((x) => x.type === 'pending')) {
      const url = `${a.uri.replace(/\/$/, '')}/timestamp/${n.msg.toString('hex')}`;
      let res;
      try {
        res = await httpFetch(url, { accept: 'application/vnd.opentimestamps.v1', timeoutMs: 15000 });
      } catch {
        continue;
      }
      if (res.status !== 200) { await res.arrayBuffer().catch(() => null); continue; }
      const body = Buffer.from(await res.arrayBuffer());
      mergeTimestamp(n, readTimestamp(new Reader(body), n.msg));
      changed = true;
    }
    for (const { child } of n.ops) await visit(child);
  }
  await visit(node);
  if (changed && attestationsOf(node).some((a) => a.type === 'bitcoin')) prunePending(node);
  return changed;
}

// --- The run.

function parseArgs(argv) {
  const out = { home: '.', calendars: DEFAULT_CALENDARS, waitMs: 300000, upgrade: true, stamp: true };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === '--environment') out.environment = next();
    else if (a === '--platform') out.platform = next().replace(/\/$/, '');
    else if (a === '--home') out.home = next();
    else if (a === '--calendars') out.calendars = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--wait-ms') out.waitMs = Number(next());
    else if (a === '--no-upgrade') out.upgrade = false;
    else if (a === '--no-stamp') out.stamp = false;
    else throw new Error(`unknown argument ${a}`);
  }
  if (!out.environment || !/^[a-z]+$/.test(out.environment)) throw new Error('--environment is required (staging or production)');
  if (out.stamp && !out.platform) throw new Error('--platform is required');
  return out;
}

// The platform may be asleep (a free instance wakes in about a minute):
// keep asking until it answers or the wait budget ends.
async function fetchJsonPatiently(url, waitMs) {
  const deadline = Date.now() + waitMs;
  let last = null;
  for (;;) {
    try {
      const res = await httpFetch(url, { timeoutMs: 60000 });
      const text = await res.text();
      if (res.ok) return JSON.parse(text);
      last = `${res.status} ${text.slice(0, 200)}`;
      if (res.status === 503 && text.includes('anchor_unconfigured')) throw new Error(`the platform reports anchoring unconfigured at ${url}`);
    } catch (err) {
      if (String(err.message).includes('unconfigured')) throw err;
      last = err.message;
    }
    if (Date.now() >= deadline) throw new Error(`${url} did not answer within ${waitMs} ms; last: ${last}`);
    await new Promise((r) => setTimeout(r, 10000));
  }
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function writeJson(path, value) {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function listProofFiles(envDir) {
  const out = [];
  if (!existsSync(envDir)) return out;
  for (const entry of readdirSync(envDir)) {
    const p = join(envDir, entry);
    if (entry === 'keys' || entry === 'index.json' || !statSync(p).isDirectory()) continue;
    for (const f of readdirSync(p)) if (/^\d{4}-\d{2}-\d{2}\.json$/.test(f)) out.push(join(p, f));
  }
  return out.sort();
}

// A record from the platform is trusted only after it checks out: the
// spec, the environment, the key the platform itself publishes, the
// signature, the digest, and the labels.
function checkRecord(record, environment, envDir) {
  for (const k of RECORD_KEYS) if (!(k in record)) throw new Error(`a record lacks ${k}`);
  if (record.spec !== SPEC) throw new Error(`a record is spec ${record.spec}`);
  if (record.environment !== environment) throw new Error(`a record is for ${record.environment}, not ${environment}`);
  const keyPath = join(envDir, 'keys', `${String(record.key_id).replace(':', '-')}.json`);
  if (!existsSync(keyPath)) throw new Error(`the record for ${record.day} is signed by ${record.key_id}, a key this home has never seen from the platform`);
  if (readJson(keyPath).public_key !== record.public_key) throw new Error(`the record for ${record.day} names key ${record.key_id} but carries a different public key`);
  if (!verifyRecord(record)) throw new Error(`the record for ${record.day} does not verify against key ${record.key_id}`);
  if (record.stamp_digest !== stampDigestOf(record).toString('hex')) throw new Error(`the stamp_digest for ${record.day} is not the sha256 of the record`);
  if (!/^(undeclared|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/.test(record.log_id) || !/^\d{4}-\d{2}-\d{2}$/.test(record.day)) {
    throw new Error(`the record for ${record.day} has a malformed log_id or day`);
  }
}

// Append-only in practice: a day already published with the same
// record is skipped; with a different record it is refused loudly and
// the file is left as it was. Otherwise the digest is stamped and the
// pending proof written.
async function publishRecord(record, envDir, calendars, { late }) {
  const proofPath = join(envDir, record.log_id, `${record.day}.json`);
  const clean = {};
  for (const k of RECORD_KEYS) clean[k] = record[k];
  clean.stamp_digest = record.stamp_digest;
  if (existsSync(proofPath)) {
    const published = readJson(proofPath);
    const same = [...RECORD_KEYS, 'stamp_digest'].every((k) => published[k] === clean[k]);
    if (!same) throw new Error(`refusing to overwrite ${proofPath}: the platform now serves a different record for ${record.day}`);
    console.log(`already published: ${proofPath}`);
    return { skipped: true, path: proofPath };
  }
  const digest = Buffer.from(record.stamp_digest, 'hex');
  const { timestamp, accepted, refused } = await stampDigest(digest, calendars);
  const ots = serializeOts(digest, timestamp);
  parseOts(ots);
  writeJson(proofPath, {
    ...clean,
    timestamp: {
      status: 'pending',
      late,
      ots_base64: ots.toString('base64'),
      submitted_at: new Date().toISOString(),
      calendars: accepted,
      refused_calendars: refused,
    },
  });
  console.log(`stamped ${record.day}${late ? ' LATE' : ''}: ${accepted.length} calendar(s) accepted, proof at ${proofPath}`);
  return { skipped: false, path: proofPath, calendars: accepted, refused, late };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envDir = join(args.home, args.environment);
  mkdirSync(join(envDir, 'keys'), { recursive: true });
  const summary = { environment: args.environment, stamped: null, late: [], upgraded: [], skipped: null, index: null };

  if (args.stamp) {
    // 1. The platform's key, patiently.
    const key = await fetchJsonPatiently(`${args.platform}/api/anchors/key`, args.waitMs);
    if (key.environment !== args.environment) throw new Error(`the platform says it is ${key.environment}, not ${args.environment}`);
    if (!/^[0-9a-f]{64}$/.test(key.public_key) || key.key_id !== keyIdOf(key.public_key)) throw new Error('the platform published a malformed key');
    const keyPath = join(envDir, 'keys', `${key.key_id.replace(':', '-')}.json`);
    if (existsSync(keyPath)) {
      const known = readJson(keyPath);
      if (known.public_key !== key.public_key) throw new Error(`the key file ${keyPath} disagrees with the platform's key`);
    } else {
      writeJson(keyPath, { spec: SPEC, environment: args.environment, algorithm: 'ed25519', public_key: key.public_key, key_id: key.key_id, lane: key.lane, first_seen: new Date().toISOString() });
      console.log(`published key ${key.key_id} to ${keyPath}`);
    }

    // 2. Today's record (the alarm clock: this request computes the day
    // if nothing has yet), checked against the platform's own key.
    const record = await fetchJsonPatiently(`${args.platform}/api/anchors/today`, args.waitMs);
    checkRecord(record, args.environment, envDir);
    console.log(`record: ${record.environment} ${record.day} log ${record.log_id} watermark ${record.watermark} leaves ${record.leaf_count} root ${record.root} key ${record.key_id}: signature verified`);
    const outcome = await publishRecord(record, envDir, args.calendars, { late: false });
    if (outcome.skipped) summary.skipped = outcome.path;
    else summary.stamped = outcome;

    // 3. Any earlier recorded day the home lacks is stamped now and
    // labeled late: the proof then says the record existed by the late
    // stamp's block, which is weaker than a same-day stamp and better
    // than nothing (the platform's watchdog raises no_proof for these).
    const listed = await fetchJsonPatiently(`${args.platform}/api/anchors/days?limit=400`, args.waitMs);
    for (const past of Array.isArray(listed.days) ? listed.days : []) {
      if (past.day === record.day) continue;
      if (existsSync(join(envDir, String(past.log_id), `${past.day}.json`))) continue;
      checkRecord(past, args.environment, envDir);
      const lateOutcome = await publishRecord(past, envDir, args.calendars, { late: true });
      if (!lateOutcome.skipped) summary.late.push(lateOutcome);
    }
  }

  // 3. Upgrade every pending proof in this environment.
  if (args.upgrade) {
    for (const path of listProofFiles(envDir)) {
      const proof = readJson(path);
      if (proof?.timestamp?.status !== 'pending') continue;
      const parsed = parseOts(Buffer.from(proof.timestamp.ots_base64, 'base64'));
      const changed = await upgradeTimestamp(parsed.timestamp);
      if (!changed) continue;
      const bitcoin = attestationsOf(parsed.timestamp).filter((a) => a.type === 'bitcoin');
      const ots = serializeOts(parsed.digest, parsed.timestamp);
      proof.timestamp.ots_base64 = ots.toString('base64');
      proof.timestamp.upgraded_at = new Date().toISOString();
      if (bitcoin.length > 0) {
        proof.timestamp.status = 'confirmed';
        proof.timestamp.bitcoin = { height: Math.min(...bitcoin.map((b) => b.height)), attested_merkle_root: Buffer.from(bitcoin[0].msg).reverse().toString('hex') };
      }
      writeJson(path, proof);
      summary.upgraded.push({ path, status: proof.timestamp.status, height: proof.timestamp.bitcoin?.height ?? null });
      console.log(`upgraded ${path}: ${proof.timestamp.status}${proof.timestamp.bitcoin ? ` at Bitcoin block ${proof.timestamp.bitcoin.height}` : ' (more attestations, still pending)'}`);
    }
  }

  // 4. The index the platform reads.
  const days = listProofFiles(envDir).map((path) => {
    const p = readJson(path);
    return {
      log_id: p.log_id, day: p.day, watermark: p.watermark, leaf_count: p.leaf_count, root: p.root, key_id: p.key_id,
      status: p.timestamp?.status ?? 'unknown', height: p.timestamp?.bitcoin?.height ?? null,
      path: path.slice(args.home.length).replace(/^\/+/, ''),
    };
  }).sort((a, b) => (a.day === b.day ? a.log_id.localeCompare(b.log_id) : a.day.localeCompare(b.day)));
  writeJson(join(envDir, 'index.json'), { spec: SPEC, environment: args.environment, generated_at: new Date().toISOString(), days });
  summary.index = { days: days.length, confirmed: days.filter((d) => d.status === 'confirmed').length, pending: days.filter((d) => d.status === 'pending').length };
  console.log(`index: ${summary.index.days} day(s), ${summary.index.confirmed} confirmed, ${summary.index.pending} pending`);
  console.log(JSON.stringify({ summary }));
}

export {
  canonical, keyIdOf, verifyRecord, stampDigestOf, sha256,
  Reader, Writer, readTimestamp, writeTimestamp, parseOts, serializeOts, mergeTimestamp, attestationsOf, prunePending,
  stampDigest, upgradeTimestamp, DEFAULT_CALENDARS,
};

if (process.argv[1]?.endsWith('notary.mjs')) {
  main().then(() => process.exit(0), (err) => {
    console.error(`notary: ${err.message}`);
    process.exit(1);
  });
}
