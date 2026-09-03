#!/usr/bin/env node
// The Showglobe anchoring notary (Packet 14), the external side of the
// daily job. It runs where no secret of any kind lives: it reads the
// day's public record from the platform's read-only endpoint, checks
// the platform's own signature against the platform's own published
// key, hands the record's digest to the public OpenTimestamps
// calendars, publishes the pending proof into the proof home, stamps
// late any earlier recorded day the home lacks, upgrades every pending
// proof it can, and rewrites the environment's index. The intended home
// is a scheduled workflow in a public repository, which makes the
// workflow log its own public record and its native failure
// notification a free second alarm that does not depend on the platform
// being up.
//
//   node notary.mjs --environment staging --platform https://showglobe-staging.onrender.com \
//        [--home <dir>] [--calendars <url,url>] [--explorer <url>] [--wait-ms 300000] \
//        [--no-upgrade] [--no-stamp]
//
// Standard library only, one file, like the verifier beside it. Every
// outbound request is printed as one JSON line (what left: the URL, the
// headers this script sets, the byte count, the sha256 of the bytes) for
// the SG-PN-001 egress record. Redirects are never followed.
//
// Trust, after the pre-closeout audit. A proof is marked confirmed only
// after the attested merkle root has been checked against a block
// header from a public explorer (the block's own hash, merkle root, and
// time are then published beside the proof); a calendar's word alone
// never confirms anything, and a calendar that has not answered keeps
// its pending attestation. Upgrade requests go only to the calendar
// hosts the run was configured with and the public calendars' own
// domains. One misbehaving calendar, one unverifiable past day, or one
// bad index entry is contained: it is recorded, the run continues, the
// index is written, and the run exits non-zero at the end so the
// failure email still fires while the day's proof still reaches the
// home. A published day whose record the platform now serves
// differently is refused, never overwritten.

import { createHash, createPublicKey, randomBytes, verify as cryptoVerify } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

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
const DEFAULT_EXPLORER = 'https://mempool.space/api';
const TRUSTED_CALENDAR_SUFFIXES = ['opentimestamps.org', 'eternitywall.com', 'catallaxy.com'];
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
const USER_AGENT = 'showglobe-notary/1';
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const LOG_ID = /^(undeclared|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const KEY_ID = /^ed25519:[0-9a-f]{16}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const MAX_CALENDAR_BODY = 65536;
const MAX_DEPTH = 256;

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

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

// Every outbound request: the headers this script sets are recorded
// beside the URL and the body digest; redirects are reported as
// failures and never followed, so a listed host can never hand the
// request to an unlisted one (audit finding).
async function httpFetch(url, { method = 'GET', body = null, accept = 'application/json', timeoutMs = 20000 } = {}) {
  const headers = { accept, 'user-agent': USER_AGENT };
  if (body !== null) headers['content-type'] = 'application/octet-stream';
  let res;
  let error = null;
  try {
    res = await fetch(url, { method, headers, body: body ?? undefined, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
  } catch (err) {
    error = err.message;
  }
  const redirected = res ? res.status >= 300 && res.status < 400 : false;
  egress({
    method, url, headers_sent: headers,
    body_bytes: body === null ? 0 : body.length,
    body_sha256: body === null ? null : sha256(body).toString('hex'),
    status: res ? res.status : null,
    redirect_refused: redirected || undefined,
    error,
  });
  if (error !== null) throw new Error(`${method} ${url}: ${error}`);
  if (redirected) throw new Error(`${method} ${url}: answered a redirect (${res.status}), which this script never follows`);
  return res;
}

async function readBounded(res, max) {
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > max) throw new Error(`response of ${buf.length} bytes exceeds the ${max} byte cap`);
  return buf;
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
  done() { return this.pos === this.buf.length; }
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

// An attestation payload must be consumed whole, as the reference
// client requires (audit finding: trailing bytes were accepted here and
// refused there).
function readAttestation(r) {
  const tag = r.bytes(8).toString('hex');
  const payload = r.varbytes(8192);
  const pr = new Reader(payload);
  let out;
  if (tag === ATTESTATION_PENDING) {
    const uri = pr.varbytes(1000).toString('utf8');
    if (!/^[A-Za-z0-9._\/:-]+$/.test(uri)) throw new Error('ots: pending attestation uri has forbidden characters');
    out = { type: 'pending', tag, uri };
  } else if (tag === ATTESTATION_BITCOIN) {
    out = { type: 'bitcoin', tag, height: pr.varuint() };
  } else if (tag === ATTESTATION_LITECOIN) {
    out = { type: 'litecoin', tag, height: pr.varuint() };
  } else {
    return { type: 'unknown', tag, payload };
  }
  if (!pr.done()) throw new Error('ots: attestation payload has trailing bytes');
  return out;
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
  return `${op.tag.toString(16).padStart(2, '0')}:${op.arg ? op.arg.toString('hex') : ''}`;
}

function readTimestamp(r, msg, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error(`ots: nesting deeper than ${MAX_DEPTH}`);
  const node = { msg, attestations: [], ops: [] };
  const step = (tag) => {
    if (tag === 0x00) node.attestations.push(readAttestation(r));
    else {
      const op = readOp(r, tag);
      const next = applyOp(op, msg);
      if (next.length > MAX_MESSAGE) throw new Error('ots: message too long');
      node.ops.push({ op, child: readTimestamp(r, next, depth + 1) });
    }
  };
  let tag = r.byte();
  while (tag === 0xff) { step(r.byte()); tag = r.byte(); }
  step(tag);
  return node;
}

function writeTimestamp(w, node) {
  const atts = [...node.attestations].sort((a, b) => (attestationKey(a) < attestationKey(b) ? -1 : attestationKey(a) > attestationKey(b) ? 1 : 0));
  const ops = [...node.ops].sort((a, b) => (opKey(a.op) < opKey(b.op) ? -1 : opKey(a.op) > opKey(b.op) ? 1 : 0));
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
  if (!r.done()) throw new Error('ots: trailing bytes');
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

// A calendar's answer is read for the message it was asked about and
// must be consumed whole.
function readCalendarTimestamp(body, msg) {
  const r = new Reader(body);
  const ts = readTimestamp(r, msg);
  if (!r.done()) throw new Error('ots: calendar response has trailing bytes');
  return ts;
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
      const body = await readBounded(res, MAX_CALENDAR_BODY);
      mergeTimestamp(commitment, readCalendarTimestamp(body, commitment.msg));
      accepted.push(cal);
    } catch (err) {
      refused.push({ calendar: cal, error: err.message });
    }
  }
  if (accepted.length === 0) throw new Error(`no calendar accepted the digest: ${JSON.stringify(refused)}`);
  return { timestamp: root, accepted, refused };
}

// --- Confirmation is the block's word, not the calendar's.

function calendarHostAllowed(uri, allowedHosts) {
  let u;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (LOOPBACK_HOSTS.has(u.hostname)) return allowedHosts.has(u.hostname);
  if (u.protocol !== 'https:') return false;
  if (allowedHosts.has(u.hostname)) return true;
  return TRUSTED_CALENDAR_SUFFIXES.some((s) => u.hostname === s || u.hostname.endsWith(`.${s}`));
}

async function fetchBlockHeader(explorer, height) {
  const base = explorer.replace(/\/$/, '');
  const hashRes = await httpFetch(`${base}/block-height/${height}`, { accept: 'text/plain', timeoutMs: 15000 });
  if (!hashRes.ok) throw new Error(`the explorer refused block height ${height}: ${hashRes.status}`);
  const hash = (await readBounded(hashRes, 4096)).toString('utf8').trim();
  if (!HEX64.test(hash)) throw new Error('the explorer returned a malformed block hash');
  const blockRes = await httpFetch(`${base}/block/${hash}`, { timeoutMs: 15000 });
  if (!blockRes.ok) throw new Error(`the explorer refused block ${hash}: ${blockRes.status}`);
  const block = JSON.parse((await readBounded(blockRes, 65536)).toString('utf8'));
  if (block.height !== height) throw new Error(`the explorer answered height ${block.height} for ${height}`);
  const merkle = String(block.merkle_root ?? '').toLowerCase();
  if (!HEX64.test(merkle)) throw new Error('the explorer returned a malformed merkle root');
  return { hash, merkle_root: merkle, time: Number(block.timestamp) };
}

// Upgrade: each pending attestation whose calendar is allowed is asked
// once; a calendar's subtree is merged in place of ITS pending
// attestation only when the block header it names checks out against
// the explorer. Nothing else is pruned; a failure of any one calendar
// or of the explorer is recorded and the rest continue.
async function upgradeTimestamp(node, { allowedHosts, explorer, headerCache }) {
  const outcome = { changed: false, verified: [], refused: [] };
  async function visit(n) {
    for (const a of [...n.attestations]) {
      if (a.type !== 'pending') continue;
      if (!calendarHostAllowed(a.uri, allowedHosts)) {
        outcome.refused.push({ calendar: a.uri, reason: 'host not allowed' });
        continue;
      }
      const url = `${a.uri.replace(/\/$/, '')}/timestamp/${n.msg.toString('hex')}`;
      let res;
      try {
        res = await httpFetch(url, { accept: 'application/vnd.opentimestamps.v1', timeoutMs: 15000 });
      } catch (err) {
        outcome.refused.push({ calendar: a.uri, reason: err.message });
        continue;
      }
      if (res.status !== 200) {
        await res.arrayBuffer().catch(() => null);
        continue;
      }
      let sub;
      try {
        sub = readCalendarTimestamp(await readBounded(res, MAX_CALENDAR_BODY), n.msg);
      } catch (err) {
        outcome.refused.push({ calendar: a.uri, reason: `unreadable answer: ${err.message}` });
        continue;
      }
      const bitcoin = attestationsOf(sub).filter((b) => b.type === 'bitcoin');
      if (bitcoin.length === 0) {
        outcome.refused.push({ calendar: a.uri, reason: 'answered without a Bitcoin attestation' });
        continue;
      }
      let header;
      try {
        const b = bitcoin[0];
        if (!Number.isInteger(b.height) || b.height < 1 || b.height > 2147483647) throw new Error(`implausible block height ${b.height}`);
        header = headerCache.get(b.height) ?? (await fetchBlockHeader(explorer, b.height));
        headerCache.set(b.height, header);
        const attested = Buffer.from(b.msg).reverse().toString('hex');
        if (attested !== header.merkle_root) throw new Error(`block ${b.height}: the calendar's path ends at ${attested}, the explorer's header says ${header.merkle_root}`);
        outcome.verified.push({ calendar: a.uri, height: b.height, merkle_root: header.merkle_root, block_hash: header.hash, block_time: header.time });
      } catch (err) {
        outcome.refused.push({ calendar: a.uri, reason: err.message });
        continue;
      }
      mergeTimestamp(n, sub);
      n.attestations = n.attestations.filter((x) => attestationKey(x) !== attestationKey(a));
      outcome.changed = true;
    }
    for (const { child } of n.ops) await visit(child);
  }
  await visit(node);
  return outcome;
}

// --- The run.

function parseArgs(argv) {
  const out = { home: '.', calendars: DEFAULT_CALENDARS, explorer: DEFAULT_EXPLORER, waitMs: 300000, upgrade: true, stamp: true };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === '--environment') out.environment = next();
    else if (a === '--platform') out.platform = next().replace(/\/$/, '');
    else if (a === '--home') out.home = next();
    else if (a === '--calendars') out.calendars = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--explorer') out.explorer = next();
    else if (a === '--wait-ms') out.waitMs = Number(next());
    else if (a === '--no-upgrade') out.upgrade = false;
    else if (a === '--no-stamp') out.stamp = false;
    else throw new Error(`unknown argument ${a}`);
  }
  if (!out.environment || !/^[a-z]+$/.test(out.environment)) throw new Error('--environment is required (staging or production)');
  if (out.stamp && !out.platform) throw new Error('--platform is required');
  out.home = resolve(out.home);
  return out;
}

// The platform may be asleep (a free instance wakes in about a minute):
// keep asking until it answers or the wait budget ends, but only while
// the answer is the kind that can change (a network error, 429, or a
// 5xx); any other status is final and is not retried (audit finding).
async function fetchJsonPatiently(url, waitMs) {
  const deadline = Date.now() + waitMs;
  let last = null;
  for (;;) {
    try {
      const res = await httpFetch(url, { timeoutMs: 60000 });
      const text = (await readBounded(res, 4 * 1024 * 1024)).toString('utf8');
      if (res.ok) return JSON.parse(text);
      let code = null;
      try { code = JSON.parse(text)?.error?.code ?? null; } catch { code = null; }
      if (res.status === 503 && (code === 'anchor_unconfigured' || code === 'anchor_blocked')) throw new Error(`the platform reports ${code} at ${url}`);
      if (res.status !== 429 && res.status < 500) throw new Error(`${url} answered ${res.status}${code ? ` (${code})` : ''}, which is final`);
      last = `${res.status}${code ? ` (${code})` : ''}`;
    } catch (err) {
      if (/reports anchor_|which is final/.test(String(err.message))) throw err;
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
    if (entry === 'keys' || entry === 'index.json' || !statSync(p).isDirectory() || !LOG_ID.test(entry)) continue;
    for (const f of readdirSync(p)) if (/^\d{4}-\d{2}-\d{2}\.json$/.test(f)) out.push(join(p, f));
  }
  return out.sort();
}

// A record from the platform is trusted only after it checks out: the
// shapes first (so no filesystem path is built from an unchecked
// value), then the key the platform itself publishes, the signature,
// the digest, and the labels.
function checkRecord(record, environment, envDir) {
  for (const k of RECORD_KEYS) if (!(k in record)) throw new Error(`a record lacks ${k}`);
  if (record.spec !== SPEC) throw new Error(`a record is spec ${record.spec}`);
  if (record.environment !== environment) throw new Error(`a record is for ${record.environment}, not ${environment}`);
  if (typeof record.day !== 'string' || !DAY.test(record.day)) throw new Error('a record has a malformed day');
  if (typeof record.log_id !== 'string' || !LOG_ID.test(record.log_id)) throw new Error(`the record for ${record.day} has a malformed log_id`);
  if (typeof record.public_key !== 'string' || !HEX64.test(record.public_key)) throw new Error(`the record for ${record.day} has a malformed public key`);
  if (typeof record.key_id !== 'string' || !KEY_ID.test(record.key_id) || record.key_id !== keyIdOf(record.public_key)) throw new Error(`the record for ${record.day} names key ${record.key_id}, which does not name its public key`);
  if (typeof record.stamp_digest !== 'string' || !HEX64.test(record.stamp_digest)) throw new Error(`the record for ${record.day} has a malformed stamp_digest`);
  const keyPath = join(envDir, 'keys', `${record.key_id.replace(':', '-')}.json`);
  if (!existsSync(keyPath)) throw new Error(`the record for ${record.day} is signed by ${record.key_id}, a key this home has never seen from the platform`);
  if (readJson(keyPath).public_key !== record.public_key) throw new Error(`the record for ${record.day} names key ${record.key_id} but carries a different public key`);
  if (!verifyRecord(record)) throw new Error(`the record for ${record.day} does not verify against key ${record.key_id}`);
  if (record.stamp_digest !== stampDigestOf(record).toString('hex')) throw new Error(`the stamp_digest for ${record.day} is not the sha256 of the record`);
}

// Append-only in practice: a day already published with the same
// record is skipped; with a different record it is refused loudly and
// the file is left as it was. Otherwise the digest is stamped and the
// pending proof written, labeled late when it is not today's.
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
  const allowedHosts = new Set(args.calendars.map(hostOf).filter(Boolean));
  const summary = { environment: args.environment, stamped: null, late: [], upgraded: [], skipped: null, index: null, failures: [] };
  const fail = (what, err) => {
    summary.failures.push({ what, reason: err.message });
    console.error(`notary: ${what}: ${err.message}`);
  };

  if (args.stamp) {
    // 1. The platform's key, patiently.
    const key = await fetchJsonPatiently(`${args.platform}/api/anchors/key`, args.waitMs);
    if (key.environment !== args.environment) throw new Error(`the platform says it is ${key.environment}, not ${args.environment}`);
    if (!HEX64.test(String(key.public_key)) || key.key_id !== keyIdOf(key.public_key)) throw new Error('the platform published a malformed key');
    if ((args.environment === 'staging' || args.environment === 'production') && key.lane !== 'real') {
      throw new Error(`the platform's key lane is ${key.lane}; a ${args.environment} day is stamped only under a real key`);
    }
    const keyPath = join(envDir, 'keys', `${key.key_id.replace(':', '-')}.json`);
    if (existsSync(keyPath)) {
      if (readJson(keyPath).public_key !== key.public_key) throw new Error(`the key file ${keyPath} disagrees with the platform's key`);
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

    // 3. Every earlier recorded day: one the home lacks is stamped now
    // and labeled late (the proof then says the record existed by the
    // late stamp's block, weaker than a same-day stamp and better than
    // nothing); one the home holds must still match what the platform
    // serves (a rewritten past is refused, never overwritten). Each day
    // is contained: a failure is recorded and the rest continue.
    let listed = { days: [] };
    try {
      listed = await fetchJsonPatiently(`${args.platform}/api/anchors/days?limit=400`, args.waitMs);
    } catch (err) {
      fail('listing the platform\'s days', err);
    }
    for (const past of Array.isArray(listed.days) ? listed.days : []) {
      if (typeof past !== 'object' || past === null || past.day === record.day) continue;
      try {
        checkRecord(past, args.environment, envDir);
        const path = join(envDir, past.log_id, `${past.day}.json`);
        if (existsSync(path)) {
          const published = readJson(path);
          if (published.stamp_digest !== past.stamp_digest) throw new Error(`the platform now serves a different record for ${past.day} than the one published (stamp digest ${past.stamp_digest} versus ${published.stamp_digest})`);
          continue;
        }
        const lateOutcome = await publishRecord(past, envDir, args.calendars, { late: true });
        if (!lateOutcome.skipped) summary.late.push(lateOutcome);
      } catch (err) {
        fail(`the past day ${typeof past.day === 'string' ? past.day : '(malformed)'}`, err);
      }
    }
  }

  // 4. Upgrade every pending proof in this environment, each contained.
  if (args.upgrade) {
    const headerCache = new Map();
    for (const path of listProofFiles(envDir)) {
      try {
        const proof = readJson(path);
        if (proof?.timestamp?.status !== 'pending') continue;
        const parsed = parseOts(Buffer.from(proof.timestamp.ots_base64, 'base64'));
        const outcome = await upgradeTimestamp(parsed.timestamp, { allowedHosts, explorer: args.explorer, headerCache });
        for (const r of outcome.refused) console.log(`upgrade of ${path}: ${r.calendar}: ${r.reason}`);
        if (!outcome.changed) continue;
        const ots = serializeOts(parsed.digest, parsed.timestamp);
        proof.timestamp.ots_base64 = ots.toString('base64');
        proof.timestamp.upgraded_at = new Date().toISOString();
        const lowest = [...outcome.verified].sort((a, b) => a.height - b.height)[0];
        proof.timestamp.status = 'confirmed';
        proof.timestamp.bitcoin = { height: lowest.height, merkle_root: lowest.merkle_root, block_hash: lowest.block_hash, block_time: lowest.block_time };
        proof.timestamp.attestations = outcome.verified.map((v) => ({ calendar: v.calendar, height: v.height, merkle_root: v.merkle_root }));
        writeJson(path, proof);
        summary.upgraded.push({ path, status: 'confirmed', height: lowest.height });
        console.log(`upgraded ${path}: confirmed at Bitcoin block ${lowest.height} (${outcome.verified.length} calendar path(s) verified against the explorer's header)`);
      } catch (err) {
        fail(`upgrading ${path}`, err);
      }
    }
  }

  // 5. The index the platform reads, written whatever happened above.
  const days = listProofFiles(envDir).flatMap((path) => {
    try {
      const p = readJson(path);
      return [{
        log_id: p.log_id, day: p.day, watermark: p.watermark, leaf_count: p.leaf_count, root: p.root, key_id: p.key_id,
        status: p.timestamp?.status ?? 'unknown', height: p.timestamp?.bitcoin?.height ?? null,
        late: p.timestamp?.late ?? null, submitted_at: p.timestamp?.submitted_at ?? null,
        path: relative(args.home, path),
      }];
    } catch (err) {
      fail(`indexing ${path}`, err);
      return [];
    }
  }).sort((a, b) => (a.day === b.day ? a.log_id.localeCompare(b.log_id) : a.day.localeCompare(b.day)));
  writeJson(join(envDir, 'index.json'), { spec: SPEC, environment: args.environment, generated_at: new Date().toISOString(), days });
  summary.index = { days: days.length, confirmed: days.filter((d) => d.status === 'confirmed').length, pending: days.filter((d) => d.status === 'pending').length };
  console.log(`index: ${summary.index.days} day(s), ${summary.index.confirmed} confirmed, ${summary.index.pending} pending`);
  console.log(JSON.stringify({ summary }));
  if (summary.failures.length > 0) throw new Error(`${summary.failures.length} failure(s) in this run; the index and every proof that could be written were written`);
}

export {
  canonical, keyIdOf, verifyRecord, stampDigestOf, sha256,
  Reader, Writer, readTimestamp, writeTimestamp, parseOts, serializeOts, mergeTimestamp, attestationsOf,
  stampDigest, upgradeTimestamp, calendarHostAllowed, fetchBlockHeader, DEFAULT_CALENDARS, TRUSTED_CALENDAR_SUFFIXES,
};

if (process.argv[1]?.endsWith('notary.mjs')) {
  main().then(() => process.exit(0), (err) => {
    console.error(`notary: ${err.message}`);
    process.exit(1);
  });
}
