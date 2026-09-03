# Showglobe anchoring specification, showglobe-anchor/1

Document version 1.1, 3 September 2026. Written under Packet 14
(SG-PKT-14 v1.2). Change notes: v1.1, after the packet's pre-closeout
audit: section 8 lists every field the notary writes in a proof's
timestamp object (the late label, the calendars that refused, the
block's hash, merkle root, and time, and the verified attestations) and
says what late means for the proven bound; the key file is named as
the notary names it; section 9 records that a verifier takes the day,
the environment, and the log id from the proof home's own path when it
is not told them, and refuses a proof file as a key source; section 10
says the development key signs only where the environment says local
or test out loud. Nothing in sections 2 through 7 changed, so the
identifier stays showglobe-anchor/1. v1.0 is preserved at
docs/superseded/verifier_SPEC_v1.0.md. If this document is revised,
superseded versions are preserved under docs/superseded/ and the change
notes here are extended. A change to anything in sections 2 through 7
is a new specification identifier, never a revision of this one:
proofs carry the identifier they were made under, and a verifier
refuses one it does not implement.

This is the whole of what a stranger needs to recompute a day's root
from a log export, check the operator's signature, and check the public
timestamp, with no access to the application and no trust in it. The
reference verifier beside this file (showglobe-verify.mjs) implements
every section below using only the Node.js standard library.

## 1. What is committed to

The permanent record is the append-only events table: every row, in
ascending event id order, reduced to exactly eleven fields:

    id, event_type, schema_version, occurred_at, recorded_at,
    authored_by, acting_for, on_behalf_of, context_id, correlation_id,
    payload

Nothing else is committed to. Every mutable table (identity records,
content, authentication, projections, mail seats, media receipts, and
the anchoring bookkeeping itself) is excluded by design: anchoring
mutable data is meaningless, and anchoring identity data would publish a
commitment to material people are entitled to have erased. Media bytes
are covered transitively, because attachment events carry the sha256 of
the stored bytes.

## 2. The leaf

One leaf per event row. The leaf is the UTF-8 encoding of the RFC 8785
(JSON Canonicalization Scheme) serialization of a JSON object with
exactly the eleven keys of section 1 and these value rules:

- id: a JSON number, the event id (an integer; the log's ids stay below
  2^53 by construction).
- event_type, authored_by: JSON strings.
- schema_version: a JSON number (an integer).
- occurred_at, recorded_at: JSON strings in UTC with exactly six
  fractional digits and a trailing Z, `YYYY-MM-DDTHH:MM:SS.ffffffZ`
  (Postgres keeps microseconds; fewer stored digits are zero padded).
- acting_for, on_behalf_of, context_id, correlation_id: a JSON string
  or JSON null.
- payload: the stored JSON value, canonicalized by the same RFC 8785
  rules (object keys sorted by UTF-16 code units, no whitespace,
  strings and numbers serialized as ECMAScript's JSON.stringify does).

Consequence, stated: RFC 8785 commits to the IEEE-754 double value of a
JSON number, not its decimal spelling, so a payload number written as
1.0 or 1e2 is committed as 1 or 100, and a number outside the double-
safe range is committed as its nearest double. The event vocabulary
carries identifiers as strings and no such numbers; the platform warns
when it meets one. The leaf has no trailing newline. The canonical dump
(section 8) writes one leaf per line followed by a single line feed.

## 3. The leaf hash

    leaf_hash = SHA-256(0x00 || leaf bytes)

(RFC 6962 section 2.1.)

## 4. The tree and the root

The day's root is the RFC 6962 section 2.1 Merkle Tree Hash over the
leaf hashes of every row with id less than or equal to the day's
watermark, in ascending id order:

    MTH({}) = SHA-256("")
    MTH({d0}) = leaf_hash(d0)
    MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
      where k is the largest power of two strictly less than n

The watermark is the highest event id the root covers. leaf_count is
the number of rows with id at or below the watermark; ids skipped by
aborted inserts are not leaves and do not count. A day on which no
event was appended keeps the previous watermark and produces the same
root under a new day and a new signature: "nothing changed" is itself a
claim worth proving.

This shape is chosen because RFC 6962 already defines inclusion proofs
(one leaf is in the record) and consistency proofs (an earlier day's
record is a prefix of a later day's); this packet does not build them,
and this shape permits them without redesign.

## 5. The statement

The statement is the RFC 8785 serialization of a JSON object with
exactly these keys:

    spec          "showglobe-anchor/1"
    environment   one of local, test, staging, production
    log_id        the uuid carried by the latest platform.launch.declared
                  event at or below the watermark, or the literal
                  string "undeclared"
    day           the UTC calendar day, YYYY-MM-DD
    watermark     a JSON number, the highest event id covered
    leaf_count    a JSON number, the number of leaves
    root          the root of section 4 as 64 lowercase hex characters
    computed_at   the instant of computation, UTC, six fractional
                  digits, trailing Z

Every one of these fields is under the signature, so a signature cannot
be moved to another day, another environment, another log, or another
watermark.

## 6. The signature

Ed25519 (RFC 8032), over the bytes

    UTF-8("showglobe-anchor/1\n") || statement bytes

The public key is the raw 32-byte Ed25519 public key as 64 lowercase
hex characters. The signature is the raw 64-byte signature as 128
lowercase hex characters. key_id is the string "ed25519:" followed by
the first sixteen hex characters of SHA-256(public key bytes); it names
a key for the record and is not itself trusted.

Meaning: the signature says "the operator attested this root for this
day". It does not say when. A signature can be forged by anyone who
later obtains the key, which is why the timestamp of section 7 covers
the signature as well as the root.

## 7. The record, the stamp digest, and the timestamp

The record is the statement's eight fields plus public_key, key_id, and
signature. The stamp digest is

    stamp_digest = SHA-256(RFC 8785 serialization of the record)

This is the thirty-two bytes handed to the public timestamp service. It
carries no content: a hash of a hash, a signature, a day, and counts.
The OpenTimestamps client protocol adds its own sixteen-byte random
nonce before submission (append the nonce, then SHA-256), so a calendar
server sees neither the digest nor anything derivable from it.

The timestamp is an OpenTimestamps detached timestamp (the .ots file
format defined by the OpenTimestamps reference implementation,
python-opentimestamps) whose header digest is the stamp digest. A
complete proof walks from that digest through append, prepend, and hash
operations to a Bitcoin block header attestation naming a block height;
the thirty-two-byte message at that attestation is the merkle root of
that block's header, in the header's own byte order (which is the byte
reverse of the hexadecimal that block explorers display).

Meaning: the timestamp says "these bytes existed before this block was
mined". It does not say who made them. Both the signature and the
timestamp are needed; neither substitutes for the other.

## 8. The proof file and the canonical dump

The proof file for a day is a JSON document carrying the record's
eleven fields, stamp_digest, and a timestamp object:

    timestamp.status              "pending" or "confirmed"
    timestamp.late                false when the day was stamped on its
                                  own day by the notary's run, true when
                                  a later run stamped a day the home
                                  lacked; a label, not a signed fact
    timestamp.ots_base64          the .ots bytes, base64
    timestamp.submitted_at        when the digest was submitted
    timestamp.calendars           the calendar servers that accepted it
    timestamp.refused_calendars   the ones that did not, with the reason
    timestamp.upgraded_at         when a confirmation was recorded
    timestamp.bitcoin             present once confirmed: the height,
                                  the block's merkle root in explorer
                                  order, the block hash, and the block
                                  time as the notary read them from a
                                  public block explorer when it checked
                                  the calendar's path against the header
    timestamp.attestations        every calendar path the notary checked
                                  against a header, each with its height
                                  and merkle root

Meaning of late, plainly: the proven bound is always the block that
confirms the stamp, whatever the label says. A same-day stamp proves
the record existed by a block mined that day or the next; a late stamp
proves it existed by a later block, which is weaker and better than
nothing. The label is a convenience for readers; a verifier derives the
bound from the block's time (section 9).

Proof files live in the public proof home under
`<environment>/<log_id>/<day>.json`, beside the environment's public
keys under `<environment>/keys/ed25519-<sixteen hex>.json` (the key id
with its colon written as a hyphen, so the name is a plain file name).
The home is for convenience and discoverability; the guarantee that
nobody can quietly edit a proof comes from the block chain, not from
the home.

The canonical dump is a line-delimited file of leaves (section 2), one
per line in ascending id order. It is produced by the platform's dump
script from the events table and is the verifier's input; it is the
seed of the future export format and not that export. It is never
published: the log's identifiers are private even though they are not
personal content.

## 9. Verification

Given a dump, a proof file, and a trusted public key (obtained from the
proof home or from the operator, never from the proof file itself), a
verifier accepts the day when all of the following hold:

1. The proof's spec is "showglobe-anchor/1" and its public_key equals
   the trusted key.
2. The signature verifies (section 6) over the statement rebuilt from
   the proof's eight statement fields.
3. In the dump, every line re-canonicalizes to exactly its own bytes,
   ids strictly ascend, the rows with id at or below the proof's
   watermark number exactly leaf_count, and their Merkle Tree Hash
   (sections 3 and 4) equals the proof's root.
4. stamp_digest equals SHA-256 of the record rebuilt from the proof's
   eleven record fields, and the .ots header digest equals it.
5. If the .ots carries a Bitcoin block header attestation, the message
   at that attestation equals the merkle root of the block at that
   height, the verifier having obtained the merkle root from a source
   it trusts (a block explorer, a node, or a pasted value); the block's
   time is then the proven existence bound. If it carries only pending
   attestations, the day is signed and its root is verified but its
   public timestamp is not yet confirmed.
6. If the verifier was asked about a particular day, environment, or
   log, the proof names them. When it was not asked, it takes them from
   the proof home's own path (`<environment>/<log_id>/<day>.json`) when
   the file sits in that layout, so a proof filed under another day's
   name is caught; a plainly named file carries no expectation, and the
   verifier says so.
7. The trusted key never comes from the proof file: a file carrying a
   signature, a root, or a stamp digest is refused as a key source, and
   a keys file whose key id does not name its public key is refused.
8. The block header's time, when the caller supplies it or fetches it,
   is the proven existence bound; the verifier reports it, warns when
   it precedes the record's own computed_at by more than miners' clock
   skew allows, and warns when the confirming block is more than a day
   past the day itself (a late stamp).

Any failure is a rejection with a reason. A proof for one day is never
evidence for another: the day is under the signature and under the
stamp digest.

## 10. The known development key

Runs whose environment says local or test out loud, with no configured
key, sign with a published, non-secret key derived from the seed
SHA-256("showglobe-anchor-dev-key-not-a-secret"). Its records are
labeled by their key_id and are never to be trusted for anything; a
hosted environment without a real key, and any environment that does
not say which it is, refuses to anchor rather than use it, and the
notary refuses to stamp a staging or production day under it.
