# Showglobe anchors

The public proof home for the Showglobe Casting daily log anchor
(Packet 14). Every day the platform fingerprints its entire permanent
log, signs the fingerprint, and a notary here hands it to the public
OpenTimestamps calendars, which commit it to the Bitcoin block chain
inside one transaction shared by thousands of users. Nothing of the
log itself is here or on the chain: only a root hash, a signature, a
public key, dates, and counts.

- staging/ and production/ each hold keys/<key id>.json (the public
  keys the platform published), <log id>/<day>.json (one proof per
  day per log epoch), and index.json. A rehearsal proof from staging
  can never be mistaken for a real one: the environment is under the
  signature and under the stamp digest.
- verifier/showglobe-verify.mjs checks a day with nothing but a log
  export, a proof file, and a public key, using the Node.js standard
  library only; verifier/SPEC.md is the specification.
- notary/notary.mjs is the script the scheduled workflow runs; it
  holds no secret of any kind.

The guarantee that nobody, including us, can quietly edit a proof
comes from the block chain, not from this repository; this home is
for convenience and discovery.
