# The anchoring notary and the proof home

This directory is the source of record for the external side of the
Showglobe daily anchor (Packet 14, SG-PKT-14). It is copied whole into
the public proof-home repository; the platform side lives in
src/anchoring.js and never leaves the platform.

- notary.mjs: reads the day's public record from the platform's
  read-only endpoint, checks the platform's own signature against the
  key the platform publishes, hands the record's digest to the public
  OpenTimestamps calendars, writes the pending proof, stamps late any
  earlier recorded day the home lacks, upgrades every pending proof it
  can, and rewrites the environment's index. A proof is marked
  confirmed only after the calendar's path has been checked against a
  block header from a public explorer (mempool.space by default); a
  calendar's word alone confirms nothing. Upgrade requests go only to
  the configured calendar hosts and the public calendars' own domains,
  redirects are never followed, and one bad answer, one unverifiable
  past day, or one bad file is recorded and contained rather than
  ending the run. Standard library only; no secret of any kind.
- anchor-notary.yml: the scheduled workflow, to be placed at
  .github/workflows/anchor-notary.yml in the proof-home repository.
- The verifier and its specification (verifier/showglobe-verify.mjs
  and verifier/SPEC.md in this repository) are copied beside the
  proofs so a stranger who finds the home finds the tool.

Layout of the proof home:

    README.md
    verifier/showglobe-verify.mjs
    verifier/SPEC.md
    notary/notary.mjs
    .github/workflows/anchor-notary.yml
    staging/keys/ed25519-<sixteen hex>.json
    staging/<log_id>/<day>.json
    staging/index.json
    production/...                    (from P10C)

Staging and production are separated by directory and by the
environment field inside every record, which is under the signature
and under the stamp digest, so a rehearsal proof can never be mistaken
for a real one. Each rehearsal epoch of staging (each launch
declaration after a wipe) has its own log_id directory; a log that has
not been declared files under `undeclared`.

The uneditable guarantee comes from the Bitcoin anchor, not from the
home: a proof that has reached a block cannot be quietly changed by
anyone, including us, and the home is for convenience and discovery.
The home's own append-only posture is branch protection on its default
branch (no force pushes, no deletions), set once by the repository's
owner; the workflow's automatic token can push to any branch, and that
protection is what bounds it. The workflow's publish step runs even
when the notary step fails, so a day's proof reaches the home whatever
else went wrong, and the notary's non-zero exit still fires the failure
email.
