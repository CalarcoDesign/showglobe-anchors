# Showglobe anchors

In Athens, the results of the Dionysia, the city's great drama festival, were cut into marble and set up where anyone could read them: the year, who paid for the chorus, which poets won, with new entries added in the years that followed. More than two thousand years later, the surviving fragments of that stone, which scholars call the Fasti, still say so. These proofs are inspired by it, for a logbook: one fingerprint a day, committed where no one, including us, can recarve it, so whoever comes after us can know that what they hold is what was written.

Only fingerprints are published here, never the record itself; the record stays with whoever keeps the logbook.

## What a proof says

Each file under `staging/<log_id>/<day>.json` carries, for one calendar
day: a root hash over the logbook as of that day, the number of entries
it covers, an Ed25519 signature over those fields, and a public
timestamp.

The two carry different claims and neither replaces the other. The
signature says the operator attested this root for this day. It does not
say when. The timestamp says these bytes existed before a particular
Bitcoin block was mined. It does not say who made them.

A timestamp reads `pending` until the calendar's path has been checked
against a real block header, and `confirmed` afterward.
`staging/index.json` lists every published day with its status.

## How to verify

The verifier is a single file. It needs Node.js 18 or newer and nothing
else: no dependencies, no network unless you ask for it, and no access
to the platform.

    node verifier/showglobe-verify.mjs \
      --proof staging/<log_id>/<day>.json \
      --dump <events.jsonl> \
      --public-key @staging/keys/ed25519-<sixteen hex>.json

To inspect a timestamp on its own, with no proof and no dump:

    node verifier/showglobe-verify.mjs --ots-info <file.ots>

Optional flags: `--day YYYY-MM-DD` and `--environment <name>` assert
what you expect the proof to be for; `--online` fetches the block
headers from a public explorer; `--bitcoin-merkle-root <height>:<hex>[:<unix time>]`
supplies a header you already trust instead; `--json` prints the full
result as JSON.

One input is not published here. `--dump` is a canonical, line-delimited
export of the logbook, and only whoever keeps the logbook can give you
one. Without it the verifier cannot recompute the root. With the proof
and the key alone you can still check the signature, the stamp digest,
and the Bitcoin timestamp.

Take the public key from `staging/keys/`, or from the operator directly.
The verifier refuses to take a key from a proof file.

`verifier/SPEC.md` is the specification the verifier implements. It is
the whole of what is needed to write your own.

## How to read a result

The last line is the verdict, and the exit code says the same thing, so
a script can use it directly.

    VERIFIED (code): exit 0
        the day checks out and its timestamp is confirmed against a
        block header

    PENDING (code): exit 2
        the signature and the root verify, but the timestamp is still
        pending, or no block header was supplied to check a confirmed
        one against

    REJECTED (code): exit 1
        the day does not check out; the code and the detail say why

Above the verdict, each `[ok]` line is a check that passed, each
`[warning]` line is something worth looking at that is not a rejection,
and each `[online]` line shows a block header that was fetched. Every
rejection names a reason code. Nothing exits 0 without printing a
verdict.

## Layout

    README.md
    verifier/showglobe-verify.mjs     the verifier
    verifier/SPEC.md                  the specification it implements
    notary/notary.mjs                 the script that publishes the proofs
    staging/keys/                     the public keys
    staging/<log_id>/<day>.json       one proof per day
    staging/index.json                every published day and its status

`staging` is a rehearsal environment. Which environment a proof belongs
to is a field inside the record, under the signature and under the stamp
digest, so a rehearsal proof cannot be mistaken for a real one. Proofs
are grouped into directories by the logbook they cover.

The guarantee that nobody, including the operator, can quietly change a
proof comes from the Bitcoin anchor, not from this repository. This
repository is for convenience and discovery. Its own default branch
accepts no force pushes and no deletions.
