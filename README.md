# aileron-anchor

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)

**Anchor [Aileron](https://github.com/aileron-sh/aileron) checkpoints in
Sigstore Rekor, so that deleting the newest checkpoints or truncating the
journal tail becomes detectable from a place the attacker does not control.**

Aileron is a tamper-evident flight recorder for AI agents: a hash-chained JSONL
journal with Ed25519-signed checkpoints. Its library and CLI make no network
calls, ever. That is a deliberate, load-bearing promise, and it leaves one gap
that Aileron's own `SECURITY.md` states plainly: no purely local scheme can
detect that the *most recent* checkpoints were deleted along with the tail of
the journal, because that is indistinguishable from the checkpoints never
having been made.

Closing that gap means writing somewhere the attacker cannot reach. This
package does exactly that, and nothing else, as a separate tool so Aileron
itself stays offline.

## How it works

Every Aileron checkpoint is already an artifact, a signature, and a public key:
the signature is Ed25519 over the canonical JSON of
`{ts, log_path, index, prev_checkpoint_hash, count, tip_hash}`. That is
precisely what a Rekor entry needs.

- **`aileron-anchor push`** uploads one checkpoint (by default the newest) to
  Rekor as a `rekord` entry and appends what Rekor returned to
  `<log>.anchors.jsonl`.
- **`aileron-anchor check`** fetches every anchored entry back, verifies that
  Rekor's response is genuine (signed entry timestamp and inclusion proof
  under Rekor's key), verifies that the entry is the checkpoint we expect (same
  payload hash, same signature bytes, same public key) and that the Ed25519
  signature verifies locally, and only then compares the now Rekor-backed
  `count` and `tip_hash` against the local journal and checkpoint file. It
  also asks Rekor's search index for every entry signed by this key, which is
  what catches a checkpoint deleted together with its anchor record.

Once an anchor exists, an attacker who later truncates the journal, deletes
the newest checkpoint, or rewrites the tail has to also remove an entry from a
public append-only log, which they cannot do.

## Install

```console
$ pip install aileron-anchor
```

Runtime dependencies are `aileron` and `cryptography`; HTTP goes through the
standard library. Python 3.10 or newer.

## Quickstart

```console
$ aileron init                                        # keypair in ./keys (or wherever you keep it)
$ aileron sign-checkpoint run.chain.jsonl --key keys/aileron_ed25519.key
$ aileron-anchor push run.chain.jsonl --key keys/aileron_ed25519.pub
checkpoint 1: count 3, tip 7f3a0c1d9e2b4a6f..., signature verified locally
local journal agrees with the checkpoint
publishing to https://rekor.sigstore.dev: the signed payload (...) become public and permanent
Rekor accepted entry 24296fb24b8ad77a...
Rekor's stored entry matches the checkpoint (hash, signature, public key)
Rekor key: fetched from the Rekor instance itself (trust on first use; ...)
entry: signed entry timestamp verified (log index 1234567, integrated 2026-10-14T09:12:03Z)
entry: inclusion proof verified against a Rekor-signed checkpoint
recorded anchor in run.chain.jsonl.anchors.jsonl
OK: anchor recorded

$ aileron-anchor check run.chain.jsonl --key keys/aileron_ed25519.pub
public key: keys/aileron_ed25519.pub
journal: 3 events, chain intact
checkpoint file: 1 usable checkpoint(s)
Rekor key: fetched from the Rekor instance itself (trust on first use; ...)
anchor 1 (24296fb24b8ad77a...): signed entry timestamp verified (...)
anchor 1 (24296fb24b8ad77a...): inclusion proof verified against a Rekor-signed checkpoint
anchor 1 (24296fb24b8ad77a...): Rekor entry matches the recorded checkpoint and its Ed25519 signature verifies
journal: event 3 matches the anchored tip hash
checkpoint file: holds anchored checkpoint 1
discovery: Rekor lists 1 entry(ies) under this key, 0 not in the anchors file
OK: every anchor verified and the local files agree with Rekor
```

**Pushing to `rekor.sigstore.dev` is permanent and public.** The payload
contains the checkpoint's timestamps, event count, tip hash, and the
`log_path` string Aileron recorded (a filesystem path), together with your
public key. Nothing from the journal's contents is included, but read the
line `push` prints before it uploads, and test against a local Rekor first
(below).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | `push`: anchor recorded. `check`: every anchor verified and the local files agree with Rekor |
| 1 | Could not verify: network error, Rekor unavailable, missing key, nothing anchored. Not a pass |
| 2 | Tamper evidence: the local files disagree with what Rekor holds (`TRUNCATED`, `REWRITTEN`, or a mismatch) |

### Options

Both commands take:

- `--key PEM` the checkpoint public key. Defaults to the `pubkey_path` the
  checkpoint names. A private key PEM or a directory holding
  `aileron_ed25519.pub` also works. Verification hosts never need the
  private key.
- `--rekor-url URL` defaults to `https://rekor.sigstore.dev`.
- `--rekor-pubkey PEM` Rekor's own public key, obtained out of band. Without
  it the key is fetched from the Rekor instance, which is trust on first use.
  For the public instance, `cosign initialize` writes the Sigstore TUF root's
  copy to `~/.sigstore/root/targets/rekor.pub`.
- `--timeout SECONDS` HTTP timeout (default 30).

`push` takes `--index N` to anchor a specific checkpoint instead of the
newest. `check` takes `--no-discover` to skip the search index query (see
limitations).

## What `check` verifies, exactly

For every record in `<log>.anchors.jsonl`:

| Step | Verified cryptographically? | Against what |
|---|---|---|
| Rekor's signed entry timestamp over `{body, integratedTime, logID, logIndex}` | Yes, ECDSA P-256 (or Ed25519) | Rekor's public key; `logID` must be that key's SHA-256 fingerprint |
| Inclusion proof from the entry's leaf hash to the tree root | Yes, RFC 6962 hashing | The root and tree size in Rekor's signed checkpoint note, whose signature is verified with the same key |
| Entry body is a `rekord` whose public key is ours | Yes, keys compared as raw Ed25519 bytes | The local `--key` |
| Entry body's signature bytes equal the recorded checkpoint's signature, and its `data.hash` equals SHA-256 of the checkpoint's signed payload | Yes | The checkpoint carried in the anchor record |
| The Ed25519 signature verifies over the rebuilt payload | Yes | The local key |
| Journal holds at least `count` events and event `count` hashes to `tip_hash`; chain intact | Hash chain only (Aileron's `verify`) | The local journal |
| Checkpoint file still contains the anchored checkpoint | Payload hash comparison | The local checkpoint file |
| Anchors file fields agree with the Rekor entry and with the checkpoint it carries | Comparison | Detects an edited anchors file |

Then, unless `--no-discover`: every entry Rekor's search index lists under the
public key that the anchors file does not mention is fetched, verified the
same way, and matched against the local checkpoint file. An entry no local
checkpoint hashes to is reported as `TRUNCATED`.

The anchors file is never trusted. Everything it says is checked against
Rekor and the key before being used; the only thing it contributes is the
plaintext of the payload, which Rekor does not store.

## The anchors file

`<log>.anchors.jsonl`, one JSON object per line:

```json
{"checkpoint_index": 2, "tip_hash": "...", "count": 5,
 "rekor_url": "https://rekor.sigstore.dev", "uuid": "24296fb2...",
 "log_index": 1234567, "integrated_time": 1760432323,
 "ts": "2026-10-14T09:12:04.118Z", "checkpoint": {"ts": "...", "log_path": "...",
 "index": 2, "prev_checkpoint_hash": "...", "count": 5, "tip_hash": "...",
 "signature": "...", "pubkey_path": "..."}}
```

`checkpoint` is the full checkpoint object. Rekor keeps only the hash of the
signed payload, so the payload itself has to live somewhere local for `check`
to rebuild and verify it after the checkpoint file has been truncated.

## Why `rekord` and not `hashedrekord`

Rekor's `hashedrekord` type stores only the artifact's hash and verifies the
signature against that hash. For Ed25519 keys it does so in the prehashed
`Ed25519ph` mode (sigstore/rekor#1945, sigstore/sigstore#1595), which is a
different signature scheme from the pure Ed25519 that Aileron, and
`cryptography`, produce. A pure Ed25519 signature submitted as a
`hashedrekord` is rejected. The `rekord` type takes the artifact inline and
verifies with the plain Ed25519 verifier over those bytes. A checkpoint
payload is a few hundred bytes, so inlining it costs nothing, and Rekor's
canonical entry drops the content and keeps its SHA-256 anyway.

## Testing against a local Rekor

Never develop against the public instance: every upload there is permanent.
Rekor ships a docker compose file that brings up a full instance on
`http://localhost:3000`:

```console
$ git clone https://github.com/sigstore/rekor && cd rekor
$ docker compose up -d
$ curl -s http://localhost:3000/api/v1/log | head -c 200   # wait until this answers
```

Then run the quickstart against it:

```console
$ aileron-anchor push run.chain.jsonl --key keys/aileron_ed25519.pub --rekor-url http://localhost:3000
$ aileron-anchor check run.chain.jsonl --key keys/aileron_ed25519.pub --rekor-url http://localhost:3000
$ sed -i '$d' run.chain.jsonl.checkpoints.jsonl            # delete the newest checkpoint
$ aileron-anchor check run.chain.jsonl --key keys/aileron_ed25519.pub --rekor-url http://localhost:3000
...
PROBLEM: TRUNCATED: checkpoint 1 is anchored in Rekor but missing from run.chain.jsonl.checkpoints.jsonl
TAMPERED: the local files disagree with what Rekor holds (see PROBLEM lines)
$ echo $?
2
```

Fetch the local instance's key with
`curl http://localhost:3000/api/v1/log/publicKey > rekor-local.pub` and pass
`--rekor-pubkey rekor-local.pub` to exercise the out-of-band path.

## Limitations

- **Detection, not prevention, and only back to the last anchor.** Events
  recorded after the newest anchored checkpoint are protected only by
  Aileron's local guarantees. Anchor as often as the window you can tolerate.
- **One key per journal.** Discovery works by public key. If one key signs
  several journals, entries for the other journals are reported as checkpoints
  missing from this one. Use a key per journal, or `--no-discover` and accept
  that a checkpoint deleted together with its anchor record goes unnoticed.
- **The search index is a Rekor v1 feature.** The public instance serves it
  today; Rekor v2 (tile-based) does not. If the index is unavailable, `check`
  exits 1 and says so rather than quietly passing.
- **Rekor's key is trust on first use by default.** Pass `--rekor-pubkey`.
- **No consistency proofs between runs.** `check` verifies each entry against
  the checkpoint Rekor serves at that moment. It does not persist tree heads
  or verify that the log has grown consistently; a Rekor operator who forks
  the log is outside this threat model (see [SECURITY.md](SECURITY.md)).

## Development

```console
$ python3 -m venv .venv && source .venv/bin/activate
$ pip install -e /path/to/aileron          # or let pip fetch it from PyPI
$ pip install -e ".[dev]"
$ python -m pytest tests/ -q
```

The tests make no network calls. `urllib.request.urlopen` is replaced for
every test with a function that fails, and Rekor is a fake behind the
package's `transport` seam that keeps a real RFC 6962 tree and signs genuine
SETs and checkpoints with a throwaway ECDSA key. Journals and keypairs are
real, created with Aileron's own API in `tmp_path`.

Plain English throughout; see Aileron's `CONTRIBUTING.md` for the conventions
this package follows.

## License

Apache-2.0. See [LICENSE](LICENSE).
