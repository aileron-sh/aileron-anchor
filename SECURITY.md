# Security Policy

aileron-anchor extends a security tool, and a verification step that passes
when it should not is worse than one that is missing. This document says what
anchoring proves, what it assumes, and what it does not do.

## Reporting a vulnerability

**Please do not open public issues for security vulnerabilities.**

Report privately via GitHub Private Vulnerability Reporting on this
repository (Security tab, "Report a vulnerability"). Include the affected
version, reproduction steps, and whether the issue lets `check` pass against a
journal or checkpoint file that has been tampered with. We aim to acknowledge
within 72 hours and credit reporters in the release notes unless asked not to.

If the issue is in Aileron itself (chain verification, checkpoint signing),
report it there: it has its own `SECURITY.md`.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (latest) | security fixes |

## What anchoring proves

After `aileron-anchor push` succeeds and later `aileron-anchor check` exits 0,
the following holds, with the trust assumptions listed in the next section:

1. **A specific checkpoint existed by a specific time.** Rekor's signed entry
   timestamp covers the entry body (which contains the SHA-256 of the signed
   checkpoint payload, the Ed25519 signature bytes, and the public key) and
   the integration time. Anyone holding Rekor's public key can confirm it.
2. **That checkpoint was signed by the holder of the private key.** The
   signature bytes Rekor holds verify, locally, over the payload rebuilt from
   the anchors file, under the public key you passed in.
3. **The local journal still contains the attested prefix.** The journal has
   at least `count` events, the event at `count` hashes to `tip_hash`, and
   the hash chain is intact. Because `count` and `tip_hash` come from a
   payload whose hash and signature Rekor holds, an attacker cannot make the
   check pass by editing the anchors file or the checkpoint file.
4. **The local checkpoint file still contains the anchored checkpoint**, and
   (with discovery) **no checkpoint signed by this key has been removed from
   it**, because every entry Rekor's search index lists under the key is
   matched against the file.

Together these turn "the newest checkpoints were deleted" from undetectable
into a `TRUNCATED` finding with exit code 2.

## What anchoring does not prove

- **That the journal is true.** Anchoring attests that a signed checkpoint
  existed. It says nothing about whether the events in the journal are an
  honest record of what an agent did. That is Aileron's host-integrity
  assumption and it is unchanged.
- **Anything about events after the newest anchor.** Between the last `push`
  and now, the tail is protected only by Aileron's local checkpoint chain,
  with the gap this package exists to close. Anchor as often as the window
  you can tolerate.
- **That an attacker with the signing key did not also anchor.** Someone
  holding the private key can sign a shorter, consistent-looking checkpoint
  and anchor it too. They still cannot remove the earlier, longer anchor, so
  `check` reports the truncation against that one. But keep signing keys off
  the recorded host, as Aileron already asks.
- **The Rekor log's own consistency.** `check` verifies each entry against
  the signed checkpoint Rekor serves at that moment. It does not store tree
  heads between runs or verify consistency proofs, so it would not notice a
  Rekor operator presenting a forked view of the log. Witnessing and gossip
  are the transparency-log ecosystem's answer and are out of scope here.

## Trust assumptions

- **Rekor is trusted for availability and for time.** If Rekor is down,
  `check` exits 1 (could not verify), never 0. The integration time in the
  signed entry timestamp is Rekor's clock and Rekor's word; it is what
  "existed by a specific time" rests on.
- **Rekor's public key.** By default it is fetched from the same instance
  over HTTPS at the start of each run, which is trust on first use: a party
  able to impersonate the instance to you could present entries signed with
  a key of their own. Pass `--rekor-pubkey` with a copy obtained elsewhere
  (for the public instance, the Sigstore TUF root via `cosign initialize`).
  The `logID` in every entry must match the fingerprint of whichever key is
  used, so an entry from one log cannot be presented as from another.
- **The checkpoint public key is yours and was obtained out of band.**
  `--key` is the root of the Ed25519 side. By default it is read from the
  path the checkpoint names, which lives on the recorded host; for an
  investigation, pass a copy you already held.
- **The search index.** Discovery relies on Rekor's `index/retrieve`
  endpoint, a Rekor v1 convenience that is not part of the signed log. A
  missing or incomplete index means a checkpoint deleted together with its
  anchor record is not found. `check` treats an unavailable index as exit 1,
  not a pass. `--no-discover` opts out explicitly.
- **TLS.** HTTPS to the configured instance uses the system trust store via
  `urllib`. Plain `http://` is accepted so a local docker Rekor can be used
  for testing; do not use it for anything that matters.

## What is published

`push` sends to Rekor, permanently and publicly:

- the checkpoint's signed payload: `ts`, `log_path`, `index`,
  `prev_checkpoint_hash`, `count`, `tip_hash`. **`log_path` is the
  filesystem path Aileron recorded** and may reveal usernames or project
  names. Rekor stores only the SHA-256 of this payload in the canonical
  entry, but the full content is in the request and in the log's history.
- the Ed25519 signature bytes;
- the public key, which makes every anchor by that key discoverable by
  anyone.

No event content, digests, tool names, or anything else from the journal is
sent. `check` sends the public key (to the search index) and entry UUIDs.

## Network behaviour

Exactly these requests are made, all to the configured `--rekor-url`:

| Command | Request |
|---|---|
| `push` | `POST /api/v1/log/entries`, then `GET /api/v1/log/entries/{uuid}` on a 409, then `GET /api/v1/log/publicKey` unless `--rekor-pubkey` |
| `check` | `GET /api/v1/log/publicKey` (unless `--rekor-pubkey`), `GET /api/v1/log/entries/{uuid}` per anchor, `POST /api/v1/index/retrieve` and further `GET`s unless `--no-discover` |

Nothing else, no telemetry, no other hosts. A request outside this table is a
bug; please report it.

## Fail-closed behaviour

- Any HTTP status other than the expected one, any malformed response, any
  SET or inclusion proof that does not verify, and any transport failure
  stops the operation. `push` records nothing locally unless Rekor confirmed
  the entry and the confirmation verified. `check` never exits 0 unless at
  least one anchor verified end to end and nothing was left unverified.
- A `check` with no anchors to verify exits 1, not 0.
- Malformed lines in the anchors file are reported as a problem (exit 2),
  not skipped: the file was edited.

## Known gaps

- Rekor v2 (tile-based log, no search index, different checkpoint shape) is
  not supported. The public v1 instance is the target of this release.
- RFC 8785 canonicalization is implemented only for the flat ASCII objects
  Rekor signs. Anything outside that subset is refused rather than guessed;
  this is deliberate, and a Rekor change that put non-ASCII text in the SET
  payload would make `check` exit 1 until updated.
- No consistency proofs between runs (see above).

## Disclosure process

1. Report received, acknowledgment within 72 hours.
2. Triage and reproduction; severity agreed with the reporter.
3. Fix developed privately.
4. Coordinated release with a changelog entry that says what could have been
   missed and for how long. For a verification tool, saying so is part of the
   product.
