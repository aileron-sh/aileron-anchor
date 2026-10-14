# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once 1.0 is reached; 0.x releases may change APIs between minor versions.

## [0.1.0] - 2026-10-14

First release. Closes the one gap Aileron's `SECURITY.md` documents as
undetectable by any purely local scheme: deleting the newest checkpoints along
with the tail of the journal.

### Added

- `aileron-anchor push <log>`: uploads a signed checkpoint (newest, or
  `--index N`) to Sigstore Rekor as a `rekord` entry with the payload inlined,
  verifies Rekor's response (signed entry timestamp, inclusion proof, and that
  the stored entry is the checkpoint we sent), and appends a record to
  `<log>.anchors.jsonl`. Re-running on the same checkpoint is harmless: Rekor
  answers 409 and the existing entry is recorded.
- `aileron-anchor check <log>`: fetches every anchored entry, verifies Rekor's
  signatures and proofs, verifies the entry is the expected checkpoint under
  the local public key, and compares the Rekor-backed `count` and `tip_hash`
  against the journal and the checkpoint file. Reports `TRUNCATED` or
  `REWRITTEN` with specifics and exits 2. Asks Rekor's search index for
  entries under the key that the anchors file does not list, which catches a
  checkpoint deleted together with its anchor record (`--no-discover` to opt
  out).
- `--rekor-pubkey` to verify Rekor's signatures with a key obtained out of
  band instead of one fetched from the instance.
- Exit codes: 0 verified, 1 could not verify (never a pass), 2 tamper
  evidence.

### Design notes

- `rekord` rather than `hashedrekord`: Rekor verifies Ed25519 keys in
  `hashedrekord` with the prehashed `Ed25519ph` scheme, which pure Ed25519
  signatures (Aileron's) do not satisfy. `rekord` verifies over the inlined
  bytes with plain Ed25519.
- All HTTP goes through one injectable transport over `urllib.request`. The
  test suite replaces `urllib.request.urlopen` with a function that fails, so
  no test can reach the public log by accident.
