"""The anchors file, and the comparison between Rekor, the journal, and the
checkpoint file.

An anchor record is one JSON line in ``<log>.anchors.jsonl``::

    {checkpoint_index, tip_hash, count, rekor_url, uuid, log_index,
     integrated_time, ts, checkpoint}

``checkpoint`` is the full checkpoint object that was anchored. Rekor stores
only the hash of the signed payload, the signature, and the public key, so the
payload itself has to come from somewhere local; carrying it in the record
means ``check`` can rebuild and verify it even after the checkpoint file has
been truncated. The anchors file is not trusted: everything it says is checked
against Rekor and against the local key before it is used.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from aileron import chainlog
from aileron.signing import PUBLIC_KEY_NAME, _read_checkpoints, _signed_payload
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .rekor import (
    LogEntry,
    RekorClient,
    RekorError,
    RekorVerificationError,
    build_rekord_entry,
    load_rekor_public_key,
    unb64,
    verify_inclusion,
    verify_set,
)

ANCHORS_SUFFIX = ".anchors.jsonl"
RECORD_KEYS = (
    "checkpoint_index", "tip_hash", "count", "rekor_url", "uuid",
    "log_index", "integrated_time", "ts", "checkpoint",
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_TAMPERED = 2


class AnchorError(Exception):
    """Something local is missing or unusable; nothing was concluded."""


@dataclass
class Report:
    """What a command found, in the order it found it.

    ``lines`` is the plain-English transcript printed to the operator.
    ``problems`` are tamper findings (exit 2). ``errors`` are things that
    stopped verification from completing (exit 1). An empty report with
    neither is not a pass: ``verified`` must be set by the command.
    """

    lines: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    verified: bool = False
    result: dict | None = None

    def say(self, text: str) -> None:
        self.lines.append(text)

    def problem(self, text: str) -> None:
        self.problems.append(text)
        self.lines.append(f"PROBLEM: {text}")

    def error(self, text: str) -> None:
        self.errors.append(text)
        self.lines.append(f"ERROR: {text}")

    @property
    def exit_code(self) -> int:
        if self.problems:
            return EXIT_TAMPERED
        if self.errors or not self.verified:
            return EXIT_ERROR
        return EXIT_OK


# --- Local files ---------------------------------------------------------------


def anchors_path(log_path: str) -> str:
    return f"{log_path}{ANCHORS_SUFFIX}"


def read_anchors(log_path: str) -> list[tuple[int, Any]]:
    """Every non-blank line of the anchors file as ``(line number, decoded)``.

    Lines that are not JSON come back as ``(lineno, None)`` so the caller can
    report them; an edited anchors file is something the operator should hear
    about rather than have skipped.
    """
    path = anchors_path(log_path)
    if not os.path.exists(path):
        return []
    out: list[tuple[int, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append((lineno, json.loads(line)))
            except ValueError:
                out.append((lineno, None))
    return out


def append_anchor(log_path: str, record: dict) -> None:
    with open(anchors_path(log_path), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def load_public_key(key_path: str) -> Ed25519PublicKey:
    """Load the checkpoint signing public key.

    Accepts a PEM public key, a PEM private key (public half derived), or a
    directory holding aileron's standard keypair files.
    """
    path = key_path
    if os.path.isdir(path):
        path = os.path.join(path, PUBLIC_KEY_NAME)
    if not os.path.exists(path):
        raise AnchorError(f"key file not found: {path}")
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        key: Any = serialization.load_pem_public_key(data)
    except ValueError:
        try:
            key = serialization.load_pem_private_key(data, password=None)
        except (ValueError, TypeError) as exc:
            raise AnchorError(f"not a PEM key: {path} ({exc})") from exc
        if isinstance(key, Ed25519PrivateKey):
            key = key.public_key()
    if not isinstance(key, Ed25519PublicKey):
        raise AnchorError(f"not an Ed25519 key: {path}")
    return key


def public_key_pem(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def _raw(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def checkpoint_payload(checkpoint: dict) -> bytes:
    """The exact bytes the checkpoint signature covers (aileron's definition)."""
    return _signed_payload(checkpoint)


def checkpoint_payload_hash(checkpoint: dict) -> str:
    return hashlib.sha256(checkpoint_payload(checkpoint)).hexdigest()


def checkpoint_signature(checkpoint: dict) -> bytes:
    sig = checkpoint.get("signature")
    if not isinstance(sig, str):
        raise AnchorError("checkpoint has no signature")
    try:
        return base64.b64decode(sig, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AnchorError(f"checkpoint signature is not base64: {exc}") from exc


def verify_checkpoint_signature(checkpoint: dict, key: Ed25519PublicKey) -> None:
    try:
        key.verify(checkpoint_signature(checkpoint), checkpoint_payload(checkpoint))
    except InvalidSignature as exc:
        raise AnchorError("checkpoint signature does not verify with this key") from exc


def well_formed_checkpoint(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    count = obj.get("count")
    index = obj.get("index")
    for value in (count, index):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            return False
    return isinstance(obj.get("tip_hash"), str) and isinstance(obj.get("signature"), str)


def select_checkpoint(checkpoints: list[dict], index: int | None) -> dict:
    """The checkpoint with signed ``index`` (default: the highest one)."""
    usable = [c for c in checkpoints if well_formed_checkpoint(c)]
    if not usable:
        raise AnchorError("no usable checkpoint found")
    if index is None:
        return max(usable, key=lambda c: c["index"])
    matches = [c for c in usable if c["index"] == index]
    if not matches:
        raise AnchorError(f"no checkpoint with index {index} "
                          f"(have {sorted(c['index'] for c in usable)})")
    if len(matches) > 1:
        raise AnchorError(f"checkpoint index {index} appears {len(matches)} times")
    return matches[0]


# --- Rekor entry versus checkpoint -------------------------------------------------


def entry_matches_checkpoint(entry: LogEntry, checkpoint: dict, key: Ed25519PublicKey) -> None:
    """Require the Rekor entry body to be exactly this checkpoint under this key.

    The body carries the SHA-256 of the signed payload, the signature bytes,
    and the public key. All three must agree with what we hold, and the
    signature must verify locally over the rebuilt payload. After this, the
    checkpoint's ``count`` and ``tip_hash`` are backed by Rekor, not by any
    file the attacker could edit.
    """
    body = entry.body
    if body.get("kind") != "rekord":
        raise RekorVerificationError(f"entry kind is {body.get('kind')!r}, not rekord")
    spec = body.get("spec")
    if not isinstance(spec, dict):
        raise RekorVerificationError("entry has no spec")
    sig_spec = spec.get("signature") or {}
    data_spec = spec.get("data") or {}
    if sig_spec.get("format") != "x509":
        raise RekorVerificationError("entry signature format is not x509")
    pem = unb64((sig_spec.get("publicKey") or {}).get("content"), "entry public key")
    try:
        entry_key = serialization.load_pem_public_key(pem)
    except ValueError as exc:
        raise RekorVerificationError(f"entry public key is not PEM: {exc}") from exc
    if not isinstance(entry_key, Ed25519PublicKey) or _raw(entry_key) != _raw(key):
        raise RekorVerificationError("entry was signed by a different public key")
    signature = unb64(sig_spec.get("content"), "entry signature")
    if signature != checkpoint_signature(checkpoint):
        raise RekorVerificationError("entry signature differs from the checkpoint signature")
    hash_spec = data_spec.get("hash") or {}
    if hash_spec.get("algorithm") != "sha256":
        raise RekorVerificationError("entry data hash is not sha256")
    if hash_spec.get("value") != checkpoint_payload_hash(checkpoint):
        raise RekorVerificationError("entry data hash differs from the checkpoint payload hash")
    try:
        key.verify(signature, checkpoint_payload(checkpoint))
    except InvalidSignature as exc:
        raise RekorVerificationError("checkpoint signature does not verify") from exc


def _resolve_rekor_key(client: RekorClient, rekor_key_pem: bytes | None, report: Report):
    if rekor_key_pem is not None:
        key = load_rekor_public_key(rekor_key_pem)
        report.say("Rekor key: supplied out of band")
        return key
    pem = client.public_key_pem()
    key = load_rekor_public_key(pem)
    report.say("Rekor key: fetched from the Rekor instance itself (trust on first use; pass "
               "--rekor-pubkey with a copy obtained elsewhere for a stronger check)")
    return key


def _verify_rekor_side(entry: LogEntry, rekor_key, report: Report, label: str) -> None:
    """SET and inclusion proof. Raises on failure; says what passed."""
    verify_set(entry, rekor_key)
    report.say(f"{label}: signed entry timestamp verified "
               f"(log index {entry.log_index}, integrated {_fmt_time(entry.integrated_time)})")
    verify_inclusion(entry, rekor_key)
    report.say(f"{label}: inclusion proof verified against a Rekor-signed checkpoint")


def _fmt_time(unix: int) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- push ---------------------------------------------------------------------------


def push(log_path: str, key_path: str | None, client: RekorClient, index: int | None = None,
         rekor_key_pem: bytes | None = None) -> Report:
    """Anchor one checkpoint in Rekor and record the result locally."""
    report = Report()
    try:
        checkpoints = _read_checkpoints(log_path)
        if not checkpoints:
            raise AnchorError(f"no checkpoint file at {log_path}.checkpoints.jsonl "
                              "(run `aileron sign-checkpoint` first)")
        checkpoint = select_checkpoint(checkpoints, index)
        if key_path is None:
            key_path = checkpoint.get("pubkey_path")
            if not isinstance(key_path, str) or not os.path.exists(key_path):
                raise AnchorError("checkpoint names no readable public key; pass --key")
        key = load_public_key(key_path)
        verify_checkpoint_signature(checkpoint, key)
        report.say(f"checkpoint {checkpoint['index']}: count {checkpoint['count']}, "
                   f"tip {checkpoint['tip_hash'][:16]}..., signature verified locally")

        result = chainlog.verify(log_path)
        events = chainlog.ChainLog.read(log_path)
        count = checkpoint["count"]
        if not result.ok:
            report.say("note: the local journal chain is broken; anchoring the checkpoint anyway "
                       "preserves evidence of what it attested")
        elif result.count < count or events[count - 1].get("hash") != checkpoint["tip_hash"]:
            report.say("note: the local journal does not match this checkpoint; anchoring anyway")
        else:
            report.say("local journal agrees with the checkpoint")

        payload = checkpoint_payload(checkpoint)
        report.say(f"publishing to {client.base_url}: the signed payload (timestamp, count, tip "
                   f"hash, checkpoint chain, and log_path {checkpoint.get('log_path')!r}), the "
                   "signature, and the public key become public and permanent")
        proposed = build_rekord_entry(payload, checkpoint_signature(checkpoint), public_key_pem(key))
        entry = client.create_entry(proposed)
        report.say(f"Rekor accepted entry {entry.uuid}")
        entry_matches_checkpoint(entry, checkpoint, key)
        report.say("Rekor's stored entry matches the checkpoint (hash, signature, public key)")

        rekor_key = _resolve_rekor_key(client, rekor_key_pem, report)
        _verify_rekor_side(entry, rekor_key, report, "entry")

        record = {
            "checkpoint_index": checkpoint["index"],
            "tip_hash": checkpoint["tip_hash"],
            "count": count,
            "rekor_url": client.base_url,
            "uuid": entry.uuid,
            "log_index": entry.log_index,
            "integrated_time": entry.integrated_time,
            "ts": now_ts(),
            "checkpoint": checkpoint,
        }
        append_anchor(log_path, record)
        report.say(f"recorded anchor in {anchors_path(log_path)}")
        report.result = record
        report.verified = True
    except (AnchorError, RekorError, OSError, ValueError) as exc:
        report.error(str(exc))
    return report


# --- check --------------------------------------------------------------------------


def _valid_record(obj: Any) -> bool:
    if not isinstance(obj, dict) or any(k not in obj for k in RECORD_KEYS):
        return False
    if not well_formed_checkpoint(obj["checkpoint"]):
        return False
    return (isinstance(obj["uuid"], str) and isinstance(obj["count"], int)
            and isinstance(obj["tip_hash"], str) and isinstance(obj["log_index"], int)
            and isinstance(obj["integrated_time"], int))


def _compare_with_journal(count: int, tip_hash: str, index: int, chain, events: list[dict],
                          report: Report) -> None:
    if not chain.ok:
        report.problem(f"local journal chain is broken: {chain.errors[0]}")
        return
    if chain.count < count:
        report.problem(f"TRUNCATED: Rekor-anchored checkpoint {index} attests to {count} events "
                       f"but the journal holds {chain.count}")
    elif events[count - 1].get("hash") != tip_hash:
        report.problem(f"REWRITTEN: event {count} does not hash to the Rekor-anchored tip "
                       f"of checkpoint {index}")
    else:
        report.say(f"journal: event {count} matches the anchored tip hash")


def check(log_path: str, key_path: str | None, client: RekorClient,
          rekor_key_pem: bytes | None = None, discover: bool = True) -> Report:
    """Verify every anchor against Rekor, then the local files against the anchors."""
    report = Report()
    try:
        records = read_anchors(log_path)
        checkpoints = _read_checkpoints(log_path)
        if key_path is None:
            named = [c.get("pubkey_path") for c in checkpoints if isinstance(c.get("pubkey_path"), str)]
            named += [r["checkpoint"].get("pubkey_path") for _n, r in records if _valid_record(r)]
            found = [p for p in named if os.path.exists(p)]
            if not found:
                raise AnchorError("no readable public key named by any checkpoint; pass --key")
            key_path = found[-1]
        key = load_public_key(key_path)
        report.say(f"public key: {key_path}")

        if not os.path.exists(log_path):
            raise AnchorError(f"journal not found: {log_path}")
        chain = chainlog.verify(log_path)
        events = chainlog.ChainLog.read(log_path)
        report.say(f"journal: {chain.count} events, chain {'intact' if chain.ok else 'BROKEN'}")
        local_hashes = {checkpoint_payload_hash(c): c
                        for c in checkpoints if well_formed_checkpoint(c)}
        report.say(f"checkpoint file: {len(local_hashes)} usable checkpoint(s)")

        rekor_key = _resolve_rekor_key(client, rekor_key_pem, report)

        anchored_uuids: set[str] = set()
        verified_anchors = 0
        if not records:
            report.say(f"no anchors recorded in {anchors_path(log_path)}")
        for lineno, record in records:
            if not _valid_record(record):
                report.problem(f"anchors file line {lineno} is malformed; the file has been edited")
                continue
            uuid = record["uuid"]
            label = f"anchor {record['checkpoint_index']} ({uuid[:16]}...)"
            anchored_uuids.add(uuid)
            if record["rekor_url"].rstrip("/") != client.base_url:
                report.say(f"{label}: recorded against {record['rekor_url']}, "
                           f"checking against {client.base_url}")
            try:
                entry = client.get_entry(uuid)
                _verify_rekor_side(entry, rekor_key, report, label)
                checkpoint = record["checkpoint"]
                entry_matches_checkpoint(entry, checkpoint, key)
            except RekorVerificationError as exc:
                report.problem(f"{label}: Rekor entry does not match the recorded checkpoint: {exc}")
                continue
            except RekorError as exc:
                report.error(f"{label}: {exc}")
                continue
            report.say(f"{label}: Rekor entry matches the recorded checkpoint and its Ed25519 "
                       "signature verifies")
            if (entry.log_index != record["log_index"]
                    or entry.integrated_time != record["integrated_time"]
                    or checkpoint["count"] != record["count"]
                    or checkpoint["tip_hash"] != record["tip_hash"]
                    or checkpoint["index"] != record["checkpoint_index"]):
                report.problem(f"{label}: anchors file fields disagree with the Rekor entry or "
                               "with the checkpoint it carries; the file has been edited")
                continue
            verified_anchors += 1
            # From here on count and tip_hash are backed by Rekor and the key.
            _compare_with_journal(checkpoint["count"], checkpoint["tip_hash"],
                                  checkpoint["index"], chain, events, report)
            if checkpoint_payload_hash(checkpoint) not in local_hashes:
                report.problem(f"TRUNCATED: checkpoint {checkpoint['index']} is anchored in Rekor "
                               f"but missing from {log_path}.checkpoints.jsonl")
            else:
                report.say(f"checkpoint file: holds anchored checkpoint {checkpoint['index']}")

        if discover:
            _discover(client, key, rekor_key, anchored_uuids, local_hashes, chain, events, report)
        else:
            report.say("discovery: skipped (--no-discover)")

        if verified_anchors == 0 and not report.problems:
            report.error("nothing was verified: no anchor could be checked against Rekor")
        report.verified = verified_anchors > 0 and not report.errors
    except (AnchorError, RekorError, OSError, ValueError) as exc:
        report.error(str(exc))
    return report


def _discover(client: RekorClient, key: Ed25519PublicKey, rekor_key, anchored_uuids: set[str],
              local_hashes: dict, chain, events: list[dict], report: Report) -> None:
    """Ask Rekor's search index for every entry under this key.

    This is what catches an attacker who deletes the newest checkpoint and its
    anchor record together: the entry is still in Rekor, under our key, and no
    local checkpoint hashes to it.
    """
    try:
        uuids = client.search_by_public_key(public_key_pem(key))
    except RekorError as exc:
        report.error(f"discovery: Rekor search index unavailable ({exc}); entries anchored "
                     "but then deleted locally cannot be found. Use --no-discover to accept this")
        return
    unknown = [u for u in uuids if u not in anchored_uuids]
    report.say(f"discovery: Rekor lists {len(uuids)} entry(ies) under this key, "
               f"{len(unknown)} not in the anchors file")
    for uuid in unknown:
        label = f"discovered {uuid[:16]}..."
        try:
            entry = client.get_entry(uuid)
            _verify_rekor_side(entry, rekor_key, report, label)
        except RekorVerificationError as exc:
            report.problem(f"{label}: does not verify against Rekor's key: {exc}")
            continue
        except RekorError as exc:
            report.error(f"{label}: {exc}")
            continue
        payload_hash = ((entry.body.get("spec") or {}).get("data") or {}).get("hash", {}).get("value")
        match = local_hashes.get(payload_hash)
        if match is None:
            report.problem(
                f"TRUNCATED: Rekor entry {uuid} (integrated {_fmt_time(entry.integrated_time)}) is a "
                "checkpoint signed by this key that no local checkpoint matches. Either the "
                "checkpoint file lost its newest entries, or this key also signs another journal")
            continue
        try:
            entry_matches_checkpoint(entry, match, key)
        except RekorVerificationError as exc:
            report.problem(f"{label}: matches local checkpoint {match['index']} by hash but not "
                           f"otherwise: {exc}")
            continue
        report.say(f"{label}: is local checkpoint {match['index']}, anchored but not recorded "
                   "in the anchors file")
        _compare_with_journal(match["count"], match["tip_hash"], match["index"], chain, events, report)
