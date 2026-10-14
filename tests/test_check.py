from __future__ import annotations

import base64
import json

from aileron.chainlog import ChainLog
from aileron.events import new_event
from aileron.signing import generate_keypair, sign_checkpoint

from aileron_anchor.anchors import EXIT_ERROR, EXIT_OK, EXIT_TAMPERED, anchors_path, check, push

from conftest import extend_journal


def anchored(journal, client):
    """Two checkpoints (counts 3 and 5), both anchored."""
    log_path, key_path, pub_path = journal
    assert push(log_path, pub_path, client).exit_code == EXIT_OK
    extend_journal(log_path, 2)
    sign_checkpoint(log_path, key_path)
    assert push(log_path, pub_path, client).exit_code == EXIT_OK
    return log_path, key_path, pub_path


def drop_last_line(path: str) -> None:
    lines = open(path, encoding="utf-8").read().splitlines()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines[:-1]) + ("\n" if lines[:-1] else ""))


def test_check_passes(journal, rekor, client):
    log_path, _key, pub_path = anchored(journal, client)
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_OK, report.lines
    text = "\n".join(report.lines)
    assert text.count("signed entry timestamp verified") == 2
    assert text.count("inclusion proof verified") == 2
    assert "event 3 matches" in text and "event 5 matches" in text
    assert "2 not in the anchors file" not in text
    assert ("POST", "/api/v1/index/retrieve") in rekor.calls


def test_check_passes_after_more_appends(journal, client):
    log_path, _key, pub_path = anchored(journal, client)
    extend_journal(log_path, 4)
    assert check(log_path, pub_path, client).exit_code == EXIT_OK


def test_check_uses_key_named_by_checkpoint(journal, client):
    log_path, _key, _pub = anchored(journal, client)
    assert check(log_path, None, client).exit_code == EXIT_OK


def test_check_detects_journal_truncation(journal, client):
    log_path, _key, pub_path = anchored(journal, client)
    drop_last_line(log_path)
    drop_last_line(log_path)  # back to 3 events: checkpoint 1 holds, checkpoint 2 does not
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_TAMPERED
    assert any("TRUNCATED" in p and "attests to 5 events" in p and "holds 3" in p
               for p in report.problems), report.problems


def test_check_detects_truncation_when_checkpoint_file_is_also_truncated(journal, client):
    """The all-local evidence is gone; Rekor still has it."""
    log_path, _key, pub_path = anchored(journal, client)
    drop_last_line(log_path)
    drop_last_line(log_path)
    drop_last_line(f"{log_path}.checkpoints.jsonl")
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_TAMPERED
    text = "\n".join(report.problems)
    assert "attests to 5 events" in text
    assert "missing from" in text


def test_check_detects_deleted_latest_checkpoint(journal, client):
    log_path, _key, pub_path = anchored(journal, client)
    drop_last_line(f"{log_path}.checkpoints.jsonl")
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_TAMPERED
    assert any("checkpoint 2 is anchored in Rekor but missing" in p for p in report.problems)


def test_check_discovers_checkpoint_deleted_along_with_its_anchor(journal, rekor, client):
    """Deleting the newest checkpoint and the newest anchor record together
    leaves the local files mutually consistent. The search index still knows."""
    log_path, _key, pub_path = anchored(journal, client)
    drop_last_line(f"{log_path}.checkpoints.jsonl")
    drop_last_line(anchors_path(log_path))
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_TAMPERED
    assert any("no local checkpoint matches" in p for p in report.problems), report.problems

    # Without discovery the same state looks fine, which is why discovery is on by default.
    quiet = check(log_path, pub_path, client, discover=False)
    assert quiet.exit_code == EXIT_OK
    assert "skipped" in "\n".join(quiet.lines)


def test_check_discovery_unavailable_is_an_error_not_a_pass(journal, rekor, client):
    log_path, _key, pub_path = anchored(journal, client)
    rekor.search_status = 404
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_ERROR
    assert any("search index unavailable" in e for e in report.errors)
    assert check(log_path, pub_path, client, discover=False).exit_code == EXIT_OK


def test_check_detects_rewritten_journal(journal, client):
    """Same length, valid chain, different content: only the anchored tip catches it."""
    log_path, _key, pub_path = anchored(journal, client)
    with open(log_path, "w", encoding="utf-8"):
        pass
    log = ChainLog(log_path)
    for _ in range(5):
        log.append(new_event("tool_call", "s", "bot", "fw", tool={"name": "innocent"}))
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_TAMPERED
    assert any("REWRITTEN" in p for p in report.problems), report.problems


def test_check_detects_rekor_entry_that_does_not_match_local_checkpoint(journal, client):
    """The anchors file claims a checkpoint that Rekor's entry was not made from."""
    log_path, _key, pub_path = anchored(journal, client)
    path = anchors_path(log_path)
    lines = open(path, encoding="utf-8").read().splitlines()
    record = json.loads(lines[-1])
    record["checkpoint"]["count"] = 4
    record["count"] = 4
    lines[-1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_TAMPERED
    assert any("does not match the recorded checkpoint" in p for p in report.problems)


def test_check_detects_edited_anchor_fields(journal, client):
    log_path, _key, pub_path = anchored(journal, client)
    path = anchors_path(log_path)
    lines = open(path, encoding="utf-8").read().splitlines()
    record = json.loads(lines[-1])
    record["integrated_time"] += 1
    lines[-1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_TAMPERED
    assert any("anchors file fields disagree" in p for p in report.problems)


def test_check_malformed_anchor_line_is_reported(journal, client):
    log_path, _key, pub_path = anchored(journal, client)
    with open(anchors_path(log_path), "a", encoding="utf-8") as fh:
        fh.write("not json\n")
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_TAMPERED
    assert any("malformed" in p for p in report.problems)


def test_check_rejects_bad_set(journal, rekor, client):
    """Rekor's own signature is checked, not just the shape of the response."""
    log_path, _key, pub_path = anchored(journal, client)

    def bump_time(uuid, entry):
        entry = dict(entry)
        entry["integratedTime"] += 1
        return entry

    rekor.override_entry = bump_time
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_TAMPERED
    assert any("SET: signature does not verify" in p for p in report.problems), report.problems


def test_check_rejects_rekor_key_mismatch(journal, rekor, client):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    log_path, _key, pub_path = anchored(journal, client)
    other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    report = check(log_path, pub_path, client, rekor_key_pem=other)
    assert report.exit_code == EXIT_TAMPERED
    assert any("logID" in p for p in report.problems), report.problems


def test_check_with_out_of_band_rekor_key(journal, rekor, client):
    log_path, _key, pub_path = anchored(journal, client)
    rekor.calls.clear()
    report = check(log_path, pub_path, client, rekor_key_pem=rekor.public_pem)
    assert report.exit_code == EXIT_OK
    assert "supplied out of band" in "\n".join(report.lines)
    assert ("GET", "/api/v1/log/publicKey") not in rekor.calls


def test_check_rejects_tampered_inclusion_proof(journal, rekor, client):
    log_path, _key, pub_path = anchored(journal, client)

    def break_proof(uuid, entry):
        entry = json.loads(json.dumps(entry))
        proof = entry["verification"]["inclusionProof"]
        proof["hashes"] = ["00" * 32 for _ in proof["hashes"]] or ["00" * 32]
        return entry

    rekor.override_entry = break_proof
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_TAMPERED
    assert any("inclusion proof" in p for p in report.problems), report.problems


def test_check_http_errors_fail_closed(journal, rekor, client):
    log_path, _key, pub_path = anchored(journal, client)
    rekor.force_status = 503
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_ERROR
    assert report.problems == []
    assert not report.verified


def test_check_missing_entry_is_an_error(journal, rekor, client):
    log_path, _key, pub_path = anchored(journal, client)
    rekor.leaves.pop()
    rekor.integrated.pop()
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_ERROR
    assert any("has no entry" in e for e in report.errors)


def test_check_with_nothing_anchored_is_not_a_pass(journal, client):
    log_path, _key, pub_path = journal
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_ERROR
    assert "no anchors recorded" in "\n".join(report.lines)


def test_check_wrong_local_key_is_tamper_evidence(journal, client, tmp_path):
    log_path, _key, _pub = anchored(journal, client)
    _other_key, other_pub = generate_keypair(str(tmp_path / "other"))
    report = check(log_path, other_pub, client)
    assert report.exit_code == EXIT_TAMPERED
    assert any("different public key" in p for p in report.problems)


def test_check_entry_body_pubkey_is_compared_by_key_not_text(journal, rekor, client):
    """Rekor re-encodes the PEM it stores; the comparison must survive that."""
    log_path, _key, pub_path = anchored(journal, client)

    def reflow_pem(uuid, entry):
        body = json.loads(base64.b64decode(entry["body"]))
        pem = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])
        body["spec"]["signature"]["publicKey"]["content"] = base64.b64encode(
            pem.replace(b"\n", b"\r\n")).decode()
        entry = dict(entry)
        entry["body"] = base64.b64encode(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).decode()
        return entry

    # The body changed, so the SET and leaf hash no longer match: that is the
    # fake telling the truth about a changed body. Rebuild the tree with the
    # reflowed body so only the PEM encoding differs.
    for i, leaf in enumerate(rekor.leaves):
        rekor.leaves[i] = base64.b64decode(reflow_pem(None, {"body": base64.b64encode(leaf).decode()})["body"])
    path = anchors_path(log_path)
    lines = open(path, encoding="utf-8").read().splitlines()
    out = []
    for line, leaf in zip(lines, rekor.leaves):
        record = json.loads(line)
        record["uuid"] = rekor.uuid_for(leaf)
        out.append(json.dumps(record, sort_keys=True, separators=(",", ":")))
    open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")
    report = check(log_path, pub_path, client)
    assert report.exit_code == EXIT_OK, report.lines
