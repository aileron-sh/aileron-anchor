from __future__ import annotations

import base64
import hashlib
import json
import os

from aileron.signing import _signed_payload, sign_checkpoint

from aileron_anchor.anchors import EXIT_ERROR, EXIT_OK, anchors_path, push, read_anchors
from aileron_anchor.rekor import build_rekord_entry

from conftest import extend_journal


def test_push_happy_path(journal, rekor, client):
    log_path, _key, pub_path = journal
    report = push(log_path, pub_path, client)
    assert report.exit_code == EXIT_OK, report.lines
    assert ("POST", "/api/v1/log/entries") in rekor.calls

    records = read_anchors(log_path)
    assert len(records) == 1
    _lineno, record = records[0]
    checkpoint = json.loads(open(f"{log_path}.checkpoints.jsonl").read().splitlines()[-1])
    assert record["checkpoint_index"] == 1
    assert record["count"] == 3
    assert record["tip_hash"] == checkpoint["tip_hash"]
    assert record["rekor_url"] == rekor.base_url
    assert record["uuid"] == rekor.uuid_for(rekor.leaves[0])
    assert record["log_index"] == 0
    assert record["integrated_time"] == rekor.integrated[0]
    assert record["ts"].endswith("Z")
    assert record["checkpoint"] == checkpoint

    # What Rekor holds is the checkpoint's signed payload hash, signature, and key.
    body = json.loads(rekor.leaves[0])
    spec = body["spec"]
    assert spec["data"]["hash"]["value"] == hashlib.sha256(_signed_payload(checkpoint)).hexdigest()
    assert spec["signature"]["content"] == checkpoint["signature"]
    assert base64.b64decode(spec["signature"]["publicKey"]["content"]) == open(pub_path, "rb").read()

    # The report says what was verified.
    text = "\n".join(report.lines)
    assert "signature verified locally" in text
    assert "signed entry timestamp verified" in text
    assert "inclusion proof verified" in text


def test_push_uses_key_named_by_checkpoint(journal, rekor, client):
    log_path, _key, _pub = journal
    report = push(log_path, None, client)
    assert report.exit_code == EXIT_OK, report.lines


def test_push_missing_checkpoint_file(tmp_path, rekor, client):
    from conftest import make_journal
    log_path = make_journal(tmp_path)
    report = push(log_path, None, client)
    assert report.exit_code == EXIT_ERROR
    assert "checkpoint" in report.errors[0]
    assert rekor.calls == []
    assert not os.path.exists(anchors_path(log_path))


def test_push_selects_checkpoint_by_index(journal, rekor, client):
    log_path, key_path, pub_path = journal
    extend_journal(log_path, 2)
    sign_checkpoint(log_path, key_path)
    report = push(log_path, pub_path, client, index=1)
    assert report.exit_code == EXIT_OK, report.lines
    assert read_anchors(log_path)[0][1]["count"] == 3
    report = push(log_path, pub_path, client)
    assert read_anchors(log_path)[1][1]["count"] == 5
    assert push(log_path, pub_path, client, index=7).exit_code == EXIT_ERROR


def test_push_twice_is_harmless(journal, rekor, client):
    log_path, _key, pub_path = journal
    assert push(log_path, pub_path, client).exit_code == EXIT_OK
    report = push(log_path, pub_path, client)
    assert report.exit_code == EXIT_OK, report.lines
    assert len(rekor.leaves) == 1
    records = read_anchors(log_path)
    assert len(records) == 2 and records[0][1]["uuid"] == records[1][1]["uuid"]


def test_push_http_error_fails_closed(journal, rekor, client):
    log_path, _key, pub_path = journal
    rekor.force_status = 500
    report = push(log_path, pub_path, client)
    assert report.exit_code == EXIT_ERROR
    assert "HTTP 500" in report.errors[0]
    assert not os.path.exists(anchors_path(log_path))


def test_push_transport_failure_fails_closed(journal):
    from aileron_anchor.rekor import RekorClient, RekorError
    log_path, _key, pub_path = journal

    def down(method, url, body, headers):
        raise RekorError("connection refused")

    report = push(log_path, pub_path, RekorClient("https://rekor.test", transport=down))
    assert report.exit_code == EXIT_ERROR
    assert not os.path.exists(anchors_path(log_path))


def test_push_refuses_checkpoint_that_does_not_verify(journal, rekor, client, tmp_path):
    from aileron.signing import generate_keypair
    log_path, _key, _pub = journal
    _other_key, other_pub = generate_keypair(str(tmp_path / "other"))
    report = push(log_path, other_pub, client)
    assert report.exit_code == EXIT_ERROR
    assert "does not verify" in report.errors[0]
    assert rekor.calls == []


def test_push_rejects_rekor_entry_that_differs(journal, rekor, client):
    """If Rekor's stored entry is not our checkpoint, nothing is recorded."""
    log_path, _key, pub_path = journal

    def swap_signature(uuid, entry):
        body = json.loads(base64.b64decode(entry["body"]))
        body["spec"]["signature"]["content"] = base64.b64encode(b"\x00" * 64).decode()
        entry = dict(entry)
        entry["body"] = base64.b64encode(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).decode()
        return entry

    rekor.override_entry = swap_signature
    report = push(log_path, pub_path, client)
    assert report.exit_code == EXIT_ERROR
    assert not os.path.exists(anchors_path(log_path))


def test_build_rekord_entry_shape():
    entry = build_rekord_entry(b"payload", b"sig", b"-----BEGIN PUBLIC KEY-----\n")
    assert entry["kind"] == "rekord" and entry["apiVersion"] == "0.0.1"
    assert base64.b64decode(entry["spec"]["data"]["content"]) == b"payload"
    assert entry["spec"]["signature"]["format"] == "x509"
    assert base64.b64decode(entry["spec"]["signature"]["content"]) == b"sig"
    assert "hash" not in entry["spec"]["data"]
