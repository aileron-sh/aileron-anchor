from __future__ import annotations

import base64
import hashlib
import json

import pytest

from aileron_anchor.rekor import (
    RekorClient,
    RekorError,
    RekorVerificationError,
    jcs,
    leaf_hash,
    parse_log_entry,
    parse_signed_note,
    verify_inclusion_path,
    verify_set,
    verify_signed_note,
    load_rekor_public_key,
)

from conftest import merkle_path, merkle_root


def test_jcs_matches_rfc8785_for_flat_ascii():
    assert jcs({"b": 1, "a": "x", "c": True, "d": None}) == b'{"a":"x","b":1,"c":true,"d":null}'
    assert jcs({"s": 'q"\\\n\x01'}) == b'{"s":"q\\"\\\\\\n\\u0001"}'


def test_jcs_refuses_what_it_cannot_canonicalize():
    with pytest.raises(RekorVerificationError):
        jcs({"f": 1.5})
    with pytest.raises(RekorVerificationError):
        jcs({"s": "café"})


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 7, 8, 9, 16, 33])
def test_inclusion_path_every_leaf(size):
    leaves = [f"leaf-{i}".encode() for i in range(size)]
    root = merkle_root(leaves)
    for i, leaf in enumerate(leaves):
        verify_inclusion_path(i, size, leaf_hash(leaf), merkle_path(i, leaves), root)


def test_inclusion_path_rejects_wrong_leaf_and_bad_shapes():
    leaves = [f"leaf-{i}".encode() for i in range(5)]
    root = merkle_root(leaves)
    path = merkle_path(2, leaves)
    with pytest.raises(RekorVerificationError):
        verify_inclusion_path(2, 5, leaf_hash(b"other"), path, root)
    with pytest.raises(RekorVerificationError):
        verify_inclusion_path(2, 5, leaf_hash(leaves[2]), path[:-1], root)
    with pytest.raises(RekorVerificationError):
        verify_inclusion_path(2, 5, leaf_hash(leaves[2]), path + [b"\x00" * 32], root)
    with pytest.raises(RekorVerificationError):
        verify_inclusion_path(5, 5, leaf_hash(leaves[2]), path, root)


def test_signed_note_parse_and_verify(rekor):
    rekor.leaves.append(b"x")
    rekor.integrated.append(1)
    note = parse_signed_note(rekor.checkpoint_note())
    assert note.origin == "rekor.test - 123"
    assert note.tree_size == 1
    assert note.root_hash == merkle_root(rekor.leaves)
    key = load_rekor_public_key(rekor.public_pem)
    verify_signed_note(note, key)

    forged = rekor.checkpoint_note().replace("\n1\n", "\n2\n")
    with pytest.raises(RekorVerificationError):
        verify_signed_note(parse_signed_note(forged), key)
    with pytest.raises(RekorVerificationError):
        parse_signed_note("no signature section at all\n")


def test_verify_set_round_trip_and_rejections(rekor):
    rekor.leaves.append(json.dumps({"kind": "rekord"}).encode())
    rekor.integrated.append(1234)
    entry = parse_log_entry(rekor.entry(0))
    key = load_rekor_public_key(rekor.public_pem)
    verify_set(entry, key)

    entry.log_index += 1
    with pytest.raises(RekorVerificationError):
        verify_set(entry, key)
    entry.log_index -= 1
    entry.signed_entry_timestamp = None
    with pytest.raises(RekorVerificationError):
        verify_set(entry, key)


def test_parse_log_entry_rejects_bad_shapes():
    with pytest.raises(RekorVerificationError):
        parse_log_entry({})
    with pytest.raises(RekorVerificationError):
        parse_log_entry({"a" * 80: {"body": "!!!", "logIndex": 0, "integratedTime": 1, "logID": "x"}})
    body = base64.b64encode(b'{"kind":"rekord"}').decode()
    with pytest.raises(RekorVerificationError):
        parse_log_entry({"a" * 80: {"body": body, "logIndex": -1, "integratedTime": 1, "logID": "x"}})
    with pytest.raises(RekorVerificationError):
        parse_log_entry({"a" * 80: {"body": body, "logIndex": 0, "integratedTime": 1.5, "logID": "x"}})


def test_client_refuses_malformed_uuid_and_mismatched_answer(rekor, client):
    with pytest.raises(RekorError):
        client.get_entry("not-hex")

    def lie(method, url, body, headers):
        other = "ab" * 40
        return 200, {}, json.dumps({other: {
            "body": base64.b64encode(b"{}").decode(), "logIndex": 0,
            "integratedTime": 1, "logID": "x"}}).encode()

    with pytest.raises(RekorVerificationError):
        RekorClient("https://rekor.test", transport=lie).get_entry("cd" * 40)


def test_client_public_key_requires_pem(rekor, client):
    def not_pem(method, url, body, headers):
        return 200, {}, b"<html>"
    with pytest.raises(RekorError):
        RekorClient("https://rekor.test", transport=not_pem).public_key_pem()


def test_client_conflict_without_location_is_an_error():
    def conflict(method, url, body, headers):
        return 409, {}, b""
    with pytest.raises(RekorError):
        RekorClient("https://rekor.test", transport=conflict).create_entry({"kind": "rekord"})


def test_leaf_hash_is_rfc6962():
    assert leaf_hash(b"abc") == hashlib.sha256(b"\x00abc").digest()
