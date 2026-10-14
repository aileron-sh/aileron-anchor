"""Shared fixtures: a fake Rekor behind the transport seam, and real Aileron journals.

No test opens a socket. ``urllib.request.urlopen`` is replaced for every test
with a function that fails loudly, so a network call anywhere in the package
would turn into a test failure rather than a quiet upload to the public log.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from aileron.chainlog import ChainLog  # noqa: E402
from aileron.events import new_event  # noqa: E402
from aileron.signing import generate_keypair, sign_checkpoint  # noqa: E402


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("a test tried to reach the network")
    monkeypatch.setattr("urllib.request.urlopen", refuse)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    k = _split(len(leaves))
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def merkle_path(m: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if m < k:
        return merkle_path(m, leaves[:k]) + [merkle_root(leaves[k:])]
    return merkle_path(m - k, leaves[k:]) + [merkle_root(leaves[:k])]


EM_DASH = "\u2014"  # signed-note signature line marker, as an escape


class FakeRekor:
    """Enough of Rekor v1 to exercise push and check end to end, in memory.

    Entries are kept as canonical body bytes in insertion order and form a real
    RFC 6962 tree, so inclusion proofs, checkpoints, and SETs are genuine
    signatures over genuine hashes, made with a throwaway ECDSA P-256 key.
    """

    def __init__(self, base_url: str = "https://rekor.test"):
        self.base_url = base_url
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.signing_key.public_key()
        self.public_pem = self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        der = self.public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.log_id = hashlib.sha256(der).hexdigest()
        self.key_hint = hashlib.sha256(der).digest()[:4]
        self.tree_id = "1b2c3d4e5f607182"
        self.leaves: list[bytes] = []
        self.integrated: list[int] = []
        self.calls: list[tuple[str, str]] = []
        self.force_status: int | None = None
        self.search_status: int = 200
        self.clock = 1_760_000_000
        # Hooks tests use to serve something other than the truth.
        self.override_entry = None  # callable(uuid, entry_dict) -> entry_dict

    # -- tree helpers --

    def uuid_for(self, body: bytes) -> str:
        return self.tree_id + leaf_hash(body).hex()

    def _index_of(self, uuid: str) -> int | None:
        for i, body in enumerate(self.leaves):
            if self.uuid_for(body) == uuid:
                return i
        return None

    def _sign(self, message: bytes) -> bytes:
        return self.signing_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def checkpoint_note(self) -> str:
        n = len(self.leaves)
        text = f"rekor.test - 123\n{n}\n{b64(merkle_root(self.leaves))}\n"
        sig = self._sign(text.encode("utf-8"))
        return text + "\n" + EM_DASH + " rekor.test " + b64(self.key_hint + sig) + "\n"

    def entry(self, index: int, with_proof: bool = True) -> dict:
        body = self.leaves[index]
        body_b64 = b64(body)
        payload = json.dumps(
            {"body": body_b64, "integratedTime": self.integrated[index],
             "logID": self.log_id, "logIndex": index},
            sort_keys=True, separators=(",", ":")).encode("utf-8")
        verification = {"signedEntryTimestamp": b64(self._sign(payload))}
        if with_proof:
            verification["inclusionProof"] = {
                "logIndex": index,
                "treeSize": len(self.leaves),
                "rootHash": merkle_root(self.leaves).hex(),
                "hashes": [h.hex() for h in merkle_path(index, self.leaves)],
                "checkpoint": self.checkpoint_note(),
            }
        uuid = self.uuid_for(body)
        entry = {
            "body": body_b64,
            "integratedTime": self.integrated[index],
            "logID": self.log_id,
            "logIndex": index,
            "verification": verification,
        }
        if self.override_entry is not None:
            entry = self.override_entry(uuid, entry)
        return {uuid: entry}

    # -- the transport --

    def transport(self, method: str, url: str, body: bytes | None, headers: dict):
        parsed = urlparse(url)
        assert f"{parsed.scheme}://{parsed.netloc}" == self.base_url, url
        path = parsed.path
        self.calls.append((method, path))
        if self.force_status is not None:
            return self.force_status, {}, b'{"code":500,"message":"forced"}'
        ok = {"content-type": "application/json"}

        if method == "POST" and path == "/api/v1/log/entries":
            proposed = json.loads(body)
            assert proposed["kind"] == "rekord"
            spec = proposed["spec"]
            content = base64.b64decode(spec["data"]["content"])
            canonical = {
                "apiVersion": "0.0.1",
                "kind": "rekord",
                "spec": {
                    "data": {"hash": {"algorithm": "sha256",
                                      "value": hashlib.sha256(content).hexdigest()}},
                    "signature": {
                        "content": spec["signature"]["content"],
                        "format": spec["signature"]["format"],
                        "publicKey": {"content": spec["signature"]["publicKey"]["content"]},
                    },
                },
            }
            leaf = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
            uuid = self.uuid_for(leaf)
            existing = self._index_of(uuid)
            if existing is not None:
                return 409, {"location": f"{self.base_url}/api/v1/log/entries/{uuid}"}, b""
            self.leaves.append(leaf)
            self.clock += 60
            self.integrated.append(self.clock)
            index = len(self.leaves) - 1
            return 201, {**ok, "location": f"{self.base_url}/api/v1/log/entries/{uuid}"}, \
                json.dumps(self.entry(index)).encode("utf-8")

        if method == "GET" and path.startswith("/api/v1/log/entries/"):
            uuid = path.rsplit("/", 1)[-1]
            index = self._index_of(uuid)
            if index is None:
                return 404, {}, b'{"code":404,"message":"not found"}'
            return 200, ok, json.dumps(self.entry(index)).encode("utf-8")

        if method == "POST" and path == "/api/v1/index/retrieve":
            if self.search_status != 200:
                return self.search_status, {}, b""
            wanted = json.loads(body)["publicKey"]["content"]
            uuids = []
            for leaf in self.leaves:
                spec = json.loads(leaf)["spec"]
                if spec["signature"]["publicKey"]["content"] == wanted:
                    uuids.append(self.uuid_for(leaf))
            return 200, ok, json.dumps(uuids).encode("utf-8")

        if method == "GET" and path == "/api/v1/log/publicKey":
            return 200, {"content-type": "application/x-pem-file"}, self.public_pem

        return 404, {}, b"no such route"


@pytest.fixture
def rekor():
    return FakeRekor()


@pytest.fixture
def client(rekor):
    from aileron_anchor.rekor import RekorClient
    return RekorClient(rekor.base_url, transport=rekor.transport)


def make_journal(tmp_path, n: int = 3, name: str = "run.chain.jsonl") -> str:
    path = str(tmp_path / name)
    log = ChainLog(path)
    for _ in range(n):
        log.append(new_event("tool_call", "s", "bot", "fw", tool={"name": "t"}))
    return path


def extend_journal(log_path: str, n: int) -> None:
    log = ChainLog(log_path)
    for _ in range(n):
        log.append(new_event("tool_call", "s", "bot", "fw", tool={"name": "more"}))


@pytest.fixture
def journal(tmp_path):
    """A signed journal: (log_path, private_key_path, public_key_path)."""
    key_path, pub_path = generate_keypair(str(tmp_path / "keys"))
    log_path = make_journal(tmp_path)
    sign_checkpoint(log_path, key_path)
    return log_path, key_path, pub_path
